"""独立 POP3 调试脚本：连接 163 POP3，列最近邮件并抓取邮件头/正文片段。"""

from __future__ import annotations

import argparse
import email
import poplib
import re
import socket
import ssl
import sys
from email.header import decode_header
from pathlib import Path
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.database.init_db import initialize_database  # noqa: E402
from src.database.models import EmailService  # noqa: E402
from src.database.session import get_db  # noqa: E402


SECRET_FIELDS = {"password", "api_key", "refresh_token", "access_token", "admin_token", "admin_password"}
OPENAI_SENDERS = ("noreply@openai.com", "no-reply@openai.com", "@openai.com", ".openai.com")


def mask_config(config: dict[str, Any]) -> dict[str, Any]:
    return {
        key: ("***" if key in SECRET_FIELDS and value else value)
        for key, value in sorted((config or {}).items())
    }


def resolve_service(service_id: Optional[int]) -> EmailService:
    with get_db() as db:
        query = db.query(EmailService).filter(EmailService.enabled == True)  # noqa: E712
        if service_id:
            service = query.filter(EmailService.id == service_id).first()
            if not service:
                raise RuntimeError(f"未找到启用的邮箱服务 ID={service_id}")
            return service

        service = (
            query.filter(EmailService.service_type.in_(["catchall_pop3", "catchall_imap", "imap_mail"]))
            .order_by(EmailService.priority.asc(), EmailService.id.asc())
            .first()
        )
        if not service:
            raise RuntimeError("未找到启用的 catchall_pop3 / catchall_imap / imap_mail 邮箱服务")
        return service


def infer_pop_host(config: dict[str, Any]) -> str:
    explicit = str(config.get("pop_host") or config.get("pop3_host") or "").strip()
    if explicit:
        return explicit
    host = str(config.get("host") or "").strip()
    if host.startswith("imap."):
        return "pop." + host[len("imap.") :]
    if "163.com" in host:
        return "pop.163.com"
    return host


def build_effective_config(service: EmailService, default_pop_port: int) -> dict[str, Any]:
    config = dict(service.config or {})
    config["pop_host"] = infer_pop_host(config)
    config["pop_port"] = int(config.get("pop_port") or config.get("pop3_port") or default_pop_port)
    config["pop_use_ssl"] = bool(config.get("pop_use_ssl", True))
    return config


def decode_header_value(value: str) -> str:
    if value is None:
        return ""
    parts = decode_header(value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(str(part))
    return " ".join(decoded)


def connect_pop3(config: dict[str, Any], timeout: int) -> poplib.POP3:
    host = str(config.get("pop_host") or "").strip()
    port = int(config.get("pop_port") or 995)
    use_ssl = bool(config.get("pop_use_ssl", True))
    username = str(config.get("email") or "").strip()
    password = str(config.get("password") or "")

    socket.setdefaulttimeout(timeout)
    if use_ssl:
        client = poplib.POP3_SSL(host, port, timeout=timeout, context=ssl.create_default_context())
    else:
        client = poplib.POP3(host, port, timeout=timeout)
        try:
            client.stls(context=ssl.create_default_context())
        except Exception:
            pass
    client.user(username)
    client.pass_(password)
    return client


def print_stat(client: poplib.POP3) -> tuple[int, int]:
    count, size = client.stat()
    print(f"[STAT] messages={count}, total_size={size}")
    return count, size


def print_uidl(client: poplib.POP3, recent: int) -> list[int]:
    resp, items, _ = client.uidl()
    print(f"[UIDL] status={resp.decode(errors='ignore') if isinstance(resp, bytes) else resp}")
    indexes = []
    for raw in items[-recent:]:
        text = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
        print(f"  {text}")
        try:
            indexes.append(int(text.split()[0]))
        except Exception:
            pass
    return indexes


def extract_text_preview(msg) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                charset = part.get_content_charset() or "utf-8"
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode(charset, errors="replace")
    else:
        charset = msg.get_content_charset() or "utf-8"
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(charset, errors="replace")
    body = re.sub(r"\s+", " ", body).strip()
    return body[:240]


def sender_is_openai(sender: str) -> bool:
    sender_lower = str(sender or "").lower()
    return any(flag in sender_lower for flag in OPENAI_SENDERS)


def print_message_headers(client: poplib.POP3, indexes: list[int], alias: str) -> None:
    alias_lower = str(alias or "").strip().lower()
    if not indexes:
        print("[HEADERS] 没有可检查的邮件")
        return

    print("[HEADERS] 最近邮件详情")
    for idx in indexes:
        print(f"  [Message {idx}]")
        try:
            resp, lines, octets = client.top(idx, 0)
            print(f"    TOP={resp.decode(errors='ignore') if isinstance(resp, bytes) else resp}, octets={octets}")
            raw = b"\r\n".join(lines) + b"\r\n\r\n"
            msg = email.message_from_bytes(raw)
            fields = {
                "From": decode_header_value(msg.get("From", "")),
                "To": decode_header_value(msg.get("To", "")),
                "Delivered-To": decode_header_value(msg.get("Delivered-To", "")),
                "X-Original-To": decode_header_value(msg.get("X-Original-To", "")),
                "Envelope-To": decode_header_value(msg.get("Envelope-To", "")),
                "Subject": decode_header_value(msg.get("Subject", "")),
                "Date": decode_header_value(msg.get("Date", "")),
            }
            for key, value in fields.items():
                if value:
                    print(f"    {key}: {value}")
            sender = fields.get("From", "")
            if sender:
                print(f"    OpenAI Sender Match: {sender_is_openai(sender)}")
            if alias_lower:
                alias_hit = any(alias_lower in str(v).lower() for v in fields.values())
                print(f"    Alias Match({alias_lower}): {alias_hit}")

            try:
                resp_retr, retr_lines, retr_octets = client.retr(idx)
                print(f"    RETR={resp_retr.decode(errors='ignore') if isinstance(resp_retr, bytes) else resp_retr}, octets={retr_octets}")
                full_msg = email.message_from_bytes(b"\r\n".join(retr_lines))
                preview = extract_text_preview(full_msg)
                if preview:
                    print(f"    Body Preview: {preview}")
            except Exception as retr_err:
                print(f"    RETR_ERROR={type(retr_err).__name__}: {retr_err}")
        except Exception as e:
            print(f"    TOP_ERROR={type(e).__name__}: {e}")


def main() -> int:
    parser = argparse.ArgumentParser(description="独立 POP3 调试脚本")
    parser.add_argument("--service-id", type=int, default=0, help="邮箱服务 ID；默认自动选择 catchall_imap / imap_mail")
    parser.add_argument("--recent", type=int, default=5, help="检查最近几封邮件")
    parser.add_argument("--timeout", type=int, default=20, help="POP3 连接超时（秒）")
    parser.add_argument("--alias", default="", help="要匹配的别名邮箱地址，例如 xxxx@wzz28043.qzz.io")
    parser.add_argument("--pop-host", default="", help="覆盖 POP3 服务器地址")
    parser.add_argument("--pop-port", type=int, default=0, help="覆盖 POP3 端口")
    args = parser.parse_args()

    initialize_database()
    service = resolve_service(args.service_id or None)
    config = build_effective_config(service, default_pop_port=995)
    if args.pop_host:
        config["pop_host"] = args.pop_host.strip()
    if args.pop_port > 0:
        config["pop_port"] = int(args.pop_port)

    print("[SERVICE]")
    print(f"  id={service.id}")
    print(f"  type={service.service_type}")
    print(f"  name={service.name}")
    print(f"  config={mask_config(config)}")

    client = None
    try:
        print("[CONNECT] 正在连接并登录 POP3...")
        client = connect_pop3(config, timeout=max(5, int(args.timeout)))
        print("[CONNECT] 登录成功")
        count, _ = print_stat(client)
        indexes = print_uidl(client, recent=max(1, min(int(args.recent), count or 1)))
        print_message_headers(client, indexes, args.alias)
        return 0
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        return 1
    finally:
        if client is not None:
            try:
                client.quit()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
