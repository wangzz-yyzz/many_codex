"""独立 IMAP 调试脚本：列目录、逐个 select/status，并抓取最近邮件头。"""

from __future__ import annotations

import argparse
import base64
import email
import imaplib
import re
import sys
from pathlib import Path
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.database.init_db import initialize_database  # noqa: E402
from src.database.models import EmailService  # noqa: E402
from src.database.session import get_db  # noqa: E402


SECRET_FIELDS = {"password", "api_key", "refresh_token", "access_token", "admin_token", "admin_password"}
DEFAULT_MAILBOX_CANDIDATES = ["INBOX", "Inbox", "inbox"]


def mask_config(config: dict[str, Any]) -> dict[str, Any]:
    return {
        key: ("***" if key in SECRET_FIELDS and value else value)
        for key, value in sorted((config or {}).items())
    }


def decode_imap_utf7(text: str) -> str:
    result: list[str] = []
    i = 0
    while i < len(text):
        if text[i] != "&":
            j = text.find("&", i)
            if j == -1:
                j = len(text)
            result.append(text[i:j])
            i = j
            continue

        j = text.find("-", i)
        if j == -1:
            result.append(text[i:])
            break

        payload = text[i + 1 : j]
        if payload == "":
            result.append("&")
        else:
            b64 = payload.replace(",", "/")
            padding = "=" * ((4 - len(b64) % 4) % 4)
            raw = base64.b64decode(b64 + padding)
            result.append(raw.decode("utf-16-be", errors="replace"))
        i = j + 1
    return "".join(result)


def parse_list_line(raw_line: Any) -> tuple[str, str]:
    text = raw_line.decode(errors="replace") if isinstance(raw_line, bytes) else str(raw_line)
    match = re.search(r'"([^"]+)"$', text)
    mailbox = match.group(1) if match else text.rsplit(" ", 1)[-1]
    mailbox = mailbox.strip('"')
    return text, mailbox


def resolve_service(service_id: Optional[int]) -> EmailService:
    with get_db() as db:
        query = db.query(EmailService).filter(EmailService.enabled == True)  # noqa: E712
        if service_id:
            service = query.filter(EmailService.id == service_id).first()
            if not service:
                raise RuntimeError(f"未找到启用的邮箱服务 ID={service_id}")
            return service

        service = (
            query.filter(EmailService.service_type.in_(["catchall_imap", "imap_mail"]))
            .order_by(EmailService.priority.asc(), EmailService.id.asc())
            .first()
        )
        if not service:
            raise RuntimeError("未找到启用的 catchall_imap / imap_mail 邮箱服务")
        return service


def build_effective_config(service: EmailService, catchall_domain: str) -> dict[str, Any]:
    config = dict(service.config or {})
    if service.service_type == "imap_mail":
        config["catchall_domain"] = (
            str(
                config.get("catchall_domain")
                or config.get("default_domain")
                or config.get("domain")
                or catchall_domain
            ).strip()
        )
    return config


def connect_imap(config: dict[str, Any]) -> imaplib.IMAP4:
    host = str(config.get("host") or "").strip()
    port = int(config.get("port", 993) or 993)
    use_ssl = bool(config.get("use_ssl", True))
    username = str(config.get("email") or "").strip()
    password = str(config.get("password") or "")
    if use_ssl:
        mail = imaplib.IMAP4_SSL(host, port)
    else:
        mail = imaplib.IMAP4(host, port)
        mail.starttls()
    mail.login(username, password)
    return mail


def list_mailboxes(mail: imaplib.IMAP4) -> list[tuple[str, str, str]]:
    status, data = mail.list()
    if status != "OK":
        print(f"[LIST] status={status}")
        return []

    rows: list[tuple[str, str, str]] = []
    print("[LIST] 目录列表")
    for idx, line in enumerate(data or [], start=1):
        raw_text, mailbox_token = parse_list_line(line)
        decoded_name = decode_imap_utf7(mailbox_token) if mailbox_token.startswith("&") else mailbox_token
        rows.append((raw_text, mailbox_token, decoded_name))
        print(f"  {idx}. raw={raw_text}")
        print(f"     token={mailbox_token}")
        print(f"     decoded={decoded_name}")
    return rows


def print_status(mail: imaplib.IMAP4, mailbox_token: str) -> None:
    try:
        status_resp = mail.status(mailbox_token, "(MESSAGES UNSEEN RECENT UIDNEXT UIDVALIDITY)")
        print(f"     STATUS={status_resp[0]} {status_resp[1]}")
    except Exception as e:
        print(f"     STATUS_ERROR={type(e).__name__}: {e}")


def fetch_recent_headers(mail: imaplib.IMAP4, mailbox_token: str, recent: int) -> None:
    try:
        status, data = mail.search(None, "ALL")
        print(f"     SEARCH_ALL={status}")
        if status != "OK" or not data or not data[0]:
            print("     无邮件或搜索失败")
            return
        ids = data[0].split()
        target_ids = ids[-recent:]
        print(f"     最近邮件数量={len(ids)}，展示最后 {len(target_ids)} 封")
        for msg_id in target_ids:
            fetch_status, msg_data = mail.fetch(msg_id, "(BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE DELIVERED-TO X-ORIGINAL-TO ENVELOPE-TO)])")
            print(f"       FETCH {msg_id.decode()} -> {fetch_status}")
            if fetch_status != "OK" or not msg_data:
                continue
            raw_header = msg_data[0][1]
            msg = email.message_from_bytes(raw_header)
            fields = {
                "From": msg.get("From", ""),
                "To": msg.get("To", ""),
                "Delivered-To": msg.get("Delivered-To", ""),
                "X-Original-To": msg.get("X-Original-To", ""),
                "Envelope-To": msg.get("Envelope-To", ""),
                "Subject": msg.get("Subject", ""),
                "Date": msg.get("Date", ""),
            }
            for key, value in fields.items():
                if value:
                    print(f"         {key}: {value}")
    except Exception as e:
        print(f"     FETCH_ERROR={type(e).__name__}: {e}")


def probe_mailboxes(mail: imaplib.IMAP4, rows: list[tuple[str, str, str]], recent: int) -> None:
    seen = set()
    ordered_tokens = []
    for token in DEFAULT_MAILBOX_CANDIDATES + [row[1] for row in rows]:
        key = str(token or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        ordered_tokens.append(key)

    print("[PROBE] 逐个尝试 SELECT/STATUS/FETCH")
    for idx, token in enumerate(ordered_tokens, start=1):
        decoded = decode_imap_utf7(token) if token.startswith("&") else token
        print(f"  {idx}. mailbox={token} decoded={decoded}")
        try:
            select_status, select_data = mail.select(token, readonly=True)
            print(f"     SELECT={select_status} {select_data}")
            print_status(mail, token)
            if select_status == "OK":
                fetch_recent_headers(mail, token, recent)
        except Exception as e:
            print(f"     SELECT_ERROR={type(e).__name__}: {e}")


def main() -> int:
    parser = argparse.ArgumentParser(description="独立 IMAP 调试脚本")
    parser.add_argument("--service-id", type=int, default=0, help="邮箱服务 ID；默认自动选择 catchall_imap / imap_mail")
    parser.add_argument("--catchall-domain", default="wzz28043.qzz.io", help="当复用 imap_mail 时附带的 catch-all 域名")
    parser.add_argument("--recent", type=int, default=3, help="每个可选目录抓取最近几封邮件头")
    args = parser.parse_args()

    initialize_database()
    service = resolve_service(args.service_id or None)
    effective_config = build_effective_config(service, args.catchall_domain)

    print("[SERVICE]")
    print(f"  id={service.id}")
    print(f"  type={service.service_type}")
    print(f"  name={service.name}")
    print(f"  config={mask_config(effective_config)}")

    mail = None
    try:
        print("[CONNECT] 正在连接并登录 IMAP...")
        mail = connect_imap(effective_config)
        print("[CONNECT] 登录成功")
        rows = list_mailboxes(mail)
        probe_mailboxes(mail, rows, max(1, args.recent))
        return 0
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        return 1
    finally:
        if mail is not None:
            try:
                mail.logout()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
