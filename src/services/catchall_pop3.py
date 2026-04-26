"""
Catch-all POP3 邮箱服务
使用固定 POP3 收件箱轮询邮件，但注册时生成随机别名地址。
"""

from __future__ import annotations

import email as py_email
import logging
import poplib
import random
import socket
import ssl
import string
import time
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Optional

from .base import EmailServiceError
from .imap_mail import ImapMailService
from ..config.constants import EmailServiceType


logger = logging.getLogger(__name__)


class CatchAllPop3Service(ImapMailService):
    """基于固定 POP3 收件箱的 catch-all 随机邮箱服务。"""

    def __init__(self, config: Dict[str, Any] = None, name: str = None):
        super().__init__(config, name)
        cfg = config or {}
        catchall_domain = str(
            cfg.get("catchall_domain") or cfg.get("domain") or cfg.get("default_domain") or ""
        ).strip().lower()
        if not catchall_domain:
            raise ValueError("缺少必需配置: catchall_domain")

        self.service_type = EmailServiceType.CATCHALL_POP3
        self.catchall_domain = catchall_domain
        self.local_part_length = max(4, int(cfg.get("local_part_length", 10) or 10))
        self.pop_host = str(cfg.get("pop_host") or cfg.get("pop3_host") or self._infer_pop_host(self.host)).strip()
        self.pop_port = int(cfg.get("pop_port", cfg.get("pop3_port", 995)) or 995)
        self.pop_use_ssl = bool(cfg.get("pop_use_ssl", True))
        self.recent_window = max(5, int(cfg.get("recent_window", 20) or 20))

    def _infer_pop_host(self, host: str) -> str:
        text = str(host or "").strip()
        if text.startswith("imap."):
            return "pop." + text[len("imap.") :]
        if "163.com" in text:
            return "pop.163.com"
        return text

    def _connect_pop3(self) -> poplib.POP3:
        socket.setdefaulttimeout(self.timeout)
        if self.pop_use_ssl:
            client = poplib.POP3_SSL(
                self.pop_host,
                self.pop_port,
                timeout=self.timeout,
                context=ssl.create_default_context(),
            )
        else:
            client = poplib.POP3(self.pop_host, self.pop_port, timeout=self.timeout)
            try:
                client.stls(context=ssl.create_default_context())
            except Exception:
                pass
        client.user(self.email_addr)
        client.pass_(self.password)
        return client

    def _generate_local_part(self, length: Optional[int] = None) -> str:
        actual_length = max(4, int(length or self.local_part_length))
        alphabet = string.ascii_lowercase + string.digits
        prefix = random.choice(string.ascii_lowercase)
        suffix = "".join(random.choice(alphabet) for _ in range(actual_length - 1))
        return f"{prefix}{suffix}"

    def _matches_alias(self, msg, alias_email: str) -> bool:
        alias_lower = str(alias_email or "").strip().lower()
        if not alias_lower:
            return True

        header_candidates = []
        for header_name in ("To", "Delivered-To", "X-Original-To", "Envelope-To", "Cc"):
            header_candidates.extend(msg.get_all(header_name, []))
        received_headers = msg.get_all("Received", [])
        header_candidates.extend(received_headers[:3])

        for raw_value in header_candidates:
            value = self._decode_str(raw_value).lower()
            if alias_lower in value:
                return True
        logger.info(f"Catch-all POP3 未匹配到别名头: alias={alias_lower}")
        return False

    def _is_recent_enough(self, msg, otp_sent_at: Optional[float]) -> bool:
        if not otp_sent_at:
            return True
        try:
            parsed = parsedate_to_datetime(msg.get("Date"))
            if parsed is None:
                return True
            return parsed.timestamp() >= (float(otp_sent_at) - 5.0)
        except Exception:
            return True

    def create_email(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        cfg = config or {}
        local_part = str(cfg.get("local_part") or "").strip().lower()
        if not local_part:
            local_part = self._generate_local_part(cfg.get("local_part_length"))
        email_addr = f"{local_part}@{self.catchall_domain}"
        self.update_status(True)
        logger.info(f"Catch-all POP3 生成随机邮箱: {email_addr}")
        return {
            "email": email_addr,
            "service_id": email_addr,
            "id": email_addr,
            "source_email": self.email_addr,
            "catchall_domain": self.catchall_domain,
            "pop_host": self.pop_host,
        }

    def get_verification_code(
        self,
        email: str,
        email_id: str = None,
        timeout: int = 60,
        pattern: str = None,
        otp_sent_at: Optional[float] = None,
    ) -> Optional[str]:
        start_time = time.time()
        seen_uids: set[str] = set()
        client = None
        alias_email = str(email or email_id or "").strip().lower()

        try:
            client = self._connect_pop3()
            logger.info(
                "Catch-all POP3 已连接: "
                f"host={self.pop_host}, port={self.pop_port}, alias={alias_email or '-'}"
            )

            while time.time() - start_time < timeout:
                try:
                    count, _ = client.stat()
                    if count <= 0:
                        time.sleep(3)
                        continue

                    resp, items, _ = client.uidl()
                    if not str(resp or "").upper().startswith("B'+OK") and resp != b"+OK":
                        logger.info(f"Catch-all POP3 UIDL 状态异常: {resp}")
                    candidates = items[-min(count, self.recent_window):]
                    logger.info(
                        "Catch-all POP3 正在检查最近邮件: "
                        f"count={count}, recent_window={min(count, self.recent_window)}"
                    )

                    for raw in reversed(candidates):
                        line = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
                        parts = line.split()
                        if len(parts) < 2:
                            continue
                        msg_index = int(parts[0])
                        uid = parts[1]
                        if uid in seen_uids:
                            continue
                        seen_uids.add(uid)

                        resp_retr, retr_lines, _ = client.retr(msg_index)
                        if not str(resp_retr or "").upper().startswith("B'+OK") and resp_retr != b"+OK":
                            continue

                        msg = py_email.message_from_bytes(b"\r\n".join(retr_lines))
                        from_addr = self._decode_str(msg.get("From", ""))
                        if not self._is_openai_sender(from_addr):
                            continue
                        if not self._matches_alias(msg, alias_email):
                            continue
                        if not self._is_recent_enough(msg, otp_sent_at):
                            continue

                        body = self._get_text_body(msg)
                        code = self._extract_otp(body)
                        if code:
                            self.update_status(True)
                            logger.info(f"Catch-all POP3 获取验证码成功: {alias_email} -> {code}")
                            return code

                except poplib.error_proto as e:
                    logger.warning(f"Catch-all POP3 轮询失败: {e}")
                    self.update_status(False, EmailServiceError(str(e)))
                except Exception as e:
                    logger.warning(f"Catch-all POP3 解析邮件失败: {e}")
                    self.update_status(False, str(e))

                time.sleep(3)

        except Exception as e:
            logger.warning(f"Catch-all POP3 连接/轮询失败: {e}")
            self.update_status(False, str(e))
        finally:
            if client:
                try:
                    client.quit()
                except Exception:
                    pass

        self.update_status(False, EmailServiceError("等待验证码超时"))
        return None
