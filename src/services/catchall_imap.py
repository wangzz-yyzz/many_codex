"""
Catch-all IMAP 邮箱服务
使用固定 IMAP 收件箱轮询邮件，但注册时生成随机别名地址。
"""

from __future__ import annotations

import email as py_email
import imaplib
import logging
import random
import string
import time
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Optional

from .imap_mail import ImapMailService
from .base import EmailServiceError
from ..config.constants import EmailServiceType


logger = logging.getLogger(__name__)


class CatchAllImapService(ImapMailService):
    """基于固定 IMAP 收件箱的 catch-all 随机邮箱服务。"""

    def __init__(self, config: Dict[str, Any] = None, name: str = None):
        super().__init__(config, name)
        cfg = config or {}
        catchall_domain = str(
            cfg.get("catchall_domain") or cfg.get("domain") or cfg.get("default_domain") or ""
        ).strip().lower()
        if not catchall_domain:
            raise ValueError("缺少必需配置: catchall_domain")
        self.service_type = EmailServiceType.CATCHALL_IMAP
        self.catchall_domain = catchall_domain
        self.local_part_length = max(4, int(cfg.get("local_part_length", 10) or 10))

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
        logger.info(f"Catch-all IMAP 未匹配到别名头: alias={alias_lower}")
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
        return {
            "email": email_addr,
            "service_id": email_addr,
            "id": email_addr,
            "source_email": self.email_addr,
            "catchall_domain": self.catchall_domain,
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
        seen_ids: set[str] = set()
        mail = None
        alias_email = str(email or email_id or "").strip().lower()

        try:
            mail = self._connect()
            selected_mailbox = self._select_mailbox(mail)
            if not selected_mailbox:
                self.update_status(False, EmailServiceError("未找到可用 IMAP 邮箱目录"))
                return None
            logger.info(f"Catch-all IMAP 已选择邮箱目录: {selected_mailbox}, alias={alias_email}")

            while time.time() - start_time < timeout:
                try:
                    status, data = mail.search(None, "UNSEEN")
                    if status != "OK" or not data or not data[0]:
                        time.sleep(3)
                        continue

                    msg_ids = data[0].split()
                    for msg_id in reversed(msg_ids):
                        id_str = msg_id.decode()
                        if id_str in seen_ids:
                            continue
                        seen_ids.add(id_str)

                        status, msg_data = mail.fetch(msg_id, "(RFC822)")
                        if status != "OK" or not msg_data:
                            continue

                        raw = msg_data[0][1]
                        msg = py_email.message_from_bytes(raw)

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
                            mail.store(msg_id, "+FLAGS", "\\Seen")
                            self.update_status(True)
                            logger.info(f"Catch-all IMAP 获取验证码成功: {alias_email} -> {code}")
                            return code

                except imaplib.IMAP4.error as e:
                    logger.debug(f"Catch-all IMAP 搜索邮件失败: {e}")
                    try:
                        self._select_mailbox(mail)
                    except Exception:
                        pass

                time.sleep(3)

        except Exception as e:
            logger.warning(f"Catch-all IMAP 连接/轮询失败: {e}")
            self.update_status(False, str(e))
        finally:
            if mail:
                try:
                    mail.logout()
                except Exception:
                    pass

        return None
