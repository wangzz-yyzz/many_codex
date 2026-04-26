"""
注册流程引擎
从 main.py 中提取并重构的注册流程
"""

import asyncio
import importlib
import re
import json
import time
import logging
import random
import secrets
import string
import sys
import uuid
import urllib.parse
from typing import Optional, Dict, Any, Tuple, Callable, List
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from curl_cffi import requests as cffi_requests

from .anyauto.register_flow import AnyAutoRegistrationEngine
from .anyauto.utils import build_browser_headers, generate_datadog_trace
from .anyauto.sentinel_token import build_sentinel_token
from .openai.oauth import OAuthManager, OAuthStart
from .http_client import OpenAIHTTPClient, HTTPClientError
from ..services import EmailServiceFactory, BaseEmailService, EmailServiceType
from ..database import crud
from ..database.session import get_db
from ..config.constants import (
    OPENAI_API_ENDPOINTS,
    OPENAI_PAGE_TYPES,
    generate_random_user_info,
    OTP_CODE_PATTERN,
    DEFAULT_PASSWORD_LENGTH,
    PASSWORD_SPECIAL_CHARSET,
    PASSWORD_CHARSET,
    AccountStatus,
    TaskStatus,
)
from ..config.settings import get_settings


logger = logging.getLogger(__name__)


class RegistrationCancelledError(asyncio.CancelledError):
    """注册任务收到取消请求时抛出的协作式取消异常。"""


@dataclass
class RegistrationResult:
    """注册结果"""
    success: bool
    email: str = ""
    password: str = ""  # 注册密码
    account_id: str = ""
    workspace_id: str = ""
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    session_token: str = ""  # 会话令牌
    device_id: str = ""  # oai-did
    error_message: str = ""
    logs: list = None
    metadata: dict = None
    source: str = "register"  # 'register' 或 'login'，区分账号来源

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "success": self.success,
            "email": self.email,
            "password": self.password,
            "account_id": self.account_id,
            "workspace_id": self.workspace_id,
            "access_token": self.access_token[:20] + "..." if self.access_token else "",
            "refresh_token": self.refresh_token[:20] + "..." if self.refresh_token else "",
            "id_token": self.id_token[:20] + "..." if self.id_token else "",
            "session_token": self.session_token[:20] + "..." if self.session_token else "",
            "device_id": self.device_id,
            "error_message": self.error_message,
            "logs": self.logs or [],
            "metadata": self.metadata or {},
            "source": self.source,
        }


@dataclass
class SignupFormResult:
    """提交注册表单的结果"""
    success: bool
    page_type: str = ""  # 响应中的 page.type 字段
    is_existing_account: bool = False  # 是否为已注册账号
    response_data: Dict[str, Any] = None  # 完整的响应数据
    error_message: str = ""
    current_url: str = ""


class RegistrationEngine:
    """
    注册引擎
    负责协调邮箱服务、OAuth 流程和 OpenAI API 调用
    """

    def __init__(
        self,
        email_service: BaseEmailService,
        proxy_url: Optional[str] = None,
        callback_logger: Optional[Callable[[str], None]] = None,
        task_uuid: Optional[str] = None,
        check_cancelled: Optional[Callable[[], bool]] = None,
    ):
        """
        初始化注册引擎

        Args:
            email_service: 邮箱服务实例
            proxy_url: 代理 URL
            callback_logger: 日志回调函数
            task_uuid: 任务 UUID（用于数据库记录）
            check_cancelled: 取消检查回调（返回 True 表示任务应尽快停止）
        """
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.callback_logger = callback_logger or (lambda msg: logger.info(msg))
        self.task_uuid = task_uuid
        self._check_cancelled = check_cancelled or (lambda: False)

        # 每个注册流程随机一组浏览器指纹，降低固定指纹触发风控的概率。
        fingerprint = self._random_chrome_fingerprint()
        self._fingerprint_impersonate: str = str(fingerprint["impersonate"])
        self._fingerprint_user_agent: str = str(fingerprint["user_agent"])
        self._fingerprint_sec_ch_ua: str = str(fingerprint["sec_ch_ua"])
        self._fingerprint_chrome_full: str = str(fingerprint["chrome_full"])
        self._fingerprint_accept_language: str = random.choice(
            [
                "en-US,en;q=0.9",
                "en-US,en;q=0.9,zh-CN;q=0.8",
                "en,en-US;q=0.9",
                "en-US,en;q=0.8",
            ]
        )

        # 创建 HTTP 客户端
        self.http_client = OpenAIHTTPClient(proxy_url=proxy_url)
        self.http_client.config.impersonate = self._fingerprint_impersonate
        self.http_client.default_headers["User-Agent"] = self._fingerprint_user_agent
        self.http_client.default_headers["Accept-Language"] = self._fingerprint_accept_language
        self.http_client.default_headers["sec-ch-ua"] = self._fingerprint_sec_ch_ua
        self.http_client.default_headers["sec-ch-ua-mobile"] = "?0"
        self.http_client.default_headers["sec-ch-ua-platform"] = '"Windows"'

        # 创建 OAuth 管理器
        settings = get_settings()
        self.oauth_manager = OAuthManager(
            client_id=settings.openai_client_id,
            auth_url=settings.openai_auth_url,
            token_url=settings.openai_token_url,
            redirect_uri=settings.openai_redirect_uri,
            scope=settings.openai_scope,
            proxy_url=proxy_url  # 传递代理配置
        )
        entry_flow = str(getattr(settings, "registration_entry_flow", "native") or "native").strip().lower()
        # 配置层仅保留 native/abcard；Outlook 邮箱在执行时自动切换 outlook 链路。
        self.registration_entry_flow: str = entry_flow if entry_flow in {"native", "abcard"} else "native"

        # 状态变量
        self.email: Optional[str] = None
        self.inbox_email: Optional[str] = None  # 邮箱服务原始地址（用于收件）
        self.password: Optional[str] = None  # 注册密码
        self.email_info: Optional[Dict[str, Any]] = None
        self.oauth_start: Optional[OAuthStart] = None
        self.session: Optional[cffi_requests.Session] = None
        self.session_token: Optional[str] = None  # 会话令牌
        self.device_id: Optional[str] = None  # oai-did
        self.logs: list = []
        self._otp_sent_at: Optional[float] = None  # OTP 发送时间戳
        self._is_existing_account: bool = False  # 是否为已注册账号（用于自动登录）
        self._token_acquisition_requires_login: bool = False  # 新注册账号需要二次登录拿 token
        self._create_account_continue_url: Optional[str] = None  # create_account 返回的 continue_url（ABCard链路兜底）
        self._create_account_workspace_id: Optional[str] = None
        self._create_account_account_id: Optional[str] = None
        self._create_account_refresh_token: Optional[str] = None
        self._last_create_account_error: Optional[str] = None
        self._last_validate_otp_continue_url: Optional[str] = None
        self._last_validate_otp_workspace_id: Optional[str] = None
        self._last_register_password_error: Optional[str] = None
        self._last_otp_validation_code: Optional[str] = None
        self._last_otp_validation_status_code: Optional[int] = None
        self._last_otp_validation_outcome: str = ""  # success/http_non_200/network_timeout/network_error
        self._last_otp_validation_error_detail: str = ""
        self._last_send_otp_status_code: Optional[int] = None
        self._last_send_otp_error_detail: str = ""
        self._last_send_otp_page_type: str = ""
        self._last_send_otp_current_url: str = ""
        self._last_auth_page_url: str = ""
        self._oauth_bootstrap_final_url: str = ""
        self._prewarm_authorize_url: str = ""
        self._prewarm_authorize_final_url: str = ""
        self._allow_prewarm_bootstrap_bypass: bool = False
        self._last_signup_rate_limit_session_ended: bool = False
        self._rate_limit_max_attempts: int = 3
        self._rate_limit_wait_seconds: float = 5.0
        self._cached_oai_client_auth_session: Dict[str, Any] = {}
        self._cached_oai_client_auth_info: Dict[str, Any] = {}

    def _is_cancel_requested(self) -> bool:
        try:
            return bool(self._check_cancelled())
        except Exception:
            return False

    @staticmethod
    def _random_chrome_fingerprint() -> Dict[str, str]:
        profiles = [
            {
                "major": 131,
                "impersonate": "chrome131",
                "build": 6778,
                "patch_range": (69, 205),
                "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            },
            {
                "major": 133,
                "impersonate": "chrome133a",
                "build": 6943,
                "patch_range": (33, 153),
                "sec_ch_ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
            },
            {
                "major": 136,
                "impersonate": "chrome136",
                "build": 7103,
                "patch_range": (48, 175),
                "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
            },
        ]
        profile = random.choice(profiles)
        patch = random.randint(*profile["patch_range"])
        chrome_full = f"{profile['major']}.0.{profile['build']}.{patch}"
        return {
            "impersonate": str(profile["impersonate"]),
            "chrome_full": chrome_full,
            "sec_ch_ua": str(profile["sec_ch_ua"]),
            "user_agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_full} Safari/537.36"
            ),
        }

    def _apply_browser_fingerprint_to_session(self) -> None:
        if not self.session:
            return
        try:
            self.session.headers.update(
                {
                    "User-Agent": self._fingerprint_user_agent,
                    "Accept-Language": self._fingerprint_accept_language,
                    "sec-ch-ua": self._fingerprint_sec_ch_ua,
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": '"Windows"',
                    "sec-ch-ua-arch": '"x86"',
                    "sec-ch-ua-bitness": '"64"',
                    "sec-ch-ua-full-version": f'"{self._fingerprint_chrome_full}"',
                    "sec-ch-ua-platform-version": f'"{random.randint(10, 15)}.0.0"',
                }
            )
        except Exception:
            pass

    def _seed_oai_device_cookie(self, did: str) -> None:
        if not self.session or not did:
            return
        for domain in (
            "chatgpt.com",
            ".chatgpt.com",
            "openai.com",
            ".openai.com",
            "auth.openai.com",
            ".auth.openai.com",
        ):
            try:
                self.session.cookies.set("oai-did", did, domain=domain, path="/")
            except Exception:
                continue

    @staticmethod
    def _append_authorize_hint_params(auth_url: str, did: str) -> str:
        """对齐 arr：给 authorize URL 补充 ext-oai-did 与 auth_session_logging_id。"""
        try:
            parsed = urllib.parse.urlparse(str(auth_url or "").strip())
            if not parsed.scheme or not parsed.netloc:
                return auth_url
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if did and not query.get("ext-oai-did"):
                query["ext-oai-did"] = [did]
            if not query.get("auth_session_logging_id"):
                query["auth_session_logging_id"] = [str(uuid.uuid4())]
            new_query = urllib.parse.urlencode(query, doseq=True)
            return urllib.parse.urlunparse(parsed._replace(query=new_query))
        except Exception:
            return auth_url

    def _split_authorize_request(self, did: str) -> Tuple[str, Dict[str, Any]]:
        """把完整 auth_url 拆成 aar 同款的 authorize_url + params。"""
        auth_url = self._append_authorize_hint_params(
            str(getattr(self.oauth_start, "auth_url", "") or "").strip(),
            did,
        )
        parsed = urllib.parse.urlparse(auth_url)
        if not parsed.scheme or not parsed.netloc:
            return "", {}

        params: Dict[str, Any] = {}
        for key, values in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items():
            if not values:
                params[key] = ""
            elif len(values) == 1:
                params[key] = values[0]
            else:
                params[key] = values

        params.setdefault("audience", "https://api.openai.com/v1")
        params.setdefault("prompt", "login")
        params.setdefault("screen_hint", "login_or_signup")
        params.setdefault("ext-passkey-client-capabilities", "1111")
        params.setdefault("codex_cli_simplified_flow", "true")
        params.setdefault("id_token_add_organizations", "true")
        if did:
            params.setdefault("ext-oai-did", did)
        if self.email:
            params.setdefault("login_hint", str(self.email or "").strip())
        if not str(params.get("scope") or "").strip():
            params["scope"] = "openid profile email offline_access"

        authorize_url = urllib.parse.urlunparse(
            parsed._replace(query="", params="", fragment="")
        )
        return authorize_url, params

    @staticmethod
    def _parse_url_query(url: str) -> Dict[str, str]:
        try:
            parsed = urllib.parse.urlparse(str(url or "").strip())
            if not parsed.scheme or not parsed.netloc:
                return {}
            data: Dict[str, str] = {}
            for key, values in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items():
                if not values:
                    data[key] = ""
                else:
                    data[key] = str(values[-1] or "")
            return data
        except Exception:
            return {}

    def _log_authorize_url_diff(self, did: str) -> None:
        """对比 prewarm authorize URL 与 oauth_start.auth_url 的 query 差异。"""
        oauth_auth_url = self._append_authorize_hint_params(
            str(getattr(self.oauth_start, "auth_url", "") or "").strip(),
            did,
        )
        prewarm_auth_url = str(self._prewarm_authorize_url or "").strip()
        if not oauth_auth_url or not prewarm_auth_url:
            return

        oauth_query = self._parse_url_query(oauth_auth_url)
        prewarm_query = self._parse_url_query(prewarm_auth_url)
        oauth_keys = set(oauth_query.keys())
        prewarm_keys = set(prewarm_query.keys())
        only_in_prewarm = sorted(prewarm_keys - oauth_keys)
        only_in_oauth = sorted(oauth_keys - prewarm_keys)
        changed = sorted(
            key for key in (oauth_keys & prewarm_keys)
            if str(oauth_query.get(key) or "") != str(prewarm_query.get(key) or "")
        )
        changed_preview = [
            f"{key}=prewarm:{str(prewarm_query.get(key) or '')[:24]}|oauth:{str(oauth_query.get(key) or '')[:24]}"
            for key in changed[:6]
        ]
        self._log(
            "authorize URL 差异: "
            f"prewarm_only={','.join(only_in_prewarm[:8]) or '-'}; "
            f"oauth_only={','.join(only_in_oauth[:8]) or '-'}; "
            f"changed={'; '.join(changed_preview) or '-'}"
        )

    def _has_prewarm_auth_ready_state(self) -> bool:
        target = str(
            self._prewarm_authorize_final_url
            or self._oauth_bootstrap_final_url
            or self._last_auth_page_url
            or ""
        ).strip().lower()
        return "auth.openai.com/create-account/password" in target

    def _is_prewarm_bad_terminal_state(self) -> bool:
        target = str(
            self._prewarm_authorize_final_url
            or self._last_auth_page_url
            or ""
        ).strip().lower()
        if not target:
            return False
        bad_markers = (
            "auth.openai.com/error",
            "auth.openai.com/email-verification",
        )
        return any(marker in target for marker in bad_markers)

    def _raise_if_cancelled(self, reason: str = "任务已取消") -> None:
        if self._is_cancel_requested():
            raise RegistrationCancelledError(reason)

    def _sleep_interruptible(self, seconds: float) -> None:
        remaining = max(0.0, float(seconds or 0.0))
        while remaining > 0:
            self._raise_if_cancelled("任务在等待重试阶段被取消")
            chunk = min(0.2, remaining)
            time.sleep(chunk)
            remaining -= chunk

    def _browser_pause(self, low: float = 0.15, high: float = 0.4) -> None:
        self._sleep_interruptible(random.uniform(low, high))

    def _build_browser_headers(
        self,
        url: str,
        *,
        accept: str,
        referer: Optional[str] = None,
        origin: Optional[str] = None,
        content_type: Optional[str] = None,
        navigation: bool = False,
        fetch_mode: Optional[str] = None,
        fetch_dest: Optional[str] = None,
        fetch_site: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        return build_browser_headers(
            url=url,
            user_agent=self._fingerprint_user_agent,
            sec_ch_ua=self._fingerprint_sec_ch_ua,
            chrome_full_version=self._fingerprint_chrome_full,
            accept=accept,
            accept_language=self._fingerprint_accept_language,
            referer=referer,
            origin=origin,
            content_type=content_type,
            navigation=navigation,
            fetch_mode=fetch_mode,
            fetch_dest=fetch_dest,
            fetch_site=fetch_site,
            headed=False,
            extra_headers=extra_headers,
        )

    @staticmethod
    def _parse_retry_after_seconds(value: Any) -> float:
        try:
            text = str(value or "").strip()
            if not text:
                return 0.0
            return max(0.0, float(text))
        except Exception:
            return 0.0

    def _compute_rate_limit_backoff(self, attempt: int, retry_after: float, max_wait: Optional[float] = None) -> float:
        # 调试阶段尽量减少限流等待，加快暴露真实阻断点。
        _ = attempt
        if max_wait is None:
            max_wait = float(self._rate_limit_wait_seconds or 2.0)
        server_wait = min(max_wait, max(0.0, float(retry_after or 0.0)))
        return max(1.0, min(max_wait, max(float(self._rate_limit_wait_seconds or 2.0), server_wait)))

    def _bootstrap_oauth_session(self, did: str, stage: str) -> str:
        """对齐 aar：显式 bootstrap auth 会话，优先建立 login_session。"""
        if not self.session or not self.oauth_start:
            return ""

        authorize_url, authorize_params = self._split_authorize_request(did)
        if not authorize_url:
            self._log(f"{stage}: OAuth URL 无法拆分 bootstrap 参数", "warning")
            return ""

        self._seed_oai_device_cookie(did)
        final_url = ""
        prewarm_authorize_url = str(self._prewarm_authorize_url or "").strip()
        request_plan = []
        if prewarm_authorize_url:
            request_plan.append((prewarm_authorize_url, None, "Bootstrap prewarm authorize"))
        request_plan.extend([
            (authorize_url, "Bootstrap /oauth/authorize"),
            ("https://auth.openai.com/api/oauth/oauth2/auth", "Bootstrap /api/oauth/oauth2/auth"),
        ])
        normalized_plan = []
        for item in request_plan:
            if len(item) == 3:
                normalized_plan.append(item)
            else:
                request_url, label = item
                normalized_plan.append((request_url, authorize_params, label))

        for request_url, request_params, label in normalized_plan:
            try:
                headers = self._build_browser_headers(
                    request_url,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    referer="https://chatgpt.com/",
                    navigation=True,
                )
                headers.update(generate_datadog_trace())
                self._browser_pause()
                response = self.session.get(
                    request_url,
                    params=request_params,
                    headers=headers,
                    allow_redirects=True,
                    timeout=20,
                )
                self._capture_auth_cookies_from_response(response, f"{stage} {label}")
                final_url = str(getattr(response, "url", "") or "").strip()
                redirects = len(getattr(response, "history", []) or [])
                self._log(f"{stage}: {label} -> {response.status_code}, redirects={redirects}")
                if final_url:
                    self._last_auth_page_url = final_url
                if response.status_code == 429:
                    retry_after = self._parse_retry_after_seconds(response.headers.get("Retry-After"))
                    request_id = str(response.headers.get("x-request-id") or "").strip()
                    extra = ""
                    if retry_after > 0:
                        extra += f", retry_after={retry_after:.0f}s"
                    if request_id:
                        extra += f", request_id={request_id}"
                    self._log(f"{stage}: {label} 命中 429{extra}", "warning")
                    return ""
                self._log_oauth_session_quality(f"{stage} {label} 后")
                if self._has_session_cookie("login_session"):
                    self._oauth_bootstrap_final_url = final_url or request_url
                    return self._oauth_bootstrap_final_url
                if request_url == authorize_url:
                    self._log(f"{stage}: 首轮未拿到 login_session，继续尝试 oauth2/auth", "warning")
            except Exception as e:
                self._log(f"{stage}: {label} 异常: {e}", "warning")
        return ""

    def _refresh_oauth_context(self, did: str) -> None:
        """命中限流后重新 bootstrap auth 链路，重建 login_session。"""
        _ = self._bootstrap_oauth_session(did, "OAuth 上下文预热")

    def _has_session_cookie(self, cookie_name: str) -> bool:
        try:
            if not self.session:
                return False
            try:
                direct_value = str(self.session.cookies.get(cookie_name) or "").strip()
                if direct_value:
                    return True
            except Exception:
                pass
            for cookie in (self.session.cookies or []):
                name = str(getattr(cookie, "name", "") or "").strip()
                if name == cookie_name:
                    return True
        except Exception:
            return False
        return False

    def _log_oauth_session_quality(self, stage: str) -> None:
        try:
            if not self.session:
                self._log(f"{stage}: 当前无 session", "warning")
                return
            names = []
            try:
                for key, value in self.session.cookies.items():
                    if str(key or "").strip() and str(value or "").strip():
                        names.append(str(key or "").strip())
            except Exception:
                pass
            for cookie in (self.session.cookies or []):
                name = str(getattr(cookie, "name", "") or "").strip()
                domain = str(getattr(cookie, "domain", "") or "").strip()
                if name and ("openai.com" in domain or "chatgpt.com" in domain or name in {"login_session", "oai-did"}):
                    names.append(name)
            deduped = []
            seen = set()
            for name in names:
                if name in seen:
                    continue
                seen.add(name)
                deduped.append(name)
            auth_session_ready = bool(
                self.session.cookies.get("oai-client-auth-session") or self._cached_oai_client_auth_session
            )
            auth_info_ready = bool(
                self.session.cookies.get("oai-client-auth-info") or self._cached_oai_client_auth_info
            )
            self._log(
                f"{stage}: login_session={'有' if self._has_session_cookie('login_session') else '无'}, "
                f"oai-did={'有' if self._has_session_cookie('oai-did') else '无'}, "
                f"auth_session={'有' if auth_session_ready else '无'}, "
                f"auth_info={'有' if auth_info_ready else '无'}, "
                f"cookies={','.join(deduped[:8]) or '-'}"
            )
        except Exception as e:
            self._log(f"{stage}: 记录 session 质量异常: {e}", "warning")

    def _ensure_login_session(self, did: str, stage: str, max_rounds: int = 2) -> bool:
        """确保 auth 域上已有 login_session，否则提前视为坏会话。"""
        current_did = str(did or self.device_id or "").strip()
        self._log_oauth_session_quality(f"{stage} 前")
        if self._has_session_cookie("login_session"):
            return True

        for round_idx in range(1, max_rounds + 1):
            self._log(f"{stage}: 未检测到 login_session，开始第 {round_idx}/{max_rounds} 轮 auth 预热", "warning")
            self._refresh_oauth_context(current_did)
            self._log_oauth_session_quality(f"{stage} 预热后")
            if self._has_session_cookie("login_session"):
                return True
            if round_idx < max_rounds:
                self._sleep_interruptible(2)
        return False

    def _resolve_authorize_continue_referer(self, fallback_url: str, *, prefer_bootstrap: bool = False) -> str:
        """优先复用 bootstrap 后的真实 auth 页面，避免写死 create-account/log-in。"""
        fallback = str(fallback_url or "https://auth.openai.com/log-in").strip()
        if not prefer_bootstrap:
            return fallback
        candidate = str(self._oauth_bootstrap_final_url or self._last_auth_page_url or "").strip()
        lower_candidate = candidate.lower()
        if candidate.startswith("https://auth.openai.com/") and all(
            marker not in lower_candidate for marker in ("oauth/authorize", "oauth2/auth")
        ):
            return candidate
        return fallback

    def _refresh_create_account_password_page(self) -> str:
        """刷新 create-account/password 页面，重建 user/register 所需状态。"""
        if not self.session:
            return ""
        try:
            url = "https://auth.openai.com/create-account/password"
            headers = self._build_browser_headers(
                url,
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                referer="https://auth.openai.com/create-account",
                navigation=True,
            )
            headers.update(generate_datadog_trace())
            self._browser_pause()
            response = self.session.get(url, headers=headers, allow_redirects=True, timeout=20)
            self._capture_auth_cookies_from_response(response, "刷新 create-account/password 页面")
            final_url = str(getattr(response, "url", "") or "").strip()
            if final_url:
                self._last_auth_page_url = final_url
                self._log(f"刷新 create-account/password 页面完成: {final_url[:160]}")
            login_session_exists = any(
                (getattr(cookie, "name", str(cookie)) == "login_session") for cookie in (self.session.cookies or [])
            )
            self._log(f"create-account/password 页面刷新后 login_session={'有' if login_session_exists else '无'}")
            return final_url
        except Exception as e:
            self._log(f"刷新 create-account/password 页面异常: {e}", "warning")
            return ""

    def _refresh_about_you_page(self) -> str:
        """访问 about-you 页面，尽量让 create_account 前的 auth 状态落稳。"""
        if not self.session:
            return ""
        try:
            candidate = str(self._last_validate_otp_continue_url or "").strip()
            url = candidate if candidate.startswith("https://auth.openai.com/") else "https://auth.openai.com/about-you"
            headers = self._build_browser_headers(
                url,
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                referer="https://auth.openai.com/email-verification",
                navigation=True,
            )
            headers.update(generate_datadog_trace())
            self._browser_pause()
            response = self.session.get(url, headers=headers, allow_redirects=True, timeout=20)
            self._capture_auth_cookies_from_response(response, "刷新 about-you 页面")
            final_url = str(getattr(response, "url", "") or "").strip()
            if final_url:
                self._last_auth_page_url = final_url
            self._log(f"刷新 about-you 页面完成: {(final_url or url)[:160]}")
            self._log_oauth_session_quality("about-you 页面刷新后")
            return final_url or url
        except Exception as e:
            self._log(f"刷新 about-you 页面异常: {e}", "warning")
            return ""

    def _get_browser_sentinel_token(
        self,
        flow: str,
        *,
        page_url: str,
        device_id: str,
    ) -> str:
        """优先复用 aar 的浏览器 Sentinel helper，失败再回退现有 HTTP PoW。"""
        try:
            aar_root = Path(__file__).resolve().parents[2] / "aar"
            if not aar_root.exists():
                return ""

            aar_root_str = str(aar_root)
            if aar_root_str not in sys.path:
                sys.path.insert(0, aar_root_str)
            sentinel_mod = importlib.import_module("chatgpt.sentinel_browser")
            get_token = getattr(sentinel_mod, "get_sentinel_token_via_browser", None)
            quickjs_token = getattr(sentinel_mod, "_get_sentinel_token_via_quickjs", None)
            token = ""
            if callable(get_token):
                token = str(
                    get_token(
                        flow=flow,
                        proxy=self.proxy_url,
                        page_url=page_url,
                        headless=True,
                        device_id=device_id,
                        log_fn=lambda msg: self._log(f"{flow}: {msg}"),
                    ) or ""
                ).strip()
            if (not token) and callable(quickjs_token):
                token = str(
                    quickjs_token(
                        flow=flow,
                        proxy=self.proxy_url,
                        timeout_ms=45000,
                        device_id=device_id,
                        logger=lambda msg: self._log(f"{flow}: {msg}"),
                    ) or ""
                ).strip()
            return token
        except Exception as e:
            self._log(f"{flow}: 浏览器 Sentinel 获取异常: {e}", "warning")
            return ""

    def _prewarm_chatgpt_entry(self, email: str, did: str) -> str:
        """对齐 aar：OAuth 前先走 ChatGPT 首页 -> CSRF -> signin/openai 预热链路。"""
        if not self.session:
            return ""
        homepage_url = "https://chatgpt.com/"
        csrf_url = "https://chatgpt.com/api/auth/csrf"
        signin_url = "https://chatgpt.com/api/auth/signin/openai"

        try:
            self._log("force_chatgpt_entry: 访问 ChatGPT 首页...")
            self._browser_pause()
            self.session.get(
                homepage_url,
                headers=self._build_browser_headers(
                    homepage_url,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    navigation=True,
                ),
                allow_redirects=True,
                timeout=30,
            )
        except Exception as e:
            self._log(f"force_chatgpt_entry: 首页访问异常: {e}", "warning")

        csrf_token = ""
        try:
            self._log("force_chatgpt_entry: 获取 CSRF token...")
            r_csrf = self.session.get(
                csrf_url,
                headers=self._build_browser_headers(
                    csrf_url,
                    accept="application/json",
                    referer=homepage_url,
                    fetch_site="same-origin",
                ),
                timeout=30,
            )
            if r_csrf.status_code == 200:
                csrf_token = str((r_csrf.json() or {}).get("csrfToken") or "").strip()
        except Exception as e:
            self._log(f"force_chatgpt_entry: 获取 CSRF 异常: {e}", "warning")

        if not csrf_token:
            return ""

        authorize_url = ""
        try:
            self._log("force_chatgpt_entry: 提交邮箱获取 authorize URL...")
            params = {
                "prompt": "login",
                "ext-oai-did": did,
                "auth_session_logging_id": str(uuid.uuid4()),
                "screen_hint": "login_or_signup",
                "login_hint": email,
            }
            form_data = {
                "callbackUrl": "https://chatgpt.com/",
                "csrfToken": csrf_token,
                "json": "true",
            }
            r_signin = self.session.post(
                signin_url,
                params=params,
                data=form_data,
                headers=self._build_browser_headers(
                    signin_url,
                    accept="application/json",
                    referer=homepage_url,
                    origin="https://chatgpt.com",
                    content_type="application/x-www-form-urlencoded",
                    fetch_site="same-origin",
                ),
                timeout=30,
            )
            if r_signin.status_code == 200:
                authorize_url = str((r_signin.json() or {}).get("url") or "").strip()
                if authorize_url:
                    self._log("force_chatgpt_entry: 已获取 authorize URL")
            else:
                self._log(
                    f"force_chatgpt_entry: authorize URL 获取失败 {r_signin.status_code}",
                    "warning",
                )
        except Exception as e:
            self._log(f"force_chatgpt_entry: 提交邮箱异常: {e}", "warning")
            return ""

        if not authorize_url:
            return ""

        self._prewarm_authorize_url = authorize_url
        try:
            parsed = urllib.parse.urlparse(authorize_url)
            self._log(
                "force_chatgpt_entry: authorize URL 摘要 "
                f"path={parsed.path}, query_keys={','.join(sorted(urllib.parse.parse_qs(parsed.query).keys())[:12]) or '-'}"
            )
        except Exception:
            pass

        try:
            self._log("force_chatgpt_entry: 访问 authorize URL...")
            self._browser_pause()
            r_auth = self.session.get(
                authorize_url,
                headers=self._build_browser_headers(
                    authorize_url,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    referer=homepage_url,
                    navigation=True,
                ),
                allow_redirects=True,
                timeout=30,
            )
            final_url = str(r_auth.url)
            self._prewarm_authorize_final_url = final_url
            self._log(f"force_chatgpt_entry: authorize 最终跳转 {final_url[:160]}")
            self._log_oauth_session_quality("force_chatgpt_entry 后")
            return final_url
        except Exception as e:
            self._log(f"force_chatgpt_entry: 访问 authorize 异常: {e}", "warning")
            return authorize_url

    def _log(self, message: str, level: str = "info"):
        """记录日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"

        # 添加到日志列表
        self.logs.append(log_message)

        # 调用回调函数
        if self.callback_logger:
            self.callback_logger(log_message)

        # 记录到数据库（如果有关联任务）
        if self.task_uuid:
            try:
                with get_db() as db:
                    crud.append_task_log(db, self.task_uuid, log_message)
            except Exception as e:
                logger.warning(f"记录任务日志失败: {e}")

        # 根据级别记录到日志系统
        if level == "error":
            logger.error(message)
        elif level == "warning":
            logger.warning(message)
        else:
            logger.info(message)

    def _dump_session_cookies(self) -> str:
        """导出当前会话 cookies（用于后续支付/绑卡自动化）。"""
        if not self.session:
            return ""
        try:
            cookie_map: dict[str, str] = {}
            order: list[str] = []

            def _push(name: Optional[str], value: Optional[str]):
                key = str(name or "").strip()
                val = str(value or "").strip()
                if not key:
                    return
                if key not in cookie_map:
                    cookie_map[key] = val
                    order.append(key)
                    return
                # 同名 cookie 可能来自不同域/路径：优先保留非空且更长值，避免空值覆盖有效分片。
                prev = str(cookie_map.get(key) or "").strip()
                if (not prev and val) or (val and len(val) > len(prev)):
                    cookie_map[key] = val

            # 1) 常规 requests/curl_cffi 字典接口
            try:
                for key, value in self.session.cookies.items():
                    _push(key, value)
            except Exception:
                pass

            # 2) CookieJar 接口（可拿到分片 cookie）
            try:
                jar = getattr(self.session.cookies, "jar", None)
                if jar is not None:
                    for cookie in jar:
                        _push(getattr(cookie, "name", ""), getattr(cookie, "value", ""))
            except Exception:
                pass

            # 3) 关键 cookie 兜底读取
            for key in (
                "oai-did",
                "oai-client-auth-session",
                "__Secure-next-auth.session-token",
                "_Secure-next-auth.session-token",
            ):
                try:
                    _push(key, self.session.cookies.get(key))
                except Exception:
                    continue

            pairs = [(k, cookie_map.get(k, "")) for k in order if k]
            return "; ".join(f"{k}={v}" for k, v in pairs if k)
        except Exception:
            return ""

    def _seed_cookie_like_state(self, name: str, value: Any) -> None:
        if not self.session:
            return
        cookie_name = str(name or "").strip()
        if not cookie_name:
            return
        try:
            if isinstance(value, (dict, list)):
                cookie_value = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
            else:
                cookie_value = str(value or "").strip()
            if not cookie_value:
                return
            for domain in ("auth.openai.com", ".auth.openai.com"):
                try:
                    self.session.cookies.set(cookie_name, cookie_value, domain=domain, path="/")
                except Exception:
                    continue
        except Exception as e:
            self._log(f"回填 {cookie_name} Cookie 异常: {e}", "warning")

    @staticmethod
    def _extract_workspace_id_from_payload(payload: Any) -> str:
        if not isinstance(payload, dict):
            return ""
        workspace_id = str(
            payload.get("workspace_id")
            or payload.get("workspaceId")
            or payload.get("default_workspace_id")
            or ((payload.get("workspace") or {}).get("id") if isinstance(payload.get("workspace"), dict) else "")
            or ""
        ).strip()
        if workspace_id:
            return workspace_id
        workspaces = payload.get("workspaces") or []
        if isinstance(workspaces, list) and workspaces:
            return str((workspaces[0] or {}).get("id") or "").strip()
        return ""

    def _cache_auth_session_payload(self, payload: Any, stage: str) -> None:
        if not isinstance(payload, dict):
            return

        session_payload = payload.get("oai-client-auth-session")
        if not isinstance(session_payload, dict):
            session_payload = payload.get("oai_client_auth_session")
        if isinstance(session_payload, dict) and session_payload:
            self._cached_oai_client_auth_session = dict(session_payload)
            self._seed_cookie_like_state("oai-client-auth-session", session_payload)
            workspace_id = self._extract_workspace_id_from_payload(session_payload)
            if workspace_id and not self._last_validate_otp_workspace_id:
                self._last_validate_otp_workspace_id = workspace_id
            self._log(
                f"{stage}: 已缓存 oai-client-auth-session"
                + (f" workspace={workspace_id}" if workspace_id else "")
            )

        auth_info_payload = payload.get("oai-client-auth-info")
        if not isinstance(auth_info_payload, dict):
            auth_info_payload = payload.get("oai_client_auth_info")
        if isinstance(auth_info_payload, dict) and auth_info_payload:
            self._cached_oai_client_auth_info = dict(auth_info_payload)
            self._seed_cookie_like_state("oai-client-auth-info", auth_info_payload)
            workspace_id = self._extract_workspace_id_from_payload(auth_info_payload)
            if workspace_id and not self._last_validate_otp_workspace_id:
                self._last_validate_otp_workspace_id = workspace_id
            self._log(
                f"{stage}: 已缓存 oai-client-auth-info"
                + (f" workspace={workspace_id}" if workspace_id else "")
            )

    def _capture_auth_cookies_from_response(self, response: Any, stage: str) -> None:
        if not self.session or response is None:
            return
        try:
            def _collect_header_values(resp_obj: Any) -> List[str]:
                collected: List[str] = []
                headers = getattr(resp_obj, "headers", None)
                if headers is None:
                    return collected
                try:
                    get_list = getattr(headers, "get_list", None)
                    if callable(get_list):
                        collected.extend([str(v or "") for v in (get_list("Set-Cookie") or []) if str(v or "").strip()])
                except Exception:
                    pass
                if not collected:
                    try:
                        getall = getattr(headers, "getall", None)
                        if callable(getall):
                            collected.extend([str(v or "") for v in (getall("Set-Cookie") or []) if str(v or "").strip()])
                    except Exception:
                        pass
                if not collected:
                    try:
                        for key, value in headers.items():
                            if str(key or "").lower() == "set-cookie" and str(value or "").strip():
                                collected.append(str(value or ""))
                    except Exception:
                        pass
                return collected

            header_values = _collect_header_values(response)
            for hist_resp in (getattr(response, "history", []) or []):
                header_values.extend(_collect_header_values(hist_resp))
            if not header_values:
                return

            cookie_names = (
                "login_session",
                "oai-did",
                "oai-client-auth-session",
                "oai-client-auth-info",
            )
            captured: List[str] = []
            for header_value in header_values:
                for cookie_name in cookie_names:
                    match = re.search(
                        rf"(?:^|,\s*){re.escape(cookie_name)}=([^;,\r\n]+)",
                        str(header_value or ""),
                        re.IGNORECASE,
                    )
                    if not match:
                        continue
                    cookie_value = str(match.group(1) or "").strip()
                    if not cookie_value:
                        continue
                    for domain in ("auth.openai.com", ".auth.openai.com"):
                        try:
                            self.session.cookies.set(cookie_name, cookie_value, domain=domain, path="/")
                        except Exception:
                            continue
                    if cookie_name == "oai-did":
                        self.device_id = self.device_id or cookie_value
                    captured.append(cookie_name)

            if captured:
                deduped = ",".join(sorted(set(captured)))
                self._log(f"{stage}: 从响应头补抓 Cookie -> {deduped}")
        except Exception as e:
            self._log(f"{stage}: 解析响应头 Cookie 异常: {e}", "warning")

    @staticmethod
    def _decode_cookie_json_value(value: Any) -> Optional[Dict[str, Any]]:
        raw_value = str(value or "").strip()
        if not raw_value:
            return None

        candidates = [raw_value]
        if "." in raw_value:
            candidates.insert(0, raw_value.split(".", 1)[0])

        for candidate in candidates:
            text = str(candidate or "").strip()
            if not text:
                continue

            # 1) 直接 JSON
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass

            # 2) URL 解码后 JSON
            try:
                decoded_text = urllib.parse.unquote(text)
                if decoded_text != text:
                    parsed = json.loads(decoded_text)
                    if isinstance(parsed, dict):
                        return parsed
            except Exception:
                pass

            # 3) base64 / urlsafe base64
            padded = text + "=" * (-len(text) % 4)
            import base64
            for decoder in (base64.urlsafe_b64decode, base64.b64decode):
                try:
                    decoded = decoder(padded).decode("utf-8")
                    parsed = json.loads(decoded)
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    continue

        return None

    def _decode_oauth_session_cookie(self) -> Optional[Dict[str, Any]]:
        if not self.session:
            return None

        cookie_names = ("oai-client-auth-session", "oai-client-auth-info")
        for cookie_name in cookie_names:
            try:
                direct_value = self.session.cookies.get(cookie_name)
            except Exception:
                direct_value = None
            parsed = self._decode_cookie_json_value(direct_value)
            if parsed:
                return parsed

        try:
            jar = getattr(self.session.cookies, "jar", None)
            if jar is not None:
                for cookie in jar:
                    name = str(getattr(cookie, "name", "") or "").strip()
                    if name not in cookie_names:
                        continue
                    parsed = self._decode_cookie_json_value(getattr(cookie, "value", ""))
                    if parsed:
                        return parsed
        except Exception:
            pass

        return None

    def _fetch_consent_page_html(self, consent_url: str, user_agent: str, impersonate: str) -> str:
        _ = user_agent, impersonate
        if not self.session:
            return ""
        try:
            headers = self._build_browser_headers(
                consent_url,
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                referer="https://auth.openai.com/email-verification",
                navigation=True,
            )
            headers.update(generate_datadog_trace())
            self._browser_pause(0.12, 0.3)
            response = self.session.get(
                consent_url,
                headers=headers,
                allow_redirects=False,
                timeout=30,
            )
            self._capture_auth_cookies_from_response(response, "consent HTML")
            content_type = str((response.headers.get("content-type") if response.headers else "") or "").lower()
            if response.status_code == 200 and "text/html" in content_type:
                return str(response.text or "")
        except Exception as e:
            self._log(f"获取 consent HTML 异常: {e}", "warning")
        return ""

    def _extract_session_data_from_consent_html(self, html: str) -> Optional[Dict[str, Any]]:
        if not html or "workspaces" not in html:
            return None

        def _first_match(patterns: List[str], text: str) -> str:
            for pattern in patterns:
                match = re.search(pattern, text, re.S)
                if match:
                    return str(match.group(1) or "")
            return ""

        def _build_from_text(text: str) -> Optional[Dict[str, Any]]:
            if not text or "workspaces" not in text:
                return None

            normalized = text.replace('\\"', '"')
            session_id = _first_match(
                [
                    r'"session_id","([^"]+)"',
                    r'"session_id":"([^"]+)"',
                ],
                normalized,
            )
            client_id = _first_match(
                [
                    r'"openai_client_id","([^"]+)"',
                    r'"openai_client_id":"([^"]+)"',
                ],
                normalized,
            )

            start = normalized.find('"workspaces"')
            if start < 0:
                start = normalized.find("workspaces")
            if start < 0:
                return None

            end = normalized.find('"openai_client_id"', start)
            if end < 0:
                end = normalized.find("openai_client_id", start)
            if end < 0:
                end = min(len(normalized), start + 4000)
            else:
                end = min(len(normalized), end + 600)

            workspace_chunk = normalized[start:end]
            ids = re.findall(r'"id"(?:,|:)"([0-9a-fA-F-]{36})"', workspace_chunk)
            if not ids:
                return None

            kinds = re.findall(r'"kind"(?:,|:)"([^"]+)"', workspace_chunk)
            workspaces = []
            seen = set()
            for idx, wid in enumerate(ids):
                if wid in seen:
                    continue
                seen.add(wid)
                item: Dict[str, Any] = {"id": wid}
                if idx < len(kinds):
                    item["kind"] = kinds[idx]
                workspaces.append(item)

            if not workspaces:
                return None

            return {
                "session_id": session_id,
                "openai_client_id": client_id,
                "workspaces": workspaces,
            }

        candidates = [html]
        for quoted in re.findall(
            r'streamController\.enqueue\(("(?:\\.|[^"\\])*")\)',
            html,
            re.S,
        ):
            try:
                decoded = json.loads(quoted)
            except Exception:
                continue
            if decoded:
                candidates.append(str(decoded))

        if '\\"' in html:
            candidates.append(html.replace('\\"', '"'))

        for candidate in candidates:
            parsed = _build_from_text(str(candidate or ""))
            if parsed and parsed.get("workspaces"):
                return parsed

        return None

    def _load_workspace_session_data(self, consent_url: str, user_agent: str, impersonate: str) -> Dict[str, Any]:
        session_data = self._decode_oauth_session_cookie() or {}
        if session_data and session_data.get("workspaces"):
            return session_data

        html = self._fetch_consent_page_html(consent_url, user_agent, impersonate)
        if not html:
            return session_data

        parsed = self._extract_session_data_from_consent_html(html)
        if parsed and parsed.get("workspaces"):
            self._log(f"从 consent HTML 提取到 {len(parsed.get('workspaces', []))} 个 workspace")
            return parsed

        return session_data

    @staticmethod
    def _extract_session_token_from_cookie_jar(cookie_jar) -> str:
        """
        从 CookieJar 中提取 next-auth session token（兼容分片 + 重复域名）。
        """
        if not cookie_jar:
            return ""

        entries: list[tuple[str, str]] = []
        try:
            for key, value in cookie_jar.items():
                entries.append((str(key or "").strip(), str(value or "").strip()))
        except Exception:
            pass

        try:
            jar = getattr(cookie_jar, "jar", None)
            if jar is not None:
                for cookie in jar:
                    entries.append(
                        (
                            str(getattr(cookie, "name", "") or "").strip(),
                            str(getattr(cookie, "value", "") or "").strip(),
                        )
                    )
        except Exception:
            pass

        direct_candidates = [
            val
            for name, val in entries
            if name in ("__Secure-next-auth.session-token", "_Secure-next-auth.session-token") and val
        ]
        if direct_candidates:
            return max(direct_candidates, key=len)

        chunk_map: dict[int, str] = {}
        for name, value in entries:
            if not (
                name.startswith("__Secure-next-auth.session-token.")
                or name.startswith("_Secure-next-auth.session-token.")
            ):
                continue
            if not value:
                continue
            try:
                idx = int(name.rsplit(".", 1)[-1])
            except Exception:
                continue
            prev = chunk_map.get(idx, "")
            if not prev or len(value) > len(prev):
                chunk_map[idx] = value

        if chunk_map:
            return "".join(chunk_map[i] for i in sorted(chunk_map.keys()))
        return ""

    @staticmethod
    def _flatten_set_cookie_headers(response) -> str:
        """
        合并多条 Set-Cookie（包含分片 cookie）。
        """
        try:
            headers = getattr(response, "headers", None)
            if headers is None:
                return ""
            if hasattr(headers, "get_list"):
                values = headers.get_list("set-cookie")
                if values:
                    return " | ".join(str(v or "") for v in values if v is not None)
            if hasattr(headers, "get_all"):
                values = headers.get_all("set-cookie")
                if values:
                    return " | ".join(str(v or "") for v in values if v is not None)
            return str(headers.get("set-cookie") or "")
        except Exception:
            return ""

    @staticmethod
    def _extract_request_cookie_header(response) -> str:
        """
        从响应对象关联的请求头中提取 Cookie。
        对齐 F12 Network -> Request Headers -> Cookie 的观测路径。
        """
        try:
            request_obj = getattr(response, "request", None)
            if request_obj is None:
                return ""
            headers = getattr(request_obj, "headers", None)
            if headers is None:
                return ""

            if hasattr(headers, "get"):
                value = headers.get("cookie") or headers.get("Cookie")
                if value:
                    return str(value)

            try:
                for key, value in dict(headers).items():
                    if str(key or "").strip().lower() == "cookie" and value:
                        return str(value)
            except Exception:
                pass
        except Exception:
            pass
        return ""

    def _generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        """生成随机密码"""
        length = max(8, int(length or DEFAULT_PASSWORD_LENGTH))
        password_chars = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice(PASSWORD_SPECIAL_CHARSET),
        ]
        password_chars.extend(secrets.choice(PASSWORD_CHARSET) for _ in range(length - len(password_chars)))
        secrets.SystemRandom().shuffle(password_chars)
        return ''.join(password_chars)

    def _check_ip_location(self) -> Tuple[bool, Optional[str]]:
        """检查 IP 地理位置"""
        self._raise_if_cancelled("任务已取消，跳过 IP 地理位置检查")
        try:
            return self.http_client.check_ip_location()
        except Exception as e:
            self._log(f"检查 IP 地理位置失败: {e}", "error")
            return False, None

    def _create_email(self) -> bool:
        """创建邮箱"""
        self._raise_if_cancelled("任务已取消，跳过邮箱创建")
        try:
            self._log(f"正在创建 {self.email_service.service_type.value} 邮箱，先给新账号整个收件箱...")
            self.email_info = self.email_service.create_email()

            if not self.email_info or "email" not in self.email_info:
                self._log("创建邮箱失败: 返回信息不完整", "error")
                return False

            raw_email = str(self.email_info["email"] or "").strip()
            normalized_email = raw_email.lower()

            # 保留原始收件地址，注册链路统一使用规范化邮箱，规避 "Failed to register username"。
            self.inbox_email = raw_email
            self.email = normalized_email
            self.email_info["email"] = normalized_email

            if raw_email and raw_email != normalized_email:
                self._log(f"邮箱规范化: {raw_email} -> {normalized_email}")

            inbox_mode = str(self.email_info.get("inbox_mode") or "").strip()
            source = str(self.email_info.get("source") or "").strip()
            purchase_id = str(self.email_info.get("purchase_id") or "").strip()
            order_no = str(self.email_info.get("order_no") or "").strip()
            preferred_domain = str(self.email_info.get("preferred_domain") or "").strip()
            reuse_attempts_used = int(self.email_info.get("reuse_purchase_attempts_used") or 0)
            reuse_retry_reports = self.email_info.get("reuse_purchase_retry_reports") or []
            reuse_selected_email = str(self.email_info.get("reuse_purchase_selected_email") or "").strip()
            if inbox_mode or source:
                self._log(
                    "邮箱分支: "
                    f"mode={inbox_mode or '-'}, "
                    f"source={source or '-'}, "
                    f"purchase_id={purchase_id or '-'}, "
                    f"order_no={order_no or '-'}, "
                    f"preferred_domain={preferred_domain or '-'}"
                )
                if source == "reuse_purchase":
                    self._log("邮箱分支说明: 本次命中 LuckMail 已购邮箱复用分支")
                    if reuse_selected_email:
                        self._log(f"邮箱复用命中: 本轮选中已购邮箱 {reuse_selected_email}")
                elif source == "resume_failed":
                    self._log("邮箱分支说明: 本次命中 LuckMail 失败邮箱恢复分支")
                    if reuse_selected_email:
                        self._log(f"邮箱复用命中: 本轮恢复历史邮箱 {reuse_selected_email}")
                elif source == "new_purchase":
                    self._log("邮箱分支说明: 本次未复用到已购邮箱，改走新购邮箱分支")
                    if reuse_attempts_used > 0:
                        self._log(f"邮箱复用重试: 已尝试复用已购邮箱 {reuse_attempts_used} 次")
                    if isinstance(reuse_retry_reports, list):
                        for report in reuse_retry_reports[:3]:
                            if report:
                                self._log(f"邮箱复用失败原因: {str(report)[:300]}")
                elif source == "new_order":
                    self._log("邮箱分支说明: 本次走 LuckMail 新建订单分支")

            self._log(f"邮箱已就位，地址新鲜出炉: {self.email}")
            return True

        except Exception as e:
            self._log(f"创建邮箱失败: {e}", "error")
            return False

    def _start_oauth(self) -> bool:
        """开始 OAuth 流程"""
        self._raise_if_cancelled("任务已取消，跳过 OAuth 初始化")
        try:
            self._log("开始 OAuth 授权流程，去门口刷个脸...")
            self.oauth_start = self.oauth_manager.start_oauth()
            self._log(f"OAuth URL 已备好，通道已经打开: {self.oauth_start.auth_url[:80]}...")
            if not self.session:
                self.session = self.http_client.session
                self._apply_browser_fingerprint_to_session()
            provisional_did = str(self.device_id or "").strip() or str(uuid.uuid4())
            self.device_id = provisional_did
            self._seed_oai_device_cookie(provisional_did)
            warm_url = self._prewarm_chatgpt_entry(self.email or "", provisional_did)
            if warm_url:
                self._last_auth_page_url = warm_url
                self._log("force_chatgpt_entry: 预热完成，继续主 OAuth 链路")
            if self._is_prewarm_bad_terminal_state():
                self._log(
                    f"OAuth 初始化: prewarm 落到异常终态 {str(self._prewarm_authorize_final_url or warm_url or '')[:160]}，"
                    "本轮会话直接判废并重建",
                    "warning",
                )
                return False
            self._log_authorize_url_diff(provisional_did)
            bootstrap_final_url = self._bootstrap_oauth_session(provisional_did, "OAuth 初始化")
            if bootstrap_final_url:
                self._last_auth_page_url = bootstrap_final_url
                self._log(f"OAuth 初始化: bootstrap 最终落点 {bootstrap_final_url[:160]}")
            self._allow_prewarm_bootstrap_bypass = False
            if (not bootstrap_final_url) and self._has_prewarm_auth_ready_state():
                self._allow_prewarm_bootstrap_bypass = True
                self._log(
                    "OAuth 初始化: 命中预热直连实验分支，虽然未建立 login_session，"
                    "但 prewarm 已进入 create-account/password，先跳过 oauth/authorize 429 继续验证后链路",
                    "warning",
                )
            if not self._ensure_login_session(provisional_did, "OAuth 初始化", max_rounds=2):
                if self._allow_prewarm_bootstrap_bypass and self._has_prewarm_auth_ready_state():
                    self._log("OAuth 初始化: 预热直连实验分支放行，继续使用本地 Device ID", "warning")
                    return True
                self._log("OAuth 初始化失败: 预热后仍未建立 login_session，本轮会话质量不足", "warning")
                return False
            return True
        except Exception as e:
            self._log(f"生成 OAuth URL 失败: {e}", "error")
            return False

    def _init_session(self) -> bool:
        """初始化会话"""
        self._raise_if_cancelled("任务已取消，跳过会话初始化")
        try:
            self.session = self.http_client.session
            self._apply_browser_fingerprint_to_session()
            return True
        except Exception as e:
            self._log(f"初始化会话失败: {e}", "error")
            return False

    def _get_device_id(self) -> Optional[str]:
        """获取 Device ID"""
        self._raise_if_cancelled("任务已取消，停止获取 Device ID")
        if not self.oauth_start:
            return None

        # 对齐 arr：先本地预置 did，避免完全依赖服务端 Set-Cookie。
        provisional_did = str(self.device_id or "").strip() or str(uuid.uuid4())
        self.device_id = provisional_did
        self._seed_oai_device_cookie(provisional_did)
        if self._allow_prewarm_bootstrap_bypass and self._has_prewarm_auth_ready_state():
            self._log(
                "Device ID 阶段: 走预热直连实验分支，跳过 /oauth/authorize 领取，直接复用本地预置 did",
                "warning",
            )
            return provisional_did

        max_attempts = max(int(self._rate_limit_max_attempts or 2), 1)
        for attempt in range(1, max_attempts + 1):
            self._raise_if_cancelled("任务已取消，停止获取 Device ID")
            try:
                if not self.session:
                    self.session = self.http_client.session
                    self._apply_browser_fingerprint_to_session()
                    self._seed_oai_device_cookie(provisional_did)

                authorize_url = self._append_authorize_hint_params(
                    self.oauth_start.auth_url,
                    provisional_did,
                )
                headers = self._build_browser_headers(
                    authorize_url,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    referer="https://chatgpt.com/",
                    navigation=True,
                )
                headers.update(generate_datadog_trace())
                self._browser_pause()
                response = self.session.get(
                    authorize_url,
                    headers=headers,
                    timeout=20,
                )
                did = self.session.cookies.get("oai-did")

                if not did:
                    # 对齐 ABCard：部分环境 cookie 不落盘，尝试从 HTML 文本提取
                    try:
                        m = re.search(r'oai-did["\s:=]+([a-f0-9-]{36})', str(response.text or ""), re.IGNORECASE)
                        if m:
                            did = str(m.group(1) or "").strip()
                            if did:
                                try:
                                    self.session.cookies.set("oai-did", did, domain=".chatgpt.com", path="/")
                                except Exception:
                                    pass
                    except Exception:
                        pass

                if response.status_code == 429:
                    retry_after = self._parse_retry_after_seconds(response.headers.get("Retry-After"))
                    request_id = str(response.headers.get("x-request-id") or "").strip()
                    wait_seconds = int(self._compute_rate_limit_backoff(attempt, retry_after))
                    extra_hint = ""
                    if retry_after > float(self._rate_limit_wait_seconds or 2.0):
                        extra_hint = (
                            f"（服务端建议 {int(retry_after)}s，"
                            f"已上限为 {int(self._rate_limit_wait_seconds or 2)}s）"
                        )
                    if request_id:
                        extra_hint += f" request_id={request_id}"
                    self._log(
                        f"获取 Device ID 命中限流 429（第 {attempt}/{max_attempts} 次），"
                        f"{wait_seconds}s 后重试{extra_hint}",
                        "warning" if attempt < max_attempts else "error",
                    )
                    if attempt < max_attempts:
                        self._refresh_oauth_context(provisional_did)
                        self._sleep_interruptible(wait_seconds)
                        continue

                if did:
                    self._log(f"Device ID: {did}")
                    return did

                self._log(
                    f"获取 Device ID 失败: 未返回 oai-did Cookie (HTTP {response.status_code}, 第 {attempt}/{max_attempts} 次)",
                    "warning" if attempt < max_attempts else "error"
                )
            except Exception as e:
                self._log(
                    f"获取 Device ID 失败: {e} (第 {attempt}/{max_attempts} 次)",
                    "warning" if attempt < max_attempts else "error"
                )

            if attempt < max_attempts:
                self._sleep_interruptible(attempt)
                # 仅在网络波动场景短暂重试；限流场景由上方 429 分支处理更长退避。
                self.http_client.close()
                self.session = self.http_client.session
                self._apply_browser_fingerprint_to_session()
                self._seed_oai_device_cookie(provisional_did)

        # 对齐 ABCard：无法从响应拿到 did 时，优先复用上次成功 did，再使用 UUID 兜底。
        fallback_did = str(self.device_id or "").strip() or str(uuid.uuid4())
        try:
            if self.session:
                self.session.cookies.set("oai-did", fallback_did, domain=".chatgpt.com", path="/")
        except Exception:
            pass
        self._log(f"未获取到 oai-did，使用兜底 Device ID: {fallback_did}", "warning")
        return fallback_did

    def _check_sentinel(self, did: str) -> Optional[str]:
        """检查 Sentinel 拦截"""
        self._raise_if_cancelled("任务已取消，停止 Sentinel 检查")
        try:
            sen_token = self.http_client.check_sentinel(did)
            if sen_token:
                self._log(f"Sentinel token 获取成功")
                return sen_token
            self._log("Sentinel 检查失败: 未获取到 token", "warning")
            return None

        except Exception as e:
            self._log(f"Sentinel 检查异常: {e}", "warning")
            return None

    def _submit_auth_start(
        self,
        did: str,
        sen_token: Optional[str],
        *,
        screen_hint: str,
        referer: str,
        log_label: str,
        record_existing_account: bool = True,
    ) -> SignupFormResult:
        """
        提交授权入口表单

        Returns:
            SignupFormResult: 提交结果，包含账号状态判断
        """
        max_attempts = max(int(self._rate_limit_max_attempts or 2), 1)
        current_did = str(did or "").strip()
        current_sen_token = str(sen_token or "").strip() if sen_token else None
        for attempt in range(1, max_attempts + 1):
            self._raise_if_cancelled("任务已取消，停止提交授权入口")
            try:
                self._last_signup_rate_limit_session_ended = False
                resolved_referer = self._resolve_authorize_continue_referer(
                    referer,
                    prefer_bootstrap=(str(screen_hint or "").strip().lower() != "signup"),
                )
                request_body = json.dumps({
                    "username": {
                        "value": self.email,
                        "kind": "email",
                    },
                    "screen_hint": screen_hint,
                })

                headers = {
                    "oai-device-id": current_did,
                }
                if current_sen_token:
                    headers["openai-sentinel-token"] = current_sen_token
                headers = self._build_browser_headers(
                    OPENAI_API_ENDPOINTS["signup"],
                    accept="application/json",
                    referer=resolved_referer,
                    origin="https://auth.openai.com",
                    content_type="application/json",
                    fetch_site="same-origin",
                    extra_headers=headers,
                )
                headers.update(generate_datadog_trace())
                self._log(f"{log_label}使用 referer: {resolved_referer[:160]}")

                self._browser_pause()
                response = self.session.post(
                    OPENAI_API_ENDPOINTS["signup"],
                    headers=headers,
                    json=json.loads(request_body),
                    allow_redirects=False,
                    timeout=30,
                )

                self._log(f"{log_label}状态: {response.status_code}")
                response_url = str(getattr(response, "url", "") or "").strip()
                if response_url:
                    self._last_auth_page_url = response_url

                if response.status_code == 429 and attempt < max_attempts:
                    retry_after = self._parse_retry_after_seconds(response.headers.get("Retry-After"))
                    request_id = str(response.headers.get("x-request-id") or "").strip()
                    wait_seconds = int(self._compute_rate_limit_backoff(attempt, retry_after))
                    self._log(
                        f"{log_label}命中限流 429（第 {attempt}/{max_attempts} 次），{wait_seconds}s 后自动重试...",
                        "warning",
                    )
                    if request_id:
                        self._log(f"{log_label} 429 request_id={request_id}", "warning")
                    if response_url:
                        self._log(f"{log_label} 429 response_url={response_url[:160]}", "warning")
                    raw_body = str(response.text or "").strip()
                    if raw_body:
                        self._log(f"{log_label} 429 响应体预览: {raw_body[:300]}", "warning")
                        lower_body = raw_body.lower()
                        if ("session has ended" in lower_body) or ("你的会话已结束" in raw_body):
                            self._last_signup_rate_limit_session_ended = True
                            self._log(
                                f"{log_label} 429 页面提示会话已结束，当前 auth 状态可能已经丢失，需要重新预热 login_session",
                                "warning",
                            )
                    self._refresh_oauth_context(current_did)
                    refreshed = self._check_sentinel(current_did)
                    if refreshed:
                        current_sen_token = refreshed
                    self._sleep_interruptible(wait_seconds)
                    continue

                # 部分网络/会话边界情况下会返回 409，做自愈重试而非直接失败。
                if response.status_code == 409 and attempt < max_attempts:
                    wait_seconds = min(10, 2 * attempt)
                    self._log(
                        f"{log_label}命中 409（第 {attempt}/{max_attempts} 次），"
                        f"会话上下文可能冲突，{wait_seconds}s 后自动重试...",
                        "warning",
                    )
                    # 尝试刷新 sentinel，避免 token 过期导致冲突。
                    try:
                        refreshed = self._check_sentinel(current_did)
                        if refreshed:
                            current_sen_token = refreshed
                    except Exception:
                        pass
                    # 预热一次授权页，帮助服务端重建登录上下文。
                    try:
                        if self.oauth_start and getattr(self.oauth_start, "auth_url", None):
                            self.session.get(str(self.oauth_start.auth_url), timeout=12)
                    except Exception:
                        pass
                    self._sleep_interruptible(wait_seconds)
                    continue

                if response.status_code != 200:
                    return SignupFormResult(
                        success=False,
                        error_message=f"HTTP {response.status_code}: {response.text[:200]}"
                    )

                # 解析响应判断账号状态
                try:
                    response_data = response.json()
                    page_type = response_data.get("page", {}).get("type", "")
                    self._log(f"响应页面类型: {page_type}")

                    is_existing = page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]

                    if is_existing:
                        self._otp_sent_at = time.time()
                        if record_existing_account:
                            self._log(f"检测到已注册账号，将自动切换到登录流程")
                            self._is_existing_account = True
                        else:
                            self._log("登录流程已触发，等待系统自动发送的验证码")

                    return SignupFormResult(
                        success=True,
                        page_type=page_type,
                        is_existing_account=is_existing,
                        response_data=response_data,
                        current_url=response_url,
                    )

                except Exception as parse_error:
                    self._log(f"解析响应失败: {parse_error}", "warning")
                    # 无法解析，默认成功
                    return SignupFormResult(success=True, current_url=response_url)

            except Exception as e:
                if attempt < max_attempts:
                    self._log(
                        f"{log_label}异常（第 {attempt}/{max_attempts} 次）: {e}，准备重试...",
                        "warning",
                    )
                    self._sleep_interruptible(2 * attempt)
                    continue
                self._log(f"{log_label}失败: {e}", "error")
                return SignupFormResult(success=False, error_message=str(e))

        return SignupFormResult(success=False, error_message=f"{log_label}失败: 超过最大重试次数")

    def _submit_signup_form(
        self,
        did: str,
        sen_token: Optional[str],
        *,
        record_existing_account: bool = True,
    ) -> SignupFormResult:
        """提交注册入口表单。"""
        return self._submit_auth_start(
            did,
            sen_token,
            screen_hint="signup",
            referer="https://auth.openai.com/create-account",
            log_label="提交注册表单",
            record_existing_account=record_existing_account,
        )

    def _recover_signup_after_rate_limit(self) -> SignupFormResult:
        """
        命中 signup 429 时的兜底：
        部分场景服务端已经实际发送验证码，只是返回层被风控页覆盖。
        """
        otp_fetch_timeout = 75
        current_did = str(self.device_id or self.session.cookies.get("oai-did") or "").strip()

        self._log(
            "检测到 signup 429，开始按“偶发可恢复”场景重试探测邮箱验证码步骤...",
            "warning",
        )
        self._log("signup 429 发信探测: 只执行 1 次 send_otp，后续不再重复发码", "warning")
        if current_did:
            self._refresh_oauth_context(current_did)
            refreshed = self._check_sentinel(current_did)
            if refreshed:
                self._log("signup 429 发信探测: Sentinel token 刷新成功", "warning")

        send_probe_ok = self._send_verification_code(referer="https://auth.openai.com/email-verification")
        probe_detail = str(self._last_send_otp_error_detail or "unknown").strip()
        if send_probe_ok:
            self._log(
                "signup 429 发信探测成功: send_otp=200，后续仅等待新邮件并多次校验，不再重发验证码",
                "warning",
            )

        if not send_probe_ok:
            if self._last_signup_rate_limit_session_ended:
                self._log("signup 429 单轮探测后仍提示会话结束，尝试彻底重建 OAuth 会话并重新递邮箱...", "warning")
                reauth_result = self._restart_signup_after_session_end()
                if reauth_result.success:
                    self._log("signup 429 会话重建成功，已重新进入有效注册状态", "warning")
                    return reauth_result
            return SignupFormResult(
                success=False,
                error_message=(
                    "HTTP 429，且单轮发信探测未确认已进入邮箱验证码步骤；"
                    f"send_otp={self._last_send_otp_status_code or '-'}, detail={probe_detail or '-'}"
                ),
            )

        otp_ok = self._verify_email_otp_with_retry(
            stage_label="注册入口验证码(429兜底)",
            max_attempts=4,
            fetch_timeout=otp_fetch_timeout,
            retry_wait_seconds=5.0,
            invalid_state_retry_wait_seconds=10.0,
        )
        if not otp_ok:
            return SignupFormResult(
                success=False,
                error_message=(
                    "HTTP 429 且注册入口验证码兜底校验失败；"
                    f"send_otp={self._last_send_otp_status_code or '-'}, "
                    f"send_detail={self._last_send_otp_error_detail or '-'}"
                ),
            )

        continue_url = str(self._last_validate_otp_continue_url or "").strip().lower()
        workspace_id = str(self._last_validate_otp_workspace_id or "").strip()

        if "auth.openai.com/create-account/password" in continue_url:
            self._log("注册分支: signup_429_recover -> create_account_password", "warning")
            self._log("429 兜底成功：已进入 create-account/password，继续新账号流程", "warning")
            return SignupFormResult(success=True, page_type="signup_otp_password_ready")

        if ("auth.openai.com/about-you" in continue_url) or ("auth.openai.com/add-phone" in continue_url) or workspace_id:
            self._log("注册分支: signup_429_recover -> post_password_gate", "warning")
            self._log("429 兜底成功：已越过邮箱校验，直接续上注册后半段", "warning")
            return SignupFormResult(success=True, page_type="signup_otp_post_password")

        self._is_existing_account = True
        self._log("注册分支: signup_429_recover -> existing_account", "warning")
        self._log("429 兜底成功：当前更像已有账号登录链，切换登录收尾", "warning")
        return SignupFormResult(
            success=True,
            page_type=OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"],
            is_existing_account=True,
        )

    def _recover_signup_via_prewarm_password_path(
        self,
        did: str,
        sen_token: Optional[str],
    ) -> SignupFormResult:
        """当 prewarm 已进入 create-account/password 时，直接走注册密码主链。"""
        if not self._has_prewarm_auth_ready_state():
            return SignupFormResult(success=False, error_message="prewarm 未进入 create-account/password")

        self._log("signup 429 恢复: 命中 prewarm 密码直连分支，直接提交注册密码", "warning")
        password_ok, _password = self._register_password_with_retry(did, sen_token)
        if not password_ok:
            return SignupFormResult(
                success=False,
                error_message=self._last_register_password_error or "prewarm 密码直连分支提交密码失败",
            )

        self._log("signup 429 恢复: 密码提交成功，继续触发注册验证码", "warning")
        if not self._send_verification_code(referer="https://auth.openai.com/create-account/password"):
            return SignupFormResult(
                success=False,
                error_message=(
                    "prewarm 密码直连分支触发验证码失败；"
                    f"send_otp={self._last_send_otp_status_code or '-'}, "
                    f"detail={self._last_send_otp_error_detail or '-'}"
                ),
            )

        otp_ok = self._verify_email_otp_with_retry(
            stage_label="注册入口验证码(prewarm直连)",
            max_attempts=2,
            fetch_timeout=45,
            retry_wait_seconds=6.0,
            invalid_state_retry_wait_seconds=12.0,
        )
        if not otp_ok:
            return SignupFormResult(
                success=False,
                error_message=(
                    "prewarm 密码直连分支验证码校验失败；"
                    f"send_otp={self._last_send_otp_status_code or '-'}, "
                    f"detail={self._last_send_otp_error_detail or '-'}"
                ),
            )

        continue_url = str(self._last_validate_otp_continue_url or "").strip().lower()
        workspace_id = str(self._last_validate_otp_workspace_id or "").strip()
        if "auth.openai.com/create-account/password" in continue_url:
            self._log("注册分支: signup_429_prewarm_password -> create_account_password", "warning")
            return SignupFormResult(success=True, page_type="signup_otp_password_ready")
        if ("auth.openai.com/about-you" in continue_url) or ("auth.openai.com/add-phone" in continue_url) or workspace_id:
            self._log("注册分支: signup_429_prewarm_password -> post_password_gate", "warning")
            return SignupFormResult(success=True, page_type="signup_otp_post_password")
        return SignupFormResult(
            success=True,
            page_type=OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"],
            is_existing_account=True,
        )

    def _restart_signup_after_session_end(self) -> SignupFormResult:
        """当 signup 429 明确提示会话结束时，彻底重建 OAuth 会话并重新递邮箱。"""
        try:
            self._reset_auth_flow()
            did, sen_token = self._prepare_authorize_flow("重新递邮箱")
            if not did:
                return SignupFormResult(success=False, error_message="会话重建后获取 Device ID 失败")
            self.device_id = did
            if not sen_token:
                return SignupFormResult(success=False, error_message="会话重建后 Sentinel POW 验证失败")
            self._log("会话重建完成，重新提交注册表单...", "warning")
            return self._submit_signup_form(did, sen_token, record_existing_account=True)
        except Exception as e:
            self._log(f"会话重建后重新递邮箱异常: {e}", "warning")
            return SignupFormResult(success=False, error_message=f"会话重建异常: {e}")

    def _submit_login_start(self, did: str, sen_token: Optional[str]) -> SignupFormResult:
        """提交登录入口表单。"""
        return self._submit_auth_start(
            did,
            sen_token,
            screen_hint="login",
            referer="https://auth.openai.com/log-in",
            log_label="提交登录入口",
            record_existing_account=False,
        )

    def _submit_login_password(self) -> SignupFormResult:
        """提交登录密码，进入邮箱验证码页面。"""
        self._raise_if_cancelled("任务已取消，停止提交登录密码")
        max_attempts = max(int(self._rate_limit_max_attempts or 2), 1)
        password_text = str(self.password or "").strip()
        if not password_text and self.email:
            try:
                with get_db() as db:
                    account = crud.get_account_by_email(db, self.email)
                    db_password = str(getattr(account, "password", "") or "").strip() if account else ""
                    if db_password:
                        self.password = db_password
                        password_text = db_password
                        self._log("登录阶段未发现内存密码，已从账号库回填密码")
            except Exception as e:
                self._log(f"登录阶段尝试回填密码失败: {e}", "warning")

        if not password_text:
            return SignupFormResult(
                success=False,
                error_message="登录密码为空：该邮箱可能是已存在账号但当前任务未持有密码",
            )

        for attempt in range(1, max_attempts + 1):
            self._raise_if_cancelled("任务已取消，停止登录密码重试")
            try:
                response = self.session.post(
                    OPENAI_API_ENDPOINTS["password_verify"],
                    headers=dict(
                        self._build_browser_headers(
                            OPENAI_API_ENDPOINTS["password_verify"],
                            accept="application/json",
                            referer="https://auth.openai.com/log-in/password",
                            origin="https://auth.openai.com",
                            content_type="application/json",
                            fetch_site="same-origin",
                            extra_headers={
                                "oai-device-id": str(self.device_id or self.session.cookies.get("oai-did") or "").strip(),
                            },
                        ),
                        **generate_datadog_trace(),
                    ),
                    json={"password": self.password},
                    allow_redirects=False,
                    timeout=30,
                )

                self._log(f"提交登录密码状态: {response.status_code}")

                if response.status_code == 429 and attempt < max_attempts:
                    wait_seconds = int(self._compute_rate_limit_backoff(attempt, 0.0))
                    self._log(
                        f"提交登录密码命中限流 429（第 {attempt}/{max_attempts} 次），{wait_seconds}s 后自动重试...",
                        "warning",
                    )
                    self._sleep_interruptible(wait_seconds)
                    continue

                if response.status_code == 401 and attempt < max_attempts:
                    body = str(response.text or "")
                    if "invalid_username_or_password" in body:
                        wait_seconds = min(12, 3 * attempt)
                        self._log(
                            f"提交登录密码命中 401（第 {attempt}/{max_attempts} 次），"
                            f"疑似密码尚未生效或历史账号密码不一致，{wait_seconds}s 后自动重试...",
                            "warning",
                        )
                        self._sleep_interruptible(wait_seconds)
                        continue

                if response.status_code != 200:
                    return SignupFormResult(
                        success=False,
                        error_message=f"HTTP {response.status_code}: {response.text[:200]}"
                    )

                response_data = response.json()
                page_type = response_data.get("page", {}).get("type", "")
                self._log(f"登录密码响应页面类型: {page_type}")

                is_existing = page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]
                if is_existing:
                    self._otp_sent_at = time.time()
                    self._log("登录密码校验通过，等待系统自动发送的验证码")

                return SignupFormResult(
                    success=True,
                    page_type=page_type,
                    is_existing_account=is_existing,
                    response_data=response_data,
                )

            except Exception as e:
                if attempt < max_attempts:
                    self._log(
                        f"提交登录密码异常（第 {attempt}/{max_attempts} 次）: {e}，准备重试...",
                        "warning",
                    )
                    self._sleep_interruptible(2 * attempt)
                    continue
                self._log(f"提交登录密码失败: {e}", "error")
                return SignupFormResult(success=False, error_message=str(e))

        return SignupFormResult(success=False, error_message="提交登录密码失败: 超过最大重试次数")

    def _reset_auth_flow(self) -> None:
        """重置会话，准备重新发起 OAuth 流程。"""
        self.http_client.close()
        self.session = None
        self.oauth_start = None
        self.session_token = None
        self._otp_sent_at = None
        self._last_auth_page_url = ""
        self._oauth_bootstrap_final_url = ""
        self._prewarm_authorize_url = ""
        self._prewarm_authorize_final_url = ""
        self._allow_prewarm_bootstrap_bypass = False

    def _prepare_authorize_flow(self, label: str) -> Tuple[Optional[str], Optional[str]]:
        """初始化当前阶段的授权流程，返回 device id 和 sentinel token。"""
        max_bootstrap_attempts = 3
        for attempt in range(1, max_bootstrap_attempts + 1):
            self._raise_if_cancelled(f"任务已取消，停止执行 {label}")
            self._log(f"{label}: 先把会话热热身...")
            if not self._init_session():
                return None, None

            self._log(f"{label}: OAuth 流程准备开跑，系好鞋带...")
            if not self._start_oauth():
                if attempt < max_bootstrap_attempts:
                    self._log(f"{label}: OAuth 初始化会话质量不足，重建全新 session 后再试一次...", "warning")
                    self._reset_auth_flow()
                    continue
                return None, None

            self._log(f"{label}: 领取 Device ID 通行证...")
            did = str(self._get_device_id() or "").strip()
            if not did:
                if attempt < max_bootstrap_attempts:
                    self._log(f"{label}: Device ID 阶段失败，重建全新 session 后再试一次...", "warning")
                    self._reset_auth_flow()
                    continue
                return None, None

            self.device_id = did
            self._log_oauth_session_quality(f"{label} Device ID 后")

            self._log(f"{label}: 解一道 Sentinel POW 小题，答对才给进...")
            sen_token = self._check_sentinel(did)
            if not sen_token:
                return did, None

            self._log(f"{label}: Sentinel 点头放行，继续前进")
            return did, sen_token
        return None, None

    @staticmethod
    def _extract_session_token_from_cookie_text(cookie_text: str) -> str:
        """从 Cookie 文本中提取 next-auth session token（兼容分片）。"""
        text = str(cookie_text or "")
        if not text:
            return ""

        direct = re.search(r"(?:^|[;,]\s*)(?:__|_)Secure-next-auth\.session-token=([^;,]*)", text)
        if direct:
            direct_val = str(direct.group(1) or "").strip().strip('"').strip("'")
            if direct_val:
                return direct_val

        parts = re.findall(r"(?:__|_)Secure-next-auth\.session-token\.(\d+)=([^;,]*)", text)
        if not parts:
            return ""

        chunk_map = {}
        for idx, value in parts:
            try:
                clean_value = str(value or "").strip().strip('"').strip("'")
                if clean_value:
                    chunk_map[int(idx)] = clean_value
            except Exception:
                continue
        if not chunk_map:
            return ""
        return "".join(chunk_map[i] for i in sorted(chunk_map.keys()))

    def _warmup_chatgpt_session(self) -> None:
        """
        仅预热 chatgpt 首页，避免提前消费一次性 continue_url。
        """
        try:
            self.session.get(
                "https://chatgpt.com/",
                headers={
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "referer": "https://auth.openai.com/",
                    "user-agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                    ),
                },
                timeout=20,
            )
        except Exception as e:
            self._log(f"chatgpt 首页预热异常: {e}", "warning")

    def _capture_auth_session_tokens(self, result: RegistrationResult, access_hint: Optional[str] = None) -> bool:
        """
        直接通过 /api/auth/session 捕获 session_token + access_token。
        这是 ABCard Phase 1 的关键路径。
        """
        access_token = str(access_hint or "").strip()
        set_cookie_text = ""
        request_cookie_text = ""
        try:
            headers = {
                "accept": "application/json",
                "referer": "https://chatgpt.com/",
                "origin": "https://chatgpt.com",
                "user-agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                ),
                "cache-control": "no-cache",
                "pragma": "no-cache",
            }
            if access_token:
                headers["authorization"] = f"Bearer {access_token}"
            response = self.session.get(
                "https://chatgpt.com/api/auth/session",
                headers=headers,
                timeout=20,
            )
            set_cookie_text = self._flatten_set_cookie_headers(response)
            request_cookie_text = self._extract_request_cookie_header(response)
            if response.status_code == 200:
                try:
                    data = response.json() or {}
                    access_from_json = str(data.get("accessToken") or "").strip()
                    if access_from_json:
                        access_token = access_from_json
                except Exception:
                    pass
            else:
                self._log(f"/api/auth/session 返回异常状态: {response.status_code}", "warning")
        except Exception as e:
            self._log(f"获取 auth/session 失败: {e}", "warning")

        # 1) 直接从 cookie jar 拿
        session_token = self._extract_session_token_from_cookie_jar(self.session.cookies)

        # 2) 从完整 cookies 文本兜底（含分片）
        if not session_token:
            session_token = self._extract_session_token_from_cookie_text(self._dump_session_cookies())

        # 3) 从 set-cookie 兜底（含分片）
        if not session_token and set_cookie_text:
            session_token = self._extract_session_token_from_cookie_text(set_cookie_text)

        # 4) 从请求 Cookie 头兜底（对齐 F12 Network 观测）
        if not session_token and request_cookie_text:
            session_token = self._extract_session_token_from_cookie_text(request_cookie_text)

        # 兜底：已有 access_token 但无 session_token 时，带 Bearer 再请求一次 auth/session
        if (not session_token) and access_token:
            try:
                retry_response = self.session.get(
                    "https://chatgpt.com/api/auth/session",
                    headers={
                        "accept": "application/json",
                        "referer": "https://chatgpt.com/",
                        "origin": "https://chatgpt.com",
                        "user-agent": (
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                        ),
                        "authorization": f"Bearer {access_token}",
                        "cache-control": "no-cache",
                        "pragma": "no-cache",
                    },
                    timeout=20,
                )
                retry_set_cookie = self._flatten_set_cookie_headers(retry_response)
                retry_request_cookie = self._extract_request_cookie_header(retry_response)
                if not session_token:
                    session_token = self._extract_session_token_from_cookie_jar(self.session.cookies)
                if not session_token:
                    session_token = self._extract_session_token_from_cookie_text(self._dump_session_cookies())
                if not session_token and retry_set_cookie:
                    session_token = self._extract_session_token_from_cookie_text(retry_set_cookie)
                if not session_token and retry_request_cookie:
                    session_token = self._extract_session_token_from_cookie_text(retry_request_cookie)
            except Exception as e:
                self._log(f"Bearer 兜底换 session_token 失败: {e}", "warning")

        if not session_token:
            cookies_text = self._dump_session_cookies()
            raw_direct_match = re.search(
                r"(?:^|[;,]\s*)(?:__|_)Secure-next-auth\.session-token=([^;,]*)",
                cookies_text,
            )
            raw_direct_len = len(str(raw_direct_match.group(1) or "").strip()) if raw_direct_match else 0
            chunk_count = len(re.findall(r"(?:__|_)Secure-next-auth\.session-token\.(\d+)=", cookies_text))
            req_cookie_len = len(str(request_cookie_text or "").strip())
            self._log(
                f"auth/session 仍未命中 session_token（raw_direct_len={raw_direct_len}, chunks={chunk_count}, req_cookie_len={req_cookie_len}）",
                "warning",
            )

        # 设备 ID 同步
        did = ""
        try:
            did = str(self.session.cookies.get("oai-did") or "").strip()
        except Exception:
            did = ""
        if did:
            self.device_id = did
            result.device_id = did

        if session_token:
            self.session_token = session_token
            result.session_token = session_token
        if access_token:
            result.access_token = access_token

        self._log(
            "Auth Session 捕获结果: session_token="
            + ("有" if bool(result.session_token) else "无")
            + ", access_token="
            + ("有" if bool(result.access_token) else "无")
        )
        return bool(result.session_token and result.access_token)

    def _bootstrap_chatgpt_signin_for_session(self, result: RegistrationResult) -> bool:
        """
        对齐 ABCard 的补会话路径：
        csrf -> signin/openai -> 跟随跳转 -> auth/session，目标是拿到 session_token。
        """
        self._log("Session Token 还没就位，尝试 ABCard 同款会话桥接...")
        self._warmup_chatgpt_session()
        csrf_token = ""
        auth_url = ""
        try:
            csrf_resp = self.session.get(
                "https://chatgpt.com/api/auth/csrf",
                headers={
                    "accept": "application/json",
                    "referer": "https://chatgpt.com/auth/login",
                    "origin": "https://chatgpt.com",
                    "user-agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                    ),
                },
                timeout=20,
            )
            if csrf_resp.status_code == 200:
                csrf_token = str((csrf_resp.json() or {}).get("csrfToken") or "").strip()
            else:
                self._log(f"csrf 获取失败: HTTP {csrf_resp.status_code}", "warning")
        except Exception as e:
            self._log(f"csrf 获取异常: {e}", "warning")

        if not csrf_token:
            self._log("csrf token 为空，跳过会话桥接", "warning")
            return False

        try:
            signin_resp = self.session.post(
                "https://chatgpt.com/api/auth/signin/openai",
                headers={
                    "accept": "application/json",
                    "content-type": "application/x-www-form-urlencoded",
                    "origin": "https://chatgpt.com",
                    "referer": "https://chatgpt.com/auth/login",
                    "user-agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                    ),
                },
                data={
                    "csrfToken": csrf_token,
                    "callbackUrl": "https://chatgpt.com/",
                    "json": "true",
                },
                timeout=20,
            )
            if signin_resp.status_code == 200:
                auth_url = str((signin_resp.json() or {}).get("url") or "").strip()
            else:
                self._log(f"signin/openai 失败: HTTP {signin_resp.status_code}", "warning")
        except Exception as e:
            self._log(f"signin/openai 异常: {e}", "warning")

        if not auth_url:
            self._log("signin/openai 未返回 auth_url，跳过会话桥接", "warning")
            return False

        callback_url = ""
        final_url = auth_url
        try:
            callback_url, final_url = self._follow_chatgpt_auth_redirects(auth_url)
        except Exception as e:
            self._log(f"会话桥接重定向跟踪异常: {e}", "warning")
            callback_url = ""
            final_url = auth_url

        # 若已拿到 callback，补打一跳确保 next-auth callback 被完整执行。
        if callback_url and "error=" not in callback_url:
            try:
                self.session.get(
                    callback_url,
                    headers={
                        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "referer": "https://chatgpt.com/auth/login",
                        "user-agent": (
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                        ),
                    },
                    allow_redirects=True,
                    timeout=25,
                )
            except Exception as e:
                self._log(f"会话桥接 callback 补跳异常: {e}", "warning")
        elif callback_url and "error=" in callback_url:
            self._log(f"会话桥接回调返回错误参数: {callback_url[:140]}...", "warning")
        else:
            self._log(f"会话桥接未命中 callback，final_url={final_url[:120]}...", "warning")
            # 命中 auth.openai 登录页时，尝试自动登录补会话（对齐 ABCard 的登录态建立思路）。
            if "auth.openai.com/log-in" in str(final_url or "").lower():
                self._log("会话桥接进入登录页，尝试自动登录后继续抓取 session_token...")
                if self._bridge_login_for_session_token(result):
                    return True

        self._warmup_chatgpt_session()
        cookie_text = self._dump_session_cookies()
        direct_token = self._extract_session_token_from_cookie_text(cookie_text)
        has_direct = bool(direct_token)
        chunk_count = len(re.findall(r"(?:__|_)Secure-next-auth\.session-token\.(\d+)=", cookie_text))
        if direct_token and not result.session_token:
            self.session_token = direct_token
            result.session_token = direct_token
            self._log(f"会话桥接已缓存 session_token（len={len(direct_token)}）")
        self._log(
            f"会话桥接后 cookie 概览: direct={'有' if has_direct else '无'}, chunks={chunk_count}"
        )
        return self._capture_auth_session_tokens(result, access_hint=result.access_token)

    def _bridge_login_for_session_token(self, result: RegistrationResult) -> bool:
        """
        当 chatgpt signin/openai 跳回 auth.openai 登录页时，自动补一次登录流程：
        login -> password -> email otp -> workspace -> auth/session。
        """
        try:
            if not self.email or not self.password:
                self._log("会话桥接自动登录缺少邮箱或密码，无法继续", "warning")
                return False

            did = ""
            try:
                did = str(self.session.cookies.get("oai-did") or "").strip()
            except Exception:
                did = ""
            if not did:
                did = str(uuid.uuid4())
                try:
                    self.session.cookies.set("oai-did", did, domain=".chatgpt.com", path="/")
                except Exception:
                    pass
            self.device_id = did
            result.device_id = result.device_id or did

            sen_token = self._check_sentinel(did)
            login_start_result = self._submit_login_start(did, sen_token)
            if not login_start_result.success:
                self._log(
                    f"会话桥接自动登录入口失败: {login_start_result.error_message}",
                    "warning",
                )
                return False
            page_type = str(login_start_result.page_type or "").strip()
            if page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]:
                self._log("会话桥接自动登录已直达邮箱验证码页，跳过密码提交")
            elif page_type == OPENAI_PAGE_TYPES["LOGIN_PASSWORD"]:
                password_result = self._submit_login_password()
                if not password_result.success:
                    self._log(
                        f"会话桥接自动登录提交密码失败: {password_result.error_message}",
                        "warning",
                    )
                    return False
                if not password_result.is_existing_account:
                    self._log(
                        f"会话桥接自动登录未进入邮箱验证码页: {password_result.page_type or 'unknown'}",
                        "warning",
                    )
                    return False
            else:
                self._log(
                    f"会话桥接自动登录入口返回未知页面: {page_type or 'unknown'}",
                    "warning",
                )
                return False

            if not self._verify_email_otp_with_retry(stage_label="会话桥接登录验证码", max_attempts=3):
                self._log("会话桥接自动登录验证码校验失败", "warning")
                return False

            # OTP 成功后先直接抓一次 auth/session，避免无谓依赖 workspace 流程。
            self._warmup_chatgpt_session()
            if self._capture_auth_session_tokens(result, access_hint=result.access_token):
                self._log("会话桥接自动登录在 OTP 后已命中 session_token")
                return True

            workspace_id = self._get_workspace_id()
            if not workspace_id:
                workspace_id = str(result.workspace_id or "").strip()
                if workspace_id:
                    self._log(f"会话桥接自动登录复用已知 workspace_id: {workspace_id}")
            if not workspace_id:
                self._log("会话桥接自动登录未获取到 workspace_id", "warning")
                return False
            result.workspace_id = workspace_id

            continue_url = self._select_workspace(workspace_id)
            if not continue_url:
                cached_continue = str(self._create_account_continue_url or "").strip()
                if cached_continue:
                    continue_url = cached_continue
                    self._log("会话桥接自动登录未获取到 continue_url，改用 create_account 缓存 continue_url", "warning")
                else:
                    self._log("会话桥接自动登录未获取到 continue_url", "warning")
                    return False

            callback_url, final_url = self._follow_redirects(continue_url)
            self._log(
                f"会话桥接自动登录重定向完成: callback={'有' if callback_url else '无'}, final={str(final_url or '')[:100]}..."
            )

            self._warmup_chatgpt_session()
            return self._capture_auth_session_tokens(result, access_hint=result.access_token)
        except Exception as e:
            self._log(f"会话桥接自动登录异常: {e}", "warning")
            return False

    def _follow_chatgpt_auth_redirects(self, start_url: str) -> Tuple[str, str]:
        """
        对齐 ABCard 的 next-auth 重定向跟踪：
        - 手动跟踪 30x
        - 识别 /api/auth/callback/openai
        Returns:
            (callback_url, final_url)
        """
        import urllib.parse

        current_url = str(start_url or "").strip()
        callback_url = ""
        bridged_header_token = ""
        if not current_url:
            return "", ""

        max_redirects = 12
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        )
        for i in range(max_redirects):
            self._log(f"会话桥接重定向 {i+1}/{max_redirects}: {current_url[:120]}...")
            if "/api/auth/callback/openai" in current_url and not callback_url:
                callback_url = current_url

            resp = self.session.get(
                current_url,
                headers={
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "referer": "https://chatgpt.com/",
                    "user-agent": ua,
                },
                timeout=25,
                allow_redirects=False,
            )

            # 直接从每一跳响应头 Set-Cookie 抓 session_token（对齐 F12 Network 视角）
            set_cookie_text = self._flatten_set_cookie_headers(resp)
            token_from_header = self._extract_session_token_from_cookie_text(set_cookie_text)
            if token_from_header:
                bridged_header_token = token_from_header
                # 同时写入两种命名兼容，避免库在不同平台下键名差异。
                for name in ("__Secure-next-auth.session-token", "_Secure-next-auth.session-token"):
                    for domain in (".chatgpt.com", "chatgpt.com"):
                        try:
                            self.session.cookies.set(name, token_from_header, domain=domain, path="/")
                        except Exception:
                            continue
                self._log(
                    f"会话桥接命中 Set-Cookie session_token（len={len(token_from_header)}）"
                )

            if resp.status_code not in (301, 302, 303, 307, 308):
                break

            location = str(resp.headers.get("Location") or "").strip()
            if not location:
                break
            current_url = urllib.parse.urljoin(current_url, location)

        if callback_url and not str(current_url or "").startswith("https://chatgpt.com/"):
            try:
                self.session.get(
                    "https://chatgpt.com/",
                    headers={
                        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "referer": current_url,
                        "user-agent": ua,
                    },
                    timeout=20,
                )
            except Exception:
                pass

        self._log(
            f"会话桥接重定向结束: callback={'有' if callback_url else '无'}, "
            f"set_cookie_token={'有' if bool(bridged_header_token) else '无'}, final={current_url[:120]}..."
        )
        return callback_url, current_url

    def _complete_token_exchange(self, result: RegistrationResult, require_login_otp: bool = True) -> bool:
        """在登录态已建立后，补齐 session/access，并尽量获取 OAuth token。"""
        if require_login_otp:
            self._log("等待登录验证码到场，最后这位嘉宾还在路上...")
            self._log("核对登录验证码，验明正身一下...")
            if not self._verify_email_otp_with_retry(stage_label="登录验证码", max_attempts=3):
                result.error_message = "验证码校验失败"
                return False
        else:
            self._log("ABCard 入口链路：跳过二次登录验证码，直接进入 workspace + redirect + auth/session 抓取")

        self._log("摸一下 Workspace ID，看看该坐哪桌...")
        workspace_id = self._get_workspace_id()
        continue_url = ""
        if workspace_id:
            result.workspace_id = workspace_id

            self._log("选择 Workspace，安排个靠谱座位...")
            continue_url = self._select_workspace(workspace_id)
            if not continue_url:
                cached_continue = str(self._create_account_continue_url or "").strip()
                if cached_continue:
                    continue_url = cached_continue
                    self._log("workspace/select 未返回 continue_url，改用 create_account 缓存 continue_url", "warning")
                else:
                    result.error_message = "选择 Workspace 失败"
                    return False
        else:
            cached_continue = str(self._create_account_continue_url or "").strip()
            if cached_continue:
                continue_url = cached_continue
                self._log("未获取到 Workspace ID，改用 create_account 缓存 continue_url 继续链路", "warning")
            else:
                result.error_message = "获取 Workspace ID 失败"
                return False

        self._log("顺着重定向面包屑往前走，别跟丢了...")
        callback_url, final_url = self._follow_redirects(continue_url)
        self._log(
            f"重定向链完成，callback={'有' if callback_url else '无'}，final={final_url[:100]}..."
        )
        self._log("重定向链结束，直接请求 /api/auth/session 抓取 session/access...")
        captured = self._capture_auth_session_tokens(result, access_hint=result.access_token)
        if not captured:
            self._log("直抓未命中，补一次 chatgpt 预热后再抓取...", "warning")
            self._warmup_chatgpt_session()
            captured = self._capture_auth_session_tokens(result, access_hint=result.access_token)
        final_url_lower = str(final_url or "").lower()
        add_phone_gate = ("auth.openai.com/add-phone" in final_url_lower)

        # ABCard 入口常见失败点：被 add-phone 风控页截断，导致拿不到 callback/session。
        if add_phone_gate and (not callback_url) and (not captured):
            self._log("检测到 auth.openai.com/add-phone 风控页，当前链路未完成 OAuth 回调", "warning")
            if (not require_login_otp) and (not self._is_existing_account):
                self._log("ABCard 入口命中 add-phone，回退原生重登链路再试一次...", "warning")
                login_ready, login_error = self._restart_login_flow()
                if not login_ready:
                    result.error_message = f"ABCard 回退原生链路失败: {login_error}"
                    return False
                return self._complete_token_exchange(result, require_login_otp=True)
            result.error_message = "命中 add-phone 风控页，未获取到 session_token"
            return False

        callback_has_error = bool(
            callback_url and ("error=" in callback_url) and ("code=" not in callback_url)
        )
        if callback_url:
            if callback_has_error:
                self._log(f"回调返回错误参数，跳过 OAuth 回调: {callback_url[:140]}...", "warning")
                if not captured:
                    result.error_message = "OAuth 回调返回 access_denied，且未获取到 auth/session"
                    return False
            else:
                self._log("处理 OAuth 回调，准备把 token 请出来...")
                token_info = self._handle_oauth_callback(callback_url)
                if token_info:
                    result.account_id = token_info.get("account_id", "")
                    result.access_token = token_info.get("access_token", "") or result.access_token
                    result.refresh_token = token_info.get("refresh_token", "")
                    result.id_token = token_info.get("id_token", "")
                elif captured:
                    self._log("OAuth 回调失败，但 session/access 已拿到，继续后续流程", "warning")
                else:
                    result.error_message = "处理 OAuth 回调失败"
                    return False
        else:
            if captured:
                self._log("未拿到 callback_url，但 session/access 已拿到，继续后续流程", "warning")
            else:
                result.error_message = "跟随重定向链失败"
                return False

        result.password = self.password or ""
        result.source = "login" if self._is_existing_account else "register"
        result.device_id = result.device_id or str(self.device_id or "")

        session_cookie = self.session.cookies.get("__Secure-next-auth.session-token")
        if session_cookie:
            self.session_token = session_cookie
            result.session_token = session_cookie
            self._log("Session Token 也捞到了，今天这网没白连")

        if not result.access_token or not result.session_token:
            # 再捞一次，避免某些链路里 session 建立稍慢
            self._capture_auth_session_tokens(result, access_hint=result.access_token)
        if not result.session_token:
            # 对齐 ABCard：尝试走 csrf + signin/openai 的会话桥接。
            self._bootstrap_chatgpt_signin_for_session(result)
        if not result.session_token:
            result.session_token = self._extract_session_token_from_cookie_text(self._dump_session_cookies())
        if not result.device_id:
            result.device_id = str(self.device_id or self.session.cookies.get("oai-did") or "")

        if not result.access_token:
            result.error_message = "未获取到 access_token"
            return False
        if not result.session_token:
            native_register_flow = (self.registration_entry_flow == "native") and (not self._is_existing_account)
            if native_register_flow:
                # 对齐 K:\1\2 备份：原生注册流程里 session_token 不做阻断。
                self._log(
                    "当前链路未拿到 session_token，先保存账号并标记待补会话（可在账号详情/支付页一键补全）",
                    "warning",
                )
            else:
                # 非原生注册入口仍保持强制，避免后续流程不可用。
                if not self._ensure_session_token_strict(result, max_rounds=2):
                    result.error_message = "未获取到 session_token（强制要求）"
                    self._log(
                        "强制模式未拿到 session_token，本次注册判定失败，请检查网络/代理与登录回调链路",
                        "error",
                    )
                    return False

        return True

    def _complete_token_exchange_native_backup(self, result: RegistrationResult) -> bool:
        """
        原生入口对齐备份版收尾链路：
        登录验证码 -> Workspace -> redirect -> OAuth callback -> token 入袋。
        """
        def _is_registration_gate_url(url: str) -> bool:
            u = str(url or "").strip().lower()
            if not u:
                return False
            return ("auth.openai.com/about-you" in u) or ("auth.openai.com/add-phone" in u)

        self._log("等待登录验证码到场，最后这位嘉宾还在路上...")
        self._log("核对登录验证码，验明正身一下...")
        login_otp_tried_codes: set[str] = set()
        login_otp_ok = self._verify_email_otp_with_retry(
            stage_label="登录验证码",
            max_attempts=1,
            fetch_timeout=120,
            attempted_codes=login_otp_tried_codes,
        )
        if not login_otp_ok:
            self._log("登录验证码首轮未命中，尝试在当前会话原地重发 OTP 后再校验...", "warning")
            resent = self._send_verification_code(referer="https://auth.openai.com/email-verification")
            if resent:
                login_otp_ok = self._verify_email_otp_with_retry(
                    stage_label="登录验证码(原地重发)",
                    max_attempts=2,
                    fetch_timeout=120,
                    attempted_codes=login_otp_tried_codes,
                )

        if not login_otp_ok:
            self._log("登录验证码仍未命中，尝试重触发登录 OTP 后再校验...", "warning")
            if not self._retrigger_login_otp():
                self._log("重触发登录 OTP 失败，尝试完整重登链路后再校验一次...", "warning")
                login_ready, login_error = self._restart_login_flow()
                if not login_ready:
                    result.error_message = f"登录验证码重触发失败，且完整重登失败: {login_error}"
                    return False
            login_otp_ok = self._verify_email_otp_with_retry(
                stage_label="登录验证码(重发)",
                max_attempts=3,
                fetch_timeout=120,
                attempted_codes=login_otp_tried_codes,
            )
            if not login_otp_ok:
                result.error_message = "验证码校验失败"
                return False

        self._log("摸一下 Workspace ID，看看该坐哪桌...")
        workspace_id = str(self._last_validate_otp_workspace_id or "").strip()
        if workspace_id:
            self._log(f"使用 OTP 返回的 Workspace ID: {workspace_id}")
        if not workspace_id:
            workspace_id = str(self._get_workspace_id() or "").strip()
        if workspace_id:
            result.workspace_id = workspace_id

        continue_url = ""
        otp_continue = str(self._last_validate_otp_continue_url or "").strip()
        if otp_continue and _is_registration_gate_url(otp_continue):
            self._log("OTP 返回 continue_url 指向注册门页（about-you/add-phone），本轮收尾忽略该地址", "warning")
            otp_continue = ""

        cached_continue = str(self._create_account_continue_url or "").strip()
        if cached_continue and _is_registration_gate_url(cached_continue):
            self._log("create_account 缓存 continue_url 指向注册门页（about-you/add-phone），本轮收尾忽略该地址", "warning")
            cached_continue = ""

        if workspace_id:
            self._log("选择 Workspace，安排个靠谱座位...")
            continue_url = str(self._select_workspace(workspace_id) or "").strip()
            if not continue_url:
                self._log("workspace/select 未返回 continue_url，尝试 OAuth authorize 兜底", "warning")

        if not continue_url:
            oauth_start_url = str(
                (
                    getattr(self.oauth_start, "auth_url", "")
                    or getattr(self.oauth_start, "url", "")
                    if self.oauth_start
                    else ""
                )
                or ""
            ).strip()
            if oauth_start_url:
                continue_url = oauth_start_url
                self._log("使用 OAuth authorize URL 作为兜底 continue_url", "warning")

        if not continue_url and otp_continue:
            continue_url = otp_continue
            self._log("使用 OTP 返回 continue_url 继续授权链路", "warning")

        if not continue_url and cached_continue:
            continue_url = cached_continue
            self._log("使用 create_account 缓存 continue_url 作为兜底", "warning")

        if not continue_url:
            result.error_message = "获取 continue_url 失败"
            return False

        self._log("顺着重定向面包屑往前走，别跟丢了...")
        callback_url, _final_url = self._follow_redirects(continue_url)
        if not callback_url:
            self._log("未命中 OAuth 回调，尝试 auth/session 兜底抓取 token...", "warning")
            self._capture_auth_session_tokens(result, access_hint=result.access_token)
            if not result.account_id:
                result.account_id = str(self._create_account_account_id or "").strip()
            if not result.workspace_id:
                result.workspace_id = str(workspace_id or self._create_account_workspace_id or "").strip()
            if not result.refresh_token:
                result.refresh_token = str(self._create_account_refresh_token or "").strip()
            if result.access_token:
                result.password = self.password or ""
                result.source = "login" if self._is_existing_account else "register"
                result.device_id = result.device_id or str(self.device_id or "")
                self._log("未命中 callback，已通过 auth/session 兜底拿到 Access Token，继续完成注册", "warning")
                return True

            # 对新注册账号放宽：账号已创建成功时允许“注册成功、token 待补”
            if (not self._is_existing_account) and self._create_account_account_id:
                result.account_id = result.account_id or str(self._create_account_account_id or "").strip()
                result.workspace_id = result.workspace_id or str(workspace_id or self._create_account_workspace_id or "").strip()
                result.refresh_token = result.refresh_token or str(self._create_account_refresh_token or "").strip()
                result.password = self.password or ""
                result.source = "register"
                result.device_id = result.device_id or str(self.device_id or "")
                self._log("回调链路未命中且未抓到 Access Token，但账号已创建成功；按注册成功收尾（token 待后续补齐）", "warning")
                return True

            result.error_message = "跟随重定向链失败"
            return False

        self._log("处理 OAuth 回调，准备把 token 请出来...")
        token_info = self._handle_oauth_callback(callback_url)
        if not token_info:
            if (not self._is_existing_account) and self._create_account_account_id:
                result.account_id = result.account_id or str(self._create_account_account_id or "").strip()
                result.workspace_id = result.workspace_id or str(workspace_id or self._create_account_workspace_id or "").strip()
                result.refresh_token = result.refresh_token or str(self._create_account_refresh_token or "").strip()
                result.password = self.password or ""
                result.source = "register"
                result.device_id = result.device_id or str(self.device_id or "")
                self._log("OAuth 回调处理失败，但账号已创建成功；按注册成功收尾（token 待后续补齐）", "warning")
                return True
            result.error_message = "处理 OAuth 回调失败"
            return False

        result.account_id = token_info.get("account_id", "")
        result.access_token = token_info.get("access_token", "")
        result.refresh_token = token_info.get("refresh_token", "")
        result.id_token = token_info.get("id_token", "")
        result.password = self.password or ""
        result.source = "login" if self._is_existing_account else "register"
        result.device_id = result.device_id or str(self.device_id or "")

        session_cookie = self.session.cookies.get("__Secure-next-auth.session-token")
        if session_cookie:
            self.session_token = session_cookie
            result.session_token = session_cookie
            self._log("Session Token 也捞到了，今天这网没白连")

        return True

    def _complete_token_exchange_outlook(self, result: RegistrationResult) -> bool:
        """
        Outlook 入口链路（迁移版）：
        对齐 codex-console-main-clean 的收尾流程，
        走「登录 OTP -> Workspace -> OAuth callback」主干，避免 ABCard/native 增强链路干扰。
        同时补齐“第二封验证码”重试链路，避免 Outlook 轮询卡死。
        """
        self._log("等待登录验证码到场，最后这位嘉宾还在路上...")
        self._log("核对登录验证码，验明正身一下...")
        login_otp_tried_codes: set[str] = set()
        login_otp_ok = self._verify_email_otp_with_retry(
            stage_label="登录验证码",
            max_attempts=1,
            fetch_timeout=90,
            attempted_codes=login_otp_tried_codes,
        )
        if not login_otp_ok:
            self._log("登录验证码首轮未命中，先尝试当前会话原地重发 OTP 后再校验...", "warning")
            resent = self._send_verification_code(referer="https://auth.openai.com/email-verification")
            if resent:
                login_otp_ok = self._verify_email_otp_with_retry(
                    stage_label="登录验证码(原地重发)",
                    max_attempts=2,
                    fetch_timeout=90,
                    attempted_codes=login_otp_tried_codes,
                )

        if not login_otp_ok:
            self._log("登录验证码仍未命中，尝试重触发登录 OTP 后再校验...", "warning")
            if not self._retrigger_login_otp():
                self._log("重触发登录 OTP 失败，尝试完整重登链路后再校验一次...", "warning")
                login_ready, login_error = self._restart_login_flow()
                if not login_ready:
                    result.error_message = f"登录验证码重触发失败，且完整重登失败: {login_error}"
                    return False

            login_otp_ok = self._verify_email_otp_with_retry(
                stage_label="登录验证码(重发)",
                max_attempts=3,
                fetch_timeout=120,
                attempted_codes=login_otp_tried_codes,
            )
        if not login_otp_ok:
            result.error_message = "验证码校验失败"
            return False

        self._log("摸一下 Workspace ID，看看该坐哪桌...")
        workspace_id = str(self._last_validate_otp_workspace_id or "").strip()
        if workspace_id:
            self._log(f"使用 OTP 返回的 Workspace ID: {workspace_id}")
        if not workspace_id:
            workspace_id = str(self._get_workspace_id() or "").strip()
        if not workspace_id:
            workspace_id = str(self._last_validate_otp_workspace_id or self._create_account_workspace_id or "").strip()
            if workspace_id:
                self._log(f"Workspace ID（缓存）: {workspace_id}", "warning")

        continue_url = ""
        if workspace_id:
            result.workspace_id = workspace_id
            self._log("选择 Workspace，安排个靠谱座位...")
            continue_url = str(self._select_workspace(workspace_id) or "").strip()
            if not continue_url:
                self._log("workspace/select 未返回 continue_url，尝试使用缓存 continue_url", "warning")
        else:
            self._log("未获取到 Workspace ID，尝试直接使用缓存 continue_url", "warning")

        if not continue_url:
            continue_url = str(self._last_validate_otp_continue_url or self._create_account_continue_url or "").strip()
            if continue_url:
                self._log("使用缓存 continue_url 继续授权链路", "warning")

        if not continue_url:
            result.error_message = "获取 Workspace ID 失败"
            return False

        self._log("顺着重定向面包屑往前走，别跟丢了...")
        callback_url, _final_url = self._follow_redirects(continue_url)
        if not callback_url:
            result.error_message = "跟随重定向链失败"
            return False

        self._log("处理 OAuth 回调，准备把 token 请出来...")
        token_info = self._handle_oauth_callback(callback_url)
        if not token_info:
            result.error_message = "处理 OAuth 回调失败"
            return False

        result.account_id = str(token_info.get("account_id") or result.account_id or "").strip()
        result.access_token = str(token_info.get("access_token") or result.access_token or "").strip()
        result.refresh_token = str(token_info.get("refresh_token") or result.refresh_token or "").strip()
        result.id_token = str(token_info.get("id_token") or result.id_token or "").strip()
        result.password = self.password or ""
        result.source = "login" if self._is_existing_account else "register"
        result.device_id = result.device_id or str(self.device_id or "")

        if not result.account_id:
            result.account_id = str(self._create_account_account_id or "").strip()
        if not result.workspace_id:
            result.workspace_id = str(self._create_account_workspace_id or "").strip()
        if not result.refresh_token:
            result.refresh_token = str(self._create_account_refresh_token or "").strip()

        session_cookie = self.session.cookies.get("__Secure-next-auth.session-token")
        if session_cookie:
            self.session_token = session_cookie
            result.session_token = session_cookie
            self._log("Session Token 也捞到了，今天这网没白连")

        if not result.access_token:
            result.error_message = "未获取到 access_token"
            return False

        return True

    def _ensure_session_token_strict(self, result: RegistrationResult, max_rounds: int = 2) -> bool:
        """
        强制确保 session_token 可用。
        - 先走 auth/session 直抓
        - 再走 ABCard 同款会话桥接
        连续多轮失败则返回 False。
        """
        if result.session_token:
            return True

        rounds = max(int(max_rounds), 1)
        for idx in range(rounds):
            self._log(f"强制补会话 round {idx + 1}/{rounds}：尝试补抓 session_token ...")

            self._warmup_chatgpt_session()
            self._capture_auth_session_tokens(result, access_hint=result.access_token)
            if result.session_token:
                self._log("强制补会话成功：auth/session 已拿到 session_token")
                return True

            self._bootstrap_chatgpt_signin_for_session(result)
            if result.session_token:
                self._log("强制补会话成功：桥接链路已拿到 session_token")
                return True

            fallback_token = self._extract_session_token_from_cookie_text(self._dump_session_cookies())
            if fallback_token:
                result.session_token = fallback_token
                self.session_token = fallback_token
                self._log("强制补会话成功：cookie 文本兜底命中 session_token")
                return True

            self._log("强制补会话本轮未命中 session_token", "warning")

        return False

    def _capture_native_core_tokens(self, result: RegistrationResult) -> bool:
        """
        原生注册入口的轻量 token 抓取：
        - 不做二次登录
        - 不强依赖 session_token
        - 尽量补齐 account/workspace/access/refresh
        """
        try:
            client_id = str(getattr(self.oauth_manager, "client_id", "") or "").strip()
            if client_id:
                self._log(f"原生入口 token 抓取: Client ID: {client_id}")

            if (not result.account_id) and self._create_account_account_id:
                result.account_id = str(self._create_account_account_id or "").strip()
                self._log(f"原生入口 token 抓取: 复用 create_account Account ID: {result.account_id}")
            if (not result.refresh_token) and self._create_account_refresh_token:
                result.refresh_token = str(self._create_account_refresh_token or "").strip()
                self._log("原生入口 token 抓取: 复用 create_account Refresh Token")

            workspace_id = str(result.workspace_id or "").strip()
            if not workspace_id:
                workspace_id = str(self._create_account_workspace_id or "").strip()
            if not workspace_id:
                workspace_id = str(self._get_workspace_id() or "").strip()
            if workspace_id:
                result.workspace_id = workspace_id
                self._log(f"原生入口 token 抓取: Workspace ID: {workspace_id}")
            else:
                self._log("原生入口 token 抓取: 未获取到 Workspace ID", "warning")

            continue_url = ""
            if workspace_id:
                continue_url = str(self._select_workspace(workspace_id) or "").strip()
            if not continue_url:
                cached_continue = str(self._create_account_continue_url or "").strip()
                if cached_continue:
                    continue_url = cached_continue
                    self._log("原生入口 token 抓取: 使用 create_account 缓存 continue_url", "warning")

            callback_url: Optional[str] = None
            final_url = ""
            if continue_url:
                self._log("原生入口 token 抓取: 跟随重定向链获取 OAuth callback...")
                callback_url, final_url = self._follow_redirects(continue_url)
                self._log(
                    f"原生入口 token 抓取: 重定向完成，callback={'有' if callback_url else '无'}，final={str(final_url)[:100]}..."
                )
            else:
                self._log("原生入口 token 抓取: 未获得 continue_url，跳过 callback 交换", "warning")

            callback_has_error = bool(
                callback_url and ("error=" in callback_url) and ("code=" not in callback_url)
            )
            if callback_url and (not callback_has_error):
                token_info = self._handle_oauth_callback(callback_url)
                if token_info:
                    result.account_id = str(token_info.get("account_id") or result.account_id or "").strip()
                    result.access_token = str(token_info.get("access_token") or result.access_token or "").strip()
                    result.refresh_token = str(token_info.get("refresh_token") or result.refresh_token or "").strip()
                    result.id_token = str(token_info.get("id_token") or result.id_token or "").strip()
                    self._log(
                        "原生入口 token 抓取结果: "
                        f"account_id={'有' if bool(result.account_id) else '无'}, "
                        f"access={'有' if bool(result.access_token) else '无'}, "
                        f"refresh={'有' if bool(result.refresh_token) else '无'}"
                    )
                else:
                    self._log("原生入口 token 抓取: OAuth 回调处理失败", "warning")
            elif callback_has_error:
                self._log(f"原生入口 token 抓取: callback 含 error，跳过 token 交换: {callback_url[:140]}...", "warning")
            else:
                self._log("原生入口 token 抓取: 未命中 callback_url", "warning")

            # 不走重登，仅轻量探测 auth/session 里的 accessToken（不依赖 session_token）。
            if not result.access_token:
                self._capture_access_token_light(result)

            if (not result.account_id) and result.id_token:
                try:
                    account_info = self.oauth_manager.extract_account_info(result.id_token)
                    result.account_id = str(account_info.get("account_id") or "").strip()
                except Exception:
                    pass
            if (not result.account_id) and result.access_token:
                token_acc = self._extract_account_id_from_access_token(result.access_token)
                if token_acc:
                    result.account_id = token_acc
                    self._log(f"原生入口 token 抓取: 从 access_token 解析 Account ID: {token_acc}")
            if not result.workspace_id:
                try:
                    workspace_id_after = str(self._get_workspace_id() or "").strip()
                    if workspace_id_after:
                        result.workspace_id = workspace_id_after
                        self._log(f"原生入口 token 抓取: 二次获取 Workspace ID 成功: {workspace_id_after}")
                except Exception:
                    pass

            missing = []
            if not result.account_id:
                missing.append("Account ID")
            if not result.workspace_id:
                missing.append("Workspace ID")
            if not result.access_token:
                missing.append("Access Token")
            if not result.refresh_token:
                missing.append("Refresh Token")
            if missing:
                self._log(f"原生入口 token 抓取: 未获取字段 -> {', '.join(missing)}", "warning")

            return bool(result.access_token and result.refresh_token)
        except Exception as e:
            self._log(f"原生入口 token 抓取异常: {e}", "warning")
            return False

    def _try_salvage_add_phone_after_otp(self, result: RegistrationResult) -> bool:
        """
        OTP 后命中 add-phone 时，先在当前 OAuth 会话里抢救 workspace/callback/token。
        不进入手机号验证，也不触发 anyauto，只做一次轻量续跑。
        """
        try:
            self._log(
                "add_phone 抢救: 不进入手机号验证，先尝试基于当前会话解析 workspace/callback/token",
                "warning",
            )
            result.password = self.password or ""
            result.source = "register"
            result.device_id = result.device_id or str(self.device_id or self.session.cookies.get("oai-did") or "")

            workspace_hint = str(self._last_validate_otp_workspace_id or "").strip()
            if not workspace_hint:
                workspace_hint = str(self._get_workspace_id() or "").strip()
            if workspace_hint:
                result.workspace_id = result.workspace_id or workspace_hint
                self._log(f"add_phone 抢救: Workspace ID 线索={workspace_hint}")

            recovered = self._capture_native_core_tokens(result)
            if not recovered:
                consent_url = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
                referer_url = str(self._last_validate_otp_continue_url or self._last_auth_page_url or "https://auth.openai.com/add-phone").strip()
                self._log("add_phone 抢救: 访问 canonical consent，争取重签 workspace/callback", "warning")
                try:
                    self._browser_pause()
                    consent_resp = self.session.get(
                        consent_url,
                        headers=self._build_browser_headers(
                            consent_url,
                            accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            referer=referer_url,
                            navigation=True,
                        ),
                        allow_redirects=True,
                        timeout=20,
                    )
                    consent_final_url = str(getattr(consent_resp, "url", "") or "").strip()
                    if consent_final_url:
                        self._last_auth_page_url = consent_final_url
                    self._log(f"add_phone 抢救: canonical consent 最终落点 {(consent_final_url or consent_url)[:160]}")
                    self._log_oauth_session_quality("add_phone canonical consent 后")
                except Exception as consent_err:
                    self._log(f"add_phone 抢救: 访问 canonical consent 异常: {consent_err}", "warning")

                try:
                    session_data = self._load_workspace_session_data(
                        consent_url,
                        self._fingerprint_user_agent,
                        self._fingerprint_impersonate,
                    ) or {}
                except Exception as session_err:
                    self._log(f"add_phone 抢救: 解析 consent session 数据异常: {session_err}", "warning")
                    session_data = {}
                workspaces = session_data.get("workspaces") or []
                if workspaces:
                    workspace_hint = str((workspaces[0] or {}).get("id") or "").strip()
                    if workspace_hint:
                        result.workspace_id = workspace_hint
                        self._create_account_workspace_id = self._create_account_workspace_id or workspace_hint
                        self._log(f"add_phone 抢救: consent session 提取 Workspace ID={workspace_hint}")

                workspace_hint = str(result.workspace_id or self._get_workspace_id() or "").strip()
                continue_url = ""
                if workspace_hint:
                    result.workspace_id = workspace_hint
                    self._log(f"add_phone 抢救: canonical consent 后 Workspace ID={workspace_hint}")
                    continue_url = str(self._select_workspace(workspace_hint) or "").strip()
                if not continue_url:
                    continue_url = consent_url
                    self._log("add_phone 抢救: workspace/select 未拿到 continue_url，改用 canonical consent 直接跟随重定向", "warning")

                callback_url, final_url = self._follow_redirects(continue_url)
                if callback_url:
                    self._log(f"add_phone 抢救: 跟随重定向命中 callback {callback_url[:140]}...")
                    token_info = self._handle_oauth_callback(callback_url)
                    if token_info:
                        result.account_id = str(token_info.get("account_id") or result.account_id or "").strip()
                        result.access_token = str(token_info.get("access_token") or result.access_token or "").strip()
                        result.refresh_token = str(token_info.get("refresh_token") or result.refresh_token or "").strip()
                        result.id_token = str(token_info.get("id_token") or result.id_token or "").strip()
                        self._log("add_phone 抢救: canonical consent 回调已拿到 OAuth token", "warning")
                else:
                    self._log(f"add_phone 抢救: canonical consent 未命中 callback，final={final_url[:140]}...", "warning")

                recovered = self._capture_native_core_tokens(result) or bool(result.access_token and result.refresh_token)
            if recovered and self._ensure_native_required_tokens(result):
                session_cookie = self.session.cookies.get("__Secure-next-auth.session-token")
                if session_cookie:
                    self.session_token = session_cookie
                    result.session_token = session_cookie
                    self._log("add_phone 抢救: Session Token 也拿到了")
                self._log("add_phone 抢救成功：当前会话已拿到核心 token", "warning")
                return True

            self._log(
                "add_phone 抢救未拿到完整 token："
                f" account_id={'有' if bool(result.account_id) else '无'},"
                f" workspace={'有' if bool(result.workspace_id) else '无'},"
                f" access={'有' if bool(result.access_token) else '无'},"
                f" refresh={'有' if bool(result.refresh_token) else '无'}",
                "warning",
            )
            return False
        except Exception as e:
            self._log(f"add_phone 抢救异常: {e}", "warning")
            return False

    def _capture_access_token_light(self, result: RegistrationResult) -> bool:
        """轻量从 /api/auth/session 抓 accessToken（不依赖 session_token）。"""
        try:
            response = self.session.get(
                "https://chatgpt.com/api/auth/session",
                headers={
                    "accept": "application/json",
                    "referer": "https://chatgpt.com/",
                },
                timeout=20,
            )
            if response.status_code != 200:
                self._log(f"原生入口轻量 auth/session 状态异常: {response.status_code}", "warning")
                return False
            data = response.json() or {}
            access_token = str(data.get("accessToken") or "").strip()
            if access_token:
                result.access_token = access_token
                self._log("原生入口轻量 auth/session 命中 Access Token")
                return True
            self._log("原生入口轻量 auth/session 未命中 Access Token", "warning")
            return False
        except Exception as e:
            self._log(f"原生入口轻量 auth/session 异常: {e}", "warning")
            return False

    def _extract_account_id_from_access_token(self, access_token: str) -> str:
        """从 access_token 的 JWT payload 尝试解析 chatgpt_account_id。"""
        try:
            raw = str(access_token or "").strip()
            if raw.count(".") < 2:
                return ""
            payload = raw.split(".")[1]
            import base64
            pad = "=" * ((4 - (len(payload) % 4)) % 4)
            decoded = base64.urlsafe_b64decode((payload + pad).encode("ascii"))
            claims = json.loads(decoded.decode("utf-8"))
            if not isinstance(claims, dict):
                return ""
            auth_claims = claims.get("https://api.openai.com/auth") or {}
            account_id = str(
                auth_claims.get("chatgpt_account_id")
                or claims.get("chatgpt_account_id")
                or ""
            ).strip()
            return account_id
        except Exception:
            return ""

    def _ensure_native_required_tokens(self, result: RegistrationResult) -> bool:
        """
        原生注册入口要求拿齐：
        Account ID / Workspace ID / Client ID / Access Token / Refresh Token
        """
        try:
            if (not result.account_id) and result.id_token:
                try:
                    account_info = self.oauth_manager.extract_account_info(result.id_token)
                    result.account_id = str(account_info.get("account_id") or "").strip()
                except Exception:
                    pass
            if (not result.account_id) and result.access_token:
                result.account_id = self._extract_account_id_from_access_token(result.access_token)

            if not result.workspace_id:
                result.workspace_id = str(self._get_workspace_id() or "").strip()
            if (not result.refresh_token) and self._create_account_refresh_token:
                result.refresh_token = str(self._create_account_refresh_token or "").strip()

            settings = get_settings()
            client_id = str(
                getattr(settings, "openai_client_id", "")
                or getattr(self.oauth_manager, "client_id", "")
                or ""
            ).strip()

            missing = []
            if not result.account_id:
                missing.append("Account ID")
            if not result.workspace_id:
                missing.append("Workspace ID")
            if not client_id:
                missing.append("Client ID")
            if not result.access_token:
                missing.append("Access Token")
            if not result.refresh_token:
                missing.append("Refresh Token")

            if missing:
                self._log(f"原生入口关键参数缺失: {', '.join(missing)}", "error")
                return False

            self._log(
                "原生入口关键参数校验通过: "
                f"Account ID={result.account_id}, Workspace ID={result.workspace_id}, "
                f"Client ID={client_id}, Access=有, Refresh=有"
            )
            return True
        except Exception as e:
            self._log(f"原生入口关键参数校验异常: {e}", "error")
            return False

    def _restart_login_flow(self) -> Tuple[bool, str]:
        """新注册账号完成建号后，重新发起一次登录流程拿 token。"""
        self._token_acquisition_requires_login = True
        self._log("注册这边忙完了，再走一趟登录把 token 请出来，收个尾...")
        self._reset_auth_flow()

        did, sen_token = self._prepare_authorize_flow("重新登录")
        if not did:
            return False, "重新登录时获取 Device ID 失败"
        if not sen_token:
            return False, "重新登录时 Sentinel POW 验证失败"

        login_start_result = self._submit_login_start(did, sen_token)
        if not login_start_result.success:
            return False, f"重新登录提交邮箱失败: {login_start_result.error_message}"
        if login_start_result.page_type != OPENAI_PAGE_TYPES["LOGIN_PASSWORD"]:
            return False, f"重新登录未进入密码页面: {login_start_result.page_type or 'unknown'}"

        password_result = self._submit_login_password()
        if not password_result.success:
            return False, f"重新登录提交密码失败: {password_result.error_message}"
        if not password_result.is_existing_account:
            return False, f"重新登录未进入验证码页面: {password_result.page_type or 'unknown'}"
        return True, ""

    def _retrigger_login_otp(self) -> bool:
        """
        在“登录验证码”阶段重触发 OTP 发送。
        优先复用登录链路（login_start -> login_password），避免误走注册 OTP 流程。
        """
        try:
            did = str(self.device_id or self.session.cookies.get("oai-did") or "").strip()
            if not did:
                did = str(uuid.uuid4())
                try:
                    self.session.cookies.set("oai-did", did, domain=".chatgpt.com", path="/")
                except Exception:
                    pass
                self.device_id = did

            sen_token = self._check_sentinel(did)
            login_start_result = self._submit_login_start(did, sen_token)
            if not login_start_result.success:
                self._log(
                    f"重触发登录 OTP 失败：提交登录入口失败: {login_start_result.error_message}",
                    "warning",
                )
                return False

            page_type = str(login_start_result.page_type or "").strip()
            if page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]:
                self._log("重触发登录 OTP 成功：已直达邮箱验证码页")
                return True

            if page_type != OPENAI_PAGE_TYPES["LOGIN_PASSWORD"]:
                self._log(f"重触发登录 OTP 失败：未进入密码页（{page_type or 'unknown'}）", "warning")
                return False

            password_result = self._submit_login_password()
            if not password_result.success:
                self._log(f"重触发登录 OTP 失败：提交登录密码失败: {password_result.error_message}", "warning")
                return False
            if not password_result.is_existing_account:
                self._log(
                    f"重触发登录 OTP 失败：密码后未进入验证码页（{password_result.page_type or 'unknown'}）",
                    "warning",
                )
                return False

            self._log("重触发登录 OTP 成功：已进入邮箱验证码页")
            return True
        except Exception as e:
            self._log(f"重触发登录 OTP 异常: {e}", "warning")
            return False

    def _register_password(self, did: Optional[str] = None, sen_token: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """注册密码"""
        try:
            self._last_register_password_error = None
            referer_url = str(self._last_auth_page_url or "").strip()
            if (not referer_url) or ("create-account/password" not in referer_url):
                referer_url = self._refresh_create_account_password_page()
            if (not referer_url) or ("create-account/password" not in referer_url):
                referer_url = "https://auth.openai.com/create-account/password"
            self._log(f"提交注册密码使用 referer: {referer_url[:160]}")
            # 生成密码
            password = self._generate_password()
            self.password = password  # 保存密码到实例变量
            self._log(f"生成密码: {password}")

            # 提交密码注册
            register_body = json.dumps({
                "password": password,
                "username": self.email
            })
            current_did = str(did or self.device_id or self.session.cookies.get("oai-did") or "").strip()
            current_sen_token = ""
            if current_did:
                current_sen_token = self._get_browser_sentinel_token(
                    "username_password_create",
                    page_url=referer_url,
                    device_id=current_did,
                )
                if current_sen_token:
                    self._log("username_password_create: 已通过浏览器 Sentinel helper 获取 token")
            if current_did and not current_sen_token:
                try:
                    current_sen_token = str(
                        build_sentinel_token(
                            self.session,
                            current_did,
                            flow="username_password_create",
                            user_agent=self._fingerprint_user_agent,
                            sec_ch_ua=self._fingerprint_sec_ch_ua,
                            impersonate=self._fingerprint_impersonate,
                        ) or ""
                    ).strip()
                except Exception as e:
                    self._log(f"username_password_create sentinel 获取异常: {e}", "warning")
                    current_sen_token = ""
                if current_sen_token:
                    self._log("username_password_create: 已通过 HTTP PoW 获取 token")
            if current_did and not current_sen_token:
                current_sen_token = str(sen_token or "").strip() if sen_token else ""
            if current_did and not current_sen_token:
                current_sen_token = str(self._check_sentinel(current_did) or "").strip()

            response = self.session.post(
                OPENAI_API_ENDPOINTS["register"],
                headers=dict(
                    self._build_browser_headers(
                        OPENAI_API_ENDPOINTS["register"],
                        accept="application/json",
                        referer=referer_url,
                        origin="https://auth.openai.com",
                        content_type="application/json",
                        fetch_site="same-origin",
                        extra_headers={
                            "oai-device-id": current_did,
                            "openai-sentinel-token": current_sen_token or None,
                        },
                    ),
                    **generate_datadog_trace(),
                ),
                json=json.loads(register_body),
                allow_redirects=False,
                timeout=30,
            )
            self._capture_auth_cookies_from_response(response, "提交注册密码")

            self._log(f"提交密码状态: {response.status_code}")
            response_url = str(getattr(response, "url", "") or "").strip()
            if response_url:
                self._log(f"提交密码 response_url={response_url[:160]}")

            if response.status_code == 429:
                retry_after = self._parse_retry_after_seconds(response.headers.get("Retry-After"))
                request_id = str(response.headers.get("x-request-id") or "").strip()
                self._last_register_password_error = (
                    f"注册密码接口返回异常: HTTP 429"
                    + (f", retry_after={int(retry_after)}s" if retry_after > 0 else "")
                    + (f", request_id={request_id}" if request_id else "")
                )
                self._log(self._last_register_password_error, "warning")
                return False, None

            if response.status_code != 200:
                error_text = response.text[:500]
                self._log(f"密码注册失败: {error_text}", "warning")

                # 解析错误信息，判断是否是邮箱已注册
                try:
                    error_json = response.json()
                    error_msg = error_json.get("error", {}).get("message", "")
                    error_code = error_json.get("error", {}).get("code", "")
                    normalized_error_msg = str(error_msg or "").strip()
                    normalized_error_code = str(error_code or "").strip()

                    # 检测邮箱已注册的情况
                    if "already" in normalized_error_msg.lower() or "exists" in normalized_error_msg.lower() or normalized_error_code == "user_exists":
                        self._log(f"邮箱 {self.email} 可能已在 OpenAI 注册过", "error")
                        # 标记此邮箱为已注册状态
                        self._mark_email_as_registered()
                        self._last_register_password_error = "该邮箱可能已在 OpenAI 注册，建议更换邮箱或改走登录流程"
                    elif "failed to register username" in normalized_error_msg.lower():
                        self._last_register_password_error = (
                            "OpenAI 拒绝当前邮箱用户名（可能已占用或触发风控），建议更换邮箱后重试"
                        )
                        if did:
                            self._log("检测到用户名注册失败，尝试登录入口探测邮箱是否已存在...", "warning")
                            try:
                                probe = self._submit_login_start(did, sen_token)
                                if probe.success and probe.page_type in (
                                    OPENAI_PAGE_TYPES["LOGIN_PASSWORD"],
                                    OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"],
                                ):
                                    self._log("登录入口探测命中：该邮箱大概率已是 OpenAI 账号", "warning")
                                    self._mark_email_as_registered()
                                    self._last_register_password_error = (
                                        "该邮箱已存在 OpenAI 账号。"
                                        "若是刚刚注册中断，请优先使用上一轮任务日志里的“生成密码”走登录续跑；"
                                        "拿不到旧密码再更换邮箱。"
                                    )
                            except Exception as probe_error:
                                self._log(f"登录入口探测失败: {probe_error}", "warning")
                    else:
                        self._last_register_password_error = (
                            f"注册密码接口返回异常: {normalized_error_msg or f'HTTP {response.status_code}'}"
                        )
                    if normalized_error_code == "invalid_state":
                        self._log("注册密码命中 invalid_state，准备刷新 create-account/password 页面重建会话", "warning")
                        self._refresh_create_account_password_page()
                except Exception:
                    self._last_register_password_error = f"注册密码接口返回异常: HTTP {response.status_code}"

                return False, None

            return True, password

        except Exception as e:
            self._log(f"密码注册失败: {e}", "error")
            self._last_register_password_error = str(e)
            return False, None

    def _register_password_with_retry(
        self,
        did: Optional[str] = None,
        sen_token: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Retry password registration when OpenAI returns a generic recoverable 400."""
        self._raise_if_cancelled("任务已取消，停止密码注册重试")
        max_attempts = 5
        retryable_markers = (
            "failed to create account",
            "create account",
            "invalid_request_error",
            "invalid session",
            "invalid_state",
            "http 409",
            "http 400",
            "http 429",
            "retry_after",
            "rate limit",
        )

        for attempt in range(1, max_attempts + 1):
            self._raise_if_cancelled("任务已取消，停止密码注册重试")
            success, password = self._register_password(did, sen_token)
            if success:
                return True, password

            error_text = str(self._last_register_password_error or "").strip().lower()
            if attempt >= max_attempts:
                break
            if not any(marker in error_text for marker in retryable_markers):
                break

            self._log(
                f"密码注册命中可重试 400，准备重新生成密码后重试 ({attempt}/{max_attempts})...",
                "warning",
            )
            current_did = str(did or self.device_id or self.session.cookies.get("oai-did") or "").strip()
            should_refresh_oauth = any(marker in error_text for marker in ("http 429", "retry_after", "rate limit"))
            should_rewarm_chatgpt = any(marker in error_text for marker in ("invalid_state", "invalid session"))
            if should_refresh_oauth:
                self._log("密码注册重试: 检测到限流/重试信号，先补一次 OAuth 上下文预热", "warning")
                self._refresh_oauth_context(current_did)
            elif should_rewarm_chatgpt:
                self._log("密码注册重试: 命中 invalid_state，先重走 ChatGPT prewarm 再回到密码页", "warning")
                warm_url = self._prewarm_chatgpt_entry(self.email or "", current_did)
                if warm_url:
                    self._last_auth_page_url = warm_url
            else:
                self._log("密码注册重试: 当前更像密码页会话失配，跳过 OAuth 预热，直接重建 create-account/password", "warning")
            self._refresh_create_account_password_page()
            self._sleep_interruptible(min(3 * attempt, 10))

        return False, None

    def _mark_email_as_registered(self):
        """标记邮箱为已注册状态（用于防止重复尝试）"""
        try:
            with get_db() as db:
                # 检查是否已存在该邮箱的记录
                existing = crud.get_account_by_email(db, self.email)
                if not existing:
                    # 创建一个失败记录，标记该邮箱已注册过
                    crud.create_account(
                        db,
                        email=self.email,
                        password="",  # 空密码表示未成功注册
                        email_service=self.email_service.service_type.value,
                        email_service_id=self.email_info.get("service_id") if self.email_info else None,
                        status="failed",
                        extra_data={"register_failed_reason": "email_already_registered_on_openai"}
                    )
                    self._log(f"已在数据库中标记邮箱 {self.email} 为已注册状态")
        except Exception as e:
            logger.warning(f"标记邮箱状态失败: {e}")

    def _send_verification_code(self, referer: Optional[str] = None) -> bool:
        """发送验证码"""
        self._raise_if_cancelled("任务已取消，停止发送验证码")
        try:
            self._last_send_otp_status_code = None
            self._last_send_otp_error_detail = ""
            self._last_send_otp_page_type = ""
            self._last_send_otp_current_url = ""
            send_referer = str(referer or "https://auth.openai.com/create-account/password").strip()
            current_did = str(self.session.cookies.get("oai-did") or self.device_id or "").strip()
            if current_did:
                self._seed_oai_device_cookie(current_did)

            response = self.session.get(
                OPENAI_API_ENDPOINTS["send_otp"],
                headers=dict(
                    self._build_browser_headers(
                        OPENAI_API_ENDPOINTS["send_otp"],
                        accept="application/json, text/plain, */*",
                        referer=send_referer,
                        fetch_site="same-origin",
                        extra_headers={"oai-device-id": current_did} if current_did else None,
                    ),
                    **generate_datadog_trace(),
                ),
                allow_redirects=True,
                timeout=30,
            )
            self._capture_auth_cookies_from_response(response, "验证码发送")

            self._log(f"验证码发送状态: {response.status_code}")
            self._last_send_otp_status_code = int(response.status_code)
            current_url = str(getattr(response, "url", "") or "").strip()
            if current_url:
                self._last_send_otp_current_url = current_url
                self._last_auth_page_url = current_url
                self._log(f"验证码发送 response_url: {current_url[:160]}")
            if response.status_code == 200:
                page_type = ""
                try:
                    payload = response.json() or {}
                    if isinstance(payload, dict):
                        self._cache_auth_session_payload(payload, "验证码发送")
                        page_info = payload.get("page") or {}
                        if isinstance(page_info, dict):
                            page_type = str(page_info.get("type") or "").strip()
                        if not page_type:
                            page_type = str(payload.get("type") or "").strip()
                        self._log(f"验证码发送响应 page_type: {page_type or '-'}")
                        self._log(f"验证码发送响应体预览: {str(payload)[:300]}")
                except Exception:
                    self._log("验证码发送响应: 非 JSON", "warning")

                self._last_send_otp_page_type = page_type
                current_url_lower = current_url.lower()
                page_type_lower = page_type.lower()
                reached_email_verification = (
                    "email-verification" in current_url_lower
                    or page_type_lower == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]
                )
                if reached_email_verification:
                    self._otp_sent_at = time.time()
                    self._log("验证码发送确认进入 email-verification 状态，开始等待邮件", "warning")
                    return True

                self._last_send_otp_error_detail = (
                    f"HTTP 200 但未确认进入邮箱验证码页; "
                    f"page_type={page_type or '-'}, url={current_url or '-'}"
                )
                self._log(
                    "验证码发送返回 200，但当前会话未确认进入 email-verification 状态，"
                    "本轮不视为已成功发信",
                    "warning",
                )
                return False

            error_code = ""
            error_message = str(response.text or "")[:500]
            try:
                error_data = response.json() or {}
                error_info = error_data.get("error") or {}
                error_code = str(error_info.get("code") or "").strip()
                error_message = str(error_info.get("message") or error_message).strip()
            except Exception:
                pass
            detail = f"HTTP {response.status_code}"
            if error_code:
                detail += f": {error_code}"
            elif error_message:
                detail += f": {error_message}"
            self._last_send_otp_error_detail = detail
            self._log(f"验证码发送失败详情: {detail}", "warning")
            raw_body = str(response.text or "").strip()
            if raw_body:
                self._log(f"验证码发送失败响应体: {raw_body[:500]}", "warning")
            return False

        except Exception as e:
            self._last_send_otp_error_detail = str(e)
            self._log(f"发送验证码失败: {e}", "error")
            return False

    def _get_verification_code(self, timeout: Optional[int] = None) -> Optional[str]:
        """获取验证码"""
        self._raise_if_cancelled("任务已取消，停止拉取验证码")
        try:
            mailbox_email = str(self.inbox_email or self.email or "").strip()
            self._log(f"正在等待邮箱 {mailbox_email} 的验证码...")

            email_id = self.email_info.get("service_id") if self.email_info else None
            fetch_timeout = int(timeout) if timeout and int(timeout) > 0 else 120
            code = self.email_service.get_verification_code(
                email=mailbox_email,
                email_id=email_id,
                timeout=fetch_timeout,
                pattern=OTP_CODE_PATTERN,
                otp_sent_at=self._otp_sent_at,
            )

            if code:
                self._log(f"成功获取验证码: {code}")
                return code
            else:
                service_last_error = str(getattr(self.email_service, "last_error", "") or "").strip()
                if service_last_error:
                    self._log(f"等待验证码超时，邮箱服务最后错误: {service_last_error}", "error")
                else:
                    self._log("等待验证码超时", "error")
                return None

        except Exception as e:
            self._log(f"获取验证码失败: {e}", "error")
            return None

    def _validate_verification_code(self, code: str) -> bool:
        """验证验证码"""
        self._raise_if_cancelled("任务已取消，停止校验验证码")
        try:
            self._last_otp_validation_code = str(code or "").strip()
            self._last_otp_validation_status_code = None
            self._last_otp_validation_outcome = ""
            self._last_otp_validation_error_detail = ""
            current_did = str(self.session.cookies.get("oai-did") or self.device_id or "").strip()
            if current_did:
                self._seed_oai_device_cookie(current_did)
            otp_referer = str(
                self._last_send_otp_current_url
                or self._last_validate_otp_continue_url
                or "https://auth.openai.com/email-verification"
            ).strip()
            current_sen_token = ""
            if current_did:
                current_sen_token = self._get_browser_sentinel_token(
                    "email_otp_validate",
                    page_url=otp_referer,
                    device_id=current_did,
                )
                if current_sen_token:
                    self._log("email_otp_validate: 已通过浏览器 Sentinel helper 获取 token")
            if current_did and not current_sen_token:
                try:
                    current_sen_token = str(
                        build_sentinel_token(
                            self.session,
                            current_did,
                            flow="email_otp_validate",
                            user_agent=self._fingerprint_user_agent,
                            sec_ch_ua=self._fingerprint_sec_ch_ua,
                            impersonate=self._fingerprint_impersonate,
                        ) or ""
                    ).strip()
                except Exception as e:
                    self._log(f"email_otp_validate sentinel 获取异常: {e}", "warning")
                    current_sen_token = ""
                if current_sen_token:
                    self._log("email_otp_validate: 已通过 HTTP PoW 获取 token")
            if current_did and not current_sen_token:
                current_sen_token = str(self._check_sentinel(current_did) or "").strip()

            response = self.session.post(
                OPENAI_API_ENDPOINTS["validate_otp"],
                headers=dict(
                    self._build_browser_headers(
                        OPENAI_API_ENDPOINTS["validate_otp"],
                        accept="application/json",
                        referer=otp_referer,
                        origin="https://auth.openai.com",
                        content_type="application/json",
                        fetch_site="same-origin",
                        extra_headers={
                            "oai-device-id": current_did,
                            "openai-sentinel-token": current_sen_token or None,
                        },
                    ),
                    **generate_datadog_trace(),
                ),
                json={"code": code},
                allow_redirects=False,
                timeout=30,
            )
            self._capture_auth_cookies_from_response(response, "验证码校验")

            self._log(f"验证码校验状态: {response.status_code}")
            self._last_otp_validation_status_code = int(response.status_code)
            self._last_otp_validation_outcome = "success" if response.status_code == 200 else "http_non_200"
            if response.status_code != 200:
                error_code = ""
                error_message = str(response.text or "")[:500]
                try:
                    error_data = response.json() or {}
                    error_info = error_data.get("error") or {}
                    error_code = str(error_info.get("code") or "").strip()
                    error_message = str(error_info.get("message") or error_message).strip()
                except Exception:
                    pass
                detail = f"HTTP {response.status_code}"
                if error_code:
                    detail += f": {error_code}"
                elif error_message:
                    detail += f": {error_message}"
                self._last_otp_validation_error_detail = detail
                self._log(f"验证码校验失败详情: {detail}", "warning")
                raw_body = str(response.text or "").strip()
                if raw_body:
                    self._log(f"验证码校验失败响应体: {raw_body[:500]}", "warning")
            if response.status_code == 200:
                # 记录 OTP 校验返回中的 continue/workspace 提示，供 native 收尾兜底
                try:
                    import urllib.parse as urlparse
                    payload = response.json() or {}
                    self._cache_auth_session_payload(payload, "验证码校验")
                    candidates: List[Dict[str, Any]] = []
                    if isinstance(payload, dict):
                        candidates.append(payload)
                        for key in ("data", "result", "next", "payload"):
                            value = payload.get(key)
                            if isinstance(value, dict):
                                candidates.append(value)

                    found_continue = ""
                    found_workspace = ""
                    for item in candidates:
                        if not isinstance(item, dict):
                            continue
                        if not found_workspace:
                            found_workspace = str(
                                item.get("workspace_id")
                                or item.get("workspaceId")
                                or item.get("default_workspace_id")
                                or ((item.get("workspace") or {}).get("id") if isinstance(item.get("workspace"), dict) else "")
                                or ""
                            ).strip()
                        if not found_continue:
                            for key in ("continue_url", "continueUrl", "next_url", "nextUrl", "redirect_url", "redirectUrl", "url"):
                                candidate = str(item.get(key) or "").strip()
                                if not candidate:
                                    continue
                                if candidate.startswith("/"):
                                    candidate = urlparse.urljoin(OPENAI_API_ENDPOINTS["validate_otp"], candidate)
                                found_continue = candidate
                                break
                        if found_workspace and found_continue:
                            break

                    if found_workspace:
                        self._last_validate_otp_workspace_id = found_workspace
                        self._log(f"OTP 校验返回 Workspace ID: {found_workspace}")
                    if found_continue:
                        self._last_validate_otp_continue_url = found_continue
                        self._log(f"OTP 校验返回 continue_url: {found_continue[:100]}...")
                except Exception as parse_err:
                    self._log(f"解析 OTP 校验返回信息失败: {parse_err}", "warning")

            return response.status_code == 200

        except Exception as e:
            err_text = str(e or "").lower()
            if (
                "timed out" in err_text
                or "timeout" in err_text
                or "curl: (28)" in err_text
                or "operation timed out" in err_text
            ):
                self._last_otp_validation_outcome = "network_timeout"
            else:
                self._last_otp_validation_outcome = "network_error"
            self._log(f"验证验证码失败: {e}", "error")
            return False

    def _verify_email_otp_with_retry(
        self,
        stage_label: str = "验证码",
        max_attempts: int = 3,
        fetch_timeout: Optional[int] = None,
        attempted_codes: Optional[set[str]] = None,
        retry_wait_seconds: float = 2.0,
        invalid_state_retry_wait_seconds: Optional[float] = None,
    ) -> bool:
        """
        获取并校验验证码（带重试）。
        用于规避邮箱里历史验证码导致的 400（第一次取到旧码，第二次取新码）。
        """
        # 每轮验证码阶段开始前，清理上轮 OTP 校验缓存，避免 continue_url/workspace 被旧阶段污染。
        self._raise_if_cancelled(f"任务已取消，停止{stage_label}校验")
        self._last_validate_otp_continue_url = None
        self._last_validate_otp_workspace_id = None
        base_wait_seconds = max(float(retry_wait_seconds or 0.0), 0.0)
        invalid_state_wait_seconds = max(
            float(invalid_state_retry_wait_seconds if invalid_state_retry_wait_seconds is not None else base_wait_seconds),
            0.0,
        )
        if attempted_codes is None:
            attempted_codes = set()
        for attempt in range(1, max_attempts + 1):
            self._raise_if_cancelled(f"任务已取消，停止{stage_label}重试")
            code = (
                self._get_verification_code(timeout=fetch_timeout)
                if fetch_timeout
                else self._get_verification_code()
            )
            if not code:
                if attempt < max_attempts:
                    self._log(
                        f"{stage_label}第 {attempt}/{max_attempts} 次未取到验证码，稍后重试...",
                        "warning",
                    )
                    self._sleep_interruptible(base_wait_seconds)
                    continue
                return False

            if code in attempted_codes:
                allow_same_code_retry = (
                    self._last_otp_validation_code == code
                    and self._last_otp_validation_outcome in {"network_timeout", "network_error"}
                )
                if allow_same_code_retry:
                    self._log(
                        f"{stage_label}第 {attempt}/{max_attempts} 次命中重复验证码 {code}，"
                        f"但上次校验为网络异常（{self._last_otp_validation_outcome}），重试同码...",
                        "warning",
                    )
                    if self._validate_verification_code(code):
                        return True
                    if attempt < max_attempts:
                        self._sleep_interruptible(base_wait_seconds)
                        continue
                    return False

                if attempt < max_attempts:
                    self._log(
                        f"{stage_label}第 {attempt}/{max_attempts} 次命中重复验证码 {code}，等待新邮件...",
                        "warning",
                    )
                    self._sleep_interruptible(base_wait_seconds)
                    continue
                return False

            attempted_codes.add(code)

            if self._validate_verification_code(code):
                return True

            non_retryable_detail = str(self._last_otp_validation_error_detail or "").lower()
            if "invalid_auth_step" in non_retryable_detail:
                self._log(
                    f"{stage_label}命中 invalid_auth_step：当前会话已不在邮箱 OTP 校验步骤，停止等待新邮件",
                    "warning",
                )
                return False

            if attempt < max_attempts:
                detail_text = str(
                    self._last_otp_validation_error_detail or self._last_otp_validation_outcome or "unknown"
                )
                wait_seconds = (
                    invalid_state_wait_seconds
                    if "invalid_state" in detail_text.lower()
                    else base_wait_seconds
                )
                self._log(
                    f"{stage_label}第 {attempt}/{max_attempts} 次校验未通过，"
                    f"detail={detail_text}，"
                    f"疑似旧验证码，等待 {wait_seconds:g} 秒后自动重试下一封...",
                    "warning",
                )
                self._sleep_interruptible(wait_seconds)

        return False

    def _create_user_account(self) -> bool:
        """创建用户账户"""
        self._raise_if_cancelled("任务已取消，停止创建用户账户")
        self._last_create_account_error = None
        try:
            user_info = generate_random_user_info()
            full_name = str(user_info.get("name") or "").strip()
            birthdate = str(user_info.get("birthdate") or "").strip()
            first_name = str(user_info.get("first_name") or "").strip()
            last_name = str(user_info.get("last_name") or "").strip()
            if (not full_name) and (first_name or last_name):
                full_name = f"{first_name} {last_name}".strip()
            create_account_payload = {
                "name": full_name,
                "birthdate": birthdate,
            }
            self._log(
                "生成用户信息: "
                f"name={full_name or '-'}, "
                f"first_name={first_name or '-'}, "
                f"last_name={last_name or '-'}, "
                f"birthdate={birthdate or '-'}"
            )

            request_url = OPENAI_API_ENDPOINTS["create_account"]
            current_did = str(self.session.cookies.get("oai-did") or self.device_id or "").strip()
            current_sen_token = ""
            if current_did:
                self._seed_oai_device_cookie(current_did)
            about_you_referer = str(self._last_validate_otp_continue_url or self._last_auth_page_url or "").strip()
            about_you_target_ready = (
                about_you_referer.startswith("https://auth.openai.com/")
                and ("about-you" in about_you_referer or "add-phone" in about_you_referer)
            )
            if about_you_target_ready:
                self._log(f"create_account: 复用 OTP 返回落点作为 referer: {about_you_referer[:160]}")
            else:
                about_you_referer = str(self._refresh_about_you_page() or "https://auth.openai.com/about-you").strip()
            self._log_oauth_session_quality("create_account 前")

            def _build_create_headers(sentinel_token: str = "") -> Dict[str, str]:
                extra_headers: Dict[str, str] = {}
                if current_did:
                    extra_headers["oai-device-id"] = current_did
                if sentinel_token:
                    extra_headers["openai-sentinel-token"] = sentinel_token
                headers = self._build_browser_headers(
                    request_url,
                    accept="application/json",
                    referer=about_you_referer,
                    origin="https://auth.openai.com",
                    content_type="application/json",
                    fetch_site="same-origin",
                    extra_headers=extra_headers,
                )
                headers.update(generate_datadog_trace())
                return headers

            def _post_create(sentinel_token: str = ""):
                self._browser_pause()
                response = self.session.post(
                    request_url,
                    headers=_build_create_headers(sentinel_token),
                    json=create_account_payload,
                    allow_redirects=False,
                    timeout=30,
                )
                self._capture_auth_cookies_from_response(response, "create_account")
                return response

            response = _post_create("")

            self._log(f"账户创建状态: {response.status_code}")
            self._log(f"账户创建使用 referer: {about_you_referer[:160]}")

            response_text = str(response.text or "")
            if (
                response.status_code in (401, 403)
                or "sentinel" in response_text.lower()
                or "challenge" in response_text.lower()
            ) and current_did:
                self._log("create_account 首次请求触发挑战，补发 sentinel 后重试...", "warning")
                current_sen_token = self._get_browser_sentinel_token(
                    "oauth_create_account",
                    page_url=about_you_referer,
                    device_id=current_did,
                )
                if current_sen_token:
                    self._log("oauth_create_account: 已通过浏览器 Sentinel helper 获取 token")
                if not current_sen_token:
                    try:
                        current_sen_token = str(
                            build_sentinel_token(
                                self.session,
                                current_did,
                                flow="oauth_create_account",
                                user_agent=self._fingerprint_user_agent,
                                sec_ch_ua=self._fingerprint_sec_ch_ua,
                                impersonate=self._fingerprint_impersonate,
                            ) or ""
                        ).strip()
                    except Exception as e:
                        self._log(f"create_account 重试前获取 sentinel 异常: {e}", "warning")
                        current_sen_token = ""
                    if current_sen_token:
                        self._log("oauth_create_account: 已通过 HTTP PoW 获取 token")
                if not current_sen_token:
                    current_sen_token = str(self._check_sentinel(current_did) or "").strip()
                if current_sen_token:
                    self._log("create_account: 已生成 sentinel token")
                else:
                    self._log("create_account: 未生成 sentinel token，降级继续请求", "warning")
                if current_sen_token:
                    response = _post_create(current_sen_token)
                    response_text = str(response.text or "")
                    self._log(f"账户创建重试状态: {response.status_code}")

            retryable_detail = ""
            if response.status_code == 400:
                try:
                    error_data = response.json() or {}
                    error_info = error_data.get("error") or {}
                    retryable_detail = str(error_info.get("code") or error_info.get("message") or "").strip().lower()
                except Exception:
                    retryable_detail = str(response_text or "").strip().lower()
                if "registration_disallowed" in retryable_detail:
                    self._log("create_account 命中 registration_disallowed，刷新 about-you 页面后再做一次无 sentinel 验证...", "warning")
                    about_you_referer = str(self._refresh_about_you_page() or about_you_referer).strip()
                    response = _post_create("")
                    response_text = str(response.text or "")
                    self._log(f"账户创建刷新后重试状态: {response.status_code}")
                    if response.status_code == 400 and current_did:
                        self._log("create_account 再次命中 registration_disallowed，补发 oauth_create_account Sentinel 后最后再试一次...", "warning")
                        current_sen_token = self._get_browser_sentinel_token(
                            "oauth_create_account",
                            page_url=about_you_referer,
                            device_id=current_did,
                        )
                        if current_sen_token:
                            self._log("oauth_create_account: registration_disallowed 分支已通过浏览器 Sentinel helper 获取 token")
                        if not current_sen_token:
                            try:
                                current_sen_token = str(
                                    build_sentinel_token(
                                        self.session,
                                        current_did,
                                        flow="oauth_create_account",
                                        user_agent=self._fingerprint_user_agent,
                                        sec_ch_ua=self._fingerprint_sec_ch_ua,
                                        impersonate=self._fingerprint_impersonate,
                                    ) or ""
                                ).strip()
                            except Exception as e:
                                self._log(f"create_account registration_disallowed 分支获取 sentinel 异常: {e}", "warning")
                                current_sen_token = ""
                        if current_sen_token:
                            response = _post_create(current_sen_token)
                            response_text = str(response.text or "")
                            self._log(f"账户创建 Sentinel 收尾重试状态: {response.status_code}")

            if response.status_code != 200:
                error_code = ""
                error_message = response_text[:500]
                try:
                    error_data = response.json() or {}
                    error_info = error_data.get("error") or {}
                    error_code = str(error_info.get("code") or "").strip()
                    error_message = str(error_info.get("message") or error_message).strip()
                except Exception:
                    pass
                detail = f"HTTP {response.status_code}"
                if error_code:
                    detail += f": {error_code}"
                elif error_message:
                    detail += f": {error_message}"
                self._last_create_account_error = detail
                self._log(
                    "账户创建失败: "
                    f"detail={detail}, "
                    f"did={'set' if current_did else 'missing'}, "
                    f"sentinel={'set' if current_sen_token else 'missing'}",
                    "warning",
                )
                if response_text:
                    self._log(f"账户创建失败响应体: {response_text[:500]}", "warning")
                return False

            try:
                data = response.json() or {}
                continue_url = str(data.get("continue_url") or "").strip()
                if continue_url:
                    self._create_account_continue_url = continue_url
                    self._log(f"create_account 返回 continue_url，已缓存: {continue_url[:100]}...")
                account_id = str(
                    data.get("account_id")
                    or data.get("chatgpt_account_id")
                    or (data.get("account") or {}).get("id")
                    or ""
                ).strip()
                if account_id:
                    self._create_account_account_id = account_id
                    self._log(f"create_account 返回 account_id，已缓存: {account_id}")
                workspace_id = str(
                    data.get("workspace_id")
                    or data.get("default_workspace_id")
                    or (data.get("workspace") or {}).get("id")
                    or ""
                ).strip()
                if (not workspace_id) and isinstance(data.get("workspaces"), list) and data.get("workspaces"):
                    workspace_id = str((data.get("workspaces")[0] or {}).get("id") or "").strip()
                if workspace_id:
                    self._create_account_workspace_id = workspace_id
                    self._log(f"create_account 返回 workspace_id，已缓存: {workspace_id}")
                refresh_token = str(data.get("refresh_token") or "").strip()
                if refresh_token:
                    self._create_account_refresh_token = refresh_token
                    self._log("create_account 返回 refresh_token，已缓存")
            except Exception:
                pass

            self._last_create_account_error = None

            return True

        except Exception as e:
            self._last_create_account_error = str(e)
            self._log(f"创建账户失败: {e}", "error")
            return False

    def _get_workspace_id(self) -> Optional[str]:
        """获取 Workspace ID"""
        self._raise_if_cancelled("任务已取消，停止获取 Workspace ID")
        try:
            def _extract_workspace_id(payload: Any) -> str:
                if not isinstance(payload, dict):
                    return ""
                workspace_id = str(
                    payload.get("workspace_id")
                    or payload.get("default_workspace_id")
                    or ((payload.get("workspace") or {}).get("id") if isinstance(payload.get("workspace"), dict) else "")
                    or ""
                ).strip()
                if workspace_id:
                    return workspace_id
                workspaces = payload.get("workspaces") or []
                if isinstance(workspaces, list) and workspaces:
                    return str((workspaces[0] or {}).get("id") or "").strip()
                return ""

            auth_cookie = str(self.session.cookies.get("oai-client-auth-session") or "").strip()
            if not auth_cookie:
                self._log("未能获取到授权 Cookie，尝试从 auth-info 里取 workspace", "warning")

            # 解码 JWT
            import base64
            import json as json_module
            import urllib.parse as urlparse

            try:
                candidate_payloads: List[str] = []
                if auth_cookie:
                    segments = auth_cookie.split(".")
                    # 对齐 ABCard：优先 JWT payload 段（第 2 段）
                    if len(segments) >= 2 and segments[1]:
                        candidate_payloads.append(segments[1])
                    if segments and segments[0]:
                        candidate_payloads.append(segments[0])
                    # 极端情况下 cookie 可能直接是 JSON 字符串
                    candidate_payloads.append(auth_cookie)

                for payload in candidate_payloads:
                    raw = str(payload or "").strip()
                    if not raw:
                        continue
                    auth_json = None
                    try:
                        pad = "=" * ((4 - (len(raw) % 4)) % 4)
                        decoded = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
                        auth_json = json_module.loads(decoded.decode("utf-8"))
                    except Exception:
                        try:
                            auth_json = json_module.loads(raw)
                        except Exception:
                            auth_json = None

                    workspace_id = _extract_workspace_id(auth_json)
                    if workspace_id:
                        self._log(f"Workspace ID: {workspace_id}")
                        return workspace_id

                # 兜底：从 oai-client-auth-info（URL 编码 JSON）提取 workspace
                auth_info_raw = str(self.session.cookies.get("oai-client-auth-info") or "").strip()
                if auth_info_raw:
                    auth_info_text = auth_info_raw
                    for _ in range(2):
                        decoded = urlparse.unquote(auth_info_text)
                        if decoded == auth_info_text:
                            break
                        auth_info_text = decoded
                    try:
                        auth_info_json = json_module.loads(auth_info_text)
                        workspace_id = _extract_workspace_id(auth_info_json)
                        if workspace_id:
                            self._log(f"Workspace ID (auth-info): {workspace_id}")
                            return workspace_id
                    except Exception as auth_info_err:
                        self._log(f"解析 auth-info Cookie 失败: {auth_info_err}", "warning")

                # 兜底：复用 create_account 缓存
                cached_workspace = str(self._create_account_workspace_id or "").strip()
                if cached_workspace:
                    self._log(f"Workspace ID (create_account缓存): {cached_workspace}")
                    return cached_workspace

                self._log("授权 Cookie 里没有 workspace 信息", "warning")
                return None

            except Exception as e:
                self._log(f"解析授权 Cookie 失败: {e}", "warning")
                return None

        except Exception as e:
            self._log(f"获取 Workspace ID 失败: {e}", "error")
            return None

    def _select_workspace(self, workspace_id: str) -> Optional[str]:
        """选择 Workspace"""
        self._raise_if_cancelled("任务已取消，停止选择 Workspace")
        try:
            select_body = f'{{"workspace_id":"{workspace_id}"}}'

            response = self.session.post(
                OPENAI_API_ENDPOINTS["select_workspace"],
                headers={
                    "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                    "content-type": "application/json",
                    "accept": "application/json",
                },
                data=select_body,
                allow_redirects=False,
            )

            # 兼容 30x：部分环境 continue_url 在 Location 头里。
            location = str(response.headers.get("Location") or "").strip()
            if response.status_code in [301, 302, 303, 307, 308] and location:
                import urllib.parse
                continue_url = urllib.parse.urljoin(OPENAI_API_ENDPOINTS["select_workspace"], location)
                self._log(f"Continue URL (Location): {continue_url[:100]}...")
                return continue_url

            if response.status_code != 200:
                self._log(f"选择 workspace 失败: {response.status_code}", "error")
                self._log(f"响应: {response.text[:200]}", "warning")
                return None

            continue_url = ""
            try:
                continue_url = str((response.json() or {}).get("continue_url") or "").strip()
            except Exception as json_err:
                body_text = str(response.text or "")
                self._log(f"workspace/select 非 JSON 响应，尝试文本兜底解析: {json_err}", "warning")
                # 兜底1：HTML/文本里直接包含 continue_url
                m = re.search(r'"continue_url"\s*:\s*"([^"]+)"', body_text)
                if m:
                    continue_url = str(m.group(1) or "").strip()
                # 兜底2：返回页内含 auth.openai.com/oauth/authorize 链接
                if not continue_url:
                    m2 = re.search(r"https://auth\.openai\.com/[^\s\"'<>]+", body_text)
                    if m2:
                        continue_url = str(m2.group(0) or "").strip()

            if not continue_url:
                if location:
                    import urllib.parse
                    continue_url = urllib.parse.urljoin(OPENAI_API_ENDPOINTS["select_workspace"], location)
                else:
                    self._log("workspace/select 响应里缺少 continue_url", "error")
                    return None

            if continue_url:
                continue_url = continue_url.replace("\\/", "/")
                self._log(f"Continue URL: {continue_url[:100]}...")
                return continue_url

            return None

        except Exception as e:
            self._log(f"选择 Workspace 失败: {e}", "error")
            return None

    def _follow_redirects(self, start_url: str) -> Tuple[Optional[str], str]:
        """手动跟随重定向链，返回 (callback_url, final_url)。"""
        self._raise_if_cancelled("任务已取消，停止跟随重定向")
        try:
            def _is_oauth_callback(url: str) -> bool:
                try:
                    import urllib.parse as _urlparse

                    parsed = _urlparse.urlparse(url)
                    path = (parsed.path or "").lower()
                    if ("/auth/callback" not in path) and ("/api/auth/callback/openai" not in path):
                        return False
                    query = _urlparse.parse_qs(parsed.query or "", keep_blank_values=True)
                    # 只要带 code 或 error，就认为已经进入回调阶段（避免被本地 503 干扰识别）
                    return bool(query.get("code") or query.get("error"))
                except Exception:
                    return False

            current_url = start_url
            callback_url: Optional[str] = None
            max_redirects = 12

            for i in range(max_redirects):
                self._raise_if_cancelled("任务已取消，停止跟随重定向")
                self._log(f"重定向 {i+1}/{max_redirects}: {current_url[:100]}...")
                if _is_oauth_callback(current_url) and not callback_url:
                    callback_url = current_url
                    self._log(f"命中回调 URL: {current_url[:120]}...")
                    # 已拿到 callback，不再请求本地 callback 地址，避免 503 干扰后续判断
                    break

                response = self.session.get(
                    current_url,
                    allow_redirects=False,
                    timeout=15
                )

                location = response.headers.get("Location") or ""

                if "/api/auth/callback/openai" in current_url and not callback_url:
                    callback_url = current_url

                # 如果不是重定向状态码，停止
                if response.status_code not in [301, 302, 303, 307, 308]:
                    self._log(f"非重定向状态码: {response.status_code}")
                    break

                if not location:
                    self._log("重定向响应缺少 Location 头")
                    break

                # 构建下一个 URL
                import urllib.parse
                next_url = urllib.parse.urljoin(current_url, location)

                # 命中回调时仅记录，不提前返回；继续跟到底，让 next-auth 充分落 cookie。
                if _is_oauth_callback(next_url) and not callback_url:
                    callback_url = next_url
                    self._log(f"找到回调 URL: {next_url[:100]}...")
                    current_url = next_url
                    break

                current_url = next_url

            # 对齐 ABCard：补打一跳 chatgpt 首页，确保 next-auth cookie 完整落地。
            try:
                if not current_url.rstrip("/").endswith("chatgpt.com"):
                    self.session.get(
                        "https://chatgpt.com/",
                        headers={
                            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "referer": current_url,
                            "user-agent": (
                                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                            ),
                        },
                        timeout=20,
                    )
            except Exception as home_err:
                self._log(f"重定向结束后首页补跳异常: {home_err}", "warning")

            if not callback_url:
                self._log("未能在重定向链中找到回调 URL", "warning")
            return callback_url, current_url

        except Exception as e:
            self._log(f"跟随重定向失败: {e}", "error")
            return None, start_url

    def _handle_oauth_callback(self, callback_url: str) -> Optional[Dict[str, Any]]:
        """处理 OAuth 回调"""
        self._raise_if_cancelled("任务已取消，停止处理 OAuth 回调")
        try:
            if not self.oauth_start:
                self._log("OAuth 流程未初始化", "error")
                return None

            self._log("处理 OAuth 回调，最后一哆嗦，稳住别抖...")
            token_info = self.oauth_manager.handle_callback(
                callback_url=callback_url,
                expected_state=self.oauth_start.state,
                code_verifier=self.oauth_start.code_verifier
            )

            self._log("OAuth 授权成功，通关文牒到手")
            return token_info

        except Exception as e:
            self._log(f"处理 OAuth 回调失败: {e}", "error")
            return None

    def _run_primary_registration(self) -> RegistrationResult:
        """
        执行完整的注册流程

        支持已注册账号自动登录：
        - 如果检测到邮箱已注册，自动切换到登录流程
        - 已注册账号跳过：设置密码、发送验证码、创建用户账户
        - 共用步骤：获取验证码、验证验证码、Workspace 和 OAuth 回调

        Returns:
            RegistrationResult: 注册结果
        """
        self._raise_if_cancelled("任务已取消，停止注册流程")
        result = RegistrationResult(success=False, logs=self.logs)

        try:
            self._is_existing_account = False
            self._token_acquisition_requires_login = False
            add_phone_recovered = False
            self._otp_sent_at = None
            self._create_account_continue_url = None
            self._create_account_workspace_id = None
            self._create_account_account_id = None
            self._create_account_refresh_token = None
            self._last_create_account_error = None
            self._last_validate_otp_continue_url = None
            self._last_validate_otp_workspace_id = None

            self._log("=" * 60)
            self._log("注册流程启动，开始替你敲门")
            self._log("=" * 60)
            self._log(f"注册入口链路配置: {self.registration_entry_flow}")
            configured_entry_flow = self.registration_entry_flow
            service_type_raw = getattr(self.email_service, "service_type", "")
            service_type_value = str(getattr(service_type_raw, "value", service_type_raw) or "").strip().lower()
            effective_entry_flow = configured_entry_flow
            if service_type_value == "outlook":
                self._log("检测到 Outlook 邮箱，自动使用 Outlook 入口链路（无需在设置中选择）")
                effective_entry_flow = "outlook"

            # 1. 检查 IP 地理位置
            self._log("1. 先看看这条网络从哪儿来，别一开局就站错片场...")
            self._raise_if_cancelled("任务已取消，停止注册流程")
            ip_ok, location = self._check_ip_location()
            if not ip_ok:
                result.error_message = f"IP 地理位置不支持: {location}"
                self._log(f"IP 检查失败: {location}", "error")
                return result

            self._log(f"IP 位置: {location}")

            # 2. 创建邮箱
            self._log("2. 开个新邮箱，准备收信...")
            self._raise_if_cancelled("任务已取消，停止注册流程")
            if not self._create_email():
                result.error_message = "创建邮箱失败"
                return result

            result.email = self.email

            # 3. 准备首轮授权流程
            self._raise_if_cancelled("任务已取消，停止注册流程")
            did, sen_token = self._prepare_authorize_flow("首次授权")
            if not did:
                result.error_message = "获取 Device ID 失败"
                return result
            result.device_id = did
            if not sen_token:
                result.error_message = "Sentinel POW 验证失败"
                return result

            # 4. 提交注册入口邮箱
            self._log("4. 递上邮箱，看看 OpenAI 这球怎么接...")
            self._raise_if_cancelled("任务已取消，停止注册流程")
            signup_result = self._submit_signup_form(did, sen_token)
            if not signup_result.success:
                if "HTTP 429" in str(signup_result.error_message or ""):
                    signup_result = self._recover_signup_after_rate_limit()
                    if signup_result.success:
                        self._log("提交注册表单虽然返回 429，但验证码兜底已接管流程", "warning")
                    elif self._has_prewarm_auth_ready_state():
                        self._log(
                            "提交注册表单 429 兜底未拿到稳定邮箱验证码，切换到 prewarm 密码直连恢复分支...",
                            "warning",
                        )
                        signup_result = self._recover_signup_via_prewarm_password_path(did, sen_token)
                        if signup_result.success:
                            self._log("提交注册表单 429 已通过 prewarm 密码直连分支恢复", "warning")
                if not signup_result.success:
                    result.error_message = f"提交注册表单失败: {signup_result.error_message}"
                    return result

            self._log(f"注册分支: signup_result.page_type={signup_result.page_type or '-'}")
            if self._is_existing_account:
                self._log("注册分支: existing_account_login")
                self._log("检测到这是老朋友账号，直接切去登录拿 token，不走弯路")
            else:
                recovered_post_password = (signup_result.page_type == "signup_otp_post_password")

                if not recovered_post_password:
                    self._log("注册分支: new_account_password_then_email_otp")
                    self._log("5. 设置密码，别让小偷偷笑...")
                    self._raise_if_cancelled("任务已取消，停止注册流程")
                    password_ok, _ = self._register_password_with_retry(did, sen_token)
                    if not password_ok:
                        result.error_message = self._last_register_password_error or "注册密码失败"
                        return result

                    self._log("6. 催一下注册验证码出门，邮差该冲刺了...")
                    self._raise_if_cancelled("任务已取消，停止注册流程")
                    if not self._send_verification_code():
                        result.error_message = "发送验证码失败"
                        return result

                    self._log("7. 等验证码飞来，邮箱请注意查收...")
                    self._log("8. 对一下验证码，看看是不是本人...")
                    self._raise_if_cancelled("任务已取消，停止注册流程")
                    if not self._verify_email_otp_with_retry(stage_label="注册验证码", max_attempts=3):
                        result.error_message = "验证验证码失败"
                        return result
                else:
                    self._log("注册分支: signup_429_recover_post_password")
                    self._log("注册入口 429 兜底已完成邮箱校验，本轮跳过密码/验证码重复步骤", "warning")

                otp_continue = str(self._last_validate_otp_continue_url or "").strip().lower()
                if "auth.openai.com/add-phone" in otp_continue:
                    self._log("注册分支: add_phone_gate_after_otp", "warning")
                    if self._try_salvage_add_phone_after_otp(result):
                        self._log("注册分支: add_phone_recovered_current_session", "warning")
                        add_phone_recovered = True
                    else:
                        settings = get_settings()
                        fallback_enabled = bool(getattr(settings, "registration_enable_anyauto_fallback", True))
                        result.error_message = (
                            "命中 add-phone 分支，主链路停止并交给 anyauto 回退继续处理"
                            if fallback_enabled
                            else "命中 add-phone 分支，当前会话未拿到 workspace/callback/token"
                        )
                        return result
                if not add_phone_recovered:
                    self._log("注册分支: create_account")
                    self._log("9. 给账号办个正式户口，名字写档案里...")
                    self._raise_if_cancelled("任务已取消，停止注册流程")
                    if not self._create_user_account():
                        result.error_message = str(self._last_create_account_error or "创建用户账户失败")
                        return result

                    if effective_entry_flow in {"native", "outlook"}:
                        self._raise_if_cancelled("任务已取消，停止注册流程")
                        login_ready, login_error = self._restart_login_flow()
                        if not login_ready:
                            result.error_message = login_error
                            return result
                        if effective_entry_flow == "outlook":
                            self._log("注册入口链路: Outlook（迁移版，按朋友版 Outlook 主流程收尾）")
                    else:
                        self._log("注册入口链路: ABCard（新账号不重登，直接抓取会话）")

            if not add_phone_recovered:
                if effective_entry_flow == "native":
                    self._raise_if_cancelled("任务已取消，停止注册流程")
                    if not self._complete_token_exchange_native_backup(result):
                        return result
                elif effective_entry_flow == "outlook":
                    self._raise_if_cancelled("任务已取消，停止注册流程")
                    if not self._complete_token_exchange_outlook(result):
                        return result
                else:
                    use_abcard_entry = (effective_entry_flow == "abcard") and (not self._is_existing_account)
                    self._raise_if_cancelled("任务已取消，停止注册流程")
                    if not self._complete_token_exchange(result, require_login_otp=not use_abcard_entry):
                        return result

            # 10. 完成
            self._log("=" * 60)
            if self._is_existing_account:
                self._log("登录成功，老朋友顺利回家")
            else:
                self._log("注册成功，账号已经稳稳落地，可以开香槟了")
            self._log(f"邮箱: {result.email}")
            self._log(f"Device ID: {result.device_id or '-'}")
            self._log(f"Account ID: {result.account_id}")
            self._log(f"Workspace ID: {result.workspace_id}")
            self._log("=" * 60)

            result.success = True
            settings = get_settings()
            client_id = str(getattr(settings, "openai_client_id", "") or getattr(self.oauth_manager, "client_id", "") or "").strip()
            result.metadata = {
                "email_service": self.email_service.service_type.value,
                "proxy_used": self.proxy_url,
                "registered_at": datetime.now().isoformat(),
                "is_existing_account": self._is_existing_account,
                "token_acquired_via_relogin": self._token_acquisition_requires_login,
                "client_id": client_id,
                "device_id": result.device_id,
                "has_session_token": bool(result.session_token),
                "has_access_token": bool(result.access_token),
                "has_refresh_token": bool(result.refresh_token),
                "registration_entry_flow": configured_entry_flow,
                "registration_entry_flow_effective": effective_entry_flow,
                # 对齐 K:\1\2：原生入口允许无 session_token 成功，但会标记待补。
                "session_token_pending": (effective_entry_flow == "native") and (not bool(result.session_token)),
            }

            return result

        except Exception as e:
            self._log(f"注册过程中发生未预期错误: {e}", "error")
            result.error_message = str(e)
            return result

    def _build_anyauto_fallback_result(
        self,
        flow_result: Optional[Dict[str, Any]],
        primary_error: str = "",
    ) -> RegistrationResult:
        """Map PR60 AnyAuto V2 output into the current RegistrationResult structure."""
        result = RegistrationResult(success=False, logs=self.logs)
        result.email = str(self.email or "")
        result.password = str(self.password or "")
        result.device_id = str(self.device_id or "")

        if not flow_result or not flow_result.get("success"):
            fallback_error = str((flow_result or {}).get("error_message") or "注册失败").strip()
            if primary_error and fallback_error and fallback_error != primary_error:
                result.error_message = f"{primary_error} | anyauto fallback: {fallback_error}"
            else:
                result.error_message = fallback_error or primary_error or "注册失败"
            result.metadata = {
                "registration_flow": "any-auto-register-fallback",
                "fallback_attempted": True,
                "primary_error": primary_error,
                "fallback_success": False,
            }
            return result

        result.success = True
        result.access_token = str(flow_result.get("access_token") or "")
        result.refresh_token = str(flow_result.get("refresh_token") or "")
        result.id_token = str(flow_result.get("id_token") or "")
        result.session_token = str(flow_result.get("session_token") or "")
        result.account_id = str(flow_result.get("account_id") or "")
        result.workspace_id = str(flow_result.get("workspace_id") or "")
        result.source = "register"

        if not result.account_id:
            token_payload = result.access_token or result.id_token
            result.account_id = str(self._extract_account_id_from_access_token(token_payload) or "").strip()
        if (not result.account_id) and result.id_token:
            try:
                account_info = self.oauth_manager.extract_account_info(result.id_token)
                result.account_id = str(account_info.get("account_id") or "").strip()
            except Exception:
                pass

        settings = get_settings()
        client_id = str(
            getattr(settings, "openai_client_id", "")
            or getattr(self.oauth_manager, "client_id", "")
            or ""
        ).strip()
        metadata = dict(flow_result.get("metadata") or {})
        metadata.update(
            {
                "email_service": self.email_service.service_type.value,
                "proxy_used": self.proxy_url,
                "registered_at": datetime.now().isoformat(),
                "registration_flow": "any-auto-register-fallback",
                "fallback_attempted": True,
                "primary_error": primary_error,
                "client_id": client_id,
                "device_id": result.device_id,
                "has_session_token": bool(result.session_token),
                "has_access_token": bool(result.access_token),
                "has_refresh_token": bool(result.refresh_token),
            }
        )
        result.metadata = metadata
        return result

    def _run_anyauto_fallback(self, primary_error: str = "") -> RegistrationResult:
        """Run the PR60 AnyAuto V2 engine as a controlled fallback."""
        self._raise_if_cancelled("任务已取消，停止回退注册流程")
        settings = get_settings()
        max_retries = int(getattr(settings, "registration_max_retries", 3) or 3)
        browser_mode = str(
            getattr(settings, "registration_anyauto_browser_mode", "protocol") or "protocol"
        ).strip()

        flow_engine = AnyAutoRegistrationEngine(
            email_service=self.email_service,
            proxy_url=self.proxy_url,
            callback_logger=self._log,
            max_retries=max_retries,
            browser_mode=browser_mode or "protocol",
            extra_config=None,
        )
        flow_result = flow_engine.run()

        self.email_info = flow_engine.email_info
        self.email = flow_engine.email
        self.inbox_email = flow_engine.inbox_email
        self.password = flow_engine.password
        self.session = flow_engine.session
        self.device_id = flow_engine.device_id

        fallback_result = self._build_anyauto_fallback_result(flow_result, primary_error=primary_error)
        if fallback_result.session_token:
            self.session_token = fallback_result.session_token
        return fallback_result

    def _should_try_anyauto_fallback(self, result: RegistrationResult) -> bool:
        settings = get_settings()
        enabled = bool(getattr(settings, "registration_enable_anyauto_fallback", True))
        if not enabled or result.success:
            return False

        error_text = str(result.error_message or "").strip().lower()
        if not error_text:
            return True

        non_retryable_markers = (
            "unsupported country",
            "invalid email service",
            "email service not found",
        )
        if any(marker in error_text for marker in non_retryable_markers):
            return False

        retryable_markers = (
            "access_token",
            "refresh_token",
            "session",
            "oauth",
            "callback",
            "authorization code",
            "workspace",
            "consent",
            "otp",
            "verification code",
            "phone",
            "add_phone",
            "add-phone",
            "sentinel",
            "创建用户账户失败",
            "命中 add-phone 分支",
            "failed to create account",
            "create account",
            "invalid_request_error",
            "http 400",
            "registration failed",
        )
        return any(marker in error_text for marker in retryable_markers)

    def run(self) -> RegistrationResult:
        """Run the current primary flow first, then selectively fall back to PR60 AnyAuto V2."""
        self._raise_if_cancelled("任务已取消，停止注册流程")
        primary_result = self._run_primary_registration()
        self._raise_if_cancelled("任务已取消，停止注册流程")
        if primary_result.success:
            return primary_result

        if not self._should_try_anyauto_fallback(primary_result):
            return primary_result

        self._raise_if_cancelled("任务已取消，跳过回退注册流程")
        primary_error = str(primary_result.error_message or "").strip()
        self._log("主注册链路未成功，开始尝试 PR60 anyauto V2 回退流程...", "warning")
        fallback_result = self._run_anyauto_fallback(primary_error=primary_error)
        if fallback_result.success:
            self._log("PR60 anyauto V2 回退流程成功，已补上 V2 注册兜底能力")
            return fallback_result

        self._log(f"PR60 anyauto V2 回退流程也失败了: {fallback_result.error_message}", "warning")
        return fallback_result

    def save_to_database(
        self,
        result: RegistrationResult,
        account_label: Optional[str] = None,
        role_tag: Optional[str] = None,
    ) -> bool:
        """
        保存注册结果到数据库

        Args:
            result: 注册结果

        Returns:
            是否保存成功
        """
        if not result.success:
            return False

        try:
            # 获取默认 client_id
            settings = get_settings()

            with get_db() as db:
                # 保存账户信息
                account = crud.create_account(
                    db,
                    email=result.email,
                    password=result.password,
                    client_id=settings.openai_client_id,
                    session_token=result.session_token,
                    cookies=self._dump_session_cookies(),
                    email_service=self.email_service.service_type.value,
                    email_service_id=self.email_info.get("service_id") if self.email_info else None,
                    account_id=result.account_id,
                    workspace_id=result.workspace_id,
                    access_token=result.access_token,
                    refresh_token=result.refresh_token,
                    id_token=result.id_token,
                    proxy_used=self.proxy_url,
                    extra_data=result.metadata,
                    source=result.source,
                    account_label=account_label,
                    role_tag=role_tag,
                )

                self._log(f"账户已存进数据库，落袋为安，ID: {account.id}")
                return True

        except Exception as e:
            self._log(f"保存到数据库失败: {e}", "error")
            return False
