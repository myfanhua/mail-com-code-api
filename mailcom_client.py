"""Minimal mail.com web client reconstructed from the supplied HAR captures."""

from __future__ import annotations

import base64
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from curl_cffi import requests
from curl_cffi.requests.exceptions import RequestException


LOGIN_PAGE_URL = "https://www.mail.com/"
LOGIN_URL = "https://login.mail.com/login"
OAUTH_URL = "https://oauthbridge.navigator-lxa.mail.com/navigator/oauth2/token"
MAIL_LIST_URL = "https://maillist.mail.com/Mailbox/Mail"
MAIL_BODY_URL = "https://webmail-cats-live.mail.com/mailbox/primary/mailbody/{mail_id}/Body"
SETTINGS_ADDRESSES_URL = "https://settings-cats.mail.com/mailaccount/primary/emailAddresses"
SETTINGS_VALIDATE_URL = "https://settings-cats.mail.com/mailaccount/emailAddressValidations"
SETTINGS_DOMAINS_URL = "https://settings-cats.mail.com/domains"

MAIL_SCOPE = "mail_mailbox_r"
SETTINGS_SCOPE = "mail_mailbox_w webmailer_setting_r webmailer_setting_w mail_confix_w"
MAIL_CLIENT_ID = "mailcom_webmailermaillist_passport_live"
SETTINGS_CLIENT_ID = "mailcom_mailset_root_live"
# This is the public SPA secret shipped in mail.com's frontend bundle.  It is
# not an account credential; allow an environment override for future bundle
# rotations without changing the client code.
OAUTH_PUBLIC_SECRET = os.getenv("MAIL_OAUTH_PUBLIC_SECRET", "*******")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
)
HTTP_IMPERSONATE = os.getenv("MAIL_HTTP_IMPERSONATE", "chrome136")
STATISTICS_RE = re.compile(r'name=["\']statistics["\'][^>]*value=["\']([^"\']*)', re.I)


class MailComError(RuntimeError):
    def __init__(self, message: str, *, kind: str = "upstream_error", status: int = 502):
        super().__init__(message)
        self.kind = kind
        self.status = status


@dataclass(slots=True)
class MailMessage:
    mail_id: str
    subject: str
    sender: str
    recipients: list[str]
    date_ms: int
    folder: str


class MailComClient:
    def __init__(
        self,
        username: str,
        password: str,
        *,
        state: dict[str, Any] | None = None,
        timeout: float = 25.0,
        proxy_url: str = "",
    ) -> None:
        self.username = username.strip().lower()
        self.password = password
        self.timeout = timeout
        # mail.com checks the browser TLS/HTTP fingerprint during login.  A
        # plain requests/urllib3 client is redirected to support.mail.com even
        # when the same account and proxy work in a browser.
        self.session = requests.Session(impersonate=HTTP_IMPERSONATE)
        self.session.headers.update({"User-Agent": USER_AGENT})
        # A proxy is an account property.  Reuse it for every upstream request;
        # rotation and fallback to another account's proxy are intentionally absent.
        self.proxy_url = proxy_url.strip()
        if self.proxy_url:
            self.session.trust_env = False
            self.session.proxies.update({"http": self.proxy_url, "https": self.proxy_url})
        state = state or {}
        self.sid = str(state.get("sid") or "")
        self.auth_id = str(state.get("auth_id") or "")
        self.tokens: dict[str, str] = dict(state.get("tokens") or {})
        cookies = state.get("cookies") or {}
        if isinstance(cookies, dict):
            self.session.cookies.update(cookies)

    def export_state(self) -> dict[str, Any]:
        return {
            "sid": self.sid,
            "auth_id": self.auth_id,
            "tokens": self.tokens,
            "cookies": self.session.cookies.get_dict(),
            "saved_at": int(time.time()),
        }

    @staticmethod
    def decode_token(token: str) -> dict[str, Any]:
        try:
            part = token.split(".")[1]
            part += "=" * (-len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(part).decode("utf-8"))
        except (IndexError, ValueError, json.JSONDecodeError) as exc:
            raise MailComError("mail.com 返回了无法解析的 access token") from exc

    @classmethod
    def token_expiry(cls, token: str) -> float:
        value = float(cls.decode_token(token).get("exp") or 0)
        # mail.com currently emits epoch milliseconds, unlike conventional JWT seconds.
        return value / 1000.0 if value > 10_000_000_000 else value

    @staticmethod
    def _timezone_hours() -> int:
        local = time.localtime()
        offset = -time.timezone if not local.tm_isdst else -time.altzone
        return int(offset // 3600)

    def login(self, retries: int = 3) -> None:
        last_error: MailComError | None = None
        for attempt in range(retries):
            try:
                self._login_once()
                self.tokens.clear()
                return
            except MailComError as exc:
                last_error = exc
                if exc.kind in {"bad_credentials", "blocked"}:
                    break
                if attempt + 1 < retries:
                    time.sleep(2 * (attempt + 1))
        raise last_error or MailComError("mail.com 登录失败", kind="login_failed")

    def _login_once(self) -> None:
        statistics = ""
        try:
            page = self.session.get(LOGIN_PAGE_URL, timeout=self.timeout)
            if page.ok:
                match = STATISTICS_RE.search(page.text)
                statistics = match.group(1) if match else ""
        except RequestException:
            # The login POST can still work when the marketing page is unavailable.
            pass

        form = {
            "username": self.username,
            "password": self.password,
            "service": "mailint",
            "uasServiceID": "mc_starter_mailcom",
            "successURL": "https://$(clientName)-$(dataCenter).mail.com/login",
            "loginFailedURL": "https://www.mail.com/logout?ls=wd",
            "loginErrorURL": "https://www.mail.com/logout?ls=te",
            "edition": "US",
            "lang": "en",
            "usertype": "standard",
            "ibaInfo": "abd=false",
            "statistics": statistics,
        }
        try:
            response = self.session.post(
                LOGIN_URL,
                data=form,
                allow_redirects=False,
                timeout=self.timeout,
                headers={"Origin": LOGIN_PAGE_URL.rstrip("/"), "Referer": LOGIN_PAGE_URL},
            )
        except RequestException as exc:
            raise MailComError("无法连接 mail.com 登录服务", kind="network") from exc

        location = response.headers.get("Location", "")
        if response.status_code == 429:
            raise MailComError("mail.com 登录频率受限", kind="rate_limited", status=429)
        if response.status_code == 403:
            raise MailComError("mail.com 拒绝了当前网络的登录请求", kind="blocked", status=403)
        if response.status_code in (302, 303) and "ott=" not in location:
            kind = "bad_credentials" if "logout?ls=wd" in location else "login_redirect"
            raise MailComError("登录未返回一次性令牌", kind=kind, status=401)
        if response.status_code != 303 or "ott=" not in location:
            raise MailComError(f"登录响应异常 (HTTP {response.status_code})", kind="login_failed")

        callback = urljoin(LOGIN_URL, location)
        parsed = urlparse(callback)
        query = parsed.query + ("&" if parsed.query else "") + f"tz={self._timezone_hours()}"
        halogin = urlunparse((parsed.scheme, parsed.netloc, "/halogin", "", query, ""))
        try:
            exchanged = self.session.get(halogin, allow_redirects=False, timeout=self.timeout)
        except RequestException as exc:
            raise MailComError("无法完成 mail.com 会话交换", kind="network") from exc
        location = exchanged.headers.get("Location", "")
        sid = (parse_qs(urlparse(location).query).get("sid") or [""])[0]
        if exchanged.status_code not in (302, 303) or not sid:
            raise MailComError("mail.com 会话交换未返回 sid", kind="session_rejected", status=401)
        self.sid = sid

    def _token_key(self, client_id: str, scope: str) -> str:
        return f"{client_id}|{scope}"

    @staticmethod
    def _oauth_headers(client_id: str) -> dict[str, str]:
        """Return the browser application context expected by OAuthBridge.

        OAuthBridge chooses the public SPA client from the request origin and
        UI application.  Using the webmailer context for settings scopes
        causes WRONG_PUBLIC_SECRET even when the mailbox session is valid.
        """
        if client_id == SETTINGS_CLIENT_ID:
            context = {
                "Origin": "https://mailset-root.mail.com",
                "Referer": "https://mailset-root.mail.com/",
            }
        else:
            context = {
                "Origin": "https://webmailer.mail.com",
                "Referer": "https://webmailer.mail.com/",
                "x-ui-app": "mailcom.webmailer.mail-list/6.6.3",
            }
        basic = base64.b64encode(f"{client_id}:{OAUTH_PUBLIC_SECRET}".encode()).decode()
        context["Authorization"] = f"Basic {basic}"
        return context

    def get_token(self, scope: str, client_id: str, *, force: bool = False) -> str:
        key = self._token_key(client_id, scope)
        token = self.tokens.get(key, "")
        if token and not force:
            try:
                if self.token_expiry(token) > time.time() + 60:
                    return token
            except MailComError:
                pass
        if not self.sid:
            self.login()

        try:
            response = self.session.post(
                OAUTH_URL,
                params={"sid": self.sid},
                data={"grant_type": "urn:mam:oauth:grant-type:spa", "scope": scope},
                timeout=self.timeout,
                headers=self._oauth_headers(client_id),
            )
        except RequestException as exc:
            raise MailComError("无法连接 mail.com OAuth 服务", kind="network") from exc
        if response.status_code in (401, 403):
            raise MailComError("mail.com 会话已失效或被拒绝", kind="session_expired", status=401)
        if response.status_code == 429:
            raise MailComError("mail.com token 请求频率受限", kind="rate_limited", status=429)
        if response.status_code != 200:
            raise MailComError(f"token 请求失败 (HTTP {response.status_code})", kind="oauth_failed")
        try:
            token = str(response.json()["access_token"])
        except (ValueError, KeyError) as exc:
            raise MailComError("token 响应缺少 access_token", kind="oauth_failed") from exc
        payload = self.decode_token(token)
        self.auth_id = str(payload.get("auth_id") or self.auth_id)
        self.tokens[key] = token
        return token

    def ensure_mail_token(self) -> str:
        try:
            return self.get_token(MAIL_SCOPE, MAIL_CLIENT_ID)
        except MailComError as exc:
            if exc.kind not in {"session_expired", "oauth_failed"}:
                raise
            self.sid = ""
            self.tokens.clear()
            self.login()
            return self.get_token(MAIL_SCOPE, MAIL_CLIENT_ID, force=True)

    def _mail_headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.1and1.mms.unified-maillist-v1+json; charset=utf-8",
            "Content-Type": "application/vnd.1and1.mms.inboxadrequest-v1+json; charset=utf-8",
            "Origin": "https://webmailer.mail.com",
            "Referer": "https://webmailer.mail.com/",
            "x-ui-app": "mailcom.webmailer.mail-list/6.6.3",
        }

    def _cache_buster(self) -> str:
        # auth_id 在一次登录会话内不会变化，单独使用它会让连续查询命中
        # mail.com 的旧邮件列表缓存，导致第二封验证码邮件暂时不可见。
        return f"{self.auth_id}-{time.time_ns()}"

    def query_messages(self, recipient: str, *, amount: int = 20) -> list[MailMessage]:
        token = self.ensure_mail_token()
        params: dict[str, Any] = {
            "folderTypeOrId": "INBOX",
            "offset": "0",
            "amount": str(max(1, min(amount, 50))),
            "orderBy": "INTERNALDATE DESC",
            "no_cache": self._cache_buster(),
            "condition": f"mail.header:subject,to,from,cc:{recipient}",
        }
        try:
            response = self.session.post(
                MAIL_LIST_URL, params=params, data=b"", headers=self._mail_headers(token), timeout=self.timeout
            )
        except RequestException as exc:
            raise MailComError("无法连接 mail.com 邮件列表服务", kind="network") from exc
        if response.status_code == 401:
            self.tokens.pop(self._token_key(MAIL_CLIENT_ID, MAIL_SCOPE), None)
            token = self.ensure_mail_token()
            params["no_cache"] = self._cache_buster()
            try:
                response = self.session.post(
                    MAIL_LIST_URL, params=params, data=b"", headers=self._mail_headers(token), timeout=self.timeout
                )
            except RequestException as exc:
                raise MailComError("无法连接 mail.com 邮件列表服务", kind="network") from exc
        if response.status_code != 200:
            raise MailComError(f"查询收件箱失败 (HTTP {response.status_code})", kind="mail_query_failed")
        try:
            elements = response.json().get("mailListElements") or []
        except ValueError as exc:
            raise MailComError("邮件列表响应不是 JSON", kind="mail_query_failed") from exc
        messages: list[MailMessage] = []
        for element in elements:
            raw = element.get("rawData") or {}
            attr = raw.get("attribute") or {}
            header = raw.get("mailHeader") or {}
            mail_id = attr.get("mailIdentifier")
            if not mail_id:
                continue
            recipients = header.get("to") or []
            if isinstance(recipients, str):
                recipients = [recipients]
            messages.append(
                MailMessage(
                    mail_id=str(mail_id),
                    subject=str(header.get("subject") or ""),
                    sender=str(header.get("from") or ""),
                    recipients=[str(value) for value in recipients],
                    date_ms=int(header.get("date") or attr.get("internalDate") or 0),
                    folder=str(attr.get("folderType") or ""),
                )
            )
        return messages

    def get_body(self, mail_id: str) -> str:
        token = self.ensure_mail_token()
        try:
            response = self.session.get(
                MAIL_BODY_URL.format(mail_id=mail_id),
                params={"absoluteURI": "false", "no_cache": self._cache_buster()},
                headers={**self._mail_headers(token), "Accept": "text/plain"},
                timeout=self.timeout,
            )
        except RequestException as exc:
            raise MailComError("无法连接 mail.com 邮件正文服务", kind="network") from exc
        if response.status_code != 200:
            raise MailComError(f"获取邮件正文失败 (HTTP {response.status_code})", kind="mail_body_failed")
        return response.text

    def _settings_headers(
        self, token: str, content_type: str, *, accept: str | None = None
    ) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": accept or content_type,
            "Content-Type": content_type,
            "Origin": "https://mailset-root.mail.com",
            "Referer": "https://mailset-root.mail.com/",
            "x-ui-app": "mailcom.mailset-compose/1.0.5-build.335",
        }

    def ensure_settings_token(self) -> str:
        try:
            return self.get_token(SETTINGS_SCOPE, SETTINGS_CLIENT_ID)
        except MailComError as exc:
            if exc.kind not in {"session_expired", "oauth_failed"}:
                raise
            self.sid = ""
            self.tokens.clear()
            self.login()
            return self.get_token(SETTINGS_SCOPE, SETTINGS_CLIENT_ID, force=True)

    def list_aliases(self) -> list[str]:
        token = self.ensure_settings_token()
        response = self.session.get(
            SETTINGS_ADDRESSES_URL,
            params={"absoluteURI": "false", "q.state.in": "ACTIVE", "q.type.in": "MANAGED,DOMAIN_HOSTING"},
            headers=self._settings_headers(token, "application/vnd.ui.trinity.mailaddress.list-v5+json"),
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise MailComError(f"读取邮箱地址失败 (HTTP {response.status_code})", kind="settings_failed")
        return [str(row.get("address") or "").lower() for row in response.json().get("mailaddresslist", []) if row.get("address")]

    def list_domains(self) -> list[str]:
        token = self.ensure_settings_token()
        try:
            response = self.session.get(
                SETTINGS_DOMAINS_URL,
                params={
                    "absoluteURI": "false",
                    "q.state.eq": "ACTIVE",
                    "q.owner.eq": "gmx_MAILCOM",
                },
                headers=self._settings_headers(token, "application/json"),
                timeout=self.timeout,
            )
        except RequestException as exc:
            raise MailComError("无法连接 mail.com 域名服务", kind="network") from exc
        if response.status_code != 200:
            raise MailComError(
                f"读取域名列表失败 (HTTP {response.status_code})",
                kind="settings_failed",
            )
        try:
            rows = response.json().get("domains") or []
        except ValueError as exc:
            raise MailComError("域名列表响应不是 JSON", kind="settings_failed") from exc
        return list(dict.fromkeys(str(row.get("domain") or "").lower() for row in rows if row.get("domain")))

    def add_alias(self, address: str, *, validate: bool = True) -> None:
        token = self.ensure_settings_token()
        if validate:
            validation = self.session.post(
                SETTINGS_VALIDATE_URL,
                params={"absoluteURI": "false"},
                json=[address],
                headers=self._settings_headers(
                    token,
                    "application/vnd.ui.trinity.email-address-validation-request+json",
                    accept="application/vnd.ui.trinity.email-address-validation-response+json",
                ),
                timeout=self.timeout,
            )
            if validation.status_code != 200:
                raise MailComError(
                    f"邮箱地址校验失败 (HTTP {validation.status_code})", kind="alias_invalid", status=400
                )
        response = self.session.post(
            SETTINGS_ADDRESSES_URL,
            params={"absoluteURI": "false"},
            json={
                "address": address,
                "deletable": True,
                "pgpEnabled": False,
                "defaultSenderAddress": False,
                "defaultReceiverAddress": False,
                "state": "ACTIVE",
            },
            headers=self._settings_headers(token, "application/vnd.ui.trinity.minimalmailaddress-v3+json"),
            timeout=self.timeout,
        )
        if response.status_code != 201:
            kind = "alias_limit" if response.status_code in (403, 409, 422, 429) else "settings_failed"
            raise MailComError(
                f"添加邮箱地址失败 (HTTP {response.status_code})",
                kind=kind,
                status=response.status_code,
            )
