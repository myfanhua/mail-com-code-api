#!/usr/bin/env python3
"""Deployable mail.com account-to-verification-code HTTP service."""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, quote, urlparse, urlsplit

from code_extract import extract_code
from mailcom_client import MailComClient, MailComError
from storage import Account, Address, Store


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.I,
)
MAX_REQUEST_BODY = 2 * 1024 * 1024
WEB_DIR = Path(__file__).with_name("web")
WEB_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8"}
MAIL_COM_DOMAINS = (
    "2trom.com", "accountant.com", "acdcfan.com", "activist.com", "adexec.com",
    "africamail.com", "alumni.com", "angelic.com", "archaeologist.com",
    "arcticmail.com", "artlover.com", "asia.com", "atheist.com",
    "australiamail.com", "bartender.net", "berlin.com", "bikerider.com",
    "birdlover.com", "boardermail.com", "brazilmail.com", "brew-master.com",
    "bsdmail.com", "californiamail.com", "catlover.com", "cheerful.com",
    "chef.net", "chemist.com", "chinamail.com", "clubmember.org",
    "collector.org", "columnist.com", "comic.com", "consultant.com",
    "contractor.com", "contractor.net", "counsellor.com", "cutey.com",
    "cyber-wizard.com", "cyberdude.com", "cybergal.com", "cyberservices.com",
    "dallasmail.com", "dbzmail.com", "diplomats.com", "disciples.com",
    "discofan.com", "doglover.com", "doramail.com", "dr.com", "dublin.com",
    "dutchmail.com", "elvisfan.com", "email.com", "engineer.com",
    "englandmail.com", "europe.com", "europemail.com", "execs.com",
    "financier.com", "fireman.net", "galaxyhit.com", "gardener.com",
    "geologist.com", "germanymail.com", "graduate.org", "graphic-designer.com",
    "greenmail.net", "groupmail.com", "hackermail.com", "hairdresser.net", "hilarious.com",
    "housemail.com",
    "hiphopfan.com", "iname.com", "innocent.com", "irelandmail.com",
    "israelmail.com", "italymail.com", "keromail.com", "kissfans.com",
    "kittymail.com", "koreamail.com", "legislator.com", "linuxmail.org",
    "lobbyist.com", "lovecat.com", "madonnafan.com", "mail.com",
    "marchmail.com", "metalfan.com", "mexicomail.com", "minister.com",
    "moscowmail.com", "munich.com", "musician.org", "muslim.com",
    "myself.com", "ninfan.com", "nonpartisan.com", "null.net", "nycmail.com",
    "optician.com", "orthodontist.net", "pediatrician.com", "petlover.com",
    "photographer.net", "physicist.net", "polandmail.com", "politician.com",
    "post.com", "presidency.com", "priest.com", "programmer.net", "protestant.com",
    "publicist.com", "ravemail.com", "realtyagent.com", "reborn.com",
    "reggaefan.com", "registerednurses.com", "reincarnate.com",
    "religious.com", "repairman.com", "safrica.com", "saintly.com",
    "sanfranmail.com", "scotlandmail.com", "secretary.net",
    "socialworker.net", "sociologist.com", "solution4u.com", "songwriter.net", "spainmail.com",
    "swedenmail.com", "swissmail.com", "teachers.org", "techie.com",
    "technologist.com", "theplate.com", "therapist.net", "toke.com",
    "toothfairy.com", "torontomail.com", "tvstar.com", "usa.com", "uymail.com",
    "webname.com", "computer4u.com", "bellair.net",
)
MAIL_COM_DOMAINS_BY_TLD = {
    tld: tuple(domain for domain in MAIL_COM_DOMAINS if domain.endswith(f".{tld}"))
    for tld in ("com", "net")
}
MAIL_COM_MAX_ADDRESSES_PER_ACCOUNT = 10
MAX_SPLIT_ALIASES = MAIL_COM_MAX_ADDRESSES_PER_ACCOUNT - 1
ALIAS_FIRST_NAMES = (
    "alex", "amelia", "ava", "benjamin", "charlotte", "chloe", "daniel", "david",
    "ella", "emily", "emma", "ethan", "evelyn", "grace", "hannah", "henry",
    "isabella", "jack", "james", "jasmine", "john", "joseph", "liam", "lily",
    "lucas", "mason", "mia", "natalie", "noah", "nora", "olivia", "owen",
    "ryan", "samuel", "sophia", "william", "zoe",
)
ALIAS_LAST_NAMES = (
    "adams", "anderson", "baker", "bennett", "brooks", "brown", "campbell",
    "carter", "clark", "collins", "cooper", "davis", "edwards", "evans",
    "foster", "garcia", "green", "hall", "harris", "hill", "jackson",
    "johnson", "king", "lee", "lewis", "martin", "miller", "mitchell",
    "moore", "morgan", "nelson", "parker", "roberts", "scott", "smith",
    "taylor", "thomas", "walker", "white", "wilson", "young",
)


class RateLimiter:
    def __init__(self, requests_per_minute: int) -> None:
        self.limit = max(1, requests_per_minute)
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            events = self._events[key]
            while events and events[0] < now - 60:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True


def normalize_proxy_url(value: Any) -> str | None:
    """Normalize a proxy value without ever returning credentials in errors.

    Accepted forms are ``http(s)://[user:pass@]host:port`` and the compact
    ``host:port:user:pass`` form used by common proxy exports.  The normalized
    value is stored encrypted by ``Store``.
    """
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if "://" not in text:
            parts = text.split(":", 3)
            if len(parts) != 4:
                raise ValueError
            host, port, username, password = parts
            if not host or not port or not username or not password:
                raise ValueError
            text = (
                f"http://{quote(username, safe='')}:{quote(password, safe='')}"
                f"@{host}:{port}"
            )
        parsed = urlsplit(text)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError
        if parsed.port is None or not 1 <= parsed.port <= 65535:
            raise ValueError
        # Force a canonical scheme while preserving encoded credentials.
        return text
    except (ValueError, UnicodeError):
        raise ValueError("proxy 格式无效，应为 http://host:port 或 host:port:user:pass")


def normalize_domain(value: Any) -> str:
    text = str(value or "").strip().strip("\ufeff\u200b\"'").lower()
    if text.startswith("[") and "](" in text and text.endswith(")"):
        text = text[text.rfind("](") + 2 : -1].strip().lower()
    if "@" in text:
        text = text.split("@", 1)[1].strip()
    if "://" in text:
        parsed = urlsplit(text)
        text = (parsed.hostname or "").lower()
    elif "/" in text:
        parsed = urlsplit(f"https://{text}")
        text = (parsed.hostname or "").lower()
    if not DOMAIN_RE.fullmatch(text):
        raise ValueError("domain 格式无效")
    return text


def normalize_mailcom_domain(value: Any) -> str:
    domain = normalize_domain(value)
    if domain not in MAIL_COM_DOMAINS:
        raise ValueError(f"domain 不是 mail.com 支持的别名域名：{domain}")
    return domain


def parse_split_domains(value: Any) -> list[str]:
    if isinstance(value, str):
        raw_values = [item.strip() for item in value.replace(",", "\n").splitlines()]
    elif isinstance(value, list):
        raw_values = [str(item or "").strip() for item in value]
    elif value:
        raise ValueError("domain 必须是文本或数组")
    else:
        raw_values = []

    result: list[str] = []
    for raw in raw_values:
        if not raw:
            continue
        # 指定域名只做格式校验，不再依赖本地静态白名单。
        # mail.com 的可用别名域名会变化，最终是否支持交给上游添加接口判断。
        domain = normalize_domain(raw)
        if domain not in result:
            result.append(domain)
    return result


def parse_random_domain_tlds(payload: dict[str, Any]) -> list[str]:
    raw = payload.get("random_domain_tlds", payload.get("random_tlds", []))
    if isinstance(raw, str):
        values = [item.strip().lower().removeprefix(".") for item in raw.replace(",", "\n").splitlines()]
    elif isinstance(raw, list):
        values = [str(item or "").strip().lower().removeprefix(".") for item in raw]
    elif raw:
        raise ValueError("random_domain_tlds 必须是数组或文本")
    else:
        values = []

    if payload.get("random_com"):
        values.append("com")
    if payload.get("random_net"):
        values.append("net")

    result: list[str] = []
    for value in values:
        if not value:
            continue
        if value not in {"com", "net"}:
            raise ValueError("随机域名只支持 com 或 net")
        if value not in result:
            result.append(value)
    return result


def log_api_event(event: str, **fields: Any) -> None:
    print(
        "mail-code-api "
        + json.dumps({"event": event, **fields}, ensure_ascii=False, separators=(",", ":")),
        file=sys.stderr,
    )


def _parse_account_rows(payload: Any) -> list[tuple[str, str, str | None]]:
    if isinstance(payload, dict):
        payload = payload.get("accounts", payload.get("text", ""))
    if isinstance(payload, list):
        rows: list[tuple[str, str, str | None]] = []
        for index, item in enumerate(payload, 1):
            if not isinstance(item, dict):
                raise ValueError(f"第 {index} 项必须是对象")
            rows.append(
                (
                    str(item.get("email") or ""),
                    str(item.get("password") or ""),
                    normalize_proxy_url(item.get("proxy", item.get("proxy_url"))),
                )
            )
    elif isinstance(payload, str):
        rows = []
        for line_no, raw in enumerate(payload.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            delimiter = next((value for value in ("----", "---", "\t", ",") if value in line), "")
            if not delimiter:
                raise ValueError(f"第 {line_no} 行缺少分隔符（支持 ----、---、Tab、逗号）")
            fields = line.split(delimiter, 2)
            email, password = fields[0], fields[1]
            proxy = normalize_proxy_url(fields[2]) if len(fields) == 3 else None
            rows.append((email, password, proxy))
    else:
        raise ValueError("请求体必须是账号数组或文本")

    normalized: dict[str, tuple[str, str | None]] = {}
    for index, (email, password, proxy) in enumerate(rows, 1):
        email = email.strip().lower()
        password = password.strip()
        if not EMAIL_RE.match(email):
            raise ValueError(f"第 {index} 个邮箱格式无效")
        if not password:
            raise ValueError(f"第 {index} 个密码为空")
        previous = normalized.get(email)
        if previous and previous[1] and proxy and previous[1] != proxy:
            raise ValueError(f"第 {index} 行与同账号已有固定代理不一致")
        normalized[email] = (password, proxy or (previous[1] if previous else None))
    if not normalized:
        raise ValueError("没有可导入的账号")
    return [(email, password, proxy) for email, (password, proxy) in normalized.items()]


def parse_credentials(payload: Any) -> list[tuple[str, str]]:
    """Backward-compatible credential-only parser used by callers and tests."""
    return [(email, password) for email, password, _proxy in _parse_account_rows(payload)]


def parse_account_rows(payload: Any) -> list[tuple[str, str, str | None]]:
    return _parse_account_rows(payload)


def load_proxy_pool(path_value: str | Path) -> list[str]:
    """Load and normalize a private one-proxy-per-line pool file."""
    if not str(path_value).strip():
        return []
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        raise RuntimeError(f"proxy pool file not found: {path}")
    proxies: list[str] = []
    seen: set[str] = set()
    for line_no, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            proxy = normalize_proxy_url(line)
        except ValueError as exc:
            raise RuntimeError(f"proxy pool line {line_no} is invalid") from exc
        if proxy and proxy not in seen:
            seen.add(proxy)
            proxies.append(proxy)
    if not proxies:
        raise RuntimeError("proxy pool file has no valid entries")
    return proxies


def parse_proxy_pool_text(payload: Any) -> list[str]:
    if isinstance(payload, dict):
        payload = payload.get("text", payload.get("proxies", payload.get("proxy_pool", "")))
    if isinstance(payload, list):
        values = [str(item or "") for item in payload]
    elif isinstance(payload, str):
        values = payload.splitlines()
    else:
        raise ValueError("请求体必须是代理池文本或代理数组")

    proxies: list[str] = []
    seen: set[str] = set()
    for line_no, raw in enumerate(values, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            proxy = normalize_proxy_url(line)
        except ValueError as exc:
            raise ValueError(f"代理池第 {line_no} 行格式无效") from exc
        if proxy and proxy not in seen:
            seen.add(proxy)
            proxies.append(proxy)
    if not proxies:
        raise ValueError("代理池为空")
    return proxies


def parse_email_list(payload: Any) -> list[str]:
    if isinstance(payload, dict):
        payload = payload.get("emails", payload.get("text", ""))
    if isinstance(payload, list):
        values = [str(item or "") for item in payload]
    elif isinstance(payload, str):
        values = [item for line in payload.splitlines() for item in line.replace(",", "\n").splitlines()]
    else:
        raise ValueError("请求体必须是邮箱数组或文本")
    result, seen = [], set()
    for value in values:
        email = value.strip().lower()
        if not email:
            continue
        if not EMAIL_RE.match(email):
            raise ValueError(f"邮箱格式无效：{email}")
        if email not in seen:
            seen.add(email)
            result.append(email)
    if not result:
        raise ValueError("没有可查询的邮箱")
    if len(result) > 100:
        raise ValueError("单次最多查询 100 个邮箱")
    return result


def parse_timestamp(value: str) -> float | None:
    if not value:
        return None
    try:
        numeric = float(value)
        return numeric / 1000 if numeric > 10_000_000_000 else numeric
    except ValueError:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError as exc:
            raise ValueError("since 必须是 Unix 时间戳或 ISO-8601 时间") from exc


def parse_pagination(query: str) -> tuple[int, int]:
    params = parse_qs(query)
    try:
        page = max(1, int((params.get("page") or ["1"])[0]))
        page_size = max(1, min(100, int((params.get("page_size") or ["20"])[0])))
    except (TypeError, ValueError) as exc:
        raise ValueError("page 和 page_size 必须是正整数") from exc
    return page, page_size


class MailCodeApplication:
    def __init__(
        self,
        store: Store,
        admin_token: str,
        *,
        timeout: float = 25.0,
        rate_limit: int = 30,
        client_factory: Callable[..., MailComClient] = MailComClient,
        proxy_pool: list[str] | None = None,
        proxy_pool_file: str | Path | None = None,
    ) -> None:
        self.store = store
        self.admin_token = admin_token
        self.timeout = timeout
        self.client_factory = client_factory
        self.rate_limiter = RateLimiter(rate_limit)
        self._account_locks: dict[int, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self.proxy_pool = tuple(proxy_pool or ())
        self.proxy_pool_file = Path(proxy_pool_file).expanduser().resolve() if proxy_pool_file else None
        self._proxy_pool_lock = threading.Lock()
        self._assigned_proxies = self.store.list_assigned_proxies()
        self._proxy_pool_cursor = 0

    def account_lock(self, account_id: int) -> threading.Lock:
        with self._locks_guard:
            return self._account_locks.setdefault(account_id, threading.Lock())

    def import_account(
        self,
        email: str,
        password: str,
        supplied_proxy: str | None = None,
        *,
        use_proxy_pool: bool = False,
    ) -> tuple[Address, Account]:
        """Persist an account and optionally assign one proxy exactly once.

        Pool allocation happens only during import and only when explicitly
        requested.  No request path contains failover, rotation, or
        wrap-around behavior.
        """
        with self._proxy_pool_lock:
            existing = self.store.get_account_by_email(email)
            if existing and existing.proxy_url:
                route = self.store.upsert_account(email, password, supplied_proxy)
                account = self.store.get_account(route.account_id)
                if not account:
                    raise RuntimeError("account disappeared after import")
                return route, account

            proxy_url = supplied_proxy if use_proxy_pool else None
            allocated = False
            if proxy_url and proxy_url in self._assigned_proxies:
                raise ValueError("proxy_already_assigned")
            if use_proxy_pool and not proxy_url and self.proxy_pool:
                while (
                    self._proxy_pool_cursor < len(self.proxy_pool)
                    and self.proxy_pool[self._proxy_pool_cursor] in self._assigned_proxies
                ):
                    self._proxy_pool_cursor += 1
                if self._proxy_pool_cursor >= len(self.proxy_pool):
                    raise ValueError("proxy_pool_exhausted")
                proxy_url = self.proxy_pool[self._proxy_pool_cursor]
                self._proxy_pool_cursor += 1
            if proxy_url:
                self._assigned_proxies.add(proxy_url)
                allocated = True
            try:
                route = self.store.upsert_account(email, password, proxy_url)
            except Exception:
                if allocated and proxy_url:
                    self._assigned_proxies.discard(proxy_url)
                raise
            account = self.store.get_account(route.account_id)
            if not account:
                raise RuntimeError("account disappeared after import")
            return route, account

    def proxy_pool_stats(self) -> dict[str, int]:
        with self._proxy_pool_lock:
            assigned = sum(1 for proxy in self.proxy_pool if proxy in self._assigned_proxies)
            return {
                "total": len(self.proxy_pool),
                "assigned": assigned,
                "remaining": max(0, len(self.proxy_pool) - assigned),
            }

    def add_proxy_pool(self, proxies: list[str]) -> dict[str, int]:
        cleaned = []
        seen = set(self.proxy_pool)
        for proxy in proxies:
            if proxy not in seen:
                seen.add(proxy)
                cleaned.append(proxy)
        if not cleaned:
            return self.proxy_pool_stats()
        with self._proxy_pool_lock:
            current = list(self.proxy_pool)
            current.extend(cleaned)
            self.proxy_pool = tuple(current)
            if self.proxy_pool_file:
                self.proxy_pool_file.parent.mkdir(parents=True, exist_ok=True)
                self.proxy_pool_file.write_text("\n".join(self.proxy_pool) + "\n", encoding="utf-8")
        return self.proxy_pool_stats()

    def client_for(self, account: Account) -> MailComClient:
        return self.client_factory(
            account.email,
            account.password,
            state=account.session,
            timeout=self.timeout,
            proxy_url=account.proxy_url,
        )

    def check_account(self, account: Account, *, sync_aliases: bool = False) -> dict[str, Any]:
        with self.account_lock(account.id):
            client = self.client_for(account)
            try:
                client.ensure_mail_token()
                aliases: list[str] = []
                if sync_aliases:
                    aliases = client.list_aliases()
                    for address in aliases:
                        self.store.add_address(account.id, address, primary=address == account.email)
                self.store.update_session(account.id, client.export_state(), status="ready")
                return {"ok": True, "email": account.email, "aliases": aliases}
            except MailComError as exc:
                self.store.update_status(account.id, exc.kind, str(exc))
                return {"ok": False, "email": account.email, "error": exc.kind, "detail": str(exc)}

    def add_alias(
        self,
        account: Account,
        address: str,
        *,
        verify_visible: bool = True,
        validate: bool = True,
    ) -> Address:
        address = address.strip().lower()
        if not EMAIL_RE.match(address):
            raise ValueError("别名邮箱格式无效")
        with self.account_lock(account.id):
            client = self.client_for(account)
            client.add_alias(address, validate=validate)
            if verify_visible:
                aliases = client.list_aliases()
                if address not in aliases:
                    raise MailComError("上游返回成功，但别名列表中未出现该地址", kind="alias_not_visible")
            route = self.store.add_address(account.id, address)
            self.store.update_session(account.id, client.export_state(), status="ready")
            return route

    def add_aliases(
        self,
        account: Account,
        addresses: list[str],
        *,
        verify_visible: bool = True,
        validate: bool = True,
    ) -> list[Address]:
        routes: list[Address] = []
        for address in addresses:
            routes.append(
                self.add_alias(account, address, verify_visible=verify_visible, validate=validate)
            )
        return routes

    def sync_aliases(self, account: Account) -> list[Address]:
        with self.account_lock(account.id):
            client = self.client_for(account)
            aliases = client.list_aliases()
            routes = [
                self.store.add_address(account.id, address, primary=address == account.email)
                for address in aliases
            ]
            self.store.update_session(account.id, client.export_state(), status="ready")
            return routes

    def list_alias_domains(self, account: Account) -> list[str]:
        with self.account_lock(account.id):
            client = self.client_for(account)
            domains = client.list_domains()
            self.store.update_session(account.id, client.export_state(), status="ready")
            return domains

    def split_aliases(
        self,
        account: Account,
        count: int,
        *,
        prefix: str | None = None,
        domain: str | None = None,
        random_domain_tlds: list[str] | None = None,
    ) -> list[Address]:
        count = max(1, min(int(count), MAX_SPLIT_ALIASES))
        current_address_count = len(self.store.list_addresses_for_account(account.id))
        remaining = MAIL_COM_MAX_ADDRESSES_PER_ACCOUNT - current_address_count
        if remaining <= 0:
            raise MailComError(
                f"账号地址已达 mail.com 上限（本地已有 {current_address_count} 个地址）",
                kind="alias_limit",
                status=409,
            )
        count = min(count, remaining)
        _local, account_domain = account.email.rsplit("@", 1)
        alias_domains = tuple(parse_split_domains(domain))
        random_domains: tuple[str, ...] = ()
        if random_domain_tlds and not alias_domains:
            upstream_domains = self.list_alias_domains(account)
            random_domains = tuple(
                domain
                for tld in random_domain_tlds
                for domain in upstream_domains
                if domain.endswith(f".{tld}")
            )
            if not random_domains:
                raise MailComError(
                    f"mail.com 未返回可用的随机 {', '.join('.' + tld for tld in random_domain_tlds)} 别名域名",
                    kind="settings_failed",
                    status=502,
                )
        # 默认组合常见英文名和姓氏，并随机切换排列、分隔符及数字形式，
        # 生成更接近真人邮箱且没有固定 split 标记的子号。
        base = (prefix or "").strip().lower()
        if "@" in base:
            base = base.split("@", 1)[0]
        base = base[:32]
        routes: list[Address] = []
        generated_locals: set[str] = set()
        for _ in range(count):
            while True:
                first = secrets.choice(ALIAS_FIRST_NAMES)
                last = secrets.choice(ALIAS_LAST_NAMES)
                short_number = str(10 + secrets.randbelow(90))
                long_number = str(100 + secrets.randbelow(9900))
                year = str(1980 + secrets.randbelow(27))
                human_local = secrets.choice(
                    (
                        f"{first}.{last}{short_number}",
                        f"{first}{last}{long_number}",
                        f"{first[0]}{last}{short_number}",
                        f"{last}.{first}{short_number}",
                        f"{first}{last[0]}{year}",
                        f"{first}.{last}{year}",
                    )
                )
                alias_local = f"{base}.{human_local}" if base else human_local
                if alias_local not in generated_locals:
                    generated_locals.add(alias_local)
                    break
            if alias_domains:
                selected_domain = secrets.choice(alias_domains)
            elif random_domains:
                selected_domain = secrets.choice(random_domains)
            else:
                selected_domain = account_domain
            address = f"{alias_local}@{selected_domain}"
            routes.append(self.add_alias(account, address, verify_visible=False, validate=False))
        return routes

    def fetch_code(
        self,
        account: Account,
        route: Address,
        *,
        sender: str = "",
        since: float | None = None,
        max_age: int = 600,
    ) -> dict[str, Any] | None:
        with self.account_lock(account.id):
            client = self.client_for(account)
            try:
                messages = client.query_messages(route.address, amount=20)
                now = time.time()
                for message in messages[:10]:
                    message_time = message.date_ms / 1000 if message.date_ms > 10_000_000_000 else float(message.date_ms)
                    if since is not None and message_time and message_time < since:
                        continue
                    if max_age > 0 and message_time and message_time < now - max_age:
                        continue
                    if sender and sender.lower() not in message.sender.lower():
                        continue
                    body = client.get_body(message.mail_id)
                    code = extract_code(message.subject, body)
                    if code:
                        self.store.update_session(account.id, client.export_state(), status="ready")
                        return {
                            "email": route.address,
                            "code": code,
                            "mail": {
                                "id": message.mail_id,
                                "date": datetime.fromtimestamp(message_time, tz=timezone.utc).isoformat()
                                if message_time
                                else None,
                                "sender": message.sender,
                                "subject": message.subject,
                            },
                        }
                self.store.update_session(account.id, client.export_state(), status="ready")
                return None
            except MailComError as exc:
                self.store.update_status(account.id, exc.kind, str(exc))
                raise


class MailCodeHandler(BaseHTTPRequestHandler):
    server_version = "MailComCodeAPI/1.0"

    @property
    def app(self) -> MailCodeApplication:
        return self.server.application  # type: ignore[attr-defined]

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self.static_response(WEB_DIR / "index.html")
            return
        if parsed.path in {"/app.js", "/styles.css"}:
            self.static_response(WEB_DIR / parsed.path.lstrip("/"))
            return
        if parsed.path == "/health":
            stats = self.app.proxy_pool_stats()
            self.json_response(
                200,
                {
                    "ok": True,
                    "service": "mail-com-code-api",
                    "proxy_pool": {
                        "enabled": bool(self.app.proxy_pool),
                        "total": stats["total"],
                        "assigned": stats["assigned"],
                        "remaining": stats["remaining"],
                    },
                },
            )
            return
        if parsed.path == "/admin/accounts":
            if not self.require_admin():
                return
            try:
                page, page_size = parse_pagination(parsed.query)
            except ValueError as exc:
                self.json_response(400, {"error": "invalid_request", "detail": str(exc)})
                return
            account_params = parse_qs(parsed.query)
            query = str((account_params.get("q") or [""])[0]).strip()[:254]
            accounts, total = self.app.store.list_accounts_page(page, page_size, query)
            self.json_response(
                200,
                {
                    "accounts": accounts,
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total,
                        "total_pages": max(1, (total + page_size - 1) // page_size),
                    },
                    "query": query,
                },
            )
            return
        if parsed.path == "/admin/addresses":
            if not self.require_admin():
                return
            try:
                page, page_size = parse_pagination(parsed.query)
            except ValueError as exc:
                self.json_response(400, {"error": "invalid_request", "detail": str(exc)})
                return
            addresses, total = self.app.store.list_addresses_page(page, page_size)
            self.json_response(
                200,
                {
                    "addresses": addresses,
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total,
                        "total_pages": max(1, (total + page_size - 1) // page_size),
                    },
                },
            )
            return
        if parsed.path == "/admin/proxy-pool":
            if not self.require_admin():
                return
            self.json_response(
                200,
                {
                    "proxy_pool": self.app.proxy_pool_stats(),
                    "file": str(self.app.proxy_pool_file) if self.app.proxy_pool_file else None,
                },
            )
            return
        if parsed.path == "/admin/export":
            if not self.require_admin():
                return
            self.text_response(200, self.app.store.export_text())
            return
        if parsed.path.startswith("/code/"):
            self.handle_code(parsed)
            return
        self.json_response(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/auth/login":
            try:
                self.handle_public_login(self.read_payload())
            except ValueError as exc:
                self.json_response(400, {"error": "invalid_request", "detail": str(exc)})
            return
        if parsed.path == "/query":
            try:
                self.handle_public_query(self.read_payload())
            except ValueError as exc:
                self.json_response(400, {"error": "invalid_request", "detail": str(exc)})
            except MailComError as exc:
                self.json_response(exc.status, {"error": exc.kind, "detail": str(exc)})
            return
        if parsed.path == "/proxy-pool":
            if not self.require_admin():
                return
            try:
                self.handle_proxy_pool(self.read_payload())
            except ValueError as exc:
                self.json_response(400, {"error": "invalid_request", "detail": str(exc)})
            return
        if parsed.path in {"/aliases/split", "/admin/aliases/split"}:
            if parsed.path.startswith("/admin/") and not self.require_admin():
                return
            payload = None
            try:
                payload = self.read_payload()
                self.handle_public_split(payload)
            except ValueError as exc:
                email = ""
                count = None
                domain = None
                random_domain_tlds = None
                if isinstance(payload, dict):
                    email = str(payload.get("email") or "").strip().lower()
                    count = payload.get("count", 1)
                    domain = payload.get("domain") or None
                    raw_tlds = payload.get("random_domain_tlds", payload.get("random_tlds", []))
                    random_domain_tlds = raw_tlds if raw_tlds else None
                log_api_event(
                    "split_invalid",
                    method=self.command,
                    path=parsed.path,
                    email=email,
                    count=count,
                    domain=domain,
                    random_domain_tlds=random_domain_tlds,
                    status=400,
                    error="invalid_request",
                    detail=str(exc),
                )
                self.json_response(400, {"error": "invalid_request", "detail": str(exc)})
            except MailComError as exc:
                email = ""
                count = None
                domain = None
                random_domain_tlds = None
                if isinstance(payload, dict):
                    email = str(payload.get("email") or "").strip().lower()
                    try:
                        count = int(payload.get("count", 1))
                    except (TypeError, ValueError):
                        count = payload.get("count")
                    domain = payload.get("domain") or None
                    random_domain_tlds = parse_random_domain_tlds(payload)
                log_api_event(
                    "split_failed",
                    method=self.command,
                    path=parsed.path,
                    email=email,
                    count=count,
                    domain=domain,
                    random_domain_tlds=random_domain_tlds,
                    status=exc.status,
                    error=exc.kind,
                    detail=str(exc),
                )
                self.json_response(exc.status, {"error": exc.kind, "detail": str(exc)})
            return
        if not parsed.path.startswith("/admin/"):
            self.json_response(404, {"error": "not_found"})
            return
        if not self.require_admin():
            return
        try:
            payload = self.read_payload()
            if parsed.path == "/admin/import":
                self.handle_import(parsed, payload)
            elif parsed.path == "/admin/check":
                self.handle_check(payload)
            elif parsed.path == "/admin/aliases":
                self.handle_alias(payload)
            elif parsed.path == "/admin/aliases/sync":
                self.handle_alias_sync(payload)
            elif parsed.path == "/admin/proxy-pool":
                self.handle_proxy_pool(payload)
            elif parsed.path == "/admin/query":
                self.handle_query(payload)
            else:
                self.json_response(404, {"error": "not_found"})
        except ValueError as exc:
            self.json_response(400, {"error": "invalid_request", "detail": str(exc)})
        except MailComError as exc:
            self.json_response(exc.status, {"error": exc.kind, "detail": str(exc)})
        except Exception:
            self.json_response(500, {"error": "internal_error"})

    def handle_public_login(self, payload: Any) -> None:
        if not isinstance(payload, dict):
            raise ValueError("需要 JSON 对象")
        email = str(payload.get("email") or "").strip().lower()
        password = str(payload.get("password") or "")
        if not EMAIL_RE.match(email) or not password:
            self.json_response(401, {"error": "invalid_credentials"})
            return
        account = self.app.store.get_account_by_email(email)
        if not account or not hmac.compare_digest(account.password, password):
            self.json_response(401, {"error": "invalid_credentials"})
            return
        routes = self.app.store.list_addresses_for_account(account.id)
        self.json_response(
            200,
            {
                "email": account.email,
                "routes": [
                    {
                        "address": route.address,
                        "url": self.app.store.code_url(route.access_key),
                    }
                    for route in routes
                ],
            },
        )

    def handle_public_query(self, payload: Any) -> None:
        if not isinstance(payload, dict):
            raise ValueError("需要 JSON 对象")
        email = str(payload.get("email") or "").strip().lower()
        password = str(payload.get("password") or "")
        account = self.app.store.get_account_by_email(email)
        if not account or not password or not hmac.compare_digest(account.password, password):
            self.json_response(401, {"error": "invalid_credentials"})
            return
        requested = parse_email_list(payload)
        allowed: list[str] = []
        for address in requested:
            found = self.app.store.get_by_address(address)
            if found and found[0].id == account.id:
                allowed.append(address)
        if not allowed:
            self.json_response(403, {"error": "mailbox_not_owned"})
            return
        self.handle_query({"emails": allowed, "max_age": payload.get("max_age", 600)})

    def handle_public_split(self, payload: Any) -> None:
        if not isinstance(payload, dict):
            raise ValueError("需要 JSON 对象")
        email = str(payload.get("email") or "").strip().lower()
        password = str(payload.get("password") or "")
        prefix = str(payload.get("prefix") or "").strip().lower() or None
        domain = payload.get("domain")
        random_domain_tlds = parse_random_domain_tlds(payload)
        try:
            count = int(payload.get("count", 1))
        except (TypeError, ValueError) as exc:
            raise ValueError("count 必须是 1-9") from exc
        if count < 1 or count > MAX_SPLIT_ALIASES:
            raise ValueError("count 必须是 1-9")
        account = self.app.store.get_account_by_email(email)
        if not account or not password or not hmac.compare_digest(account.password, password):
            self.json_response(401, {"error": "invalid_credentials"})
            return
        routes = self.app.split_aliases(
            account,
            count,
            prefix=prefix,
            domain=domain,
            random_domain_tlds=random_domain_tlds,
        )
        self.json_response(
            201,
            {
                "email": account.email,
                "prefix": prefix or None,
                "domain": parse_split_domains(domain) or None,
                "random_domain_tlds": random_domain_tlds,
                "created": len(routes),
                "routes": [
                    {"address": route.address, "url": self.app.store.code_url(route.access_key)}
                    for route in routes
                ],
            },
        )

    def handle_import(self, parsed, payload: Any) -> None:
        params = parse_qs(parsed.query)
        verify = (params.get("verify") or ["false"])[0].lower() in {"1", "true", "yes"}
        sync_aliases = (params.get("sync_aliases") or ["false"])[0].lower() in {"1", "true", "yes"}
        use_proxy_pool = (params.get("use_proxy") or ["false"])[0].lower() in {"1", "true", "yes"}
        credentials = parse_account_rows(payload)
        for email, password, _proxy in credentials:
            existing = self.app.store.get_account_by_email(email)
            if existing and not hmac.compare_digest(existing.password, password):
                self.json_response(401, {"error": "invalid_credentials", "email": email})
                return
        results = []
        for email, password, proxy_url in credentials:
            try:
                route, account = self.app.import_account(
                    email,
                    password,
                    proxy_url,
                    use_proxy_pool=use_proxy_pool,
                )
            except ValueError as exc:
                if str(exc) in {
                    "proxy_binding_exists",
                    "proxy_already_assigned",
                    "proxy_pool_exhausted",
                }:
                    detail = {
                        "proxy_binding_exists": "账号已有固定代理绑定，未覆盖",
                        "proxy_already_assigned": "该代理已绑定到其他账号",
                        "proxy_pool_exhausted": "固定代理池已用完，没有重复或循环分配",
                    }[str(exc)]
                    self.json_response(
                        409,
                        {
                            "error": str(exc),
                            "email": email,
                            "detail": detail,
                        },
                    )
                    return
                raise
            item: dict[str, Any] = {
                "email": email,
                "url": self.app.store.code_url(route.access_key),
                "saved": True,
                "proxy_bound": bool(account and account.proxy_url),
            }
            if verify:
                item["verification"] = self.app.check_account(account, sync_aliases=sync_aliases)  # type: ignore[arg-type]
            results.append(item)
        self.json_response(
            200,
            {
                "imported": len(results),
                "results": results,
                "lines": [f"{item['email']}----{item['url']}" for item in results],
                "text": "\n".join(f"{item['email']}----{item['url']}" for item in results),
                "export_file": str(self.app.store.export_path),
                "proxy_pool": self.app.proxy_pool_stats(),
            },
        )

    def handle_check(self, payload: Any) -> None:
        if not isinstance(payload, dict):
            raise ValueError("JSON 对象中需要 account 字段")
        account = self.find_account(payload.get("account"))
        result = self.app.check_account(account, sync_aliases=bool(payload.get("sync_aliases")))
        self.json_response(200 if result["ok"] else 502, result)

    def handle_alias(self, payload: Any) -> None:
        if not isinstance(payload, dict):
            raise ValueError("JSON 对象中需要 account 和 address/addresses 字段")
        account = self.find_account(payload.get("account"))
        if payload.get("addresses") not in (None, "", []):
            addresses = parse_email_list(payload.get("addresses"))
        else:
            addresses = parse_email_list([str(payload.get("address") or "")])
        routes = self.app.add_aliases(account, addresses)
        first = routes[0]
        self.json_response(
            201,
            {
                "account": account.email,
                "created": len(routes),
                "address": first.address,
                "url": self.app.store.code_url(first.access_key),
                "addresses": [
                    {"address": route.address, "url": self.app.store.code_url(route.access_key)}
                    for route in routes
                ],
            },
        )

    def handle_alias_sync(self, payload: Any) -> None:
        if not isinstance(payload, dict):
            raise ValueError("JSON 对象中需要 account 字段")
        account = self.find_account(payload.get("account"))
        routes = self.app.sync_aliases(account)
        self.json_response(
            200,
            {
                "account": account.email,
                "addresses": [
                    {"address": row.address, "url": self.app.store.code_url(row.access_key)} for row in routes
                ],
            },
        )

    def handle_proxy_pool(self, payload: Any) -> None:
        proxies = parse_proxy_pool_text(payload)
        stats = self.app.add_proxy_pool(proxies)
        self.json_response(
            200,
            {
                "added": len(proxies),
                "proxy_pool": stats,
                "file": str(self.app.proxy_pool_file) if self.app.proxy_pool_file else None,
            },
        )

    def handle_query(self, payload: Any) -> None:
        emails = parse_email_list(payload)
        max_age = 600
        if isinstance(payload, dict):
            try:
                max_age = max(0, min(int(payload.get("max_age", 600)), 86400))
            except (TypeError, ValueError) as exc:
                raise ValueError("max_age 必须是数字") from exc
        results = []
        for email in emails:
            found = self.app.store.get_by_address(email)
            if not found:
                results.append({"email": email, "code": None, "error": "unknown_mailbox"})
                continue
            account, route = found
            try:
                result = self.app.fetch_code(account, route, max_age=max_age)
                results.append(result or {"email": email, "code": None, "mail": None})
            except MailComError as exc:
                results.append({"email": email, "code": None, "error": exc.kind})
        self.json_response(200, {"count": len(results), "results": results})

    def handle_code(self, parsed) -> None:
        key = parsed.path.removeprefix("/code/").strip("/")
        if not key or not self.app.rate_limiter.allow(key):
            self.json_response(429 if key else 404, {"error": "rate_limited" if key else "not_found"})
            return
        found = self.app.store.get_by_key(key)
        if not found:
            self.json_response(404, {"error": "unknown_mailbox"})
            return
        account, route = found
        params = parse_qs(parsed.query)
        try:
            wait_seconds = max(0, min(int((params.get("wait") or ["0"])[0]), 60))
            max_age = max(0, min(int((params.get("max_age") or ["600"])[0]), 86400))
            since = parse_timestamp((params.get("since") or [""])[0])
        except ValueError as exc:
            self.json_response(400, {"error": "invalid_query", "detail": str(exc)})
            return
        sender = (params.get("sender") or [""])[0]
        deadline = time.monotonic() + wait_seconds
        try:
            while True:
                result = self.app.fetch_code(
                    account, route, sender=sender, since=since, max_age=max_age
                )
                if result:
                    self.json_response(200, result)
                    return
                if time.monotonic() >= deadline:
                    self.json_response(200, {"email": route.address, "code": None, "mail": None})
                    return
                time.sleep(min(5, max(0.1, deadline - time.monotonic())))
        except MailComError as exc:
            self.json_response(exc.status, {"email": route.address, "code": None, "error": exc.kind})

    def find_account(self, value: Any) -> Account:
        text = str(value or "").strip()
        account = self.app.store.get_account(int(text)) if text.isdigit() else self.app.store.get_account_by_email(text)
        if not account:
            raise ValueError("账号不存在")
        return account

    def read_payload(self) -> Any:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Content-Length 无效") from exc
        if length <= 0 or length > MAX_REQUEST_BODY:
            raise ValueError("请求体为空或超过 2 MiB")
        raw = self.rfile.read(length).decode("utf-8-sig")
        if "application/json" in self.headers.get("Content-Type", ""):
            try:
                return json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError("JSON 格式无效") from exc
        return raw

    def require_admin(self) -> bool:
        if os.environ.get("MAIL_API_REQUIRE_ADMIN_TOKEN", "true").strip().lower() in {
            "0",
            "false",
            "no",
            "off",
        }:
            return True
        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {self.app.admin_token}"
        if not hmac.compare_digest(supplied, expected):
            self.json_response(401, {"error": "unauthorized"})
            return False
        return True

    def json_response(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def text_response(self, status: int, body_text: str) -> None:
        body = body_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="mail-code-api.txt"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def static_response(self, path: Path) -> None:
        try:
            resolved = path.resolve()
            if WEB_DIR.resolve() not in resolved.parents or not resolved.is_file():
                self.json_response(404, {"error": "not_found"})
                return
            body = resolved.read_bytes()
        except OSError:
            self.json_response(404, {"error": "not_found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", WEB_TYPES.get(resolved.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        # Paths contain access capabilities, so only log method and status.
        status = args[1] if len(args) > 1 else "-"
        print(f"mail-code-api method={self.command} status={status}", file=sys.stderr)


def load_or_create_admin_token(data_dir: Path) -> str:
    configured = os.environ.get("MAIL_API_ADMIN_TOKEN", "").strip()
    if configured:
        return configured
    path = data_dir / "admin.token"
    if path.exists():
        return path.read_text(encoding="ascii").strip()
    token = secrets.token_urlsafe(36)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token + "\n", encoding="ascii")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return token


def build_server(args: argparse.Namespace) -> ThreadingHTTPServer:
    data_dir = Path(args.data_dir).resolve()
    admin_token = load_or_create_admin_token(data_dir)
    store = Store(data_dir, args.public_base)
    proxy_pool_file = Path(args.proxy_pool_file).expanduser().resolve() if args.proxy_pool_file else data_dir / "proxy-pool.txt"
    proxy_pool = load_proxy_pool(proxy_pool_file) if proxy_pool_file.is_file() else []
    application = MailCodeApplication(
        store,
        admin_token,
        timeout=args.upstream_timeout,
        rate_limit=args.rate_limit,
        proxy_pool=proxy_pool,
        proxy_pool_file=proxy_pool_file,
    )
    server = ThreadingHTTPServer((args.bind, args.port), MailCodeHandler)
    server.daemon_threads = True
    server.application = application  # type: ignore[attr-defined]
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description="mail.com 邮箱接码 API")
    parser.add_argument("--bind", default=os.environ.get("MAIL_API_BIND", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MAIL_API_PORT", "8788")))
    parser.add_argument("--public-base", default=os.environ.get("MAIL_API_PUBLIC_BASE", "http://127.0.0.1:8788"))
    parser.add_argument("--data-dir", default=os.environ.get("MAIL_API_DATA_DIR", "./data"))
    parser.add_argument("--upstream-timeout", type=float, default=float(os.environ.get("MAIL_API_UPSTREAM_TIMEOUT", "25")))
    parser.add_argument("--rate-limit", type=int, default=int(os.environ.get("MAIL_API_RATE_LIMIT", "30")))
    parser.add_argument("--proxy-pool-file", default=os.environ.get("MAIL_API_PROXY_POOL_FILE", ""))
    args = parser.parse_args()
    server = build_server(args)
    data_dir = Path(args.data_dir).resolve()
    print(f"mail.com 接码 API 正在监听 http://{args.bind}:{args.port}", file=sys.stderr)
    print(f"管理员令牌文件: {data_dir / 'admin.token'}", file=sys.stderr)
    print(f"地址导出文件: {data_dir / '邮箱----接码API.txt'}", file=sys.stderr)
    if server.application.proxy_pool:  # type: ignore[attr-defined]
        stats = server.application.proxy_pool_stats()  # type: ignore[attr-defined]
        print(
            f"固定代理池: total={stats['total']} assigned={stats['assigned']} remaining={stats['remaining']}",
            file=sys.stderr,
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
