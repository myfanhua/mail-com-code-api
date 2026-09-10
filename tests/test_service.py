from __future__ import annotations

import io
import json
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from code_extract import extract_code  # noqa: E402
from mailcom_client import MailComClient, MailComError  # noqa: E402
from server import (
    MailCodeApplication,
    MailCodeHandler,
    load_proxy_pool,
    log_api_event,
    normalize_mailcom_domain,
    parse_split_domains,
    parse_random_domain_tlds,
    normalize_domain,
    normalize_proxy_url,
    parse_proxy_pool_text,
    parse_account_rows,
    parse_credentials,
    parse_email_list,
    parse_pagination,
    parse_timestamp,
)  # noqa: E402
from storage import Address, Store  # noqa: E402


class ParsingTests(unittest.TestCase):
    def test_import_text_and_deduplicate(self):
        rows = parse_credentials("A@mail.com----first\na@mail.com----second\nb@mail.com\tpass")
        self.assertEqual(rows, [("a@mail.com", "second"), ("b@mail.com", "pass")])

    def test_import_json(self):
        rows = parse_credentials({"accounts": [{"email": "a@mail.com", "password": "p"}]})
        self.assertEqual(rows, [("a@mail.com", "p")])

    def test_bad_import_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "格式无效"):
            parse_credentials("not-an-email----password")

    def test_proxy_is_parsed_but_credential_parser_stays_compatible(self):
        rows = parse_account_rows(
            "a@mail.com----secret----gate.example:1000:proxy-user:proxy-pass"
        )
        self.assertEqual(rows[0][0:2], ("a@mail.com", "secret"))
        self.assertEqual(
            rows[0][2], "http://proxy-user:proxy-pass@gate.example:1000"
        )
        self.assertEqual(
            parse_credentials("a@mail.com----secret----http://host:80"),
            [("a@mail.com", "secret")],
        )

    def test_invalid_proxy_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "proxy"):
            normalize_proxy_url("not-a-proxy")

    def test_proxy_pool_text_is_parsed_and_deduplicated(self):
        proxies = parse_proxy_pool_text(
            "http://user:pass@gate1.example:1000\n"
            "# comment\n"
            "gate2.example:2000:user2:pass2\n"
            "http://user:pass@gate1.example:1000\n"
        )
        self.assertEqual(
            proxies,
            [
                "http://user:pass@gate1.example:1000",
                "http://user2:pass2@gate2.example:2000",
            ],
        )

    def test_domain_is_normalized(self):
        self.assertEqual(normalize_domain("Engineer.COM"), "engineer.com")
        self.assertEqual(normalize_domain("@comic.com"), "comic.com")
        self.assertEqual(normalize_domain("x@blader.com"), "blader.com")
        self.assertEqual(normalize_domain("https://engineer.com"), "engineer.com")
        self.assertEqual(normalize_domain("[engineer](https://engineer.com)"), "engineer.com")
        with self.assertRaisesRegex(ValueError, "domain"):
            normalize_domain("not a domain")

    def test_mailcom_domain_must_be_known(self):
        self.assertEqual(normalize_mailcom_domain("Engineer.COM"), "engineer.com")
        self.assertEqual(normalize_mailcom_domain("groupmail.com"), "groupmail.com")
        self.assertEqual(normalize_mailcom_domain("null.net"), "null.net")
        self.assertEqual(normalize_mailcom_domain("solution4u.com"), "solution4u.com")
        self.assertEqual(normalize_mailcom_domain("bellair.net"), "bellair.net")
        self.assertEqual(normalize_mailcom_domain("computer4u.com"), "computer4u.com")
        self.assertEqual(normalize_mailcom_domain("presidency.com"), "presidency.com")
        self.assertEqual(normalize_mailcom_domain("housemail.com"), "housemail.com")
        with self.assertRaisesRegex(ValueError, "不是 mail.com 支持"):
            normalize_mailcom_domain("blader.com")

    def test_split_domains_are_parsed_and_deduplicated(self):
        self.assertEqual(
            parse_split_domains(
                "Engineer.COM, groupmail.com\nhttps://null.net\nsolution4u.com\nbellair.net\ncomputer4u.com\npresidency.com\nhousemail.com"
            ),
            [
                "engineer.com",
                "groupmail.com",
                "null.net",
                "solution4u.com",
                "bellair.net",
                "computer4u.com",
                "presidency.com",
                "housemail.com",
            ],
        )
        self.assertEqual(parse_split_domains(""), [])

    def test_split_domains_accept_valid_domains_not_in_static_whitelist(self):
        self.assertEqual(parse_split_domains("future-mail-alias.example"), ["future-mail-alias.example"])


    def test_random_domain_tlds_are_parsed(self):
        self.assertEqual(parse_random_domain_tlds({"random_domain_tlds": ["com", ".net", "com"]}), ["com", "net"])
        self.assertEqual(parse_random_domain_tlds({"random_com": True}), ["com"])
        self.assertEqual(parse_random_domain_tlds({"random_net": True}), ["net"])
        with self.assertRaisesRegex(ValueError, "随机域名"):
            parse_random_domain_tlds({"random_domain_tlds": ["org"]})

    def test_api_event_log_is_structured(self):
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            log_api_event(
                "split_failed",
                method="POST",
                path="/aliases/split",
                email="user@mail.com",
                status=409,
                error="alias_limit",
                detail="添加邮箱地址失败 (HTTP 409)",
            )
        line = buffer.getvalue().strip()
        self.assertTrue(line.startswith("mail-code-api "))
        payload = json.loads(line.removeprefix("mail-code-api "))
        self.assertEqual(payload["event"], "split_failed")
        self.assertEqual(payload["email"], "user@mail.com")
        self.assertEqual(payload["error"], "alias_limit")

    def test_batch_email_query_input(self):
        self.assertEqual(
            parse_email_list({"text": "A@mail.com\nb@mail.com,a@mail.com"}),
            ["a@mail.com", "b@mail.com"],
        )

    def test_timestamp_seconds_milliseconds_and_iso(self):
        self.assertEqual(parse_timestamp("1786871000"), 1786871000)
        self.assertEqual(parse_timestamp("1786871000000"), 1786871000)
        self.assertEqual(parse_timestamp("2026-08-16T00:00:00Z"), 1786838400)

    def test_pagination_is_parsed_and_capped(self):
        self.assertEqual(parse_pagination("page=2&page_size=50"), (2, 50))
        self.assertEqual(parse_pagination("page=0&page_size=999"), (1, 100))
        with self.assertRaisesRegex(ValueError, "page"):
            parse_pagination("page=bad")


class CodeExtractionTests(unittest.TestCase):
    def test_context_code_wins(self):
        self.assertEqual(extract_code("Invoice 202608", "Your verification code is 123456"), "123456")

    def test_ambiguous_generic_digits_are_rejected(self):
        self.assertIsNone(extract_code("Message 1234", "Reference 5678"))

    def test_reverse_context(self):
        self.assertEqual(extract_code("654321 is your login code", ""), "654321")


class TokenTests(unittest.TestCase):
    def test_mailcom_millisecond_expiry(self):
        header = "e30"
        payload = "eyJleHAiOjE3ODY4NzgyNTczNjN9"  # {"exp":1786878257363}
        token = f"{header}.{payload}.x"
        self.assertEqual(MailComClient.token_expiry(token), 1786878257.363)

    def test_mail_token_relogs_once_after_oauth_failure(self):
        test_case = self

        class FlakyOAuthClient(MailComClient):
            def __init__(self):
                super().__init__("user@mail.com", "secret")
                self.sid = "stale"
                self.tokens = {"old": "token"}
                self.login_calls = 0
                self.token_calls = 0

            def login(self, retries: int = 3) -> None:
                self.login_calls += 1
                self.sid = "fresh"

            def get_token(self, scope: str, client_id: str, *, force: bool = False) -> str:
                self.token_calls += 1
                if self.token_calls == 1:
                    raise MailComError("token 请求失败 (HTTP 400)", kind="oauth_failed")
                test_case.assertTrue(force)
                test_case.assertEqual(self.sid, "fresh")
                return "fresh-token"

        client = FlakyOAuthClient()

        self.assertEqual(client.ensure_mail_token(), "fresh-token")
        self.assertEqual(client.login_calls, 1)


class StorageTests(unittest.TestCase):
    def test_credentials_are_encrypted_and_export_format_is_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            route = store.upsert_account("User@mail.com", "plain-secret")
            raw = store.db_path.read_bytes()
            self.assertNotIn(b"plain-secret", raw)
            account = store.get_account(route.account_id)
            self.assertEqual(account.password, "plain-secret")
            line = store.export_text().strip()
            self.assertTrue(line.startswith("user@mail.com----https://codes.example/code/"))
            self.assertEqual(len(store.list_accounts()), 1)
            found = store.get_by_address("USER@MAIL.COM")
            self.assertEqual(found[1].access_key, route.access_key)

    def test_session_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            route = store.upsert_account("user@mail.com", "secret")
            store.update_session(route.account_id, {"sid": "private", "tokens": {"x": "y"}})
            account = store.get_account(route.account_id)
            self.assertEqual(account.session["sid"], "private")
            self.assertNotIn(b"private", store.db_path.read_bytes())

    def test_sql_pagination_for_accounts_and_addresses(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            first = store.upsert_account("first@mail.com", "first-secret")
            store.add_address(first.account_id, "first-child@engineer.com")
            store.upsert_account("second@mail.com", "second-secret")

            accounts, account_total = store.list_accounts_page(1, 1)
            self.assertEqual(account_total, 2)
            self.assertEqual(len(accounts), 1)
            self.assertEqual(accounts[0]["email"], "second@mail.com")
            self.assertEqual(accounts[0]["password"], "second-secret")

            filtered, filtered_total = store.list_accounts_page(
                1, 10, "first-child@engineer.com"
            )
            self.assertEqual(filtered_total, 1)
            self.assertEqual(filtered[0]["email"], "first@mail.com")
            filtered, filtered_total = store.list_accounts_page(1, 10, "SECOND@MAIL.COM")
            self.assertEqual(filtered_total, 1)
            self.assertEqual(filtered[0]["email"], "second@mail.com")

            addresses, address_total = store.list_addresses_page(1, 2)
            self.assertEqual(address_total, 3)
            self.assertEqual(len(addresses), 2)
            self.assertNotIn("password", addresses[0])
            self.assertIn(addresses[0]["email_type"], {"母号", "子号"})

    def test_proxy_binding_is_encrypted_and_immutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            proxy = "http://proxy-user:proxy-pass@gate.example:1000"
            route = store.upsert_account("user@mail.com", "secret", proxy)
            account = store.get_account(route.account_id)
            self.assertEqual(account.proxy_url, proxy)
            raw = store.db_path.read_bytes()
            self.assertNotIn(b"proxy-user", raw)
            self.assertNotIn(b"proxy-pass", raw)
            self.assertTrue(store.list_accounts()[0]["proxy_bound"])
            self.assertNotIn("proxy", store.list_accounts()[0])
            store.upsert_account("user@mail.com", "secret", proxy)
            with self.assertRaisesRegex(ValueError, "proxy_binding_exists"):
                store.upsert_account(
                    "user@mail.com", "secret", "http://other.example:1000"
                )


class ProxyClientTests(unittest.TestCase):
    def test_client_uses_account_proxy_for_all_requests(self):
        client = MailComClient(
            "user@mail.com",
            "secret",
            proxy_url="http://user:pass@gate.example:1000",
        )
        self.assertFalse(client.session.trust_env)
        self.assertEqual(
            client.session.proxies["http"], "http://user:pass@gate.example:1000"
        )
        self.assertEqual(
            client.session.proxies["https"], "http://user:pass@gate.example:1000"
        )


class ProxyPoolTests(unittest.TestCase):
    def test_pool_loads_compact_entries_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxies.txt"
            path.write_text(
                "gate1.example:1000:user-1:pass-1\n"
                "gate1.example:1000:user-1:pass-1\n"
                "gate2.example:1000:user-2:pass-2\n",
                encoding="utf-8",
            )
            self.assertEqual(
                load_proxy_pool(str(path)),
                [
                    "http://user-1:pass-1@gate1.example:1000",
                    "http://user-2:pass-2@gate2.example:1000",
                ],
            )

    def test_pool_assigns_once_persists_and_never_wraps(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = MailCodeApplication(
                store,
                "admin-token",
                proxy_pool=[
                    "http://user-1:pass-1@gate1.example:1000",
                    "http://user-2:pass-2@gate2.example:1000",
                ],
            )
            _, first = app.import_account("first@mail.com", "secret-1", use_proxy_pool=True)
            _, second = app.import_account("second@mail.com", "secret-2", use_proxy_pool=True)
            self.assertNotEqual(first.proxy_url, second.proxy_url)
            _, first_again = app.import_account("first@mail.com", "secret-1", use_proxy_pool=True)
            self.assertEqual(first_again.proxy_url, first.proxy_url)
            with self.assertRaisesRegex(ValueError, "proxy_pool_exhausted"):
                app.import_account("third@mail.com", "secret-3", use_proxy_pool=True)
            self.assertEqual(
                app.proxy_pool_stats(), {"total": 2, "assigned": 2, "remaining": 0}
            )

    def test_import_account_does_not_bind_proxy_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = MailCodeApplication(
                store,
                "admin-token",
                proxy_pool=["http://user-1:pass-1@gate1.example:1000"],
            )

            _, account = app.import_account("first@mail.com", "secret-1")

            self.assertEqual(account.proxy_url, "")
            self.assertEqual(app.proxy_pool_stats(), {"total": 1, "assigned": 0, "remaining": 1})


class SplitAliasTests(unittest.TestCase):
    def test_split_aliases_caps_at_ten_total_addresses(self):
        class FakeSplitApplication(MailCodeApplication):
            def add_alias(self, account, address, *, verify_visible=True, validate=True):
                return self.store.add_address(account.id, address)

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = FakeSplitApplication(store, "admin-token")
            route = store.upsert_account("longusername@mail.com", "secret")
            account = store.get_account(route.account_id)

            routes = app.split_aliases(account, 10)

            self.assertEqual(len(routes), 9)
            self.assertTrue(all(isinstance(route, Address) for route in routes))
            self.assertEqual(len({route.address for route in routes}), 9)
            self.assertTrue(all("-split-" not in route.address for route in routes))
            self.assertTrue(all(not route.address.startswith("longusername") for route in routes))

    def test_split_aliases_rejects_full_account(self):
        class FakeSplitApplication(MailCodeApplication):
            def add_alias(self, account, address, *, verify_visible=True, validate=True):
                return self.store.add_address(account.id, address)

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = FakeSplitApplication(store, "admin-token")
            route = store.upsert_account("longusername@mail.com", "secret")
            account = store.get_account(route.account_id)
            for index in range(9):
                store.add_address(account.id, f"alias-{index}@mail.com")

            with self.assertRaisesRegex(MailComError, "上限"):
                app.split_aliases(account, 1)

    def test_split_aliases_uses_custom_prefix(self):
        class FakeSplitApplication(MailCodeApplication):
            def add_alias(self, account, address, *, verify_visible=True, validate=True):
                return self.store.add_address(account.id, address)

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = FakeSplitApplication(store, "admin-token")
            route = store.upsert_account("longusername@mail.com", "secret")
            account = store.get_account(route.account_id)

            routes = app.split_aliases(account, 2, prefix="blader.com")

            self.assertEqual(len(routes), 2)
            self.assertTrue(all(route.address.startswith("blader.com") for route in routes))
            self.assertTrue(all("-split-" not in route.address for route in routes))

    def test_split_aliases_uses_custom_domain(self):
        class FakeSplitApplication(MailCodeApplication):
            def add_alias(self, account, address, *, verify_visible=True, validate=True):
                return self.store.add_address(account.id, address)

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = FakeSplitApplication(store, "admin-token")
            route = store.upsert_account("longusername@mail.com", "secret")
            account = store.get_account(route.account_id)

            routes = app.split_aliases(account, 2, domain="engineer.com")

            self.assertEqual(len(routes), 2)
            self.assertTrue(all(route.address.endswith("@engineer.com") for route in routes))

    def test_split_aliases_uses_multiple_custom_domains(self):
        class FakeSplitApplication(MailCodeApplication):
            def add_alias(self, account, address, *, verify_visible=True, validate=True):
                return self.store.add_address(account.id, address)

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = FakeSplitApplication(store, "admin-token")
            route = store.upsert_account("longusername@mail.com", "secret")
            account = store.get_account(route.account_id)

            with mock.patch("server.secrets.choice", side_effect=lambda seq: seq[-1]):
                routes = app.split_aliases(account, 3, domain="engineer.com,comic.com")

            self.assertEqual(len(routes), 3)
            self.assertTrue(all(route.address.endswith("@comic.com") for route in routes))

    def test_split_aliases_uses_random_domain_tld(self):
        class FakeSplitApplication(MailCodeApplication):
            def list_alias_domains(self, account):
                return ["fresh-domain.net", "fresh-domain.com"]

            def add_alias(self, account, address, *, verify_visible=True, validate=True):
                return self.store.add_address(account.id, address)

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = FakeSplitApplication(store, "admin-token")
            route = store.upsert_account("longusername@clubmember.org", "secret")
            account = store.get_account(route.account_id)

            routes = app.split_aliases(account, 5, random_domain_tlds=["net"])

            self.assertEqual(len(routes), 5)
            self.assertTrue(all(route.address.endswith("@fresh-domain.net") for route in routes))

    def test_split_aliases_prefers_custom_domain_over_random_tlds(self):
        class FakeSplitApplication(MailCodeApplication):
            def list_alias_domains(self, account):
                raise AssertionError("custom domain should not fetch upstream domain list")

            def add_alias(self, account, address, *, verify_visible=True, validate=True):
                return self.store.add_address(account.id, address)

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = FakeSplitApplication(store, "admin-token")
            route = store.upsert_account("longusername@mail.com", "secret")
            account = store.get_account(route.account_id)

            routes = app.split_aliases(
                account,
                5,
                domain="engineer.com",
                random_domain_tlds=["net"],
            )

            self.assertEqual(len(routes), 5)
            self.assertTrue(all(route.address.endswith("@engineer.com") for route in routes))

    def test_split_aliases_avoids_visibility_rechecks(self):
        class FakeClient:
            def __init__(self):
                self.add_alias_calls = []
                self.list_aliases_calls = 0

            def add_alias(self, address, *, validate=True):
                self.add_alias_calls.append(address)

            def list_aliases(self):
                self.list_aliases_calls += 1
                return []

            def export_state(self):
                return {"sid": "fake"}

        class FakeSplitApplication(MailCodeApplication):
            def __init__(self, store, admin_token):
                super().__init__(store, admin_token)
                self.fake_client = FakeClient()

            def client_for(self, account):
                return self.fake_client

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = FakeSplitApplication(store, "admin-token")
            route = store.upsert_account("longusername@mail.com", "secret")
            account = store.get_account(route.account_id)

            routes = app.split_aliases(account, 10)

            self.assertEqual(len(routes), 9)
            self.assertEqual(len(app.fake_client.add_alias_calls), 9)
            self.assertEqual(app.fake_client.list_aliases_calls, 0)

    def test_split_aliases_skips_validation_requests(self):
        class FakeClient:
            def __init__(self):
                self.add_alias_calls = []
                self.validation_flags = []

            def add_alias(self, address, *, validate=True):
                self.add_alias_calls.append(address)
                self.validation_flags.append(validate)

            def list_aliases(self):
                return []

            def export_state(self):
                return {"sid": "fake"}

        class FakeSplitApplication(MailCodeApplication):
            def __init__(self, store, admin_token):
                super().__init__(store, admin_token)
                self.fake_client = FakeClient()

            def client_for(self, account):
                return self.fake_client

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = FakeSplitApplication(store, "admin-token")
            route = store.upsert_account("longusername@mail.com", "secret")
            account = store.get_account(route.account_id)

            routes = app.split_aliases(account, 3)

            self.assertEqual(len(routes), 3)
            self.assertEqual(app.fake_client.validation_flags, [False, False, False])


class AdminAliasTests(unittest.TestCase):
    def test_add_aliases_creates_multiple_addresses(self):
        class FakeAliasApplication(MailCodeApplication):
            def add_alias(self, account, address, *, verify_visible=True, validate=True):
                return self.store.add_address(account.id, address)

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = FakeAliasApplication(store, "admin-token")
            route = store.upsert_account("admin@mail.com", "secret")
            account = store.get_account(route.account_id)

            routes = app.add_aliases(account, ["a@engineer.com", "b@engineer.com"])

            self.assertEqual([route.address for route in routes], ["a@engineer.com", "b@engineer.com"])

    def test_handle_alias_accepts_multiple_addresses(self):
        class FakeAliasApplication(MailCodeApplication):
            def add_alias(self, account, address, *, verify_visible=True, validate=True):
                return self.store.add_address(account.id, address)

        class DummyHandler:
            def __init__(self, app, account):
                self.app = app
                self._account = account
                self.responses = []

            def find_account(self, _value):
                return self._account

            def json_response(self, status, payload):
                self.responses.append((status, payload))

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = FakeAliasApplication(store, "admin-token")
            route = store.upsert_account("admin@mail.com", "secret")
            account = store.get_account(route.account_id)
            handler = DummyHandler(app, account)

            MailCodeHandler.handle_alias(  # type: ignore[misc]
                handler,
                {"account": "admin@mail.com", "addresses": ["a@engineer.com", "b@engineer.com"]},
            )

            self.assertEqual(handler.responses[0][0], 201)
            payload = handler.responses[0][1]
            self.assertEqual(payload["created"], 2)
            self.assertEqual(
                [item["address"] for item in payload["addresses"]],
                ["a@engineer.com", "b@engineer.com"],
            )


class ProxyPoolTests(unittest.TestCase):
    def test_add_proxy_pool_persists_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            store = Store(data_dir, "https://codes.example")
            proxy_file = data_dir / "proxy-pool.txt"
            app = MailCodeApplication(store, "admin-token", proxy_pool_file=proxy_file)

            stats = app.add_proxy_pool(
                [
                    "http://user:pass@gate1.example:1000",
                    "http://user2:pass2@gate2.example:2000",
                    "http://user:pass@gate1.example:1000",
                ]
            )

            self.assertEqual(stats["total"], 2)
            self.assertEqual(proxy_file.read_text(encoding="utf-8").splitlines(), [
                "http://user:pass@gate1.example:1000",
                "http://user2:pass2@gate2.example:2000",
            ])

    def test_handle_proxy_pool_accepts_text(self):
        class DummyHandler:
            def __init__(self, app):
                self.app = app
                self.responses = []

            def json_response(self, status, payload):
                self.responses.append((status, payload))

        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            store = Store(data_dir, "https://codes.example")
            proxy_file = data_dir / "proxy-pool.txt"
            app = MailCodeApplication(store, "admin-token", proxy_pool_file=proxy_file)
            handler = DummyHandler(app)

            MailCodeHandler.handle_proxy_pool(  # type: ignore[misc]
                handler,
                "http://user:pass@gate1.example:1000\nhttp://user2:pass2@gate2.example:2000",
            )

            self.assertEqual(handler.responses[0][0], 200)
            self.assertEqual(handler.responses[0][1]["proxy_pool"]["total"], 2)

    def test_proxy_pool_post_requires_admin_token(self):
        class DummyHandler:
            def __init__(self, app):
                self.app = app
                self.path = "/proxy-pool"
                self.responses = []

            def read_payload(self):
                return "http://user:pass@gate1.example:1000\nhttp://user2:pass2@gate2.example:2000"

            def handle_proxy_pool(self, payload):
                return MailCodeHandler.handle_proxy_pool(self, payload)  # type: ignore[misc]

            def require_admin(self):
                self.json_response(401, {"error": "unauthorized"})
                return False

            def json_response(self, status, payload):
                self.responses.append((status, payload))

        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            store = Store(data_dir, "https://codes.example")
            proxy_file = data_dir / "proxy-pool.txt"
            app = MailCodeApplication(store, "admin-token", proxy_pool_file=proxy_file)
            handler = DummyHandler(app)

            MailCodeHandler.do_POST(handler)  # type: ignore[misc]

            self.assertEqual(handler.responses, [(401, {"error": "unauthorized"})])
            self.assertFalse(proxy_file.exists())


if __name__ == "__main__":
    unittest.main()
