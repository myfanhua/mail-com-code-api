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
from mailcom_client import MailComClient, MailComError, MailMessage  # noqa: E402
from server import (
    MailCodeApplication,
    MailCodeHandler,
    load_proxy_pool,
    log_api_event,
    message_matches_recipient,
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
    redact_log_text,
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

    def test_diagnostic_log_text_redacts_verification_codes(self):
        self.assertEqual(
            redact_log_text("Your verification code is 482913"),
            "Your verification code is [code]",
        )

    def test_batch_email_query_input(self):
        self.assertEqual(
            parse_email_list({"text": "A@mail.com\nb@mail.com,a@mail.com"}),
            ["a@mail.com", "b@mail.com"],
        )

    def test_recipient_matching_uses_complete_email_address(self):
        self.assertTrue(
            message_matches_recipient(
                ["Recipient Name <Child.One@Engineer.com>"],
                "child.one@engineer.com",
            )
        )
        self.assertFalse(
            message_matches_recipient(
                ["other-child@engineer.com"], "child@engineer.com"
            )
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

    def test_japanese_verification_code_wins_over_tracking_numbers(self):
        body = (
            "この一時検証コードを入力して続行してください: 482913 "
            "https://example.com/click/20260910/ref/778899"
        )
        self.assertEqual(extract_code("ChatGPT 用の一時ログインコード", body), "482913")


class TokenTests(unittest.TestCase):
    def test_mailcom_millisecond_expiry(self):
        header = "e30"
        payload = "eyJleHAiOjE3ODY4NzgyNTczNjN9"  # {"exp":1786878257363}
        token = f"{header}.{payload}.x"
        self.assertEqual(MailComClient.token_expiry(token), 1786878257.363)

    def test_mail_queries_use_a_fresh_cache_buster(self):
        client = MailComClient("user@mail.com", "secret")
        client.auth_id = "auth-id"
        with mock.patch("mailcom_client.time.time_ns", side_effect=[100, 101]):
            self.assertEqual(client._cache_buster(), "auth-id-100")
            self.assertEqual(client._cache_buster(), "auth-id-101")

    def test_unfiltered_mail_query_omits_delayed_search_condition(self):
        client = MailComClient("user@mail.com", "secret")
        client.ensure_mail_token = mock.Mock(return_value="mail-token")
        client.session.post = mock.Mock(
            return_value=mock.Mock(
                status_code=200,
                json=mock.Mock(return_value={"mailListElements": []}),
            )
        )

        client.query_messages("", amount=50)

        _args, kwargs = client.session.post.call_args
        self.assertNotIn("condition", kwargs["params"])
        self.assertEqual(kwargs["params"]["amount"], "50")

    def test_mail_token_relogs_once_after_session_failure(self):
        test_case = self

        class FlakyOAuthClient(MailComClient):
            def __init__(self):
                super().__init__("user@mail.com", "secret")
                self.sid = "stale"
                self.tokens = {"old": "token"}
                self.session.cookies.set("navigator", "stale-cookie")
                self.login_calls = 0
                self.token_calls = 0

            def login(self, retries: int = 3) -> None:
                self.login_calls += 1
                test_case.assertEqual(self.session.cookies.get_dict(), {})
                self.sid = "fresh"

            def get_token(self, scope: str, client_id: str, *, force: bool = False) -> str:
                self.token_calls += 1
                if self.token_calls == 1:
                    raise MailComError("会话失效", kind="session_expired")
                test_case.assertTrue(force)
                test_case.assertEqual(self.sid, "fresh")
                return "fresh-token"

        client = FlakyOAuthClient()

        self.assertEqual(client.ensure_mail_token(), "fresh-token")
        self.assertEqual(client.login_calls, 1)

    def test_mail_token_does_not_relogin_for_non_session_oauth_error(self):
        class BrokenOAuthClient(MailComClient):
            def __init__(self):
                super().__init__("user@mail.com", "secret")
                self.login_calls = 0

            def login(self, retries: int = 3) -> None:
                self.login_calls += 1

            def get_token(self, scope: str, client_id: str, *, force: bool = False) -> str:
                raise MailComError("wrong client", kind="oauth_failed")

        client = BrokenOAuthClient()
        with self.assertRaises(MailComError):
            client.ensure_mail_token()
        self.assertEqual(client.login_calls, 0)

    def test_fresh_login_retries_oauth_session_propagation_without_relogin(self):
        class DelayedOAuthClient(MailComClient):
            def __init__(self):
                super().__init__("user@mail.com", "secret")
                self.sid = "stale"
                self.login_calls = 0
                self.token_calls = 0

            def login(self, retries: int = 3) -> None:
                self.login_calls += 1
                self.sid = "fresh"

            def get_token(self, scope: str, client_id: str, *, force: bool = False) -> str:
                self.token_calls += 1
                if self.token_calls <= 3:
                    raise MailComError("NO_SESSION", kind="session_expired")
                return "fresh-token"

        client = DelayedOAuthClient()
        with mock.patch("mailcom_client.time.sleep") as sleep:
            self.assertEqual(client.ensure_mail_token(), "fresh-token")

        self.assertEqual(client.login_calls, 1)
        self.assertEqual(client.token_calls, 4)
        self.assertEqual(sleep.call_count, 2)

    def test_oauth_no_session_error_is_classified_as_expired_session(self):
        client = MailComClient("user@mail.com", "secret")
        client.sid = "stale"
        client.session.post = mock.Mock(
            return_value=mock.Mock(
                status_code=400,
                json=mock.Mock(
                    return_value={
                        "error": "unauthorized_user",
                        "error_description": "OAuthBridge.NO_SESSION",
                    }
                ),
            )
        )
        with self.assertRaises(MailComError) as raised:
            client.get_token("mail_mailbox_r", "mail-client")
        self.assertEqual(raised.exception.kind, "session_expired")

    def test_delete_alias_uses_mailcom_removal_action(self):
        client = MailComClient("user@mail.com", "secret")
        response = mock.Mock(status_code=204, headers={})
        response.json.side_effect = ValueError
        client.session.post = mock.Mock(return_value=response)
        client.ensure_settings_token = mock.Mock(return_value="settings-token")

        client.delete_alias("Child+One@Engineer.com")

        args, kwargs = client.session.post.call_args
        self.assertTrue(
            args[0].endswith(
                "/emailAddressesRemovals/child%2Bone%40engineer.com/removals"
            )
        )
        self.assertEqual(kwargs["params"], {"absoluteURI": "false"})
        self.assertEqual(kwargs["headers"]["Content-Type"], "text/plain;charset=UTF-8")

    def test_delete_alias_refreshes_revoked_settings_token_once(self):
        client = MailComClient("user@mail.com", "secret")
        client.tokens[client._token_key("mailcom_mailset_root_live", "mail_mailbox_w webmailer_setting_r webmailer_setting_w mail_confix_w")] = "old-token"
        client.session.post = mock.Mock(
            side_effect=[
                mock.Mock(status_code=401, headers={}, json=mock.Mock(return_value={})),
                mock.Mock(status_code=204, headers={}, json=mock.Mock(return_value={})),
            ]
        )
        client.ensure_settings_token = mock.Mock(
            side_effect=["old-token", "fresh-token"]
        )

        client.delete_alias("child@engineer.com")

        self.assertEqual(client.session.post.call_count, 2)
        second_headers = client.session.post.call_args_list[1].kwargs["headers"]
        self.assertEqual(second_headers["Authorization"], "Bearer fresh-token")


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

    def test_child_and_parent_deletion(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            primary = store.upsert_account("parent@mail.com", "secret")
            store.add_address(primary.account_id, "child@engineer.com")

            self.assertFalse(store.delete_address(primary.account_id, "parent@mail.com"))
            self.assertTrue(store.delete_address(primary.account_id, "child@engineer.com"))
            self.assertIsNone(store.get_by_address("child@engineer.com"))
            self.assertTrue(store.delete_account(primary.account_id))
            self.assertIsNone(store.get_account(primary.account_id))

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


class DeleteTests(unittest.TestCase):
    def test_delete_child_logs_each_diagnostic_with_same_trace_id(self):
        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def delete_alias(self, address):
                raise MailComError(
                    "mail.com 会话已失效或被拒绝",
                    kind="session_expired",
                    status=401,
                )

            def drain_diagnostics(self):
                return [
                    {"step": "oauth_response", "status": 400},
                    {"step": "auth_session_reset", "old_cookie_names": ["navigator"]},
                ]

            def export_state(self):
                return {"sid": ""}

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            primary = store.upsert_account("parent@mail.com", "secret")
            store.add_address(primary.account_id, "child@engineer.com")
            account = store.get_account(primary.account_id)
            app = MailCodeApplication(store, "admin-token", client_factory=FakeClient)
            captured = io.StringIO()

            with redirect_stderr(captured), self.assertRaises(MailComError):
                app.delete_alias(account, "child@engineer.com")

            events = [
                json.loads(line.removeprefix("mail-code-api "))
                for line in captured.getvalue().splitlines()
            ]
            details = [row for row in events if row["event"] == "alias_delete_detail"]
            failed = next(row for row in events if row["event"] == "alias_delete_failed")
            self.assertEqual([row["sequence"] for row in details], [1, 2])
            self.assertEqual([row["step"] for row in details], ["oauth_response", "auth_session_reset"])
            self.assertTrue(all(row["trace_id"] == failed["trace_id"] for row in details))

    def test_delete_child_reloads_latest_session_inside_account_lock(self):
        seen_states = []

        class FakeClient:
            def __init__(self, *args, **kwargs):
                seen_states.append(kwargs.get("state"))

            def delete_alias(self, address):
                pass

            def export_state(self):
                return {"sid": "latest"}

        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(io.StringIO()):
            store = Store(Path(tmp), "https://codes.example")
            primary = store.upsert_account("parent@mail.com", "secret")
            store.add_address(primary.account_id, "child@engineer.com")
            stale_account = store.get_account(primary.account_id)
            store.update_session(primary.account_id, {"sid": "latest"})
            app = MailCodeApplication(store, "admin-token", client_factory=FakeClient)

            app.delete_alias(stale_account, "child@engineer.com")

            self.assertEqual(seen_states[0]["sid"], "latest")

    def test_delete_child_removes_upstream_before_local_route(self):
        calls = []

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def delete_alias(self, address):
                calls.append(address)

            def export_state(self):
                return {"sid": "updated"}

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            primary = store.upsert_account("parent@mail.com", "secret")
            store.add_address(primary.account_id, "child@engineer.com")
            account = store.get_account(primary.account_id)
            app = MailCodeApplication(
                store, "admin-token", client_factory=FakeClient
            )

            app.delete_alias(account, "child@engineer.com")

            self.assertEqual(calls, ["child@engineer.com"])
            self.assertIsNone(store.get_by_address("child@engineer.com"))
            self.assertEqual(store.get_account(primary.account_id).session["sid"], "updated")

    def test_delete_child_keeps_local_route_when_upstream_fails(self):
        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def delete_alias(self, address):
                raise MailComError("upstream failed", kind="alias_delete_failed")

            def export_state(self):
                return {"sid": "refreshed-after-failure"}

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            primary = store.upsert_account("parent@mail.com", "secret")
            store.add_address(primary.account_id, "child@engineer.com")
            account = store.get_account(primary.account_id)
            app = MailCodeApplication(
                store, "admin-token", client_factory=FakeClient
            )

            with self.assertRaises(MailComError):
                app.delete_alias(account, "child@engineer.com")

            self.assertIsNotNone(store.get_by_address("child@engineer.com"))
            self.assertEqual(
                store.get_account(primary.account_id).session["sid"],
                "refreshed-after-failure",
            )

    def test_primary_address_cannot_be_deleted_as_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            primary = store.upsert_account("parent@mail.com", "secret")
            account = store.get_account(primary.account_id)
            app = MailCodeApplication(store, "admin-token")

            with self.assertRaisesRegex(ValueError, "母号不能"):
                app.delete_alias(account, "parent@mail.com")


class CodeFetchTests(unittest.TestCase):
    def test_latest_unfiltered_message_bypasses_search_index_delay(self):
        query_calls = []
        now_ms = int(time.time() * 1000)

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def query_messages(self, recipient="", *, amount=20):
                query_calls.append((recipient, amount))
                if recipient:
                    return []
                return [
                    MailMessage(
                        mail_id="latest-mail",
                        subject="Your verification code",
                        sender="service@example.com",
                        recipients=["Child <child@engineer.com>"],
                        date_ms=now_ms,
                        folder="INBOX",
                    )
                ]

            def get_body(self, mail_id):
                return "Your verification code is 482913"

            def export_state(self):
                return {"sid": "updated"}

        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(io.StringIO()):
            store = Store(Path(tmp), "https://codes.example")
            primary = store.upsert_account("parent@mail.com", "secret")
            child = store.add_address(primary.account_id, "child@engineer.com")
            account = store.get_account(primary.account_id)
            app = MailCodeApplication(store, "admin-token", client_factory=FakeClient)

            result = app.fetch_code(account, child, trace_id="test-trace")

            self.assertEqual(result["code"], "482913")
            self.assertEqual(query_calls, [("", 50), ("child@engineer.com", 50)])

    def test_unfiltered_query_does_not_cross_child_addresses(self):
        now_ms = int(time.time() * 1000)

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def query_messages(self, recipient="", *, amount=20):
                if recipient:
                    return []
                return [
                    MailMessage(
                        mail_id="other-child-mail",
                        subject="Your verification code",
                        sender="service@example.com",
                        recipients=["other-child@engineer.com"],
                        date_ms=now_ms,
                        folder="INBOX",
                    )
                ]

            def get_body(self, mail_id):
                raise AssertionError("不应读取其他子号的邮件正文")

            def export_state(self):
                return {}

        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(io.StringIO()):
            store = Store(Path(tmp), "https://codes.example")
            primary = store.upsert_account("parent@mail.com", "secret")
            child = store.add_address(primary.account_id, "child@engineer.com")
            account = store.get_account(primary.account_id)
            app = MailCodeApplication(store, "admin-token", client_factory=FakeClient)

            self.assertIsNone(app.fetch_code(account, child, trace_id="test-trace"))

    def test_auth_failure_stops_second_query_and_persists_client_state(self):
        query_calls = []

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def query_messages(self, recipient="", *, amount=20):
                query_calls.append(recipient)
                raise MailComError(
                    "服务器公网 IP 被拒绝", kind="blocked", status=403
                )

            def export_state(self):
                return {"sid": "", "tokens": {}}

        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(io.StringIO()):
            store = Store(Path(tmp), "https://codes.example")
            primary = store.upsert_account("parent@mail.com", "secret")
            account = store.get_account(primary.account_id)
            app = MailCodeApplication(store, "admin-token", client_factory=FakeClient)

            with self.assertRaises(MailComError):
                app.fetch_code(account, primary, trace_id="test-trace")

            self.assertEqual(query_calls, [""])
            saved = store.get_account(primary.account_id)
            self.assertEqual(saved.status, "blocked")
            self.assertEqual(saved.session["sid"], "")


class ProxyClientTests(unittest.TestCase):
    def test_impersonation_does_not_mix_in_a_different_chrome_user_agent(self):
        client = MailComClient("user@mail.com", "secret")
        self.assertNotIn("User-Agent", client.session.headers)

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

    def test_explicit_import_proxy_does_not_require_pool_checkbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = MailCodeApplication(store, "admin-token")

            _, account = app.import_account(
                "first@mail.com",
                "secret-1",
                "http://proxy-user:proxy-pass@gate.example:1000",
            )

            self.assertEqual(
                account.proxy_url,
                "http://proxy-user:proxy-pass@gate.example:1000",
            )


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

    def test_split_aliases_randomizes_requested_domains_after_exclusions(self):
        class FakeSplitApplication(MailCodeApplication):
            def add_alias(self, account, address, *, verify_visible=True, validate=True):
                return self.store.add_address(account.id, address)

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = FakeSplitApplication(store, "admin-token")
            route = store.upsert_account("longusername@mail.com", "secret")
            account = store.get_account(route.account_id)

            routes = app.split_aliases(
                account,
                3,
                domain="engineer.com,comic.com,email.com",
                exclude_domains="engineer.com,email.com",
            )

            self.assertTrue(all(item.address.endswith("@comic.com") for item in routes))

    def test_split_aliases_excludes_domains_from_random_tld_pool(self):
        class FakeSplitApplication(MailCodeApplication):
            def list_alias_domains(self, account):
                return ["email.com", "engineer.com", "null.net"]

            def add_alias(self, account, address, *, verify_visible=True, validate=True):
                return self.store.add_address(account.id, address)

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = FakeSplitApplication(store, "admin-token")
            route = store.upsert_account("longusername@mail.com", "secret")
            account = store.get_account(route.account_id)

            routes = app.split_aliases(
                account,
                3,
                random_domain_tlds=["com"],
                exclude_domains=["email.com"],
            )

            self.assertTrue(all(item.address.endswith("@engineer.com") for item in routes))

    def test_split_aliases_reuses_session_refreshed_by_previous_alias(self):
        seen_sessions = []

        class FakeSplitApplication(MailCodeApplication):
            def add_alias(self, account, address, *, verify_visible=True, validate=True):
                seen_sessions.append(account.session.get("sid", ""))
                self.store.update_session(
                    account.id, {"sid": f"fresh-{len(seen_sessions)}"}
                )
                return self.store.add_address(account.id, address)

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp), "https://codes.example")
            app = FakeSplitApplication(store, "admin-token")
            route = store.upsert_account("longusername@mail.com", "secret")
            account = store.get_account(route.account_id)

            app.split_aliases(account, 3, domain="engineer.com")

            self.assertEqual(seen_sessions, ["", "fresh-1", "fresh-2"])

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
