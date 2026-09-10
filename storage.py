"""SQLite persistence and encrypted secret storage for the mail code service."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


@dataclass(slots=True)
class Account:
    id: int
    email: str
    password: str
    session: dict[str, Any]
    status: str
    last_error: str
    # Stored encrypted at rest; never expose the credential-bearing URL in API responses.
    proxy_url: str = ""
    proxy_assigned_at: str = ""


@dataclass(slots=True)
class Address:
    account_id: int
    address: str
    access_key: str
    is_primary: bool


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, data_dir: Path, public_base: str) -> None:
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = data_dir / "mail-code.db"
        self.export_path = data_dir / "邮箱----接码API.txt"
        self.public_base = public_base.rstrip("/")
        self._write_lock = threading.RLock()
        self.fernet = Fernet(self._load_key())
        self._migrate()

    def _load_key(self) -> bytes:
        configured = os.environ.get("MAIL_API_MASTER_KEY", "").strip()
        if configured:
            return configured.encode("ascii")
        key_path = self.data_dir / "master.key"
        if key_path.exists():
            return key_path.read_bytes().strip()
        key = Fernet.generate_key()
        key_path.write_bytes(key + b"\n")
        try:
            key_path.chmod(0o600)
        except OSError:
            pass
        return key

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=20)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @contextmanager
    def connection(self):
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _migrate(self) -> None:
        with self.connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    password_enc BLOB NOT NULL,
                    session_enc BLOB,
                    proxy_url_enc BLOB,
                    proxy_assigned_at TEXT,
                    status TEXT NOT NULL DEFAULT 'imported',
                    last_error TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS addresses (
                    id INTEGER PRIMARY KEY,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    address TEXT NOT NULL UNIQUE,
                    access_key TEXT NOT NULL UNIQUE,
                    is_primary INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_addresses_account ON addresses(account_id);
                """
            )
            # Existing installations predate per-account proxy bindings.  Keep the
            # migration additive so their encrypted sessions and routes remain intact.
            columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(accounts)")}
            if "proxy_url_enc" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN proxy_url_enc BLOB")
            if "proxy_assigned_at" not in columns:
                conn.execute("ALTER TABLE accounts ADD COLUMN proxy_assigned_at TEXT")

    def _encrypt_text(self, value: str) -> bytes:
        return self.fernet.encrypt(value.encode("utf-8"))

    def _decrypt_text(self, value: bytes | None) -> str:
        if not value:
            return ""
        try:
            return self.fernet.decrypt(bytes(value)).decode("utf-8")
        except InvalidToken as exc:
            raise RuntimeError("MAIL_API_MASTER_KEY 与数据库中的密文不匹配") from exc

    def upsert_account(self, email: str, password: str, proxy_url: str | None = None) -> Address:
        email = email.strip().lower()
        proxy_url = proxy_url.strip() if proxy_url else None
        now = utc_now()
        with self._write_lock, self.connection() as conn:
            row = conn.execute("SELECT id FROM accounts WHERE email=?", (email,)).fetchone()
            encrypted = self._encrypt_text(password)
            if row:
                account_id = int(row["id"])
                current_row = conn.execute(
                    "SELECT proxy_url_enc FROM accounts WHERE id=?", (account_id,)
                ).fetchone()
                current_proxy = self._decrypt_text(current_row["proxy_url_enc"]) if current_row else ""
                if proxy_url and current_proxy and current_proxy != proxy_url:
                    raise ValueError("proxy_binding_exists")
                if proxy_url and not current_proxy:
                    conn.execute(
                        "UPDATE accounts SET password_enc=?, session_enc=NULL, "
                        "proxy_url_enc=?, proxy_assigned_at=?, status='imported', "
                        "last_error='', updated_at=? WHERE id=?",
                        (encrypted, self._encrypt_text(proxy_url), now, now, account_id),
                    )
                else:
                    conn.execute(
                        "UPDATE accounts SET password_enc=?, session_enc=NULL, status='imported', "
                        "last_error='', updated_at=? WHERE id=?",
                        (encrypted, now, account_id),
                    )
            else:
                cursor = conn.execute(
                    "INSERT INTO accounts(email,password_enc,proxy_url_enc,proxy_assigned_at,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (
                        email,
                        encrypted,
                        self._encrypt_text(proxy_url) if proxy_url else None,
                        now if proxy_url else None,
                        now,
                        now,
                    ),
                )
                account_id = int(cursor.lastrowid)
            address = conn.execute("SELECT * FROM addresses WHERE address=?", (email,)).fetchone()
            if not address:
                access_key = secrets.token_urlsafe(32)
                conn.execute(
                    "INSERT INTO addresses(account_id,address,access_key,is_primary,created_at) VALUES(?,?,?,?,?)",
                    (account_id, email, access_key, 1, now),
                )
                address = conn.execute("SELECT * FROM addresses WHERE address=?", (email,)).fetchone()
        self.write_export()
        return self._row_to_address(address)

    def add_address(self, account_id: int, address: str, *, primary: bool = False) -> Address:
        address = address.strip().lower()
        with self._write_lock, self.connection() as conn:
            row = conn.execute("SELECT * FROM addresses WHERE address=?", (address,)).fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO addresses(account_id,address,access_key,is_primary,created_at) VALUES(?,?,?,?,?)",
                    (account_id, address, secrets.token_urlsafe(32), int(primary), utc_now()),
                )
                row = conn.execute("SELECT * FROM addresses WHERE address=?", (address,)).fetchone()
            elif int(row["account_id"]) != account_id:
                raise ValueError("该邮箱地址已属于另一个账号")
        self.write_export()
        return self._row_to_address(row)

    def get_account(self, account_id: int) -> Account | None:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        return self._row_to_account(row) if row else None

    def get_account_by_email(self, email: str) -> Account | None:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM accounts WHERE email=?", (email.strip().lower(),)).fetchone()
        return self._row_to_account(row) if row else None

    def get_by_key(self, access_key: str) -> tuple[Account, Address] | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT a.*, d.address AS route_address, d.access_key, d.is_primary "
                "FROM addresses d JOIN accounts a ON a.id=d.account_id WHERE d.access_key=?",
                (access_key,),
            ).fetchone()
        if not row:
            return None
        account = self._row_to_account(row)
        address = Address(account.id, str(row["route_address"]), str(row["access_key"]), bool(row["is_primary"]))
        return account, address

    def get_by_address(self, address: str) -> tuple[Account, Address] | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT a.*, d.address AS route_address, d.access_key, d.is_primary "
                "FROM addresses d JOIN accounts a ON a.id=d.account_id WHERE lower(d.address)=?",
                (address.strip().lower(),),
            ).fetchone()
        if not row:
            return None
        account = self._row_to_account(row)
        route = Address(account.id, str(row["route_address"]), str(row["access_key"]), bool(row["is_primary"]))
        return account, route

    def list_addresses_for_account(self, account_id: int) -> list[Address]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT account_id,address,access_key,is_primary FROM addresses "
                "WHERE account_id=? ORDER BY is_primary DESC,address",
                (account_id,),
            ).fetchall()
        return [
            Address(int(row["account_id"]), str(row["address"]), str(row["access_key"]), bool(row["is_primary"]))
            for row in rows
        ]

    def list_accounts(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT a.id,a.email,a.status,a.last_error,a.created_at,a.updated_at,"
                "a.proxy_url_enc,a.proxy_assigned_at,"
                "d.address,d.access_key,d.is_primary FROM accounts a "
                "JOIN addresses d ON d.account_id=a.id ORDER BY a.id,d.is_primary DESC,d.address"
            ).fetchall()
        grouped: dict[int, dict[str, Any]] = {}
        for row in rows:
            item = grouped.setdefault(
                int(row["id"]),
                {
                    "id": int(row["id"]),
                    "email": str(row["email"]),
                    "status": str(row["status"]),
                    "last_error": str(row["last_error"]),
                    "created_at": str(row["created_at"]),
                    "updated_at": str(row["updated_at"]),
                    "proxy_bound": bool(self._decrypt_text(row["proxy_url_enc"])),
                    "proxy_assigned_at": str(row["proxy_assigned_at"] or ""),
                    "addresses": [],
                },
            )
            item["addresses"].append(
                {
                    "address": str(row["address"]),
                    "is_primary": bool(row["is_primary"]),
                    "url": self.code_url(str(row["access_key"])),
                }
            )
        return list(grouped.values())

    def list_accounts_page(
        self, page: int, page_size: int, query: str = ""
    ) -> tuple[list[dict[str, Any]], int]:
        """按母号进行 SQL 分页，并返回该页母号的全部子号。"""
        offset = (page - 1) * page_size
        query = query.strip().lower()
        where = ""
        params: list[Any] = []
        if query:
            where = (
                " WHERE lower(a.email) LIKE ? OR EXISTS ("
                "SELECT 1 FROM addresses search_address "
                "WHERE search_address.account_id=a.id AND lower(search_address.address) LIKE ?)"
            )
            pattern = f"%{query}%"
            params.extend((pattern, pattern))
        with self.connection() as conn:
            total = int(
                conn.execute(f"SELECT COUNT(*) FROM accounts a{where}", params).fetchone()[0]
            )
            account_rows = conn.execute(
                "SELECT id,email,password_enc,status,last_error,created_at,updated_at,"
                f"proxy_url_enc,proxy_assigned_at FROM accounts a{where} "
                "ORDER BY id DESC LIMIT ? OFFSET ?",
                (*params, page_size, offset),
            ).fetchall()
            account_ids = [int(row["id"]) for row in account_rows]
            address_rows = []
            if account_ids:
                placeholders = ",".join("?" for _ in account_ids)
                address_rows = conn.execute(
                    f"SELECT account_id,address,access_key,is_primary FROM addresses "
                    f"WHERE account_id IN ({placeholders}) ORDER BY account_id,is_primary DESC,address",
                    account_ids,
                ).fetchall()

        addresses_by_account: dict[int, list[dict[str, Any]]] = {account_id: [] for account_id in account_ids}
        for row in address_rows:
            addresses_by_account[int(row["account_id"])].append(
                {
                    "address": str(row["address"]),
                    "is_primary": bool(row["is_primary"]),
                    "url": self.code_url(str(row["access_key"])),
                }
            )
        accounts = [
            {
                "id": int(row["id"]),
                "email": str(row["email"]),
                "password": self._decrypt_text(row["password_enc"]),
                "status": str(row["status"]),
                "last_error": str(row["last_error"]),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
                "proxy_bound": bool(self._decrypt_text(row["proxy_url_enc"])),
                "proxy_assigned_at": str(row["proxy_assigned_at"] or ""),
                "addresses": addresses_by_account[int(row["id"])],
            }
            for row in account_rows
        ]
        return accounts, total

    def list_addresses_page(self, page: int, page_size: int) -> tuple[list[dict[str, Any]], int]:
        """按接码地址进行 SQL 分页，不返回母号密码。"""
        offset = (page - 1) * page_size
        with self.connection() as conn:
            total = int(conn.execute("SELECT COUNT(*) FROM addresses").fetchone()[0])
            rows = conn.execute(
                "SELECT d.address,d.access_key,d.is_primary,a.email AS mother_email "
                "FROM addresses d JOIN accounts a ON a.id=d.account_id "
                "ORDER BY a.id DESC,d.is_primary DESC,d.address LIMIT ? OFFSET ?",
                (page_size, offset),
            ).fetchall()
        return [
            {
                "address": str(row["address"]),
                "mother_email": str(row["mother_email"]),
                "email_type": "母号" if bool(row["is_primary"]) else "子号",
                "is_primary": bool(row["is_primary"]),
                "url": self.code_url(str(row["access_key"])),
            }
            for row in rows
        ], total

    def update_session(self, account_id: int, session: dict[str, Any], *, status: str = "ready", error: str = "") -> None:
        encoded = self._encrypt_text(json.dumps(session, separators=(",", ":")))
        with self._write_lock, self.connection() as conn:
            conn.execute(
                "UPDATE accounts SET session_enc=?,status=?,last_error=?,updated_at=? WHERE id=?",
                (encoded, status, error[:500], utc_now(), account_id),
            )

    def update_status(self, account_id: int, status: str, error: str = "") -> None:
        with self._write_lock, self.connection() as conn:
            conn.execute(
                "UPDATE accounts SET status=?,last_error=?,updated_at=? WHERE id=?",
                (status, error[:500], utc_now(), account_id),
            )

    def list_assigned_proxies(self) -> set[str]:
        """Return decrypted proxy URLs for in-process allocation only."""
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT proxy_url_enc FROM accounts WHERE proxy_url_enc IS NOT NULL"
            ).fetchall()
        return {
            proxy
            for row in rows
            if (proxy := self._decrypt_text(row["proxy_url_enc"]))
        }

    def code_url(self, access_key: str) -> str:
        return f"{self.public_base}/code/{access_key}"

    def write_export(self) -> None:
        with self._write_lock, self.connection() as conn:
            rows = conn.execute("SELECT address,access_key FROM addresses ORDER BY address").fetchall()
        content = "".join(f"{row['address']}----{self.code_url(row['access_key'])}\n" for row in rows)
        fd, temp_name = tempfile.mkstemp(prefix="mail-code-export-", dir=self.data_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
            os.replace(temp_name, self.export_path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def export_text(self) -> str:
        self.write_export()
        return self.export_path.read_text(encoding="utf-8")

    def _row_to_account(self, row: sqlite3.Row) -> Account:
        session_text = self._decrypt_text(row["session_enc"])
        session = json.loads(session_text) if session_text else {}
        return Account(
            id=int(row["id"]),
            email=str(row["email"]),
            password=self._decrypt_text(row["password_enc"]),
            session=session,
            status=str(row["status"]),
            last_error=str(row["last_error"]),
            proxy_url=self._decrypt_text(row["proxy_url_enc"]),
            proxy_assigned_at=str(row["proxy_assigned_at"] or ""),
        )

    @staticmethod
    def _row_to_address(row: sqlite3.Row) -> Address:
        return Address(int(row["account_id"]), str(row["address"]), str(row["access_key"]), bool(row["is_primary"]))
