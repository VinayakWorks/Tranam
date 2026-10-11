"""SQLite-backed student accounts and revocable bearer sessions."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


PASSWORD_ITERATIONS = 310_000


class DuplicateEmailError(Exception):
    """Raised when an account already exists for the email address."""


class InvalidCredentialsError(Exception):
    """Raised when the email and password do not match."""


class InvalidSessionError(Exception):
    """Raised when a bearer token is missing, expired, or revoked."""


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )


class AccountStore:
    """Persist account profiles and only hashed session tokens in SQLite."""

    def __init__(self, database_path: Path, session_hours: int = 24) -> None:
        self.database_path = database_path
        self.session_hours = session_hours
        self.database_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    display_name TEXT NOT NULL,
                    college TEXT NOT NULL DEFAULT '',
                    course TEXT NOT NULL DEFAULT '',
                    interests TEXT NOT NULL DEFAULT '',
                    password_salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    expires_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS sessions_expiry_idx
                    ON sessions(expires_at);
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS password_reset_user_created_idx
                    ON password_reset_tokens(user_id, created_at);
                CREATE TABLE IF NOT EXISTS reports (
                    report_reference TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    report_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS reports_user_created_idx
                    ON reports(user_id, created_at DESC);
                """
            )

    @staticmethod
    def _profile(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "display_name": row["display_name"],
            "email": row["email"],
            "college": row["college"],
            "course": row["course"],
            "interests": row["interests"],
            "created_at": row["created_at"],
        }

    def _new_session(self, connection: sqlite3.Connection, user_id: int) -> str:
        now = datetime.now(timezone.utc)
        connection.execute(
            "DELETE FROM sessions WHERE expires_at <= ?",
            (now.isoformat(),),
        )
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        expires_at = (now + timedelta(hours=self.session_hours)).isoformat()
        connection.execute(
            "INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (token_hash, user_id, expires_at),
        )
        return token

    def register(
        self,
        email: str,
        password: str,
        display_name: str,
        college: str = "",
        course: str = "",
        interests: str = "",
    ) -> tuple[dict[str, Any], str]:
        salt = secrets.token_bytes(16)
        password_hash = _hash_password(password, salt)
        created_at = datetime.now(timezone.utc).isoformat()
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO users(
                        email, display_name, college, course, interests,
                        password_salt, password_hash, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        email,
                        display_name,
                        college,
                        course,
                        interests,
                        salt,
                        password_hash,
                        created_at,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM users WHERE id = ?",
                    (cursor.lastrowid,),
                ).fetchone()
                user_id = cursor.lastrowid
                if user_id is None:
                    raise RuntimeError("The database did not return a new account ID.")
                token = self._new_session(connection, user_id)
        except sqlite3.IntegrityError as error:
            if "users.email" in str(error).lower():
                raise DuplicateEmailError from error
            raise

        if row is None:
            raise RuntimeError("The account was not available after registration.")
        return self._profile(row), token

    def login(self, email: str, password: str) -> tuple[dict[str, Any], str]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,),
            ).fetchone()
            salt = row["password_salt"] if row else bytes(16)
            expected_hash = row["password_hash"] if row else bytes(32)
            supplied_hash = _hash_password(password, salt)
            if row is None or not hmac.compare_digest(supplied_hash, expected_hash):
                raise InvalidCredentialsError
            token = self._new_session(connection, row["id"])
        return self._profile(row), token

    def create_password_reset_token(
        self,
        email: str,
        ttl_minutes: int = 30,
        cooldown_seconds: int = 60,
    ) -> str | None:
        now = datetime.now(timezone.utc)
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        expires_at = (now + timedelta(minutes=ttl_minutes)).isoformat()
        cooldown_start = (now - timedelta(seconds=cooldown_seconds)).isoformat()
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM password_reset_tokens WHERE expires_at <= ?",
                (now.isoformat(),),
            )
            row = connection.execute(
                "SELECT id FROM users WHERE email = ?",
                (email,),
            ).fetchone()
            if row is None:
                return None
            recent_request = connection.execute(
                """
                SELECT 1 FROM password_reset_tokens
                WHERE user_id = ? AND created_at > ?
                """,
                (row["id"], cooldown_start),
            ).fetchone()
            if recent_request is not None:
                return None
            connection.execute(
                "DELETE FROM password_reset_tokens WHERE user_id = ?",
                (row["id"],),
            )
            connection.execute(
                """
                INSERT INTO password_reset_tokens(
                    token_hash, user_id, expires_at, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                (token_hash, row["id"], expires_at, now.isoformat()),
            )
        return token

    def complete_password_reset(self, token: str, new_password: str) -> bool:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        salt = secrets.token_bytes(16)
        password_hash = _hash_password(new_password, salt)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT user_id FROM password_reset_tokens
                WHERE token_hash = ? AND expires_at > ?
                """,
                (token_hash, now),
            ).fetchone()
            if row is None:
                return False
            user_id = row["user_id"]
            connection.execute(
                "UPDATE users SET password_salt = ?, password_hash = ? WHERE id = ?",
                (salt, password_hash, user_id),
            )
            connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            connection.execute(
                "DELETE FROM password_reset_tokens WHERE user_id = ?",
                (user_id,),
            )
        return True

    def delete_password_reset_token(self, token: str) -> None:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM password_reset_tokens WHERE token_hash = ?",
                (token_hash,),
            )

    def get_profile(self, token: str) -> dict[str, Any]:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT users.*
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                """,
                (token_hash, now),
            ).fetchone()
        if row is None:
            raise InvalidSessionError
        return self._profile(row)

    def update_profile(self, token: str, updates: dict[str, str]) -> dict[str, Any]:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        allowed_fields = {"display_name", "college", "course", "interests"}
        if not updates or not updates.keys() <= allowed_fields:
            raise ValueError("Provide one or more profile fields to update.")

        columns = ", ".join(f"{field} = ?" for field in updates)
        values = [*updates.values(), token_hash, now]
        with self._connect() as connection:
            cursor = connection.execute(
                f"""
                UPDATE users SET {columns}
                WHERE id = (
                    SELECT user_id FROM sessions
                    WHERE token_hash = ? AND expires_at > ?
                )
                """,
                values,
            )
            if cursor.rowcount != 1:
                raise InvalidSessionError
            row = connection.execute(
                """
                SELECT users.*
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ?
                """,
                (token_hash,),
            ).fetchone()
        if row is None:
            raise InvalidSessionError
        return self._profile(row)

    def logout(self, token: str) -> None:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM sessions WHERE token_hash = ?",
                (token_hash,),
            )

    def save_report(self, user_id: int, report: dict[str, Any]) -> dict[str, Any]:
        report_reference = report.get("report_reference")
        generated_at = report.get("generated_at")
        if not isinstance(report_reference, str) or not report_reference:
            raise ValueError("A report reference is required to save a report.")
        if not isinstance(generated_at, str) or not generated_at:
            raise ValueError("A report timestamp is required to save a report.")

        report_json = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
        if len(report_json.encode("utf-8")) > 1_000_000:
            raise ValueError("This report is too large to save.")

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO reports(report_reference, user_id, report_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (report_reference, user_id, report_json, generated_at),
            )
        return {
            "report_reference": report_reference,
            "saved_at": generated_at,
            "report": report,
        }

    def list_reports(self, user_id: int, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT report_reference, report_json, created_at
                FROM reports
                WHERE user_id = ?
                ORDER BY created_at DESC, report_reference DESC
                LIMIT ?
                """,
                (user_id, limit),
            ).fetchall()
        return [
            {
                "report_reference": row["report_reference"],
                "saved_at": row["created_at"],
                "report": json.loads(row["report_json"]),
            }
            for row in rows
        ]

    def delete_report(self, user_id: int, report_reference: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM reports
                WHERE report_reference = ? AND user_id = ?
                """,
                (report_reference, user_id),
            )
        return cursor.rowcount == 1
