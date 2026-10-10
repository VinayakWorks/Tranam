import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from services.accounts import (
    AccountStore,
    DuplicateEmailError,
    InvalidCredentialsError,
    InvalidSessionError,
)


class AccountStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_directory.name) / "accounts.sqlite3"
        self.store = AccountStore(database_path)
        self.store.initialize()

    def tearDown(self) -> None:
        self.temp_directory.cleanup()

    def test_register_login_update_and_revoke_session(self) -> None:
        profile, token = self.store.register(
            "student@example.com",
            "correct horse battery staple",
            "Aarav Student",
            college="Example College",
            course="Computer Science",
            interests="Security internships",
        )

        self.assertEqual(profile["email"], "student@example.com")
        self.assertNotIn("password", profile)
        self.assertEqual(self.store.get_profile(token), profile)

        updated = self.store.update_profile(
            token,
            {"college": "New College", "interests": "Frontend and security"},
        )
        self.assertEqual(updated["college"], "New College")
        self.assertEqual(updated["interests"], "Frontend and security")

        logged_in_profile, login_token = self.store.login(
            "student@example.com",
            "correct horse battery staple",
        )
        self.assertEqual(logged_in_profile["id"], profile["id"])
        self.assertNotEqual(login_token, token)

        self.store.logout(token)
        with self.assertRaises(InvalidSessionError):
            self.store.get_profile(token)
        self.assertEqual(self.store.get_profile(login_token)["id"], profile["id"])

    def test_password_and_session_secrets_are_not_stored_plaintext(self) -> None:
        password = "correct horse battery staple"
        _, token = self.store.register(
            "student@example.com",
            password,
            "Aarav Student",
        )
        with closing(sqlite3.connect(self.store.database_path)) as connection:
            stored_password_hash, stored_session_hash = connection.execute(
                """
                SELECT users.password_hash, sessions.token_hash
                FROM users JOIN sessions ON sessions.user_id = users.id
                """
            ).fetchone()

        self.assertNotEqual(stored_password_hash, password.encode())
        self.assertNotEqual(stored_session_hash, token)

    def test_duplicate_email_is_rejected_case_insensitively(self) -> None:
        self.store.register(
            "student@example.com",
            "correct horse battery staple",
            "Aarav Student",
        )
        with self.assertRaises(DuplicateEmailError):
            self.store.register(
                "STUDENT@example.com",
                "another secure password",
                "Another Student",
            )

    def test_incorrect_password_does_not_create_a_session(self) -> None:
        self.store.register(
            "student@example.com",
            "correct horse battery staple",
            "Aarav Student",
        )
        with self.assertRaises(InvalidCredentialsError):
            self.store.login("student@example.com", "incorrect password")

    def test_profile_update_rejects_empty_and_unknown_fields(self) -> None:
        _, token = self.store.register(
            "student@example.com",
            "correct horse battery staple",
            "Aarav Student",
        )
        with self.assertRaises(ValueError):
            self.store.update_profile(token, {})
        with self.assertRaises(ValueError):
            self.store.update_profile(token, {"email": "other@example.com"})

    def test_saved_reports_are_private_and_owner_can_delete_them(self) -> None:
        first_profile, _ = self.store.register(
            "first@example.com",
            "correct horse battery staple",
            "First Student",
        )
        second_profile, _ = self.store.register(
            "second@example.com",
            "another secure password",
            "Second Student",
        )
        report = {
            "report_reference": "TN-20261011-12345678",
            "generated_at": "2026-10-11T00:00:00+00:00",
            "score": 30,
            "classification": {"key": "medium", "label": "Medium"},
            "matches": [{"name": "Registration fee", "excerpt": "Pay a fee"}],
        }
        self.store.save_report(first_profile["id"], report)

        self.assertEqual(self.store.list_reports(first_profile["id"])[0]["report"], report)
        self.assertEqual(self.store.list_reports(second_profile["id"]), [])
        self.assertFalse(
            self.store.delete_report(
                second_profile["id"],
                report["report_reference"],
            )
        )
        self.assertTrue(
            self.store.delete_report(
                first_profile["id"],
                report["report_reference"],
            )
        )
        self.assertEqual(self.store.list_reports(first_profile["id"]), [])

    def test_saved_report_requires_backend_generated_identity_fields(self) -> None:
        profile, _ = self.store.register(
            "student@example.com",
            "correct horse battery staple",
            "Student",
        )
        with self.assertRaises(ValueError):
            self.store.save_report(profile["id"], {"score": 10})


if __name__ == "__main__":
    unittest.main()
