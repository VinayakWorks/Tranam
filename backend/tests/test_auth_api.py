import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException
from pydantic import ValidationError

import main
from services.accounts import AccountStore


class AccountApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.original_store = main.ACCOUNT_STORE
        main.ACCOUNT_STORE = AccountStore(
            Path(self.temp_directory.name) / "accounts.sqlite3"
        )
        main.ACCOUNT_STORE.initialize()

    def tearDown(self) -> None:
        main.ACCOUNT_STORE = self.original_store
        self.temp_directory.cleanup()

    def test_register_profile_update_login_and_logout(self) -> None:
        created = main.register_account(
            main.RegisterRequest.model_validate(
                {
                    "display_name": "  Aarav Student  ",
                    "email": "  STUDENT@example.com ",
                    "password": "correct horse battery staple",
                    "college": "Example College",
                    "course": "Computer Science",
                    "interests": "Security internships",
                }
            )
        )
        self.assertEqual(created["profile"]["display_name"], "Aarav Student")
        self.assertEqual(created["profile"]["email"], "student@example.com")
        self.assertNotIn("password", created["profile"])
        token = created["access_token"]
        authorization = f"Bearer {token}"

        profile = main.get_current_profile(authorization)
        self.assertEqual(profile["profile"]["college"], "Example College")

        updated = main.update_current_profile(
            main.ProfileUpdateRequest.model_validate(
                {"college": "New College", "course": "Cybersecurity"}
            ),
            authorization,
        )
        self.assertEqual(updated["profile"]["college"], "New College")
        self.assertEqual(updated["profile"]["course"], "Cybersecurity")

        login = main.login_account(
            main.AccountRequest.model_validate(
                {
                    "email": "student@example.com",
                    "password": "correct horse battery staple",
                }
            )
        )
        self.assertNotEqual(login["access_token"], token)

        logout = main.logout_account(authorization)
        self.assertEqual(logout["status"], "signed_out")
        with self.assertRaises(HTTPException) as expired_session:
            main.get_current_profile(authorization)
        self.assertEqual(expired_session.exception.status_code, 401)

    def test_duplicate_account_and_invalid_login_are_rejected(self) -> None:
        payload = main.RegisterRequest.model_validate(
            {
                "display_name": "Student",
                "email": "student@example.com",
                "password": "correct horse battery staple",
            }
        )
        main.register_account(payload)
        duplicate = main.RegisterRequest.model_validate(
            {
                "display_name": "Student",
                "email": "STUDENT@example.com",
                "password": "correct horse battery staple",
            }
        )
        with self.assertRaises(HTTPException) as duplicate_error:
            main.register_account(duplicate)
        self.assertEqual(duplicate_error.exception.status_code, 409)

        invalid_login = main.AccountRequest.model_validate(
            {"email": "student@example.com", "password": "incorrect password"}
        )
        with self.assertRaises(HTTPException) as login_error:
            main.login_account(invalid_login)
        self.assertEqual(login_error.exception.status_code, 401)

    def test_password_length_and_profile_authentication_are_enforced(self) -> None:
        with self.assertRaises(ValidationError):
            main.RegisterRequest.model_validate(
                {
                    "display_name": "Student",
                    "email": "student@example.com",
                    "password": "short",
                }
            )
        with self.assertRaises(ValidationError):
            main.RegisterRequest.model_validate(
                {
                    "display_name": "   ",
                    "email": "student@example.com",
                    "password": "correct horse battery staple",
                }
            )
        with self.assertRaises(ValidationError):
            main.ProfileUpdateRequest.model_validate({"display_name": "   "})
        with self.assertRaises(HTTPException) as unauthenticated:
            main.get_current_profile(None)
        self.assertEqual(unauthenticated.exception.status_code, 401)

    def test_analysis_saves_only_with_explicit_opt_in_and_is_user_scoped(self) -> None:
        first = main.register_account(
            main.RegisterRequest.model_validate(
                {
                    "display_name": "First Student",
                    "email": "first@example.com",
                    "password": "correct horse battery staple",
                }
            )
        )
        second = main.register_account(
            main.RegisterRequest.model_validate(
                {
                    "display_name": "Second Student",
                    "email": "second@example.com",
                    "password": "another secure password",
                }
            )
        )

        analysis = main.AnalyzeRequest.model_validate(
            {
                "offer_text": "Acme Ltd offers an intern role for 8 weeks. Pay a registration fee.",
                "company_name": "Acme Ltd",
            }
        )
        not_saved = main.analyze(analysis)
        self.assertFalse(not_saved["saved_to_account"])
        unpersisted_with_invalid_token = main.analyze(analysis, "Bearer invalid")
        self.assertFalse(unpersisted_with_invalid_token["saved_to_account"])
        self.assertEqual(
            main.list_saved_reports(
                f"Bearer {first['access_token']}",
                limit=50,
            )["reports"],
            [],
        )

        save_request = main.AnalyzeRequest.model_validate(
            {
                "offer_text": "Acme Ltd offers an intern role for 8 weeks. Pay a registration fee.",
                "company_name": "Acme Ltd",
                "save_report": True,
            }
        )
        with self.assertRaises(HTTPException) as missing_auth:
            main.analyze(save_request, None)
        self.assertEqual(missing_auth.exception.status_code, 401)

        saved = main.analyze(
            save_request,
            f"Bearer {first['access_token']}",
        )
        self.assertTrue(saved["saved_to_account"])
        first_reports = main.list_saved_reports(
            f"Bearer {first['access_token']}",
            limit=50,
        )
        second_reports = main.list_saved_reports(
            f"Bearer {second['access_token']}",
            limit=50,
        )
        self.assertEqual(len(first_reports["reports"]), 1)
        self.assertEqual(first_reports["reports"][0]["report"], saved)
        self.assertEqual(second_reports["reports"], [])

        with self.assertRaises(HTTPException) as wrong_owner:
            main.delete_saved_report(
                saved["report_reference"],
                f"Bearer {second['access_token']}",
            )
        self.assertEqual(wrong_owner.exception.status_code, 404)
        deleted = main.delete_saved_report(
            saved["report_reference"],
            f"Bearer {first['access_token']}",
        )
        self.assertEqual(deleted["status"], "deleted")
        self.assertEqual(
            main.list_saved_reports(
                f"Bearer {first['access_token']}",
                limit=50,
            )["reports"],
            [],
        )


if __name__ == "__main__":
    unittest.main()
