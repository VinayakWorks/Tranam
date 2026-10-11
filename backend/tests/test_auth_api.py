import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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

    @patch.object(main, "_send_password_reset_email")
    def test_password_reset_is_one_time_and_revokes_existing_sessions(
        self,
        send_reset_email,
    ) -> None:
        account = main.register_account(
            main.RegisterRequest.model_validate(
                {
                    "display_name": "Password Reset",
                    "email": "reset@example.com",
                    "password": "original secure password",
                }
            )
        )
        second_session = main.login_account(
            main.AccountRequest.model_validate(
                {
                    "email": "reset@example.com",
                    "password": "original secure password",
                }
            )
        )
        sent_tokens = []
        send_reset_email.side_effect = lambda email, token: sent_tokens.append(token)
        email_config = {
            "SMTP_HOST": "smtp.example.com",
            "SMTP_FROM_EMAIL": "accounts@example.com",
            "SMTP_USERNAME": "",
            "SMTP_PASSWORD": "",
        }
        with patch.multiple(main, **email_config):
            result = main.request_password_reset(
                main.EmailRequest.model_validate({"email": " RESET@example.com "})
            )
            self.assertIn("If an account exists", result["message"])
            self.assertEqual(send_reset_email.call_args.args[0], "reset@example.com")
            unknown_result = main.request_password_reset(
                main.EmailRequest.model_validate({"email": "missing@example.com"})
            )
            self.assertEqual(unknown_result, result)
            self.assertEqual(send_reset_email.call_count, 1)

            main.request_password_reset(
                main.EmailRequest.model_validate({"email": "reset@example.com"})
            )
            self.assertEqual(send_reset_email.call_count, 1)

            token = sent_tokens[0]
            completed = main.confirm_password_reset(
                main.PasswordResetRequest.model_validate(
                    {"token": token, "password": "brand new secure password"}
                )
            )
            self.assertEqual(completed["status"], "password_updated")
            for session in (account["access_token"], second_session["access_token"]):
                with self.assertRaises(HTTPException) as revoked_session:
                    main.get_current_profile(f"Bearer {session}")
                self.assertEqual(revoked_session.exception.status_code, 401)

            with self.assertRaises(HTTPException) as used_token:
                main.confirm_password_reset(
                    main.PasswordResetRequest.model_validate(
                        {"token": token, "password": "another new secure password"}
                    )
                )
            self.assertEqual(used_token.exception.status_code, 400)
            with self.assertRaises(HTTPException) as old_password:
                main.login_account(
                    main.AccountRequest.model_validate(
                        {
                            "email": "reset@example.com",
                            "password": "original secure password",
                        }
                    )
                )
            self.assertEqual(old_password.exception.status_code, 401)
            signed_in = main.login_account(
                main.AccountRequest.model_validate(
                    {
                        "email": "reset@example.com",
                        "password": "brand new secure password",
                    }
                )
            )
            self.assertEqual(signed_in["profile"]["email"], "reset@example.com")

    def test_password_reset_requires_configured_email_delivery(self) -> None:
        with patch.multiple(
            main,
            SMTP_HOST="",
            SMTP_FROM_EMAIL="",
            SMTP_USERNAME="",
            SMTP_PASSWORD="",
        ):
            with self.assertRaises(HTTPException) as not_configured:
                main.request_password_reset(
                    main.EmailRequest.model_validate(
                        {"email": "unknown@example.com"}
                    )
                )
        self.assertEqual(not_configured.exception.status_code, 503)

    @patch.object(main, "_send_password_reset_email")
    def test_failed_reset_email_does_not_leave_a_usable_token(
        self,
        send_reset_email,
    ) -> None:
        main.register_account(
            main.RegisterRequest.model_validate(
                {
                    "display_name": "Email Failure",
                    "email": "email-failure@example.com",
                    "password": "original secure password",
                }
            )
        )
        sent_tokens = []

        def fail_sending(email, token):
            sent_tokens.append(token)
            raise OSError("SMTP is unavailable")

        send_reset_email.side_effect = fail_sending
        with patch.multiple(
            main,
            SMTP_HOST="smtp.example.com",
            SMTP_FROM_EMAIL="accounts@example.com",
            SMTP_USERNAME="",
            SMTP_PASSWORD="",
        ):
            with self.assertRaises(HTTPException) as send_failure:
                main.request_password_reset(
                    main.EmailRequest.model_validate(
                        {"email": "email-failure@example.com"}
                    )
                )
        self.assertEqual(send_failure.exception.status_code, 503)
        with self.assertRaises(HTTPException) as unusable_token:
            main.confirm_password_reset(
                main.PasswordResetRequest.model_validate(
                    {
                        "token": sent_tokens[0],
                        "password": "brand new secure password",
                    }
                )
            )
        self.assertEqual(unusable_token.exception.status_code, 400)

    def test_analysis_requires_authentication_and_saves_only_with_opt_in(self) -> None:
        account = main.register_account(
            main.RegisterRequest.model_validate(
                {
                    "display_name": "Offer Reviewer",
                    "email": "reviewer@example.com",
                    "password": "correct horse battery staple",
                }
            )
        )
        another_account = main.register_account(
            main.RegisterRequest.model_validate(
                {
                    "display_name": "Another Reviewer",
                    "email": "another@example.com",
                    "password": "another secure password",
                }
            )
        )
        request = main.AnalyzeRequest.model_validate(
            {
                "offer_text": "Acme Ltd offers an intern role for 8 weeks. Pay a registration fee.",
                "company_name": "Acme Ltd",
            }
        )
        with self.assertRaises(HTTPException) as missing_auth:
            main.analyze(request, None)
        self.assertEqual(missing_auth.exception.status_code, 401)

        authorization = " ".join(("Bearer", account["access_token"]))
        with self.assertRaises(HTTPException) as invalid_auth:
            main.analyze(request, " ".join(("Bearer", "invalid-token")))
        self.assertEqual(invalid_auth.exception.status_code, 401)
        not_saved = main.analyze(request, authorization)
        self.assertFalse(not_saved["saved_to_account"])
        self.assertEqual(
            main.list_saved_reports(authorization, limit=50)["reports"],
            [],
        )

        save_request = main.AnalyzeRequest.model_validate(
            {
                "offer_text": "Acme Ltd offers an intern role for 8 weeks. Pay a registration fee.",
                "company_name": "Acme Ltd",
                "save_report": True,
            }
        )
        saved = main.analyze(save_request, authorization)
        self.assertTrue(saved["saved_to_account"])
        self.assertEqual(
            main.list_saved_reports(authorization, limit=50)["reports"][0]["report"],
            saved,
        )
        another_authorization = " ".join(("Bearer", another_account["access_token"]))
        self.assertEqual(
            main.list_saved_reports(another_authorization, limit=50)["reports"],
            [],
        )
        with self.assertRaises(HTTPException) as wrong_owner:
            main.delete_saved_report(
                saved["report_reference"],
                another_authorization,
            )
        self.assertEqual(wrong_owner.exception.status_code, 404)
        deleted = main.delete_saved_report(
            saved["report_reference"],
            authorization,
        )
        self.assertEqual(deleted["status"], "deleted")
        self.assertEqual(
            main.list_saved_reports(authorization, limit=50)["reports"],
            [],
        )

    @unittest.skip("The pre-authentication coverage is superseded by the authenticated analysis test.")
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
        with self.assertRaises(HTTPException) as missing_auth:
            main.analyze(analysis)
        self.assertEqual(missing_auth.exception.status_code, 401)
        not_saved = main.analyze(analysis, f"Bearer {first['access_token']}")
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
