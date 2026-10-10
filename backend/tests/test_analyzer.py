import unittest

from services.analyzer import analyze_offer


class AnalyzeOfferTests(unittest.TestCase):
    def test_detects_fee_and_credential_request_with_evidence(self) -> None:
        report = analyze_offer(
            "Acme Ltd offers a software intern role. Pay a registration fee today. "
            "Pay today. Send your OTP to confirm.",
            company_name="Acme Ltd",
        )

        names = {finding["name"] for finding in report["matches"]}
        self.assertIn("Registration or processing fee", names)
        self.assertIn("Request for sensitive information", names)
        self.assertEqual(report["classification"]["label"], "Critical")
        self.assertEqual(report["score"], 75)
        self.assertTrue(all(finding["excerpt"] for finding in report["matches"]))

    def test_does_not_flag_negated_fee_or_otp_text(self) -> None:
        report = analyze_offer(
            "Acme Ltd offers a software internship for 8 weeks. "
            "A registration fee is not required; never share your OTP.",
            company_name="Acme Ltd",
        )

        names = {finding["name"] for finding in report["matches"]}
        self.assertNotIn("Registration or processing fee", names)
        self.assertNotIn("Request for sensitive information", names)
        self.assertEqual(report["score"], 0)

    def test_marks_external_verification_as_not_checked(self) -> None:
        report = analyze_offer(
            "Acme Ltd offers an intern role for 8 weeks with a stipend.",
            company_name="Acme Ltd",
        )

        checklist = {item["name"]: item for item in report["checklist"]}
        self.assertEqual(checklist["Company identity"]["status"], "not-checked")
        self.assertEqual(checklist["Recruiter identity"]["status"], "not-checked")
        self.assertEqual(checklist["Official website"]["status"], "not-checked")
        self.assertEqual(checklist["Payment requests"]["status"], "passed")

    def test_reports_missing_details_without_claiming_external_checks(self) -> None:
        report = analyze_offer("We are hiring now.", company_name="")

        names = {finding["name"] for finding in report["matches"]}
        self.assertIn("No clear company identity in submitted details", names)
        self.assertIn("Internship responsibilities or terms are unclear", names)
        self.assertGreater(report["external_checks_not_performed"], 0)

    def test_uses_requested_risk_thresholds(self) -> None:
        cases = (
            ("A" * 20, "Low"),
            ("Pay an application fee. " * 1, "Medium"),
            ("Pay a registration fee and share your OTP now.", "High"),
            (
                "Pay a registration fee now. Send your OTP and password. "
                "Pay a certification fee and use this bit.ly link. "
                "Earn 5 lakhs per month, guaranteed selection.",
                "Critical",
            ),
        )

        for offer_text, expected in cases:
            with self.subTest(expected=expected):
                report = analyze_offer(offer_text, company_name="Example Ltd")
                self.assertEqual(report["classification"]["label"], expected)

    def test_stipend_and_form_findings_require_context(self) -> None:
        ordinary_offer = analyze_offer(
            "Example Ltd offers a work from home software intern role for 8 weeks "
            "with a stipend of 1,20,000 per month. Apply through Google Forms.",
            company_name="Example Ltd",
        )
        ordinary_names = {finding["name"] for finding in ordinary_offer["matches"]}
        self.assertNotIn("Unrealistic stipend or earnings promise", ordinary_names)
        self.assertNotIn("Suspicious application form", ordinary_names)

        concerning_offer = analyze_offer(
            "Example Ltd offers an intern role for 8 weeks with a guaranteed stipend "
            "of 5 lakhs per month. "
            "Submit your OTP in this Google Form.",
            company_name="Example Ltd",
        )
        concerning_names = {finding["name"] for finding in concerning_offer["matches"]}
        self.assertIn("Unrealistic stipend or earnings promise", concerning_names)
        self.assertIn("Suspicious application form", concerning_names)
        self.assertIn("Request for sensitive information", concerning_names)

    def test_shortened_url_is_a_low_severity_review_signal_not_a_fraud_claim(self) -> None:
        report = analyze_offer(
            "Example Ltd offers an intern role for 8 weeks. Apply at https://bit.ly/example.",
            company_name="Example Ltd",
        )
        finding = next(
            item
            for item in report["matches"]
            if item["name"] == "URL shortener in provided link"
        )
        self.assertEqual(finding["severity"], "Low")
        self.assertEqual(finding["points"], 5)
        self.assertIn("does not establish that it is malicious", finding["risk"])


if __name__ == "__main__":
    unittest.main()
