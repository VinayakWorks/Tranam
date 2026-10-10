"""Rule-based internship offer analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern


@dataclass(frozen=True)
class Indicator:
    name: str
    pattern: Pattern[str]
    points: int
    severity: str
    why: str
    risk: str
    action: str
    context_pattern: Pattern[str] | None = None


INDICATORS = (
    Indicator(
        "Registration or processing fee",
        re.compile(
            r"\b(?:registration|processing|application|security)\s+"
            r"(?:fee|charge|deposit)\b|\bpay\s+(?:a\s+|the\s+)?"
            r"(?:fee|amount|deposit)\b|\bpayment required\b|"
            r"\bdeposit to confirm\b",
            re.IGNORECASE,
        ),
        30,
        "Critical",
        "Legitimate employers generally do not require candidates to pay to secure an internship.",
        "An upfront payment request may be used to collect money without providing a real role.",
        "Do not pay. Contact the organization using details from its official website.",
    ),
    Indicator(
        "Guaranteed selection or job placement",
        re.compile(
            r"\b(?:guaranteed\s+(?:job|placement|selection|internship)|"
            r"100%\s+placement|job guaranteed|assured placement)\b",
            re.IGNORECASE,
        ),
        15,
        "High",
        "Guaranteed hiring or placement claims can create unrealistic expectations and pressure applicants.",
        "Such promises may be used to sell paid courses, certificates, or recruitment services.",
        "Ask for written selection terms and verify the claim with the organization directly.",
    ),
    Indicator(
        "Unrealistic stipend or earnings promise",
        re.compile(
            r"\b(?:earn|salary|stipend|income).{0,45}"
            r"(?:\b[1-9]\d{2},?\d{3,}\b|"
            r"\b[1-9]\d{0,2},\d{2},\d{3}\b|"
            r"\b\d+\s*(?:lakh|lakhs|crore|crores)\b)"
            r".{0,30}(?:per month|monthly|every month)?",
            re.IGNORECASE,
        ),
        12,
        "Medium",
        "Very large or vague earnings claims may not reflect a credible internship compensation offer.",
        "Inflated compensation promises can attract applicants to unrelated fees or data collection.",
        "Request written stipend terms and compare them with the role and duration.",
        re.compile(
            r"\b(?:guaranteed|no interview|without interview|instant selection|"
            r"no experience required|earn instantly|daily income|easy money)\b",
            re.IGNORECASE,
        ),
    ),
    Indicator(
        "Urgent payment or pressure tactics",
        re.compile(
            r"\b(?:pay immediately|urgent payment|limited time offer|act now|"
            r"pay today|immediate payment|offer expires today)\b",
            re.IGNORECASE,
        ),
        15,
        "High",
        "Urgency can discourage applicants from checking the employer or reading the terms carefully.",
        "Pressure may be used to rush a payment or disclosure of personal information.",
        "Pause. Do not pay or share information until you have verified the opportunity.",
    ),
    Indicator(
        "Request for sensitive information",
        re.compile(
            r"\b(?:send|share|submit|provide|tell us|enter).{0,45}"
            r"\b(?:password|otp|one.time password|bank pin|card cvv|"
            r"card security code|online banking credentials|bank account number|"
            r"credit card number|debit card number|aadhaar number|pan number|"
            r"passport number)\b",
            re.IGNORECASE,
        ),
        30,
        "Critical",
        "Recruiters should not need passwords, OTPs, banking PINs, or card security codes.",
        "These details can enable account takeover, unauthorized transactions, or identity theft.",
        "Do not disclose the information. If already shared, contact your bank or provider immediately.",
    ),
    Indicator(
        "Suspicious communication channel",
        re.compile(
            r"\b(?:whatsapp only|telegram only|contact only on whatsapp|"
            r"personal gmail|no official website)\b",
            re.IGNORECASE,
        ),
        12,
        "Medium",
        "A recruiter who avoids verifiable company contact channels is harder to authenticate.",
        "Impersonators may use personal accounts to avoid organizational oversight.",
        "Confirm the recruiter through the organization's independently located official channels.",
    ),
    Indicator(
        "Pay to receive a certificate",
        re.compile(
            r"\b(?:pay|payment|fee).{0,35}\b(?:certificate|certification)\b|"
            r"\b(?:certificate|certification).{0,35}\b(?:pay|payment|fee)\b",
            re.IGNORECASE,
        ),
        20,
        "High",
        "A required payment for an internship certificate may indicate a pay-to-participate scheme.",
        "Applicants may pay for a certificate or placement that is not delivered or recognized.",
        "Verify the program and certificate issuer independently before paying.",
    ),
    Indicator(
        "Unverified link or form",
        re.compile(
            r"\b(?:unknown link|unverified link|click this link|"
            r"fill this google form|submit details through this form|"
            r"enter your details in this form)\b",
            re.IGNORECASE,
        ),
        5,
        "Low",
        "A link or form cannot be authenticated by this text-only scan.",
        "A destination that has not been checked may lead to an unrelated or unsafe site.",
        "Inspect the destination and navigate to the company's website independently.",
    ),
    Indicator(
        "URL shortener in provided link",
        re.compile(
            r"\b(?:https?://)?(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy)\b",
            re.IGNORECASE,
        ),
        5,
        "Low",
        "A shortened URL hides the final destination from the reader.",
        "The destination cannot be assessed from the shortened address alone; this does not establish that it is malicious.",
        "Confirm the destination through the company's official website before opening it.",
    ),
    Indicator(
        "Free email provider used for recruitment",
        re.compile(
            r"\b[A-Z0-9._%+-]+@(?:gmail\.com|yahoo\.com|outlook\.com|"
            r"hotmail\.com|protonmail\.com)\b",
            re.IGNORECASE,
        ),
        15,
        "Medium",
        "A free email address is not tied to a company domain and does not establish recruiter identity.",
        "Impersonators can create free accounts that resemble recruiter contacts.",
        "Verify the recruiter using contact information published on the company's official site.",
    ),
    Indicator(
        "Suspicious application form",
        re.compile(
            r"\b(?:google forms?|forms\.gle|docs\.google\.com/forms|"
            r"whatsapp.{0,20}form|telegram.{0,20}form)\b",
            re.IGNORECASE,
        ),
        12,
        "Medium",
        "A general-purpose form is not proof of an official company application.",
        "Forms may collect more personal information than an application needs.",
        "Confirm the application process through the company's official website.",
        re.compile(
            r"\b(?:registration|processing|application)\s+(?:fee|charge|deposit)\b|"
            r"\b(?:pay|payment).{0,35}\b(?:form|application|certificate)\b|"
            r"\b(?:otp|one.time password|password|bank pin|card cvv|"
            r"bank account number|credit card number|debit card number|"
            r"aadhaar number|pan number|passport number)\b",
            re.IGNORECASE,
        ),
    ),
)

COMPANY_TERMS = re.compile(
    r"\b(?:company|employer|organization|organisation|inc\.?|ltd\.?|llc|corp\.?)\b",
    re.IGNORECASE,
)
INTERNSHIP_TERMS = re.compile(
    r"\b(?:role|responsibilit(?:y|ies)|duties|tasks|duration|months|weeks|"
    r"hours|per week|stipend|paid|unpaid)\b",
    re.IGNORECASE,
)
STIPEND_TERMS = re.compile(
    r"\b(?:stipend|salary|compensation|paid|unpaid|inr|rs\.?)\b|₹",
    re.IGNORECASE,
)
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
URL_PATTERN = re.compile(r"\bhttps?://\S+", re.IGNORECASE)


def _is_negated(text: str, match: re.Match[str]) -> bool:
    preceding_text = text[max(0, match.start() - 42) : match.start()]
    following_text = text[match.end() : match.end() + 42]
    negation = re.compile(
        r"(?:\bno\b|\bnot\b|\bnever\b|\bdon't\b|\bdo not\b|"
        r"\bdoesn't\b|\bdoes not\b|\bwithout\b|\bavoid\b)[^.!?\n]{0,36}$",
        re.IGNORECASE,
    )
    denial_after = re.compile(
        r"^\s*(?:(?:is|are|was|were)\s+)?"
        r"(?:not required|not requested|not necessary|not needed|waived)\b",
        re.IGNORECASE,
    )
    return bool(negation.search(preceding_text) or denial_after.search(following_text))


def _risk_classification(score: int) -> dict[str, str]:
    if score >= 70:
        return {
            "key": "critical",
            "label": "Critical",
            "summary": (
                "Multiple serious warning signs were detected. Stop before paying "
                "or sharing information and independently verify the opportunity."
            ),
        }
    if score >= 40:
        return {
            "key": "high",
            "label": "High",
            "summary": (
                "Several warning signs were detected. Verify the recruiter and "
                "company through official channels before proceeding."
            ),
        }
    if score >= 20:
        return {
            "key": "medium",
            "label": "Medium",
            "summary": (
                "Some warning signs were detected. Review the evidence and verify "
                "the offer before proceeding."
            ),
        }
    return {
        "key": "low",
        "label": "Low",
        "summary": (
            "Few matching patterns were found in the submitted text. This does "
            "not establish that the offer is genuine or safe."
        ),
    }


def _missing_indicator(name: str, points: int, severity: str, why: str, risk: str, action: str) -> dict:
    return {
        "name": name,
        "points": points,
        "severity": severity,
        "why": why,
        "risk": risk,
        "action": action,
        "excerpt": "",
    }


def _build_checklist(
    text: str,
    company_name: str,
    company_link: str,
    matches: list[dict],
) -> list[dict[str, str]]:
    names = {match["name"] for match in matches}
    has_internship_terms = bool(INTERNSHIP_TERMS.search(text))
    has_stipend_terms = bool(STIPEND_TERMS.search(text))
    has_email = bool(EMAIL_PATTERN.search(text))
    has_link = bool(company_link or URL_PATTERN.search(text))
    suspicious_link = bool(
        names.intersection(
            {
                "Unverified link or form",
                "URL shortener in provided link",
                "Suspicious application form",
            }
        )
    )
    payment_flagged = bool(
        names.intersection({"Registration or processing fee", "Pay to receive a certificate"})
    )
    sensitive_info_flagged = "Request for sensitive information" in names

    return [
        {
            "name": "Company identity",
            "status": "warning" if "No clear company identity in submitted details" in names else "not-checked",
            "detail": (
                "No clear organization name was found; no registry was checked."
                if "No clear company identity in submitted details" in names
                else f"{'The submitted name was not checked against an official registry.' if company_name else 'No company name was provided; no registry was checked.'}"
            ),
        },
        {
            "name": "Recruiter identity",
            "status": "not-checked",
            "detail": "Recruiter identity and employment relationship were not externally verified.",
        },
        {
            "name": "Official website",
            "status": "not-checked",
            "detail": "No website was opened or checked against an official company source.",
        },
        {
            "name": "Email domain",
            "status": "warning" if "Free email provider used for recruitment" in names else "not-checked",
            "detail": (
                "A free email provider appears in the text; sender ownership was not verified."
                if "Free email provider used for recruitment" in names
                else "An email address appears in the text, but domain ownership was not checked."
                if has_email
                else "No recruiter email was available to assess."
            ),
        },
        {
            "name": "Payment requests",
            "status": "failed" if payment_flagged else "passed",
            "detail": (
                "A payment-related warning pattern was found."
                if payment_flagged
                else "No configured payment-request pattern matched the submitted text."
            ),
        },
        {
            "name": "Internship description",
            "status": "passed" if has_internship_terms else "warning",
            "detail": (
                "At least one role, responsibility, or term detail appears in the text."
                if has_internship_terms
                else "No clear role, responsibilities, duration, or hours were detected."
            ),
        },
        {
            "name": "Stipend and benefits",
            "status": "passed" if has_stipend_terms else "warning",
            "detail": (
                "Compensation wording appears; the amount was not validated."
                if has_stipend_terms
                else "No stipend or compensation terms were detected."
            ),
        },
        {
            "name": "Application link",
            "status": "warning" if suspicious_link else "not-checked",
            "detail": (
                "A link or form pattern needs review; no destination was opened."
                if suspicious_link
                else "A link was provided but not opened or checked."
                if has_link
                else "No application link was provided."
            ),
        },
        {
            "name": "Offer letter consistency",
            "status": "not-checked",
            "detail": "The offer was not compared with an independently sourced company document.",
        },
        {
            "name": "Personal information requests",
            "status": "failed" if sensitive_info_flagged else "passed",
            "detail": (
                "A request for credentials or sensitive account information was detected."
                if sensitive_info_flagged
                else "No configured credential-request pattern matched the submitted text."
            ),
        },
    ]


def analyze_offer(
    offer_text: str,
    company_name: str = "",
    company_link: str = "",
    source_filename: str = "",
) -> dict:
    """Analyze supplied offer text and return a report-ready structured result."""
    text = offer_text.strip()
    analysis_text = "\n".join(part for part in (text, company_link.strip()) if part)
    matches: list[dict] = []

    for indicator in INDICATORS:
        found = indicator.pattern.search(analysis_text)
        has_required_context = (
            indicator.context_pattern is None
            or indicator.context_pattern.search(analysis_text) is not None
        )
        if found and has_required_context and not _is_negated(analysis_text, found):
            matches.append(
                {
                    "name": indicator.name,
                    "points": indicator.points,
                    "severity": indicator.severity,
                    "why": indicator.why,
                    "risk": indicator.risk,
                    "action": indicator.action,
                    "excerpt": found.group(0),
                }
            )

    if not company_name.strip() and not COMPANY_TERMS.search(text):
        matches.append(
            _missing_indicator(
                "No clear company identity in submitted details",
                12,
                "High",
                "The submitted text and company-name field do not identify a clear organization.",
                "Without a named organization, it is difficult to verify who is offering the role.",
                "Request the organization's legal name and verify it through trusted official sources.",
            )
        )

    if not INTERNSHIP_TERMS.search(text):
        matches.append(
            _missing_indicator(
                "Internship responsibilities or terms are unclear",
                8,
                "Medium",
                "The submitted text does not clearly state the work, duration, hours, or compensation terms.",
                "Unclear terms make it harder to assess whether the opportunity is genuine and suitable.",
                "Request written responsibilities, duration, working hours, stipend, and employment terms.",
            )
        )

    score = min(sum(match["points"] for match in matches), 100)
    classification = _risk_classification(score)
    checklist = _build_checklist(analysis_text, company_name, company_link, matches)
    recommendations = list(dict.fromkeys(match["action"] for match in matches))
    if score >= 20:
        recommendations.append("Pause before proceeding and resolve the warning signs first.")
    recommendations.append(
        "Verify the employer and recruiter using contact details obtained independently."
    )
    if not matches:
        recommendations.append(
            "Confirm the internship responsibilities, duration, stipend, and terms in writing."
        )

    severity_counts = {
        severity.lower(): sum(match["severity"] == severity for match in matches)
        for severity in ("Critical", "High", "Medium", "Low")
    }
    external_checks = sum(item["status"] == "not-checked" for item in checklist)
    summary = (
        f"{len(matches)} warning indicator(s) were detected from submitted text "
        f"and missing details. {classification['summary']}"
        if matches
        else classification["summary"]
    )

    return {
        "score": score,
        "classification": classification,
        "summary": summary,
        "warning_count": len(matches),
        "checks_performed": len(INDICATORS) + 2,
        "external_checks_not_performed": external_checks,
        "matches": matches,
        "severity_counts": severity_counts,
        "checklist": checklist,
        "recommendations": recommendations,
        "source_filename": source_filename.strip() or "Pasted offer text",
        "analysis_status": "Completed locally by the configured Trāṇam backend",
        "disclaimer": (
            "This rule-based score is an indicative estimate, not a statistically "
            "validated probability and not proof that an offer is fraudulent or genuine."
        ),
    }
