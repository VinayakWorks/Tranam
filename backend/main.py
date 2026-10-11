"""FastAPI application for the Trāṇam internship analyzer."""

from __future__ import annotations

import os
import re
import smtplib
import sqlite3
import ssl
from email.message import EmailMessage
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator

from services.accounts import (
    AccountStore,
    DuplicateEmailError,
    InvalidCredentialsError,
    InvalidSessionError,
)
from services.analyzer import analyze_offer


BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(BACKEND_DIR / ".env")


def _positive_int(name: str, default: int) -> int:
    value = os.getenv(name, str(default))
    try:
        parsed = int(value)
    except ValueError as error:
        raise RuntimeError(f"{name} must be a positive integer.") from error
    if parsed < 1:
        raise RuntimeError(f"{name} must be a positive integer.")
    return parsed


APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
API_HOST = os.getenv("API_HOST", "127.0.0.1").strip()
API_PORT = _positive_int("API_PORT", 8000)
MAX_OFFER_CHARACTERS = _positive_int("MAX_OFFER_CHARACTERS", 100_000)
AUTH_SESSION_HOURS = _positive_int("AUTH_SESSION_HOURS", 24)
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = _positive_int("SMTP_PORT", 587)
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "").strip()
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").strip().lower() in {"1", "true", "yes"}
FRONTEND_BASE_URL = os.getenv(
    "FRONTEND_BASE_URL",
    "http://127.0.0.1:5500",
).strip().rstrip("/")
_database_setting = Path(os.getenv("DATABASE_PATH", "tranam.sqlite3"))
DATABASE_PATH = (
    _database_setting
    if _database_setting.is_absolute()
    else BACKEND_DIR / _database_setting
)
ACCOUNT_STORE = AccountStore(DATABASE_PATH, session_hours=AUTH_SESSION_HOURS)
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://127.0.0.1:5500,http://localhost:5500",
    ).split(",")
    if origin.strip()
]


class AccountRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=254)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        email = value.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise ValueError("Enter a valid email address.")
        return email


class EmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=254)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        email = value.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise ValueError("Enter a valid email address.")
        return email


class PasswordResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=20, max_length=128)
    password: str = Field(min_length=12, max_length=128)


class RegisterRequest(AccountRequest):
    display_name: str = Field(min_length=1, max_length=100)
    college: str = Field(default="", max_length=160)
    course: str = Field(default="", max_length=120)
    interests: str = Field(default="", max_length=500)

    @field_validator("display_name")
    @classmethod
    def require_display_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Enter your name.")
        return normalized

    @field_validator("college", "course", "interests")
    @classmethod
    def trim_profile_text(cls, value: str) -> str:
        return value.strip()


class ProfileUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    college: str | None = Field(default=None, max_length=160)
    course: str | None = Field(default=None, max_length=120)
    interests: str | None = Field(default=None, max_length=500)

    @field_validator("display_name", "college", "course", "interests")
    @classmethod
    def trim_optional_profile_text(cls, value: str | None) -> str | None:
        return value.strip() if value is not None else None

    @field_validator("display_name")
    @classmethod
    def require_nonempty_updated_name(cls, value: str | None) -> str | None:
        if value is not None and not value:
            raise ValueError("Enter your name.")
        return value


def _session_token(authorization: str | None) -> str:
    scheme, separator, token = (authorization or "").partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sign in to access your profile.",
        )
    return token.strip()


@asynccontextmanager
async def lifespan(_: FastAPI):
    ACCOUNT_STORE.initialize()
    yield


class AnalyzeRequest(BaseModel):
    """Text and optional metadata submitted for an in-browser extracted offer."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    offer_text: str = Field(min_length=20, max_length=MAX_OFFER_CHARACTERS)
    company_name: str = Field(default="", max_length=200)
    company_link: str = Field(default="", max_length=2048)
    source_filename: str = Field(default="", max_length=255)
    save_report: bool = False

    @field_validator("source_filename")
    @classmethod
    def keep_filename_only(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        return normalized.rsplit("/", maxsplit=1)[-1]


app = FastAPI(
    title="Trāṇam API",
    description=(
        "Local rule-based internship offer assessment. The API does not "
        "independently verify employers, recruiters, websites, or documents."
    ),
    version="1.0.0",
    debug=APP_ENV == "development",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.get("/api/health", tags=["system"])
def health_check() -> dict[str, str]:
    """Return service status without exposing configuration or user data."""
    return {"status": "ok", "service": "tranam-api"}


@app.post("/api/analyze", tags=["analysis"])
def analyze(
    request: AnalyzeRequest,
    authorization: str | None = Header(default=None),
) -> dict:
    """Analyze submitted text for an authenticated account."""
    profile = _current_profile(authorization)
    report = analyze_offer(
        offer_text=request.offer_text,
        company_name=request.company_name,
        company_link=request.company_link,
        source_filename=request.source_filename,
    )
    generated_at = datetime.now(timezone.utc)
    report["report_reference"] = (
        f"TN-{generated_at:%Y%m%d}-{uuid4().hex[:8].upper()}"
    )
    report["generated_at"] = generated_at.isoformat()
    report["company_name"] = request.company_name
    report["company_link"] = request.company_link

    if request.save_report:
        report["saved_to_account"] = True
        try:
            ACCOUNT_STORE.save_report(profile["id"], report)
        except sqlite3.IntegrityError as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This report has already been saved.",
            ) from error
    else:
        report["saved_to_account"] = False
    return report


def _current_profile(authorization: str | None) -> dict:
    token = _session_token(authorization)
    try:
        return ACCOUNT_STORE.get_profile(token)
    except InvalidSessionError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your session expired. Sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error


def _auth_response(profile: dict, token: str) -> dict:
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": AUTH_SESSION_HOURS * 60 * 60,
        "profile": profile,
    }


def _email_delivery_configured() -> bool:
    return bool(
        SMTP_HOST
        and SMTP_FROM_EMAIL
        and bool(SMTP_USERNAME) == bool(SMTP_PASSWORD)
    )


def _send_password_reset_email(email: str, token: str) -> None:
    reset_url = f"{FRONTEND_BASE_URL}/#account?reset_token={quote(token)}"
    message = EmailMessage()
    message["Subject"] = "Reset your Trāṇam password"
    message["From"] = SMTP_FROM_EMAIL
    message["To"] = email
    message.set_content(
        "A password reset was requested for your Trāṇam account.\n\n"
        f"Use this link within 30 minutes to choose a new password:\n{reset_url}\n\n"
        "If you did not request this, you can ignore this email."
    )

    context = ssl.create_default_context()
    if SMTP_USE_SSL:
        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            timeout=15,
            context=context,
        ) as server:
            if SMTP_USERNAME:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(message)
        return

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        server.starttls(context=context)
        if SMTP_USERNAME:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(message)


@app.post(
    "/api/auth/password-reset/request",
    tags=["accounts"],
    status_code=status.HTTP_202_ACCEPTED,
)
def request_password_reset(request: EmailRequest) -> dict[str, str]:
    if not _email_delivery_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Password reset email is not configured. Contact the Trāṇam administrator.",
        )
    token = ACCOUNT_STORE.create_password_reset_token(request.email)
    if token is not None:
        try:
            _send_password_reset_email(request.email, token)
        except (OSError, smtplib.SMTPException) as error:
            ACCOUNT_STORE.delete_password_reset_token(token)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="The password reset email could not be sent. Please try again later.",
            ) from error
    return {
        "message": "If an account exists for that email, a password reset link will arrive shortly."
    }


@app.post("/api/auth/password-reset/confirm", tags=["accounts"])
def confirm_password_reset(request: PasswordResetRequest) -> dict[str, str]:
    if not ACCOUNT_STORE.complete_password_reset(request.token, request.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This password reset link is invalid or has expired. Request a new one.",
        )
    return {"status": "password_updated"}


@app.post("/api/auth/register", tags=["accounts"], status_code=status.HTTP_201_CREATED)
def register_account(request: RegisterRequest) -> dict:
    try:
        profile, token = ACCOUNT_STORE.register(
            email=request.email,
            password=request.password,
            display_name=request.display_name,
            college=request.college,
            course=request.course,
            interests=request.interests,
        )
    except DuplicateEmailError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account already exists for this email. Sign in instead.",
        ) from error
    return _auth_response(profile, token)


@app.post("/api/auth/login", tags=["accounts"])
def login_account(request: AccountRequest) -> dict:
    try:
        profile, token = ACCOUNT_STORE.login(request.email, request.password)
    except InvalidCredentialsError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email or password is incorrect.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error
    return _auth_response(profile, token)


@app.get("/api/auth/me", tags=["accounts"])
def get_current_profile(authorization: str | None = Header(default=None)) -> dict:
    token = _session_token(authorization)
    try:
        return {"profile": ACCOUNT_STORE.get_profile(token)}
    except InvalidSessionError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your session expired. Sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error


@app.patch("/api/auth/profile", tags=["accounts"])
def update_current_profile(
    request: ProfileUpdateRequest,
    authorization: str | None = Header(default=None),
) -> dict:
    token = _session_token(authorization)
    updates = {
        key: value
        for key, value in request.model_dump(exclude_unset=True).items()
        if value is not None
    }
    try:
        return {"profile": ACCOUNT_STORE.update_profile(token, updates)}
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(error),
        ) from error
    except InvalidSessionError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your session expired. Sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error


@app.post("/api/auth/logout", tags=["accounts"])
def logout_account(authorization: str | None = Header(default=None)) -> dict[str, str]:
    token = _session_token(authorization)
    ACCOUNT_STORE.logout(token)
    return {"status": "signed_out"}


@app.get("/api/reports", tags=["reports"])
def list_saved_reports(
    authorization: str | None = Header(default=None),
    limit: int = Query(default=50, ge=1, le=100),
) -> dict:
    profile = _current_profile(authorization)
    return {"reports": ACCOUNT_STORE.list_reports(profile["id"], limit=limit)}


@app.delete("/api/reports/{report_reference}", tags=["reports"])
def delete_saved_report(
    report_reference: str,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    profile = _current_profile(authorization)
    if not ACCOUNT_STORE.delete_report(profile["id"], report_reference):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Saved report not found.",
        )
    return {"status": "deleted", "report_reference": report_reference}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host=API_HOST, port=API_PORT, reload=APP_ENV == "development")
