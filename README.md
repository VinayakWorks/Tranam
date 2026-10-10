# Trāṇam — Fake Internship Detection

Trāṇam is a project in development that aims to help students and fresh graduates assess internship offers for potential signs of fraud. It is intended to make common recruitment-scam warning signs easier to recognize and explain in plain language.

> **Important:** Trāṇam's assessments are indicative and based only on the information provided. They are not proof that an offer is genuine or fraudulent. Always verify an opportunity independently before sharing sensitive information or making a payment.

## The problem

Students and early-career job seekers can encounter fake internship offers, fraudulent recruiters, registration-fee scams, misleading stipends, and suspicious application websites. These scams may cause financial loss or expose personal information.

## Project goals

- Raise awareness of internship and recruitment scams.
- Help users evaluate concerning details in an offer.
- Explain potential warning signs in accessible language.
- Encourage safer application and verification practices.

## Current application

The static HTML/CSS/JavaScript demo currently includes:

- A FastAPI backend (`backend/`) for offer text analysis and a detailed verification report.
- Risk estimate, matched warning signs with text evidence, severity breakdown, checklist, and recommendations.
- Local PDF, TXT, and Markdown text extraction, plus browser-based OCR for scanned PDFs and JPG/JPEG, PNG, WEBP, BMP, and GIF images/screenshots.
- PDF.js 6.4.299 and Tesseract.js 6.0.1 are loaded from pinned CDN URLs. Their libraries/language data are downloaded, but selected offer files are processed locally and are not sent to those CDNs.
- Browser print and “Save as PDF” actions, clipboard summary, and verification history saved in the current browser.
- Quick Chat, safety guidance, and responsive navigation.
- Student registration, sign-in, profile editing, and revocable 24-hour sessions backed by SQLite; password hashes use salted PBKDF2, and bearer tokens are kept in the current browser tab session.
- Optional, separately consented report storage for signed-in users, with private account history, viewing, and deletion. Browser-local history remains available independently.
- An opportunities page linking to LinkedIn, Internshala, Indeed, Naukri, Wellfound, and India's National Career Service. Listings are hosted externally and are not verified by Trāṇam.

### Run locally on Windows

Use two PowerShell terminals from the repository root.

**Terminal 1 — backend**

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload
```

**Terminal 2 — frontend**

```powershell
py -m http.server 5500
```

Open `http://127.0.0.1:5500` in a browser. The analyzer and Quick Chat send text to the backend only after the corresponding consent checkbox is selected. Analysis does not persist the full submitted offer text. If a signed-in user separately selects **Save this report to my account**, Trāṇam stores the generated report, including matched evidence excerpts and the optional company details, in the local SQLite database. The original uploaded file is never stored. Saved reports stay with the account until deleted individually; local browser history is separate and can be cleared on the device. PDF extraction and OCR require an internet connection to load the pinned PDF.js/Tesseract.js libraries and English OCR language data. The original selected file stays in the browser; only extracted text is sent to the configured Trāṇam backend after consent.

The backend reads local settings from `backend/.env`; safe development defaults are included. Copy `backend/.env.example` to create or reset that file. Account profiles and hashed credentials are stored in `backend/tranam.sqlite3` by default; this local database is ignored by Git. Set `CORS_ORIGINS` to the exact frontend origin(s) when using a different host or port. The API binds to `127.0.0.1` by default.

The account demo uses salted PBKDF2 password hashes and expiring, revocable bearer sessions. It does not yet include email verification, password reset, MFA, account deletion, or production-grade rate limiting; use a unique password and do not expose the local API publicly as-is. Browser history remains local to the device; only reports explicitly saved by a signed-in user are linked to that account.

API endpoints:

- `GET http://127.0.0.1:8000/api/health`
- `POST http://127.0.0.1:8000/api/analyze`
- `POST http://127.0.0.1:8000/api/auth/register`
- `POST http://127.0.0.1:8000/api/auth/login`
- `GET http://127.0.0.1:8000/api/auth/me`
- `PATCH http://127.0.0.1:8000/api/auth/profile`
- `POST http://127.0.0.1:8000/api/auth/logout`
- `GET http://127.0.0.1:8000/api/reports` (authenticated; optional `limit` from 1 to 100)
- `DELETE http://127.0.0.1:8000/api/reports/{report_reference}` (authenticated and owner-scoped)
- Interactive API docs: `http://127.0.0.1:8000/docs`

To persist an analysis, send `save_report: true` in `POST /api/analyze` and include the signed-in user's `Authorization: Bearer <token>` header. Omitting the flag returns an analysis without storing it; requesting persistence without a valid account session is rejected. Report listing and deletion are scoped to the authenticated account. A saved report contains the assessment and its evidence excerpts, not the complete pasted offer or uploaded file. There is no bulk-delete or account-deletion endpoint in this demo yet.

Run backend unit tests from `backend/` with:

```powershell
py -m unittest discover -s tests -v
```

### Important limitations

- The score is a rule-based estimate, not a statistically validated probability or a finding of fraud.
- Company registration, recruiter identity, websites, email ownership, live URLs, and offer-letter authenticity are not independently verified.
- OCR recognizes English only and may misread low-quality, rotated, or handwritten text; review extracted text before analysis. Scanned PDFs are limited to 30 pages per file.
- Old Word `.doc`, Word `.docx`, spreadsheets, video, and other unsupported formats are not accepted. Save/export those as PDF or paste the relevant text.
- Browser-local history is not synced; account-saved reports are separate and require explicit consent.
- Reports saved to an account persist in the local SQLite database until individually deleted. The demo has no account deletion or retention-expiry feature.
- PDF.js is loaded from jsDelivr; offer documents are not uploaded to the CDN.

## How to use

1. Start the backend and frontend using the local setup instructions above.
2. Choose **Check Internship**, then paste offer details or upload a PDF, TXT, MD, or supported image/screenshot. Scanned PDFs and images are OCR-processed in the browser.
3. Select **Analyze internship** and review the generated report, evidence, checklist statuses, and recommended actions.
4. Download the print-ready HTML report, print it, or use the browser’s print dialog to save a PDF.

Sample text to test a payment warning:

> Congratulations! You are selected for the internship. Pay a registration fee today to confirm your position. Send your OTP to complete verification.

Sample text with fewer matching warning signs:

> The software intern will assist with testing and documentation for 8 weeks, up to 20 hours per week. The stipend and schedule will be discussed in the written offer. Apply through the careers page on the company website.

## Intended users

- College students
- Fresh graduates
- Internship seekers
- Educational institutions and placement cells

## Technology

The frontend uses semantic HTML, CSS, and browser JavaScript. The backend uses FastAPI, Uvicorn, Pydantic, python-dotenv, and SQLite. PDF text extraction is provided by PDF.js 6.4.299 loaded from jsDelivr. No external AI service is configured.

## Project status

**In development.** The frontend, local FastAPI analysis flow, basic student accounts, and opt-in account report history are functional. Email verification, password recovery, MFA, account deletion, production-grade rate limiting, external company/recruiter verification, and live URL scanning remain future work.

## Future scope

- AI-assisted internship-offer classification
- Fake offer-letter detection
- Suspicious URL and website analysis
- An internship reporting portal
- Verified internship and job alerts

## Author

Vinayak Mukunda Jamdar

## License

To be decided.
