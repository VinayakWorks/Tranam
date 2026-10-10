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

## Current frontend demo

The static HTML/CSS/JavaScript demo currently includes:

- Offer text analysis with a detailed, downloadable HTML verification report.
- Risk estimate, matched warning signs with text evidence, severity breakdown, checklist, and recommendations.
- Local PDF, TXT, and Markdown text extraction. PDF text extraction uses the pinned PDF.js 6.4.299 CDN build; the offer contents are processed in the browser and are not sent to that CDN.
- A clear OCR-required notice when a PDF has no selectable text, as with many scanned documents.
- Browser print and “Save as PDF” actions, clipboard summary, and verification history saved in the current browser.
- Quick Chat, safety guidance, and responsive navigation.

Open `index.html` in a modern browser to try the frontend. PDF extraction requires an internet connection to load the PDF.js library and worker. TXT/MD extraction and pasted-text analysis do not require a backend.

### Important limitations

- The score is a rule-based estimate, not a statistically validated probability or a finding of fraud.
- Company registration, recruiter identity, websites, email ownership, live URLs, and offer-letter authenticity are not independently verified.
- A scanned PDF needs OCR. The demo does not run OCR itself.
- Verification history is local to the browser/device and is not synced.
- PDF.js is loaded from cdnjs; offer documents are not uploaded to the CDN.

## How to use

1. Open `index.html` in a modern browser.
2. Choose **Check Internship**, then paste offer details or upload a PDF, TXT, or MD file.
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

The current demo uses semantic HTML, CSS, and browser JavaScript. It does not require a backend or database. PDF text extraction is provided by PDF.js 6.4.299 loaded from jsDelivr.

## Project status

**In development.** The frontend provides an indicative text-based assessment; external verification and backend-supported features remain future work.

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
