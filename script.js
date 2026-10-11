const HISTORY_KEY = "tranam-check-history";
const ACCOUNT_TOKEN_KEY = "tranam-account-token";
const MAX_HISTORY_ITEMS = 10;
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MIN_OFFER_LENGTH = 20;
const PDFJS_BASE_URL = "https://cdn.jsdelivr.net/npm/pdfjs-dist@6.4.299/build";
const TESSERACT_URL = "https://cdn.jsdelivr.net/npm/tesseract.js@6.0.1/dist/tesseract.esm.min.js";
const MAX_PDF_PAGES = 30;
const IMAGE_EXTENSIONS = new Set(["jpg", "jpeg", "png", "webp", "bmp", "gif"]);
const API_BASE_URL = window.TRANAM_API_BASE_URL || "http://127.0.0.1:8000";
let pdfjsPromise = null;
let tesseractPromise = null;

const offerText = document.getElementById("offerText");
const analyzerForm = document.getElementById("analyzerForm");
const charCount = document.getElementById("charCount");
const errorMessage = document.getElementById("errorMessage");
const fileInput = document.getElementById("offerFile");
const dropZone = document.getElementById("dropZone");
const fileName = document.getElementById("fileName");
const fileNote = document.getElementById("fileNote");
const reportView = document.getElementById("reportView");
const historyList = document.getElementById("historyList");
const historyEmpty = document.getElementById("historyEmpty");
const historyStatus = document.getElementById("historyStatus");
const clearHistoryButton = document.getElementById("clearHistory");
const savedReportList = document.getElementById("savedReportList");
const savedHistoryStatus = document.getElementById("savedHistoryStatus");
const savedReportsEmpty = document.getElementById("savedReportsEmpty");
const refreshSavedReportsButton = document.getElementById("refreshSavedReports");

const indicators = [
  {
    name: "Registration or processing fee",
    pattern: /\b(?:registration|processing|application|security)\s+(?:fee|charge|deposit)\b|\bpay\s+(?:a\s+|the\s+)?(?:fee|amount|deposit)\b|\bpayment required\b|\bdeposit to confirm\b/i,
    points: 30,
    severity: "Critical",
    why: "Legitimate employers generally do not require candidates to pay to secure an internship.",
    risk: "An upfront payment request may be used to collect money without providing a real role.",
    action: "Do not pay. Independently contact the organization using contact details from its official website."
  },
  {
    name: "Guaranteed selection or job placement",
    pattern: /\b(guaranteed (?:job|placement|selection|internship)|100% placement|job guaranteed|assured placement)\b/i,
    points: 15,
    severity: "High",
    why: "Guaranteed hiring or placement claims can create unrealistic expectations and pressure applicants.",
    risk: "Such promises may be used to sell paid courses, certificates, or recruitment services.",
    action: "Ask for written role and selection terms, and verify the claim with the organization directly."
  },
  {
    name: "Unrealistic stipend or earnings promise",
    pattern: /\b(earn|salary|stipend|income).{0,45}(?:\b[1-9]\d{2},?\d{3,}\b|\b[1-9]\d{0,2},\d{2},\d{3}\b|\b\d+\s*(?:lakh|lakhs|crore|crores)\b).{0,30}(?:per month|monthly|every month)?/i,
    points: 12,
    severity: "Medium",
    why: "Very large or vague earnings claims may not reflect a credible internship compensation offer.",
    risk: "Inflated compensation promises can be used to attract applicants to unrelated fees or data collection.",
    action: "Request written stipend terms and compare them with the responsibilities and duration."
  },
  {
    name: "Urgent payment or pressure tactics",
    pattern: /\b(pay immediately|urgent payment|limited time offer|act now|pay today|immediate payment|offer expires today)\b/i,
    points: 15,
    severity: "High",
    why: "Urgency can discourage applicants from checking the employer or reading the terms carefully.",
    risk: "Pressure may be used to rush a payment or disclosure of personal information.",
    action: "Pause. Do not pay or share information until you have verified the opportunity independently."
  },
  {
    name: "Request for sensitive information",
    pattern: /\b(send|share|submit|provide|tell us|enter).{0,45}\b(password|otp|one.time password|bank pin|card cvv|card security code|online banking credentials|bank account number|credit card number|debit card number|aadhaar number|pan number|passport number)\b/i,
    points: 30,
    severity: "Critical",
    why: "Recruiters should not need account passwords, one-time passwords, banking PINs, or card security codes.",
    risk: "These details can enable account takeover, unauthorized transactions, or identity theft.",
    action: "Do not disclose the information. If already shared, contact your bank or account provider immediately."
  },
  {
    name: "Suspicious communication channel",
    pattern: /\b(whatsapp only|telegram only|contact only on whatsapp|personal gmail|no official website)\b/i,
    points: 12,
    severity: "Medium",
    why: "A recruiter who avoids verifiable company contact channels is harder to authenticate.",
    risk: "Impersonators may use personal accounts to avoid organizational oversight.",
    action: "Contact the company through its independently located official channels to confirm the recruiter."
  },
  {
    name: "Pay to receive a certificate",
    pattern: /\b(pay|payment|fee).{0,35}\b(certificate|certification)\b|\b(certificate|certification).{0,35}\b(pay|payment|fee)\b/i,
    points: 20,
    severity: "High",
    why: "A required payment for an internship certificate may indicate a pay-to-participate scheme.",
    risk: "Applicants may pay for a certificate or placement that is not delivered or recognized.",
    action: "Do not pay based on the offer alone; verify the program and certificate issuer independently."
  },
  {
    name: "Unverified link or form",
    pattern: /\b(unknown link|unverified link|click this link|fill this google form|submit details through this form|enter your details in this form)\b/i,
    points: 12,
    severity: "High",
    why: "A form or link mentioned without a verifiable destination cannot be authenticated by this text scan.",
    risk: "Untrusted forms can collect personal information or direct users to credential-harvesting pages.",
    action: "Inspect the destination carefully and navigate to the company website independently instead of following an unexpected link."
  },
  {
    name: "URL shortener in provided link",
    pattern: /\b(?:https?:\/\/)?(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy)\b/i,
    points: 15,
    severity: "High",
    why: "A shortened URL hides the final destination from the reader.",
    risk: "The destination cannot be assessed from the shortened address alone and may lead to an impersonation or phishing page.",
    action: "Do not open it until you can confirm its destination and purpose through the company's official website."
  },
  {
    name: "Free email provider used for recruitment",
    pattern: /\b[A-Z0-9._%+-]+@(gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|protonmail\.com)\b/i,
    points: 15,
    severity: "Medium",
    why: "A free email address is not tied to a company domain and does not establish recruiter identity.",
    risk: "Impersonators can create free accounts that resemble a recruiter contact.",
    action: "Verify the recruiter using contact information published on the organization's official website."
  },
  {
    name: "Suspicious application form",
    pattern: /\b(?:google forms|forms\.gle|docs\.google\.com\/forms|whatsapp.{0,20}form|telegram.{0,20}form)\b/i,
    points: 12,
    severity: "Medium",
    why: "An application form on a general-purpose platform is not proof of an official company application.",
    risk: "Forms may collect more personal information than an application needs.",
    action: "Confirm the application process with the company through its independently located official website."
  }
];

const viewTitles = {
  home: "Trāṇam — Verify Before You Trust",
  check: "Check an Internship — Trāṇam",
  chat: "Quick Chat — Trāṇam",
  history: "Verification History — Trāṇam",
  safety: "About & Safety — Trāṇam",
  opportunities: "Find Opportunities — Trāṇam",
  account: "Account & Profile — Trāṇam"
};
const accountRequiredViews = new Set(["check", "chat", "history", "opportunities"]);

function getRiskLevel(score) {
  if (score >= 70) {
    return {
      key: "critical",
      title: "Critical",
      description: "Multiple serious warning signs were detected. Stop before paying or sharing information and independently verify the opportunity."
    };
  }

  if (score >= 40) {
    return {
      key: "high",
      title: "High",
      description: "Several warning signs were detected. Verify the recruiter and company through official channels before proceeding."
    };
  }

  if (score >= 20) {
    return {
      key: "medium",
      title: "Medium",
      description: "Some warning signs were detected. Review the evidence and verify the offer before proceeding."
    };
  }

  return {
    key: "low",
    title: "Low",
    description: "Few matching patterns were found in the submitted text. This does not establish that the offer is genuine or safe."
  };
}

function isNegatedFinding(text, match) {
  const precedingText = text.slice(Math.max(0, match.index - 42), match.index);
  const followingText = text.slice(match.index + match[0].length, match.index + match[0].length + 42);
  const negation = /(?:\bno\b|\bnot\b|\bnever\b|\bdon't\b|\bdo not\b|\bdoesn't\b|\bdoes not\b|\bwithout\b|\bavoid\b)[^.!?\n]{0,36}$/i;
  const denialAfter = /^\s*(?:(?:is|are|was|were)\s+)?(?:not required|not requested|not necessary|not needed|waived)\b/i;

  return negation.test(precedingText) || denialAfter.test(followingText);
}

function scanText(text, companyName = "") {
  const matches = indicators
    .map((indicator) => {
      const match = text.match(indicator.pattern);
      return match && !isNegatedFinding(text, match)
        ? { ...indicator, excerpt: match[0] }
        : null;
    })
    .filter(Boolean);

  if (!companyName && !/\b(company|employer|organization|organisation|inc\.?|ltd\.?|llc|corp\.?)\b/i.test(text)) {
    matches.push({
      name: "No clear company identity in submitted details",
      points: 12,
      severity: "High",
      why: "The submitted text and company-name field do not identify a clear organization.",
      risk: "Without a named organization, it is difficult to verify who is offering the role.",
      action: "Request the organization's legal name and verify it through trusted official sources.",
      excerpt: ""
    });
  }

  if (!/\b(role|responsibilit(?:y|ies)|duties|tasks|duration|months|weeks|hours|per week|stipend|paid|unpaid)\b/i.test(text)) {
    matches.push({
      name: "Internship responsibilities or terms are unclear",
      points: 8,
      severity: "Medium",
      why: "The submitted text does not clearly state the work, duration, hours, or compensation terms.",
      risk: "Unclear terms make it harder to assess whether the opportunity is genuine and suitable.",
      action: "Request written responsibilities, duration, working hours, stipend, and employment terms.",
      excerpt: ""
    });
  }

  const score = Math.min(
    matches.reduce((total, indicator) => total + indicator.points, 0),
    100
  );

  return { matches, score, risk: getRiskLevel(score), checksPerformed: indicators.length + 2 };
}

function addListItems(element, items) {
  element.replaceChildren();

  items.forEach((item) => {
    const listItem = document.createElement("li");
    listItem.textContent = item;
    element.appendChild(listItem);
  });
}

function getRecommendations(matches, score) {
  const recommendations = [];
  matches.forEach((match) => recommendations.push(match.action));

  if (score >= 20) recommendations.push("Pause before proceeding and resolve the warning signs first.");
  recommendations.push("Verify the employer and recruiter using contact details obtained independently.");
  if (matches.length === 0) recommendations.push("Confirm the internship responsibilities, duration, stipend, and terms in writing.");

  return [...new Set(recommendations)];
}

function readHistory() {
  try {
    const savedHistory = localStorage.getItem(HISTORY_KEY);
    if (!savedHistory) return [];

    const history = JSON.parse(savedHistory);
    if (!Array.isArray(history)) throw new Error("Saved history has an invalid format.");

    return history.filter((entry) =>
      entry &&
      typeof entry.name === "string" &&
      typeof entry.score === "number" &&
      typeof entry.risk === "string" &&
      typeof entry.date === "string"
    );
  } catch (error) {
    console.error("Unable to read verification history.", error);
    return null;
  }
}

function renderHistory() {
  const history = readHistory();
  historyList.replaceChildren();
  loadSavedReports();

  if (history === null) {
    historyStatus.textContent = "History could not be loaded from this browser.";
    historyEmpty.hidden = true;
    clearHistoryButton.hidden = true;
    return;
  }

  historyStatus.textContent = history.length
    ? "Your checks are saved on this device."
    : "Your recent checks will appear here.";
  historyEmpty.hidden = history.length > 0;
  clearHistoryButton.hidden = history.length === 0;

  history.forEach((entry) => {
    const item = document.createElement("li");
    item.className = "history-item";

    const details = document.createElement("span");
    const name = document.createElement("strong");
    const date = document.createElement("small");
    name.textContent = entry.name;
    date.textContent = new Date(entry.date).toLocaleString();
    details.append(name, date);

    const score = document.createElement("span");
    score.className = `history-score ${entry.risk}`;
    score.textContent = `${entry.score}% · ${entry.risk}`;
    item.append(details, score);
    historyList.appendChild(item);
  });

}

function renderSavedReports(reports) {
  savedReportList.replaceChildren();
  savedReportsEmpty.hidden = reports.length > 0;
  savedHistoryStatus.textContent = reports.length
    ? `${reports.length} saved account report${reports.length === 1 ? "" : "s"}.`
    : "No reports have been saved to this account yet.";

  reports.forEach(({ report_reference: reference, saved_at: savedAt, report }) => {
    const item = document.createElement("li");
    item.className = "history-item saved-report-item";

    const details = document.createElement("span");
    const name = document.createElement("strong");
    const date = document.createElement("small");
    name.textContent = report.company_name || report.source_filename || reference;
    date.textContent = `${reference} · Saved ${new Date(savedAt).toLocaleString()}`;
    details.append(name, date);

    const actions = document.createElement("span");
    actions.className = "saved-report-actions";
    const score = document.createElement("span");
    score.className = `history-score ${report.classification.key}`;
    score.textContent = `${report.score}/100 · ${report.classification.label}`;
    const viewButton = document.createElement("button");
    viewButton.className = "text-button";
    viewButton.type = "button";
    viewButton.textContent = "View";
    viewButton.addEventListener("click", () => showSavedReport(report));
    const deleteButton = document.createElement("button");
    deleteButton.className = "text-button delete-saved-report";
    deleteButton.type = "button";
    deleteButton.textContent = "Delete";
    deleteButton.addEventListener("click", () => deleteSavedReport(reference));
    actions.append(score, viewButton, deleteButton);
    item.append(details, actions);
    savedReportList.appendChild(item);
  });
}

async function loadSavedReports() {
  savedReportList.replaceChildren();
  if (!accountAccessToken) {
    savedHistoryStatus.textContent = "Sign in to view reports saved to your account.";
    savedReportsEmpty.hidden = true;
    refreshSavedReportsButton.hidden = true;
    return;
  }

  refreshSavedReportsButton.hidden = false;
  savedHistoryStatus.textContent = "Loading saved reports…";
  savedReportsEmpty.hidden = true;
  try {
    const payload = await accountRequest("/api/reports?limit=50");
    renderSavedReports(payload.reports);
  } catch (error) {
    console.error("Unable to load saved reports.", error);
    savedHistoryStatus.textContent = error.status === 401
      ? "Your session expired. Sign in again to view account reports."
      : "Saved reports are unavailable right now. Please try again shortly.";
    savedReportsEmpty.hidden = true;
  }
}

function showSavedReport(report) {
  currentReport = renderReport(report);
  analyzerForm.hidden = true;
  reportView.hidden = false;
  window.location.hash = "check";
  setView("check", false);
  reportView.scrollIntoView({ behavior: "smooth", block: "start" });
  document.getElementById("reportTitle").focus({ preventScroll: true });
}

async function deleteSavedReport(reference) {
  if (!window.confirm(`Delete saved report ${reference}? This cannot be undone.`)) return;
  savedHistoryStatus.textContent = "Deleting saved report…";
  try {
    await accountRequest(`/api/reports/${encodeURIComponent(reference)}`, { method: "DELETE" });
    await loadSavedReports();
  } catch (error) {
    console.error("Unable to delete the saved report.", error);
    savedHistoryStatus.textContent = error.status === 404
      ? "That saved report was not found."
      : "The report could not be deleted right now. Please try again shortly.";
  }
}

refreshSavedReportsButton.addEventListener("click", loadSavedReports);

function saveHistory(name, score, risk) {
  const history = readHistory();
  if (history === null) {
    historyStatus.textContent = "This check worked, but browser history is unavailable.";
    return;
  }

  const entry = {
    name: name.trim() || "Internship offer",
    score,
    risk,
    date: new Date().toISOString()
  };

  try {
    localStorage.setItem(
      HISTORY_KEY,
      JSON.stringify([entry, ...history].slice(0, MAX_HISTORY_ITEMS))
    );
    renderHistory();
  } catch (error) {
    console.error("Unable to save verification history.", error);
    historyStatus.textContent = "This check worked, but could not be saved in browser history.";
  }
}

function createReportReference(date) {
  const datePart = date.toISOString().slice(0, 10).replaceAll("-", "");
  const randomPart = new Uint32Array(1);

  if (window.crypto && typeof window.crypto.getRandomValues === "function") {
    window.crypto.getRandomValues(randomPart);
  } else {
    randomPart[0] = Math.floor(Math.random() * 0xffffffff);
  }

  return `TN-${datePart}-${randomPart[0].toString(16).toUpperCase().padStart(8, "0")}`;
}

function makeChecklist(matches, text, companyName, companyLink) {
  const names = new Set(matches.map((match) => match.name));
  const emailFound = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(text);
  const hasInternshipDetails = /\b(role|responsibilit(?:y|ies)|duties|tasks|duration|months|weeks|hours|per week|stipend|paid|unpaid)\b/i.test(text);
  const hasStipendDetails = /\b(stipend|salary|compensation|paid|unpaid|₹|rs\.?|inr)\b/i.test(text);
  const hasLink = Boolean(companyLink || /\bhttps?:\/\/\S+/i.test(text));
  const suspiciousLink = names.has("URL shortener in provided link") ||
    names.has("Unverified link or form") ||
    names.has("Suspicious application form");

  return [
    {
      name: "Company identity",
      status: names.has("No clear company identity in submitted details") ? "warning" : "not-checked",
      detail: names.has("No clear company identity in submitted details")
        ? "No clear organization name was found in the submitted details; no registry was checked."
        : `Company name${companyName ? ` (“${companyName}”)` : ""} was not checked against an official registry.`
    },
    {
      name: "Recruiter identity",
      status: "not-checked",
      detail: "No recruiter identity or employment relationship was externally verified."
    },
    {
      name: "Official website",
      status: "not-checked",
      detail: "No website was opened or checked against an official company source."
    },
    {
      name: "Email domain",
      status: names.has("Free email provider used for recruitment") ? "warning" : "not-checked",
      detail: names.has("Free email provider used for recruitment")
        ? "A free email provider appears in the text; sender ownership was not verified."
        : emailFound
          ? "An email address appears in the text; domain ownership and authenticity were not checked."
          : "No recruiter email address was available to assess."
    },
    {
      name: "Payment requests",
      status: names.has("Registration or processing fee") || names.has("Pay to receive a certificate") ? "failed" : "passed",
      detail: names.has("Registration or processing fee") || names.has("Pay to receive a certificate")
        ? "A payment-related pattern was found in the submitted text."
        : "No payment-request pattern was found by the text scan."
    },
    {
      name: "Internship description",
      status: hasInternshipDetails ? "passed" : "warning",
      detail: hasInternshipDetails
        ? "The text contains at least one role, responsibility, or term detail."
        : "No clear role, responsibilities, duration, or working-hours terms were detected."
    },
    {
      name: "Stipend and benefits",
      status: hasStipendDetails ? "passed" : "warning",
      detail: hasStipendDetails
        ? "Compensation-related wording appears in the submitted text; the amount was not validated."
        : "No stipend or compensation terms were detected."
    },
    {
      name: "Application link",
      status: suspiciousLink ? "warning" : "not-checked",
      detail: suspiciousLink
        ? "A link or form pattern needs review; no destination was opened or scanned."
        : hasLink
          ? "A link was provided, but it was not opened or checked for safety."
          : "No application link was provided."
    },
    {
      name: "Offer letter consistency",
      status: "not-checked",
      detail: "The document was not compared with an independently sourced company offer or template."
    },
    {
      name: "Personal information requests",
      status: names.has("Request for sensitive information") ? "failed" : "passed",
      detail: names.has("Request for sensitive information")
        ? "A request for credentials or sensitive account information was detected."
        : "No credential-sharing warning sign was found in the submitted text."
    }
  ];
}

function renderChecklist(items) {
  const list = document.getElementById("checklistList");
  list.replaceChildren();
  const statusLabels = {
    passed: "Passed",
    warning: "Warning",
    failed: "Failed",
    "not-checked": "Not Checked"
  };

  items.forEach((item) => {
    const row = document.createElement("article");
    row.className = "checklist-row";
    row.dataset.status = item.status;

    const status = document.createElement("span");
    status.className = `check-status status-${item.status}`;
    status.textContent = statusLabels[item.status];

    const content = document.createElement("span");
    content.className = "check-content";
    const name = document.createElement("strong");
    const detail = document.createElement("small");
    name.textContent = item.name;
    detail.textContent = item.detail;
    content.append(name, detail);
    row.append(status, content);
    list.appendChild(row);
  });
}

function renderFindings(matches) {
  const list = document.getElementById("findingList");
  list.replaceChildren();

  if (!matches.length) {
    const empty = document.createElement("p");
    empty.className = "no-findings";
    empty.textContent = "No recognized warning signs were found in the submitted text. This does not verify the offer or employer.";
    list.appendChild(empty);
  }

  matches.forEach((match) => {
    const card = document.createElement("article");
    card.className = "finding-card";
    card.dataset.severity = match.severity.toLowerCase();

    const heading = document.createElement("div");
    heading.className = "finding-heading";
    const name = document.createElement("h4");
    const severity = document.createElement("span");
    name.textContent = match.name;
    severity.className = `severity-tag severity-${match.severity.toLowerCase()}`;
    severity.textContent = match.severity;
    heading.append(name, severity);

    const evidenceLabel = document.createElement("strong");
    evidenceLabel.className = "finding-label";
    evidenceLabel.textContent = "Evidence from submitted text";
    const evidence = document.createElement("blockquote");
    evidence.textContent = match.excerpt
      ? `“${match.excerpt}”`
      : "No matching excerpt. This warning is based on information missing from the submitted details.";

    const why = document.createElement("p");
    const risk = document.createElement("p");
    const action = document.createElement("p");
    [why, risk, action].forEach((paragraph) => paragraph.className = "finding-detail");
    const whyLabel = document.createElement("strong");
    const riskLabel = document.createElement("strong");
    const actionLabel = document.createElement("strong");
    whyLabel.textContent = "Why it may be suspicious: ";
    riskLabel.textContent = "Potential risk: ";
    actionLabel.textContent = "Recommended action: ";
    why.append(whyLabel, document.createTextNode(match.why));
    risk.append(riskLabel, document.createTextNode(match.risk));
    action.append(actionLabel, document.createTextNode(match.action));
    card.append(heading, evidenceLabel, evidence, why, risk, action);
    list.appendChild(card);
  });
}

function renderReport(analysis) {
  const generatedAt = new Date(analysis.generated_at);
  const classification = analysis.classification;
  const severityCounts = ["Critical", "High", "Medium", "Low"].map((severity) => ({
    severity,
    count: analysis.severity_counts[severity.toLowerCase()] || 0
  }));

  document.getElementById("reportReference").textContent = analysis.report_reference;
  document.getElementById("reportGenerated").textContent = generatedAt.toLocaleString();
  document.getElementById("reportSource").textContent = analysis.source_filename;
  document.getElementById("reportAnalysisStatus").textContent = analysis.analysis_status;
  document.getElementById("reportStorageNote").textContent = analysis.saved_to_account
    ? "This report and its evidence excerpts are saved to your Trāṇam account. The original uploaded file is not stored."
    : "Generated in your browser. This report was not saved to your account.";
  document.getElementById("reportScore").textContent = String(analysis.score);
  document.getElementById("reportRiskMeter").setAttribute("aria-valuenow", String(analysis.score));
  document.getElementById("reportRiskMeter").style.setProperty("--score", `${analysis.score}%`);
  document.getElementById("reportRiskPanel").dataset.risk = classification.key;
  document.getElementById("reportRiskTitle").textContent = `${classification.label} risk`;
  document.getElementById("reportRiskSummary").textContent = analysis.summary;
  document.getElementById("warningCount").textContent = String(analysis.warning_count);
  document.getElementById("checksCount").textContent = String(analysis.checks_performed);
  document.getElementById("notCheckedCount").textContent = String(analysis.external_checks_not_performed);
  document.getElementById("findingTotal").textContent = `${analysis.warning_count} finding${analysis.warning_count === 1 ? "" : "s"}`;

  const breakdown = document.getElementById("severityBreakdown");
  breakdown.replaceChildren();
  severityCounts.forEach(({ severity, count }) => {
    const item = document.createElement("div");
    item.className = `severity-count severity-${severity.toLowerCase()}`;
    const number = document.createElement("strong");
    const label = document.createElement("span");
    number.textContent = String(count);
    label.textContent = severity;
    item.append(number, label);
    breakdown.appendChild(item);
  });

  renderFindings(analysis.matches);
  renderChecklist(analysis.checklist);
  document.getElementById("whyFlagged").textContent = analysis.matches.length
    ? `The scanner found ${analysis.warning_count} pattern${analysis.warning_count === 1 ? "" : "s"} or missing-information signal${analysis.warning_count === 1 ? "" : "s"} that may warrant follow-up. These are indicators to review, not a conclusion about the company.`
    : "No recognized warning signs were found in the submitted text. The offer and employer have not been independently checked.";
  addListItems(document.getElementById("flagExplanationList"), analysis.matches.map((match) => `${match.name}: ${match.why}`));
  addListItems(document.getElementById("reportRecommendations"), analysis.recommendations);

  const missingItems = analysis.checklist.filter((item) =>
    item.status === "not-checked" || item.status === "warning"
  );
  document.getElementById("missingInfoText").textContent = missingItems.length
    ? `${missingItems.map((item) => item.name).join(", ")} require independent follow-up. Trāṇam did not check company records, recruiter identity, official websites, live link safety, or document authenticity.`
    : "No external checks were performed. Trāṇam did not check company records, recruiter identity, official websites, live link safety, or document authenticity.";

  return {
    matches: analysis.matches,
    score: analysis.score,
    risk: classification,
    recommendations: analysis.recommendations,
    generatedAt,
    reference: analysis.report_reference,
    sourceName: analysis.source_filename,
    companyName: analysis.company_name || ""
  };
}

let currentReport = null;

async function analyzeOffer(text, companyName, companyLink, sourceName) {
  const submitButton = document.getElementById("analyzeBtn");
  const shouldSaveReport = document.getElementById("saveReportConsent").checked;
  if (!accountProfile) {
    setView("check");
    return;
  }
  submitButton.disabled = true;
  submitButton.textContent = "Analyzing…";

  try {
    const headers = {
      "Content-Type": "application/json",
      Authorization: "Bearer " + accountAccessToken
    };
    if (shouldSaveReport) headers.Authorization = `Bearer ${accountAccessToken}`;
    const response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        offer_text: text,
        company_name: companyName,
        company_link: companyLink,
        source_filename: sourceName,
        save_report: shouldSaveReport
      })
    });
    const payload = await response.json();
    if (!response.ok) {
      const detail = typeof payload.detail === "string"
        ? payload.detail
        : "Trāṇam could not complete this analysis. Please try again.";
      const error = new Error(detail);
      error.status = response.status;
      throw error;
    }

    currentReport = renderReport(payload);
    analyzerForm.hidden = true;
    reportView.hidden = false;
    saveHistory(companyName || sourceName || "Internship offer", currentReport.score, currentReport.risk.key);
    if (payload.saved_to_account) {
      document.getElementById("reportActionStatus").textContent = "Report saved securely to your account.";
      loadSavedReports();
    }
    reportView.scrollIntoView({ behavior: "smooth", block: "start" });
    document.getElementById("reportTitle").focus({ preventScroll: true });
  } catch (error) {
    console.error("Internship analysis request failed.", error);
    if (error.status === 401 && shouldSaveReport) {
      clearAccountSession("Your session expired. Sign in again before saving a report.");
    }
    setError(
      error.status === 401
        ? "Your session expired. Sign in again, then analyze and save the report."
        : error instanceof TypeError
        ? "Unable to reach Trāṇam right now. Check your connection and try again."
        : error.message
    );
  } finally {
    submitButton.disabled = false;
    submitButton.innerHTML = 'Analyze internship <span aria-hidden="true">↗</span>';
  }
}

function getReportSummary() {
  if (!currentReport) return "";

  const findings = currentReport.matches.length
    ? currentReport.matches.map((match) => `- ${match.severity}: ${match.name}${match.excerpt ? ` — “${match.excerpt}”` : ""}`).join("\n")
    : "- No recognized warning signs were found in the submitted text.";

  return [
    "Trāṇam — Internship Verification Report",
    `Reference: ${currentReport.reference}`,
    `Generated: ${currentReport.generatedAt.toLocaleString()}`,
    `Source: ${currentReport.sourceName}`,
    `Estimated risk: ${currentReport.score}/100 (${currentReport.risk.title})`,
    `Warning signs detected: ${currentReport.matches.length}`,
    "",
    "Detected warning signs:",
    findings,
    "",
    "Recommended actions:",
    ...currentReport.recommendations.map((recommendation) => `- ${recommendation}`),
    "",
    "This automated assessment is indicative, not proof or a statistically validated probability. No company, recruiter, website, or document authenticity was independently verified."
  ].join("\n");
}

function downloadReport() {
  const reportStyles = `
    body{font:14px Arial,sans-serif;color:#0f172a;line-height:1.55;margin:32px auto;max-width:900px;padding:0 22px}
    h2,h3,h4{line-height:1.25}h2{font-size:28px;margin:8px 0}h3{font-size:20px}
    .report-document{display:block}.report-brand{display:flex;align-items:center;gap:10px;font-weight:bold}
    .report-brand small,.report-subtitle,.report-kicker,.report-meta dt,.report-footer span{display:block;color:#64748b;font-size:11px}
    .report-brand-mark{display:grid;place-items:center;width:38px;height:38px;border-radius:10px;background:#ecfdf5;color:#047857}
    .report-meta{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:22px 0}
    .report-meta dd{margin:3px 0 0;font-weight:bold;overflow-wrap:anywhere}
    .risk-panel{background:#0f172a;color:#fff;padding:20px;border-radius:12px}
    .risk-panel p,.risk-disclaimer{color:#cbd5e1}.risk-panel-main{display:flex;gap:20px;align-items:center}
    .risk-meter{display:grid;place-items:center;width:110px;height:110px;border-radius:50%;background:#059669}
    .risk-meter-inner{text-align:center}.risk-meter-inner strong,.risk-meter-inner span{display:block}
    .risk-metrics,.severity-breakdown{display:flex;gap:12px;margin-top:15px}
    .risk-metrics>div,.severity-count{flex:1;padding:12px;border:1px solid #334155;border-radius:8px}
    .risk-metrics strong,.risk-metrics span,.severity-count strong,.severity-count span{display:block}
    .report-section,.missing-info-panel{margin-top:25px}.finding-card,.checklist-row,.safety-panel{border:1px solid #dbe3ec;border-radius:8px;padding:14px;margin:10px 0;break-inside:avoid}
    .finding-heading{display:flex;justify-content:space-between;gap:12px}.finding-heading h4{margin:0}
    .severity-tag,.check-status{font-weight:bold;font-size:11px}
    .finding-card blockquote{margin:6px 0 10px;padding:8px;background:#f1f5f9;overflow-wrap:anywhere}
    .finding-detail{font-size:12px}.checklist-row{display:flex;gap:14px;align-items:flex-start}
    .check-content strong,.check-content small{display:block}.check-content small{color:#475569}
    .report-footer{margin-top:25px;border-top:1px solid #dbe3ec;padding-top:14px;color:#475569;font-size:11px}
    .report-footer p{max-width:850px}
  `;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Trāṇam Internship Verification Report</title><style>${reportStyles}</style></head><body>${document.getElementById("reportDocument").outerHTML}</body></html>`;
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `tranam-report-${currentReport.reference.toLowerCase()}.html`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  document.getElementById("reportActionStatus").textContent = "A print-ready HTML report was downloaded. Open it in a browser to print or save as PDF.";
}

async function copyReportSummary() {
  const summary = getReportSummary();

  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(summary);
    } else {
      const temporaryInput = document.createElement("textarea");
      temporaryInput.value = summary;
      temporaryInput.setAttribute("readonly", "");
      temporaryInput.style.position = "fixed";
      temporaryInput.style.opacity = "0";
      document.body.appendChild(temporaryInput);
      temporaryInput.select();
      const copied = document.execCommand("copy");
      temporaryInput.remove();
      if (!copied) throw new Error("The browser declined the clipboard copy.");
    }
    document.getElementById("reportActionStatus").textContent = "Report summary copied to the clipboard.";
  } catch (error) {
    console.error("Unable to copy report summary.", error);
    document.getElementById("reportActionStatus").textContent = "Could not copy automatically. Please select and copy the report details manually.";
  }
}

document.getElementById("downloadReport").addEventListener("click", downloadReport);
document.getElementById("printReport").addEventListener("click", () => window.print());
document.getElementById("savePdf").addEventListener("click", () => window.print());
document.getElementById("copySummary").addEventListener("click", copyReportSummary);
document.getElementById("analyzeAnother").addEventListener("click", () => {
  analyzerForm.reset();
  selectedSourceName = "";
  fileName.textContent = "";
  fileNote.textContent = "";
  errorMessage.hidden = true;
  reportView.hidden = true;
  analyzerForm.hidden = false;
  updateCharacterCount();
  window.scrollTo({ top: 0, behavior: "smooth" });
  offerText.focus({ preventScroll: true });
});

function setError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
}

function updateCharacterCount() {
  const count = offerText.value.length;
  charCount.textContent = `${count} character${count === 1 ? "" : "s"}`;
  charCount.classList.toggle("count-short", count > 0 && count < MIN_OFFER_LENGTH);
}

function setView(viewName, scroll = true) {
  let knownView = Object.hasOwn(viewTitles, viewName) ? viewName : "home";
  if (accountRequiredViews.has(knownView) && !accountProfile) {
    pendingProtectedView = knownView;
    knownView = "account";
    if (window.location.hash !== "#account") {
      window.history.replaceState(null, "", "#account");
    }
  }

  document.querySelectorAll("[data-view]").forEach((view) => {
    view.hidden = view.dataset.view !== knownView;
  });
  setupRevealAnimations();

  document.querySelectorAll("[data-view-link]").forEach((link) => {
    if (link.dataset.viewLink === knownView) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  });

  document.title = viewTitles[knownView];
  if (knownView === "history") renderHistory();
  if (knownView === "account" && !accountProfile) {
    showAccountForm(passwordResetToken ? "reset" : "login");
    if (pendingProtectedView) {
      setAccountStatus(accountAccessToken
        ? "Checking your sign-in session…"
        : "Sign in or create a free account to continue.");
    }
  }

  if (scroll) window.scrollTo({ top: 0, behavior: "smooth" });
}

let revealAnimationsInitialized = false;

function setupRevealAnimations() {
  if (revealAnimationsInitialized || !("IntersectionObserver" in window)
    || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  revealAnimationsInitialized = true;
  const revealObserver = new IntersectionObserver((entries, observer) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add("is-visible");
      observer.unobserve(entry.target);
    });
  }, { threshold: 0.12, rootMargin: "0px 0px -32px 0px" });

  document.querySelectorAll(
    ".section-heading, .feature-card, .step-card, .tips-copy, .safety-list, .home-cta, " +
    ".analyzer-card, .chat-card, .history-card, .safety-panel, .opportunity-card, .account-card"
  ).forEach((element) => {
    element.classList.add("reveal");
    revealObserver.observe(element);
  });
}

function syncViewWithHash() {
  const hash = window.location.hash.slice(1);
  const [hashRoute, query = ""] = hash.split("?", 2);
  const route = hashRoute === "how-it-works" ? "home" : hashRoute;
  passwordResetToken = route === "account"
    ? new URLSearchParams(query).get("reset_token") || ""
    : "";
  if (passwordResetToken) {
    accountAccessToken = "";
    sessionStorage.removeItem(ACCOUNT_TOKEN_KEY);
    accountProfile = null;
    renderSignedOut();
  }
  const validView = Object.hasOwn(viewTitles, route) ? route : "home";
  setView(validView, false);

  if (passwordResetToken) {
    showAccountForm("reset");
    setAccountStatus("Choose a new password for your account.");
  } else if (hashRoute === "how-it-works") {
    requestAnimationFrame(() => {
      document.getElementById("how-it-works").scrollIntoView({ behavior: "smooth" });
    });
  } else {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
}

let selectedSourceName = "";

let accountAccessToken = sessionStorage.getItem(ACCOUNT_TOKEN_KEY) || "";
let accountProfile = null;
let pendingProtectedView = "";
let passwordResetToken = "";

function resumePendingView() {
  if (!pendingProtectedView) return;
  const view = pendingProtectedView;
  pendingProtectedView = "";
  window.location.hash = view;
}

function setAccountStatus(message, isError = false) {
  const status = document.getElementById("accountStatus");
  status.textContent = message;
  status.classList.toggle("is-error", isError);
}

function showAccountForm(formName) {
  const isRegister = formName === "register";
  const accountForms = {
    login: "loginForm",
    register: "registerForm",
    requestReset: "passwordResetRequestForm",
    reset: "passwordResetForm"
  };
  Object.entries(accountForms).forEach(([name, id]) => {
    document.getElementById(id).hidden = name !== formName;
  });
  document.getElementById("authTabs").hidden = formName === "requestReset" || formName === "reset";
  document.getElementById("loginTab").setAttribute("aria-selected", String(!isRegister));
  document.getElementById("registerTab").setAttribute("aria-selected", String(isRegister));
  setAccountStatus("");
}

function renderAccountProfile(profile) {
  accountProfile = profile;
  document.getElementById("authPanel").hidden = true;
  document.getElementById("profilePanel").hidden = false;
  document.getElementById("accountNavLink").textContent = "Profile";
  const headerCta = document.getElementById("headerCta");
  headerCta.href = "#check";
  headerCta.innerHTML = 'Analyze offer <span aria-hidden="true">↗</span>';
  document.getElementById("profileGreeting").textContent = `Hello, ${profile.display_name}`;
  document.getElementById("profileEmail").textContent = profile.email;
  document.getElementById("profileAvatar").textContent = profile.display_name.trim().charAt(0).toUpperCase() || "T";
  document.getElementById("profileName").value = profile.display_name;
  document.getElementById("profileCollege").value = profile.college;
  document.getElementById("profileCourse").value = profile.course;
  document.getElementById("profileInterests").value = profile.interests;
}

function renderSignedOut() {
  accountProfile = null;
  document.getElementById("authPanel").hidden = false;
  document.getElementById("profilePanel").hidden = true;
  document.getElementById("accountNavLink").textContent = "Sign in";
  const headerCta = document.getElementById("headerCta");
  headerCta.href = "#account";
  headerCta.innerHTML = 'Get started <span aria-hidden="true">↗</span>';
  showAccountForm(passwordResetToken ? "reset" : "login");
}

async function accountRequest(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set("Content-Type", "application/json");
  if (accountAccessToken) headers.set("Authorization", `Bearer ${accountAccessToken}`);

  const response = await fetch(`${API_BASE_URL}${path}`, { ...options, headers });
  const payload = await response.json();
  if (!response.ok) {
    const detail = Array.isArray(payload.detail)
      ? payload.detail.map((item) => item.msg).join(" ")
      : payload.detail;
    const error = new Error(typeof detail === "string" ? detail : "The account request could not be completed.");
    error.status = response.status;
    if (response.status === 401 && accountAccessToken && !path.endsWith("/login")) {
      clearAccountSession("Your session expired. Sign in again.");
    }
    throw error;
  }
  return payload;
}

function clearAccountSession(message) {
  accountAccessToken = "";
  try {
    sessionStorage.removeItem(ACCOUNT_TOKEN_KEY);
  } catch (error) {
    console.error("Unable to clear the expired account session from this browser.", error);
  }
  renderSignedOut();
  const currentView = window.location.hash.slice(1);
  if (accountRequiredViews.has(currentView)) {
    pendingProtectedView = currentView;
    window.history.replaceState(null, "", "#account");
    setView("account", false);
  }
  setAccountStatus(message, true);
}

function saveAccountSession(payload) {
  accountAccessToken = payload.access_token;
  sessionStorage.setItem(ACCOUNT_TOKEN_KEY, accountAccessToken);
  renderAccountProfile(payload.profile);
  setAccountStatus("You are signed in. Your profile is saved to your Trāṇam account.");
  resumePendingView();
}

async function restoreAccountSession() {
  if (!accountAccessToken) {
    renderSignedOut();
    return;
  }

  try {
    const payload = await accountRequest("/api/auth/me");
    renderAccountProfile(payload.profile);
    resumePendingView();
  } catch (error) {
    console.error("Unable to restore the account session.", error);
    if (error.status === 401) {
      accountAccessToken = "";
      sessionStorage.removeItem(ACCOUNT_TOKEN_KEY);
      renderSignedOut();
      setAccountStatus("Your session expired. Sign in again.", true);
    } else {
      setAccountStatus("The account service is unavailable right now. Please try again shortly.", true);
    }
  }
}

document.getElementById("loginTab").addEventListener("click", () => showAccountForm("login"));
document.getElementById("registerTab").addEventListener("click", () => showAccountForm("register"));
document.getElementById("forgotPasswordButton").addEventListener("click", () => {
  document.getElementById("resetEmail").value = document.getElementById("loginEmail").value;
  showAccountForm("requestReset");
});
document.getElementById("backToSignIn").addEventListener("click", () => showAccountForm("login"));

document.getElementById("passwordResetRequestForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  const button = formElement.querySelector('button[type="submit"]');
  button.disabled = true;
  setAccountStatus("Sending reset link…");
  try {
    const result = await accountRequest("/api/auth/password-reset/request", {
      method: "POST",
      body: JSON.stringify({ email: form.get("email") })
    });
    setAccountStatus(result.message);
  } catch (error) {
    console.error("Password reset email request failed.", error);
    setAccountStatus(error instanceof TypeError
      ? "The account service is unavailable right now. Please try again shortly."
      : error.message, true);
  } finally {
    button.disabled = false;
  }
});

document.getElementById("passwordResetForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!passwordResetToken) {
    setAccountStatus("This reset link is missing or invalid. Request a new one.", true);
    return;
  }
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  const password = form.get("password");
  if (password !== form.get("confirm_password")) {
    setAccountStatus("The passwords do not match. Please try again.", true);
    return;
  }
  const button = formElement.querySelector('button[type="submit"]');
  button.disabled = true;
  setAccountStatus("Updating your password…");
  try {
    await accountRequest("/api/auth/password-reset/confirm", {
      method: "POST",
      body: JSON.stringify({ token: passwordResetToken, password })
    });
    passwordResetToken = "";
    window.history.replaceState(null, "", "#account");
    formElement.reset();
    showAccountForm("login");
    setAccountStatus("Your password has been updated. Sign in with your new password.");
  } catch (error) {
    console.error("Password reset could not be completed.", error);
    setAccountStatus(error instanceof TypeError
      ? "The account service is unavailable right now. Please try again shortly."
      : error.message, true);
  } finally {
    button.disabled = false;
  }
});

document.getElementById("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  const button = formElement.querySelector('button[type="submit"]');
  button.disabled = true;
  setAccountStatus("Signing in…");
  try {
    saveAccountSession(await accountRequest("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email: form.get("email"),
        password: form.get("password")
      })
    }));
    formElement.reset();
  } catch (error) {
    console.error("Account sign-in failed.", error);
    setAccountStatus(error instanceof TypeError
      ? "The account service is unavailable right now. Please try again shortly."
      : error.message, true);
  } finally {
    button.disabled = false;
  }
});

document.getElementById("registerForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  const button = formElement.querySelector('button[type="submit"]');
  button.disabled = true;
  setAccountStatus("Creating your account…");
  try {
    saveAccountSession(await accountRequest("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        display_name: form.get("display_name"),
        email: form.get("email"),
        password: form.get("password"),
        college: form.get("college"),
        course: form.get("course"),
        interests: form.get("interests")
      })
    }));
    formElement.reset();
  } catch (error) {
    console.error("Account registration failed.", error);
    setAccountStatus(error instanceof TypeError
      ? "The account service is unavailable right now. Please try again shortly."
      : error.message, true);
  } finally {
    button.disabled = false;
  }
});

document.getElementById("profilePanel").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  setAccountStatus("Saving profile…");
  try {
    const payload = await accountRequest("/api/auth/profile", {
      method: "PATCH",
      body: JSON.stringify({
        display_name: form.get("display_name"),
        college: form.get("college"),
        course: form.get("course"),
        interests: form.get("interests")
      })
    });
    renderAccountProfile(payload.profile);
    setAccountStatus("Your profile has been updated.");
  } catch (error) {
    console.error("Profile update failed.", error);
    setAccountStatus(error instanceof TypeError
      ? "The account service is unavailable right now. Please try again shortly."
      : error.message, true);
  } finally {
    button.disabled = false;
  }
});

document.getElementById("logoutButton").addEventListener("click", async () => {
  let logoutMessage = "You have signed out.";
  let logoutFailed = false;
  try {
    await accountRequest("/api/auth/logout", { method: "POST" });
  } catch (error) {
    console.error("Server-side sign-out failed.", error);
    logoutMessage = "Signed out on this device; the server could not confirm token revocation.";
    logoutFailed = true;
  } finally {
    accountAccessToken = "";
    sessionStorage.removeItem(ACCOUNT_TOKEN_KEY);
    renderSignedOut();
    setAccountStatus(logoutMessage, logoutFailed);
  }
});

async function createOcrWorker(onProgress) {
  if (!tesseractPromise) {
    tesseractPromise = import(TESSERACT_URL).catch((error) => {
      tesseractPromise = null;
      console.error("Unable to load the browser OCR library.", error);
      throw new Error("OCR could not load. Connect to the internet or paste the offer text instead.");
    });
  }

  const tesseract = await tesseractPromise;
  const createWorker = tesseract.createWorker || tesseract.default?.createWorker;
  if (!createWorker) {
    throw new Error("The browser OCR library loaded without its required worker support.");
  }
  return createWorker("eng", 1, {
    logger: ({ status, progress }) => {
      if (status === "recognizing text") {
        onProgress(`Reading text in your browser… ${Math.round(progress * 100)}%`);
      } else if (status) {
        onProgress(`Preparing browser OCR: ${status}…`);
      }
    }
  });
}

async function recognizeImageText(image, onProgress) {
  const worker = await createOcrWorker(onProgress);
  try {
    const result = await worker.recognize(image);
    return result.data.text.trim();
  } finally {
    await worker.terminate();
  }
}

async function extractPdfText(file) {
  if (!pdfjsPromise) {
    pdfjsPromise = import(`${PDFJS_BASE_URL}/pdf.min.mjs`).catch((error) => {
      pdfjsPromise = null;
      console.error("Unable to load PDF.js from its CDN.", error);
      throw new Error("PDF text extraction could not load. Connect to the internet or paste the offer text instead.");
    });
  }

  const pdfjsLib = await pdfjsPromise;
  pdfjsLib.GlobalWorkerOptions.workerSrc = `${PDFJS_BASE_URL}/pdf.worker.min.mjs`;
  const documentTask = pdfjsLib.getDocument({
    data: new Uint8Array(await file.arrayBuffer())
  });
  try {
    const pdfDocument = await documentTask.promise;
    if (pdfDocument.numPages > MAX_PDF_PAGES) {
      throw new Error(`This PDF has more than ${MAX_PDF_PAGES} pages. Split it into smaller files or paste the relevant offer text.`);
    }
    const pages = [];

    for (let pageNumber = 1; pageNumber <= pdfDocument.numPages; pageNumber += 1) {
      const page = await pdfDocument.getPage(pageNumber);
      const content = await page.getTextContent();
      const pageText = content.items
        .filter((item) => typeof item.str === "string")
        .map((item) => item.str)
        .join(" ");
      pages.push(pageText);
    }

    if (pages.some((pageText) => !pageText.trim())) {
      fileNote.textContent = "Some PDF pages have no selectable text. Starting browser-based English OCR…";
      const worker = await createOcrWorker((message) => {
        fileNote.textContent = message;
      });
      try {
        for (let pageIndex = 0; pageIndex < pages.length; pageIndex += 1) {
          if (pages[pageIndex].trim()) continue;
          const pageNumber = pageIndex + 1;
          fileNote.textContent = `Reading scanned PDF page ${pageNumber} of ${pdfDocument.numPages}…`;
          const page = await pdfDocument.getPage(pageNumber);
          const viewport = page.getViewport({ scale: 1.5 });
          const canvas = document.createElement("canvas");
          canvas.width = Math.ceil(viewport.width);
          canvas.height = Math.ceil(viewport.height);
          const context = canvas.getContext("2d");
          if (!context) {
            throw new Error("Your browser could not prepare a PDF page for OCR.");
          }
          try {
            await page.render({ canvasContext: context, viewport }).promise;
            const result = await worker.recognize(canvas);
            pages[pageIndex] = result.data.text;
          } finally {
            canvas.width = 0;
            canvas.height = 0;
          }
        }
      } finally {
        await worker.terminate();
      }
    }

    const text = pages.join("\n").trim();
    if (!text) {
      throw new Error("No readable text was found in this PDF. You can paste the offer text or use a trusted OCR tool.");
    }
    return text;
  } finally {
    await documentTask.destroy();
  }
}

async function loadTextFile(file) {
  const extension = file.name.match(/\.([^.]+)$/)?.[1]?.toLowerCase();
  if (!["pdf", "txt", "md"].includes(extension) && !IMAGE_EXTENSIONS.has(extension)) {
    setError("Choose a PDF, JPG/JPEG, PNG, WEBP, BMP, GIF, TXT, or MD file.");
    return;
  }

  if (file.size > MAX_FILE_SIZE) {
    setError("The selected file is larger than 10 MB. Choose a smaller file.");
    return;
  }

  offerText.value = "";
  selectedSourceName = "";
  fileName.textContent = "";
  fileNote.textContent = "";
  reportView.hidden = true;
  analyzerForm.hidden = false;
  errorMessage.hidden = true;
  updateCharacterCount();

  try {
    let extractedText;
    if (extension === "pdf") {
      extractedText = await extractPdfText(file);
    } else if (IMAGE_EXTENSIONS.has(extension)) {
      fileNote.textContent = "Starting browser-based English OCR… The image stays on this device.";
      extractedText = await recognizeImageText(file, (message) => {
        fileNote.textContent = message;
      });
      if (!extractedText) {
        throw new Error("No readable text was found in this image. Try a clearer screenshot or paste the offer text.");
      }
    } else {
      extractedText = await file.text();
    }

    offerText.value = extractedText;
    selectedSourceName = file.name;
    fileName.textContent = `Added: ${file.name}`;
    fileNote.textContent = extension === "pdf"
      ? "PDF text extracted in your browser. Extraction does not verify document authenticity."
      : IMAGE_EXTENSIONS.has(extension)
        ? "English OCR text extracted in your browser. Check it for recognition mistakes before analysis."
        : "File text loaded locally. The filename is not used as analysis evidence.";
    updateCharacterCount();
    errorMessage.hidden = true;
    reportView.hidden = true;
    analyzerForm.hidden = false;
  } catch (error) {
    console.error("Unable to extract text from the selected file.", error);
    fileNote.textContent = "";
    setError(error.message || "The selected file could not be read. Please try another file.");
  }
}

offerText.addEventListener("input", () => {
  updateCharacterCount();
  errorMessage.hidden = true;
  reportView.hidden = true;
  analyzerForm.hidden = false;
});

["companyName", "companyLink"].forEach((fieldId) => {
  document.getElementById(fieldId).addEventListener("input", () => {
    errorMessage.hidden = true;
    reportView.hidden = true;
    analyzerForm.hidden = false;
  });
});

analyzerForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!accountAccessToken) {
    setView("check");
    return;
  }
  errorMessage.hidden = true;

  const text = offerText.value.trim();
  if (text.length < MIN_OFFER_LENGTH) {
    setError(`Please enter at least ${MIN_OFFER_LENGTH} characters of internship offer details.`);
    offerText.focus();
    return;
  }

  analyzeOffer(
    text,
    document.getElementById("companyName").value.trim(),
    document.getElementById("companyLink").value.trim(),
    selectedSourceName
  );
});

document.getElementById("browseFiles").addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", () => {
  const [file] = fileInput.files;
  if (file) loadTextFile(file);
  fileInput.value = "";
});

["dragenter", "dragover"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("is-dragging");
  });
});

["dragleave", "drop"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("is-dragging");
  });
});

dropZone.addEventListener("drop", (event) => {
  const [file] = event.dataTransfer.files;
  if (file) loadTextFile(file);
});

document.getElementById("chatForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!accountProfile) {
    setView("chat");
    return;
  }

  const chatInput = document.getElementById("chatInput");
  const message = chatInput.value.trim();
  if (!message) return;

  const chatMessages = document.getElementById("chatMessages");
  const userBubble = document.createElement("div");
  userBubble.className = "chat-bubble user-bubble";
  userBubble.textContent = message;
  chatMessages.appendChild(userBubble);
  chatInput.value = "";
  const assistantBubble = document.createElement("div");
  assistantBubble.className = "chat-bubble assistant-bubble";
  assistantBubble.textContent = "Checking the submitted details…";
  chatMessages.appendChild(assistantBubble);
  chatMessages.scrollTop = chatMessages.scrollHeight;

  try {
    const response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `******`
      },
      body: JSON.stringify({ offer_text: message, source_filename: "Quick chat" })
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(typeof payload.detail === "string" ? payload.detail : "Trāṇam could not complete this review. Please try again.");
    }

    const findings = payload.matches.length
      ? `Patterns to review: ${payload.matches.map((match) => match.name).join(", ")}.`
      : "No recognized warning signs were found. This does not verify that the offer is safe.";
    assistantBubble.textContent = `${payload.classification.label} risk (${payload.score}/100). ${payload.summary}\n\n${findings}\n\n${payload.recommendations[0] || "Verify the employer independently."}`;
    saveHistory("Quick chat", payload.score, payload.classification.key);
  } catch (error) {
    console.error("Quick chat analysis request failed.", error);
    assistantBubble.textContent = error instanceof TypeError
      ? "Unable to reach Trāṇam right now. Check your connection and try again."
      : error.message;
  }
  chatMessages.scrollTop = chatMessages.scrollHeight;
});

clearHistoryButton.addEventListener("click", () => {
  try {
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
  } catch (error) {
    console.error("Unable to clear verification history.", error);
    historyStatus.textContent = "History could not be cleared in this browser.";
  }
});

window.addEventListener("hashchange", syncViewWithHash);
document.getElementById("currentYear").textContent = new Date().getFullYear();
updateCharacterCount();
syncViewWithHash();
restoreAccountSession();
