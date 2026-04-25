# OWASP Top 5 Smart Bug Report Generator

A complete, logic-driven web application for generating professional security vulnerability reports.
No external APIs, no AI services — pure rule-based engine.

## Project Structure

```
owasp-bug-report/
├── app.py              ← Flask routes (entry point)
├── report_engine.py    ← Logic engine: severity, templates, suggestions
├── requirements.txt    ← Python dependencies
├── templates/
│   └── index.html      ← Single-page frontend
└── static/
    ├── style.css       ← Dark cybersecurity UI
    └── app.js          ← Dynamic form, API calls, PDF generation
```

## Setup & Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the app
python app.py

# 3. Open in browser
# http://localhost:5000
```

## Supported Vulnerabilities

| Type | OWASP ID | CWE |
|------|----------|-----|
| Cross-Site Scripting (XSS) | A03:2021 | CWE-79 |
| SQL Injection | A03:2021 | CWE-89 |
| Broken Access Control (IDOR) | A01:2021 | CWE-639 |
| Security Misconfiguration | A05:2021 | CWE-16 |
| Sensitive Data Exposure | A02:2021 | CWE-200 |

## Features

- **Smart dynamic form** — fields change based on selected vulnerability
- **Severity auto-calculation** — keyword-based rules (High/Medium/Low)
- **Professional report structure** — Title, OWASP Category, CWE, Steps, Impact, Mitigation
- **Improvement suggestions** — triggered when inputs are vague or incomplete
- **Copy to Clipboard** — formatted plaintext report
- **PDF Download** — via browser print dialog (no external libraries)
- **Dark cybersecurity UI** — JetBrains Mono + Syne fonts, neon accents
