# OWASP Top 5 Smart Bug Report Generator

A logic-driven web application for generating structured security vulnerability reports based on OWASP Top 10 concepts.

Built using a rule-based engine (no external APIs or AI services), this tool helps standardize and speed up the bug reporting process for cybersecurity learners and bug bounty beginners.

---

## 🧠 Why this project?

Writing bug bounty reports manually can be:
- Time-consuming  
- Inconsistent in structure  
- Difficult for beginners to format correctly  

This tool helps:
- Standardize report writing  
- Guide users with structured inputs  
- Reduce effort in creating professional-looking reports  

---

## 🚀 Features

- Smart dynamic form — adapts based on selected vulnerability type  
- Severity auto-calculation — keyword-based classification (High/Medium/Low)  
- Structured report output including:
  - Title  
  - OWASP Category  
  - CWE Mapping  
  - Steps to Reproduce  
  - Impact  
  - Mitigation  
- Input improvement suggestions for incomplete or vague entries  
- Copy to Clipboard — formatted plaintext report  
- PDF Download — via browser print dialog  
- Clean dark UI for better readability  

---

## 🛡 Supported Vulnerabilities

| Type | OWASP ID | CWE |
|------|----------|-----|
| Cross-Site Scripting (XSS) | A03:2021 | CWE-79 |
| SQL Injection | A03:2021 | CWE-89 |
| Broken Access Control (IDOR) | A01:2021 | CWE-639 |
| Security Misconfiguration | A05:2021 | CWE-16 |
| Sensitive Data Exposure | A02:2021 | CWE-200 |

---

## 📸 Demo



---

## 🌐 Live Demo



---

## ⚙️ Project Structure

```
owasp-bug-report/
├── app.py              ← Flask routes (entry point)
├── report_engine.py    ← Logic engine: severity, templates, suggestions
├── requirements.txt    ← Python dependencies
├── templates/
│   └── index.html      ← Frontend UI
└── static/
    ├── style.css       ← Styling
    └── app.js          ← Frontend logic
```



---

## ▶️ Setup & Run

```bash
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
