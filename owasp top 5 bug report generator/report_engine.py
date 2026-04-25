"""
report_engine.py
Logic-based report generation and severity calculation engine.
No external AI or paid APIs — all rules and templates are hand-crafted.
"""

from datetime import datetime
import uuid

# ─────────────────────────────────────────────
#  SEVERITY RULES
#  Each rule maps keyword triggers → severity level
# ─────────────────────────────────────────────

SEVERITY_RULES = {
    "High": [
        "account takeover", "authentication bypass", "admin", "administrator",
        "remote code execution", "rce", "full database", "all records", "all users",
        "password", "credentials", "token", "session hijack", "stored xss",
        "blind sql", "union-based", "exfiltration", "pii", "personal data",
        "credit card", "ssn", "social security", "health record",
    ],
    "Medium": [
        "unauthorized access", "idor", "object reference", "other user",
        "reflected xss", "limited data", "partial access", "dom-based",
        "error-based sql", "time-based", "misconfiguration", "default credentials",
        "directory listing", "stack trace", "debug mode",
    ],
    "Low": [
        "self xss", "minor", "informational", "low impact", "no sensitive",
        "public data", "verbose error", "banner grabbing", "version disclosure",
    ],
}

# ─────────────────────────────────────────────
#  OWASP CATEGORY METADATA
# ─────────────────────────────────────────────

OWASP_META = {
    "xss": {
        "label": "Cross-Site Scripting (XSS)",
        "owasp_id": "A03:2021",
        "owasp_name": "Injection",
        "cwe": "CWE-79",
    },
    "sqli": {
        "label": "SQL Injection",
        "owasp_id": "A03:2021",
        "owasp_name": "Injection",
        "cwe": "CWE-89",
    },
    "idor": {
        "label": "Broken Access Control (IDOR)",
        "owasp_id": "A01:2021",
        "owasp_name": "Broken Access Control",
        "cwe": "CWE-639",
    },
    "misconfig": {
        "label": "Security Misconfiguration",
        "owasp_id": "A05:2021",
        "owasp_name": "Security Misconfiguration",
        "cwe": "CWE-16",
    },
    "exposure": {
        "label": "Sensitive Data Exposure",
        "owasp_id": "A02:2021",
        "owasp_name": "Cryptographic Failures",
        "cwe": "CWE-200",
    },
}

# ─────────────────────────────────────────────
#  MITIGATION TEMPLATES
# ─────────────────────────────────────────────

MITIGATIONS = {
    "xss": [
        "Encode all user-supplied output using context-aware encoding (HTML, JS, CSS, URL).",
        "Implement a strict Content Security Policy (CSP) header to restrict script execution.",
        "Use modern frameworks that auto-escape output (e.g., React, Angular) instead of raw innerHTML.",
        "Validate and sanitize all inputs server-side using an allowlist approach.",
        "Set the HttpOnly and Secure flags on session cookies to prevent theft via XSS.",
    ],
    "sqli": [
        "Use parameterized queries (prepared statements) exclusively — never concatenate user input into SQL.",
        "Apply the principle of least privilege to database accounts; avoid using root/admin DB users in apps.",
        "Deploy a Web Application Firewall (WAF) with SQLi rule sets as a defense-in-depth measure.",
        "Validate all inputs server-side; reject or sanitize unexpected characters.",
        "Implement error handling that never exposes raw database errors or stack traces to users.",
    ],
    "idor": [
        "Implement server-side authorization checks on every resource access — never trust client-supplied IDs alone.",
        "Use indirect reference maps (GUIDs, hashed IDs) instead of sequential integers for object identifiers.",
        "Enforce role-based or attribute-based access control (RBAC/ABAC) consistently across all endpoints.",
        "Log and alert on access-control failures; consider rate-limiting requests to sensitive objects.",
        "Conduct thorough access-control testing (horizontal and vertical privilege escalation) during QA.",
    ],
    "misconfig": [
        "Disable default accounts, sample applications, and unused features in all environments.",
        "Apply security hardening guides (CIS Benchmarks) for your OS, web server, and frameworks.",
        "Automate configuration scanning with tools like Lynis, ScoutSuite, or AWS Security Hub.",
        "Separate production from development/debug configurations; never enable debug mode in production.",
        "Review and tighten HTTP security headers: HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy.",
    ],
    "exposure": [
        "Encrypt sensitive data at rest using AES-256 and in transit using TLS 1.2+ with strong cipher suites.",
        "Never store plaintext passwords; use adaptive hashing algorithms (bcrypt, Argon2, scrypt).",
        "Audit all data flows; ensure PII and secrets are not logged, cached, or included in error messages.",
        "Apply data minimisation: collect and retain only what is strictly necessary for business purposes.",
        "Use secrets management solutions (HashiCorp Vault, AWS Secrets Manager) — never hardcode credentials.",
    ],
}

# ─────────────────────────────────────────────
#  IMPROVEMENT SUGGESTIONS (triggered on weak input)
# ─────────────────────────────────────────────

IMPROVEMENT_HINTS = {
    "xss": [
        "Include the exact payload string used (e.g., <script>alert(1)</script> or a DOM-based variant).",
        "Specify whether the payload is Stored, Reflected, or DOM-based — this significantly changes severity.",
        "Provide proof of concept: a URL, form field name, or HTTP request snippet.",
        "Document any bypasses used (e.g., filter evasion techniques).",
    ],
    "sqli": [
        "Specify the injection type (error-based, blind boolean, time-based, UNION) to improve severity accuracy.",
        "Include the vulnerable parameter name and sample HTTP request.",
        "Note which database system is in use (MySQL, MSSQL, PostgreSQL) if known.",
        "If data was extracted, specify what was exposed (table names, credentials, PII).",
    ],
    "idor": [
        "Document the exact IDs manipulated (e.g., changed user_id=123 to user_id=124).",
        "Confirm whether vertical privilege escalation (lower role → higher role) is also possible.",
        "List what data was accessible or modifiable via the exposed endpoint.",
        "Include the HTTP method and endpoint path (e.g., GET /api/users/{id}/profile).",
    ],
    "misconfig": [
        "Specify the exact misconfiguration observed (e.g., directory listing enabled, default credentials).",
        "Include the server response or screenshot evidence of the finding.",
        "Note the environment (production, staging) to accurately assess risk.",
        "Check for related misconfigurations: CORS, CSP, HTTP headers.",
    ],
    "exposure": [
        "Identify the type of data exposed (credentials, PII, health data, financial info).",
        "Document how the data was discovered (API response, log file, error message).",
        "Confirm whether encryption was absent, weak, or improperly implemented.",
        "Check if the exposed data is indexed by search engines or accessible without authentication.",
    ],
}

# ─────────────────────────────────────────────
#  INPUT VALIDATION
# ─────────────────────────────────────────────

REQUIRED_FIELDS = {
    "xss": ["url", "payload", "xss_type", "execution_proof"],
    "sqli": ["url", "injection_type", "db_impact", "parameter"],
    "idor": ["url", "object_id", "accessed_data", "http_method"],
    "misconfig": ["url", "misconfig_type", "environment", "evidence"],
    "exposure": ["url", "data_type", "discovery_method", "encryption_status"],
}


def validate_inputs(data: dict) -> dict:
    """
    Validate that required fields are present and non-empty.
    Returns a dict with 'valid' bool and optional 'message'.
    """
    vuln_type = data.get("vuln_type", "").lower()
    if vuln_type not in REQUIRED_FIELDS:
        return {"valid": False, "message": f"Unknown vulnerability type: '{vuln_type}'"}

    required = REQUIRED_FIELDS[vuln_type]
    missing = [field for field in required if not data.get(field, "").strip()]

    if missing:
        return {
            "valid": False,
            "message": f"Missing required fields: {', '.join(missing)}",
        }
    return {"valid": True}


# ─────────────────────────────────────────────
#  SEVERITY CALCULATOR
# ─────────────────────────────────────────────

def calculate_severity(data: dict) -> str:
    """
    Calculate severity by scanning all input values for known trigger keywords.
    Priority: High → Medium → Low (first match wins at highest tier).
    """
    # Build a single lowercase string from all input values for keyword scanning
    combined_text = " ".join(str(v).lower() for v in data.values())

    for level in ["High", "Medium", "Low"]:
        for keyword in SEVERITY_RULES[level]:
            if keyword in combined_text:
                return level

    # Default to Medium if no clear signal
    return "Medium"


# ─────────────────────────────────────────────
#  WEAKNESS DETECTOR (triggers improvement hints)
# ─────────────────────────────────────────────

WEAKNESS_SIGNALS = ["n/a", "none", "unknown", "not sure", "todo", "tbd", "example", "test"]


def detect_weak_inputs(data: dict, vuln_type: str) -> list:
    """
    Detect vague or placeholder inputs and return relevant improvement suggestions.
    """
    is_weak = False
    for key, val in data.items():
        if key == "vuln_type":
            continue
        if any(signal in str(val).lower() for signal in WEAKNESS_SIGNALS) or len(str(val).strip()) < 10:
            is_weak = True
            break

    return IMPROVEMENT_HINTS.get(vuln_type, []) if is_weak else []


# ─────────────────────────────────────────────
#  REPORT BUILDERS (one per vulnerability type)
# ─────────────────────────────────────────────

def build_xss_report(data: dict, severity: str) -> dict:
    xss_type = data.get("xss_type", "Reflected")
    payload = data.get("payload", "")
    url = data.get("url", "")
    proof = data.get("execution_proof", "")

    return {
        "title": f"{xss_type} Cross-Site Scripting (XSS) via User-Controlled Input",
        "description": (
            f"A {xss_type} Cross-Site Scripting vulnerability was identified at the endpoint "
            f"'{url}'. An attacker can inject and execute arbitrary JavaScript in the context "
            f"of a victim's browser session by supplying a crafted payload. "
            f"This occurs because user-supplied input is reflected in the HTTP response without "
            f"adequate encoding or sanitization."
        ),
        "steps_to_reproduce": [
            f"Navigate to the vulnerable endpoint: {url}",
            f"Identify the input vector (form field, URL parameter, HTTP header).",
            f"Submit the following payload: {payload}",
            f"Observe execution: {proof}",
            "Confirm that the payload executes within the victim's browser session.",
        ],
        "impact": _xss_impact(xss_type, severity),
    }


def _xss_impact(xss_type: str, severity: str) -> str:
    impacts = {
        "Stored": (
            "Stored XSS persists in the application database and executes for every user who "
            "views the affected page. This enables large-scale session hijacking, credential theft, "
            "malware distribution, and full account takeover at scale."
        ),
        "Reflected": (
            "Reflected XSS allows an attacker to craft a malicious URL that, when visited by a "
            "victim, executes arbitrary JavaScript in their browser. This can be used for "
            "session hijacking, phishing, and credential harvesting."
        ),
        "DOM-based": (
            "DOM-based XSS executes entirely client-side, making it harder to detect via "
            "server-side scanning. It enables the same attack surface as Reflected XSS but "
            "may bypass server-side WAF rules."
        ),
    }
    return impacts.get(xss_type, impacts["Reflected"])


def build_sqli_report(data: dict, severity: str) -> dict:
    injection_type = data.get("injection_type", "Error-based")
    db_impact = data.get("db_impact", "")
    url = data.get("url", "")
    parameter = data.get("parameter", "")

    return {
        "title": f"SQL Injection ({injection_type}) in Parameter '{parameter}'",
        "description": (
            f"A {injection_type} SQL Injection vulnerability was identified in the '{parameter}' "
            f"parameter at '{url}'. The application constructs SQL queries by concatenating "
            f"user-controlled input without parameterization, allowing an attacker to manipulate "
            f"query logic and interact directly with the backend database."
        ),
        "steps_to_reproduce": [
            f"Navigate to the vulnerable endpoint: {url}",
            f"Locate the vulnerable parameter: '{parameter}'",
            f"Inject a SQL payload appropriate for {injection_type} injection.",
            f"Observe the database response or inferred behavior.",
            f"Database impact confirmed: {db_impact}",
        ],
        "impact": (
            f"Successful exploitation allows an attacker to {db_impact.lower()}. "
            "Depending on the database user's privileges, this could extend to reading arbitrary "
            "files, executing OS commands (via xp_cmdshell or UDF), or dumping the entire database "
            "including credentials and PII. This constitutes a critical data breach risk."
        ),
    }


def build_idor_report(data: dict, severity: str) -> dict:
    url = data.get("url", "")
    object_id = data.get("object_id", "")
    accessed_data = data.get("accessed_data", "")
    http_method = data.get("http_method", "GET")

    return {
        "title": f"Insecure Direct Object Reference (IDOR) Allowing Unauthorized Data Access",
        "description": (
            f"An Insecure Direct Object Reference vulnerability was identified at '{url}'. "
            f"By manipulating the object identifier ('{object_id}') in a {http_method} request, "
            f"an authenticated user can access resources belonging to other users without "
            f"authorization. The server performs no ownership or permission validation."
        ),
        "steps_to_reproduce": [
            f"Authenticate as a low-privileged user (User A).",
            f"Send a {http_method} request to: {url}",
            f"Modify the object ID parameter to: {object_id}",
            "Observe that the server returns data belonging to another user.",
            f"Confirmed accessible data: {accessed_data}",
        ],
        "impact": (
            f"This vulnerability enables horizontal privilege escalation, allowing any "
            f"authenticated user to access or manipulate data belonging to other accounts. "
            f"Exposed data includes: {accessed_data}. "
            "Depending on the endpoint, an attacker could also modify or delete resources, "
            "leading to data integrity violations and potential account takeover."
        ),
    }


def build_misconfig_report(data: dict, severity: str) -> dict:
    url = data.get("url", "")
    misconfig_type = data.get("misconfig_type", "")
    environment = data.get("environment", "Production")
    evidence = data.get("evidence", "")

    return {
        "title": f"Security Misconfiguration: {misconfig_type} Detected in {environment}",
        "description": (
            f"A security misconfiguration of type '{misconfig_type}' was identified at '{url}' "
            f"in the {environment} environment. This configuration weakness exposes the application "
            "to unnecessary attack surface and may assist an attacker in reconnaissance, "
            "exploitation, or privilege escalation."
        ),
        "steps_to_reproduce": [
            f"Navigate to or probe the endpoint: {url}",
            f"Identify the misconfiguration: {misconfig_type}",
            f"Observe evidence of the issue: {evidence}",
            f"Confirm this is present in: {environment} environment.",
        ],
        "impact": (
            f"The identified misconfiguration ({misconfig_type}) in {environment} "
            "can provide attackers with sensitive information (server versions, internal paths, "
            "debug data), enable unauthorized access via default credentials, or expose "
            "administrative interfaces. In production environments, this significantly lowers "
            "the barrier for targeted attacks."
        ),
    }


def build_exposure_report(data: dict, severity: str) -> dict:
    url = data.get("url", "")
    data_type = data.get("data_type", "")
    discovery_method = data.get("discovery_method", "")
    encryption_status = data.get("encryption_status", "")

    return {
        "title": f"Sensitive Data Exposure: {data_type} Accessible Without Adequate Protection",
        "description": (
            f"Sensitive data of type '{data_type}' was found to be exposed at '{url}'. "
            f"The data was discovered via: {discovery_method}. "
            f"Encryption/protection status: {encryption_status}. "
            "Failure to adequately protect sensitive data violates the principle of data minimisation "
            "and may constitute a breach under GDPR, HIPAA, or PCI-DSS depending on the data category."
        ),
        "steps_to_reproduce": [
            f"Access the endpoint or resource at: {url}",
            f"Apply the following discovery method: {discovery_method}",
            f"Observe that {data_type} data is exposed.",
            f"Confirm protection status: {encryption_status}",
        ],
        "impact": (
            f"Exposure of {data_type} can lead to identity theft, financial fraud, regulatory "
            "fines, and reputational damage. If credentials are exposed, full account takeover "
            "is possible. Depending on the volume of data and jurisdictional regulations, "
            "this may require mandatory breach notification to authorities and affected individuals."
        ),
    }


# ─────────────────────────────────────────────
#  MAIN REPORT GENERATOR
# ─────────────────────────────────────────────

REPORT_BUILDERS = {
    "xss": build_xss_report,
    "sqli": build_sqli_report,
    "idor": build_idor_report,
    "misconfig": build_misconfig_report,
    "exposure": build_exposure_report,
}


def generate_report(data: dict) -> dict:
    """
    Orchestrate report generation:
    1. Identify vulnerability type
    2. Calculate severity
    3. Build type-specific report sections
    4. Detect weak inputs for improvement hints
    5. Assemble final report object
    """
    vuln_type = data.get("vuln_type", "").lower()
    meta = OWASP_META[vuln_type]
    severity = calculate_severity(data)
    builder = REPORT_BUILDERS[vuln_type]
    core = builder(data, severity)
    suggestions = detect_weak_inputs(data, vuln_type)
    mitigations = MITIGATIONS[vuln_type]

    report = {
        "report_id": str(uuid.uuid4())[:8].upper(),
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "title": core["title"],
        "owasp_category": meta["label"],
        "owasp_id": meta["owasp_id"],
        "owasp_name": meta["owasp_name"],
        "cwe": meta["cwe"],
        "severity": severity,
        "description": core["description"],
        "steps_to_reproduce": core["steps_to_reproduce"],
        "impact": core["impact"],
        "mitigation": mitigations,
        "improvement_suggestions": suggestions,
        "reporter_url": data.get("url", ""),
    }

    return report
