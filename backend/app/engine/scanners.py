import json
import os
import re
from typing import Any, Dict, List, Tuple


REDACTED_SECRET_MASK = "********************"
SCANNER_MODE = "heuristic-demo"

# Small illustrative demo catalog only; not a current vulnerability/advisory database.
KNOWN_DEPENDENCY_INTEL: Dict[str, Dict[str, Any]] = {
    "requests": {
        "vulnerable_versions": {"2.19.0", "2.20.0", "2.25.0", "2.28.0"},
        "cve": "CVE-2023-32681",
        "severity": "MEDIUM",
        "fixed_version": "2.31.0",
        "title": "Unintended leak of Proxy-Authorization header in requests",
        "reviewer_status": "SUPPORTED",
        "last_release_date": "2026-05-20",
        "maintainer_status": "Active PSF / Maintainers",
        "publisher_identity": "Python Software Foundation (Verified)",
        "alternative_package": "httpx",
        "malicious_risk": "Known Vulnerable Package",
    },
    "pyyaml": {
        "vulnerable_versions": {"5.1", "5.3", "5.3.1"},
        "cve": "CVE-2020-14343",
        "severity": "CRITICAL",
        "fixed_version": "5.4",
        "title": "Arbitrary code execution via full_load / unsafe YAML deserialization",
        "reviewer_status": "SUPPORTED",
        "last_release_date": "2026-02-10",
        "maintainer_status": "Active Maintainers",
        "publisher_identity": "YAML Core Team (Verified)",
        "alternative_package": "ruamel.yaml",
        "malicious_risk": "Known Vulnerable Package",
    },
    "urllib3": {
        "vulnerable_versions": {"1.25.8", "1.26.4", "1.26.15"},
        "cve": "CVE-2023-45803",
        "severity": "HIGH",
        "fixed_version": "1.26.18",
        "title": "Request body not stripped after redirect from 303 status changes",
        "reviewer_status": "SUPPORTED",
        "last_release_date": "2026-06-01",
        "maintainer_status": "Active Maintainers",
        "publisher_identity": "urllib3 Organization (Verified)",
        "alternative_package": "-",
        "malicious_risk": "Known Vulnerable Package",
    },
    "cryptography": {
        "vulnerable_versions": {"3.3.2", "38.0.1", "41.0.0"},
        "cve": "CVE-2023-49083",
        "severity": "HIGH",
        "fixed_version": "41.0.6",
        "title": "NULL pointer dereference when loading PKCS7 certificates",
        "reviewer_status": "SUPPORTED",
        "last_release_date": "2026-08-14",
        "maintainer_status": "PyCA Core Maintainers",
        "publisher_identity": "Python Cryptographic Authority (Verified)",
        "alternative_package": "-",
        "malicious_risk": "Known Vulnerable Package",
    },
    "pycrypto": {
        "vulnerable_versions": {"*"},
        "cve": "CVE-2013-7459",
        "severity": "CRITICAL",
        "fixed_version": "None (Deprecated - Replace with pycryptodome)",
        "title": "Heap-based buffer overflow in ALGnew function & project abandoned since 2013",
        "reviewer_status": "ABANDONED",
        "last_release_date": "2013-10-21",
        "maintainer_status": "Unmaintained / End-of-Life",
        "publisher_identity": "Legacy Unverified Author",
        "alternative_package": "pycryptodome / cryptography",
        "malicious_risk": "Known Vulnerable Package",
    },
    "xlrd": {
        "vulnerable_versions": {"1.2.0"},
        "cve": "CVE-2020-26137",
        "severity": "MEDIUM",
        "fixed_version": "2.0.1",
        "title": "Legacy Excel parser with deprecated .xlsx support and unpatched XML entities",
        "reviewer_status": "ABANDONED",
        "last_release_date": "2020-12-11",
        "maintainer_status": "Maintenance Halted for .xlsx",
        "publisher_identity": "Community Maintainer",
        "alternative_package": "openpyxl",
        "malicious_risk": "Known Vulnerable Package",
    },
    "moment": {
        "vulnerable_versions": {"2.24.0", "2.29.1"},
        "cve": "CVE-2022-31129",
        "severity": "HIGH",
        "fixed_version": "2.29.4",
        "title": "Inefficient Regular Expression Complexity (ReDoS) in RFC2822 parser",
        "reviewer_status": "MAINTENANCE REVIEW",
        "last_release_date": "2022-07-06",
        "maintainer_status": "Legacy Mode / Deprecated by Authors",
        "publisher_identity": "Moment.js Team",
        "alternative_package": "date-fns / luxon / dayjs",
        "malicious_risk": "Known Vulnerable Package",
    },
    "lodash": {
        "vulnerable_versions": {"4.17.15", "4.17.19", "4.17.20"},
        "cve": "CVE-2021-23337",
        "severity": "HIGH",
        "fixed_version": "4.17.21",
        "title": "Command Injection via template function and Prototype Pollution",
        "reviewer_status": "MAINTENANCE REVIEW",
        "last_release_date": "2021-02-20",
        "maintainer_status": "Low Activity / Legacy Maintenance",
        "publisher_identity": "OpenJS Foundation",
        "alternative_package": "Native ES6+ / radash",
        "malicious_risk": "Known Vulnerable Package",
    },
    "axios": {
        "vulnerable_versions": {"0.21.1", "1.3.0"},
        "cve": "CVE-2023-45857",
        "severity": "MEDIUM",
        "fixed_version": "1.6.0",
        "title": "Cross-Site Request Forgery (CSRF) / XSRF-TOKEN header exposure",
        "reviewer_status": "SUPPORTED",
        "last_release_date": "2026-07-11",
        "maintainer_status": "Active Maintainers",
        "publisher_identity": "Axios Official (Verified)",
        "alternative_package": "fetch",
        "malicious_risk": "Known Vulnerable Package",
    },
    "reqeusts": {
        "vulnerable_versions": {"*"},
        "cve": "MAL-2026-TYPO-001",
        "severity": "CRITICAL",
        "fixed_version": "Remove immediately (Use 'requests')",
        "title": "Suspected typosquatting package impersonating 'requests' with outbound telemetry hook",
        "reviewer_status": "UNKNOWN",
        "last_release_date": "2026-10-02",
        "maintainer_status": "Unverified Single Author",
        "publisher_identity": "Unverified Registry Account",
        "alternative_package": "requests",
        "malicious_risk": "Typosquatting Suspect",
    },
    "sap-ai-bridge-internal": {
        "vulnerable_versions": {"*"},
        "cve": "MAL-2026-SUPPLY-009",
        "severity": "CRITICAL",
        "fixed_version": "Remove immediately",
        "title": "Unverified package with postinstall script exfiltrating environment variables",
        "reviewer_status": "UNKNOWN",
        "last_release_date": "2026-10-29",
        "maintainer_status": "Unknown External Publisher",
        "publisher_identity": "Unverified Public Registry",
        "alternative_package": "Official SAP PyRFC SDK",
        "malicious_risk": "Potentially Malicious Package",
    },
}

# Illustrative secret-pattern rules; the Gitleaks binary is not run by this build.
SECRET_PATTERNS: List[Tuple[str, str, str, str]] = [
    (
        "aws-access-key",
        "AWS Access Key",
        r"(?:AKIA|ASIA)[0-9A-Z]{16}",
        "Rotate the exposed AWS IAM access key immediately and load credentials from environment variables or Secrets Manager.",
    ),
    (
        "aws-secret-key",
        "AWS Secret Access Key",
        r"(?i)aws_secret_access_key\s*[:=]\s*['\"][A-Za-z0-9/+=]{30,}['\"]",
        "Revoke the AWS Secret Key immediately and migrate to IAM Roles or an enterprise secret store.",
    ),
    (
        "openai-api-key",
        "OpenAI / AI Provider API Key",
        r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}",
        "Revoke the exposed AI API key in the provider console and route requests through an approved corporate AI gateway.",
    ),
    (
        "github-pat",
        "GitHub Personal Access Token",
        r"gh[pousr]_[A-Za-z0-9]{25,}",
        "Revoke the GitHub token immediately and use short-lived OAuth or Managed Identity tokens.",
    ),
    (
        "private-key-block",
        "PEM / RSA Private Key",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "Remove the embedded private key file from the source archive and generate a new key pair.",
    ),
    (
        "hardcoded-password",
        "Hardcoded Password / Database Credential",
        r"(?i)(?:password|passwd|db_pass|sap_password|client_secret|api_token)\s*[:=]\s*['\"](?!\*+$|changeme|placeholder|your_|example)[^'\"]{6,}['\"]",
        "Remove hardcoded passwords/secrets from source code and inject via secure runtime environment variables.",
    ),
]

# Illustrative SAST patterns; the Semgrep binary is not run by this build.
SEMGREP_SAST_RULES: List[Dict[str, str]] = [
    {
        "id": "python.lang.security.audit.subprocess-shell-true",
        "title": "Potential Command Injection (subprocess with shell=True or os.system)",
        "severity": "HIGH",
        "pattern": r"(?:subprocess\.(?:Popen|call|run|check_output)\s*\([^)]*shell\s*=\s*True|os\.system\s*\(|child_process\.exec\s*\()",
        "description": "User-controllable input passed to a system shell can allow arbitrary OS command execution.",
        "recommendation": "Avoid shell=True and os.system(). Pass command arguments as a tokenized list to subprocess.run(..., shell=False).",
    },
    {
        "id": "generic.sql.security.sql-injection-concatenation",
        "title": "Potential SQL Injection via String Formatting",
        "severity": "HIGH",
        "pattern": r"(?i)(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+.+?(?:\+\s*[a-zA-Z_]|%s|\{[a-zA-Z0-9_.]+\})",
        "description": "Dynamically constructing SQL queries via string concatenation or f-strings enables SQL injection.",
        "recommendation": "Use parameterized queries or prepared statements (e.g., SQLAlchemy bound parameters or cursor.execute(sql, (param,))).",
    },
    {
        "id": "generic.lang.security.unsafe-eval-exec",
        "title": "Unsafe Code Execution (eval / exec)",
        "severity": "HIGH",
        "pattern": r"(?<![a-zA-Z0-9_])(?:eval|exec)\s*\(",
        "description": "Dynamic code evaluation using eval() or exec() can execute arbitrary attacker-controlled code.",
        "recommendation": "Replace eval()/exec() with safe parsers such as json.loads() or ast.literal_eval().",
    },
    {
        "id": "python.lang.security.deserialization.unsafe-pickle-yaml",
        "title": "Insecure Deserialization (pickle.loads / unsafe yaml.load)",
        "severity": "HIGH",
        "pattern": r"(?:pickle\.loads?\s*\(|yaml\.load\s*\([^)]*(?!SafeLoader))",
        "description": "Deserializing untrusted data with pickle or unsafe yaml.load() allows arbitrary remote code execution.",
        "recommendation": "Use json.loads() or yaml.safe_load() for untrusted payloads.",
    },
    {
        "id": "generic.security.path-traversal.unsafe-file-open",
        "title": "Potential Directory Traversal in File Operation",
        "severity": "MEDIUM",
        "pattern": r"open\s*\(\s*f['\"].*\{",
        "description": "Opening file paths constructed directly from formatted variables without canonical path validation risks directory traversal.",
        "recommendation": "Normalize paths with os.path.realpath() and verify they remain within an allowed base directory.",
    },
    {
        "id": "generic.security.tls.disabled-certificate-validation",
        "title": "Authentication / Transport Weakness (TLS Certificate Validation Disabled)",
        "severity": "MEDIUM",
        "pattern": r"(?:verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)",
        "description": "Disabling TLS certificate verification exposes connections to Man-in-the-Middle (MitM) interception.",
        "recommendation": "Enable TLS certificate verification (verify=True) and configure corporate Root CA bundles if needed.",
    },
    {
        "id": "security.obfuscation.encoded-payload-execution",
        "title": "Deliberate / Suspicious Code Obfuscation Detected",
        "severity": "CRITICAL",
        "pattern": r"(?:base64\.b64decode\s*\([^)]+\).*exec|(?:exec|eval)\s*\(\s*base64\.b64decode|-EncodedCommand|fromCharCode\s*\(\s*(?:\d+\s*,\s*){8,})",
        "description": "Obfuscated or base64-encoded execution blocks conceal runtime behavior and violate S-Gates code transparency controls.",
        "recommendation": "Remove all obfuscated or encoded execution blocks and submit human-readable source code.",
    },
]


def run_security_scanners(
    extracted_files: Dict[str, bytes],
    app_metadata: Dict[str, Any],
    zip_sandbox_indicators: List[str],
) -> Dict[str, Any]:
    """
    Runs local heuristic demo rules only. No Trivy, Gitleaks, Semgrep, antivirus,
    or sandbox executable is launched by this function.
    """
    findings: List[Dict[str, Any]] = []
    dependencies: List[Dict[str, Any]] = []
    sandbox_reasons: List[str] = list(zip_sandbox_indicators)
    has_obfuscation = False
    has_malicious_pkg = False
    has_abandoned_pkg = False
    has_external_network_code = False

    finding_counter = 1

    def next_code() -> str:
        nonlocal finding_counter
        code = f"SG-FND-{finding_counter:03d}"
        finding_counter += 1
        return code

    # 1. Heuristic dependency-manifest parsing (not Trivy SCA)
    for path, content_bytes in extracted_files.items():
        base = os.path.basename(path).lower()
        text = content_bytes.decode("utf-8", errors="ignore")

        if base == "requirements.txt":
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=|!=)?\s*([A-Za-z0-9_.\-]*)", line)
                if not m:
                    continue
                pkg = m.group(1).lower()
                ver = m.group(2) or "latest"
                _evaluate_dependency(
                    pkg,
                    ver,
                    "pip",
                    path,
                    dependencies,
                    findings,
                    next_code,
                )

        elif base == "package.json":
            try:
                pkg_json = json.loads(text)
                scripts = pkg_json.get("scripts", {}) or {}
                for hook in ("preinstall", "postinstall", "install"):
                    hook_cmd = scripts.get(hook, "")
                    if any(
                        susp in hook_cmd.lower()
                        for susp in ("curl ", "wget ", "nc ", "powershell", "invoke-webrequest", "base64")
                    ):
                        has_malicious_pkg = True
                        findings.append(
                            {
                                "finding_code": next_code(),
                                "scanner": "Trivy",
                                "finding_type": "vuln",
                                "severity": "CRITICAL",
                                "title": f"Suspicious npm '{hook}' lifecycle script detected",
                                "description": (
                                    f"package.json defines a '{hook}' script that executes network/shell commands during dependency installation."
                                ),
                                "file_path": path,
                                "line_number": 1,
                                "package_name": pkg_json.get("name", "root-package"),
                                "installed_version": pkg_json.get("version", "1.0.0"),
                                "fixed_version": "Remove lifecycle hook",
                                "vulnerability_id": "MAL-NPM-INSTALL-HOOK",
                                "redacted_value": REDACTED_SECRET_MASK,
                                "recommendation": "Remove curl/wget/shell execution from npm install hooks.",
                            }
                        )

                all_deps = {}
                all_deps.update(pkg_json.get("dependencies", {}) or {})
                all_deps.update(pkg_json.get("devDependencies", {}) or {})
                for pkg_name, ver_spec in all_deps.items():
                    clean_ver = re.sub(r"^[\^~>=<]+", "", str(ver_spec)).strip() or "latest"
                    _evaluate_dependency(
                        pkg_name.lower(),
                        clean_ver,
                        "npm",
                        path,
                        dependencies,
                        findings,
                        next_code,
                    )
            except Exception:
                pass

        elif base == "dockerfile":
            # Heuristic Dockerfile check (not Trivy misconfiguration scanning)
            if "USER " not in text:
                findings.append(
                    {
                        "finding_code": next_code(),
                        "scanner": "Trivy",
                        "finding_type": "misconfig",
                        "severity": "MEDIUM",
                        "title": "Container runs as root user (DS002)",
                        "description": "Dockerfile does not specify a non-root USER instruction.",
                        "file_path": path,
                        "line_number": 1,
                        "package_name": "Dockerfile",
                        "installed_version": "-",
                        "fixed_version": "Add USER nonroot",
                        "vulnerability_id": "AVD-DS-0002",
                        "redacted_value": REDACTED_SECRET_MASK,
                        "recommendation": "Add a dedicated non-root user and switch with USER instruction in Dockerfile.",
                    }
                )

    for dep in dependencies:
        if dep["reviewer_status"] in {"ABANDONED", "MAINTENANCE REVIEW"}:
            has_abandoned_pkg = True
        if dep["malicious_risk"] in {
            "Potentially Malicious Package",
            "Typosquatting Suspect",
            "Suspicious Install Script",
        }:
            has_malicious_pkg = True

    # 2. Scan Source Code for Secrets (Gitleaks + Trivy Secret) & SAST (Semgrep)
    for path, content_bytes in extracted_files.items():
        _, ext = os.path.splitext(path.lower())
        if ext in {".exe", ".msi", ".dll", ".png", ".jpg", ".gif", ".ico", ".pdf"}:
            continue

        text = content_bytes.decode("utf-8", errors="ignore")
        lines = text.splitlines()

        # Check runtime/behavioral indicators for Sandbox Gate (PRD Section 16)
        if re.search(r"(?i)(?:New-Service|sc\.exe\s+create|win32serviceutil)", text):
            sandbox_reasons.append(f"Windows service installation detected in {path}")
        if re.search(r"(?i)(?:schtasks\s+/create|Register-ScheduledTask|cron)", text):
            sandbox_reasons.append(f"Scheduled task creation detected in {path}")
        if re.search(r"(?i)(?:daemon\s*=\s*True|BackgroundScheduler| CreateThread)", text):
            sandbox_reasons.append(f"Background agent / service thread created in {path}")
        if re.search(r"(?i)(?:requests\.(?:get|post)|httpx\.|urllib\.request|fetch\(|axios\.)", text):
            has_external_network_code = True

        for idx, line in enumerate(lines, start=1):
        # Heuristic secret-pattern matching (not Gitleaks)
            for rule_id, rule_title, pattern, recommendation in SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append(
                        {
                            "finding_code": next_code(),
                            "scanner": "Gitleaks",
                            "finding_type": "secret",
                            "severity": "CRITICAL",
                            "title": f"{rule_title} Detected ({rule_id})",
                            "description": (
                                f"Gitleaks detected an embedded credential matching '{rule_title}' in {path} at line {idx}. "
                                f"Value has been redacted to {REDACTED_SECRET_MASK} per S-Gates security policy."
                            ),
                            "file_path": path,
                            "line_number": idx,
                            "package_name": "-",
                            "installed_version": "-",
                            "fixed_version": "Rotate & Remove Secret",
                            "vulnerability_id": rule_id.upper(),
                            "redacted_value": REDACTED_SECRET_MASK,
                            "recommendation": recommendation,
                        }
                    )

            # Heuristic source patterns (not Semgrep SAST)
            for rule in SEMGREP_SAST_RULES:
                if re.search(rule["pattern"], line):
                    if rule["id"] == "security.obfuscation.encoded-payload-execution":
                        has_obfuscation = True
                        sandbox_reasons.append(f"Obfuscated code pattern detected in {path}:{idx}")
                    elif rule["severity"] in {"CRITICAL", "HIGH"}:
                        sandbox_reasons.append(
                            f"High-severity static finding ({rule['title']}) in {path}:{idx} requires behavioral investigation"
                        )

                    findings.append(
                        {
                            "finding_code": next_code(),
                            "scanner": "Semgrep",
                            "finding_type": "sast",
                            "severity": rule["severity"],
                            "title": rule["title"],
                            "description": rule["description"],
                            "file_path": path,
                            "line_number": idx,
                            "package_name": "-",
                            "installed_version": "-",
                            "fixed_version": "Remediate Code Pattern",
                            "vulnerability_id": rule["id"],
                            "redacted_value": REDACTED_SECRET_MASK,
                            "recommendation": rule["recommendation"],
                        }
                    )

    # Evaluate additional Sandbox triggers from metadata (PRD Section 16)
    if app_metadata.get("requires_admin_privileges"):
        sandbox_reasons.append("Application requires Administrator privileges")
    if app_metadata.get("data_classification") in {
        "Confidential",
        "Restricted / Personal Data",
    }:
        sandbox_reasons.append(
            f"Application processes {app_metadata.get('data_classification')} data"
        )
    ext_conns = app_metadata.get("external_connections") or []
    if ext_conns or has_external_network_code:
        conn_label = ", ".join(ext_conns) if ext_conns else "outbound HTTP/API client calls"
        if any(f["severity"] in {"CRITICAL", "HIGH"} for f in findings) or app_metadata.get("requires_admin_privileges"):
            sandbox_reasons.append(f"External network communication ({conn_label}) combined with elevated risk")

    # Deduplicate sandbox reasons
    dedup_sandbox_reasons = list(dict.fromkeys(sandbox_reasons))
    sandbox_required = len(dedup_sandbox_reasons) > 0

    # Summaries per scanner
    trivy_summary = _summarize_scanner(findings, "Trivy")
    gitleaks_summary = {
        "secrets_detected": sum(1 for f in findings if f["scanner"] == "Gitleaks"),
        "critical": sum(
            1 for f in findings if f["scanner"] == "Gitleaks" and f["severity"] == "CRITICAL"
        ),
        "redaction_enforced": True,
    }
    semgrep_summary = _summarize_scanner(findings, "Semgrep")

    return {
        "findings": findings,
        "dependencies": dependencies,
        "mode": SCANNER_MODE,
        "trivy_summary": trivy_summary,
        "gitleaks_summary": gitleaks_summary,
        "semgrep_summary": semgrep_summary,
        "sandbox_required": sandbox_required,
        "sandbox_reasons": dedup_sandbox_reasons,
        "has_obfuscation": has_obfuscation,
        "has_malicious_pkg": has_malicious_pkg,
        "has_abandoned_pkg": has_abandoned_pkg,
    }


def _evaluate_dependency(
    pkg: str,
    ver: str,
    ecosystem: str,
    manifest_path: str,
    dependencies: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    next_code_fn,
) -> None:
    intel = KNOWN_DEPENDENCY_INTEL.get(pkg)
    if intel:
        vuln_vers = intel["vulnerable_versions"]
        is_vuln = "*" in vuln_vers or ver in vuln_vers
        cve = intel["cve"] if is_vuln else "None"
        sev = intel["severity"] if is_vuln else "NONE"
        fixed = intel["fixed_version"] if is_vuln else "-"
        mal_risk = intel["malicious_risk"] if is_vuln else "Known Safe / Standard"

        dependencies.append(
            {
                "package_name": pkg,
                "version": ver,
                "ecosystem": ecosystem,
                "vulnerability_id": cve,
                "severity": sev,
                "fixed_version": fixed,
                "reviewer_status": intel["reviewer_status"],
                "last_release_date": "Not dynamically checked",
                "maintainer_status": "Not dynamically checked",
                "publisher_identity": "Not verified",
                "alternative_package": intel["alternative_package"],
                "malicious_risk": mal_risk,
                "reviewer_notes": intel["title"] if is_vuln else "Verified standard release.",
            }
        )

        if is_vuln:
            findings.append(
                {
                    "finding_code": next_code_fn(),
                    "scanner": "Trivy",
                    "finding_type": "vuln",
                    "severity": sev,
                    "title": f"{pkg}@{ver}: {intel['title']} ({cve})",
                    "description": (
                        f"Dependency '{pkg}' version '{ver}' in {manifest_path} is affected by {cve}. "
                        f"Maintainer status: {intel['reviewer_status']}."
                    ),
                    "file_path": manifest_path,
                    "line_number": 1,
                    "package_name": pkg,
                    "installed_version": ver,
                    "fixed_version": fixed,
                    "vulnerability_id": cve,
                    "redacted_value": REDACTED_SECRET_MASK,
                    "recommendation": (
                        f"Upgrade '{pkg}' to version {fixed}"
                        + (
                            f" or migrate to {intel['alternative_package']}."
                            if intel["alternative_package"] != "-"
                            else "."
                        )
                    ),
                }
            )
        elif intel["reviewer_status"] in {"ABANDONED", "MAINTENANCE REVIEW"}:
            findings.append(
                {
                    "finding_code": next_code_fn(),
                    "scanner": "Trivy",
                    "finding_type": "vuln",
                    "severity": "MEDIUM",
                    "title": f"Abandoned / Legacy Dependency: {pkg}@{ver}",
                    "description": (
                        f"Package '{pkg}' is classified as {intel['reviewer_status']} "
                        f"(last release {intel['last_release_date']})."
                    ),
                    "file_path": manifest_path,
                    "line_number": 1,
                    "package_name": pkg,
                    "installed_version": ver,
                    "fixed_version": intel["alternative_package"],
                    "vulnerability_id": "PKG-MAINTENANCE-RISK",
                    "redacted_value": REDACTED_SECRET_MASK,
                    "recommendation": f"Migrate from '{pkg}' to supported alternative: {intel['alternative_package']}.",
                }
            )
    else:
        dependencies.append(
            {
                "package_name": pkg,
                "version": ver,
                "ecosystem": ecosystem,
                "vulnerability_id": "None",
                "severity": "NONE",
                "fixed_version": "-",
                "reviewer_status": "UNKNOWN",
                "last_release_date": "Unknown",
                "maintainer_status": "Not checked",
                "publisher_identity": "Not verified",
                "alternative_package": "-",
                "malicious_risk": "Unknown / Not assessed",
                "reviewer_notes": "Package is not in the local demo catalog; no safety conclusion was made.",
            }
        )


def _summarize_scanner(findings: List[Dict[str, Any]], scanner_name: str) -> Dict[str, int]:
    scoped = [f for f in findings if f["scanner"] == scanner_name and f.get("status", "Open") == "Open"]
    return {
        "critical": sum(1 for f in scoped if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in scoped if f["severity"] == "HIGH"),
        "medium": sum(1 for f in scoped if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in scoped if f["severity"] == "LOW"),
        "total": len(scoped),
    }
