from typing import Any, Dict, List, Tuple


def evaluate_risk_decision(
    zip_valid: bool,
    zip_errors: List[str],
    security_intel_status: str,
    trivy_db_available: bool,
    findings: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]],
    app_metadata: Dict[str, Any],
    av_status: str = "Pending",
    sandbox_required: bool = False,
) -> Tuple[str, str, List[str]]:
    """
    PRD Section 20 & Section 30: Risk Decision Engine.
    Returns (technical_status, risk_level, status_reasons).

    Supported Technical Statuses:
    1. PASS-WITH-MANUAL-CHECKS
    2. REVIEW
    3. REJECT
    4. SCAN-ERROR (must NEVER be interpreted as PASS)
    """
    reasons: List[str] = []

    # 1. Check SCAN-ERROR conditions first (PRD Section 20 & 30)
    if not trivy_db_available or security_intel_status in {"OUTDATED", "UNAVAILABLE"}:
        reasons.append(
            f"Security Intelligence Status is {security_intel_status} (Trivy vulnerability database unavailable). "
            "SCAN-ERROR enforced per S-Gates Section 30 policy."
        )
        return ("SCAN-ERROR", "HIGH", reasons)

    if not zip_valid:
        for err in zip_errors:
            reasons.append(f"ZIP Security Gate Rejection: {err}")
        # If missing source code or malicious path traversal, classify as REJECT / SCAN-ERROR
        if any("traversal" in e.lower() or "suspicious" in e.lower() or "missing source" in e.lower() for e in zip_errors):
            return ("REJECT", "CRITICAL", reasons)
        return ("SCAN-ERROR", "HIGH", reasons)

    # Filter active (Open) findings
    open_findings = [
        f for f in findings if f.get("status", "Open") not in {"False Positive", "Resolved", "Accepted"}
    ]
    accepted_findings = [
        f for f in findings if f.get("status") == "Accepted"
    ]

    active_secrets = [
        f for f in open_findings if f["scanner"] == "Gitleaks" or f["finding_type"] == "secret"
    ]
    critical_vulns = [
        f for f in open_findings if f["severity"] == "CRITICAL" and f["finding_type"] != "secret"
    ]
    high_findings = [
        f for f in open_findings if f["severity"] == "HIGH"
    ]
    semgrep_findings = [
        f for f in open_findings if f["scanner"] == "Semgrep"
    ]
    obfuscation_findings = [
        f for f in open_findings if "obfuscation" in f.get("vulnerability_id", "").lower() or "obfuscation" in f.get("title", "").lower()
    ]

    malicious_deps = [
        d for d in dependencies
        if d.get("malicious_risk") in {
            "Potentially Malicious Package",
            "Typosquatting Suspect",
            "Suspicious Install Script",
        }
    ]
    abandoned_deps = [
        d for d in dependencies
        if d.get("reviewer_status") in {"ABANDONED", "MAINTENANCE REVIEW"}
    ]
    unknown_deps = [d for d in dependencies if d.get("reviewer_status") == "UNKNOWN"]

    # 2. Check REJECT triggers (PRD Section 20)
    reject_reasons: List[str] = []
    if active_secrets:
        reject_reasons.append(
            f"{len(active_secrets)} confirmed embedded secret(s)/credential(s) detected by Gitleaks (redacted)."
        )
    if critical_vulns:
        reject_reasons.append(
            f"{len(critical_vulns)} unresolved CRITICAL security finding(s) present."
        )
    if av_status == "Threat Detected":
        reject_reasons.append(
            "Antivirus / Trend Micro Security Scan reported: Threat Detected."
        )
    if malicious_deps:
        pkg_names = ", ".join(d["package_name"] for d in malicious_deps)
        reject_reasons.append(
            f"Potentially malicious or typosquatted dependency detected: {pkg_names}."
        )
    if obfuscation_findings:
        reject_reasons.append(
            "Deliberate unexplained code obfuscation detected in submitted source package."
        )

    if reject_reasons:
        return ("REJECT", "CRITICAL", reject_reasons)

    # 3. Check REVIEW triggers (PRD Section 20)
    review_reasons: List[str] = []
    if high_findings:
        review_reasons.append(
            f"{len(high_findings)} HIGH severity finding(s) require IT/Security review."
        )
    if semgrep_findings:
        review_reasons.append(
            f"{len(semgrep_findings)} Semgrep static code analysis finding(s) require validation."
        )
    if abandoned_deps:
        pkg_names = ", ".join(f"{d['package_name']} ({d['reviewer_status']})" for d in abandoned_deps)
        review_reasons.append(
            f"Abandoned or maintenance-review package(s) detected: {pkg_names}."
        )
    if unknown_deps:
        review_reasons.append(
            f"{len(unknown_deps)} dependency item(s) are not covered by the local heuristic catalog."
        )
    if app_metadata.get("requires_admin_privileges"):
        review_reasons.append(
            "Application requires Administrator privileges."
        )
    if app_metadata.get("data_classification") in {"Confidential", "Restricted / Personal Data"}:
        review_reasons.append(
            f"Application processes sensitive data ({app_metadata.get('data_classification')})."
        )
    ext_conns = app_metadata.get("external_connections") or []
    if any(c in {"SAP", "External API", "Database", "SharePoint", "OneDrive"} for c in ext_conns) and (open_findings or accepted_findings):
        review_reasons.append(
            f"External/Enterprise integration ({', '.join(ext_conns)}) with security findings."
        )
    if av_status in {"Pending", "Investigation Required"}:
        review_reasons.append("Manual antivirus/security evidence has not been cleared.")
    if sandbox_required:
        review_reasons.append(
            "Behavioral Sandbox Analysis is required before final pilot approval."
        )

    if review_reasons:
        risk_lvl = "HIGH" if (high_findings or app_metadata.get("requires_admin_privileges")) else "MEDIUM"
        return ("REVIEW", risk_lvl, review_reasons)

    # 4. PASS-WITH-MANUAL-CHECKS (PRD Section 20 & 42)
    pass_reasons = [
        "This development build uses heuristic demo rules and does not provide security clearance. "
        "Validated scanners and manual/risk-based checks are required before deployment decisions."
    ]
    return ("PASS-WITH-MANUAL-CHECKS", "LOW", pass_reasons)
