from datetime import datetime, timezone
import html
import io
import json
import os
import zipfile
from typing import Any, Dict, List
from app.config import settings


MANDATORY_GOVERNANCE_DISCLAIMER = (
    "This development build uses heuristic demo rules and does not provide security clearance. "
    "Validated scanners and manual/risk-based checks are required before deployment decisions."
)


def write_evidence_vault(
    assessment_code: str,
    app_info: Dict[str, Any],
    assessment_info: Dict[str, Any],
    zip_bytes: bytes,
    csv_inventory: str,
    findings: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]],
) -> str:
    """
    PRD Section 24: Evidence Artifacts.
    Creates and populates the exact folder hierarchy:
    <vault_root>/<assessment_code>/
      +-- Submission/Source.zip
      +-- Inventory/file-inventory.csv
      +-- Reports/
      |   +-- trivy-report.json
      |   +-- trivy-report.txt
      |   +-- gitleaks-report.json
      |   +-- semgrep-report.json
      |   +-- scan-summary.json
      |   +-- scan-summary.html
      +-- Evidence/
      |   +-- antivirus-result
      |   +-- sandbox-result
      +-- Approval/
          +-- decision
    """
    base_dir = os.path.join(settings.EVIDENCE_VAULT_DIR, assessment_code)
    for sub in ("Submission", "Inventory", "Reports", "Evidence", "Approval"):
        os.makedirs(os.path.join(base_dir, sub), exist_ok=True)

    # 1. Submission/Source.zip
    with open(os.path.join(base_dir, "Submission", "Source.zip"), "wb") as f:
        f.write(zip_bytes)

    # 2. Inventory/file-inventory.csv
    with open(
        os.path.join(base_dir, "Inventory", "file-inventory.csv"),
        "w",
        encoding="utf-8",
    ) as f:
        f.write(csv_inventory or "File Path,Extension,Size (Bytes),SHA-256,Category,Sandbox Flag\n")

    # 3. Reports/trivy-report.json & trivy-report.txt
    scanner_mode = (assessment_info.get("scanner_versions") or {}).get("mode", "heuristic-demo")
    is_external = scanner_mode == "external"

    trivy_findings = [item for item in findings if item["scanner"] == "Trivy"]
    trivy_payload = {
        "SchemaVersion": 2,
        "ArtifactName": assessment_info.get("zip_filename", "Source.zip"),
        "AssessmentID": assessment_code,
        "ScannerMode": "external (Aqua Trivy CLI)" if is_external else "heuristic-demo; official Trivy was not executed",
        "Scanners": ["vuln", "misconfig"] if is_external else ["heuristic dependency rules", "heuristic misconfiguration rules"],
        "Summary": assessment_info.get("trivy_summary", {}),
        "Dependencies": dependencies,
        "Results": trivy_findings,
    }
    with open(
        os.path.join(base_dir, "Reports", "trivy-report.json"), "w", encoding="utf-8"
    ) as f:
        json.dump(trivy_payload, f, indent=2)

    trivy_txt_lines = [
        "================================================================================",
        f" S-GATES {'AQUA TRIVY SCA & CONFIG' if is_external else 'HEURISTIC DEMO'} REPORT — {assessment_code}",
        *([] if is_external else [" WARNING: Trivy was not executed; results are illustrative only."]),
        "================================================================================",
        f" Application: {app_info.get('name')} (v{assessment_info.get('version')})",
        f" Archive SHA-256: {assessment_info.get('sha256_hash')}",
        "--------------------------------------------------------------------------------",
    ]
    if not trivy_findings:
        trivy_txt_lines.append("0 Trivy vulnerabilities or misconfigurations detected.")
    else:
        for tf in trivy_findings:
            trivy_txt_lines.append(
                f"[{tf['severity']}] {tf['vulnerability_id']} | Package: {tf.get('package_name', '-')} "
                f"(Installed: {tf.get('installed_version', '-')}, Fixed: {tf.get('fixed_version', '-')}) "
                f"| File: {tf['file_path']} | {tf['title']}"
            )
    with open(
        os.path.join(base_dir, "Reports", "trivy-report.txt"), "w", encoding="utf-8"
    ) as f:
        f.write("\n".join(trivy_txt_lines) + "\n")

    # 4. Reports/gitleaks-report.json (Strictly redacted!)
    gitleaks_findings = [
        {
            "RuleID": item["vulnerability_id"],
            "Description": item["title"],
            "File": item["file_path"],
            "StartLine": item["line_number"],
            "Secret": "********************",
            "Match": "********************",
            "Severity": item["severity"],
            "Status": item.get("status", "Open"),
        }
        for item in findings
        if item["scanner"] == "Gitleaks"
    ]
    with open(
        os.path.join(base_dir, "Reports", "gitleaks-report.json"),
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            {
                "AssessmentID": assessment_code,
                "RedactionPolicy": "MANDATORY_MASKED",
                "TotalSecrets": len(gitleaks_findings),
                "Findings": gitleaks_findings,
            },
            f,
            indent=2,
        )

    # 5. Reports/semgrep-report.json
    semgrep_findings = [item for item in findings if item["scanner"] == "Semgrep"]
    with open(
        os.path.join(base_dir, "Reports", "semgrep-report.json"),
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            {
                "AssessmentID": assessment_code,
                "Scanner": "Semgrep Static Application Security Testing (SAST)",
                "Summary": assessment_info.get("semgrep_summary", {}),
                "Results": semgrep_findings,
            },
            f,
            indent=2,
        )

    # 5b. Reports/supply-chain-report.json (OSV-Scanner, GuardDog & Registry Metadata)
    sc_findings = [
        item for item in findings
        if item["scanner"] in {"OSV-Scanner", "GuardDog", "RegistryMetadata"}
    ]
    with open(
        os.path.join(base_dir, "Reports", "supply-chain-report.json"),
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            {
                "AssessmentID": assessment_code,
                "Scanners": ["OSV-Scanner", "GuardDog", "PyPI/npm Registry Metadata Checker"],
                "Dependencies": dependencies,
                "Results": sc_findings,
            },
            f,
            indent=2,
        )

    # 6. Evidence/antivirus-result, Evidence/sandbox-result, Approval/decision
    # & Reports/scan-summary.json + scan-summary.html
    refresh_vault_governance_files(
        base_dir=base_dir,
        assessment_code=assessment_code,
        app_info=app_info,
        assessment_info=assessment_info,
        findings=findings,
        dependencies=dependencies,
    )

    return base_dir


def refresh_vault_governance_files(
    base_dir: str,
    assessment_code: str,
    app_info: Dict[str, Any],
    assessment_info: Dict[str, Any],
    findings: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]],
) -> None:
    """Updates Evidence/, Approval/, and Reports/scan-summary.{json,html} whenever findings or gates change."""
    for sub in ("Reports", "Evidence", "Approval"):
        os.makedirs(os.path.join(base_dir, sub), exist_ok=True)

    now_iso = datetime.now(timezone.utc).isoformat()

    # Evidence/antivirus-result
    av_payload = {
        "assessment_code": assessment_code,
        "engine": "Manual evidence entry (no antivirus integration configured)",
        "status": assessment_info.get("av_status", "Pending"),
        "notes": assessment_info.get("av_notes", ""),
        "evidence_reference": assessment_info.get("av_evidence_ref", ""),
        "reviewed_by": assessment_info.get("av_reviewed_by", "System Default"),
        "recorded_at": now_iso,
    }
    with open(
        os.path.join(base_dir, "Evidence", "antivirus-result"), "w", encoding="utf-8"
    ) as f:
        json.dump(av_payload, f, indent=2)

    # Evidence/sandbox-result
    sandbox_payload = {
        "assessment_code": assessment_code,
        "sandbox_required": assessment_info.get("sandbox_required", False),
        "triggers": assessment_info.get("sandbox_reasons", []),
        "status": assessment_info.get("sandbox_status", "Not Required"),
        "technology": assessment_info.get("sandbox_technology", "Windows Sandbox"),
        "notes": assessment_info.get("sandbox_notes", ""),
        "reviewed_by": assessment_info.get("sandbox_reviewed_by", ""),
        "recorded_at": now_iso,
    }
    with open(
        os.path.join(base_dir, "Evidence", "sandbox-result"), "w", encoding="utf-8"
    ) as f:
        json.dump(sandbox_payload, f, indent=2)

    # Approval/decision
    decision_payload = {
        "assessment_code": assessment_code,
        "application_name": app_info.get("name"),
        "version": assessment_info.get("version"),
        "technical_status": assessment_info.get("technical_status"),
        "final_decision": assessment_info.get("final_decision", "PENDING_REVIEW"),
        "decision_by": assessment_info.get("decision_by", ""),
        "decision_role": assessment_info.get("decision_role", ""),
        "decision_notes": assessment_info.get("decision_notes", ""),
        "governance_principle": MANDATORY_GOVERNANCE_DISCLAIMER,
        "recorded_at": now_iso,
    }
    with open(
        os.path.join(base_dir, "Approval", "decision"), "w", encoding="utf-8"
    ) as f:
        json.dump(decision_payload, f, indent=2)

    # Reports/scan-summary.json (PRD Section 23)
    scanner_versions = assessment_info.get("scanner_versions") or {}
    is_external = scanner_versions.get("mode") == "external"
    governance_statement = (
        "Automated scan executed using Aqua Trivy, Gitleaks, and Semgrep SAST. "
        "Manual governance review may still apply depending on organizational risk thresholds."
        if is_external
        else MANDATORY_GOVERNANCE_DISCLAIMER
    )
    summary_payload = {
        "executive_summary": {
            "assessment_id": assessment_code,
            "application_name": app_info.get("name"),
            "application_version": assessment_info.get("version"),
            "department": app_info.get("department"),
            "business_owner": app_info.get("business_owner"),
            "technical_owner": app_info.get("technical_owner"),
            "ai_development_tool": app_info.get("ai_tool"),
            "data_classification": app_info.get("data_classification"),
            "assessment_date": assessment_info.get("created_at", now_iso),
            "sha256_hash": assessment_info.get("sha256_hash"),
            "risk_classification": assessment_info.get("risk_level"),
            "technical_status": assessment_info.get("technical_status"),
            "final_decision": assessment_info.get("final_decision"),
            "governance_statement": governance_statement,
        },
        "scanner_summary": {
            "mode": (
                f"external (Trivy {scanner_versions.get('trivy', 'installed')}, "
                f"Gitleaks {scanner_versions.get('gitleaks', 'installed')}, "
                f"Semgrep {scanner_versions.get('semgrep', 'installed')})"
                if is_external
                else "heuristic-demo (Trivy, Gitleaks, and Semgrep were not executed)"
            ),
            "trivy": assessment_info.get("trivy_summary", {}),
            "gitleaks": assessment_info.get("gitleaks_summary", {}),
            "semgrep": assessment_info.get("semgrep_summary", {}),
            "antivirus_security_scan": assessment_info.get("av_status"),
            "sandbox": assessment_info.get("sandbox_status"),
        },
        "dependencies": dependencies,
        "detailed_findings": findings,
    }
    with open(
        os.path.join(base_dir, "Reports", "scan-summary.json"), "w", encoding="utf-8"
    ) as f:
        json.dump(summary_payload, f, indent=2)

    # Reports/scan-summary.html (PRD Section 23 Printable Executive + Technical Report)
    html_report = _render_html_report(
        assessment_code=assessment_code,
        app_info=app_info,
        assessment_info=assessment_info,
        findings=findings,
        dependencies=dependencies,
    )
    with open(
        os.path.join(base_dir, "Reports", "scan-summary.html"), "w", encoding="utf-8"
    ) as f:
        f.write(html_report)


def _render_html_report(
    assessment_code: str,
    app_info: Dict[str, Any],
    assessment_info: Dict[str, Any],
    findings: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]],
) -> str:
    status = html.escape(str(assessment_info.get("technical_status", "REVIEW")))
    badge_color = "#f59e0b"
    if status == "PASS-WITH-MANUAL-CHECKS":
        badge_color = "#10b981"
    elif status in {"REJECT", "SCAN-ERROR"}:
        badge_color = "#ef4444"

    rows_html = ""
    for f in findings:
        rows_html += f"""
        <tr>
          <td><code>{html.escape(str(f.get('finding_code', '')))}</code></td>
          <td>{html.escape(str(f.get('scanner', '')))}</td>
          <td><strong>{html.escape(str(f.get('severity', '')))}</strong></td>
          <td><code>{html.escape(str(f.get('file_path', '')))}:{f.get('line_number', 1)}</code></td>
          <td>{html.escape(str(f.get('title', '')))}<br/><small>{html.escape(str(f.get('description', '')))}</small></td>
          <td>{html.escape(str(f.get('recommendation', '')))}</td>
          <td>{html.escape(str(f.get('status', 'Open')))}</td>
        </tr>
        """
    scanner_versions = assessment_info.get("scanner_versions") or {}
    is_external = scanner_versions.get("mode") == "external"

    if not rows_html:
        empty_msg = (
            "No vulnerabilities, exposed secrets, or SAST policy violations detected."
            if is_external
            else "No findings matched the demo heuristics. This is not a security clearance."
        )
        rows_html = f'<tr><td colspan="7" style="text-align:center;">{empty_msg}</td></tr>'

    trivy = assessment_info.get("trivy_summary", {})
    gitleaks = assessment_info.get("gitleaks_summary", {})
    semgrep = assessment_info.get("semgrep_summary", {})

    disclaimer_html = (
        f'<div class="disclaimer"><strong>Security Scanners Executed:</strong> Aqua Trivy (v{html.escape(str(scanner_versions.get("trivy", "0.76.2")))}), Gitleaks (v{html.escape(str(scanner_versions.get("gitleaks", "8.30.1")))}), Semgrep SAST (v{html.escape(str(scanner_versions.get("semgrep", "1.95.0")))}), OSV-Scanner (v{html.escape(str(scanner_versions.get("osv", "2.7.1")))}), GuardDog (v{html.escape(str(scanner_versions.get("guarddog", "3.2.0")))}), and PyPI/npm Registry Metadata Checker. Secret values are strictly redacted.</div>'
        if is_external
        else (
            '<div class="disclaimer"><strong>DEMO HEURISTICS ONLY:</strong> This report was not produced by Trivy, Gitleaks, Semgrep, an antivirus engine, or a sandbox. Do not use it as a production security clearance.</div>'
            f'<div class="disclaimer"><strong>Governance Principle (PRD Section 42):</strong> {html.escape(MANDATORY_GOVERNANCE_DISCLAIMER)}</div>'
        )
    )
    trivy_label = f"Aqua Trivy SCA & Config (v{html.escape(str(scanner_versions.get('trivy', '0.76.2')))})" if is_external else "Dependency/misconfiguration heuristics (Trivy not executed)"
    gitleaks_label = f"Gitleaks Secret Detection (v{html.escape(str(scanner_versions.get('gitleaks', '8.30.1')))})" if is_external else "Secret-pattern heuristics (Gitleaks not executed)"
    semgrep_label = f"Semgrep SAST (v{html.escape(str(scanner_versions.get('semgrep', '1.95.0')))})" if is_external else "SAST heuristics (Semgrep not executed)"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>S-Gates Security Assessment Report: {html.escape(assessment_code)}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #0f172a; margin: 32px; background: #f8fafc; }}
    .card {{ background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 24px; margin-bottom: 24px; }}
    .badge {{ display: inline-block; padding: 6px 14px; border-radius: 6px; color: #fff; font-weight: 700; background: {badge_color}; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; }}
    .disclaimer {{ background: #eff6ff; border-left: 4px solid #2563eb; padding: 14px; margin-top: 16px; font-size: 13px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>S-Gates Application Security Assessment Report</h1>
    <p><strong>Assessment ID:</strong> {html.escape(assessment_code)} &nbsp;|&nbsp; <strong>Technical Status:</strong> <span class="badge">{status}</span></p>
    {disclaimer_html}
  </div>

  <div class="card">
    <h2>1. Executive Summary</h2>
    <table>
      <tr><th>Application Name</th><td>{html.escape(str(app_info.get('name', '')))}</td><th>Application Version</th><td>{html.escape(str(assessment_info.get('version', '')))}</td></tr>
      <tr><th>Business Owner</th><td>{html.escape(str(app_info.get('business_owner', '')))}</td><th>Technical Owner</th><td>{html.escape(str(app_info.get('technical_owner', '')))}</td></tr>
      <tr><th>Department</th><td>{html.escape(str(app_info.get('department', '')))}</td><th>AI Development Tool</th><td>{html.escape(str(app_info.get('ai_tool', '')))}</td></tr>
      <tr><th>Data Classification</th><td>{html.escape(str(app_info.get('data_classification', '')))}</td><th>Risk Classification</th><td><strong>{html.escape(str(assessment_info.get('risk_level', '')))}</strong></td></tr>
      <tr><th>ZIP SHA-256 Hash</th><td colspan="3"><code>{html.escape(str(assessment_info.get('sha256_hash', '')))}</code></td></tr>
      <tr><th>Final Approval Status</th><td colspan="3"><strong>{html.escape(str(assessment_info.get('final_decision', 'PENDING_REVIEW')))}</strong></td></tr>
    </table>
  </div>

  <div class="card">
    <h2>2. Scanner Summary</h2>
    <table>
      <tr>
        <th>{trivy_label}</th>
        <td>Critical: {trivy.get('critical', 0)} | High: {trivy.get('high', 0)} | Medium: {trivy.get('medium', 0)} | Low: {trivy.get('low', 0)}</td>
      </tr>
      <tr>
        <th>{gitleaks_label}</th>
        <td>Detected secrets: {gitleaks.get('secrets_detected', 0)}. Credential values are masked; the source archive is stored unmodified.</td>
      </tr>
      <tr>
        <th>{semgrep_label}</th>
        <td>Critical: {semgrep.get('critical', 0)} | High: {semgrep.get('high', 0)} | Medium: {semgrep.get('medium', 0)} | Low: {semgrep.get('low', 0)}</td>
      </tr>
      <tr>
        <th>Manual antivirus evidence (no engine configured)</th>
        <td>{html.escape(str(assessment_info.get('av_status', 'Pending')))}</td>
      </tr>
      <tr>
        <th>Manual sandbox evidence (no sandbox configured)</th>
        <td>{html.escape(str(assessment_info.get('sandbox_status', 'Not Required')))}</td>
      </tr>
    </table>
  </div>

  <div class="card">
    <h2>3. Detailed Findings</h2>
    <table>
      <thead>
        <tr>
          <th>Finding ID</th>
          <th>Scanner</th>
          <th>Severity</th>
          <th>Source</th>
          <th>Description</th>
          <th>Recommendation</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>
</body>
</html>
"""


def list_vault_artifacts(assessment_code: str) -> List[Dict[str, Any]]:
    base_dir = os.path.join(settings.EVIDENCE_VAULT_DIR, assessment_code)
    artifacts: List[Dict[str, Any]] = []
    if not os.path.exists(base_dir):
        return artifacts

    for root, _, files in os.walk(base_dir):
        for fname in sorted(files):
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, base_dir).replace("\\", "/")
            size_bytes = os.path.getsize(full_path)
            artifacts.append(
                {
                    "relative_path": rel_path,
                    "folder": os.path.dirname(rel_path),
                    "filename": fname,
                    "size_bytes": size_bytes,
                }
            )
    return artifacts


def bundle_vault_zip(assessment_code: str) -> bytes:
    base_dir = os.path.join(settings.EVIDENCE_VAULT_DIR, assessment_code)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if os.path.exists(base_dir):
            for root, _, files in os.walk(base_dir):
                for fname in sorted(files):
                    full_path = os.path.join(root, fname)
                    rel_path = os.path.relpath(full_path, base_dir).replace("\\", "/")
                    zf.write(full_path, arcname=f"{assessment_code}/{rel_path}")
    return buf.getvalue()
