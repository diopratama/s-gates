import json
import os
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.config import settings
from app.engine.evidence_vault import refresh_vault_governance_files
from app.models import Assessment, NotificationEvent
from app.security import record_audit_event


INVALIDATION_REASON = (
    "Legacy assessment used heuristic demo rules, not validated external scanners; "
    "its previous security decision is not valid clearance."
)


def invalidate_legacy_assessments(db: Session) -> int:
    """Downgrade persisted results created before scanner mode was recorded."""
    if settings.APP_ENV.lower() == "test":
        return 0

    changed = 0
    for assessment in db.query(Assessment).order_by(Assessment.id.asc()).all():
        versions = assessment.scanner_versions or {}
        if versions.get("mode") in {"heuristic-demo", "external", "legacy-heuristic-invalidated"}:
            continue

        old_status = assessment.technical_status
        assessment.scanner_versions = {
            "mode": "legacy-heuristic-invalidated",
            "trivy": "not executed",
            "gitleaks": "not executed",
            "semgrep": "not executed",
            "security_intel_status": "UNAVAILABLE",
        }
        assessment.technical_status = "SCAN-ERROR"
        assessment.risk_level = "HIGH"
        assessment.status_reasons = [INVALIDATION_REASON]
        assessment.trivy_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        assessment.gitleaks_summary = {
            "secrets_detected": 0,
            "critical": 0,
            "redaction_enforced": True,
        }
        assessment.semgrep_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        assessment.av_status = "Pending"
        assessment.av_notes = "Legacy status invalidated; no antivirus integration ran."
        assessment.av_evidence_ref = ""
        assessment.av_reviewed_by = ""
        assessment.sandbox_status = "Required - Pending" if assessment.sandbox_required else "Not Required"
        assessment.sandbox_notes = ""
        assessment.sandbox_reviewed_by = ""
        assessment.final_decision = "SCAN_ERROR_BLOCKED"
        assessment.decision_by = ""
        assessment.decision_role = ""
        assessment.decision_notes = INVALIDATION_REASON
        assessment.decision_at = None
        assessment.sharepoint_synced = False
        assessment.sharepoint_url = ""

        for finding in assessment.findings:
            finding.scanner = "Legacy heuristic"
            finding.severity = "UNKNOWN"
            finding.vulnerability_id = "UNVERIFIED"
            finding.status = "Open"
            finding.itsm_ticket_id = ""
        for dependency in assessment.dependencies:
            dependency.reviewer_status = "UNKNOWN"
            dependency.severity = "UNKNOWN"
            dependency.vulnerability_id = "UNVERIFIED"
            dependency.fixed_version = "-"
            dependency.malicious_risk = "Unknown / Not assessed"
            dependency.last_release_date = "Not dynamically checked"
            dependency.maintainer_status = "Not dynamically checked"
            dependency.publisher_identity = "Not verified"
            dependency.reviewer_notes = "Legacy heuristic result; verify using external tooling."

        if assessment.application:
            assessment.application.security_status = "SCAN-ERROR"
            assessment.application.risk_level = "HIGH"
            assessment.application.production_status = "Scan Error - Blocked"

        for notification in db.query(NotificationEvent).filter(
            NotificationEvent.assessment_code == assessment.assessment_code
        ):
            notification.event_type = "Legacy Assessment Invalidated"
            notification.message = INVALIDATION_REASON
            notification.channel = "In-App"

        record_audit_event(
            db=db,
            actor_email="system@s-gates.local",
            actor_role="SYSTEM",
            event_type="LEGACY_HEURISTIC_ASSESSMENT_INVALIDATED",
            summary=f"Invalidated legacy heuristic result for {assessment.assessment_code}: {old_status} -> SCAN-ERROR.",
            assessment_code=assessment.assessment_code,
            sgates_app_id=assessment.application.sgates_app_id if assessment.application else None,
            previous_state=old_status,
            new_state="SCAN-ERROR",
            sha256_file_hash=assessment.sha256_hash,
            metadata_json={"reason": INVALIDATION_REASON},
        )

        _stamp_legacy_evidence(assessment)
        changed += 1

    if changed:
        db.commit()
    return changed


def _stamp_legacy_evidence(assessment: Assessment) -> None:
    vault_root = os.path.realpath(settings.EVIDENCE_VAULT_DIR)
    base_dir = os.path.realpath(assessment.evidence_vault_path)
    try:
        if os.path.commonpath((vault_root, base_dir)) != vault_root or not os.path.isdir(base_dir):
            return
    except ValueError:
        return

    app = assessment.application
    app_info: dict[str, Any] = {
        "name": app.name if app else "",
        "department": app.department if app else "",
        "business_owner": app.business_owner if app else "",
        "technical_owner": app.technical_owner if app else "",
        "ai_tool": app.ai_tool if app else "",
        "data_classification": app.data_classification if app else "",
    }
    assessment_info: dict[str, Any] = {
        "version": assessment.version,
        "zip_filename": assessment.zip_filename,
        "sha256_hash": assessment.sha256_hash,
        "technical_status": "SCAN-ERROR",
        "risk_level": "HIGH",
        "trivy_summary": assessment.trivy_summary,
        "gitleaks_summary": assessment.gitleaks_summary,
        "semgrep_summary": assessment.semgrep_summary,
        "av_status": "Pending",
        "av_notes": assessment.av_notes,
        "av_evidence_ref": "",
        "av_reviewed_by": "",
        "sandbox_required": assessment.sandbox_required,
        "sandbox_reasons": assessment.sandbox_reasons or [],
        "sandbox_status": assessment.sandbox_status,
        "sandbox_technology": assessment.sandbox_technology,
        "sandbox_notes": "",
        "sandbox_reviewed_by": "",
        "final_decision": assessment.final_decision,
        "decision_by": "",
        "decision_role": "",
        "decision_notes": INVALIDATION_REASON,
        "created_at": assessment.created_at.isoformat() if assessment.created_at else datetime.now(timezone.utc).isoformat(),
    }
    refresh_vault_governance_files(
        base_dir=base_dir,
        assessment_code=assessment.assessment_code,
        app_info=app_info,
        assessment_info=assessment_info,
        findings=[
            {
                "finding_code": finding.finding_code,
                "scanner": finding.scanner,
                "severity": finding.severity,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "title": finding.title,
                "description": INVALIDATION_REASON,
                "recommendation": "Reassess with validated scanners before relying on this finding.",
                "status": finding.status,
            }
            for finding in assessment.findings
        ],
        dependencies=[],
    )

    for report_name in ("trivy-report.json", "gitleaks-report.json", "semgrep-report.json"):
        report_path = os.path.join(base_dir, "Reports", report_name)
        if not os.path.isfile(report_path):
            continue
        try:
            with open(report_path, encoding="utf-8") as report_file:
                report = json.load(report_file)
            if isinstance(report, dict):
                report["ScannerMode"] = "legacy-heuristic-invalidated"
                report["Warning"] = INVALIDATION_REASON
                with open(report_path, "w", encoding="utf-8") as report_file:
                    json.dump(report, report_file, indent=2)
        except (OSError, json.JSONDecodeError):
            continue

    text_report = os.path.join(base_dir, "Reports", "trivy-report.txt")
    if os.path.isfile(text_report):
        with open(text_report, encoding="utf-8") as report_file:
            content = report_file.read()
        if "legacy heuristic" not in content.lower():
            with open(text_report, "w", encoding="utf-8") as report_file:
                report_file.write(f"WARNING: {INVALIDATION_REASON}\n\n{content}")
