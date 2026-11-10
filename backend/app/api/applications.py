import os
import shutil
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.engine.adapters.manager import default_scanner_manager
from app.engine.orchestrator import get_or_create_system_settings
from app.models import Application, Assessment, Finding, NotificationEvent, User
from app.security import get_current_user, record_audit_event, require_roles

router = APIRouter(prefix="/applications", tags=["Application Inventory & KPIs"])


@router.get("/dashboard-summary")
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """PRD Section 21, 30, 38: Dashboard KPIs, Success Metrics, and System Intelligence Status."""
    sys_cfg = get_or_create_system_settings(db)
    apps = db.query(Application).order_by(Application.last_scan_date.desc()).all()
    assessments = db.query(Assessment).order_by(Assessment.id.desc()).all()
    findings = db.query(Finding).all()

    status_counts = {
        "PASS-WITH-MANUAL-CHECKS": sum(
            1 for a in assessments if a.technical_status == "PASS-WITH-MANUAL-CHECKS"
        ),
        "REVIEW": sum(1 for a in assessments if a.technical_status == "REVIEW"),
        "REJECT": sum(1 for a in assessments if a.technical_status == "REJECT"),
        "SCAN-ERROR": sum(1 for a in assessments if a.technical_status == "SCAN-ERROR"),
    }

    approved_assessments = [
        a for a in assessments if a.final_decision in {"PILOT_APPROVED", "PRODUCTION"}
    ]
    unresolved_critical_at_approval = 0
    exposed_secrets_at_approval = 0
    for a in approved_assessments:
        for f in a.findings:
            if f.status == "Open" and f.severity == "CRITICAL":
                unresolved_critical_at_approval += 1
            if f.status == "Open" and f.scanner == "Gitleaks":
                exposed_secrets_at_approval += 1

    total_secrets_discovered = sum(1 for f in findings if f.scanner == "Gitleaks")
    total_vulns_detected = sum(1 for f in findings if f.scanner != "Gitleaks")

    unread_notifications = (
        db.query(NotificationEvent)
        .filter(NotificationEvent.is_read == False)  # noqa: E712
        .count()
    )

    app_count = len(apps)
    assessment_count = len(assessments)
    scoped_apps = sum(
        1 for app in apps if app.business_owner.strip() and app.technical_owner.strip()
    )
    production_apps = {
        app.id for app in apps if app.production_status in {"Pilot", "Production"}
    }
    externally_scanned_apps = {
        assessment.application_id
        for assessment in assessments
        if (assessment.scanner_versions or {}).get("mode") == "external"
        and assessment.technical_status != "SCAN-ERROR"
    }
    retained_sources = sum(
        1
        for assessment in assessments
        if assessment.evidence_vault_path
        and os.path.isfile(
            os.path.join(assessment.evidence_vault_path, "Submission", "Source.zip")
        )
    )
    retained_evidence = sum(
        1
        for assessment in assessments
        if assessment.evidence_vault_path and os.path.isdir(assessment.evidence_vault_path)
    )

    scanner_status = default_scanner_manager.get_scanner_status()
    all_ready = scanner_status["all_available"]
    scanner_mode = "external" if all_ready else "heuristic-demo"
    sec_intel = {
        "status": sys_cfg.security_intel_status if (all_ready or sys_cfg.security_intel_status == "HEALTHY") else scanner_status["status"],
        "trivy_db_available": sys_cfg.trivy_db_available if all_ready else scanner_status["trivy_db_available"],
        "trivy_version": scanner_status["trivy_version"] if all_ready else sys_cfg.trivy_version,
        "gitleaks_version": scanner_status["gitleaks_version"] if all_ready else sys_cfg.gitleaks_version,
        "semgrep_version": scanner_status["semgrep_version"] if all_ready else sys_cfg.semgrep_version,
        "osv_version": scanner_status.get("osv_version", "not-installed"),
        "guarddog_version": scanner_status.get("guarddog_version", "not-installed"),
    }

    return {
        "scanner_mode": scanner_mode,
        "production_ready": all_ready,
        "security_intelligence": sec_intel,
        "kpis": {
            "registered_apps_count": len(apps),
            "total_assessments_count": len(assessments),
            "registered_scoped_apps_pct": round(scoped_apps * 100 / app_count) if app_count else 0,
            "scanned_before_pilot_pct": round(
                len(production_apps & externally_scanned_apps) * 100 / len(production_apps)
            ) if production_apps else 0,
            "unresolved_critical_at_approval": unresolved_critical_at_approval,
            "exposed_secrets_at_approval": exposed_secrets_at_approval,
            "source_code_retained_pct": round(retained_sources * 100 / assessment_count) if assessment_count else 0,
            "owners_defined_pct": round(scoped_apps * 100 / app_count) if app_count else 0,
            "evidence_retained_pct": round(retained_evidence * 100 / assessment_count) if assessment_count else 0,
            "total_secrets_discovered": total_secrets_discovered,
            "total_vulnerabilities_detected": total_vulns_detected,
            "applications_rejected": status_counts["REJECT"],
            "applications_requiring_review": status_counts["REVIEW"],
        },
        "status_breakdown": status_counts,
        "unread_notifications": unread_notifications,
        "recent_assessments": [
            {
                "id": a.id,
                "assessment_code": a.assessment_code,
                "application_id": a.application_id,
                "application_name": a.application.name if a.application else "",
                "department": a.application.department if a.application else "",
                "business_owner": a.application.business_owner if a.application else "",
                "technical_owner": a.application.technical_owner if a.application else "",
                "ai_tool": a.application.ai_tool if a.application else "",
                "version": a.version,
                "technical_status": a.technical_status,
                "risk_level": a.risk_level,
                "final_decision": a.final_decision,
                "trivy_summary": a.trivy_summary,
                "gitleaks_summary": a.gitleaks_summary,
                "semgrep_summary": a.semgrep_summary,
                "av_status": a.av_status,
                "sandbox_required": a.sandbox_required,
                "sandbox_status": a.sandbox_status,
                "created_at": a.created_at,
            }
            for a in assessments[:10]
        ],
    }


@router.get("")
def list_applications(
    department: Optional[str] = None,
    security_status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """PRD Section 26: Centralized Application Inventory."""
    query = db.query(Application)
    if department:
        query = query.filter(Application.department == department)
    if security_status:
        query = query.filter(Application.security_status == security_status)
    if search:
        like_q = f"%{search.strip()}%"
        query = query.filter(
            (Application.name.ilike(like_q))
            | (Application.sgates_app_id.ilike(like_q))
            | (Application.ai_tool.ilike(like_q))
        )

    apps = query.order_by(Application.id.desc()).all()
    result = []
    for app in apps:
        result.append(
            {
                "id": app.id,
                "sgates_app_id": app.sgates_app_id,
                "name": app.name,
                "latest_version": app.latest_version,
                "department": app.department,
                "business_owner": app.business_owner,
                "technical_owner": app.technical_owner,
                "description": app.description,
                "ai_tool": app.ai_tool,
                "app_type": app.app_type,
                "data_classification": app.data_classification,
                "external_connections": app.external_connections,
                "expected_users": app.expected_users,
                "requires_admin_privileges": app.requires_admin_privileges,
                "risk_level": app.risk_level,
                "security_status": app.security_status,
                "production_status": app.production_status,
                "last_scan_date": app.last_scan_date,
                "next_review_date": app.next_review_date,
                "assessments": [
                    {
                        "assessment_code": asmt.assessment_code,
                        "version": asmt.version,
                        "technical_status": asmt.technical_status,
                        "risk_level": asmt.risk_level,
                        "final_decision": asmt.final_decision,
                        "created_at": asmt.created_at,
                    }
                    for asmt in app.assessments
                ],
            }
        )
    return result


@router.delete("/{sgates_app_id}")
def delete_application(
    sgates_app_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("ADMIN")),
):
    """Admin-only: Delete an application from inventory along with all linked assessments and Evidence Vault directories."""
    app = (
        db.query(Application)
        .filter(Application.sgates_app_id == sgates_app_id)
        .first()
    )
    if not app:
        raise HTTPException(status_code=404, detail="Application not found.")

    app_name = app.name
    linked_count = len(app.assessments)
    for asmt in app.assessments:
        if asmt.evidence_vault_path and os.path.isdir(asmt.evidence_vault_path):
            shutil.rmtree(asmt.evidence_vault_path, ignore_errors=True)

    db.delete(app)
    db.commit()

    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        event_type="APPLICATION_DELETED",
        sgates_app_id=sgates_app_id,
        summary=(
            f"Application {sgates_app_id} ('{app_name}') and {linked_count} linked assessment(s) "
            f"deleted from inventory by Administrator."
        ),
    )
    db.commit()
    return {
        "message": f"Application {sgates_app_id} ({app_name}) and {linked_count} linked assessment(s) deleted.",
        "sgates_app_id": sgates_app_id,
        "deleted_assessments_count": linked_count,
    }
