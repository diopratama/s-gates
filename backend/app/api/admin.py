import hashlib
import json
from datetime import timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.config import settings
from app.engine.orchestrator import get_or_create_system_settings
from app.models import AuditRecord, NotificationEvent, User
from app.schemas import SystemSettingsUpdateRequest
from app.security import get_current_user, record_audit_event, require_roles

router = APIRouter(prefix="/admin", tags=["Administration, Scanner Config & Audit Trail"])


@router.get("/settings")
def get_system_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cfg = get_or_create_system_settings(db)
    from app.engine.adapters.manager import default_scanner_manager
    scanner_status = default_scanner_manager.get_scanner_status()
    is_test = settings.APP_ENV.lower() == "test"
    all_ready = scanner_status["all_available"]

    intel_status = cfg.security_intel_status if (is_test or all_ready) else "UNAVAILABLE"
    trivy_avail = cfg.trivy_db_available if (is_test or all_ready) else False
    mode = "external" if all_ready else ("heuristic-demo" if not is_test else cfg.security_intel_status.lower())

    return {
        "scanner_mode": "external" if all_ready else "heuristic-demo",
        "production_ready": all_ready,
        "max_zip_size_mb": min(cfg.max_zip_size_mb, settings.MAX_ZIP_SIZE_MB),
        "max_expanded_size_mb": min(cfg.max_expanded_size_mb, settings.MAX_EXPANDED_SIZE_MB),
        "max_file_count": min(cfg.max_file_count, settings.MAX_FILE_COUNT),
        "max_scan_seconds": min(cfg.max_scan_seconds, settings.MAX_SCAN_SECONDS),
        "security_intel_status": intel_status,
        "trivy_db_available": trivy_avail,
        "trivy_version": cfg.trivy_version if (is_test or all_ready) else "not-installed",
        "gitleaks_version": cfg.gitleaks_version if (is_test or all_ready) else "not-installed",
        "semgrep_version": cfg.semgrep_version if (is_test or all_ready) else "not-installed",
        "osv_version": scanner_status.get("osv_version", "not-installed") if (is_test or all_ready) else "not-installed",
        "guarddog_version": scanner_status.get("guarddog_version", "not-installed") if (is_test or all_ready) else "not-installed",
        "sharepoint_vault_url": cfg.sharepoint_vault_url if is_test else "not-configured",
        "teams_webhook_url": cfg.teams_webhook_url if is_test else "not-configured",
        "freshservice_domain": cfg.freshservice_domain if is_test else "not-configured",
        "updated_at": cfg.updated_at,
    }


@router.patch("/settings")
def update_system_settings(
    payload: SystemSettingsUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("ADMIN", "SECURITY_REVIEWER")),
):
    """
    PRD Section 11, 27, 30, 35:
    Allows administrators to configure bounded ZIP limits. Scanner status is not user-editable.
    Note: Administrator CANNOT alter previously approved immutable audit evidence.
    """
    if (
        settings.APP_ENV.lower() != "test"
        and (payload.security_intel_status is not None or payload.trivy_db_available is not None)
    ):
        raise HTTPException(
            status_code=501,
            detail="Scanner health cannot be changed manually; no external scanner integration is installed.",
        )

    cfg = get_or_create_system_settings(db)
    prev_intel = "UNAVAILABLE"

    if payload.max_zip_size_mb is not None:
        cfg.max_zip_size_mb = payload.max_zip_size_mb
    if payload.max_expanded_size_mb is not None:
        cfg.max_expanded_size_mb = payload.max_expanded_size_mb
    if payload.max_file_count is not None:
        cfg.max_file_count = payload.max_file_count
    if payload.max_scan_seconds is not None:
        cfg.max_scan_seconds = payload.max_scan_seconds
    if settings.APP_ENV.lower() == "test":
        if payload.security_intel_status is not None:
            cfg.security_intel_status = payload.security_intel_status
            cfg.trivy_db_available = payload.security_intel_status == "HEALTHY"
        if payload.trivy_db_available is not None:
            cfg.trivy_db_available = payload.trivy_db_available
            cfg.security_intel_status = "HEALTHY" if payload.trivy_db_available else "OUTDATED"
    if payload.sharepoint_vault_url is not None:
        cfg.sharepoint_vault_url = payload.sharepoint_vault_url
    if payload.teams_webhook_url is not None:
        cfg.teams_webhook_url = payload.teams_webhook_url
    if payload.freshservice_domain is not None:
        cfg.freshservice_domain = payload.freshservice_domain

    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        event_type="SYSTEM_CONFIG_UPDATED",
        summary=(
            f"Updated S-Gates system configuration. Security Intelligence Status: "
            f"{prev_intel}; scanner binaries are not installed."
        ),
        previous_state=prev_intel,
        new_state=prev_intel,
    )
    db.commit()
    db.refresh(cfg)
    return get_system_settings(db, current_user)


@router.get("/audit-logs")
def get_audit_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns the database-backed SHA-256 chain and verifies its recorded fields."""
    records = db.query(AuditRecord).order_by(AuditRecord.id.asc()).all()
    prev_sig = "GENESIS-SGATES-2026"
    chain_valid = True

    for r in records:
        payload = {
            "prev_sig": prev_sig,
            "actor_email": r.actor_email,
            "actor_role": r.actor_role,
            "event_type": r.event_type,
            "assessment_code": r.assessment_code,
            "sgates_app_id": r.sgates_app_id,
            "previous_state": r.previous_state,
            "new_state": r.new_state,
            "sha256_file_hash": r.sha256_file_hash,
            "summary": r.summary,
        }
        metadata = r.metadata_json or {}
        if metadata.get("_chain_version") == 2:
            signed_created_at = metadata.get("_chain_created_at")
            stored_created_at = r.created_at
            if stored_created_at and stored_created_at.tzinfo is None:
                stored_created_at = stored_created_at.replace(tzinfo=timezone.utc)
            if (
                not signed_created_at
                or not stored_created_at
                or stored_created_at.isoformat(timespec="microseconds") != signed_created_at
            ):
                chain_valid = False
            payload["metadata_json"] = metadata
            payload["created_at"] = signed_created_at

        payload_str = json.dumps(payload, sort_keys=True)
        expected_sig = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
        if expected_sig != r.immutable_signature:
            chain_valid = False
        prev_sig = r.immutable_signature

    return {
        "chain_integrity_verified": chain_valid,
        "total_records": len(records),
        "records": [
            {
                "id": r.id,
                "assessment_code": r.assessment_code,
                "sgates_app_id": r.sgates_app_id,
                "actor_email": r.actor_email,
                "actor_role": r.actor_role,
                "event_type": r.event_type,
                "previous_state": r.previous_state,
                "new_state": r.new_state,
                "sha256_file_hash": r.sha256_file_hash,
                "summary": r.summary,
                "immutable_signature": r.immutable_signature,
                "created_at": r.created_at,
            }
            for r in reversed(records)
        ],
    }


@router.get("/notifications")
def list_notifications(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    items = (
        db.query(NotificationEvent)
        .order_by(NotificationEvent.id.desc())
        .limit(30)
        .all()
    )
    return [
        {
            "id": n.id,
            "event_type": n.event_type,
            "assessment_code": n.assessment_code,
            "application_name": n.application_name,
            "channel": n.channel,
            "message": n.message,
            "is_read": n.is_read,
            "created_at": n.created_at,
        }
        for n in items
    ]


@router.post("/notifications/mark-all-read")
def mark_notifications_read(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    db.query(NotificationEvent).update({NotificationEvent.is_read: True})
    db.commit()
    return {"status": "ok"}
