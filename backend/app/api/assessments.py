import asyncio
from datetime import datetime, timezone
import json
import os
import queue
import re
import shutil
import threading
from typing import Callable, List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from app.database import SessionLocal, get_db
from app.engine.evidence_vault import (
    MANDATORY_GOVERNANCE_DISCLAIMER,
    list_vault_artifacts,
)
from app.engine.github_source import GitHubSourceError, fetch_github_repository_zip
from app.engine.orchestrator import (
    execute_full_assessment,
    get_or_create_system_settings,
    recalculate_assessment_state,
)
from app.engine.sample_generator import generate_sample_zip
from app.models import (
    AuditRecord,
    Assessment,
    DependencyItem,
    Finding,
    User,
)
from app.config import settings
from app.schemas import (
    ApprovalDecisionRequest,
    DependencyUpdateRequest,
    FindingUpdateRequest,
    GitHubSubmissionRequest,
    ManualGateUpdateRequest,
    SampleSubmissionRequest,
)
from app.security import (
    emit_notification,
    get_current_user,
    record_audit_event,
    require_roles,
)

router = APIRouter(prefix="/assessments", tags=["Security Assessments & Gates"])


def _serialize_assessment(db: Session, a: Assessment) -> dict:
    app = a.application
    audit_events = (
        db.query(AuditRecord)
        .filter(AuditRecord.assessment_code == a.assessment_code)
        .order_by(AuditRecord.id.desc())
        .all()
    )
    return {
        "id": a.id,
        "assessment_code": a.assessment_code,
        "version": a.version,
        "submitter_email": a.submitter_email,
        "submitter_name": a.submitter_name,
        "zip_filename": a.zip_filename,
        "zip_size_bytes": a.zip_size_bytes,
        "expanded_size_bytes": a.expanded_size_bytes,
        "file_count": a.file_count,
        "sha256_hash": a.sha256_hash,
        "zip_valid": a.zip_valid,
        "zip_validation_errors": a.zip_validation_errors or [],
        "file_inventory_preview": a.file_inventory_preview or [],
        "technical_status": a.technical_status,
        "risk_level": a.risk_level,
        "status_reasons": a.status_reasons or [],
        "governance_disclaimer": MANDATORY_GOVERNANCE_DISCLAIMER,
        "scanner_versions": a.scanner_versions or {},
        "trivy_summary": a.trivy_summary or {},
        "gitleaks_summary": a.gitleaks_summary or {},
        "semgrep_summary": a.semgrep_summary or {},
        "av_status": a.av_status,
        "av_notes": a.av_notes,
        "av_evidence_ref": a.av_evidence_ref,
        "av_reviewed_by": a.av_reviewed_by,
        "sandbox_required": a.sandbox_required,
        "sandbox_reasons": a.sandbox_reasons or [],
        "sandbox_status": a.sandbox_status,
        "sandbox_technology": a.sandbox_technology,
        "sandbox_notes": a.sandbox_notes,
        "sandbox_reviewed_by": a.sandbox_reviewed_by,
        "final_decision": a.final_decision,
        "decision_by": a.decision_by,
        "decision_role": a.decision_role,
        "decision_notes": a.decision_notes,
        "decision_at": a.decision_at,
        "evidence_vault_path": a.evidence_vault_path,
        "sharepoint_synced": a.sharepoint_synced,
        "sharepoint_url": a.sharepoint_url,
        "created_at": a.created_at,
        "application": {
            "id": app.id,
            "sgates_app_id": app.sgates_app_id,
            "name": app.name,
            "department": app.department,
            "business_owner": app.business_owner,
            "technical_owner": app.technical_owner,
            "description": app.description,
            "ai_tool": app.ai_tool,
            "app_type": app.app_type,
            "data_classification": app.data_classification,
            "external_connections": app.external_connections or [],
            "expected_users": app.expected_users,
            "requires_admin_privileges": app.requires_admin_privileges,
            "production_status": app.production_status,
            "next_review_date": app.next_review_date,
        }
        if app
        else None,
        "findings": [
            {
                "id": f.id,
                "finding_code": f.finding_code,
                "scanner": f.scanner,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "package_name": f.package_name,
                "installed_version": f.installed_version,
                "fixed_version": f.fixed_version,
                "vulnerability_id": f.vulnerability_id,
                "redacted_value": "********************",
                "recommendation": f.recommendation,
                "status": f.status,
                "reviewer_comment": f.reviewer_comment,
                "itsm_ticket_id": f.itsm_ticket_id,
            }
            for f in a.findings
        ],
        "dependencies": [
            {
                "id": d.id,
                "package_name": d.package_name,
                "version": d.version,
                "ecosystem": d.ecosystem,
                "vulnerability_id": d.vulnerability_id,
                "severity": d.severity,
                "fixed_version": d.fixed_version,
                "reviewer_status": d.reviewer_status,
                "last_release_date": d.last_release_date,
                "maintainer_status": d.maintainer_status,
                "publisher_identity": d.publisher_identity,
                "alternative_package": d.alternative_package,
                "malicious_risk": d.malicious_risk,
                "reviewer_notes": d.reviewer_notes,
            }
            for d in a.dependencies
        ],
        "vault_artifacts": list_vault_artifacts(a.assessment_code),
        "audit_history": [
            {
                "id": ev.id,
                "actor_email": ev.actor_email,
                "actor_role": ev.actor_role,
                "event_type": ev.event_type,
                "previous_state": ev.previous_state,
                "new_state": ev.new_state,
                "sha256_file_hash": ev.sha256_file_hash,
                "summary": ev.summary,
                "immutable_signature": ev.immutable_signature,
                "created_at": ev.created_at,
            }
            for ev in audit_events
        ],
    }


@router.get("")
def list_assessments(
    technical_status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Assessment)
    if technical_status:
        query = query.filter(Assessment.technical_status == technical_status)
    items = query.order_by(Assessment.id.desc()).all()
    return [
        {
            "id": a.id,
            "assessment_code": a.assessment_code,
            "application_name": a.application.name if a.application else "",
            "sgates_app_id": a.application.sgates_app_id if a.application else "",
            "department": a.application.department if a.application else "",
            "ai_tool": a.application.ai_tool if a.application else "",
            "version": a.version,
            "technical_status": a.technical_status,
            "risk_level": a.risk_level,
            "final_decision": a.final_decision,
            "zip_filename": a.zip_filename,
            "sha256_hash": a.sha256_hash,
            "trivy_summary": a.trivy_summary,
            "gitleaks_summary": a.gitleaks_summary,
            "semgrep_summary": a.semgrep_summary,
            "av_status": a.av_status,
            "sandbox_required": a.sandbox_required,
            "sandbox_status": a.sandbox_status,
            "created_at": a.created_at,
        }
        for a in items
    ]


@router.get("/sample-zip/{preset}")
def download_sample_zip(preset: str):
    """Downloads a sample source-code ZIP package ('clean', 'review', 'reject', 'traversal')."""
    try:
        fname, data = generate_sample_zip(preset)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.post("/submit")
async def submit_assessment_zip(
    application_name: str = Form(...),
    version: str = Form("1.0"),
    department: str = Form(...),
    business_owner: str = Form(...),
    technical_owner: str = Form(...),
    description: str = Form(...),
    ai_tool: str = Form("Cursor"),
    app_type: str = Form("Internal Web Application"),
    data_classification: str = Form("Internal"),
    external_connections: str = Form("[]"),
    expected_users: int = Form(10),
    requires_admin_privileges: bool = Form(False),
    source_zip: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """PRD Section 9.1 & 10: Upload Source Code ZIP and execute full S-Gates scan workflow."""
    upload_limit = min(
        get_or_create_system_settings(db).max_zip_size_mb,
        settings.MAX_ZIP_SIZE_MB,
    ) * 1024 * 1024
    zip_bytes = await source_zip.read(upload_limit + 1)
    if len(zip_bytes) > upload_limit:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"ZIP exceeds the {upload_limit // (1024 * 1024)} MB upload limit.",
        )
    try:
        ext_list = json.loads(external_connections)
        if not isinstance(ext_list, list):
            ext_list = [str(external_connections)]
    except Exception:
        ext_list = [
            x.strip() for x in external_connections.split(",") if x.strip()
        ]

    assessment = await run_in_threadpool(execute_full_assessment,
        db=db,
        zip_bytes=zip_bytes,
        zip_filename=source_zip.filename or "Source.zip",
        app_name=application_name,
        version=version,
        department=department,
        business_owner=business_owner,
        technical_owner=technical_owner,
        description=description,
        ai_tool=ai_tool,
        app_type=app_type,
        data_classification=data_classification,
        external_connections=ext_list,
        expected_users=expected_users,
        requires_admin_privileges=requires_admin_privileges,
        submitter_email=current_user.email,
        submitter_name=current_user.full_name,
        submitter_role=current_user.role,
    )
    return _serialize_assessment(db, assessment)


@router.post("/submit-sample")
def submit_sample_assessment(
    payload: SampleSubmissionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """1-Click sample assessment submission for instant verification of all S-Gates gates."""
    try:
        fname, zip_bytes = generate_sample_zip(payload.preset)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    preset_defaults = {
        "clean": {
            "name": payload.application_name or "Vendor SLA Tracker Utility",
            "desc": "Read-only SLA compliance calculator generated with Cursor.",
            "data_class": "Internal",
            "conns": ["SharePoint"],
            "admin": False,
        },
        "review": {
            "name": payload.application_name or "Regional Commission Forecaster",
            "desc": "AI-assisted forecasting tool with CSV export and BI webhook.",
            "data_class": "Confidential",
            "conns": ["SharePoint", "External API"],
            "admin": False,
        },
        "reject": {
            "name": payload.application_name or "Shadow AI ERP Auto-Poster",
            "desc": "Background service connecting SAP vendor tables to external LLM.",
            "data_class": "Restricted / Personal Data",
            "conns": ["SAP", "Database", "External API"],
            "admin": True,
        },
        "traversal": {
            "name": payload.application_name or "Untrusted Third-Party Macro Bundle",
            "desc": "Archive containing path traversal ../../Windows/System32/example.exe.",
            "data_class": "Confidential",
            "conns": ["OneDrive"],
            "admin": True,
        },
    }
    d = preset_defaults.get(payload.preset, preset_defaults["clean"])

    assessment = execute_full_assessment(
        db=db,
        zip_bytes=zip_bytes,
        zip_filename=fname,
        app_name=d["name"],
        version=payload.version or "1.0",
        department=payload.department or "Operations & Finance",
        business_owner=payload.business_owner or "Sarah Chen (VP Operations)",
        technical_owner=payload.technical_owner or current_user.full_name,
        description=payload.description or d["desc"],
        ai_tool=payload.ai_tool or "Cursor + Claude",
        app_type=payload.app_type or "Internal Web Application",
        data_classification=d["data_class"],
        external_connections=payload.external_connections if payload.external_connections is not None else d["conns"],
        expected_users=payload.expected_users or 25,
        requires_admin_privileges=d["admin"],
        submitter_email=current_user.email,
        submitter_name=current_user.full_name,
        submitter_role=current_user.role,
    )
    return _serialize_assessment(db, assessment)


@router.post("/submit-github")
def submit_github_assessment(
    payload: GitHubSubmissionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch a GitHub repository archive and run it through the normal scan pipeline."""
    try:
        owner, repository, branch, zip_bytes = fetch_github_repository_zip(
            repository_url=payload.repository_url,
            ref=payload.branch,
            token=payload.github_token.get_secret_value() if payload.github_token else None,
            max_bytes=settings.MAX_ZIP_SIZE_MB * 1024 * 1024,
        )
    except GitHubSourceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    branch_slug = re.sub(r"[^A-Za-z0-9._-]+", "-", branch).strip("-.")[:64] or "ref"
    zip_filename = f"github-{owner}-{repository}-{branch_slug}.zip"
    external_connections = list(payload.external_connections)
    if "GitHub" not in external_connections:
        external_connections.append("GitHub")

    assessment = execute_full_assessment(
        db=db,
        zip_bytes=zip_bytes,
        zip_filename=zip_filename,
        app_name=payload.application_name,
        version=payload.version,
        department=payload.department,
        business_owner=payload.business_owner,
        technical_owner=payload.technical_owner,
        description=(
            f"{payload.description}\n\n"
            f"Scanned from GitHub: https://github.com/{owner}/{repository} (ref: {branch})."
        ).strip(),
        ai_tool=payload.ai_tool,
        app_type=payload.app_type,
        data_classification=payload.data_classification,
        external_connections=external_connections,
        expected_users=payload.expected_users,
        requires_admin_privileges=payload.requires_admin_privileges,
        submitter_email=current_user.email,
        submitter_name=current_user.full_name,
        submitter_role=current_user.role,
    )
    return _serialize_assessment(db, assessment)


def _stream_assessment_events(
    worker_fn: Callable[[Callable[[str, str, str], None]], dict],
) -> StreamingResponse:
    """Streams real-time NDJSON progress logs followed by the final assessment result."""
    event_queue: "queue.Queue[Optional[dict]]" = queue.Queue()

    def log_callback(level: str, stage: str, message: str) -> None:
        event_queue.put({
            "type": "log",
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3],
            "level": level,
            "stage": stage,
            "message": message,
        })

    def runner() -> None:
        try:
            result_dict = worker_fn(log_callback)
            event_queue.put({
                "type": "result",
                "assessment": jsonable_encoder(result_dict),
            })
        except GitHubSourceError as exc:
            log_callback("ERR", "INTAKE", str(exc))
            event_queue.put({"type": "error", "detail": str(exc)})
        except Exception as exc:
            log_callback("ERR", "SYSTEM", f"Backend execution error: {exc}")
            event_queue.put({"type": "error", "detail": str(exc)})
        finally:
            event_queue.put(None)

    threading.Thread(target=runner, daemon=True).start()

    async def stream_generator():
        while True:
            try:
                item = event_queue.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.05)
                continue
            if item is None:
                break
            yield json.dumps(item) + "\n"

    return StreamingResponse(
        stream_generator(),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/submit-stream")
async def submit_assessment_zip_stream(
    application_name: str = Form(...),
    version: str = Form("1.0"),
    department: str = Form(...),
    business_owner: str = Form(...),
    technical_owner: str = Form(...),
    description: str = Form(...),
    ai_tool: str = Form("Cursor"),
    app_type: str = Form("Internal Web Application"),
    data_classification: str = Form("Internal"),
    external_connections: str = Form("[]"),
    expected_users: int = Form(10),
    requires_admin_privileges: bool = Form(False),
    source_zip: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Streaming variant of ZIP upload assessment emitting live NDJSON backend progress."""
    upload_limit = min(
        get_or_create_system_settings(db).max_zip_size_mb,
        settings.MAX_ZIP_SIZE_MB,
    ) * 1024 * 1024
    zip_bytes = await source_zip.read(upload_limit + 1)
    if len(zip_bytes) > upload_limit:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"ZIP exceeds the {upload_limit // (1024 * 1024)} MB upload limit.",
        )
    try:
        ext_list = json.loads(external_connections)
        if not isinstance(ext_list, list):
            ext_list = [str(external_connections)]
    except Exception:
        ext_list = [x.strip() for x in external_connections.split(",") if x.strip()]

    zip_filename = source_zip.filename or "Source.zip"
    submitter_email = current_user.email
    submitter_name = current_user.full_name
    submitter_role = current_user.role

    def run_job(log_cb: Callable[[str, str, str], None]) -> dict:
        worker_db = SessionLocal()
        try:
            log_cb("INFO", "INTAKE", f"Received uploaded ZIP '{zip_filename}' ({len(zip_bytes) / 1024:.1f} KB).")
            assessment = execute_full_assessment(
                db=worker_db,
                zip_bytes=zip_bytes,
                zip_filename=zip_filename,
                app_name=application_name,
                version=version,
                department=department,
                business_owner=business_owner,
                technical_owner=technical_owner,
                description=description,
                ai_tool=ai_tool,
                app_type=app_type,
                data_classification=data_classification,
                external_connections=ext_list,
                expected_users=expected_users,
                requires_admin_privileges=requires_admin_privileges,
                submitter_email=submitter_email,
                submitter_name=submitter_name,
                submitter_role=submitter_role,
                log_callback=log_cb,
            )
            return _serialize_assessment(worker_db, assessment)
        finally:
            worker_db.close()

    return _stream_assessment_events(run_job)


@router.post("/submit-github-stream")
def submit_github_assessment_stream(
    payload: GitHubSubmissionRequest,
    current_user: User = Depends(get_current_user),
):
    """Streaming variant of GitHub assessment emitting live NDJSON backend progress."""
    submitter_email = current_user.email
    submitter_name = current_user.full_name
    submitter_role = current_user.role
    token_value = payload.github_token.get_secret_value() if payload.github_token else None

    def run_job(log_cb: Callable[[str, str, str], None]) -> dict:
        owner, repository, branch, zip_bytes = fetch_github_repository_zip(
            repository_url=payload.repository_url,
            ref=payload.branch,
            token=token_value,
            max_bytes=settings.MAX_ZIP_SIZE_MB * 1024 * 1024,
            log_callback=log_cb,
        )

        branch_slug = re.sub(r"[^A-Za-z0-9._-]+", "-", branch).strip("-.")[:64] or "ref"
        zip_filename = f"github-{owner}-{repository}-{branch_slug}.zip"
        external_connections = list(payload.external_connections)
        if "GitHub" not in external_connections:
            external_connections.append("GitHub")

        worker_db = SessionLocal()
        try:
            assessment = execute_full_assessment(
                db=worker_db,
                zip_bytes=zip_bytes,
                zip_filename=zip_filename,
                app_name=payload.application_name,
                version=payload.version,
                department=payload.department,
                business_owner=payload.business_owner,
                technical_owner=payload.technical_owner,
                description=(
                    f"{payload.description}\n\n"
                    f"Scanned from GitHub: https://github.com/{owner}/{repository} (ref: {branch})."
                ).strip(),
                ai_tool=payload.ai_tool,
                app_type=payload.app_type,
                data_classification=payload.data_classification,
                external_connections=external_connections,
                expected_users=payload.expected_users,
                requires_admin_privileges=payload.requires_admin_privileges,
                submitter_email=submitter_email,
                submitter_name=submitter_name,
                submitter_role=submitter_role,
                log_callback=log_cb,
            )
            return _serialize_assessment(worker_db, assessment)
        finally:
            worker_db.close()

    return _stream_assessment_events(run_job)


@router.delete("/purge-history")
def purge_all_assessments(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("ADMIN")),
):
    """Admin-only: Purge all assessments and associated evidence vault folders."""
    assessments = db.query(Assessment).all()
    count = len(assessments)
    for a in assessments:
        if a.evidence_vault_path and os.path.isdir(a.evidence_vault_path):
            shutil.rmtree(a.evidence_vault_path, ignore_errors=True)
        db.delete(a)
    db.commit()

    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        event_type="SCAN_HISTORY_PURGED",
        summary=f"Administrator purged {count} scan assessments from history and cleared vault storage.",
    )
    db.commit()
    return {"message": f"Successfully purged {count} scan assessments from history.", "count": count}


@router.delete("/{assessment_code}")
def delete_assessment(
    assessment_code: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("ADMIN")),
):
    """Admin-only: Delete a specific assessment, its findings, dependencies, and evidence vault artifacts."""
    a = (
        db.query(Assessment)
        .filter(Assessment.assessment_code == assessment_code)
        .first()
    )
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")

    vault_path = a.evidence_vault_path
    app_name = a.application.name if a.application else "Unknown"

    if vault_path and os.path.isdir(vault_path):
        shutil.rmtree(vault_path, ignore_errors=True)

    db.delete(a)
    db.commit()

    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        event_type="ASSESSMENT_DELETED",
        summary=f"Assessment {assessment_code} for '{app_name}' deleted by Administrator.",
        assessment_code=assessment_code,
    )
    db.commit()
    return {"message": f"Assessment {assessment_code} deleted successfully.", "assessment_code": assessment_code}


@router.get("/{assessment_code}")
def get_assessment_detail(
    assessment_code: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    a = (
        db.query(Assessment)
        .filter(Assessment.assessment_code == assessment_code)
        .first()
    )
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return _serialize_assessment(db, a)


@router.patch("/{assessment_code}/findings/{finding_id}")
def update_finding_status(
    assessment_code: str,
    finding_id: int,
    payload: FindingUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("IT_REVIEWER", "SECURITY_REVIEWER", "ADMIN")
    ),
):
    """PRD Section 22 & 27: Reviewers can classify false positives, accept risk, or mark resolved."""
    a = (
        db.query(Assessment)
        .filter(Assessment.assessment_code == assessment_code)
        .first()
    )
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")

    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id, Finding.assessment_id == a.id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    prev_status = finding.status
    finding.status = payload.status
    if payload.reviewer_comment is not None:
        finding.reviewer_comment = payload.reviewer_comment

    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        event_type="FINDING_STATUS_UPDATED",
        summary=(
            f"Updated finding {finding.finding_code} ({finding.scanner}: {finding.title}) "
            f"from '{prev_status}' to '{payload.status}'."
        ),
        assessment_code=a.assessment_code,
        sgates_app_id=a.application.sgates_app_id if a.application else None,
        previous_state=prev_status,
        new_state=payload.status,
        sha256_file_hash=a.sha256_hash,
    )
    recalculate_assessment_state(db, a)
    return _serialize_assessment(db, a)


@router.post("/{assessment_code}/findings/{finding_id}/itsm-ticket")
def create_itsm_vulnerability_ticket(
    assessment_code: str,
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("IT_REVIEWER", "SECURITY_REVIEWER", "ADMIN")
    ),
):
    """Placeholder endpoint; no synthetic ticket identifier is generated."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Freshservice is not configured; no ticket was created.",
    )


@router.patch("/{assessment_code}/dependencies/{dep_id}")
def update_dependency_review_status(
    assessment_code: str,
    dep_id: int,
    payload: DependencyUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("IT_REVIEWER", "SECURITY_REVIEWER", "ADMIN")
    ),
):
    """PRD Section 18 & 19: Abandoned Package Review (SUPPORTED, MAINTENANCE REVIEW, ABANDONED, UNKNOWN) & Malicious Risk."""
    a = (
        db.query(Assessment)
        .filter(Assessment.assessment_code == assessment_code)
        .first()
    )
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")

    dep = (
        db.query(DependencyItem)
        .filter(DependencyItem.id == dep_id, DependencyItem.assessment_id == a.id)
        .first()
    )
    if not dep:
        raise HTTPException(status_code=404, detail="Dependency item not found.")

    prev = dep.reviewer_status
    dep.reviewer_status = payload.reviewer_status
    if payload.malicious_risk:
        dep.malicious_risk = payload.malicious_risk
    if payload.reviewer_notes is not None:
        dep.reviewer_notes = payload.reviewer_notes

    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        event_type="DEPENDENCY_GOVERNANCE_UPDATED",
        summary=(
            f"Updated package '{dep.package_name}@{dep.version}' reviewer status from '{prev}' "
            f"to '{payload.reviewer_status}' (Malicious Classification: {dep.malicious_risk})."
        ),
        assessment_code=a.assessment_code,
        sgates_app_id=a.application.sgates_app_id if a.application else None,
        previous_state=prev,
        new_state=payload.reviewer_status,
        sha256_file_hash=a.sha256_hash,
    )
    recalculate_assessment_state(db, a)
    return _serialize_assessment(db, a)


@router.patch("/{assessment_code}/manual-gates")
def update_manual_security_gates(
    assessment_code: str,
    payload: ManualGateUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("IT_REVIEWER", "SECURITY_REVIEWER", "ADMIN")
    ),
):
    """PRD Section 15 (Antivirus/Trend Micro) & Section 16 (Sandbox Analysis) manual gates."""
    a = (
        db.query(Assessment)
        .filter(Assessment.assessment_code == assessment_code)
        .first()
    )
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")

    changes = []
    if payload.av_status:
        a.av_status = payload.av_status
        a.av_reviewed_by = f"{current_user.full_name} ({current_user.role})"
        changes.append(f"Antivirus/Trend Micro -> {payload.av_status}")
    if payload.av_notes is not None:
        a.av_notes = payload.av_notes
    if payload.av_evidence_ref is not None:
        a.av_evidence_ref = payload.av_evidence_ref

    if payload.sandbox_status:
        a.sandbox_status = payload.sandbox_status
        a.sandbox_reviewed_by = f"{current_user.full_name} ({current_user.role})"
        changes.append(f"Sandbox Gate -> {payload.sandbox_status}")
    if payload.sandbox_technology:
        a.sandbox_technology = payload.sandbox_technology
    if payload.sandbox_notes is not None:
        a.sandbox_notes = payload.sandbox_notes

    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        event_type="MANUAL_SECURITY_GATES_UPDATED",
        summary=f"Recorded manual gate evidence: {', '.join(changes) or 'Updated notes'}.",
        assessment_code=a.assessment_code,
        sgates_app_id=a.application.sgates_app_id if a.application else None,
        previous_state=a.technical_status,
        new_state=a.av_status,
        sha256_file_hash=a.sha256_hash,
    )
    recalculate_assessment_state(db, a)
    return _serialize_assessment(db, a)


@router.post("/{assessment_code}/decision")
def record_approval_decision(
    assessment_code: str,
    payload: ApprovalDecisionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("IT_REVIEWER", "SECURITY_REVIEWER", "ADMIN")
    ),
):
    """
    PRD Section 20, 27, 28, 30, 38:
    Records formal reviewer decision.
    Strictly blocks PILOT_APPROVED when:
    - Technical status is SCAN-ERROR (PRD Section 20: SCAN-ERROR must never be interpreted as PASS)
    - Scanner Intelligence Status is OUTDATED / UNAVAILABLE (PRD Section 30)
    - Unresolved Critical vulnerabilities or open Gitleaks secrets exist (PRD Section 38 KPI: 0 unresolved criticals/secrets at approval)
    - Risk Acceptance / Rejection of high-risk cases requires SECURITY_REVIEWER or ADMIN (PRD Section 27)
    """
    sys_cfg = get_or_create_system_settings(db)
    a = (
        db.query(Assessment)
        .filter(Assessment.assessment_code == assessment_code)
        .first()
    )
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")

    decision = payload.decision.upper()

    if decision in {"PILOT_APPROVED", "PILOT_RECOMMENDED", "RISK_ACCEPTED"} and (
        a.scanner_versions or {}
    ).get("mode") != "external":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Approval is disabled for heuristic demo results; validated external scanner evidence is required.",
        )

    if decision == "RISK_ACCEPTED":
        if current_user.role not in {"SECURITY_REVIEWER", "ADMIN"}:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only a Security Reviewer or Administrator can record formal Risk Acceptance (PRD Section 27).",
            )
        if a.technical_status != "REVIEW":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Risk acceptance is only available for REVIEW assessments; REJECT and SCAN-ERROR cannot be accepted.",
            )

    if decision in {"PILOT_APPROVED", "PILOT_RECOMMENDED"}:
        if not sys_cfg.trivy_db_available or sys_cfg.security_intel_status != "HEALTHY":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Approval blocked per PRD Section 30: Security Intelligence Status is "
                    f"'{sys_cfg.security_intel_status}' (Trivy DB unavailable). Results in SCAN-ERROR, not PASS."
                ),
            )
        if a.technical_status != "PASS-WITH-MANUAL-CHECKS":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Approval blocked: technical status is {a.technical_status}; only PASS-WITH-MANUAL-CHECKS may proceed.",
            )
        if decision == "PILOT_APPROVED" and (
            a.av_status != "No Threat Detected" or not (a.av_evidence_ref or "").strip()
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Approval blocked: record a cleared antivirus result and its evidence reference first.",
            )
        if decision == "PILOT_APPROVED" and a.sandbox_required and a.sandbox_status != "Passed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Approval blocked: required sandbox evidence has not passed.",
            )
        open_secrets = [
            f
            for f in a.findings
            if f.scanner == "Gitleaks" and f.status not in {"False Positive", "Resolved"}
        ]
        open_criticals = [
            f
            for f in a.findings
            if f.severity == "CRITICAL" and f.status not in {"False Positive", "Resolved", "Accepted"}
        ]
        if open_secrets or open_criticals:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Approval blocked per PRD Section 38 KPIs: {len(open_criticals)} unresolved CRITICAL finding(s) "
                    f"and {len(open_secrets)} exposed secret(s) remain Open."
                ),
            )

    expected_production_status = {
        "PILOT_APPROVED": "Pilot",
        "RISK_ACCEPTED": "Pilot (Risk Accepted)",
        "REMEDIATION_REQUESTED": "Remediation Required",
        "REJECTED": "Rejected",
    }.get(decision)
    if payload.production_status and payload.production_status != expected_production_status:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Production status is determined by the recorded decision and cannot be overridden.",
        )

    prev_decision = a.final_decision
    a.final_decision = decision
    a.decision_by = current_user.full_name
    a.decision_role = current_user.role
    a.decision_notes = payload.notes
    a.decision_at = datetime.now(timezone.utc)

    if a.application:
        if expected_production_status:
            a.application.production_status = expected_production_status

    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        event_type=f"DECISION_{decision}",
        summary=f"Recorded decision '{decision}' on {a.assessment_code}: {payload.notes}",
        assessment_code=a.assessment_code,
        sgates_app_id=a.application.sgates_app_id if a.application else None,
        previous_state=prev_decision,
        new_state=decision,
        sha256_file_hash=a.sha256_hash,
    )

    notif_map = {
        "PILOT_APPROVED": "Pilot Approved",
        "REMEDIATION_REQUESTED": "Remediation Required",
        "REJECTED": "Application Rejected",
    }
    emit_notification(
        db=db,
        event_type=notif_map.get(decision, "Scan Completed"),
        assessment_code=a.assessment_code,
        application_name=a.application.name if a.application else a.assessment_code,
        message=f"Reviewer {current_user.full_name} recorded decision {decision}: {payload.notes}",
    )

    recalculate_assessment_state(db, a)
    return _serialize_assessment(db, a)


@router.post("/{assessment_code}/re-evaluate")
def reevaluate_assessment(
    assessment_code: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Re-evaluates the assessment against current SystemSettings (e.g. after restoring Trivy DB health)."""
    a = (
        db.query(Assessment)
        .filter(Assessment.assessment_code == assessment_code)
        .first()
    )
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")

    prev_status = a.technical_status
    recalculate_assessment_state(db, a)
    record_audit_event(
        db=db,
        actor_email=current_user.email,
        actor_role=current_user.role,
        event_type="ASSESSMENT_REEVALUATED",
        summary=f"Re-evaluated stored findings for {a.assessment_code}; source code was not rescanned. Status: {prev_status} -> {a.technical_status}.",
        assessment_code=a.assessment_code,
        sgates_app_id=a.application.sgates_app_id if a.application else None,
        previous_state=prev_status,
        new_state=a.technical_status,
        sha256_file_hash=a.sha256_hash,
    )
    db.commit()
    return _serialize_assessment(db, a)
