import os
import posixpath
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.engine.evidence_vault import bundle_vault_zip, list_vault_artifacts
from app.models import Assessment, User
from app.security import get_current_user, require_roles

router = APIRouter(prefix="/evidence", tags=["Evidence Vault & SharePoint Sync"])


def _get_assessment_for_user(assessment_code: str, db: Session, current_user: User) -> Assessment:
    assessment = (
        db.query(Assessment)
        .filter(Assessment.assessment_code == assessment_code)
        .first()
    )
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    if (
        current_user.role not in {"IT_REVIEWER", "SECURITY_REVIEWER", "ADMIN"}
        and assessment.submitter_email != current_user.email
    ):
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return assessment


def _resolve_vault_file(assessment: Assessment, relative_path: str) -> str:
    clean_rel = posixpath.normpath(relative_path.replace("\\", "/"))
    if clean_rel in {".", ".."} or clean_rel.startswith("../") or clean_rel.startswith("/"):
        raise HTTPException(status_code=400, detail="Invalid artifact path.")

    vault_root = os.path.realpath(settings.EVIDENCE_VAULT_DIR)
    base_dir = os.path.realpath(assessment.evidence_vault_path)
    target_path = os.path.realpath(os.path.join(base_dir, clean_rel))
    try:
        if os.path.commonpath((vault_root, base_dir)) != vault_root:
            raise HTTPException(status_code=404, detail="Artifact file not found in Evidence Vault.")
        if os.path.commonpath((base_dir, target_path)) != base_dir or not os.path.isfile(target_path):
            raise HTTPException(status_code=404, detail="Artifact file not found in Evidence Vault.")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Artifact file not found in Evidence Vault.") from exc
    return target_path


@router.get("/{assessment_code}/files")
def get_vault_file_list(
    assessment_code: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    a = _get_assessment_for_user(assessment_code, db, current_user)
    return {
        "assessment_code": assessment_code,
        "sharepoint_synced": a.sharepoint_synced,
        "sharepoint_url": a.sharepoint_url,
        "files": list_vault_artifacts(assessment_code),
    }


@router.get("/{assessment_code}/download")
def download_vault_artifact(
    assessment_code: str,
    path: str = Query(..., description="Relative path inside the Evidence Vault, e.g. Reports/scan-summary.html"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    a = _get_assessment_for_user(assessment_code, db, current_user)
    target_path = _resolve_vault_file(a, path)

    fname = os.path.basename(target_path)
    media_type = "application/octet-stream"
    if fname.endswith(".json") or fname in {"antivirus-result", "sandbox-result", "decision"}:
        media_type = "application/json"
    elif fname.endswith(".html"):
        media_type = "text/html; charset=utf-8"
    elif fname.endswith(".txt"):
        media_type = "text/plain; charset=utf-8"
    elif fname.endswith(".csv"):
        media_type = "text/csv; charset=utf-8"
    elif fname.endswith(".zip"):
        media_type = "application/zip"

    return FileResponse(
        path=target_path,
        media_type=media_type,
        filename=f"{assessment_code}-{fname}",
        headers={"X-Content-Type-Options": "nosniff"},
    )


@router.get("/{assessment_code}/bundle.zip")
def download_full_evidence_bundle(
    assessment_code: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    a = _get_assessment_for_user(assessment_code, db, current_user)

    zip_bytes = bundle_vault_zip(assessment_code)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{assessment_code}-Evidence-Vault.zip"'
        },
    )


@router.post("/{assessment_code}/sync-sharepoint")
def sync_evidence_to_sharepoint(
    assessment_code: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("IT_REVIEWER", "SECURITY_REVIEWER", "ADMIN")),
):
    """Placeholder endpoint; never claim a sync until a real connector is configured."""
    raise HTTPException(
        status_code=501,
        detail="SharePoint synchronization is not configured; no evidence was uploaded.",
    )
