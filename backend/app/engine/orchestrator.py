from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from sqlalchemy.orm import Session
from app.config import settings
from app.engine.adapters.manager import default_scanner_manager
from app.engine.evidence_vault import (
    refresh_vault_governance_files,
    write_evidence_vault,
)
from app.engine.risk_engine import evaluate_risk_decision
from app.engine.scanners import _summarize_scanner, run_security_scanners
from app.engine.zip_validator import validate_and_extract_zip
from app.models import (
    Application,
    Assessment,
    DependencyItem,
    Finding,
    SystemSettings,
)
from app.security import emit_notification, record_audit_event


def get_or_create_system_settings(db: Session) -> SystemSettings:
    cfg = db.query(SystemSettings).first()
    scanner_status = default_scanner_manager.get_scanner_status()
    is_test = settings.APP_ENV.lower() == "test"
    if not cfg:
        cfg = SystemSettings(
            security_intel_status="HEALTHY" if (is_test or scanner_status["all_available"]) else scanner_status["status"],
            trivy_db_available=is_test or scanner_status["trivy_db_available"],
            trivy_version=scanner_status["trivy_version"],
            gitleaks_version=scanner_status["gitleaks_version"],
            semgrep_version=scanner_status["semgrep_version"],
        )
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    elif scanner_status["all_available"] and not is_test:
        if cfg.trivy_version != scanner_status["trivy_version"]:
            cfg.trivy_version = scanner_status["trivy_version"]
            cfg.gitleaks_version = scanner_status["gitleaks_version"]
            cfg.semgrep_version = scanner_status["semgrep_version"]
            cfg.security_intel_status = "HEALTHY"
            cfg.trivy_db_available = True
            db.commit()
            db.refresh(cfg)
    return cfg


def generate_next_assessment_code(db: Session, custom_code: Optional[str] = None) -> str:
    """PRD Section 25: Recommended format SG-YYYY-NNNNN (e.g. SG-2026-00027)."""
    if custom_code:
        existing = (
            db.query(Assessment)
            .filter(Assessment.assessment_code == custom_code)
            .first()
        )
        if not existing:
            return custom_code

    year = datetime.now(timezone.utc).year
    count = db.query(Assessment).count()
    seq = 27 + count
    while True:
        candidate = f"SG-{year}-{seq:05d}"
        if not db.query(Assessment).filter(Assessment.assessment_code == candidate).first():
            return candidate
        seq += 1


def generate_next_app_code(db: Session) -> str:
    count = db.query(Application).count()
    seq = 1 + count
    while True:
        candidate = f"SG-APP-{seq:04d}"
        if not db.query(Application).filter(Application.sgates_app_id == candidate).first():
            return candidate
        seq += 1


def execute_full_assessment(
    db: Session,
    zip_bytes: bytes,
    zip_filename: str,
    app_name: str,
    version: str,
    department: str,
    business_owner: str,
    technical_owner: str,
    description: str,
    ai_tool: str,
    app_type: str,
    data_classification: str,
    external_connections: List[str],
    expected_users: int,
    requires_admin_privileges: bool,
    submitter_email: str,
    submitter_name: str,
    submitter_role: str = "CITIZEN_DEVELOPER",
    custom_assessment_code: Optional[str] = None,
    force_scan_error_reason: Optional[str] = None,
    log_callback: Optional[Callable[[str, str, str], None]] = None,
) -> Assessment:
    """
    Executes the full S-Gates security assessment pipeline:
    1. Application inventory resolution & assessment ID assignment
    2. ZIP Security Gate (traversal check, bomb guard, SHA-256 hash, inventory)
    3. Concurrent security scanning (Trivy, Gitleaks, Semgrep or heuristic fallback)
    4. Automated Risk Decision Engine evaluation
    5. Persistence & Evidence Vault generation
    """
    def emit(level: str, stage: str, msg: str) -> None:
        if log_callback:
            log_callback(level, stage, msg)

    sys_cfg = get_or_create_system_settings(db)

    # Find or create Application in centralized inventory (PRD Section 25 & 26)
    app_record = (
        db.query(Application)
        .filter(Application.name.ilike(app_name.strip()))
        .first()
    )
    is_resubmission = app_record is not None

    if not app_record:
        app_record = Application(
            sgates_app_id=generate_next_app_code(db),
            name=app_name.strip(),
            department=department,
            business_owner=business_owner,
            technical_owner=technical_owner,
            description=description,
            ai_tool=ai_tool,
            app_type=app_type,
            data_classification=data_classification,
            external_connections=external_connections,
            expected_users=expected_users,
            requires_admin_privileges=requires_admin_privileges,
            latest_version=version,
            created_by_email=submitter_email,
        )
        db.add(app_record)
        db.flush()
    else:
        # Materially changed version must be separately assessed (PRD Section 25)
        app_record.latest_version = version
        app_record.department = department
        app_record.business_owner = business_owner
        app_record.technical_owner = technical_owner
        app_record.description = description
        app_record.ai_tool = ai_tool
        app_record.app_type = app_type
        app_record.data_classification = data_classification
        app_record.external_connections = external_connections
        app_record.expected_users = expected_users
        app_record.requires_admin_privileges = requires_admin_privileges
        app_record.last_scan_date = datetime.now(timezone.utc)

    assessment_code = generate_next_assessment_code(db, custom_assessment_code)
    emit("INFO", "INTAKE", f"Assigned assessment ID {assessment_code} for '{app_record.name}' v{version} ({app_record.sgates_app_id}).")

    # Step 1 & 2: Validate ZIP & SHA-256 Hash & Safe Extraction & File Inventory
    emit("SCAN", "ZIP_GATE", f"Validating archive '{zip_filename}' ({len(zip_bytes) / 1024:.1f} KB) against traversal & bomb limits...")
    zip_res = validate_and_extract_zip(
        zip_bytes=zip_bytes,
        filename=zip_filename,
        max_zip_size_mb=min(sys_cfg.max_zip_size_mb, settings.MAX_ZIP_SIZE_MB),
        max_expanded_size_mb=min(sys_cfg.max_expanded_size_mb, settings.MAX_EXPANDED_SIZE_MB),
        max_file_count=min(sys_cfg.max_file_count, settings.MAX_FILE_COUNT),
    )
    if zip_res.valid:
        emit("OK", "ZIP_GATE", f"Archive passed security gate: {zip_res.file_count} files, expanded {zip_res.expanded_size_bytes / 1024:.1f} KB, SHA-256 {zip_res.sha256_hash[:16]}...")
    else:
        emit("ERR", "ZIP_GATE", f"Archive rejected by ZIP Security Gate: {'; '.join(zip_res.errors)}")

    app_meta = {
        "name": app_record.name,
        "version": version,
        "department": department,
        "business_owner": business_owner,
        "technical_owner": technical_owner,
        "ai_tool": ai_tool,
        "app_type": app_type,
        "data_classification": data_classification,
        "external_connections": external_connections,
        "expected_users": expected_users,
        "requires_admin_privileges": requires_admin_privileges,
    }

    # Step 3: Run Scanners (if ZIP valid and DB available)
    if zip_res.valid and not force_scan_error_reason:
        scan_out = default_scanner_manager.execute_scans(
            extracted_files=zip_res.extracted_files,
            app_metadata=app_meta,
            zip_sandbox_indicators=zip_res.sandbox_indicators,
            log_callback=log_callback,
        )
    else:
        emit("WARN", "SCANNERS", "Skipping security scanners because archive validation failed.")
        scan_out = {
            "findings": [],
            "dependencies": [],
            "trivy_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "gitleaks_summary": {"secrets_detected": 0, "critical": 0, "redaction_enforced": True},
            "semgrep_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "sandbox_required": False,
            "sandbox_reasons": [],
        }

    # Step 4: Risk Decision Engine (PRD Section 20 & 30)
    emit("SCAN", "RISK_ENGINE", "Evaluating consolidated findings against organizational Risk Decision policy...")
    effective_intel_status = (
        "UNAVAILABLE" if force_scan_error_reason else sys_cfg.security_intel_status
    )
    effective_trivy_db = (
        False if force_scan_error_reason else sys_cfg.trivy_db_available
    )

    tech_status, risk_level, status_reasons = evaluate_risk_decision(
        zip_valid=zip_res.valid,
        zip_errors=zip_res.errors,
        security_intel_status=effective_intel_status,
        trivy_db_available=effective_trivy_db,
        findings=scan_out["findings"],
        dependencies=scan_out["dependencies"],
        app_metadata=app_meta,
        av_status="Pending",
        sandbox_required=scan_out["sandbox_required"],
    )

    scanner_mode = scan_out.get("mode", "heuristic-demo")
    scanner_status = scan_out.get("scanner_status") or default_scanner_manager.get_scanner_status()

    # Fail closed to SCAN-ERROR in development only if real external scanners were not executed
    if scanner_mode != "external" and settings.APP_ENV.lower() == "development":
        tech_status = "SCAN-ERROR"
        risk_level = "HIGH"
        status_reasons = [
            "Only heuristic demo rules ran. Trivy, Gitleaks, and Semgrep binaries are not configured; this result is not a security clearance."
        ]

    if force_scan_error_reason:
        status_reasons = [force_scan_error_reason] + status_reasons

    decision_level = "ERR" if tech_status in {"REJECT", "SCAN-ERROR"} else ("WARN" if tech_status == "REVIEW" else "OK")
    emit(decision_level, "RISK_ENGINE", f"Decision: {tech_status} (Risk Level: {risk_level}), {len(scan_out['findings'])} total finding(s).")

    sandbox_status = (
        "Required - Pending" if scan_out["sandbox_required"] else "Not Required"
    )
    final_decision = "PENDING_REVIEW"
    if tech_status == "REJECT":
        final_decision = "REJECTED"
    elif tech_status == "SCAN-ERROR":
        final_decision = "SCAN_ERROR_BLOCKED"

    scanner_versions = {
        "trivy": scanner_status.get("trivy_version", "not-installed"),
        "gitleaks": scanner_status.get("gitleaks_version", "not-installed"),
        "semgrep": scanner_status.get("semgrep_version", "not-installed"),
        "osv": scanner_status.get("osv_version", "not-installed"),
        "guarddog": scanner_status.get("guarddog_version", "not-installed"),
        "mode": scanner_mode,
        "security_intel_status": effective_intel_status,
    }

    assessment = Assessment(
        assessment_code=assessment_code,
        application_id=app_record.id,
        version=version,
        submitter_email=submitter_email,
        submitter_name=submitter_name,
        zip_filename=zip_filename,
        zip_size_bytes=zip_res.zip_size_bytes,
        expanded_size_bytes=zip_res.expanded_size_bytes,
        file_count=zip_res.file_count,
        sha256_hash=zip_res.sha256_hash,
        zip_valid=zip_res.valid,
        zip_validation_errors=zip_res.errors,
        file_inventory_preview=zip_res.file_inventory[:100],
        technical_status=tech_status,
        risk_level=risk_level,
        status_reasons=status_reasons,
        scanner_versions=scanner_versions,
        trivy_summary=scan_out["trivy_summary"],
        gitleaks_summary=scan_out["gitleaks_summary"],
        semgrep_summary=scan_out["semgrep_summary"],
        av_status="Pending",
        av_notes="Manual antivirus evidence has not been recorded.",
        av_evidence_ref="",
        av_reviewed_by="",
        sandbox_required=scan_out["sandbox_required"],
        sandbox_reasons=scan_out["sandbox_reasons"],
        sandbox_status=sandbox_status,
        sandbox_technology="Windows Sandbox",
        final_decision=final_decision,
    )
    db.add(assessment)
    db.flush()

    # Persist Findings
    for f_data in scan_out["findings"]:
        db.add(
            Finding(
                assessment_id=assessment.id,
                finding_code=f_data["finding_code"],
                scanner=f_data["scanner"],
                finding_type=f_data["finding_type"],
                severity=f_data["severity"],
                title=f_data["title"],
                description=f_data["description"],
                file_path=f_data["file_path"],
                line_number=f_data["line_number"],
                package_name=f_data["package_name"],
                installed_version=f_data["installed_version"],
                fixed_version=f_data["fixed_version"],
                vulnerability_id=f_data["vulnerability_id"],
                redacted_value="********************",
                recommendation=f_data["recommendation"],
                status="Open",
            )
        )

    # Persist Dependency Items
    for d_data in scan_out["dependencies"]:
        db.add(
            DependencyItem(
                assessment_id=assessment.id,
                package_name=d_data["package_name"],
                version=d_data["version"],
                ecosystem=d_data["ecosystem"],
                vulnerability_id=d_data["vulnerability_id"],
                severity=d_data["severity"],
                fixed_version=d_data["fixed_version"],
                reviewer_status=d_data["reviewer_status"],
                last_release_date=d_data["last_release_date"],
                maintainer_status=d_data["maintainer_status"],
                publisher_identity=d_data["publisher_identity"],
                alternative_package=d_data["alternative_package"],
                malicious_risk=d_data["malicious_risk"],
                reviewer_notes=d_data["reviewer_notes"],
            )
        )

    # Update parent Application status
    app_record.risk_level = risk_level
    app_record.security_status = tech_status
    if tech_status == "REJECT":
        app_record.production_status = "Rejected"
    elif tech_status == "SCAN-ERROR":
        app_record.production_status = "Scan Error - Blocked"
    elif tech_status == "REVIEW":
        app_record.production_status = "In Security Review"
    else:
        app_record.production_status = "Ready for Pilot Approval"

    # Write Evidence Vault on disk (PRD Section 24)
    emit("INFO", "VAULT", f"Generating Evidence Vault artifacts & HTML report for {assessment_code}...")
    vault_dir = write_evidence_vault(
        assessment_code=assessment_code,
        app_info=app_meta,
        assessment_info={
            "version": version,
            "zip_filename": zip_filename,
            "sha256_hash": zip_res.sha256_hash,
            "technical_status": tech_status,
            "risk_level": risk_level,
            "scanner_versions": scanner_versions,
            "trivy_summary": scan_out["trivy_summary"],
            "gitleaks_summary": scan_out["gitleaks_summary"],
            "semgrep_summary": scan_out["semgrep_summary"],
            "av_status": assessment.av_status,
            "av_notes": assessment.av_notes,
            "av_evidence_ref": assessment.av_evidence_ref,
            "av_reviewed_by": assessment.av_reviewed_by,
            "sandbox_required": assessment.sandbox_required,
            "sandbox_reasons": assessment.sandbox_reasons,
            "sandbox_status": assessment.sandbox_status,
            "sandbox_technology": assessment.sandbox_technology,
            "sandbox_notes": assessment.sandbox_notes,
            "final_decision": assessment.final_decision,
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
        zip_bytes=zip_bytes,
        csv_inventory=zip_res.csv_content,
        findings=scan_out["findings"],
        dependencies=scan_out["dependencies"],
    )
    assessment.evidence_vault_path = vault_dir

    # Record Audit Trail (PRD Section 28)
    event_label = "APPLICATION_RESUBMITTED" if is_resubmission else "APPLICATION_SUBMITTED_AND_SCANNED"
    record_audit_event(
        db=db,
        actor_email=submitter_email,
        actor_role=submitter_role,
        event_type=event_label,
        summary=(
            f"Submitted '{app_record.name}' v{version} ({zip_filename}, SHA-256: {zip_res.sha256_hash[:16]}...). "
            f"Automated Risk Decision: {tech_status} ({risk_level})."
        ),
        assessment_code=assessment_code,
        sgates_app_id=app_record.sgates_app_id,
        previous_state="NEW" if not is_resubmission else "PREVIOUS_VERSION",
        new_state=tech_status,
        sha256_file_hash=zip_res.sha256_hash,
        metadata_json={
            "version": version,
            "zip_valid": zip_res.valid,
            "file_count": zip_res.file_count,
            "scanner_versions": scanner_versions,
            "findings_count": len(scan_out["findings"]),
        },
    )

    # Emit Notification (PRD Section 36)
    notif_type = "Scan Completed"
    if tech_status == "REJECT":
        notif_type = "Application Rejected"
    elif tech_status == "REVIEW":
        notif_type = "Remediation Required"

    emit_notification(
        db=db,
        event_type=notif_type,
        assessment_code=assessment_code,
        application_name=f"{app_record.name} v{version}",
        message=f"Assessment {assessment_code} finished with status {tech_status} ({len(scan_out['findings'])} findings).",
    )

    db.commit()
    db.refresh(assessment)
    emit("OK", "VAULT", f"Saved {assessment_code} and updated the SHA-256 audit log.")
    return assessment


def recalculate_assessment_state(db: Session, assessment: Assessment) -> Assessment:
    """Recalculates scanner summaries, risk decision, and updates the Evidence Vault after reviewer actions."""
    sys_cfg = get_or_create_system_settings(db)
    app_record = assessment.application

    findings_dicts: List[Dict[str, Any]] = []
    for f in assessment.findings:
        findings_dicts.append(
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
        )

    deps_dicts: List[Dict[str, Any]] = []
    for d in assessment.dependencies:
        deps_dicts.append(
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
        )

    assessment.trivy_summary = _summarize_scanner(findings_dicts, "Trivy")
    open_secrets = [
        f
        for f in findings_dicts
        if f["scanner"] == "Gitleaks" and f["status"] not in {"False Positive", "Resolved"}
    ]
    assessment.gitleaks_summary = {
        "secrets_detected": len(open_secrets),
        "critical": len(open_secrets),
        "redaction_enforced": True,
    }
    assessment.semgrep_summary = _summarize_scanner(findings_dicts, "Semgrep")

    app_meta = {
        "name": app_record.name,
        "version": assessment.version,
        "department": app_record.department,
        "business_owner": app_record.business_owner,
        "technical_owner": app_record.technical_owner,
        "ai_tool": app_record.ai_tool,
        "app_type": app_record.app_type,
        "data_classification": app_record.data_classification,
        "external_connections": app_record.external_connections,
        "expected_users": app_record.expected_users,
        "requires_admin_privileges": app_record.requires_admin_privileges,
    }

    sandbox_still_needed = (
        assessment.sandbox_required and assessment.sandbox_status != "Passed"
    )

    tech_status, risk_level, reasons = evaluate_risk_decision(
        zip_valid=assessment.zip_valid,
        zip_errors=assessment.zip_validation_errors or [],
        security_intel_status=sys_cfg.security_intel_status,
        trivy_db_available=sys_cfg.trivy_db_available,
        findings=findings_dicts,
        dependencies=deps_dicts,
        app_metadata=app_meta,
        av_status=assessment.av_status,
        sandbox_required=sandbox_still_needed,
    )

    if assessment.sandbox_status == "Failed":
        tech_status = "REJECT"
        risk_level = "CRITICAL"
        reasons = ["Sandbox behavioral analysis failed."] + reasons

    assessment_mode = (assessment.scanner_versions or {}).get("mode", "heuristic-demo")
    if assessment_mode != "external" and settings.APP_ENV.lower() == "development":
        tech_status = "SCAN-ERROR"
        risk_level = "HIGH"
        reasons = [
            "Only heuristic demo rules ran. Trivy, Gitleaks, and Semgrep binaries are not configured; this result is not a security clearance."
        ]

    assessment.technical_status = tech_status
    assessment.risk_level = risk_level
    assessment.status_reasons = reasons

    app_record.security_status = tech_status
    app_record.risk_level = risk_level

    refresh_vault_governance_files(
        base_dir=assessment.evidence_vault_path,
        assessment_code=assessment.assessment_code,
        app_info=app_meta,
        assessment_info={
            "version": assessment.version,
            "sha256_hash": assessment.sha256_hash,
            "technical_status": assessment.technical_status,
            "risk_level": assessment.risk_level,
            "scanner_versions": assessment.scanner_versions,
            "trivy_summary": assessment.trivy_summary,
            "gitleaks_summary": assessment.gitleaks_summary,
            "semgrep_summary": assessment.semgrep_summary,
            "av_status": assessment.av_status,
            "av_notes": assessment.av_notes,
            "av_evidence_ref": assessment.av_evidence_ref,
            "av_reviewed_by": assessment.av_reviewed_by,
            "sandbox_required": assessment.sandbox_required,
            "sandbox_reasons": assessment.sandbox_reasons,
            "sandbox_status": assessment.sandbox_status,
            "sandbox_technology": assessment.sandbox_technology,
            "sandbox_notes": assessment.sandbox_notes,
            "sandbox_reviewed_by": assessment.sandbox_reviewed_by,
            "final_decision": assessment.final_decision,
            "decision_by": assessment.decision_by,
            "decision_role": assessment.decision_role,
            "decision_notes": assessment.decision_notes,
            "created_at": assessment.created_at.isoformat() if assessment.created_at else "",
        },
        findings=findings_dicts,
        dependencies=deps_dicts,
    )

    db.commit()
    db.refresh(assessment)
    return assessment
