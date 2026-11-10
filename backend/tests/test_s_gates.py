import os
import tempfile
import pytest
from fastapi.testclient import TestClient

# Point tests to an isolated temporary SQLite DB and Evidence Vault
_tmp_dir = tempfile.mkdtemp(prefix="sgates_test_")
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(_tmp_dir, 'test_sgates.db')}"
os.environ["EVIDENCE_VAULT_DIR"] = os.path.join(_tmp_dir, "evidence_vault")
os.environ["SEED_DEMO_ASSESSMENTS"] = "true"

from app.main import app  # noqa: E402
from app.api import assessments as assessments_api  # noqa: E402
from app.api import auth as auth_api  # noqa: E402
from app.engine.sample_generator import generate_sample_zip  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import AuditRecord  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _auth_header(client: TestClient, role: str) -> dict:
    resp = client.post("/api/v1/auth/switch-role", json={"role": role})
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_health_and_mandatory_disclaimer(client: TestClient):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["scanner_mode"] == "heuristic-demo"
    assert data["production_ready"] is False


def test_demo_role_switcher_is_disabled_when_flag_is_off(client: TestClient, monkeypatch):
    monkeypatch.setattr(auth_api.settings, "ENABLE_DEMO_ROLE_SWITCHER", False)
    response = client.post("/api/v1/auth/switch-role", json={"role": "ADMIN"})
    assert response.status_code == 404


def test_production_startup_is_blocked_for_heuristic_only_build(monkeypatch):
    from app.config import settings, validate_runtime_settings

    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "ENABLE_DEMO_ROLE_SWITCHER", False)
    monkeypatch.setattr(settings, "SEED_DEMO_ASSESSMENTS", False)
    with pytest.raises(RuntimeError, match="Production startup is disabled"):
        validate_runtime_settings()


def test_bootstrap_admin_can_use_password_login(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "test-admin@example.test", "password": "test-admin-password-only-for-tests"},
    )
    assert response.status_code == 200
    assert response.json()["user"]["role"] == "ADMIN"


def test_seeded_assessments_and_versions(client: TestClient):
    headers = _auth_header(client, "IT_REVIEWER")
    resp = client.get("/api/v1/assessments", headers=headers)
    assert resp.status_code == 200
    items = resp.json()
    codes = {i["assessment_code"]: i for i in items}
    assert "SG-2026-00027" in codes
    assert "SG-2026-00044" in codes
    assert codes["SG-2026-00044"]["technical_status"] == "REVIEW"
    assert codes["SG-2026-00045"]["technical_status"] == "REVIEW"
    assert codes["SG-2026-00046"]["technical_status"] == "REJECT"
    assert codes["SG-2026-00047"]["technical_status"] == "SCAN-ERROR"


def test_github_repository_submission_uses_security_scan_pipeline(client: TestClient, monkeypatch):
    _, archive = generate_sample_zip("clean")

    def fake_fetch(repository_url, ref, token, max_bytes):
        assert repository_url == "https://github.com/octocat/Hello-World"
        assert ref == "main"
        assert token == "temporary-test-token"
        assert max_bytes > len(archive)
        return "octocat", "Hello-World", "main", archive

    monkeypatch.setattr(assessments_api, "fetch_github_repository_zip", fake_fetch)
    headers = _auth_header(client, "IT_REVIEWER")
    response = client.post(
        "/api/v1/assessments/submit-github",
        json={
            "repository_url": "https://github.com/octocat/Hello-World",
            "branch": "main",
            "github_token": "temporary-test-token",
            "application_name": "GitHub Test Repository",
            "version": "1.0",
            "department": "Engineering",
            "business_owner": "Engineering Lead",
            "technical_owner": "Test Reviewer",
            "description": "Test GitHub repository scan.",
        },
        headers=headers,
    )

    assert response.status_code == 200
    assessment = response.json()
    assert assessment["zip_filename"] == "github-octocat-Hello-World-main.zip"
    assert assessment["zip_valid"] is True
    assert "https://github.com/octocat/Hello-World" in assessment["application"]["description"]
    assert "temporary-test-token" not in response.text


def test_zip_security_gate_blocks_path_traversal(client: TestClient):
    """PRD Section 11: ../../Windows/System32/example.exe must cause the archive to be rejected."""
    headers = _auth_header(client, "CITIZEN_DEVELOPER")
    resp = client.post(
        "/api/v1/assessments/submit-sample",
        json={"preset": "traversal", "application_name": "Traversal Test App", "version": "1.0"},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["zip_valid"] is False
    assert data["technical_status"] == "REJECT"
    assert any("Windows/System32/example.exe" in err for err in data["zip_validation_errors"])


def test_zip_upload_rejects_oversized_body_before_scanning(client: TestClient, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "MAX_ZIP_SIZE_MB", 1)
    headers = _auth_header(client, "CITIZEN_DEVELOPER")
    response = client.post(
        "/api/v1/assessments/submit",
        data={
            "application_name": "Oversize Test",
            "department": "Engineering",
            "business_owner": "Engineering Lead",
            "technical_owner": "Test User",
            "description": "Size-limit test",
        },
        files={"source_zip": ("large.zip", b"x" * (1024 * 1024 + 1), "application/zip")},
        headers=headers,
    )
    assert response.status_code == 413


def test_gitleaks_secret_redaction_never_exposes_raw_secrets(client: TestClient):
    """PRD Section 13: The UI and reports SHALL never display complete discovered secret values."""
    headers = _auth_header(client, "SECURITY_REVIEWER")
    resp = client.get("/api/v1/assessments/SG-2026-00046", headers=headers)
    assert resp.status_code == 200
    raw_text = resp.text
    # Ensure actual embedded secrets from sample_generator are never returned
    assert "AKIAIOSFODNN7EXAMPLE" not in raw_text
    assert "SuperSecretSapProdPassword2026!" not in raw_text

    data = resp.json()
    secret_findings = [f for f in data["findings"] if f["scanner"] == "Gitleaks"]
    assert len(secret_findings) >= 2
    for sf in secret_findings:
        assert sf["redacted_value"] == "********************"


def test_rbac_citizen_developer_cannot_approve_or_modify_findings(client: TestClient):
    """PRD Section 27: Citizen Developer cannot approve application or modify scanner result."""
    citizen_headers = _auth_header(client, "CITIZEN_DEVELOPER")
    detail = client.get("/api/v1/assessments/SG-2026-00044", headers=citizen_headers).json()
    finding_id = detail["findings"][0]["id"]

    # Attempt to modify finding status as Citizen Developer -> 403
    mod_resp = client.patch(
        f"/api/v1/assessments/SG-2026-00044/findings/{finding_id}",
        json={"status": "False Positive", "reviewer_comment": "Trying to bypass"},
        headers=citizen_headers,
    )
    assert mod_resp.status_code == 403

    # Attempt to approve pilot as Citizen Developer -> 403
    app_resp = client.post(
        "/api/v1/assessments/SG-2026-00044/decision",
        json={"decision": "PILOT_APPROVED", "notes": "Self-approving"},
        headers=citizen_headers,
    )
    assert app_resp.status_code == 403


def test_manual_gates_and_evidence_vault_artifacts(client: TestClient):
    """PRD Sections 15, 16, 24: Record Trend Micro AV & Sandbox results and verify Evidence Vault files."""
    reviewer_headers = _auth_header(client, "IT_REVIEWER")

    # Update manual gates on SG-2026-00044
    gate_resp = client.patch(
        "/api/v1/assessments/SG-2026-00044/manual-gates",
        json={
            "av_status": "No Threat Detected",
            "av_notes": "Trend Micro Apex One scan clean (0 detections).",
            "sandbox_status": "Passed",
            "sandbox_technology": "Windows Sandbox",
            "sandbox_notes": "Executed export processor in isolated Windows Sandbox; no unexpected outbound traffic.",
        },
        headers=reviewer_headers,
    )
    assert gate_resp.status_code == 200
    updated = gate_resp.json()
    assert updated["av_status"] == "No Threat Detected"
    assert updated["sandbox_status"] == "Passed"

    # Check Evidence Vault structure (PRD Section 24)
    vault_resp = client.get("/api/v1/evidence/SG-2026-00044/files", headers=reviewer_headers)
    assert vault_resp.status_code == 200
    paths = {f["relative_path"] for f in vault_resp.json()["files"]}
    expected_paths = {
        "Submission/Source.zip",
        "Inventory/file-inventory.csv",
        "Reports/trivy-report.json",
        "Reports/trivy-report.txt",
        "Reports/gitleaks-report.json",
        "Reports/semgrep-report.json",
        "Reports/scan-summary.json",
        "Reports/scan-summary.html",
        "Evidence/antivirus-result",
        "Evidence/sandbox-result",
        "Approval/decision",
    }
    assert expected_paths.issubset(paths)

    # Download HTML report and verify disclaimer
    download_path = "/api/v1/evidence/SG-2026-00044/download?path=Reports/scan-summary.html"
    assert client.get(download_path).status_code == 401
    assert client.get("/api/v1/evidence/SG-2026-00044/bundle.zip").status_code == 401
    html_resp = client.get(download_path, headers=reviewer_headers)
    assert html_resp.status_code == 200
    assert "does not provide security clearance" in html_resp.text


def test_external_connectors_do_not_report_fake_success(client: TestClient):
    headers = _auth_header(client, "IT_REVIEWER")
    response = client.post(
        "/api/v1/evidence/SG-2026-00044/sync-sharepoint",
        headers=headers,
    )
    assert response.status_code == 501

    detail = client.get("/api/v1/assessments/SG-2026-00044", headers=headers).json()
    finding_id = detail["findings"][0]["id"]
    ticket = client.post(
        f"/api/v1/assessments/SG-2026-00044/findings/{finding_id}/itsm-ticket",
        headers=headers,
    )
    assert ticket.status_code == 501


def test_heuristic_results_cannot_be_approved(client: TestClient):
    headers = _auth_header(client, "ADMIN")
    response = client.post(
        "/api/v1/assessments/SG-2026-00045/decision",
        json={"decision": "PILOT_APPROVED", "notes": "Testing demo-mode approval guard"},
        headers=headers,
    )
    assert response.status_code == 409


def test_scanner_state_is_simulated_and_never_allows_approval(client: TestClient):
    """The prototype must not claim real scanner health or approve heuristic results."""
    admin_headers = _auth_header(client, "ADMIN")

    # Test-only simulation of an external scanner database outage.
    cfg_resp = client.patch(
        "/api/v1/admin/settings",
        json={"security_intel_status": "OUTDATED", "trivy_db_available": False},
        headers=admin_headers,
    )
    assert cfg_resp.status_code == 200
    assert cfg_resp.json()["security_intel_status"] == "OUTDATED"

    # Submit a clean app while DB is OUTDATED -> Must become SCAN-ERROR, never PASS!
    sub_resp = client.post(
        "/api/v1/assessments/submit-sample",
        json={"preset": "clean", "application_name": "Outdated DB Test App", "version": "1.0"},
        headers=admin_headers,
    )
    assert sub_resp.status_code == 200
    new_asmt = sub_resp.json()
    assert new_asmt["technical_status"] == "SCAN-ERROR"

    # Attempt to approve while DB is OUTDATED -> Must be blocked (400)
    approve_resp = client.post(
        f"/api/v1/assessments/{new_asmt['assessment_code']}/decision",
        json={"decision": "PILOT_APPROVED", "notes": "Attempting approval with outdated DB"},
        headers=admin_headers,
    )
    assert approve_resp.status_code == 409

    # Restore the test-only DB flag and re-evaluate stored findings (not a rescan).
    client.patch(
        "/api/v1/admin/settings",
        json={"security_intel_status": "HEALTHY", "trivy_db_available": True},
        headers=admin_headers,
    )
    rescan_resp = client.post(
        f"/api/v1/assessments/{new_asmt['assessment_code']}/re-evaluate",
        headers=admin_headers,
    )
    assert rescan_resp.status_code == 200
    assert rescan_resp.json()["technical_status"] == "REVIEW"


def test_immutable_audit_chain_integrity(client: TestClient):
    """PRD Section 28: Audit trail integrity verification."""
    admin_headers = _auth_header(client, "ADMIN")
    resp = client.get("/api/v1/admin/audit-logs", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["chain_integrity_verified"] is True
    assert data["total_records"] >= 5


def test_audit_chain_detects_metadata_tampering(client: TestClient):
    headers = _auth_header(client, "ADMIN")
    db = SessionLocal()
    record_id = None
    orig_meta = None
    try:
        record = db.query(AuditRecord).order_by(AuditRecord.id.desc()).first()
        assert record is not None
        assert record.metadata_json["_chain_version"] == 2
        record_id = record.id
        orig_meta = dict(record.metadata_json)
        record.metadata_json = {**record.metadata_json, "tampered": True}
        db.commit()

        response = client.get("/api/v1/admin/audit-logs", headers=headers)
        assert response.status_code == 200
        assert response.json()["chain_integrity_verified"] is False
    finally:
        if record_id is not None and orig_meta is not None:
            rec = db.query(AuditRecord).filter(AuditRecord.id == record_id).first()
            if rec:
                rec.metadata_json = orig_meta
                db.commit()
        db.close()


def test_admin_delete_assessment_and_audit(client: TestClient):
    """Admin can delete an individual assessment and an audit record is preserved."""
    admin_headers = _auth_header(client, "ADMIN")
    citizen_headers = _auth_header(client, "CITIZEN_DEVELOPER")

    # Submit a test sample
    sub_resp = client.post(
        "/api/v1/assessments/submit-sample",
        json={"preset": "clean", "application_name": "Delete Target App", "version": "1.0"},
        headers=admin_headers,
    )
    assert sub_resp.status_code == 200
    code = sub_resp.json()["assessment_code"]

    # Citizen developer should be blocked (403)
    del_blocked = client.delete(f"/api/v1/assessments/{code}", headers=citizen_headers)
    assert del_blocked.status_code == 403

    # Admin should succeed (200)
    del_ok = client.delete(f"/api/v1/assessments/{code}", headers=admin_headers)
    assert del_ok.status_code == 200
    assert del_ok.json()["assessment_code"] == code

    # Assessment should now be 404
    get_resp = client.get(f"/api/v1/assessments/{code}", headers=admin_headers)
    assert get_resp.status_code == 404


def test_admin_purge_scan_history(client: TestClient):
    """Admin can purge all scan history."""
    admin_headers = _auth_header(client, "ADMIN")
    citizen_headers = _auth_header(client, "CITIZEN_DEVELOPER")

    # Non-admin cannot purge
    purge_blocked = client.delete("/api/v1/assessments/purge-history", headers=citizen_headers)
    assert purge_blocked.status_code == 403

    # Admin can purge
    purge_ok = client.delete("/api/v1/assessments/purge-history", headers=admin_headers)
    assert purge_ok.status_code == 200
    assert "count" in purge_ok.json()

    # List of assessments should now be empty
    list_resp = client.get("/api/v1/assessments", headers=admin_headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 0


def test_submit_zip_stream_emits_logs_and_result(client: TestClient):
    """Streaming ZIP upload emits structured NDJSON backend logs followed by result."""
    import json

    headers = _auth_header(client, "CITIZEN_DEVELOPER")
    fname, zip_bytes = generate_sample_zip("clean")

    resp = client.post(
        "/api/v1/assessments/submit-stream",
        headers=headers,
        data={
            "application_name": "Streamed ZIP App",
            "version": "1.0",
            "department": "Engineering",
            "business_owner": "VP Engineering",
            "technical_owner": "Stream Tester",
            "description": "Streaming scan test",
        },
        files={"source_zip": (fname, zip_bytes, "application/zip")},
    )
    assert resp.status_code == 200
    lines = [json.loads(line) for line in resp.text.strip().splitlines() if line.strip()]
    log_events = [item for item in lines if item.get("type") == "log"]
    result_events = [item for item in lines if item.get("type") == "result"]

    assert len(log_events) >= 4
    stages = {item["stage"] for item in log_events}
    assert {"INTAKE", "ZIP_GATE", "SCANNERS", "RISK_ENGINE", "VAULT"}.issubset(stages)
    assert len(result_events) == 1
    assert result_events[0]["assessment"]["assessment_code"].startswith("SG-")


def test_submit_github_stream_does_not_leak_token(client: TestClient, monkeypatch):
    """Streaming GitHub scan emits logs without exposing any private GitHub token."""
    import json

    headers = _auth_header(client, "CITIZEN_DEVELOPER")
    _, archive = generate_sample_zip("clean")
    secret_token = "ghp_SECRET_TEST_TOKEN_DO_NOT_LEAK_999"

    def fake_fetch(repository_url, ref, token, max_bytes, log_callback=None):
        assert token == secret_token
        if log_callback:
            log_callback("INFO", "INTAKE", "Validating GitHub repository URL...")
            log_callback("OK", "INTAKE", "Downloaded repository archive (2.0 KB).")
        return "example", "repo", ref or "main", archive

    monkeypatch.setattr(assessments_api, "fetch_github_repository_zip", fake_fetch)

    resp = client.post(
        "/api/v1/assessments/submit-github-stream",
        headers=headers,
        json={
            "repository_url": "https://github.com/example/repo",
            "branch": "main",
            "github_token": secret_token,
            "application_name": "Streamed GitHub App",
            "version": "1.0",
            "department": "Engineering",
            "business_owner": "VP Engineering",
            "technical_owner": "Stream Tester",
            "description": "Streaming GitHub scan test",
        },
    )
    assert resp.status_code == 200
    assert secret_token not in resp.text
    lines = [json.loads(line) for line in resp.text.strip().splitlines() if line.strip()]
    result_events = [item for item in lines if item.get("type") == "result"]
    assert len(result_events) == 1
    assert result_events[0]["assessment"]["application"]["name"] == "Streamed GitHub App"


def test_admin_delete_application_cascades_and_audits(client: TestClient):
    """Admin can delete an application from inventory, cascading assessments & vault files."""
    admin_headers = _auth_header(client, "ADMIN")
    citizen_headers = _auth_header(client, "CITIZEN_DEVELOPER")

    sub_resp = client.post(
        "/api/v1/assessments/submit-sample",
        json={"preset": "clean", "application_name": "Inventory Delete Target", "version": "1.0"},
        headers=admin_headers,
    )
    assert sub_resp.status_code == 200
    payload = sub_resp.json()
    sgates_app_id = payload["application"]["sgates_app_id"]
    asmt_code = payload["assessment_code"]

    # Non-admin blocked
    blocked = client.delete(f"/api/v1/applications/{sgates_app_id}", headers=citizen_headers)
    assert blocked.status_code == 403

    # Admin deletes application
    deleted = client.delete(f"/api/v1/applications/{sgates_app_id}", headers=admin_headers)
    assert deleted.status_code == 200
    assert deleted.json()["sgates_app_id"] == sgates_app_id
    assert deleted.json()["deleted_assessments_count"] >= 1

    # Linked assessment is also removed
    asmt_resp = client.get(f"/api/v1/assessments/{asmt_code}", headers=admin_headers)
    assert asmt_resp.status_code == 404

    # Audit trail records APPLICATION_DELETED with verified SHA-256 chain
    audit_resp = client.get("/api/v1/admin/audit-logs", headers=admin_headers)
    assert audit_resp.status_code == 200
    audit_data = audit_resp.json()
    assert audit_data["chain_integrity_verified"] is True
    assert any(
        ev["event_type"] == "APPLICATION_DELETED" and ev["sgates_app_id"] == sgates_app_id
        for ev in audit_data["records"]
    )

