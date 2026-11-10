import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from app.engine.evidence_vault import (
    bundle_vault_zip,
    list_vault_artifacts,
    write_evidence_vault,
)
from app.engine.risk_engine import evaluate_risk_decision
from app.engine.sample_generator import generate_sample_zip
from app.engine.scanners import REDACTED_SECRET_MASK, run_security_scanners
from app.engine.zip_validator import validate_and_extract_zip


class TestSGatesSecurityEngine(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="sgates_unit_")
        settings.EVIDENCE_VAULT_DIR = self.tmp_dir

    def test_01_zip_security_controls_reject_path_traversal(self):
        """PRD Section 11: ../../Windows/System32/example.exe must cause the archive to be rejected."""
        fname, zbytes = generate_sample_zip("traversal")
        res = validate_and_extract_zip(zbytes, fname)
        self.assertFalse(res.valid)
        self.assertTrue(len(res.sha256_hash) == 64)
        self.assertTrue(
            any("Windows/System32/example.exe" in err for err in res.errors),
            f"Expected Windows/System32/example.exe rejection in {res.errors}",
        )

    def test_02_unlisted_dependencies_require_review(self):
        """Packages outside the local demo catalog are not silently marked safe."""
        fname, zbytes = generate_sample_zip("clean")
        zres = validate_and_extract_zip(zbytes, fname)
        self.assertTrue(zres.valid)
        self.assertGreaterEqual(zres.file_count, 4)
        self.assertIn("File Path,Extension,Size (Bytes),SHA-256", zres.csv_content)

        scan = run_security_scanners(
            zres.extracted_files,
            {"name": "KPI Calculator", "requires_admin_privileges": False},
            zres.sandbox_indicators,
        )
        self.assertEqual(len(scan["findings"]), 0)

        status, risk, reasons = evaluate_risk_decision(
            zip_valid=zres.valid,
            zip_errors=zres.errors,
            security_intel_status="HEALTHY",
            trivy_db_available=True,
            findings=scan["findings"],
            dependencies=scan["dependencies"],
            app_metadata={"name": "KPI Calculator"},
            av_status="No Threat Detected",
            sandbox_required=scan["sandbox_required"],
        )
        self.assertEqual(status, "REVIEW")
        self.assertEqual(risk, "MEDIUM")
        self.assertTrue(any("not covered by the local heuristic catalog" in reason for reason in reasons))

    def test_03_review_package_detects_high_sast_and_abandoned_pkg(self):
        """PRD Section 14, 18, 21: Sales Analytics v1.2 triggers REVIEW with Semgrep HIGH & Abandoned package."""
        fname, zbytes = generate_sample_zip("review")
        zres = validate_and_extract_zip(zbytes, fname)
        self.assertTrue(zres.valid)

        scan = run_security_scanners(
            zres.extracted_files,
            {"name": "Sales Analytics Tool", "data_classification": "Confidential"},
            zres.sandbox_indicators,
        )
        scanners_found = {f["scanner"] for f in scan["findings"]}
        self.assertIn("Trivy", scanners_found)
        self.assertIn("Semgrep", scanners_found)

        abandoned = [
            d for d in scan["dependencies"] if d["reviewer_status"] == "ABANDONED"
        ]
        self.assertGreaterEqual(len(abandoned), 1)

        status, risk, _ = evaluate_risk_decision(
            zip_valid=zres.valid,
            zip_errors=zres.errors,
            security_intel_status="HEALTHY",
            trivy_db_available=True,
            findings=scan["findings"],
            dependencies=scan["dependencies"],
            app_metadata={"name": "Sales Analytics Tool"},
            av_status="No Threat Detected",
            sandbox_required=scan["sandbox_required"],
        )
        self.assertEqual(status, "REVIEW")
        self.assertEqual(risk, "HIGH")

    def test_04_reject_package_redacts_secrets_and_flags_malicious_deps(self):
        """PRD Section 13, 16, 19, 20: Secret redaction (********************), typosquatting, and Sandbox EXE trigger."""
        fname, zbytes = generate_sample_zip("reject")
        zres = validate_and_extract_zip(zbytes, fname)
        self.assertTrue(zres.valid)

        scan = run_security_scanners(
            zres.extracted_files,
            {"name": "Shadow AI SAP Sync", "requires_admin_privileges": True},
            zres.sandbox_indicators,
        )
        gitleaks_findings = [
            f for f in scan["findings"] if f["scanner"] == "Gitleaks"
        ]
        self.assertGreaterEqual(len(gitleaks_findings), 2)
        for gf in gitleaks_findings:
            self.assertEqual(gf["redacted_value"], REDACTED_SECRET_MASK)
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", gf["description"])

        self.assertTrue(scan["sandbox_required"])
        self.assertTrue(scan["has_malicious_pkg"])
        self.assertTrue(scan["has_obfuscation"])

        status, risk, _ = evaluate_risk_decision(
            zip_valid=zres.valid,
            zip_errors=zres.errors,
            security_intel_status="HEALTHY",
            trivy_db_available=True,
            findings=scan["findings"],
            dependencies=scan["dependencies"],
            app_metadata={"name": "Shadow AI SAP Sync"},
            av_status="No Threat Detected",
            sandbox_required=scan["sandbox_required"],
        )
        self.assertEqual(status, "REJECT")
        self.assertEqual(risk, "CRITICAL")

    def test_05_scanner_db_outdated_forces_scan_error_never_pass(self):
        """PRD Section 20 & 30: Trivy DB unavailable results in SCAN-ERROR, never PASS."""
        status, _, reasons = evaluate_risk_decision(
            zip_valid=True,
            zip_errors=[],
            security_intel_status="OUTDATED",
            trivy_db_available=False,
            findings=[],
            dependencies=[],
            app_metadata={"name": "Clean App"},
        )
        self.assertEqual(status, "SCAN-ERROR")
        self.assertNotEqual(status, "PASS-WITH-MANUAL-CHECKS")
        self.assertTrue(any("OUTDATED" in r for r in reasons))

    def test_06_evidence_vault_writes_all_prd_section_24_artifacts(self):
        """PRD Section 24: Verify exact Evidence Vault directory tree and files."""
        fname, zbytes = generate_sample_zip("review")
        zres = validate_and_extract_zip(zbytes, fname)
        scan = run_security_scanners(
            zres.extracted_files,
            {"name": "Sales Analytics Tool"},
            zres.sandbox_indicators,
        )
        code = "SG-2026-00044"
        write_evidence_vault(
            assessment_code=code,
            app_info={
                "name": "Sales Analytics Tool",
                "department": "Sales",
                "business_owner": "VP Sales",
                "technical_owner": "Alex Rivera",
                "ai_tool": "Claude",
                "data_classification": "Confidential",
            },
            assessment_info={
                "version": "1.2",
                "zip_filename": fname,
                "sha256_hash": zres.sha256_hash,
                "technical_status": "REVIEW",
                "risk_level": "HIGH",
                "trivy_summary": scan["trivy_summary"],
                "gitleaks_summary": scan["gitleaks_summary"],
                "semgrep_summary": scan["semgrep_summary"],
                "av_status": "No Threat Detected",
                "sandbox_status": "Required - Pending",
                "final_decision": "PENDING_REVIEW",
            },
            zip_bytes=zbytes,
            csv_inventory=zres.csv_content,
            findings=scan["findings"],
            dependencies=scan["dependencies"],
        )

        artifacts = list_vault_artifacts(code)
        rel_paths = {a["relative_path"] for a in artifacts}
        required = {
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
        self.assertTrue(required.issubset(rel_paths))

        bundle = bundle_vault_zip(code)
        self.assertGreater(len(bundle), 500)


if __name__ == "__main__":
    unittest.main()
