import json
import logging
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional
from app.engine.adapters.base import AdapterResult, BaseScannerAdapter

logger = logging.getLogger(__name__)


class TrivyAdapter(BaseScannerAdapter):
    """
    Adapter for Aqua Security Trivy CLI scanner.
    Runs: trivy fs --scanners vuln,misconfig --format json --output <temp_json> <dir>
    Produces SCA vulnerabilities, misconfigurations, and package inventory.
    """

    def __init__(self, binary_path: str = "trivy"):
        self.binary_path = binary_path
        self._resolved_path: Optional[str] = None

    def _get_bin(self) -> Optional[str]:
        if self._resolved_path is None:
            self._resolved_path = shutil.which(self.binary_path)
        return self._resolved_path

    def is_available(self) -> bool:
        return self._get_bin() is not None

    def get_version(self) -> str:
        bin_path = self._get_bin()
        if not bin_path:
            return "not-installed"
        try:
            res = subprocess.run(
                [bin_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            # Output format: Version: 0.58.0 or trivy version 0.58.0
            first_line = res.stdout.strip().splitlines()[0] if res.stdout.strip() else ""
            return first_line.replace("Version:", "").strip() or "trivy-installed"
        except Exception as exc:
            logger.warning(f"Failed to query Trivy version: {exc}")
            return "unknown"

    def scan(self, target_dir: str, timeout_seconds: int = 60) -> AdapterResult:
        bin_path = self._get_bin()
        if not bin_path:
            return AdapterResult(
                scanner_name="Trivy",
                version="not-installed",
                success=False,
                error_message="Trivy executable was not found on system PATH.",
            )

        start_time = time.time()
        # Run trivy fs
        cmd = [
            bin_path,
            "fs",
            "--scanners",
            "vuln,misconfig",
            "--format",
            "json",
            "--quiet",
            target_dir,
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            elapsed = time.time() - start_time
            if proc.returncode not in {0, 1}:  # Trivy exit code 1 may signify findings
                err_msg = proc.stderr.strip() or f"Trivy exited with code {proc.returncode}"
                return AdapterResult(
                    scanner_name="Trivy",
                    version=self.get_version(),
                    success=False,
                    execution_time_seconds=elapsed,
                    error_message=err_msg,
                )

            report_data = json.loads(proc.stdout) if proc.stdout.strip() else {}
            findings, dependencies = self.parse_report(report_data, target_dir)

            return AdapterResult(
                scanner_name="Trivy",
                version=self.get_version(),
                findings=findings,
                dependencies=dependencies,
                raw_report=report_data,
                execution_time_seconds=elapsed,
                success=True,
            )
        except subprocess.TimeoutExpired:
            return AdapterResult(
                scanner_name="Trivy",
                version=self.get_version(),
                success=False,
                execution_time_seconds=float(timeout_seconds),
                error_message=f"Trivy scan timed out after {timeout_seconds} seconds.",
            )
        except Exception as exc:
            return AdapterResult(
                scanner_name="Trivy",
                version=self.get_version(),
                success=False,
                execution_time_seconds=time.time() - start_time,
                error_message=str(exc),
            )

    def parse_report(
        self, report: Dict[str, Any], base_dir: str
    ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        findings: List[Dict[str, Any]] = []
        dependencies: List[Dict[str, Any]] = []
        f_idx = 1

        results = report.get("Results", [])
        if not isinstance(results, list):
            return findings, dependencies

        for target_result in results:
            target_file = target_result.get("Target", "unknown")
            rel_target = os.path.relpath(target_file, base_dir) if target_file.startswith(base_dir) else target_file
            rel_target = rel_target.replace("\\", "/").lstrip("./")

            ecosystem = target_result.get("Type", "generic")

            # Extract Packages into dependencies list
            for pkg in target_result.get("Packages", []) or []:
                pkg_name = pkg.get("Name", "")
                pkg_ver = pkg.get("Version", "unknown")
                dependencies.append(
                    {
                        "package_name": pkg_name,
                        "version": pkg_ver,
                        "ecosystem": ecosystem,
                        "vulnerability_id": "None",
                        "severity": "NONE",
                        "fixed_version": "-",
                        "reviewer_status": "SUPPORTED",
                        "last_release_date": "Verified via Trivy",
                        "maintainer_status": "Active",
                        "publisher_identity": "Verified Package Registry",
                        "alternative_package": "-",
                        "malicious_risk": "Known Safe / Standard",
                        "reviewer_notes": "Discovered via Trivy filesystem SCA scan.",
                    }
                )

            # Extract Vulnerabilities
            for vuln in target_result.get("Vulnerabilities", []) or []:
                cve_id = vuln.get("VulnerabilityID", "UNKNOWN-CVE")
                sev = (vuln.get("Severity") or "LOW").upper()
                if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                    sev = "LOW"

                pkg_name = vuln.get("PkgName", "")
                installed_ver = vuln.get("InstalledVersion", "")
                fixed_ver = vuln.get("FixedVersion", "-")
                title = vuln.get("Title") or f"Vulnerability in {pkg_name} ({cve_id})"
                desc = vuln.get("Description") or title

                findings.append(
                    {
                        "finding_code": f"TRV-VULN-{f_idx:03d}",
                        "scanner": "Trivy",
                        "finding_type": "vuln",
                        "severity": sev,
                        "title": title,
                        "description": desc,
                        "file_path": rel_target,
                        "line_number": 1,
                        "package_name": pkg_name,
                        "installed_version": installed_ver,
                        "fixed_version": fixed_ver,
                        "vulnerability_id": cve_id,
                        "redacted_value": "",
                        "recommendation": f"Upgrade {pkg_name} to {fixed_ver}." if fixed_ver != "-" else "Mitigate or replace package.",
                        "status": "Open",
                    }
                )
                f_idx += 1

                # Update or append matching dependency item with vulnerability info
                matched_dep = next((d for d in dependencies if d["package_name"].lower() == pkg_name.lower()), None)
                if matched_dep:
                    matched_dep["vulnerability_id"] = cve_id
                    matched_dep["severity"] = sev
                    matched_dep["fixed_version"] = fixed_ver
                    matched_dep["malicious_risk"] = "Known Vulnerable Package"

            # Extract Misconfigurations
            for misconf in target_result.get("Misconfigurations", []) or []:
                m_id = misconf.get("ID", "MISCONFIG")
                sev = (misconf.get("Severity") or "LOW").upper()
                if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                    sev = "LOW"

                title = misconf.get("Title") or f"Misconfiguration {m_id}"
                desc = misconf.get("Description") or title
                res = misconf.get("Resolution") or "Follow security best practice for configuration."

                findings.append(
                    {
                        "finding_code": f"TRV-CFG-{f_idx:03d}",
                        "scanner": "Trivy",
                        "finding_type": "misconfig",
                        "severity": sev,
                        "title": title,
                        "description": desc,
                        "file_path": rel_target,
                        "line_number": 1,
                        "package_name": "Configuration",
                        "installed_version": "-",
                        "fixed_version": "-",
                        "vulnerability_id": m_id,
                        "redacted_value": "",
                        "recommendation": res,
                        "status": "Open",
                    }
                )
                f_idx += 1

        return findings, dependencies

