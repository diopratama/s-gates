import json
import logging
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional
from app.engine.adapters.base import AdapterResult, BaseScannerAdapter

logger = logging.getLogger(__name__)


class SemgrepAdapter(BaseScannerAdapter):
    """
    Adapter for Semgrep Static Application Security Testing (SAST) CLI.
    Runs: semgrep scan --config auto --json <target_dir>
    Produces static code analysis findings mapped to OWASP / CWE categories.
    """

    def __init__(self, binary_path: str = "semgrep", custom_rules_path: Optional[str] = None):
        self.binary_path = binary_path
        self.custom_rules_path = custom_rules_path
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
            v = res.stdout.strip() or res.stderr.strip()
            return v.splitlines()[0] if v else "semgrep-installed"
        except Exception as exc:
            logger.warning(f"Failed to query Semgrep version: {exc}")
            return "unknown"

    def scan(self, target_dir: str, timeout_seconds: int = 60) -> AdapterResult:
        bin_path = self._get_bin()
        if not bin_path:
            return AdapterResult(
                scanner_name="Semgrep",
                version="not-installed",
                success=False,
                error_message="Semgrep executable was not found on system PATH.",
            )

        start_time = time.time()
        config_arg = self.custom_rules_path if self.custom_rules_path and os.path.exists(self.custom_rules_path) else "auto"

        cmd = [
            bin_path,
            "scan",
            "--config",
            config_arg,
            "--json",
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

            # Semgrep exit codes:
            # 0: Scan finished, no blocking findings (or all reported)
            # 1: Findings detected (when fail-on-findings is set, or exit code)
            # Semgrep json is output to stdout
            raw_output = proc.stdout.strip()
            if not raw_output and proc.stderr:
                # If stdout is empty and stderr has error
                if proc.returncode != 0:
                    return AdapterResult(
                        scanner_name="Semgrep",
                        version=self.get_version(),
                        success=False,
                        execution_time_seconds=elapsed,
                        error_message=proc.stderr.strip() or f"Semgrep exited with code {proc.returncode}",
                    )

            report_data = {}
            if raw_output:
                try:
                    report_data = json.loads(raw_output)
                except json.JSONDecodeError:
                    report_data = {}

            findings = self.parse_report(report_data, target_dir)

            return AdapterResult(
                scanner_name="Semgrep",
                version=self.get_version(),
                findings=findings,
                raw_report=report_data,
                execution_time_seconds=elapsed,
                success=True,
            )
        except subprocess.TimeoutExpired:
            return AdapterResult(
                scanner_name="Semgrep",
                version=self.get_version(),
                success=False,
                execution_time_seconds=float(timeout_seconds),
                error_message=f"Semgrep scan timed out after {timeout_seconds} seconds.",
            )
        except Exception as exc:
            return AdapterResult(
                scanner_name="Semgrep",
                version=self.get_version(),
                success=False,
                execution_time_seconds=time.time() - start_time,
                error_message=str(exc),
            )

    def parse_report(
        self, report: Dict[str, Any], base_dir: str
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        results = report.get("results", [])
        if not isinstance(results, list):
            return findings

        for idx, item in enumerate(results, start=1):
            check_id = item.get("check_id", "sast-rule")
            target_path = item.get("path", "unknown")
            rel_path = os.path.relpath(target_path, base_dir) if target_path.startswith(base_dir) else target_path
            rel_path = rel_path.replace("\\", "/").lstrip("./")

            start_pos = item.get("start", {}) or {}
            line = start_pos.get("line", 1)

            extra = item.get("extra", {}) or {}
            raw_severity = (extra.get("severity") or "WARNING").upper()

            # Map Semgrep severity (ERROR, WARNING, INFO) to S-Gates (CRITICAL, HIGH, MEDIUM, LOW)
            if raw_severity == "ERROR":
                severity = "HIGH"
                if any(x in check_id.lower() for x in ("rce", "sqli", "injection", "obfuscation")):
                    severity = "CRITICAL"
            elif raw_severity == "WARNING":
                severity = "MEDIUM"
            else:
                severity = "LOW"

            message = extra.get("message") or f"Semgrep rule {check_id} triggered."
            title = check_id.split(".")[-1].replace("-", " ").title()

            metadata = extra.get("metadata", {}) or {}
            cwe = metadata.get("cwe")
            if isinstance(cwe, list) and cwe:
                title = f"{title} ({cwe[0]})"

            recommendation = (
                "Review and remediate the flagged code pattern according to secure coding guidelines."
            )

            findings.append(
                {
                    "finding_code": f"SMP-SAST-{idx:03d}",
                    "scanner": "Semgrep",
                    "finding_type": "sast",
                    "severity": severity,
                    "title": title,
                    "description": message,
                    "file_path": rel_path,
                    "line_number": line,
                    "package_name": "-",
                    "installed_version": "-",
                    "fixed_version": "Remediate Code Pattern",
                    "vulnerability_id": check_id,
                    "redacted_value": "",
                    "recommendation": recommendation,
                    "status": "Open",
                }
            )

        return findings

