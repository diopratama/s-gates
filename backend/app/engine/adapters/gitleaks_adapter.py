import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional
from app.engine.adapters.base import AdapterResult, BaseScannerAdapter

logger = logging.getLogger(__name__)
REDACTED_SECRET_MASK = "********************"


class GitleaksAdapter(BaseScannerAdapter):
    """
    Adapter for Gitleaks credential & secret detection CLI scanner.
    Runs: gitleaks dir <target_dir> --no-git --report-format json --report-path <temp_file>
    Applies strict mandatory masking to discovered secret values.
    """

    def __init__(self, binary_path: str = "gitleaks"):
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
                [bin_path, "version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            v = res.stdout.strip() or res.stderr.strip()
            return v.splitlines()[0] if v else "gitleaks-installed"
        except Exception as exc:
            logger.warning(f"Failed to query Gitleaks version: {exc}")
            return "unknown"

    def scan(self, target_dir: str, timeout_seconds: int = 60) -> AdapterResult:
        bin_path = self._get_bin()
        if not bin_path:
            return AdapterResult(
                scanner_name="Gitleaks",
                version="not-installed",
                success=False,
                error_message="Gitleaks executable was not found on system PATH.",
            )

        start_time = time.time()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as report_file:
            report_path = report_file.name

        try:
            cmd = [
                bin_path,
                "dir",
                target_dir,
                "--report-format",
                "json",
                "--report-path",
                report_path,
                "--redact",  # Ask gitleaks to redact output if supported
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            elapsed = time.time() - start_time

            # Gitleaks exit code 0: no leaks found
            # Gitleaks exit code 1: leaks detected (success for S-Gates scanning!)
            # Gitleaks exit code > 1: real failure
            if proc.returncode not in {0, 1}:
                err_msg = proc.stderr.strip() or f"Gitleaks error exit code {proc.returncode}"
                return AdapterResult(
                    scanner_name="Gitleaks",
                    version=self.get_version(),
                    success=False,
                    execution_time_seconds=elapsed,
                    error_message=err_msg,
                )

            report_data: List[Dict[str, Any]] = []
            if os.path.isfile(report_path) and os.path.getsize(report_path) > 0:
                with open(report_path, "r", encoding="utf-8") as rf:
                    try:
                        report_data = json.load(rf)
                    except json.JSONDecodeError:
                        report_data = []

            findings = self.parse_report(report_data, target_dir)

            # Redact raw report payload before storing in vault
            sanitized_report = self._sanitize_raw_report(report_data, target_dir)

            return AdapterResult(
                scanner_name="Gitleaks",
                version=self.get_version(),
                findings=findings,
                raw_report={"results": sanitized_report},
                execution_time_seconds=elapsed,
                success=True,
            )
        except subprocess.TimeoutExpired:
            return AdapterResult(
                scanner_name="Gitleaks",
                version=self.get_version(),
                success=False,
                execution_time_seconds=float(timeout_seconds),
                error_message=f"Gitleaks scan timed out after {timeout_seconds} seconds.",
            )
        except Exception as exc:
            return AdapterResult(
                scanner_name="Gitleaks",
                version=self.get_version(),
                success=False,
                execution_time_seconds=time.time() - start_time,
                error_message=str(exc),
            )
        finally:
            if os.path.exists(report_path):
                os.remove(report_path)

    def parse_report(
        self, report: List[Dict[str, Any]], base_dir: str
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not isinstance(report, list):
            return findings

        for idx, item in enumerate(report, start=1):
            rule_id = item.get("RuleID", "SECRET")
            desc = item.get("Description") or f"Exposed Secret Detected ({rule_id})"
            target_file = item.get("File", "unknown")
            rel_file = os.path.relpath(target_file, base_dir) if target_file.startswith(base_dir) else target_file
            rel_file = rel_file.replace("\\", "/").lstrip("./")
            line = item.get("StartLine", 1)

            findings.append(
                {
                    "finding_code": f"GLK-SEC-{idx:03d}",
                    "scanner": "Gitleaks",
                    "finding_type": "secret",
                    "severity": "CRITICAL",
                    "title": desc,
                    "description": (
                        f"Gitleaks discovered an embedded secret ({rule_id}) in {rel_file} at line {line}. "
                        f"Secret value has been strictly redacted per S-Gates Section 13 policy."
                    ),
                    "file_path": rel_file,
                    "line_number": line,
                    "package_name": "-",
                    "installed_version": "-",
                    "fixed_version": "Revoke & Rotate Secret",
                    "vulnerability_id": rule_id.upper(),
                    "redacted_value": REDACTED_SECRET_MASK,
                    "recommendation": "Revoke and rotate the exposed credential immediately. Never commit secrets to source archives.",
                    "status": "Open",
                }
            )

        return findings

    def _sanitize_raw_report(
        self, report: List[Dict[str, Any]], base_dir: str
    ) -> List[Dict[str, Any]]:
        sanitized = []
        for item in report:
            c = dict(item)
            c["Secret"] = REDACTED_SECRET_MASK
            c["Match"] = REDACTED_SECRET_MASK
            target_file = c.get("File", "")
            if target_file.startswith(base_dir):
                c["File"] = os.path.relpath(target_file, base_dir).replace("\\", "/").lstrip("./")
            sanitized.append(c)
        return sanitized

