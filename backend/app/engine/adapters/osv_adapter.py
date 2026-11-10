import json
import logging
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple
from app.engine.adapters.base import AdapterResult, BaseScannerAdapter

logger = logging.getLogger(__name__)


def _cvss_to_severity(score_val: Any) -> str:
    try:
        score = float(score_val)
    except (TypeError, ValueError):
        return ""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_fixed_version(vuln: Dict[str, Any]) -> str:
    fixed_versions: List[str] = []
    for affected in vuln.get("affected", []) or []:
        for r in affected.get("ranges", []) or []:
            for ev in r.get("events", []) or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    fixed_versions.append(str(ev["fixed"]))
    if fixed_versions:
        return ", ".join(dict.fromkeys(fixed_versions))
    return "-"


def _map_ecosystem(osv_eco: str) -> str:
    mapping = {
        "PyPI": "pip",
        "npm": "npm",
        "Go": "Go",
        "Maven": "Maven",
        "NuGet": "NuGet",
        "RubyGems": "RubyGems",
        "crates.io": "Cargo",
    }
    return mapping.get(osv_eco, osv_eco or "generic")


class OsvScannerAdapter(BaseScannerAdapter):
    """
    Adapter for Google OSV-Scanner CLI (Apache-2.0).
    Runs: osv-scanner scan --format json -r <target_dir>
    Detects lockfile/manifest vulnerabilities and OpenSSF Malicious Packages (MAL-*).
    """

    def __init__(self, binary_path: str = "osv-scanner"):
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
            output = (res.stdout or res.stderr or "").strip()
            for line in output.splitlines():
                if "version" in line.lower():
                    return line.split(":")[-1].strip().split()[-1]
            return output.splitlines()[0] if output else "osv-installed"
        except Exception as exc:
            logger.warning(f"Failed to query OSV-Scanner version: {exc}")
            return "unknown"

    def scan(self, target_dir: str, timeout_seconds: int = 60) -> AdapterResult:
        bin_path = self._get_bin()
        if not bin_path:
            return AdapterResult(
                scanner_name="OSV-Scanner",
                version="not-installed",
                success=False,
                error_message="osv-scanner executable was not found on system PATH.",
            )

        start_time = time.time()
        cmd = [
            bin_path,
            "scan",
            "--format",
            "json",
            "-r",
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

            # Exit code 0 = clean, 1 = vulns found, 128 = no packages found
            if proc.returncode == 128:
                return AdapterResult(
                    scanner_name="OSV-Scanner",
                    version=self.get_version(),
                    findings=[],
                    dependencies=[],
                    raw_report={"results": [], "note": "No scannable lockfiles/manifests found."},
                    execution_time_seconds=elapsed,
                    success=True,
                )

            if proc.returncode not in {0, 1}:
                err_msg = proc.stderr.strip() or f"osv-scanner exited with code {proc.returncode}"
                return AdapterResult(
                    scanner_name="OSV-Scanner",
                    version=self.get_version(),
                    success=False,
                    execution_time_seconds=elapsed,
                    error_message=err_msg,
                )

            report_data = json.loads(proc.stdout) if proc.stdout.strip() else {}
            findings, dependencies = self.parse_report(report_data, target_dir)

            return AdapterResult(
                scanner_name="OSV-Scanner",
                version=self.get_version(),
                findings=findings,
                dependencies=dependencies,
                raw_report=report_data,
                execution_time_seconds=elapsed,
                success=True,
            )
        except subprocess.TimeoutExpired:
            return AdapterResult(
                scanner_name="OSV-Scanner",
                version=self.get_version(),
                success=False,
                execution_time_seconds=float(timeout_seconds),
                error_message=f"OSV-Scanner timed out after {timeout_seconds} seconds.",
            )
        except Exception as exc:
            return AdapterResult(
                scanner_name="OSV-Scanner",
                version=self.get_version(),
                success=False,
                execution_time_seconds=time.time() - start_time,
                error_message=str(exc),
            )

    def parse_report(
        self, report: Dict[str, Any], base_dir: str
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        findings: List[Dict[str, Any]] = []
        dependencies: List[Dict[str, Any]] = []
        dep_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
        f_idx = 1

        results = report.get("results", []) or []
        if not isinstance(results, list):
            return findings, dependencies

        for result in results:
            source_info = result.get("source") or {}
            target_file = str(source_info.get("path", "lockfile"))
            rel_target = (
                os.path.relpath(target_file, base_dir)
                if target_file.startswith(base_dir)
                else target_file
            )
            rel_target = rel_target.replace("\\", "/").lstrip("./")

            for pkg_entry in result.get("packages", []) or []:
                pkg_info = pkg_entry.get("package") or {}
                pkg_name = str(pkg_info.get("name", "")).strip()
                pkg_ver = str(pkg_info.get("version", "unknown")).strip()
                eco = _map_ecosystem(str(pkg_info.get("ecosystem", "")))
                if not pkg_name:
                    continue

                dep_key = (pkg_name.lower(), eco)
                if dep_key not in dep_map:
                    dep_record = {
                        "package_name": pkg_name,
                        "version": pkg_ver,
                        "ecosystem": eco,
                        "vulnerability_id": "None",
                        "severity": "NONE",
                        "fixed_version": "-",
                        "reviewer_status": "SUPPORTED",
                        "last_release_date": "Pending registry check",
                        "maintainer_status": "Active",
                        "publisher_identity": "Verified Package Registry",
                        "alternative_package": "-",
                        "malicious_risk": "Known Safe / Standard",
                        "reviewer_notes": f"Discovered via OSV-Scanner in {rel_target}.",
                    }
                    dep_map[dep_key] = dep_record
                    dependencies.append(dep_record)
                else:
                    dep_record = dep_map[dep_key]

                # Map group max_severity by advisory ID if provided
                group_sev_by_id: Dict[str, str] = {}
                for grp in pkg_entry.get("groups", []) or []:
                    max_s = _cvss_to_severity(grp.get("max_severity"))
                    for gid in grp.get("ids", []) or []:
                        if max_s:
                            group_sev_by_id[str(gid)] = max_s

                for vuln in pkg_entry.get("vulnerabilities", []) or []:
                    vuln_id = str(vuln.get("id", "OSV-UNKNOWN"))
                    aliases = [str(a) for a in (vuln.get("aliases") or [])]
                    all_ids = [vuln_id] + aliases
                    is_malicious = any(vid.upper().startswith("MAL-") for vid in all_ids)

                    db_spec = vuln.get("database_specific") or {}
                    raw_sev = str(db_spec.get("severity") or "").upper()
                    sev = raw_sev if raw_sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else ""
                    if not sev:
                        sev = group_sev_by_id.get(vuln_id, "")
                    if is_malicious:
                        sev = "CRITICAL"
                    if not sev:
                        sev = "HIGH" if vuln_id.startswith("GHSA-") else "MEDIUM"

                    fixed_ver = _extract_fixed_version(vuln)
                    summary = str(vuln.get("summary") or "").strip()
                    details = str(vuln.get("details") or summary or f"OSV advisory {vuln_id} affecting {pkg_name}.").strip()

                    if is_malicious:
                        title = f"OpenSSF Malicious Package Detected: {pkg_name} ({vuln_id})"
                        recommendation = (
                            f"IMMEDIATELY REMOVE '{pkg_name}' ({pkg_ver}). "
                            f"Advisory {vuln_id} identifies this package as confirmed malicious software in OpenSSF Malicious Packages."
                        )
                    else:
                        title = summary or f"{vuln_id} in {pkg_name} ({pkg_ver})"
                        recommendation = (
                            f"Upgrade {pkg_name} from {pkg_ver} to fixed version {fixed_ver}."
                            if fixed_ver != "-"
                            else f"Review advisory {vuln_id} and mitigate or replace {pkg_name}."
                        )

                    findings.append(
                        {
                            "finding_code": f"OSV-{f_idx:03d}",
                            "scanner": "OSV-Scanner",
                            "finding_type": "malicious_package" if is_malicious else "vuln",
                            "severity": sev,
                            "title": title[:255],
                            "description": details[:2000],
                            "file_path": rel_target,
                            "line_number": 1,
                            "package_name": pkg_name,
                            "installed_version": pkg_ver,
                            "fixed_version": fixed_ver,
                            "vulnerability_id": vuln_id,
                            "redacted_value": "",
                            "recommendation": recommendation,
                            "status": "Open",
                        }
                    )
                    f_idx += 1

                    # Escalate dependency record
                    if is_malicious:
                        dep_record["malicious_risk"] = "Potentially Malicious Package"
                        dep_record["severity"] = "CRITICAL"
                        dep_record["vulnerability_id"] = vuln_id
                        dep_record["reviewer_notes"] = f"Flagged as {vuln_id} by OSV-Scanner OpenSSF Malicious Packages."
                    elif dep_record["malicious_risk"] != "Potentially Malicious Package":
                        dep_record["malicious_risk"] = "Known Vulnerable Package"
                        if dep_record["vulnerability_id"] == "None":
                            dep_record["vulnerability_id"] = vuln_id
                            dep_record["severity"] = sev
                            dep_record["fixed_version"] = fixed_ver

        return findings, dependencies

