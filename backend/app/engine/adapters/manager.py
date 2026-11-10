from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import os
import shutil
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple
from app.config import settings
from app.engine.adapters.base import AdapterResult
from app.engine.adapters.gitleaks_adapter import GitleaksAdapter
from app.engine.adapters.guarddog_adapter import GuardDogAdapter
from app.engine.adapters.manifest_parser import extract_direct_manifest_packages
from app.engine.adapters.osv_adapter import OsvScannerAdapter
from app.engine.adapters.registry_checker import RegistryMetadataChecker
from app.engine.adapters.semgrep_adapter import SemgrepAdapter
from app.engine.adapters.trivy_adapter import TrivyAdapter
from app.engine.scanners import run_security_scanners as run_heuristic_scanners

logger = logging.getLogger(__name__)
LogCallback = Optional[Callable[[str, str, str], None]]

_RISK_PRIORITY = {
    "Known Safe / Standard": 0,
    "Known Vulnerable Package": 1,
    "Typosquatting Suspect": 2,
    "Suspicious Install Script": 3,
    "Potentially Malicious Package": 4,
}


def _norm_ecosystem(eco: str) -> str:
    low = (eco or "").lower().strip()
    if low in {"pip", "pypi", "python", "poetry", "pipenv"}:
        return "pip"
    if low in {"npm", "yarn", "pnpm", "node"}:
        return "npm"
    return eco or "generic"


def _merge_dependency_lists(*lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    by_key: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for dep_list in lists:
        for item in dep_list:
            pkg_name = str(item.get("package_name") or "").strip()
            if not pkg_name:
                continue
            eco = _norm_ecosystem(str(item.get("ecosystem") or ""))
            key = (pkg_name.lower(), eco)
            if key not in by_key:
                copy_item = dict(item)
                copy_item["ecosystem"] = eco
                by_key[key] = copy_item
                merged.append(copy_item)
            else:
                existing = by_key[key]
                # Escalate vulnerability & malicious risk
                old_prio = _RISK_PRIORITY.get(existing.get("malicious_risk", ""), 0)
                new_prio = _RISK_PRIORITY.get(item.get("malicious_risk", ""), 0)
                if new_prio > old_prio:
                    existing["malicious_risk"] = item["malicious_risk"]
                if existing.get("vulnerability_id") in {"None", "-", ""} and item.get("vulnerability_id") not in {"None", "-", ""}:
                    existing["vulnerability_id"] = item["vulnerability_id"]
                    existing["severity"] = item.get("severity", existing["severity"])
                    existing["fixed_version"] = item.get("fixed_version", existing["fixed_version"])
                if existing.get("version") in {"latest", "unknown", ""} and item.get("version") not in {"latest", "unknown", ""}:
                    existing["version"] = item["version"]
                note = str(item.get("reviewer_notes") or "").strip()
                if note and note not in str(existing.get("reviewer_notes") or ""):
                    existing["reviewer_notes"] = f"{existing.get('reviewer_notes', '')} | {note}".strip(" |")
    return merged


class ScannerManager:
    """
    Orchestrates real security scanner adapters (Trivy, Gitleaks, Semgrep, OSV-Scanner,
    GuardDog) plus live PyPI/npm Registry Metadata Checker with isolated temp workspace
    execution and graceful fallback.
    """

    def __init__(
        self,
        trivy_bin: Optional[str] = None,
        gitleaks_bin: Optional[str] = None,
        semgrep_bin: Optional[str] = None,
        osv_bin: Optional[str] = None,
        guarddog_bin: Optional[str] = None,
        registry_checker: Optional[RegistryMetadataChecker] = None,
    ):
        self.trivy = TrivyAdapter(binary_path=trivy_bin or settings.TRIVY_BINARY_PATH)
        self.gitleaks = GitleaksAdapter(binary_path=gitleaks_bin or settings.GITLEAKS_BINARY_PATH)
        self.semgrep = SemgrepAdapter(binary_path=semgrep_bin or settings.SEMGREP_BINARY_PATH)
        self.osv = OsvScannerAdapter(binary_path=osv_bin or settings.OSV_SCANNER_BINARY_PATH)
        self.guarddog = GuardDogAdapter(binary_path=guarddog_bin or settings.GUARDDOG_BINARY_PATH)
        self.registry = registry_checker or RegistryMetadataChecker()

    def get_scanner_status(self) -> Dict[str, Any]:
        """Queries the host/container environment for installed scanner CLIs."""
        trivy_ok = self.trivy.is_available()
        gitleaks_ok = self.gitleaks.is_available()
        semgrep_ok = self.semgrep.is_available()
        osv_ok = self.osv.is_available()
        guarddog_ok = self.guarddog.is_available()

        core_ok = trivy_ok and gitleaks_ok and semgrep_ok
        all_ok = core_ok and osv_ok and guarddog_ok
        any_ok = trivy_ok or gitleaks_ok or semgrep_ok or osv_ok or guarddog_ok

        if core_ok:
            intel_status = "HEALTHY"
            scanner_mode = "external"
        elif any_ok:
            intel_status = "OUTDATED"
            scanner_mode = "external-degraded"
        else:
            intel_status = "UNAVAILABLE"
            scanner_mode = "heuristic-demo"

        return {
            "status": intel_status,
            "scanner_mode": scanner_mode,
            "trivy_db_available": trivy_ok,
            "trivy_version": self.trivy.get_version(),
            "gitleaks_version": self.gitleaks.get_version(),
            "semgrep_version": self.semgrep.get_version(),
            "osv_version": self.osv.get_version(),
            "guarddog_version": self.guarddog.get_version(),
            "osv_available": osv_ok,
            "guarddog_available": guarddog_ok,
            "core_available": core_ok,
            "all_available": all_ok,
        }

    def execute_scans(
        self,
        extracted_files: Dict[str, bytes],
        app_metadata: Dict[str, Any],
        zip_sandbox_indicators: List[str],
        timeout_seconds: Optional[int] = None,
        log_callback: LogCallback = None,
    ) -> Dict[str, Any]:
        """
        Executes real Trivy, Gitleaks, Semgrep, OSV-Scanner, GuardDog, and Registry
        Metadata Checker if available; falls back to heuristic demo rules when core
        scanner binaries are missing or mode is forced.
        """
        def emit(level: str, msg: str) -> None:
            if log_callback:
                log_callback(level, "SCANNERS", msg)

        mode_setting = settings.SCANNER_EXECUTION_MODE.lower()
        scanner_status = self.get_scanner_status()

        # Check if we should run external scanners
        should_run_external = (
            mode_setting == "external_only"
            or (mode_setting == "auto" and scanner_status["core_available"])
        )

        if not should_run_external:
            emit("WARN", "External scanner binaries unavailable in host environment; running local heuristic rules.")
            result = run_heuristic_scanners(
                extracted_files=extracted_files,
                app_metadata=app_metadata,
                zip_sandbox_indicators=zip_sandbox_indicators,
            )
            result["scanner_status"] = scanner_status
            return result

        timeout = timeout_seconds or settings.SCANNER_TIMEOUT_SECONDS

        # Create safe temporary directory on disk for external CLI scanners
        temp_dir = tempfile.mkdtemp(prefix="sgates_real_scan_")
        emit("INFO", f"Created isolated temporary scan workspace ({len(extracted_files)} files to materialize).")
        try:
            # Materialize extracted files to disk
            for rel_path, data in extracted_files.items():
                safe_rel = rel_path.replace("\\", "/").lstrip("/")
                dest_path = os.path.join(temp_dir, safe_rel)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                with open(dest_path, "wb") as f:
                    f.write(data)

            direct_manifest_pkgs = extract_direct_manifest_packages(
                temp_dir, max_packages=settings.GUARDDOG_MAX_PACKAGES
            )

            emit("SCAN", "Launching security & supply-chain scanners concurrently...")
            emit("CMD", f"trivy fs --scanners vuln,misconfig --format json <workspace> (v{scanner_status['trivy_version']})")
            emit("CMD", f"gitleaks dir <workspace> --report-format json --redact (v{scanner_status['gitleaks_version']})")
            emit("CMD", f"semgrep scan --config auto --json <workspace> (v{scanner_status['semgrep_version']})")
            if scanner_status["osv_available"]:
                emit("CMD", f"osv-scanner scan --format json -r <workspace> (v{scanner_status['osv_version']})")
            if scanner_status["guarddog_available"] and direct_manifest_pkgs:
                emit("CMD", f"guarddog <pypi|npm> scan ({len(direct_manifest_pkgs)} manifest package(s), 6h TTL cache)")

            # Execute filesystem + manifest scanners concurrently
            results: Dict[str, AdapterResult] = {}
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {
                    executor.submit(self.trivy.scan, temp_dir, timeout): "Trivy",
                    executor.submit(self.gitleaks.scan, temp_dir, timeout): "Gitleaks",
                    executor.submit(self.semgrep.scan, temp_dir, timeout): "Semgrep",
                }
                if scanner_status["osv_available"]:
                    futures[executor.submit(self.osv.scan, temp_dir, timeout)] = "OSV-Scanner"
                if scanner_status["guarddog_available"] and direct_manifest_pkgs:
                    futures[
                        executor.submit(
                            self.guarddog.scan,
                            temp_dir,
                            timeout,
                            direct_manifest_pkgs,
                        )
                    ] = "GuardDog"

                for fut in as_completed(futures):
                    scanner_name = futures[fut]
                    try:
                        res = fut.result()
                        results[scanner_name] = res
                        if res.success:
                            dep_note = f", {len(res.dependencies)} packages inventoried" if res.dependencies else ""
                            warn_note = f" (warnings: {res.error_message})" if res.error_message else ""
                            emit(
                                "WARN" if res.error_message else "OK",
                                f"{scanner_name} finished in {res.execution_time_seconds:.2f}s — {len(res.findings)} finding(s){dep_note}.{warn_note}",
                            )
                        else:
                            emit(
                                "WARN",
                                f"{scanner_name} returned non-fatal error after {res.execution_time_seconds:.2f}s: {res.error_message}",
                            )
                    except Exception as exc:
                        logger.error(f"Scanner {scanner_name} execution error: {exc}")
                        emit("WARN", f"{scanner_name} execution failed gracefully: {exc}")
                        results[scanner_name] = AdapterResult(
                            scanner_name=scanner_name,
                            version="error",
                            success=False,
                            error_message=str(exc),
                        )

            # Consolidate findings and dependencies
            all_findings: List[Dict[str, Any]] = []
            trivy_deps: List[Dict[str, Any]] = []
            osv_deps: List[Dict[str, Any]] = []
            gd_deps: List[Dict[str, Any]] = []
            sandbox_reasons: List[str] = list(zip_sandbox_indicators)

            for name in ("Trivy", "Gitleaks", "Semgrep", "OSV-Scanner", "GuardDog"):
                res = results.get(name)
                if res and res.success:
                    all_findings.extend(res.findings)
                    if res.dependencies:
                        if name == "Trivy":
                            trivy_deps.extend(res.dependencies)
                        elif name == "OSV-Scanner":
                            osv_deps.extend(res.dependencies)
                        elif name == "GuardDog":
                            gd_deps.extend(res.dependencies)
                elif res and not res.success:
                    logger.warning(f"{name} scan warning: {res.error_message}")

            manifest_baseline_deps = [
                {
                    "package_name": p["package_name"],
                    "version": p.get("version", "latest"),
                    "ecosystem": p["ecosystem"],
                    "vulnerability_id": "None",
                    "severity": "NONE",
                    "fixed_version": "-",
                    "reviewer_status": "SUPPORTED",
                    "last_release_date": "Checking registry...",
                    "maintainer_status": "Active",
                    "publisher_identity": "PyPI" if p["ecosystem"] == "pip" else "npm Registry",
                    "alternative_package": "-",
                    "malicious_risk": "Known Safe / Standard",
                    "reviewer_notes": f"Declared in {p.get('file_path', 'manifest')}.",
                }
                for p in direct_manifest_pkgs
            ]
            all_dependencies = _merge_dependency_lists(
                manifest_baseline_deps, trivy_deps, osv_deps, gd_deps
            )

            # Enrich PyPI & npm dependencies via live Registry Metadata Checker
            if all_dependencies:
                emit("SCAN", "Querying PyPI & npm registries for maintainer staleness & typosquatting...")
                all_dependencies, reg_findings, reg_warnings = self.registry.enrich_dependencies(all_dependencies)
                all_findings.extend(reg_findings)
                if reg_warnings:
                    emit("WARN", f"Registry metadata checks finished with {len(reg_warnings)} warning(s) (network/timeout).")
                else:
                    emit("OK", f"Enriched registry metadata for {len(all_dependencies)} package(s); {len(reg_findings)} typosquatting alert(s).")

            # Check sandbox triggers from real findings
            for f in all_findings:
                if f.get("severity") in {"CRITICAL", "HIGH"} and f.get("scanner") in {"Semgrep", "GuardDog", "OSV-Scanner"}:
                    if f.get("finding_type") == "malicious_package" or f.get("scanner") == "Semgrep":
                        sandbox_reasons.append(
                            f"High-severity finding ({f.get('title')}) requires behavioral verification."
                        )

            if app_metadata.get("requires_admin_privileges"):
                sandbox_reasons.append("Application requires Administrator privileges")
            if app_metadata.get("data_classification") in {
                "Confidential",
                "Restricted / Personal Data",
            }:
                sandbox_reasons.append(
                    f"Application processes {app_metadata.get('data_classification')} data"
                )

            dedup_sandbox_reasons = list(dict.fromkeys(sandbox_reasons))

            # Number the findings cleanly
            for idx, finding in enumerate(all_findings, start=1):
                finding["finding_code"] = f"SG-FND-{idx:03d}"

            # Calculate summaries
            trivy_summary = _summarize_scanner(all_findings, "Trivy")
            gitleaks_summary = {
                "secrets_detected": sum(1 for f in all_findings if f["scanner"] == "Gitleaks"),
                "critical": sum(
                    1 for f in all_findings if f["scanner"] == "Gitleaks" and f["severity"] == "CRITICAL"
                ),
                "redaction_enforced": True,
            }
            semgrep_summary = _summarize_scanner(all_findings, "Semgrep")

            raw_reports = {
                "trivy": results.get("Trivy").raw_report if results.get("Trivy") else {},
                "gitleaks": results.get("Gitleaks").raw_report if results.get("Gitleaks") else {},
                "semgrep": results.get("Semgrep").raw_report if results.get("Semgrep") else {},
                "osv": results.get("OSV-Scanner").raw_report if results.get("OSV-Scanner") else {},
                "guarddog": results.get("GuardDog").raw_report if results.get("GuardDog") else {},
            }

            return {
                "findings": all_findings,
                "dependencies": all_dependencies,
                "mode": "external",
                "trivy_summary": trivy_summary,
                "gitleaks_summary": gitleaks_summary,
                "semgrep_summary": semgrep_summary,
                "osv_summary": _summarize_scanner(all_findings, "OSV-Scanner"),
                "guarddog_summary": _summarize_scanner(all_findings, "GuardDog"),
                "sandbox_required": len(dedup_sandbox_reasons) > 0,
                "sandbox_reasons": dedup_sandbox_reasons,
                "scanner_status": scanner_status,
                "raw_reports": raw_reports,
            }
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            emit("INFO", "Cleaned up temporary scan workspace.")


def _summarize_scanner(findings: List[Dict[str, Any]], scanner_name: str) -> Dict[str, int]:
    scoped = [f for f in findings if f["scanner"] == scanner_name and f.get("status", "Open") == "Open"]
    return {
        "critical": sum(1 for f in scoped if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in scoped if f["severity"] == "HIGH"),
        "medium": sum(1 for f in scoped if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in scoped if f["severity"] == "LOW"),
        "total": len(scoped),
    }


# Singleton manager instance
default_scanner_manager = ScannerManager()

