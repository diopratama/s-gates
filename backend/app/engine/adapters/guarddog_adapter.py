from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple
from app.config import settings
from app.engine.adapters.base import AdapterResult, BaseScannerAdapter
from app.engine.adapters.manifest_parser import TTLCache, extract_direct_manifest_packages

logger = logging.getLogger(__name__)

_EXACT_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9A-Za-z._-]+)+$")

_INSTALL_SCRIPT_RULES = {
    "cmd-overwrite",
    "npm-install-script",
    "silent-process-execution",
    "npm-silent-process-execution",
}

_MALICIOUS_BEHAVIOR_RULES = {
    "code-execution",
    "exec-base64",
    "npm-exec-base64",
    "exfiltrate-sensitive-data",
    "npm-exfiltrate-sensitive-data",
    "npm-serialize-environment",
    "download-executable",
    "steganography",
    "obfuscation",
    "npm-obfuscation",
    "dll-hijacking",
    "npm-dll-hijacking",
    "clipboard-access",
}

_HIGH_HEURISTIC_RULES = {
    "shady-links",
    "potentially_compromised_email_domain",
    "unclaimed_maintainer_email_domain",
    "deceptive_author",
}


class GuardDogAdapter(BaseScannerAdapter):
    """
    Adapter for Datadog GuardDog (Apache-2.0).
    Analyzes direct PyPI and npm manifest dependencies for supply-chain malware,
    malicious setup.py/postinstall scripts, env exfiltration, and hidden payloads.
    Uses a 6-hour in-memory TTL cache and a configurable per-scan package cap.
    """

    def __init__(
        self,
        binary_path: str = "guarddog",
        max_packages: Optional[int] = None,
        cache_ttl_seconds: Optional[int] = None,
    ):
        self.binary_path = binary_path
        self.max_packages = max_packages or settings.GUARDDOG_MAX_PACKAGES
        self._resolved_path: Optional[str] = None
        self._cache = TTLCache(ttl_seconds=cache_ttl_seconds or settings.SUPPLY_CHAIN_CACHE_TTL_SECONDS)

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
            return output.splitlines()[0] if output else "guarddog-installed"
        except Exception as exc:
            logger.warning(f"Failed to query GuardDog version: {exc}")
            return "unknown"

    def _scan_single_package(
        self, bin_path: str, ecosystem: str, pkg_name: str, pkg_ver: str, timeout_seconds: int
    ) -> Dict[str, Any]:
        gd_eco = "pypi" if ecosystem == "pip" else "npm"
        ver_key = pkg_ver if _EXACT_VERSION_RE.match(pkg_ver or "") else "latest"
        cache_key = (gd_eco, pkg_name.lower(), ver_key)

        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        cmd = [bin_path, gd_eco, "scan", pkg_name, "--output-format", "json"]
        if ver_key != "latest":
            cmd.extend(["--version", ver_key])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=min(timeout_seconds, 45),
                check=False,
            )
            if not proc.stdout.strip():
                return {
                    "package": pkg_name,
                    "ecosystem": ecosystem,
                    "version": pkg_ver,
                    "results": {},
                    "warning": proc.stderr.strip() or f"GuardDog returned empty output for {pkg_name}.",
                }
            parsed = json.loads(proc.stdout)
            payload = {
                "package": pkg_name,
                "ecosystem": ecosystem,
                "version": pkg_ver,
                "issues": parsed.get("issues", 0),
                "results": parsed.get("results") or {},
                "errors": parsed.get("errors") or {},
            }
            if not payload["errors"]:
                self._cache.set(cache_key, payload)
            return payload
        except subprocess.TimeoutExpired:
            return {
                "package": pkg_name,
                "ecosystem": ecosystem,
                "version": pkg_ver,
                "results": {},
                "warning": f"GuardDog scan timed out for {gd_eco}:{pkg_name}.",
            }
        except Exception as exc:
            return {
                "package": pkg_name,
                "ecosystem": ecosystem,
                "version": pkg_ver,
                "results": {},
                "warning": f"GuardDog error for {gd_eco}:{pkg_name}: {exc}",
            }

    def scan(
        self,
        target_dir: str,
        timeout_seconds: int = 60,
        packages_override: Optional[List[Dict[str, str]]] = None,
    ) -> AdapterResult:
        bin_path = self._get_bin()
        if not bin_path:
            return AdapterResult(
                scanner_name="GuardDog",
                version="not-installed",
                success=False,
                error_message="guarddog executable was not found on system PATH.",
            )

        start_time = time.time()
        direct_pkgs = packages_override if packages_override is not None else extract_direct_manifest_packages(
            target_dir, max_packages=self.max_packages
        )
        direct_pkgs = [p for p in direct_pkgs if p.get("ecosystem") in {"pip", "npm"}][: self.max_packages]

        if not direct_pkgs:
            return AdapterResult(
                scanner_name="GuardDog",
                version=self.get_version(),
                findings=[],
                dependencies=[],
                raw_report={"packages_scanned": 0, "results": []},
                execution_time_seconds=time.time() - start_time,
                success=True,
            )

        pkg_reports: List[Dict[str, Any]] = []
        warnings: List[str] = []
        with ThreadPoolExecutor(max_workers=min(5, len(direct_pkgs))) as executor:
            futures = {
                executor.submit(
                    self._scan_single_package,
                    bin_path,
                    p["ecosystem"],
                    p["package_name"],
                    p.get("version", "latest"),
                    timeout_seconds,
                ): p
                for p in direct_pkgs
            }
            for fut in as_completed(futures):
                p = futures[fut]
                try:
                    res = fut.result()
                    res["file_path"] = p.get("file_path", "manifest")
                    if res.get("warning"):
                        warnings.append(res["warning"])
                    pkg_reports.append(res)
                except Exception as exc:
                    warnings.append(f"{p['package_name']}: {exc}")

        findings, dependencies = self.parse_reports(pkg_reports)
        elapsed = time.time() - start_time

        return AdapterResult(
            scanner_name="GuardDog",
            version=self.get_version(),
            findings=findings,
            dependencies=dependencies,
            raw_report={
                "packages_scanned": len(direct_pkgs),
                "warnings": warnings,
                "results": pkg_reports,
            },
            execution_time_seconds=elapsed,
            success=True,
            error_message="; ".join(warnings[:3]) if warnings else None,
        )

    def parse_reports(
        self, pkg_reports: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        findings: List[Dict[str, Any]] = []
        dependencies: List[Dict[str, Any]] = []
        f_idx = 1

        for pkg_res in pkg_reports:
            pkg_name = str(pkg_res.get("package", "")).strip()
            pkg_ver = str(pkg_res.get("version", "latest")).strip()
            eco = str(pkg_res.get("ecosystem", "pip"))
            file_path = str(pkg_res.get("file_path", "manifest"))
            results_map = pkg_res.get("results") or {}
            if not isinstance(results_map, dict) or not pkg_name:
                continue

            dep_risk = "Known Safe / Standard"
            dep_sev = "NONE"
            dep_vuln_id = "None"
            triggered_rules: List[str] = []

            for rule_name, rule_hits in results_map.items():
                if not rule_hits:
                    continue
                if isinstance(rule_hits, str):
                    hit_list = [{"message": rule_hits, "location": file_path}]
                elif isinstance(rule_hits, list):
                    hit_list = rule_hits
                else:
                    continue

                rule_lower = rule_name.lower()
                if rule_lower in _INSTALL_SCRIPT_RULES:
                    sev = "CRITICAL"
                    dep_risk = "Suspicious Install Script"
                elif rule_lower in _MALICIOUS_BEHAVIOR_RULES:
                    sev = "CRITICAL"
                    if dep_risk != "Suspicious Install Script":
                        dep_risk = "Potentially Malicious Package"
                elif "typosquat" in rule_lower:
                    sev = "CRITICAL"
                    dep_risk = "Typosquatting Suspect"
                elif rule_lower in _HIGH_HEURISTIC_RULES:
                    sev = "HIGH"
                else:
                    sev = "LOW"

                if sev in {"CRITICAL", "HIGH"}:
                    triggered_rules.append(rule_name)
                    if dep_vuln_id == "None":
                        dep_vuln_id = f"GD-{rule_name}"
                        dep_sev = sev

                # Emit consolidated finding per triggered rule on the package
                first_hit = hit_list[0] if isinstance(hit_list[0], dict) else {}
                location = str(first_hit.get("location") or file_path)
                detail_msg = str(
                    first_hit.get("message")
                    or first_hit.get("code")
                    or f"GuardDog heuristic '{rule_name}' matched ({len(hit_list)} occurrence(s))."
                )

                # Skip low-signal informational noise from creating noisy findings unless relevant
                if sev == "LOW":
                    continue

                findings.append(
                    {
                        "finding_code": f"GD-{f_idx:03d}",
                        "scanner": "GuardDog",
                        "finding_type": "malicious_package" if sev == "CRITICAL" else "vuln",
                        "severity": sev,
                        "title": f"GuardDog ({rule_name}): {pkg_name} ({eco})",
                        "description": f"{detail_msg} [Location inside package: {location}; {len(hit_list)} match(es)]"[:2000],
                        "file_path": file_path,
                        "line_number": 1,
                        "package_name": pkg_name,
                        "installed_version": pkg_ver,
                        "fixed_version": "-",
                        "vulnerability_id": f"GD-{rule_name}",
                        "redacted_value": "",
                        "recommendation": (
                            f"Inspect or remove '{pkg_name}' immediately; GuardDog detected {rule_name} supply-chain risk."
                            if sev == "CRITICAL"
                            else f"Review '{pkg_name}' source tarball for '{rule_name}' supply-chain indicator."
                        ),
                        "status": "Open",
                    }
                )
                f_idx += 1

            if dep_risk != "Known Safe / Standard" or triggered_rules:
                dependencies.append(
                    {
                        "package_name": pkg_name,
                        "version": pkg_ver,
                        "ecosystem": eco,
                        "vulnerability_id": dep_vuln_id,
                        "severity": dep_sev,
                        "fixed_version": "-",
                        "reviewer_status": "SUPPORTED",
                        "last_release_date": "Checked via GuardDog",
                        "maintainer_status": "Flagged by GuardDog" if triggered_rules else "Active",
                        "publisher_identity": "PyPI" if eco == "pip" else "npm Registry",
                        "alternative_package": "-",
                        "malicious_risk": dep_risk,
                        "reviewer_notes": f"GuardDog supply-chain checks matched: {', '.join(triggered_rules)}.",
                    }
                )

        return findings, dependencies

