from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen
from app.config import settings
from app.engine.adapters.manifest_parser import TTLCache

logger = logging.getLogger(__name__)

TOP_PYPI_PACKAGES = {
    "requests", "urllib3", "certifi", "charset-normalizer", "idna", "setuptools",
    "wheel", "pip", "numpy", "pandas", "scipy", "matplotlib", "scikit-learn",
    "torch", "tensorflow", "pillow", "pyyaml", "cryptography", "boto3", "botocore",
    "fastapi", "uvicorn", "starlette", "pydantic", "sqlalchemy", "flask", "django",
    "jinja2", "click", "pytest", "httpx", "aiohttp", "celery", "redis", "psycopg2",
    "psycopg2-binary", "pyjwt", "bcrypt", "passlib", "python-dotenv", "alembic",
    "beautifulsoup4", "lxml", "regex", "packaging", "typing-extensions", "attrs",
    "colorama", "tqdm", "rich", "typer", "openai", "anthropic", "langchain",
    "gunicorn", "werkzeug", "marshmallow", "grpcio", "protobuf", "requests-oauthlib",
}

TOP_NPM_PACKAGES = {
    "react", "react-dom", "next", "typescript", "axios", "lodash", "express",
    "chalk", "commander", "dotenv", "zod", "tailwindcss", "eslint", "prettier",
    "jest", "vitest", "webpack", "vite", "uuid", "moment", "dayjs", "date-fns",
    "mongoose", "prisma", "lucide-react", "jsonwebtoken", "bcryptjs", "cors",
    "helmet", "winston", "debug", "rxjs", "jquery", "underscore", "async",
    "bluebird", "yargs", "inquirer", "ora", "glob", "minimist", "semver",
    "cheerio", "puppeteer", "playwright", "stripe", "nodemon", "ts-node",
    "tsx", "autoprefixer", "postcss", "clsx", "tailwind-merge", "zustand",
}


def damerau_levenshtein(a: str, b: str) -> int:
    """Computes optimal string alignment (restricted Damerau-Levenshtein) edit distance."""
    la, lb = len(a), len(b)
    if a == b:
        return 0
    if la == 0:
        return lb
    if lb == 0:
        return la

    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j

    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,      # deletion
                d[i][j - 1] + 1,      # insertion
                d[i - 1][j - 1] + cost,  # substitution
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)  # transposition
    return d[la][lb]


def check_typosquatting(pkg_name: str, ecosystem: str) -> Optional[str]:
    """
    Checks if a PyPI or npm package name closely mimics a popular package without being it.
    Returns the mimicked target package name if suspected, else None.
    """
    norm = pkg_name.lower().strip()
    if ecosystem == "pip":
        norm = norm.replace("_", "-")
        top_set = TOP_PYPI_PACKAGES
    elif ecosystem == "npm":
        if norm.startswith("@"):
            # Scoped packages (@org/pkg) are rarely classic typosquats of unscoped names
            return None
        top_set = TOP_NPM_PACKAGES
    else:
        return None

    if norm in top_set or len(norm) < 4:
        return None

    max_dist = 1 if len(norm) < 7 else 2
    for target in top_set:
        if abs(len(norm) - len(target)) > max_dist:
            continue
        dist = damerau_levenshtein(norm, target)
        if 0 < dist <= max_dist:
            return target
    return None


def _parse_iso_date(raw_ts: str) -> Optional[datetime]:
    if not raw_ts:
        return None
    try:
        clean = raw_ts.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _classify_staleness(last_dt: Optional[datetime], is_deprecated: bool = False) -> Tuple[str, str]:
    if last_dt is None:
        if is_deprecated:
            return ("MAINTENANCE REVIEW", "Deprecated on Registry")
        return ("SUPPORTED", "Active Maintainers")

    age_days = (datetime.now(timezone.utc) - last_dt).days
    if age_days > 730:
        return ("ABANDONED", "Deprecated (> 2 yrs no release)" if is_deprecated else "Inactive (> 2 yrs since release)")
    if is_deprecated:
        return ("MAINTENANCE REVIEW", "Deprecated on Registry")
    if age_days > 365:
        return ("MAINTENANCE REVIEW", "Low Activity (> 1 yr since release)")
    return ("SUPPORTED", "Active Maintainers")


def _default_http_get_json(url: str, timeout: int) -> Optional[Dict[str, Any]]:
    req = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "S-Gates-Registry-Checker/1.0",
        },
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="ignore"))
    except HTTPError as exc:
        if exc.code == 404:
            return {"__not_found__": True}
        logger.warning(f"Registry HTTP error {exc.code} for {url}")
        return None
    except (URLError, TimeoutError, Exception) as exc:
        logger.warning(f"Registry network error for {url}: {exc}")
        return None


class RegistryMetadataChecker:
    """
    Lightweight HTTP client checking PyPI (pypi.org) and npm (registry.npmjs.org)
    to populate dependency metadata (last_release_date, maintainer_status,
    publisher_identity, reviewer_status) and detect typosquatting suspects.
    """

    def __init__(
        self,
        timeout_seconds: Optional[int] = None,
        cache_ttl_seconds: Optional[int] = None,
        http_get_json: Optional[Callable[[str, int], Optional[Dict[str, Any]]]] = None,
    ):
        self.timeout_seconds = timeout_seconds or settings.REGISTRY_HTTP_TIMEOUT_SECONDS
        self._cache = TTLCache(ttl_seconds=cache_ttl_seconds or settings.SUPPLY_CHAIN_CACHE_TTL_SECONDS)
        self._http_get_json = http_get_json or _default_http_get_json

    def check_package(self, pkg_name: str, ecosystem: str) -> Dict[str, Any]:
        norm_eco = "pip" if ecosystem.lower() in {"pip", "pypi", "python"} else ("npm" if ecosystem.lower() == "npm" else "")
        if not norm_eco or not pkg_name:
            return {}

        cache_key = (norm_eco, pkg_name.lower().strip())
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        typo_target = check_typosquatting(pkg_name, norm_eco)
        if norm_eco == "pip":
            url = f"https://pypi.org/pypi/{quote(pkg_name.strip(), safe='')}/json"
        else:
            url = f"https://registry.npmjs.org/{quote(pkg_name.strip(), safe='@')}"

        data = self._http_get_json(url, self.timeout_seconds)
        if data is None:
            # Outbound network unavailable/timeout — degrade gracefully
            result = {
                "package_name": pkg_name,
                "ecosystem": norm_eco,
                "network_error": True,
                "typosquat_target": typo_target,
            }
            if typo_target:
                result["malicious_risk"] = "Typosquatting Suspect"
                result["alternative_package"] = typo_target
            return result

        if data.get("__not_found__"):
            result = {
                "package_name": pkg_name,
                "ecosystem": norm_eco,
                "last_release_date": "Not found",
                "maintainer_status": "Unlisted Package",
                "publisher_identity": "Unknown",
                "reviewer_status": "UNKNOWN",
                "typosquat_target": typo_target,
                "malicious_risk": "Typosquatting Suspect" if typo_target else "Known Safe / Standard",
                "alternative_package": typo_target or "-",
            }
            self._cache.set(cache_key, result)
            return result

        if norm_eco == "pip":
            result = self._parse_pypi_json(pkg_name, data, typo_target)
        else:
            result = self._parse_npm_json(pkg_name, data, typo_target)

        self._cache.set(cache_key, result)
        return result

    def _parse_pypi_json(
        self, pkg_name: str, data: Dict[str, Any], typo_target: Optional[str]
    ) -> Dict[str, Any]:
        info = data.get("info") or {}
        latest_ver = str(info.get("version") or "")
        author = str(info.get("author") or info.get("maintainer") or "").strip()
        author_email = str(info.get("author_email") or info.get("maintainer_email") or "").strip()
        publisher = author or (author_email.split("<")[0].strip() if author_email else "PyPI Publisher")

        # Extract latest release timestamp
        last_ts = ""
        releases = data.get("releases") or {}
        if latest_ver and isinstance(releases.get(latest_ver), list) and releases[latest_ver]:
            last_ts = str(releases[latest_ver][-1].get("upload_time_iso_8601") or releases[latest_ver][-1].get("upload_time") or "")
        if not last_ts:
            urls = data.get("urls") or []
            if urls and isinstance(urls, list):
                last_ts = str(urls[-1].get("upload_time_iso_8601") or urls[-1].get("upload_time") or "")

        last_dt = _parse_iso_date(last_ts)
        last_date_str = last_dt.strftime("%Y-%m-%d") if last_dt else "Unknown"

        classifiers = [str(c) for c in (info.get("classifiers") or [])]
        is_inactive = any("Development Status :: 7 - Inactive" in c for c in classifiers)
        reviewer_status, maintainer_status = _classify_staleness(last_dt, is_deprecated=is_inactive)
        if is_inactive and reviewer_status == "SUPPORTED":
            reviewer_status = "ABANDONED"
            maintainer_status = "Marked Inactive on PyPI"

        return {
            "package_name": pkg_name,
            "ecosystem": "pip",
            "latest_version": latest_ver,
            "last_release_date": last_date_str,
            "maintainer_status": maintainer_status,
            "publisher_identity": publisher[:120] or "PyPI Publisher",
            "reviewer_status": reviewer_status,
            "typosquat_target": typo_target,
            "malicious_risk": "Typosquatting Suspect" if typo_target else "Known Safe / Standard",
            "alternative_package": typo_target or "-",
        }

    def _parse_npm_json(
        self, pkg_name: str, data: Dict[str, Any], typo_target: Optional[str]
    ) -> Dict[str, Any]:
        dist_tags = data.get("dist-tags") or {}
        latest_ver = str(dist_tags.get("latest") or "")
        time_map = data.get("time") or {}
        last_ts = str(time_map.get(latest_ver) or time_map.get("modified") or "")
        last_dt = _parse_iso_date(last_ts)
        last_date_str = last_dt.strftime("%Y-%m-%d") if last_dt else "Unknown"

        versions = data.get("versions") or {}
        latest_obj = versions.get(latest_ver) or {}
        is_deprecated = bool(latest_obj.get("deprecated") or data.get("deprecated"))

        maintainers = data.get("maintainers") or latest_obj.get("maintainers") or []
        publisher = ""
        if isinstance(maintainers, list) and maintainers and isinstance(maintainers[0], dict):
            publisher = str(maintainers[0].get("name") or maintainers[0].get("email") or "").strip()
        if not publisher and isinstance(data.get("author"), dict):
            publisher = str(data["author"].get("name") or "").strip()
        if not publisher:
            publisher = "npm Publisher"

        reviewer_status, maintainer_status = _classify_staleness(last_dt, is_deprecated=is_deprecated)

        return {
            "package_name": pkg_name,
            "ecosystem": "npm",
            "latest_version": latest_ver,
            "last_release_date": last_date_str,
            "maintainer_status": maintainer_status,
            "publisher_identity": publisher[:120],
            "reviewer_status": reviewer_status,
            "typosquat_target": typo_target,
            "malicious_risk": "Typosquatting Suspect" if typo_target else "Known Safe / Standard",
            "alternative_package": typo_target or "-",
        }

    def enrich_dependencies(
        self,
        dependencies: List[Dict[str, Any]],
        max_packages: int = 30,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
        """
        Enriches PyPI and npm dependency items concurrently with live registry metadata.
        Returns (updated_dependencies, registry_findings, warnings).
        """
        targets: List[Dict[str, Any]] = []
        seen = set()
        for dep in dependencies:
            eco = str(dep.get("ecosystem", "")).lower()
            if eco not in {"pip", "pypi", "python", "npm"}:
                continue
            key = (dep["package_name"].lower(), "pip" if eco != "npm" else "npm")
            if key not in seen:
                seen.add(key)
                targets.append(dep)
            if len(targets) >= max_packages:
                break

        if not targets:
            return dependencies, [], []

        metadata_by_key: Dict[Tuple[str, str], Dict[str, Any]] = {}
        warnings: List[str] = []
        with ThreadPoolExecutor(max_workers=min(8, len(targets))) as executor:
            futures = {
                executor.submit(self.check_package, d["package_name"], d["ecosystem"]): d
                for d in targets
            }
            for fut in as_completed(futures):
                d = futures[fut]
                eco_norm = "pip" if str(d["ecosystem"]).lower() != "npm" else "npm"
                try:
                    res = fut.result()
                    if res:
                        metadata_by_key[(d["package_name"].lower(), eco_norm)] = res
                        if res.get("network_error"):
                            warnings.append(f"Registry timeout/unreachable for {eco_norm}:{d['package_name']}")
                except Exception as exc:
                    warnings.append(f"Metadata check error for {d['package_name']}: {exc}")

        findings: List[Dict[str, Any]] = []
        f_idx = 1
        for dep in dependencies:
            eco = str(dep.get("ecosystem", "")).lower()
            if eco not in {"pip", "pypi", "python", "npm"}:
                continue
            eco_norm = "pip" if eco != "npm" else "npm"
            meta = metadata_by_key.get((dep["package_name"].lower(), eco_norm))
            if not meta:
                continue

            if not meta.get("network_error"):
                dep["last_release_date"] = meta.get("last_release_date") or dep.get("last_release_date", "Unknown")
                dep["maintainer_status"] = meta.get("maintainer_status") or dep.get("maintainer_status", "Active")
                dep["publisher_identity"] = meta.get("publisher_identity") or dep.get("publisher_identity", "Verified Registry")
                dep["reviewer_status"] = meta.get("reviewer_status") or dep.get("reviewer_status", "SUPPORTED")

            typo_target = meta.get("typosquat_target")
            if typo_target:
                # Never downgrade an existing Potentially Malicious Package or Suspicious Install Script
                if dep.get("malicious_risk") not in {"Potentially Malicious Package", "Suspicious Install Script"}:
                    dep["malicious_risk"] = "Typosquatting Suspect"
                dep["alternative_package"] = typo_target
                findings.append(
                    {
                        "finding_code": f"REG-TYPO-{f_idx:03d}",
                        "scanner": "RegistryMetadata",
                        "finding_type": "malicious_package",
                        "severity": "CRITICAL",
                        "title": f"Typosquatting Suspect: '{dep['package_name']}' resembles '{typo_target}'",
                        "description": (
                            f"Package '{dep['package_name']}' ({eco_norm}) has close edit distance to popular package '{typo_target}'. "
                            f"Verify this is not an accidental typo or supply-chain typosquatting attack."
                        ),
                        "file_path": "manifest",
                        "line_number": 1,
                        "package_name": dep["package_name"],
                        "installed_version": dep.get("version", "latest"),
                        "fixed_version": typo_target,
                        "vulnerability_id": "TYPOSQUAT-SUSPECT",
                        "redacted_value": "",
                        "recommendation": f"Verify package name; replace '{dep['package_name']}' with official '{typo_target}' if unintended.",
                        "status": "Open",
                    }
                )
                f_idx += 1

        return dependencies, findings, warnings
