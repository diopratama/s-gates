import json
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import tomllib  # Python 3.11+ stdlib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore

_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_PINNED_VER_RE = re.compile(r"==\s*([A-Za-z0-9._+-]+)")


class TTLCache:
    """Thread-safe in-memory TTL cache for supply-chain & registry lookups."""

    def __init__(self, ttl_seconds: int = 21600):
        self.ttl_seconds = ttl_seconds
        self._store: Dict[Any, Tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: Any) -> Optional[Any]:
        now = time.time()
        with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            expires_at, value = item
            if now > expires_at:
                del self._store[key]
                return None
            return value

    def set(self, key: Any, value: Any) -> None:
        expires_at = time.time() + self.ttl_seconds
        with self._lock:
            self._store[key] = (expires_at, value)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


def _parse_req_line(line: str) -> Optional[Tuple[str, str]]:
    clean = line.split("#", 1)[0].strip()
    if not clean or clean.startswith(("-", "--", "git+", "http://", "https://")):
        return None
    clean = clean.split(";", 1)[0].strip()
    match = _REQ_NAME_RE.match(clean)
    if not match:
        return None
    name = match.group(1).strip()
    pin_match = _PINNED_VER_RE.search(clean)
    version = pin_match.group(1) if pin_match else ""
    return name, version


def extract_direct_manifest_packages(target_dir: str, max_packages: int = 40) -> List[Dict[str, str]]:
    """
    Walks target_dir to extract direct third-party PyPI and npm packages from:
    - requirements*.txt
    - pyproject.toml
    - package.json
    Skips node_modules/.venv/.git directories.
    Returns list of {"package_name": str, "version": str, "ecosystem": "pip"|"npm", "file_path": str}.
    """
    packages: List[Dict[str, str]] = []
    seen = set()

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [
            d for d in sorted(dirs)
            if d not in {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build"}
        ]
        for fname in sorted(files):
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, target_dir).replace("\\", "/")
            lower_name = fname.lower()

            if lower_name.endswith(".txt") and "requirement" in lower_name:
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            parsed = _parse_req_line(line)
                            if parsed:
                                pkg_name, pkg_ver = parsed
                                key = ("pip", pkg_name.lower())
                                if key not in seen:
                                    seen.add(key)
                                    packages.append({
                                        "package_name": pkg_name,
                                        "version": pkg_ver or "latest",
                                        "ecosystem": "pip",
                                        "file_path": rel_path,
                                    })
                except OSError:
                    continue

            elif lower_name == "pyproject.toml" and tomllib is not None:
                try:
                    with open(full_path, "rb") as f:
                        data = tomllib.load(f)
                    deps = (data.get("project") or {}).get("dependencies") or []
                    for dep_str in deps:
                        if isinstance(dep_str, str):
                            parsed = _parse_req_line(dep_str)
                            if parsed:
                                pkg_name, pkg_ver = parsed
                                key = ("pip", pkg_name.lower())
                                if key not in seen:
                                    seen.add(key)
                                    packages.append({
                                        "package_name": pkg_name,
                                        "version": pkg_ver or "latest",
                                        "ecosystem": "pip",
                                        "file_path": rel_path,
                                    })
                except Exception:
                    continue

            elif lower_name == "package.json":
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                    for section in ("dependencies", "devDependencies"):
                        dep_dict = data.get(section) or {}
                        if not isinstance(dep_dict, dict):
                            continue
                        for pkg_name, raw_ver in dep_dict.items():
                            ver_str = str(raw_ver or "").strip()
                            if ver_str.startswith(("file:", "workspace:", "git+", "http://", "https://")):
                                continue
                            clean_ver = ver_str.lstrip("^~>=<v ").split()[0] if ver_str else "latest"
                            key = ("npm", pkg_name.lower())
                            if key not in seen:
                                seen.add(key)
                                packages.append({
                                    "package_name": pkg_name,
                                    "version": clean_ver or "latest",
                                    "ecosystem": "npm",
                                    "file_path": rel_path,
                                })
                except Exception:
                    continue

            if len(packages) >= max_packages:
                return packages[:max_packages]

    return packages[:max_packages]

