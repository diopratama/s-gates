import csv
import hashlib
import io
import os
import posixpath
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List


SUSPICIOUS_PATH_PATTERNS = [
    r"(^|/|\\)\.\.(/|\\|$)",  # Path traversal ..
    r"^[a-zA-Z]:",  # Windows drive letter e.g. C:\
    r"^(/|\\)",  # Absolute root path
    r"windows/system32",  # PRD Section 11 explicit example
    r"winnt/system32",
    r"etc/passwd",
    r"etc/shadow",
    r"\.ssh/authorized_keys",
    r"start menu/programs/startup",
]


@dataclass
class ZipValidationResult:
    valid: bool
    sha256_hash: str
    zip_size_bytes: int
    expanded_size_bytes: int
    file_count: int
    errors: List[str] = field(default_factory=list)
    file_inventory: List[Dict[str, Any]] = field(default_factory=list)
    csv_content: str = ""
    extracted_files: Dict[str, bytes] = field(default_factory=dict)
    sandbox_indicators: List[str] = field(default_factory=list)


def validate_and_extract_zip(
    zip_bytes: bytes,
    filename: str,
    max_zip_size_mb: int = 500,
    max_expanded_size_mb: int = 5120,
    max_file_count: int = 50000,
) -> ZipValidationResult:
    """
    PRD Section 11: ZIP Security Controls.
    Before extraction S-Gates SHALL validate:
    - File extension
    - ZIP structure
    - Number of files
    - Expanded archive size
    - Path traversal attempts (e.g. ../../Windows/System32/example.exe)
    - Absolute paths
    - Nested suspicious locations
    """
    sha256_hash = hashlib.sha256(zip_bytes).hexdigest()
    zip_size_bytes = len(zip_bytes)
    errors: List[str] = []

    if not filename.lower().endswith(".zip"):
        errors.append(
            f"Invalid file extension for '{filename}'. Only .zip packages are accepted."
        )

    max_zip_bytes = max_zip_size_mb * 1024 * 1024
    if zip_size_bytes > max_zip_bytes:
        errors.append(
            f"ZIP archive size ({zip_size_bytes:,} bytes) exceeds maximum limit of {max_zip_size_mb} MB."
        )

    if zip_size_bytes == 0:
        errors.append("Uploaded ZIP archive is empty (0 bytes).")
        return ZipValidationResult(
            valid=False,
            sha256_hash=sha256_hash,
            zip_size_bytes=0,
            expanded_size_bytes=0,
            file_count=0,
            errors=errors,
        )

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    except zipfile.BadZipFile:
        errors.append(
            "Invalid or corrupted ZIP archive structure (failed magic bytes / central directory check)."
        )
        return ZipValidationResult(
            valid=False,
            sha256_hash=sha256_hash,
            zip_size_bytes=zip_size_bytes,
            expanded_size_bytes=0,
            file_count=0,
            errors=errors,
        )

    infos = [info for info in zf.infolist() if not info.is_dir()]
    file_count = len(infos)
    if file_count == 0:
        errors.append("ZIP archive contains no source files (missing source code).")

    if file_count > max_file_count:
        errors.append(
            f"Archive file count ({file_count:,}) exceeds maximum limit of {max_file_count:,} files."
        )

    expanded_size_bytes = sum(info.file_size for info in infos)
    max_expanded_bytes = max_expanded_size_mb * 1024 * 1024
    if expanded_size_bytes > max_expanded_bytes:
        errors.append(
            f"Expanded archive size ({expanded_size_bytes:,} bytes) exceeds maximum limit of {max_expanded_size_mb} MB."
        )

    # Check compression ratio for ZIP bomb protection
    if zip_size_bytes > 0 and expanded_size_bytes > 50 * 1024 * 1024:
        ratio = expanded_size_bytes / max(zip_size_bytes, 1)
        if ratio > 150:
            errors.append(
                f"Suspicious compression ratio ({ratio:.1f}x) detected — potential ZIP bomb rejected."
            )

    # Inspect every entry path BEFORE extracting any bytes
    for info in infos:
        raw_name = info.filename
        norm_check = raw_name.replace("\\", "/")

        # Check traversal / absolute / suspicious system locations
        parts = norm_check.split("/")
        if ".." in parts or raw_name.startswith("/") or raw_name.startswith("\\"):
            errors.append(
                f"Path traversal or absolute path attempt rejected: '{raw_name}'"
            )
            continue

        for pat in SUSPICIOUS_PATH_PATTERNS:
            if re.search(pat, norm_check, re.IGNORECASE):
                errors.append(
                    f"Unsafe or suspicious archive entry path rejected: '{raw_name}'"
                )
                break

        # Check symlink bit in UNIX external_attr
        is_symlink = (info.external_attr >> 16) & 0o170000 == 0o120000
        if is_symlink:
            errors.append(
                f"Symbolic link entry inside archive rejected for security: '{raw_name}'"
            )

    if errors:
        zf.close()
        return ZipValidationResult(
            valid=False,
            sha256_hash=sha256_hash,
            zip_size_bytes=zip_size_bytes,
            expanded_size_bytes=expanded_size_bytes,
            file_count=file_count,
            errors=errors,
        )

    # Safe in-memory extraction + File Inventory construction (PRD Section 10 & 24)
    inventory_rows: List[Dict[str, Any]] = []
    extracted_files: Dict[str, bytes] = {}
    sandbox_indicators: List[str] = []

    csv_buffer = io.StringIO()
    csv_writer = csv.writer(csv_buffer)
    csv_writer.writerow(
        ["File Path", "Extension", "Size (Bytes)", "SHA-256", "Category", "Sandbox Flag"]
    )

    for info in infos:
        clean_path = posixpath.normpath(info.filename.replace("\\", "/")).lstrip("/")
        data = zf.read(info.filename)
        extracted_files[clean_path] = data
        file_sha = hashlib.sha256(data).hexdigest()
        _, ext = os.path.splitext(clean_path.lower())

        category = "Source Code"
        sandbox_flag = "No"
        if ext in {".exe", ".msi", ".dll", ".sys", ".scr", ".com"}:
            category = "Executable / BinaryInstaller"
            sandbox_flag = "Yes (Binary Present)"
            if ext == ".exe":
                sandbox_indicators.append(f"Executable binary (.exe) detected: {clean_path}")
            elif ext == ".msi":
                sandbox_indicators.append(f"Windows Installer (.msi) detected: {clean_path}")
            else:
                sandbox_indicators.append(f"Compiled binary ({ext}) detected: {clean_path}")
        elif ext in {".ps1", ".bat", ".cmd", ".vbs", ".wsf", ".reg"}:
            category = "Automation / Host Script"
        elif os.path.basename(clean_path.lower()) in {
            "package.json",
            "package-lock.json",
            "requirements.txt",
            "pipfile",
            "pyproject.toml",
            "go.mod",
            "pom.xml",
            "dockerfile",
        } or ext in {".csproj", ".sln"}:
            category = "Dependency / Build Manifest"
        elif ext in {".json", ".yaml", ".yml", ".toml", ".ini", ".env", ".config"}:
            category = "Configuration"

        row_dict = {
            "path": clean_path,
            "extension": ext or "none",
            "size_bytes": len(data),
            "sha256": file_sha,
            "category": category,
            "sandbox_flag": sandbox_flag,
        }
        inventory_rows.append(row_dict)
        csv_writer.writerow(
            [clean_path, ext or "none", len(data), file_sha, category, sandbox_flag]
        )

    zf.close()
    return ZipValidationResult(
        valid=True,
        sha256_hash=sha256_hash,
        zip_size_bytes=zip_size_bytes,
        expanded_size_bytes=expanded_size_bytes,
        file_count=file_count,
        errors=[],
        file_inventory=inventory_rows,
        csv_content=csv_buffer.getvalue(),
        extracted_files=extracted_files,
        sandbox_indicators=sandbox_indicators,
    )

