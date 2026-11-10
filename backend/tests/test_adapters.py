import json
import pytest
from app.engine.adapters.base import AdapterResult
from app.engine.adapters.gitleaks_adapter import GitleaksAdapter, REDACTED_SECRET_MASK
from app.engine.adapters.manager import ScannerManager
from app.engine.adapters.semgrep_adapter import SemgrepAdapter
from app.engine.adapters.trivy_adapter import TrivyAdapter


def test_trivy_adapter_parsing_sample_report():
    adapter = TrivyAdapter(binary_path="nonexistent-trivy-bin")
    assert adapter.is_available() is False
    assert adapter.get_version() == "not-installed"

    sample_trivy_json = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "/tmp/scan/requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Packages": [
                    {"Name": "urllib3", "Version": "1.26.15"},
                    {"Name": "fastapi", "Version": "0.115.0"},
                ],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-45803",
                        "PkgName": "urllib3",
                        "InstalledVersion": "1.26.15",
                        "FixedVersion": "1.26.18",
                        "Severity": "HIGH",
                        "Title": "Request body not stripped after redirect in urllib3",
                        "Description": "Detailed CVE description here.",
                    }
                ],
            },
            {
                "Target": "/tmp/scan/Dockerfile",
                "Class": "config",
                "Type": "dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "AVD-DS-0002",
                        "Title": "Specify at least 1 USER command in Dockerfile",
                        "Description": "Container running as root",
                        "Severity": "MEDIUM",
                        "Resolution": "Add USER nonroot",
                    }
                ],
            },
        ],
    }

    findings, dependencies = adapter.parse_report(sample_trivy_json, base_dir="/tmp/scan")

    assert len(dependencies) == 2
    pkg_names = {d["package_name"] for d in dependencies}
    assert "urllib3" in pkg_names
    assert "fastapi" in pkg_names

    # Check that urllib3 was enriched with the vulnerability info
    urllib3_dep = next(d for d in dependencies if d["package_name"] == "urllib3")
    assert urllib3_dep["vulnerability_id"] == "CVE-2023-45803"
    assert urllib3_dep["severity"] == "HIGH"
    assert urllib3_dep["fixed_version"] == "1.26.18"

    assert len(findings) == 2
    f_vuln = next(f for f in findings if f["finding_type"] == "vuln")
    assert f_vuln["vulnerability_id"] == "CVE-2023-45803"
    assert f_vuln["severity"] == "HIGH"
    assert f_vuln["file_path"] == "requirements.txt"

    f_cfg = next(f for f in findings if f["finding_type"] == "misconfig")
    assert f_cfg["vulnerability_id"] == "AVD-DS-0002"
    assert f_cfg["severity"] == "MEDIUM"
    assert f_cfg["file_path"] == "Dockerfile"


def test_gitleaks_adapter_parsing_and_mandatory_redaction():
    adapter = GitleaksAdapter(binary_path="nonexistent-gitleaks-bin")
    assert adapter.is_available() is False
    assert adapter.get_version() == "not-installed"

    raw_secret = "AKIAIOSFODNN7EXAMPLE"
    sample_gitleaks_json = [
        {
            "Description": "AWS Access Key",
            "StartLine": 44,
            "EndLine": 44,
            "File": "/tmp/scan/config.py",
            "RuleID": "aws-access-key",
            "Secret": raw_secret,
            "Match": f'AWS_ACCESS_KEY_ID = "{raw_secret}"',
        }
    ]

    findings = adapter.parse_report(sample_gitleaks_json, base_dir="/tmp/scan")
    assert len(findings) == 1
    f = findings[0]
    assert f["scanner"] == "Gitleaks"
    assert f["finding_type"] == "secret"
    assert f["severity"] == "CRITICAL"
    assert f["line_number"] == 44
    assert f["file_path"] == "config.py"
    assert f["redacted_value"] == REDACTED_SECRET_MASK
    # Ensure raw secret is never present in description or values
    assert raw_secret not in f["description"]
    assert raw_secret not in f["redacted_value"]

    # Test raw report sanitizer
    sanitized = adapter._sanitize_raw_report(sample_gitleaks_json, base_dir="/tmp/scan")
    assert sanitized[0]["Secret"] == REDACTED_SECRET_MASK
    assert sanitized[0]["Match"] == REDACTED_SECRET_MASK
    assert raw_secret not in json.dumps(sanitized)


def test_semgrep_adapter_parsing():
    adapter = SemgrepAdapter(binary_path="nonexistent-semgrep-bin")
    assert adapter.is_available() is False
    assert adapter.get_version() == "not-installed"

    sample_semgrep_json = {
        "results": [
            {
                "check_id": "python.lang.security.audit.subprocess-shell-true",
                "path": "/tmp/scan/processor.py",
                "start": {"line": 80, "col": 5},
                "extra": {
                    "severity": "ERROR",
                    "message": "Dangerous subprocess call with shell=True",
                    "metadata": {
                        "cwe": ["CWE-78: Command Injection"],
                        "owasp": ["A01:2017 - Injection"],
                    },
                },
            },
            {
                "check_id": "generic.security.tls.disabled-certificate-validation",
                "path": "/tmp/scan/processor.py",
                "start": {"line": 85, "col": 5},
                "extra": {
                    "severity": "WARNING",
                    "message": "TLS certificate validation disabled (verify=False)",
                    "metadata": {"cwe": ["CWE-295: Improper Certificate Validation"]},
                },
            },
        ]
    }

    findings = adapter.parse_report(sample_semgrep_json, base_dir="/tmp/scan")
    assert len(findings) == 2

    # Check high/critical command injection
    f_cmd = next(f for f in findings if "subprocess-shell-true" in f["vulnerability_id"])
    assert f_cmd["severity"] in {"HIGH", "CRITICAL"}
    assert f_cmd["line_number"] == 80
    assert f_cmd["file_path"] == "processor.py"
    assert "CWE-78" in f_cmd["title"]

    # Check medium TLS finding
    f_tls = next(f for f in findings if "disabled-certificate-validation" in f["vulnerability_id"])
    assert f_tls["severity"] == "MEDIUM"
    assert f_tls["line_number"] == 85


def test_scanner_manager_health_status():
    manager = ScannerManager(
        trivy_bin="nonexistent-trivy",
        gitleaks_bin="nonexistent-gitleaks",
        semgrep_bin="nonexistent-semgrep",
        osv_bin="nonexistent-osv",
        guarddog_bin="nonexistent-guarddog",
    )
    status = manager.get_scanner_status()
    assert status["all_available"] is False
    assert status["status"] == "UNAVAILABLE"
    assert status["scanner_mode"] == "heuristic-demo"
    assert status["trivy_version"] == "not-installed"
    assert status["gitleaks_version"] == "not-installed"
    assert status["semgrep_version"] == "not-installed"
    assert status["osv_version"] == "not-installed"
    assert status["guarddog_version"] == "not-installed"


def test_scanner_manager_fallback_execution():
    manager = ScannerManager(
        trivy_bin="nonexistent-trivy",
        gitleaks_bin="nonexistent-gitleaks",
        semgrep_bin="nonexistent-semgrep",
        osv_bin="nonexistent-osv",
        guarddog_bin="nonexistent-guarddog",
    )
    # When binaries not found, execute_scans gracefully falls back to heuristic demo rules
    extracted_files = {
        "requirements.txt": b"fastapi==0.115.0\nurllib3==1.26.15\n",
        "app.py": b"import os\nos.system('echo test')\n",
    }
    app_metadata = {
        "name": "Test App",
        "requires_admin_privileges": False,
        "data_classification": "Internal",
    }
    result = manager.execute_scans(
        extracted_files=extracted_files,
        app_metadata=app_metadata,
        zip_sandbox_indicators=[],
    )
    assert "findings" in result
    assert "dependencies" in result
    assert result["mode"] == "heuristic-demo"
    assert result["scanner_status"]["all_available"] is False


def test_osv_adapter_parses_cve_and_malicious_advisories():
    from app.engine.adapters.osv_adapter import OsvScannerAdapter

    adapter = OsvScannerAdapter(binary_path="nonexistent-osv")
    sample_osv_json = {
        "results": [
            {
                "source": {"path": "/tmp/scan/requirements.txt", "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": "evil-helper", "version": "0.1.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "MAL-2026-9999",
                                "summary": "Malicious package harvesting environment secrets",
                                "details": "Exfiltrates AWS_SECRET_ACCESS_KEY on install.",
                            }
                        ],
                    },
                    {
                        "package": {"name": "urllib3", "version": "1.26.15", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-34jh-p97f-mpxf",
                                "summary": "Proxy-Authorization header stripped on cross-origin redirect",
                                "database_specific": {"severity": "MEDIUM"},
                                "affected": [
                                    {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.26.19"}]}]}
                                ],
                            }
                        ],
                    },
                ],
            }
        ]
    }
    findings, deps = adapter.parse_report(sample_osv_json, base_dir="/tmp/scan")
    assert len(findings) == 2
    assert len(deps) == 2

    mal_f = next(f for f in findings if f["package_name"] == "evil-helper")
    assert mal_f["scanner"] == "OSV-Scanner"
    assert mal_f["finding_type"] == "malicious_package"
    assert mal_f["severity"] == "CRITICAL"

    mal_dep = next(d for d in deps if d["package_name"] == "evil-helper")
    assert mal_dep["malicious_risk"] == "Potentially Malicious Package"

    cve_f = next(f for f in findings if f["package_name"] == "urllib3")
    assert cve_f["fixed_version"] == "1.26.19"
    assert cve_f["severity"] == "MEDIUM"


def test_guarddog_adapter_parses_install_script_and_malware():
    from app.engine.adapters.guarddog_adapter import GuardDogAdapter

    adapter = GuardDogAdapter(binary_path="nonexistent-guarddog")
    pkg_reports = [
        {
            "package": "evil-setup-pkg",
            "ecosystem": "pip",
            "version": "1.0.0",
            "file_path": "requirements.txt",
            "results": {
                "cmd-overwrite": [{"location": "setup.py:14", "message": "Overwrites install cmd"}],
                "empty_information": [{"location": "METADATA", "message": "Short description"}],
            },
        },
        {
            "package": "stealer-npm",
            "ecosystem": "npm",
            "version": "2.0.0",
            "file_path": "package.json",
            "results": {
                "npm-exfiltrate-sensitive-data": [{"location": "index.js:4", "message": "Reads process.env"}],
            },
        },
    ]
    findings, deps = adapter.parse_reports(pkg_reports)
    assert len(findings) == 2  # empty_information low-signal noise skipped
    assert len(deps) == 2

    py_dep = next(d for d in deps if d["package_name"] == "evil-setup-pkg")
    assert py_dep["malicious_risk"] == "Suspicious Install Script"

    npm_dep = next(d for d in deps if d["package_name"] == "stealer-npm")
    assert npm_dep["malicious_risk"] == "Potentially Malicious Package"


def test_registry_checker_abandonment_and_typosquatting():
    from app.engine.adapters.registry_checker import RegistryMetadataChecker

    def mock_http_get(url: str, timeout: int):
        if "pypi.org/pypi/old-abandoned-pkg/json" in url:
            return {
                "info": {"version": "0.9.0", "author": "Legacy Dev", "classifiers": []},
                "releases": {"0.9.0": [{"upload_time_iso_8601": "2020-01-15T10:00:00Z"}]},
            }
        if "pypi.org/pypi/reqeusts/json" in url:
            return {
                "info": {"version": "0.0.1", "author": "Suspicious Actor", "classifiers": []},
                "releases": {"0.0.1": [{"upload_time_iso_8601": "2026-10-01T10:00:00Z"}]},
            }
        if "registry.npmjs.org/legacy-npm" in url:
            return {
                "dist-tags": {"latest": "1.0.0"},
                "time": {"1.0.0": "2026-06-01T00:00:00Z"},
                "versions": {"1.0.0": {"deprecated": "Use newer package"}},
                "maintainers": [{"name": "npm-maint"}],
            }
        return None

    checker = RegistryMetadataChecker(http_get_json=mock_http_get)
    deps = [
        {"package_name": "old-abandoned-pkg", "version": "0.9.0", "ecosystem": "pip", "malicious_risk": "Known Safe / Standard"},
        {"package_name": "reqeusts", "version": "0.0.1", "ecosystem": "pip", "malicious_risk": "Known Safe / Standard"},
        {"package_name": "legacy-npm", "version": "1.0.0", "ecosystem": "npm", "malicious_risk": "Known Safe / Standard"},
    ]
    enriched, findings, warnings = checker.enrich_dependencies(deps)
    assert warnings == []

    old_dep = next(d for d in enriched if d["package_name"] == "old-abandoned-pkg")
    assert old_dep["reviewer_status"] == "ABANDONED"
    assert old_dep["last_release_date"] == "2020-01-15"
    assert old_dep["publisher_identity"] == "Legacy Dev"

    typo_dep = next(d for d in enriched if d["package_name"] == "reqeusts")
    assert typo_dep["malicious_risk"] == "Typosquatting Suspect"
    assert typo_dep["alternative_package"] == "requests"
    assert len(findings) == 1
    assert findings[0]["scanner"] == "RegistryMetadata"
    assert findings[0]["severity"] == "CRITICAL"

    npm_dep = next(d for d in enriched if d["package_name"] == "legacy-npm")
    assert npm_dep["reviewer_status"] == "MAINTENANCE REVIEW"
    assert npm_dep["publisher_identity"] == "npm-maint"

