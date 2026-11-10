import io
import zipfile
from typing import Tuple


def generate_sample_zip(preset: str) -> Tuple[str, bytes]:
    """
    Generates realistic in-memory source-code ZIP packages to test all S-Gates workflows:
    1. 'clean'     -> PASS-WITH-MANUAL-CHECKS (Clean KPI Calculator App)
    2. 'review'    -> REVIEW (Sales Analytics Tool v1.2 matching PRD Section 21 with HIGH findings + abandoned pkg)
    3. 'reject'    -> REJECT (Shadow AI SAP Connector with AWS Access Key in config.py line 44, SQLi/Command Injection, Critical CVE, typosquatted pkg, and .exe binary)
    4. 'traversal' -> REJECT / SCAN-ERROR (Contains ../../Windows/System32/example.exe per PRD Section 11)
    """
    buf = io.BytesIO()

    if preset == "clean":
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "README.md",
                "# Manufacturing KPI Calculator v1.0\nInternal read-only OEE & cycle-time calculator built with Cursor.\n",
            )
            zf.writestr(
                "requirements.txt",
                "fastapi==0.115.0\npydantic==2.9.2\nhttpx==0.27.2\n",
            )
            zf.writestr(
                "app/calculator.py",
                '''"""Clean KPI calculation service with strict input validation."""
from dataclasses import dataclass


@dataclass
class OeeMetrics:
    availability: float
    performance: float
    quality: float

    @property
    def overall_oee(self) -> float:
        return round(self.availability * self.performance * self.quality * 100, 2)


def calculate_plant_oee(run_time_mins: float, planned_mins: float) -> float:
    if planned_mins <= 0:
        raise ValueError("Planned production minutes must be positive")
    return round(min(max(run_time_mins / planned_mins, 0.0), 1.0), 4)
''',
            )
            zf.writestr(
                "Dockerfile",
                "FROM python:3.12-slim\nWORKDIR /app\nCOPY . /app\nUSER appuser\nCMD [\"python\", \"-m\", \"app.calculator\"]\n",
            )
        return ("clean-kpi-calculator-v1.0.zip", buf.getvalue())

    if preset == "review":
        # Matches PRD Section 21 & 14 example: Sales Analytics Tool v1.2
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "README.md",
                "# Sales Analytics Tool v1.2\nRegional sales forecasting dashboard generated with Claude & Lovable.\n",
            )
            zf.writestr(
                "requirements.txt",
                "urllib3==1.26.15\ncryptography==41.0.0\nrequests==2.28.0\nxlrd==1.2.0\nfastapi==0.111.0\n",
            )
            zf.writestr(
                "package.json",
                '{\n  "name": "sales-analytics-ui",\n  "version": "1.2.0",\n  "dependencies": {\n    "axios": "1.3.0",\n    "moment": "2.29.4"\n  }\n}\n',
            )
            zf.writestr(
                "processor.py",
                '''"""Sales export processor — contains Semgrep HIGH command injection finding (PRD Section 14)."""
import subprocess
import requests


def export_regional_report(region_filter: str, report_path: str):
    # HIGH Semgrep finding: subprocess with shell=True
    cmd = f"python3 generate_csv.py --region {region_filter}"
    subprocess.run(cmd, shell=True, check=False)

    # MEDIUM Semgrep finding: opening formatted path & TLS verify=False
    with open(f"/tmp/reports/{report_path}", "r", encoding="utf-8") as handle:
        data = handle.read()
    requests.post("https://internal-bi.company.local/ingest", data=data, verify=False)
''',
            )
            zf.writestr(
                "Dockerfile",
                "FROM python:3.12-slim\nWORKDIR /app\nCOPY . /app\nCMD [\"python\", \"processor.py\"]\n",
            )
        return ("sales-analytics-tool-v1.2.zip", buf.getvalue())

    if preset == "reject":
        # Matches PRD Section 13 (config.py line 44 AWS Access Key) + Critical CVE + Typosquatting + .exe
        config_lines = [f"# Configuration header line {i}" for i in range(1, 44)]
        config_lines.append('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # Line 44 per PRD Section 13')
        config_lines.append('OPENAI_API_KEY = "sk-proj-9876543210abcdefghijklmnopQRSTUVWX"')
        config_lines.append('SAP_PROD_PASSWORD = "SuperSecretSapProdPassword2026!"')

        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "README.md",
                "# Shadow AI SAP Inventory Sync Agent v0.9\nAutomated background sync agent built with Bolt & ChatGPT.\n",
            )
            zf.writestr("config.py", "\n".join(config_lines) + "\n")
            zf.writestr(
                "requirements.txt",
                "pyyaml==5.3.1\npycrypto==2.6.1\nreqeusts==2.28.1\n",
            )
            zf.writestr(
                "sap_sync_agent.py",
                '''"""High-risk SAP sync agent with SQLi, eval, obfuscation, and Windows service creation."""
import base64
import os
import pickle


def query_sap_vendor(cursor, vendor_code: str):
    query = "SELECT * FROM Z_VENDORS WHERE VENDOR_CODE = '" + vendor_code + "'"
    cursor.execute(query)
    return cursor.fetchall()


def install_background_service():
    os.system("sc.exe create SapShadowSync binPath= C:\\\\Temp\\\\sap_helper.exe start= auto")
    os.system("schtasks /create /tn SapHourlySync /tr C:\\\\Temp\\\\sap_helper.exe /sc hourly")


def run_dynamic_formula(expr: str, raw_blob: bytes):
    obj = pickle.loads(raw_blob)
    exec(base64.b64decode("cHJpbnQoJ29iZnVzY2F0ZWQgcGF5bG9hZCcp"))
    return eval(expr), obj
''',
            )
            zf.writestr("bin/sap_helper.exe", b"MZ\x90\x00\x03\x00\x00\x00DummyWindowsExecutableHeaderForSandboxTrigger")
        return ("shadow-ai-sap-sync-v0.9.zip", buf.getvalue())

    if preset == "traversal":
        # Matches PRD Section 11 explicit protection example: ../../Windows/System32/example.exe
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("README.md", "# Malicious Archive Test\n")
            zf.writestr("../../Windows/System32/example.exe", b"MZ-malicious-path-traversal-payload")
            zf.writestr("/etc/passwd", b"root:x:0:0:root:/root:/bin/bash")
        return ("malicious-traversal-archive.zip", buf.getvalue())

    raise ValueError(f"Unknown sample preset: {preset}")

