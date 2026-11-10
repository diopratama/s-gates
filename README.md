# Security Gates (`s-gates`)

> **Build Fast. Scan First. Deploy with Confidence.**

**S-Gates (Security Gateway)** is an application security assessment, supply-chain intelligence, and governance portal for source code submitted via GitHub repositories or `.zip` archives. It executes **Aqua Trivy**, **Gitleaks**, **Semgrep SAST**, **Google OSV-Scanner**, **Datadog GuardDog**, and a **PyPI & npm Registry Metadata Checker** concurrently inside an isolated workspace, streams real-time backend telemetry to a **Live Backend Terminal**, evaluates automated risk decisions, and produces tamper-evident audit trails and Evidence Vault bundles.

---

## Core Capabilities

1. **Multi-Engine Security & Supply-Chain Scanning**
   - **Aqua Trivy (`trivy fs`)**: Software Composition Analysis (SCA) for dependency CVEs across Python, Node.js, Go, Java, and infrastructure/Dockerfile misconfigurations.
   - **Gitleaks (`gitleaks dir`)**: Secret and credential detection across 160+ token/key patterns with **mandatory redaction (`********************`)**. Raw secret values are never stored in PostgreSQL, written to disk, or streamed to the browser.
   - **Semgrep SAST (`semgrep scan`)**: Static Application Security Testing mapped to OWASP Top 10 / CWE categories (SQL injection, command injection, unsafe deserialization, XSS, and weak cryptography).
   - **Google OSV-Scanner (`osv-scanner scan`)**: Lockfile and manifest vulnerability matching against the OSV database, including **OpenSSF Malicious Packages (`MAL-*`)**. Any `MAL-*` advisory flags `Potentially Malicious Package` and automatically triggers `REJECT`.
   - **Datadog GuardDog (`guarddog pypi/npm scan`)**: Inspects direct PyPI and npm manifest dependencies (up to 20 packages per scan with a 6-hour in-memory TTL cache) for malicious `setup.py` / `postinstall` scripts, environment variable exfiltration, and hidden payloads.
   - **PyPI & npm Registry Metadata Checker**: Queries `pypi.org` and `registry.npmjs.org` (6-hour TTL cache) to populate `last_release_date`, `publisher_identity`, `maintainer_status` (`ABANDONED` if > 2 years stale, `MAINTENANCE REVIEW` if 1–2 years stale or deprecated), and typosquatting similarity checks (`Typosquatting Suspect`).
   - **Graceful Network & Environment Fallback**: Outbound HTTPS failures (`api.osv.dev`, `pypi.org`, `registry.npmjs.org`) emit warnings in the Live Terminal and continue gracefully; unit-test environments without CLI binaries fall back deterministically.

2. **GitHub & ZIP Source Intake with Live Backend Terminal**
   - **GitHub Repository Scan**: Supports public and private GitHub repositories via HTTPS URL, optional branch/tag, and transient fine-grained Personal Access Tokens (`Contents: read`, never persisted or logged).
   - **ZIP Security Gate**: Validates file extension, archive integrity, file count, expanded size, compression ratio, and blocks path traversal (`../../`) or symlink escapes prior to extraction.
   - **Live Backend Terminal (NDJSON Streaming)**: Streams real-time pipeline stages (`INTAKE` -> `ZIP_GATE` -> `SCANNERS` -> `RISK_ENGINE` -> `VAULT`), sanitized CLI commands, execution timings, and finding counts directly to the browser.

3. **Automated Risk Decision Engine & Remediation Guidance**
   - Classifies each submission into `PASS-WITH-MANUAL-CHECKS`, `REVIEW`, `REJECT`, or `SCAN-ERROR` with actionable remediation steps and manual antivirus/sandbox gate tracking.
   - Tracks application inventory across versions (`SG-APP-XXXX` / `SG-YYYY-NNNNN`).

4. **Evidence Vault & Tamper-Evident Audit Chain**
   - Generates self-contained `Reports/scan-summary.html`, `scan-summary.json`, `supply-chain-report.json`, per-scanner JSON/TXT reports, `Inventory/file-inventory.csv`, and downloadable `.zip` Evidence Vault bundles.
   - Records every submission, finding update, approval decision, and admin deletion in a SHA-256 hash-chained `AuditRecord` log.

5. **Role-Based Access Control (RBAC) & Admin Lifecycle Management**
   - JWT authentication supporting `ADMIN`, `SECURITY_REVIEWER`, `IT_REVIEWER`, and `CITIZEN_DEVELOPER` personas.
   - **Admin Deletion & History Purge**: Administrators can delete individual assessments, delete entire applications from the **Application Inventory** (cascade-deleting linked assessments and Evidence Vault folders on disk), or purge all scan history while preserving immutable audit records (`ASSESSMENT_DELETED`, `APPLICATION_DELETED`, `SCAN_HISTORY_PURGED`).

---

## Architecture & Tech Stack

| Layer | Technology |
|---|---|
| **Backend API** | FastAPI (Python 3.12), SQLAlchemy 2.0, Pydantic v2, Uvicorn |
| **Security Scanners** | Aqua Trivy (`v0.76.2`), Gitleaks (`v8.30.1`), Semgrep (`v1.95.0`), OSV-Scanner (`v2.7.1`), GuardDog (`v3.2.0` in `/opt/guarddog-venv`) |
| **Registry Intelligence** | Public PyPI (`pypi.org`) & npm (`registry.npmjs.org`) JSON APIs with 6-hour TTL caching |
| **Database** | PostgreSQL 16 (Docker) / SQLite (automated test suite) |
| **Frontend Portal** | Next.js 16 (App Router), React 19, Tailwind CSS, Lucide Icons |
| **Streaming** | NDJSON `StreamingResponse` directly on port `8003` over CORS |

---

## Network & Outbound Requirements

- **Outbound HTTPS**: `osv-scanner`, `guarddog`, and the Registry Metadata Checker query `api.osv.dev`, `pypi.org`, and `registry.npmjs.org` from the `s_gates_backend` container when running scans. If outbound access is restricted, S-Gates logs a warning in the Live Backend Terminal and continues scanning offline with Trivy, Gitleaks, and Semgrep.
- **Caching**: Both GuardDog and Registry Metadata Checker maintain 6-hour in-memory TTL caches (`SUPPLY_CHAIN_CACHE_TTL_SECONDS=21600`), with GuardDog capped at 20 direct manifest packages (`GUARDDOG_MAX_PACKAGES=20`) to keep scan latency fast.

---

## Quick Start (Docker Compose)

```bash
# 1. Copy environment template and configure secrets
cp .env.example .env
# Edit .env: set unique DB_PASSWORD, SECRET_KEY, ADMIN_EMAIL, and ADMIN_PASSWORD

# 2. Build and start PostgreSQL, Backend (with all 5 security scanners), and Frontend
make run-docker
```

### Access URLs (Localhost & LAN)
Both frontend (`0.0.0.0:3003`) and backend (`0.0.0.0:8003`) bind to all interfaces with dynamic LAN CORS support:
- **Web Portal**: [http://localhost:3003](http://localhost:3003) (or `http://<your-host-ip>:3003` from another machine on your LAN)
- **API & Swagger Docs**: [http://localhost:8003/docs](http://localhost:8003/docs)
- **Health Check**: [http://localhost:8003/health](http://localhost:8003/health)
- **PostgreSQL**: `127.0.0.1:5436`

---

## Running Automated Tests

Run the backend pytest suite (unit tests, adapter parsing, registry metadata checks, GitHub source validation, RBAC, audit chain, deletion/purge, and live NDJSON streaming):

```bash
make test
# Or locally with your Python environment:
cd backend && pytest tests/ -v
```

Verify the frontend TypeScript compilation and production build:

```bash
cd frontend && npm run build
```

---

## Port Allocation (Sibling-Safe)

| Service | Host Port | Container Port |
|---|---|---|
| **Frontend (`s_gates_frontend`)** | `3003` | `3000` |
| **Backend (`s_gates_backend`)** | `8003` | `8000` |
| **PostgreSQL (`s_gates_db`)** | `5436` | `5432` |
