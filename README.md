# Security Gates (s-gates)

S-Gates scans GitHub repositories and `.zip` source archives before deployment. It runs Aqua Trivy, Gitleaks, Semgrep SAST, Google OSV-Scanner, Datadog GuardDog, and a PyPI/npm metadata checker concurrently in an isolated workspace, streams progress logs to the browser, computes a release decision, and writes a SHA-256 audit log alongside an Evidence Vault archive.

## Capabilities

### Security and supply-chain scanners

- Aqua Trivy (`trivy fs`): scans Python, Node.js, Go, and Java manifests for known CVEs, and checks Dockerfiles and IaC files for misconfigurations such as running containers as `root`.
- Gitleaks (`gitleaks dir`): detects secrets across 160+ token and key patterns and masks matched values as `********************` before writing to PostgreSQL, disk, or browser logs.
- Semgrep SAST (`semgrep scan`): checks code against OWASP Top 10 and CWE rules for SQL injection, command injection, unsafe deserialization, XSS, and weak cryptography.
- Google OSV-Scanner (`osv-scanner scan`): checks lockfiles and manifests against OSV advisories, including OpenSSF Malicious Packages (`MAL-*`), which flag `Potentially Malicious Package` and trigger `REJECT`.
- Datadog GuardDog (`guarddog pypi/npm scan`): inspects direct PyPI and npm manifest packages (capped at 20 packages per scan with a 6-hour in-memory cache) for malicious `setup.py` or `postinstall` scripts, hidden payloads, and environment variable exfiltration.
- PyPI and npm Registry Metadata Checker: queries `pypi.org` and `registry.npmjs.org` (6-hour in-memory cache) for `last_release_date`, `publisher_identity`, `maintainer_status` (`ABANDONED` when stale over 2 years, `MAINTENANCE REVIEW` when deprecated), and typosquatting similarity (`Typosquatting Suspect`).

### Intake and live output

S-Gates accepts public or private GitHub repository URLs (with an optional branch/tag and transient read-only fine-grained token that is never saved or logged) as well as `.zip` uploads. Before extracting an upload, the ZIP security gate checks file extension, archive integrity, file count, expanded size, compression ratio, path traversal (`../../`), and symlinks. During the scan, an NDJSON stream sends stage updates (`INTAKE` -> `ZIP_GATE` -> `SCANNERS` -> `RISK_ENGINE` -> `VAULT`), sanitized commands, runtimes, and finding counts to the Live Backend Terminal.

### Risk decisions, Evidence Vault, and access control

Each scan finishes as `PASS-WITH-MANUAL-CHECKS`, `REVIEW`, `REJECT`, or `SCAN-ERROR` alongside remediation steps, manual antivirus/sandbox gate fields, and version tracking (`SG-APP-XXXX` / `SG-YYYY-NNNNN`). Reports (`Reports/scan-summary.html`, `scan-summary.json`, `supply-chain-report.json`, per-scanner JSON/TXT files, and `Inventory/file-inventory.csv`) are packaged into a downloadable `.zip` Evidence Vault, and every submission, finding update, approval, and deletion is chained in a SHA-256 `AuditRecord` log.

JWT login supports `ADMIN`, `SECURITY_REVIEWER`, `IT_REVIEWER`, and `CITIZEN_DEVELOPER` roles. Administrators can delete individual assessments, delete applications from the Application Inventory (removing linked assessments and Evidence Vault folders on disk), or purge scan history while keeping immutable audit events (`ASSESSMENT_DELETED`, `APPLICATION_DELETED`, `SCAN_HISTORY_PURGED`).

## Stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI (Python 3.12), SQLAlchemy 2.0, Pydantic v2, Uvicorn |
| Security Scanners | Aqua Trivy (`v0.76.2`), Gitleaks (`v8.30.1`), Semgrep (`v1.95.0`), OSV-Scanner (`v2.7.1`), GuardDog (`v3.2.0` in `/opt/guarddog-venv`) |
| Registry Lookup | Public PyPI (`pypi.org`) and npm (`registry.npmjs.org`) JSON APIs with 6-hour TTL caching |
| Database | PostgreSQL 16 (Docker) / SQLite (automated test suite) |
| Frontend | Next.js 16 (App Router), React 19, Tailwind CSS, Lucide Icons |
| Streaming | NDJSON `StreamingResponse` on port `8003` over CORS |

## Network and Outbound Access

`osv-scanner`, `guarddog`, and the Registry Metadata Checker make outbound HTTPS calls from `s_gates_backend` to `api.osv.dev`, `pypi.org`, and `registry.npmjs.org`. When outbound HTTPS is unavailable, S-Gates logs a warning in the Live Backend Terminal and continues scanning offline with Trivy, Gitleaks, and Semgrep.

Both GuardDog and the Registry Metadata Checker cache results in memory for 6 hours (`SUPPLY_CHAIN_CACHE_TTL_SECONDS=21600`), and GuardDog inspects up to 20 direct manifest packages per scan (`GUARDDOG_MAX_PACKAGES=20`).

## Quick Start (Docker Compose)

```bash
# 1. Copy environment template and configure secrets
cp .env.example .env
# Edit .env: set unique DB_PASSWORD, SECRET_KEY, ADMIN_EMAIL, and ADMIN_PASSWORD

# 2. Build and start PostgreSQL, Backend (with all 5 security scanners), and Frontend
make run-docker
```

Both frontend (`0.0.0.0:3003`) and backend (`0.0.0.0:8003`) bind to all interfaces with dynamic LAN CORS enabled:
- Web portal: [http://localhost:3003](http://localhost:3003) (or `http://<your-host-ip>:3003` over LAN)
- API and Swagger docs: [http://localhost:8003/docs](http://localhost:8003/docs)
- Health check: [http://localhost:8003/health](http://localhost:8003/health)
- PostgreSQL: `127.0.0.1:5436`

## Running Tests

Run the backend pytest suite (unit tests, adapter parsing, registry metadata checks, GitHub source validation, RBAC, audit chain, deletion/purge, and live NDJSON streaming):

```bash
make test
# Or locally with your Python environment:
cd backend && pytest tests/ -v
```

Verify frontend linting, TypeScript checks, and the Next.js production build:

```bash
cd frontend && npm run lint && npm run build
```

## Port Allocation

| Service | Host Port | Container Port |
|---|---|---|
| Frontend (`s_gates_frontend`) | `3003` | `3000` |
| Backend (`s_gates_backend`) | `8003` | `8000` |
| PostgreSQL (`s_gates_db`) | `5436` | `5432` |
