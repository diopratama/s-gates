"use client";

import React from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Database,
  FileText,
  HelpCircle,
  Info,
  Layers,
  Package,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import type { SystemSettings } from "@/lib/api";

interface GuideViewProps {
  systemSettings: SystemSettings | null;
}

export default function GuideView({ systemSettings }: GuideViewProps) {
  return (
    <div className="space-y-8 max-w-5xl mx-auto pb-12">
      {/* Hero Banner */}
      <div className="rounded-3xl border border-emerald-500/30 bg-gradient-to-br from-slate-900 via-slate-900/90 to-emerald-950/20 p-8 shadow-xl">
        <div className="flex flex-wrap items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shrink-0">
            <ShieldCheck className="h-7 w-7" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-white tracking-tight">
              How S-Gates Works
            </h1>
            <p className="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">
              Scan GitHub repositories or source ZIPs for dependency CVEs, leaked credentials, unsafe code, malicious packages, and registry typosquatting before deployment.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mt-6 pt-6 border-t border-slate-800/80 text-center">
          <div className="rounded-xl bg-slate-950/60 border border-slate-800 p-3">
            <div className="text-emerald-300 font-bold text-sm">Aqua Trivy</div>
            <div className="text-xs text-slate-400 mt-0.5">SCA &amp; Config</div>
          </div>
          <div className="rounded-xl bg-slate-950/60 border border-slate-800 p-3">
            <div className="text-rose-300 font-bold text-sm">Gitleaks</div>
            <div className="text-xs text-slate-400 mt-0.5">Secrets</div>
          </div>
          <div className="rounded-xl bg-slate-950/60 border border-slate-800 p-3">
            <div className="text-amber-300 font-bold text-sm">Semgrep</div>
            <div className="text-xs text-slate-400 mt-0.5">OWASP Top 10</div>
          </div>
          <div className="rounded-xl bg-slate-950/60 border border-slate-800 p-3">
            <div className="text-purple-300 font-bold text-sm">OSV-Scanner</div>
            <div className="text-xs text-slate-400 mt-0.5">MAL-* Malware</div>
          </div>
          <div className="rounded-xl bg-slate-950/60 border border-slate-800 p-3">
            <div className="text-orange-300 font-bold text-sm">GuardDog</div>
            <div className="text-xs text-slate-400 mt-0.5">Supply-Chain</div>
          </div>
          <div className="rounded-xl bg-slate-950/60 border border-slate-800 p-3">
            <div className="text-sky-300 font-bold text-sm">Registry Intel</div>
            <div className="text-xs text-slate-400 mt-0.5">Typosquatting</div>
          </div>
        </div>
      </div>

      {/* Section 1: What S-Gates Checks */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Info className="h-5 w-5 text-emerald-400" aria-hidden="true" />
          1. What S-Gates Checks
        </h2>
        <p className="text-xs text-slate-300 leading-relaxed">
          Internal tools built quickly or with AI coding assistants often ship with credentials left in source files, vulnerable or typosquatted dependencies, or unsafe execution calls.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="rounded-xl bg-slate-950/80 border border-rose-900/40 p-4 space-y-1.5">
            <div className="font-bold text-rose-300 flex items-center gap-1.5">
              <ShieldAlert className="h-4 w-4 text-rose-400" aria-hidden="true" />
              Credential Leakage
            </div>
            <p className="text-slate-300 text-xs leading-relaxed">
              API keys, GitHub tokens, database connection strings, and private keys committed into source files.
            </p>
          </div>
          <div className="rounded-xl bg-slate-950/80 border border-amber-900/40 p-4 space-y-1.5">
            <div className="font-bold text-amber-300 flex items-center gap-1.5">
              <Package className="h-4 w-4 text-amber-400" aria-hidden="true" />
              Vulnerable Dependencies (CVEs)
            </div>
            <p className="text-slate-300 text-xs leading-relaxed">
              Outdated libraries, malicious install scripts, or typosquatted packages carrying known CVEs.
            </p>
          </div>
          <div className="rounded-xl bg-slate-950/80 border border-sky-900/40 p-4 space-y-1.5">
            <div className="font-bold text-sky-300 flex items-center gap-1.5">
              <AlertTriangle className="h-4 w-4 text-sky-400" aria-hidden="true" />
              Unsafe Code Patterns (SAST)
            </div>
            <p className="text-slate-300 text-xs leading-relaxed">
              Unsafe calls such as <code className="text-sky-300">eval()</code>, <code className="text-sky-300">os.system()</code>, SQL injection, or path traversal bugs.
            </p>
          </div>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          S-Gates scans each repository or archive before release, streams command output live to the terminal, and saves reports alongside a SHA-256 audit log.
        </p>
      </div>

      {/* Section 2: Scanners */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Cpu className="h-5 w-5 text-emerald-400" aria-hidden="true" />
          2. Scanners and Registry Checks
        </h2>
        <p className="text-xs text-slate-300 leading-relaxed">
          S-Gates runs five CLI security tools and live package registry lookups concurrently inside an isolated server workspace:
        </p>

        <div className="space-y-4">
          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-sky-400" aria-hidden="true" />
                <h3 className="text-sm font-bold text-white">
                  Aqua Trivy (v{systemSettings?.trivy_version && systemSettings.trivy_version !== "not-installed" ? systemSettings.trivy_version : "0.76.2"})
                </h3>
                <span className="rounded bg-sky-950 border border-sky-800 px-2 py-0.5 text-xs font-mono text-sky-200">
                  SCA &amp; Config Audit
                </span>
              </div>
              <span className="text-xs text-slate-400">By Aqua Security</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Inspects dependency manifests (<code className="text-slate-200">requirements.txt</code>, <code className="text-slate-200">package.json</code>, <code className="text-slate-200">pom.xml</code>, <code className="text-slate-200">go.mod</code>) against CVE advisories, and checks Dockerfiles and IaC templates for issues like containers running as <code className="text-slate-200">root</code>.
            </p>
          </div>

          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-400" aria-hidden="true" />
                <h3 className="text-sm font-bold text-white">
                  Gitleaks (v{systemSettings?.gitleaks_version && systemSettings.gitleaks_version !== "not-installed" ? systemSettings.gitleaks_version : "8.30.1"})
                </h3>
                <span className="rounded bg-rose-950 border border-rose-800 px-2 py-0.5 text-xs font-mono text-rose-200">
                  Secret Detection &amp; Masking
                </span>
              </div>
              <span className="text-xs text-slate-400">By Zachary Rice</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Scans source trees against 160+ secret rules including AWS access keys, GitHub tokens, SSH/RSA private keys, OpenAI API keys, and database credentials.
            </p>
            <div className="rounded-lg bg-rose-950/30 border border-rose-900/50 p-3 text-xs text-rose-200">
              Matched credential values are replaced with <code className="font-mono text-white">********************</code> before saving to the database, Evidence Vault, or live terminal logs.
            </div>
          </div>

          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400" aria-hidden="true" />
                <h3 className="text-sm font-bold text-white">
                  Semgrep SAST (v{systemSettings?.semgrep_version && systemSettings.semgrep_version !== "not-installed" ? systemSettings.semgrep_version : "1.95.0"})
                </h3>
                <span className="rounded bg-amber-950 border border-amber-800 px-2 py-0.5 text-xs font-mono text-amber-200">
                  Static Code Analysis
                </span>
              </div>
              <span className="text-xs text-slate-400">By Semgrep / r2c</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Runs static code analysis across Python, JavaScript/TypeScript, Go, and Java using OWASP Top 10 rules to catch SQL injection, XSS, command injection, and weak cryptography.
            </p>
          </div>

          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-purple-400" aria-hidden="true" />
                <h3 className="text-sm font-bold text-white">
                  Google OSV-Scanner (v{systemSettings?.osv_version && systemSettings.osv_version !== "not-installed" ? systemSettings.osv_version : "2.7.1"})
                </h3>
                <span className="rounded bg-purple-950 border border-purple-800 px-2 py-0.5 text-xs font-mono text-purple-200">
                  OSV &amp; OpenSSF MAL-* Malware
                </span>
              </div>
              <span className="text-xs text-slate-400">By Google &amp; OpenSSF (Apache-2.0)</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Matches lockfiles and manifests against the OSV database, including OpenSSF Malicious Packages (<code>MAL-*</code>). Any <code>MAL-*</code> hit marks the package as <code>Potentially Malicious Package</code> and blocks release.
            </p>
          </div>

          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-orange-400" aria-hidden="true" />
                <h3 className="text-sm font-bold text-white">
                  Datadog GuardDog (v{systemSettings?.guarddog_version && systemSettings.guarddog_version !== "not-installed" ? systemSettings.guarddog_version : "3.2.0"})
                </h3>
                <span className="rounded bg-orange-950 border border-orange-800 px-2 py-0.5 text-xs font-mono text-orange-200">
                  PyPI &amp; npm Install-Script Inspection
                </span>
              </div>
              <span className="text-xs text-slate-400">By Datadog (Apache-2.0)</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Checks direct PyPI and npm manifest packages (up to 20 per scan with a 6-hour cache) for suspicious <code>setup.py</code> or <code>postinstall</code> scripts, hidden base64 payloads, and environment variable exfiltration.
            </p>
          </div>

          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" aria-hidden="true" />
                <h3 className="text-sm font-bold text-white">PyPI &amp; npm Registry Metadata Checker</h3>
                <span className="rounded bg-emerald-950 border border-emerald-800 px-2 py-0.5 text-xs font-mono text-emerald-200">
                  Abandonment &amp; Typosquatting
                </span>
              </div>
              <span className="text-xs text-slate-400">Public Registry JSON API (6h Cache)</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Queries <code>pypi.org</code> and <code>registry.npmjs.org</code> to populate Last Release Date, Publisher Identity, and Maintainer Status. Packages inactive over 2 years are marked <code>ABANDONED</code> (triggers review), deprecated packages are marked <code>MAINTENANCE REVIEW</code>, and lookalike names (such as <code>reqeusts</code> vs <code>requests</code>) are marked <code>Typosquatting Suspect</code> (blocks release).
            </p>
          </div>
        </div>
      </div>

      {/* Section 3: Pipeline */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Layers className="h-5 w-5 text-emerald-400" aria-hidden="true" />
          3. Scanning Pipeline
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center font-bold text-emerald-300">
              1
            </div>
            <h3 className="font-bold text-white">Source Intake</h3>
            <p className="text-slate-300 text-xs leading-relaxed">
              Submit a public or private GitHub repository URL or upload a <code className="text-slate-200">.zip</code> archive.
            </p>
          </div>

          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center font-bold text-sky-300">
              2
            </div>
            <h3 className="font-bold text-white">Gate &amp; Live Terminal</h3>
            <p className="text-slate-300 text-xs leading-relaxed">
              S-Gates checks ZIP safety, runs all five scanners plus registry checks concurrently, and streams log lines to the terminal.
            </p>
          </div>

          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center font-bold text-amber-300">
              3
            </div>
            <h3 className="font-bold text-white">Risk Decision</h3>
            <p className="text-slate-300 text-xs leading-relaxed">
              Consolidates findings into Passed, Needs Review, Blocked, or Scan Error based on severity and supply-chain rules.
            </p>
          </div>

          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center font-bold text-purple-300">
              4
            </div>
            <h3 className="font-bold text-white">Evidence Vault</h3>
            <p className="text-slate-300 text-xs leading-relaxed">
              Writes standalone HTML and JSON reports, a file inventory CSV, and the SHA-256 audit log.
            </p>
          </div>
        </div>
      </div>

      {/* Section 4: Risk Decision Statuses */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <CheckCircle2 className="h-5 w-5 text-emerald-400" aria-hidden="true" />
          4. Scan Result Statuses
        </h2>
        <div className="space-y-3 text-xs">
          <div className="rounded-xl bg-emerald-950/30 border border-emerald-500/30 p-4 flex items-start gap-3">
            <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" aria-hidden="true" />
            <div>
              <h3 className="font-bold text-emerald-200 text-sm">
                Passed (PASS-WITH-MANUAL-CHECKS)
              </h3>
              <p className="text-slate-300 mt-1 leading-relaxed">
                Zero critical vulnerabilities, zero leaked secrets, and no high-risk SAST findings. Ready for pilot or manual operational verification if required.
              </p>
            </div>
          </div>

          <div className="rounded-xl bg-amber-950/30 border border-amber-500/30 p-4 flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
            <div>
              <h3 className="font-bold text-amber-200 text-sm">
                Needs Review (REVIEW)
              </h3>
              <p className="text-slate-300 mt-1 leading-relaxed">
                Medium or High findings, abandoned packages, or pending manual antivirus/sandbox gates require sign-off before production release.
              </p>
            </div>
          </div>

          <div className="rounded-xl bg-rose-950/30 border border-rose-500/30 p-4 flex items-start gap-3">
            <XCircle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" aria-hidden="true" />
            <div>
              <h3 className="font-bold text-rose-200 text-sm">
                Blocked (REJECT)
              </h3>
              <p className="text-slate-300 mt-1 leading-relaxed">
                Triggered by exposed secrets, Critical CVEs, malicious or typosquatted packages, unsafe shell/eval calls, or ZIP path traversal. Fix the findings and re-scan.
              </p>
            </div>
          </div>

          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-slate-400 shrink-0 mt-0.5" aria-hidden="true" />
            <div>
              <h3 className="font-bold text-slate-200 text-sm">
                Scan Error (SCAN-ERROR)
              </h3>
              <p className="text-slate-300 mt-1 leading-relaxed">
                The scan could not finish because the archive was invalid, the GitHub URL was unreachable, the private token failed, or a required scanner binary was missing.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Section 5: Usage Guide */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <FileText className="h-5 w-5 text-emerald-400" aria-hidden="true" />
          5. Usage Guide
        </h2>

        <div className="space-y-4 text-xs">
          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
            <h3 className="font-bold text-white text-sm">Running a Scan</h3>
            <ol className="list-decimal list-inside space-y-1.5 text-slate-300 leading-relaxed">
              <li>Click <strong>New Scan</strong> and paste a GitHub URL or choose a <code className="text-sky-300">.zip</code> file (Project Name auto-fills).</li>
              <li>Optionally expand Application Details to tag Department, Owners, AI Tool, and Data Classification.</li>
              <li>Click <strong>Run Security Scan</strong>, watch output in the Live Backend Terminal, and open the finished report.</li>
            </ol>
          </div>

          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
            <h3 className="font-bold text-white text-sm">Downloading Reports and Deleting Data</h3>
            <ol className="list-decimal list-inside space-y-1.5 text-slate-300 leading-relaxed">
              <li>Open <strong>Results</strong> to download the offline HTML report or full Evidence Vault (.zip).</li>
              <li>Administrators can delete single assessments from Results, delete entire applications from <strong>Inventory</strong>, or purge scan history from <strong>Admin &amp; Audit</strong>.</li>
            </ol>
          </div>
        </div>
      </div>

      {/* Section 6: Stack */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Database className="h-5 w-5 text-emerald-400" aria-hidden="true" />
          6. Technical Stack
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
            <h3 className="font-bold text-emerald-300">Backend</h3>
            <ul className="list-disc list-inside space-y-1.5 text-slate-300 text-xs">
              <li>Framework: FastAPI (Python 3.12)</li>
              <li>Database: PostgreSQL 16 with SQLAlchemy 2.0 and Pydantic v2</li>
              <li>Auth: JWT bearer tokens with Admin, Security Reviewer, IT Reviewer, and Citizen Developer roles</li>
              <li>Audit log: database SHA-256 hash chain</li>
            </ul>
          </div>

          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
            <h3 className="font-bold text-sky-300">Frontend &amp; Streaming</h3>
            <ul className="list-disc list-inside space-y-1.5 text-slate-300 text-xs">
              <li>Framework: Next.js 16 (App Router) and React 19</li>
              <li>Styling: Tailwind CSS and Lucide icons</li>
              <li>Streaming: NDJSON directly to port 8003 over CORS to avoid proxy timeouts</li>
              <li>Bindings: ports 3003 (UI) and 8003 (API) on <code className="text-sky-300">0.0.0.0</code> for LAN access</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Section 7: FAQ */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <HelpCircle className="h-5 w-5 text-emerald-400" aria-hidden="true" />
          7. Frequently Asked Questions
        </h2>
        <div className="space-y-3 text-xs">
          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-1">
            <h3 className="font-bold text-white">Are extracted source files kept on disk?</h3>
            <p className="text-slate-300 leading-relaxed">
              No. S-Gates unpacks source files into a temporary directory during the scan and deletes them once scanning finishes. Only metadata, HTML/JSON reports, and the Evidence Vault zip stay on disk.
            </p>
          </div>

          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-1">
            <h3 className="font-bold text-white">How are leaked keys handled if a scan finds them?</h3>
            <p className="text-slate-300 leading-relaxed">
              The Gitleaks adapter masks matched secret values as <code className="text-emerald-300">********************</code> before inserting database rows, writing Evidence Vault files, or sending API responses.
            </p>
          </div>

          <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-1">
            <h3 className="font-bold text-white">Can teammates open S-Gates over the local network (LAN)?</h3>
            <p className="text-slate-300 leading-relaxed">
              Yes. Both services bind to <code className="text-emerald-300">0.0.0.0</code> with LAN CORS enabled, so teammates can reach the portal via your host IP on port <code className="text-emerald-300">3003</code>.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
