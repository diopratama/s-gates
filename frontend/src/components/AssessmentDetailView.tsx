"use client";

import React, { useState } from "react";
import {
  Check,
  Copy,
  Download,
  ExternalLink,
  FileText,
  FolderTree,
  HelpCircle,
  Package,
  RefreshCw,
  Search,
  ShieldAlert,
  Terminal,
  Ticket,
  Trash2,
  UserCheck,
  XCircle,
} from "lucide-react";
import type {
  AssessmentDetail,
  AssessmentSummary,
  UserPersona,
} from "@/lib/api";
import {
  formatDecisionLabel,
  formatStatusLabel,
  renderSeverityBadge,
  renderStatusBadge,
} from "@/components/badges";

export type StudioSubTab = "summary" | "findings" | "dependencies" | "compliance";

interface AssessmentDetailViewProps {
  selectedAssessment: AssessmentDetail | null;
  assessmentsList: AssessmentSummary[];
  currentUser: UserPersona | null;
  studioSubTab: StudioSubTab;
  setStudioSubTab: (tab: StudioSubTab) => void;
  onSelectAssessment: (code: string) => void;
  onStartNewScan: () => void;
  onEvidenceDownload: (path: string, filename: string) => void;
  onReevaluate: () => void;
  onDeleteAssessment: (code: string) => void;
  deletingCode: string | null;
  onUpdateFindingStatus: (findingId: number, status: string) => void;
  onUpdateDependencyStatus: (depId: number, reviewerStatus: string) => void;
  avStatusInput: string;
  setAvStatusInput: (val: string) => void;
  avRefInput: string;
  setAvRefInput: (val: string) => void;
  avNotesInput: string;
  setAvNotesInput: (val: string) => void;
  sbStatusInput: string;
  setSbStatusInput: (val: string) => void;
  sbTechInput: string;
  setSbTechInput: (val: string) => void;
  sbNotesInput: string;
  setSbNotesInput: (val: string) => void;
  onSaveManualGates: () => void;
  decisionNotes: string;
  setDecisionNotes: (val: string) => void;
  onRecordDecision: (decision: string) => void;
}

export default function AssessmentDetailView({
  selectedAssessment,
  assessmentsList,
  currentUser,
  studioSubTab,
  setStudioSubTab,
  onSelectAssessment,
  onStartNewScan,
  onEvidenceDownload,
  onReevaluate,
  onDeleteAssessment,
  deletingCode,
  onUpdateFindingStatus,
  onUpdateDependencyStatus,
  avStatusInput,
  setAvStatusInput,
  avRefInput,
  setAvRefInput,
  avNotesInput,
  setAvNotesInput,
  sbStatusInput,
  setSbStatusInput,
  sbTechInput,
  setSbTechInput,
  sbNotesInput,
  setSbNotesInput,
  onSaveManualGates,
  decisionNotes,
  setDecisionNotes,
  onRecordDecision,
}: AssessmentDetailViewProps) {
  const [scannerFilter, setScannerFilter] = useState("ALL");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [findingSearch, setFindingSearch] = useState("");
  const [copiedHash, setCopiedHash] = useState(false);

  if (!selectedAssessment) {
    return (
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-12 text-center max-w-xl mx-auto space-y-4">
        <div className="w-12 h-12 rounded-xl bg-slate-800/80 border border-slate-700 flex items-center justify-center mx-auto">
          <Terminal className="h-6 w-6 text-emerald-400" aria-hidden="true" />
        </div>
        <h3 className="text-lg font-bold text-white">No Assessment Selected</h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          Pick a past assessment below or run a new code scan.
        </p>
        {assessmentsList.length > 0 ? (
          <div className="pt-2 flex flex-col items-center gap-2">
            <label htmlFor="empty-assessment-select" className="sr-only">
              Select assessment
            </label>
            <select
              id="empty-assessment-select"
              onChange={(e) => {
                if (e.target.value) onSelectAssessment(e.target.value);
              }}
              className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs font-mono font-bold text-emerald-300 focus-visible:ring-2 focus-visible:ring-emerald-400"
              defaultValue=""
            >
              <option value="" disabled>
                Select assessment...
              </option>
              {assessmentsList.map((a) => (
                <option key={a.assessment_code} value={a.assessment_code}>
                  {a.assessment_code}: {a.application_name} (v{a.version}) [{formatStatusLabel(a.technical_status)}]
                </option>
              ))}
            </select>
          </div>
        ) : (
          <div className="pt-2">
            <button
              type="button"
              onClick={onStartNewScan}
              className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-4 py-2 text-xs font-bold text-slate-950 transition focus-visible:ring-2 focus-visible:ring-emerald-300"
            >
              Start New Scan
            </button>
          </div>
        )}
      </div>
    );
  }

  const filteredFindings = selectedAssessment.findings.filter((f) => {
    if (scannerFilter !== "ALL" && f.scanner !== scannerFilter) return false;
    if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;
    if (statusFilter !== "ALL" && f.status !== statusFilter) return false;
    if (findingSearch.trim()) {
      const q = findingSearch.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        f.file_path.toLowerCase().includes(q) ||
        f.package_name.toLowerCase().includes(q) ||
        f.vulnerability_id.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const hasAnyItsmTicket = filteredFindings.some((f) => Boolean(f.itsm_ticket_id));
  const canReview = currentUser?.role !== "CITIZEN_DEVELOPER";

  function handleCopySha() {
    if (!selectedAssessment?.sha256_hash) return;
    navigator.clipboard?.writeText(selectedAssessment.sha256_hash);
    setCopiedHash(true);
    window.setTimeout(() => setCopiedHash(false), 1800);
  }

  function resetFindingFilters() {
    setScannerFilter("ALL");
    setSeverityFilter("ALL");
    setStatusFilter("ALL");
    setFindingSearch("");
  }

  return (
    <div className="space-y-6">
      {/* Assessment Header & 4-Tab Bar */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div className="flex flex-wrap items-center gap-3">
            <label htmlFor="active-assessment-select" className="sr-only">
              Switch assessment
            </label>
            <select
              id="active-assessment-select"
              value={selectedAssessment.assessment_code}
              onChange={(e) => onSelectAssessment(e.target.value)}
              className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs font-mono font-bold text-emerald-300 focus-visible:ring-2 focus-visible:ring-emerald-400"
            >
              {assessmentsList.map((a) => (
                <option key={a.assessment_code} value={a.assessment_code}>
                  {a.assessment_code}: {a.application_name} (v{a.version}) [{formatStatusLabel(a.technical_status)}]
                </option>
              ))}
            </select>

            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-lg font-bold text-white">
                  {selectedAssessment.application?.name}
                </h1>
                <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-mono text-slate-200">
                  v{selectedAssessment.version}
                </span>
                {renderStatusBadge(selectedAssessment.technical_status)}
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 mt-1 font-mono">
                <span>
                  {selectedAssessment.file_count} files · {selectedAssessment.zip_filename} · SHA-256:{" "}
                  {selectedAssessment.sha256_hash.slice(0, 12)}...
                </span>
                <button
                  type="button"
                  onClick={handleCopySha}
                  className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-950 px-1.5 py-0.5 text-xs text-slate-300 hover:text-white transition focus-visible:ring-2 focus-visible:ring-emerald-400"
                  aria-label="Copy full SHA-256 hash"
                >
                  {copiedHash ? (
                    <>
                      <Check className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3 w-3" aria-hidden="true" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() =>
                onEvidenceDownload(
                  `/api/v1/evidence/${selectedAssessment.assessment_code}/download?${new URLSearchParams({ path: "Reports/scan-summary.html" })}`,
                  `${selectedAssessment.assessment_code}-scan-summary.html`
                )
              }
              className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 px-3 py-2 text-xs font-semibold text-slate-200 transition focus-visible:ring-2 focus-visible:ring-emerald-400"
            >
              <ExternalLink className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
              HTML Report
            </button>
            <button
              type="button"
              onClick={() =>
                onEvidenceDownload(
                  `/api/v1/evidence/${selectedAssessment.assessment_code}/bundle.zip`,
                  `${selectedAssessment.assessment_code}-Evidence-Vault.zip`
                )
              }
              className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 px-3 py-2 text-xs font-semibold text-slate-200 transition focus-visible:ring-2 focus-visible:ring-emerald-400"
            >
              <Download className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
              Vault (.zip)
            </button>
            <button
              type="button"
              onClick={onReevaluate}
              className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 px-3 py-2 text-xs font-medium text-slate-200 transition focus-visible:ring-2 focus-visible:ring-emerald-400"
              title="Recompute risk status from stored findings"
            >
              <RefreshCw className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
              Re-evaluate
            </button>

            {currentUser?.role === "ADMIN" && (
              <button
                type="button"
                onClick={() => onDeleteAssessment(selectedAssessment.assessment_code)}
                disabled={deletingCode === selectedAssessment.assessment_code}
                className="inline-flex items-center gap-1.5 rounded-lg bg-rose-950/60 hover:bg-rose-900 border border-rose-700/60 px-3 py-2 text-xs font-semibold text-rose-200 transition disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-rose-400"
                title="Delete this assessment and its Evidence Vault folder"
              >
                <Trash2 className="h-3.5 w-3.5 text-rose-400" aria-hidden="true" />
                {deletingCode === selectedAssessment.assessment_code ? "Deleting..." : "Delete"}
              </button>
            )}
          </div>
        </div>

        {/* 4 Sub-Tabs */}
        <div role="tablist" aria-label="Assessment sections" className="flex items-center gap-2 pt-3 overflow-x-auto">
          {[
            { id: "summary", label: "Summary", icon: Terminal },
            {
              id: "findings",
              label: `Findings (${selectedAssessment.findings.length})`,
              icon: ShieldAlert,
            },
            {
              id: "dependencies",
              label: `Dependencies (${selectedAssessment.dependencies.length})`,
              icon: Package,
            },
            {
              id: "compliance",
              label: "Evidence & Checks",
              icon: FolderTree,
            },
          ].map((st) => {
            const Icon = st.icon;
            const active = studioSubTab === st.id;
            return (
              <button
                type="button"
                role="tab"
                aria-selected={active}
                key={st.id}
                onClick={() => setStudioSubTab(st.id as StudioSubTab)}
                className={`inline-flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-xs font-semibold transition whitespace-nowrap focus-visible:ring-2 focus-visible:ring-emerald-400 ${
                  active
                    ? "bg-emerald-500 text-slate-950 shadow"
                    : "bg-slate-950/70 text-slate-300 hover:bg-slate-800 border border-slate-800"
                }`}
              >
                <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                {st.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* TAB 1: SUMMARY */}
      {studioSubTab === "summary" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-5">
            {!selectedAssessment.zip_valid && (
              <div role="alert" className="rounded-xl bg-rose-950/80 border border-rose-500/50 p-4">
                <h3 className="text-sm font-bold text-rose-200 flex items-center gap-2">
                  <XCircle className="h-4 w-4 text-rose-400" aria-hidden="true" />
                  Archive Blocked by ZIP Security Gate
                </h3>
                <ul className="mt-2 list-disc list-inside text-xs text-rose-200 space-y-1 font-mono">
                  {selectedAssessment.zip_validation_errors.map((err, i) => (
                    <li key={i}>{err}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Decision Summary & Next Steps */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
              <div className="flex items-center gap-2">
                <HelpCircle className="h-4 w-4 text-emerald-400" aria-hidden="true" />
                <h3 className="text-sm font-bold text-white">
                  Decision Summary &amp; Next Steps
                </h3>
              </div>

              {selectedAssessment.technical_status === "REJECT" && (
                <div className="rounded-xl border border-rose-500/40 bg-rose-950/35 p-4 space-y-1.5 text-xs">
                  <div className="font-bold text-rose-200">
                    Blocked: Critical security risks found
                  </div>
                  <p className="text-slate-300 leading-relaxed">
                    Rotate exposed secrets, upgrade or remove vulnerable or malicious packages, fix unsafe execution calls, and scan again.
                  </p>
                </div>
              )}
              {selectedAssessment.technical_status === "REVIEW" && (
                <div className="rounded-xl border border-amber-500/40 bg-amber-950/35 p-4 space-y-1.5 text-xs">
                  <div className="font-bold text-amber-200">
                    Review Required before Release
                  </div>
                  <p className="text-slate-300 leading-relaxed">
                    Inspect flagged findings, abandoned packages, or pending manual checks before approving deployment.
                  </p>
                </div>
              )}
              {selectedAssessment.technical_status === "PASS-WITH-MANUAL-CHECKS" && (
                <div className="rounded-xl border border-emerald-500/40 bg-emerald-950/35 p-4 space-y-1.5 text-xs">
                  <div className="font-bold text-emerald-200">
                    Passed Automated Security Checks
                  </div>
                  <p className="text-slate-300 leading-relaxed">
                    Zero critical CVEs, zero exposed secrets, and zero high-risk SAST findings detected. Record manual checks under Evidence &amp; Checks if required.
                  </p>
                </div>
              )}
              {selectedAssessment.technical_status === "SCAN-ERROR" && (
                <div className="rounded-xl border border-slate-700 bg-slate-950 p-4 space-y-1.5 text-xs">
                  <div className="font-bold text-slate-200">Scan Interrupted</div>
                  <p className="text-slate-300 leading-relaxed">
                    The scan did not complete cleanly. Check the archive, repository URL, or scanner status and run the scan again.
                  </p>
                </div>
              )}

              {selectedAssessment.status_reasons.length > 0 && (
                <ul className="space-y-1 text-xs text-slate-300 list-disc list-inside">
                  {selectedAssessment.status_reasons.map((r, idx) => (
                    <li key={idx}>{r}</li>
                  ))}
                </ul>
              )}
            </div>

            {/* Scanner Breakdown */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-sky-300">
                    {selectedAssessment.scanner_versions?.mode === "external"
                      ? `Trivy (v${selectedAssessment.scanner_versions.trivy || selectedAssessment.scanner_versions.trivy_version || "0.76.2"})`
                      : "Dependency SCA"}
                  </span>
                  <span className="text-xs font-mono text-slate-400">SCA</span>
                </div>
                <div className="grid grid-cols-2 gap-1.5 text-xs font-mono">
                  <div className="text-slate-300">
                    Crit: <strong className="text-rose-300">{selectedAssessment.trivy_summary.critical || 0}</strong>
                  </div>
                  <div className="text-slate-300">
                    High: <strong className="text-orange-300">{selectedAssessment.trivy_summary.high || 0}</strong>
                  </div>
                  <div className="text-slate-300">
                    Med: <strong className="text-amber-200">{selectedAssessment.trivy_summary.medium || 0}</strong>
                  </div>
                  <div className="text-slate-300">
                    Low: <strong className="text-sky-200">{selectedAssessment.trivy_summary.low || 0}</strong>
                  </div>
                </div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-rose-300">
                    {selectedAssessment.scanner_versions?.mode === "external"
                      ? `Gitleaks (v${selectedAssessment.scanner_versions.gitleaks || selectedAssessment.scanner_versions.gitleaks_version || "8.30.1"})`
                      : "Secrets"}
                  </span>
                  <span className="text-xs font-mono text-emerald-300">Masked</span>
                </div>
                <div className="text-xs font-mono text-slate-300">
                  Detected:{" "}
                  <strong
                    className={
                      (selectedAssessment.gitleaks_summary.secrets_detected || 0) > 0
                        ? "text-rose-300"
                        : "text-emerald-300"
                    }
                  >
                    {selectedAssessment.gitleaks_summary.secrets_detected || 0}
                  </strong>
                </div>
                <p className="text-xs text-slate-400 mt-1.5">
                  Secret values are masked before storage.
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-amber-300">
                    {selectedAssessment.scanner_versions?.mode === "external"
                      ? `Semgrep (v${selectedAssessment.scanner_versions.semgrep || selectedAssessment.scanner_versions.semgrep_version || "1.95.0"})`
                      : "SAST"}
                  </span>
                  <span className="text-xs font-mono text-slate-400">Code</span>
                </div>
                <div className="grid grid-cols-2 gap-1.5 text-xs font-mono">
                  <div className="text-slate-300">
                    Crit: <strong className="text-rose-300">{selectedAssessment.semgrep_summary.critical || 0}</strong>
                  </div>
                  <div className="text-slate-300">
                    High: <strong className="text-orange-300">{selectedAssessment.semgrep_summary.high || 0}</strong>
                  </div>
                  <div className="text-slate-300">
                    Med: <strong className="text-amber-200">{selectedAssessment.semgrep_summary.medium || 0}</strong>
                  </div>
                  <div className="text-slate-300">
                    Low: <strong className="text-sky-200">{selectedAssessment.semgrep_summary.low || 0}</strong>
                  </div>
                </div>
              </div>
            </div>

            {/* Application Metadata */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
              <h3 className="text-sm font-bold text-white mb-3">
                Application Details
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs">
                <div>
                  <span className="text-slate-400 block">App ID</span>
                  <span className="font-mono font-semibold text-white">
                    {selectedAssessment.application?.sgates_app_id}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">Business Owner</span>
                  <span className="font-semibold text-white">
                    {selectedAssessment.application?.business_owner || "-"}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">Technical Owner</span>
                  <span className="font-semibold text-white">
                    {selectedAssessment.application?.technical_owner || "-"}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">AI Tool</span>
                  <span className="font-semibold text-emerald-300">
                    {selectedAssessment.application?.ai_tool}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">Data Class</span>
                  <span className="font-semibold text-white">
                    {selectedAssessment.application?.data_classification}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">Admin Privileges</span>
                  <span className="font-semibold text-white">
                    {selectedAssessment.application?.requires_admin_privileges ? "Yes" : "No"}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Reviewer Sign-Off */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 flex flex-col justify-between space-y-4">
            <div className="space-y-4">
              <div className="border-b border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <UserCheck className="h-4 w-4 text-emerald-400" aria-hidden="true" />
                  Reviewer Sign-Off
                </h3>
                <p className="text-xs text-slate-300 mt-1">
                  Current Status:{" "}
                  <strong className="text-emerald-300">
                    {formatDecisionLabel(selectedAssessment.final_decision)}
                  </strong>
                </p>
              </div>

              <div className="rounded-xl bg-slate-950/80 border border-slate-800 p-3.5 text-xs space-y-1.5">
                <div className="flex justify-between">
                  <span className="text-slate-400">Antivirus Evidence</span>
                  <span className="font-semibold text-white">
                    {selectedAssessment.av_status}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Sandbox Gate</span>
                  <span
                    className={`font-semibold ${
                      selectedAssessment.sandbox_required &&
                      selectedAssessment.sandbox_status !== "Passed"
                        ? "text-amber-300"
                        : "text-emerald-300"
                    }`}
                  >
                    {selectedAssessment.sandbox_status}
                  </span>
                </div>
              </div>

              {canReview ? (
                <>
                  <div>
                    <label
                      htmlFor="reviewer-decision-notes"
                      className="block text-xs font-semibold text-slate-200 mb-1"
                    >
                      Decision Notes
                    </label>
                    <textarea
                      id="reviewer-decision-notes"
                      rows={3}
                      value={decisionNotes}
                      onChange={(e) => setDecisionNotes(e.target.value)}
                      placeholder="Add review notes, conditions, or fix instructions..."
                      className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white placeholder:text-slate-400 focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
                    />
                  </div>

                  <div className="space-y-2 pt-1">
                    <button
                      type="button"
                      onClick={() => onRecordDecision("PILOT_APPROVED")}
                      className="w-full rounded-lg bg-emerald-500 hover:bg-emerald-400 py-2.5 text-xs font-bold text-slate-950 transition shadow focus-visible:ring-2 focus-visible:ring-emerald-300"
                    >
                      Approve Pilot
                    </button>
                    <button
                      type="button"
                      onClick={() => onRecordDecision("REMEDIATION_REQUESTED")}
                      className="w-full rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 py-2 text-xs font-semibold text-amber-200 transition focus-visible:ring-2 focus-visible:ring-amber-400"
                    >
                      Request Remediation
                    </button>
                    <button
                      type="button"
                      onClick={() => onRecordDecision("RISK_ACCEPTED")}
                      className="w-full rounded-lg bg-sky-500/20 hover:bg-sky-500/30 border border-sky-500/40 py-2 text-xs font-semibold text-sky-200 transition focus-visible:ring-2 focus-visible:ring-sky-400"
                    >
                      Accept Risk (Security Reviewer)
                    </button>
                    <button
                      type="button"
                      onClick={() => onRecordDecision("REJECTED")}
                      className="w-full rounded-lg bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 py-2 text-xs font-semibold text-rose-200 transition focus-visible:ring-2 focus-visible:ring-rose-400"
                    >
                      Reject Application
                    </button>
                  </div>
                </>
              ) : (
                <div className="rounded-xl bg-slate-950/70 border border-slate-800 p-4 text-xs text-slate-300 leading-relaxed">
                  Awaiting Security or IT Reviewer sign-off. You can view findings, inspect packages, and download Evidence Vault reports.
                </div>
              )}
            </div>

            {selectedAssessment.decision_by && (
              <div className="border-t border-slate-800 pt-3 text-xs text-slate-400">
                Last decision by{" "}
                <strong className="text-slate-200">{selectedAssessment.decision_by}</strong>{" "}
                ({selectedAssessment.decision_role})
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: FINDINGS */}
      {studioSubTab === "findings" && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-base font-bold text-white">Findings</h3>
              <p className="text-xs text-slate-400">
                Filter findings by scanner, severity, or status. Secret values are masked as <code>********************</code>.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search className="h-3.5 w-3.5 text-slate-400 absolute left-2.5 top-2.5" aria-hidden="true" />
                <input
                  id="findings-search"
                  type="text"
                  aria-label="Search findings"
                  placeholder="Search file, package, CVE..."
                  value={findingSearch}
                  onChange={(e) => setFindingSearch(e.target.value)}
                  className="rounded-lg bg-slate-950 border border-slate-800 pl-8 pr-3 py-1.5 text-xs text-white placeholder:text-slate-400 focus-visible:ring-2 focus-visible:ring-emerald-400"
                />
              </div>
              <select
                aria-label="Filter by scanner"
                value={scannerFilter}
                onChange={(e) => setScannerFilter(e.target.value)}
                className="rounded-lg bg-slate-950 border border-slate-800 px-2.5 py-1.5 text-xs text-slate-200 focus-visible:ring-2 focus-visible:ring-emerald-400"
              >
                <option value="ALL">All Scanners</option>
                <option value="Trivy">Trivy (SCA &amp; Config)</option>
                <option value="OSV-Scanner">OSV-Scanner (MAL-*)</option>
                <option value="GuardDog">GuardDog</option>
                <option value="RegistryMetadata">Registry Metadata</option>
                <option value="Gitleaks">Gitleaks</option>
                <option value="Semgrep">Semgrep</option>
                <option value="Legacy heuristic">Legacy rules</option>
              </select>
              <select
                aria-label="Filter by severity"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="rounded-lg bg-slate-950 border border-slate-800 px-2.5 py-1.5 text-xs text-slate-200 focus-visible:ring-2 focus-visible:ring-emerald-400"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
              <select
                aria-label="Filter by finding status"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="rounded-lg bg-slate-950 border border-slate-800 px-2.5 py-1.5 text-xs text-slate-200 focus-visible:ring-2 focus-visible:ring-emerald-400"
              >
                <option value="ALL">All Statuses</option>
                <option value="Open">Open</option>
                <option value="Accepted">Accepted</option>
                <option value="False Positive">False Positive</option>
                <option value="Resolved">Resolved</option>
              </select>
            </div>
          </div>

          {filteredFindings.length === 0 ? (
            <div className="py-10 text-center space-y-3">
              <p className="text-xs text-slate-300">
                {selectedAssessment.findings.length === 0
                  ? "Zero security findings reported in this scan."
                  : "No findings match the current filters."}
              </p>
              {selectedAssessment.findings.length > 0 && (
                <button
                  type="button"
                  onClick={resetFindingFilters}
                  className="rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 px-3.5 py-2 text-xs font-semibold text-white transition focus-visible:ring-2 focus-visible:ring-emerald-400"
                >
                  Reset filters
                </button>
              )}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-300 bg-slate-950/60">
                    <th className="py-2.5 px-3">ID / Scanner</th>
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3">Location</th>
                    <th className="py-2.5 px-3">Issue &amp; Fix</th>
                    <th className="py-2.5 px-3">Status</th>
                    {hasAnyItsmTicket && (
                      <th className="py-2.5 px-3 text-right">Ticket</th>
                    )}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {filteredFindings.map((f) => (
                    <tr key={f.id} className="hover:bg-slate-950/40 align-top">
                      <td className="py-3 px-3 font-mono whitespace-nowrap">
                        <div className="font-bold text-slate-200">{f.finding_code}</div>
                        <span className="text-xs text-emerald-300">
                          {f.scanner} ({f.finding_type})
                        </span>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        {renderSeverityBadge(f.severity)}
                      </td>
                      <td className="py-3 px-3 font-mono text-xs">
                        <div className="text-sky-300">
                          {f.file_path}:{f.line_number}
                        </div>
                        {f.package_name && f.package_name !== "-" && (
                          <div className="text-slate-300 mt-0.5">
                            {f.package_name} ({f.installed_version} → {f.fixed_version})
                          </div>
                        )}
                        {f.finding_type === "secret" && (
                          <div className="mt-1 inline-flex rounded bg-rose-950/90 border border-rose-500/40 px-1.5 py-0.5 text-xs text-rose-200">
                            {f.redacted_value}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-3 max-w-md">
                        <div className="font-bold text-white">{f.title}</div>
                        <p className="text-slate-300 text-xs mt-0.5">{f.description}</p>
                        <p className="text-emerald-300 text-xs mt-1">
                          Fix: {f.recommendation}
                        </p>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <select
                          aria-label={`Status for finding ${f.finding_code}`}
                          value={f.status}
                          onChange={(e) => onUpdateFindingStatus(f.id, e.target.value)}
                          disabled={!canReview}
                          className="rounded bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs font-semibold text-white disabled:opacity-60 focus-visible:ring-2 focus-visible:ring-emerald-400"
                        >
                          <option value="Open">Open</option>
                          <option value="Accepted">Accepted</option>
                          <option value="False Positive">False Positive</option>
                          <option value="Resolved">Resolved</option>
                        </select>
                      </td>
                      {hasAnyItsmTicket && (
                        <td className="py-3 px-3 text-right whitespace-nowrap">
                          {f.itsm_ticket_id ? (
                            <span className="inline-flex items-center gap-1 rounded bg-sky-500/20 border border-sky-500/40 px-2.5 py-1 text-xs font-mono text-sky-200">
                              <Ticket className="h-3 w-3" aria-hidden="true" />
                              {f.itsm_ticket_id}
                            </span>
                          ) : (
                            <span className="text-slate-400">-</span>
                          )}
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: DEPENDENCIES */}
      {studioSubTab === "dependencies" && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
          <div>
            <h3 className="text-base font-bold text-white">Dependencies &amp; Supply Chain</h3>
            <p className="text-xs text-slate-400">
              Shows known CVEs, registry maintenance status, and malicious or typosquatted package alerts.
            </p>
          </div>

          {selectedAssessment.dependencies.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-400">
              No dependency manifests detected in this scan.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-300 bg-slate-950/60">
                    <th className="py-2.5 px-3">Package</th>
                    <th className="py-2.5 px-3">Ecosystem</th>
                    <th className="py-2.5 px-3">CVE</th>
                    <th className="py-2.5 px-3">Supply-Chain Risk</th>
                    <th className="py-2.5 px-3">Maintainer &amp; Release</th>
                    <th className="py-2.5 px-3">Review Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {selectedAssessment.dependencies.map((d) => (
                    <tr key={d.id} className="hover:bg-slate-950/40">
                      <td className="py-3 px-3 font-mono">
                        <div className="font-bold text-white">
                          {d.package_name}@{d.version}
                        </div>
                        {d.alternative_package !== "-" && (
                          <div className="text-xs text-emerald-300">
                            Alt: {d.alternative_package}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-3 uppercase font-mono text-xs text-slate-300">
                        {d.ecosystem}
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex items-center gap-2">
                          {renderSeverityBadge(d.severity)}
                          <span className="font-mono text-xs text-slate-200">
                            {d.vulnerability_id}
                          </span>
                        </div>
                        {d.fixed_version !== "-" && (
                          <div className="text-xs text-slate-400 mt-0.5">
                            Fixed in: {d.fixed_version}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`inline-flex rounded px-2 py-0.5 text-xs font-semibold border ${
                            d.malicious_risk.includes("Malicious") ||
                            d.malicious_risk.includes("Typosquatting")
                              ? "bg-rose-500/20 text-rose-200 border-rose-500/40"
                              : d.malicious_risk.includes("Vulnerable")
                              ? "bg-amber-500/15 text-amber-200 border-amber-500/30"
                              : "bg-emerald-500/15 text-emerald-200 border-emerald-500/30"
                          }`}
                        >
                          {d.malicious_risk}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-xs text-slate-300">
                        <div>{d.maintainer_status}</div>
                        <div className="text-slate-400">
                          {d.last_release_date} · {d.publisher_identity}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <select
                          aria-label={`Review status for ${d.package_name}`}
                          value={d.reviewer_status}
                          onChange={(e) => onUpdateDependencyStatus(d.id, e.target.value)}
                          disabled={!canReview}
                          className="rounded bg-slate-950 border border-slate-700 px-2.5 py-1.5 text-xs font-semibold text-white disabled:opacity-60 focus-visible:ring-2 focus-visible:ring-emerald-400"
                        >
                          <option value="SUPPORTED">SUPPORTED</option>
                          <option value="MAINTENANCE REVIEW">MAINTENANCE REVIEW</option>
                          <option value="ABANDONED">ABANDONED</option>
                          <option value="UNKNOWN">UNKNOWN</option>
                        </select>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: EVIDENCE & CHECKS */}
      {studioSubTab === "compliance" && (
        <div className="space-y-6">
          {/* Manual Antivirus & Sandbox Checks */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
              <div className="border-b border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-white">
                  Manual Antivirus Evidence
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Record external antivirus results. Selecting Threat Detected blocks approval.
                </p>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {[
                  "Pending",
                  "No Threat Detected",
                  "Threat Detected",
                  "Investigation Required",
                ].map((opt) => (
                  <button
                    type="button"
                    key={opt}
                    aria-pressed={avStatusInput === opt}
                    disabled={!canReview}
                    onClick={() => setAvStatusInput(opt)}
                    className={`py-2 px-2.5 rounded-lg text-xs font-semibold border transition disabled:opacity-60 focus-visible:ring-2 focus-visible:ring-emerald-400 ${
                      avStatusInput === opt
                        ? opt === "Pending"
                          ? "bg-slate-600 text-white border-slate-400"
                          : opt === "Threat Detected"
                          ? "bg-rose-500 text-slate-950 border-rose-400"
                          : opt === "Investigation Required"
                          ? "bg-amber-500 text-slate-950 border-amber-400"
                          : "bg-emerald-500 text-slate-950 border-emerald-400"
                        : "bg-slate-950 border-slate-800 text-slate-300"
                    }`}
                  >
                    {opt}
                  </button>
                ))}
              </div>

              <div>
                <label
                  htmlFor="av-ref-id"
                  className="block text-xs font-semibold text-slate-200 mb-1"
                >
                  Evidence Reference ID
                </label>
                <input
                  id="av-ref-id"
                  type="text"
                  value={avRefInput}
                  disabled={!canReview}
                  onChange={(e) => setAvRefInput(e.target.value)}
                  className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white font-mono disabled:opacity-60 focus-visible:ring-2 focus-visible:ring-emerald-400"
                />
              </div>

              <div>
                <label
                  htmlFor="av-notes"
                  className="block text-xs font-semibold text-slate-200 mb-1"
                >
                  Notes
                </label>
                <textarea
                  id="av-notes"
                  rows={2}
                  value={avNotesInput}
                  disabled={!canReview}
                  onChange={(e) => setAvNotesInput(e.target.value)}
                  className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white disabled:opacity-60 focus-visible:ring-2 focus-visible:ring-emerald-400"
                />
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
              <div className="border-b border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-white">
                  Manual Sandbox Evidence
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Record behavioral checks when executables, background services, admin privileges, or sensitive data require sandbox testing.
                </p>
              </div>

              {selectedAssessment.sandbox_reasons.length > 0 ? (
                <div className="rounded-xl bg-amber-950/40 border border-amber-500/40 p-3 text-xs text-amber-200">
                  <div className="font-bold mb-1">Sandbox Triggers:</div>
                  <ul className="list-disc list-inside space-y-0.5 text-xs">
                    {selectedAssessment.sandbox_reasons.map((r, idx) => (
                      <li key={idx}>{r}</li>
                    ))}
                  </ul>
                </div>
              ) : (
                <div className="rounded-xl bg-emerald-950/30 border border-emerald-500/30 p-3 text-xs text-emerald-200">
                  No automatic sandbox triggers detected.
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label
                    htmlFor="sb-status"
                    className="block text-xs font-semibold text-slate-200 mb-1"
                  >
                    Validation Status
                  </label>
                  <select
                    id="sb-status"
                    value={sbStatusInput}
                    disabled={!canReview}
                    onChange={(e) => setSbStatusInput(e.target.value)}
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white disabled:opacity-60 focus-visible:ring-2 focus-visible:ring-emerald-400"
                  >
                    <option value="Not Required">Not Required</option>
                    <option value="Required - Pending">Required - Pending</option>
                    <option value="Passed">Passed (Clean)</option>
                    <option value="Failed">Failed (Malicious Behavior)</option>
                  </select>
                </div>
                <div>
                  <label
                    htmlFor="sb-environment"
                    className="block text-xs font-semibold text-slate-200 mb-1"
                  >
                    Sandbox Environment
                  </label>
                  <select
                    id="sb-environment"
                    value={sbTechInput}
                    disabled={!canReview}
                    onChange={(e) => setSbTechInput(e.target.value)}
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white disabled:opacity-60 focus-visible:ring-2 focus-visible:ring-emerald-400"
                  >
                    <option value="Windows Sandbox">Windows Sandbox</option>
                    <option value="Hyper-V Isolated VM">Hyper-V Isolated VM</option>
                    <option value="Dedicated Disposable Test VM">Dedicated Disposable Test VM</option>
                  </select>
                </div>
              </div>

              <div>
                <label
                  htmlFor="sb-observations"
                  className="block text-xs font-semibold text-slate-200 mb-1"
                >
                  Observations
                </label>
                <textarea
                  id="sb-observations"
                  rows={2}
                  value={sbNotesInput}
                  disabled={!canReview}
                  onChange={(e) => setSbNotesInput(e.target.value)}
                  placeholder="Process, filesystem, or network observations..."
                  className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white placeholder:text-slate-400 disabled:opacity-60 focus-visible:ring-2 focus-visible:ring-emerald-400"
                />
              </div>

              {canReview && (
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={onSaveManualGates}
                    className="rounded-lg bg-emerald-500 hover:bg-emerald-400 px-4 py-2 text-xs font-bold text-slate-950 transition shadow focus-visible:ring-2 focus-visible:ring-emerald-300"
                  >
                    Save Manual Checks
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Evidence Vault Files */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-4 pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <FolderTree className="h-4 w-4 text-emerald-400" aria-hidden="true" />
                  Evidence Vault ({selectedAssessment.vault_artifacts.length} files)
                </h3>
                <p className="text-xs text-slate-400">
                  Retains source archive, file inventory, scanner JSON/HTML reports, and decision files.
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  onEvidenceDownload(
                    `/api/v1/evidence/${selectedAssessment.assessment_code}/bundle.zip`,
                    `${selectedAssessment.assessment_code}-Evidence-Vault.zip`
                  )
                }
                className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-3.5 py-2 text-xs font-bold text-slate-950 transition focus-visible:ring-2 focus-visible:ring-emerald-300"
              >
                <Download className="h-3.5 w-3.5" aria-hidden="true" />
                Download Vault (.zip)
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {selectedAssessment.vault_artifacts.map((art) => (
                <div
                  key={art.relative_path}
                  className="rounded-xl bg-slate-950/80 border border-slate-800 p-3 flex items-center justify-between"
                >
                  <div className="min-w-0 pr-2">
                    <div className="text-xs font-mono uppercase text-emerald-300">
                      {art.folder}/
                    </div>
                    <div className="text-xs font-mono font-bold text-white truncate">
                      {art.filename}
                    </div>
                    <div className="text-xs text-slate-400">
                      {(art.size_bytes / 1024).toFixed(2)} KB
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() =>
                      onEvidenceDownload(
                        `/api/v1/evidence/${selectedAssessment.assessment_code}/download?${new URLSearchParams({ path: art.relative_path })}`,
                        `${selectedAssessment.assessment_code}-${art.filename}`
                      )
                    }
                    className="shrink-0 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 px-2.5 py-1.5 text-xs font-semibold text-slate-200 inline-flex items-center gap-1 focus-visible:ring-2 focus-visible:ring-emerald-400"
                  >
                    <Download className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                    Download
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Assessment Audit History */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <FileText className="h-4 w-4 text-emerald-400" aria-hidden="true" />
              Assessment Audit History ({selectedAssessment.audit_history.length})
            </h3>
            <div className="space-y-2">
              {selectedAssessment.audit_history.map((ev) => (
                <div
                  key={ev.id}
                  className="rounded-xl bg-slate-950/80 border border-slate-800 p-3 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono font-bold text-emerald-300">
                      {ev.event_type}
                    </span>
                    <span className="font-mono text-xs text-slate-400">
                      {ev.actor_email} ({ev.actor_role})
                    </span>
                  </div>
                  <p className="text-slate-200 mt-1">{ev.summary}</p>
                  <div className="mt-1 flex flex-wrap items-center justify-between text-xs font-mono text-slate-400">
                    <span>
                      {ev.previous_state || "-"} → {ev.new_state || "-"}
                    </span>
                    <span>SHA-256: {ev.immutable_signature.slice(0, 20)}...</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
