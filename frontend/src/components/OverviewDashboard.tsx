"use client";

import React, { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Layers,
  Search,
  ShieldX,
} from "lucide-react";
import type { DashboardSummary } from "@/lib/api";
import { renderStatusBadge } from "@/components/badges";

type SummaryFilter = "ALL" | "PASSED" | "REVIEW" | "BLOCKED";

interface OverviewDashboardProps {
  dashboardData: DashboardSummary;
  onStartNewScan: () => void;
  onOpenAssessment: (assessmentCode: string) => void;
}

export default function OverviewDashboard({
  dashboardData,
  onStartNewScan,
  onOpenAssessment,
}: OverviewDashboardProps) {
  const [statusFilter, setStatusFilter] = useState<SummaryFilter>("ALL");
  const [query, setQuery] = useState("");

  const passedCount =
    dashboardData.status_breakdown["PASS-WITH-MANUAL-CHECKS"] || 0;
  const reviewCount = dashboardData.status_breakdown["REVIEW"] || 0;
  const blockedCount =
    (dashboardData.status_breakdown["REJECT"] || 0) +
    (dashboardData.status_breakdown["SCAN-ERROR"] || 0);

  const filteredAssessments = dashboardData.recent_assessments.filter((a) => {
    if (
      statusFilter === "PASSED" &&
      a.technical_status !== "PASS-WITH-MANUAL-CHECKS"
    ) {
      return false;
    }
    if (statusFilter === "REVIEW" && a.technical_status !== "REVIEW") {
      return false;
    }
    if (
      statusFilter === "BLOCKED" &&
      a.technical_status !== "REJECT" &&
      a.technical_status !== "SCAN-ERROR"
    ) {
      return false;
    }
    if (query.trim()) {
      const q = query.toLowerCase();
      return (
        a.application_name.toLowerCase().includes(q) ||
        a.assessment_code.toLowerCase().includes(q) ||
        a.department.toLowerCase().includes(q)
      );
    }
    return true;
  });

  function toggleFilter(next: SummaryFilter) {
    setStatusFilter((prev) => (prev === next ? "ALL" : next));
  }

  return (
    <div className="space-y-6">
      {/* Interactive 4-Card Filter & Summary Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <button
          type="button"
          onClick={() => setStatusFilter("ALL")}
          aria-pressed={statusFilter === "ALL"}
          className={`text-left rounded-xl border p-4 transition focus-visible:ring-2 focus-visible:ring-emerald-400 ${
            statusFilter === "ALL"
              ? "bg-slate-900 border-sky-500/60"
              : "bg-slate-900/70 border-slate-800 hover:border-slate-700"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-300">
            <span>All Scans</span>
            <Layers className="h-4 w-4 text-sky-400" aria-hidden="true" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">
              {dashboardData.kpis.total_assessments_count}
            </span>
            <span className="text-xs text-slate-400">
              across {dashboardData.kpis.registered_apps_count} apps
            </span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => toggleFilter("PASSED")}
          aria-pressed={statusFilter === "PASSED"}
          className={`text-left rounded-xl border p-4 transition focus-visible:ring-2 focus-visible:ring-emerald-400 ${
            statusFilter === "PASSED"
              ? "bg-emerald-950/40 border-emerald-400"
              : "bg-emerald-950/20 border-emerald-500/30 hover:border-emerald-500/60"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-emerald-200">
            <span>Passed</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" aria-hidden="true" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">
              {passedCount}
            </span>
            <span className="text-xs text-slate-300">automated checks clear</span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => toggleFilter("REVIEW")}
          aria-pressed={statusFilter === "REVIEW"}
          className={`text-left rounded-xl border p-4 transition focus-visible:ring-2 focus-visible:ring-amber-400 ${
            statusFilter === "REVIEW"
              ? "bg-amber-950/40 border-amber-400"
              : "bg-amber-950/20 border-amber-500/30 hover:border-amber-500/60"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-amber-200">
            <span>Needs Review</span>
            <AlertTriangle className="h-4 w-4 text-amber-400" aria-hidden="true" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">
              {reviewCount}
            </span>
            <span className="text-xs text-slate-300">awaiting review</span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => toggleFilter("BLOCKED")}
          aria-pressed={statusFilter === "BLOCKED"}
          className={`text-left rounded-xl border p-4 transition focus-visible:ring-2 focus-visible:ring-rose-400 ${
            statusFilter === "BLOCKED"
              ? "bg-rose-950/40 border-rose-400"
              : "bg-rose-950/20 border-rose-500/30 hover:border-rose-500/60"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-rose-200">
            <span>Blocked / Error</span>
            <ShieldX className="h-4 w-4 text-rose-400" aria-hidden="true" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">
              {blockedCount}
            </span>
            <span className="text-xs text-slate-300">
              {dashboardData.kpis.total_secrets_discovered} secrets masked
            </span>
          </div>
        </button>
      </div>

      {/* Recent Assessments */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-white">
              Recent Assessments
            </h2>
            <p className="text-xs text-slate-400">
              {dashboardData.scanner_mode === "heuristic-demo"
                ? "Demo mode active: external scanner binaries are not installed here."
                : "Open any card to review findings, dependencies, and Evidence Vault downloads."}
            </p>
          </div>

          <div className="relative w-full sm:w-64">
            <Search
              className="h-3.5 w-3.5 text-slate-400 absolute left-3 top-2.5"
              aria-hidden="true"
            />
            <input
              type="text"
              aria-label="Filter recent assessments"
              placeholder="Search app, ID, or department..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full rounded-lg bg-slate-950 border border-slate-800 pl-8 pr-3 py-2 text-xs text-white placeholder:text-slate-400 focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
            />
          </div>
        </div>

        {dashboardData.recent_assessments.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-10 text-center">
            <p className="text-sm font-semibold text-slate-200">
              No assessments yet
            </p>
            <p className="mt-1 text-xs text-slate-400">
              Scan a GitHub repository or upload a source ZIP to see results here.
            </p>
            <button
              type="button"
              onClick={onStartNewScan}
              className="mt-4 rounded-lg bg-emerald-500 px-4 py-2 text-xs font-bold text-slate-950 transition hover:bg-emerald-400 focus-visible:ring-2 focus-visible:ring-emerald-300"
            >
              Start a scan
            </button>
          </div>
        ) : filteredAssessments.length === 0 ? (
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-8 text-center space-y-3">
            <p className="text-xs text-slate-300">
              No assessments match the active filter or search.
            </p>
            <button
              type="button"
              onClick={() => {
                setStatusFilter("ALL");
                setQuery("");
              }}
              className="rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 px-3.5 py-2 text-xs font-semibold text-white transition focus-visible:ring-2 focus-visible:ring-emerald-400"
            >
              Reset filters
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {filteredAssessments.map((a) => {
              const trivyTotal =
                (a.trivy_summary?.critical || 0) +
                (a.trivy_summary?.high || 0) +
                (a.trivy_summary?.medium || 0) +
                (a.trivy_summary?.low || 0);
              const secretsTotal = a.gitleaks_summary?.secrets_detected || 0;
              const semgrepTotal =
                (a.semgrep_summary?.critical || 0) +
                (a.semgrep_summary?.high || 0) +
                (a.semgrep_summary?.medium || 0) +
                (a.semgrep_summary?.low || 0);

              return (
                <button
                  type="button"
                  key={a.assessment_code}
                  onClick={() => onOpenAssessment(a.assessment_code)}
                  className="text-left rounded-xl border border-slate-800 bg-slate-900/70 hover:border-emerald-500/50 hover:bg-slate-900 transition p-4 flex flex-col justify-between gap-3 focus-visible:ring-2 focus-visible:ring-emerald-400"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs font-bold text-emerald-400">
                          {a.assessment_code}
                        </span>
                        <span className="text-sm font-bold text-white">
                          {a.application_name}
                        </span>
                        <span className="rounded bg-slate-800 px-1.5 py-0.5 text-xs font-mono text-slate-200">
                          v{a.version}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1">
                        {a.department} · Risk:{" "}
                        <strong className="text-slate-200">{a.risk_level}</strong>
                      </p>
                    </div>
                    {renderStatusBadge(a.technical_status)}
                  </div>

                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                    <span className="rounded-md bg-slate-950 border border-slate-800 px-2.5 py-1 text-slate-300">
                      SCA/CVEs:{" "}
                      <strong
                        className={
                          trivyTotal > 0 ? "text-amber-300" : "text-emerald-300"
                        }
                      >
                        {trivyTotal}
                      </strong>
                      {(a.trivy_summary?.critical || 0) > 0 && (
                        <span className="text-rose-300 ml-1">
                          ({a.trivy_summary.critical} crit)
                        </span>
                      )}
                    </span>
                    <span className="rounded-md bg-slate-950 border border-slate-800 px-2.5 py-1 text-slate-300">
                      Secrets:{" "}
                      <strong
                        className={
                          secretsTotal > 0 ? "text-rose-300" : "text-emerald-300"
                        }
                      >
                        {secretsTotal}
                      </strong>
                    </span>
                    <span className="rounded-md bg-slate-950 border border-slate-800 px-2.5 py-1 text-slate-300">
                      SAST:{" "}
                      <strong
                        className={
                          semgrepTotal > 0 ? "text-amber-300" : "text-emerald-300"
                        }
                      >
                        {semgrepTotal}
                      </strong>
                    </span>
                  </div>

                  <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-xs text-slate-400">
                    <span>
                      AV: <strong className="text-slate-200">{a.av_status}</strong>
                      {" · "}
                      Sandbox:{" "}
                      <strong className="text-slate-200">{a.sandbox_status}</strong>
                    </span>
                    <span className="inline-flex items-center gap-1 text-emerald-300 font-semibold">
                      Open Report
                      <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
