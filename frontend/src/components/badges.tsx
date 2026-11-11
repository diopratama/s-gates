"use client";

import React from "react";
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from "lucide-react";

export function formatStatusLabel(status: string): string {
  switch (status) {
    case "PASS-WITH-MANUAL-CHECKS":
      return "Passed";
    case "REVIEW":
      return "Needs Review";
    case "REJECT":
      return "Blocked";
    case "SCAN-ERROR":
      return "Scan Error";
    default:
      return status;
  }
}

export function formatDecisionLabel(decision: string): string {
  switch (decision) {
    case "PENDING_REVIEW":
      return "Pending Review";
    case "PILOT_APPROVED":
      return "Pilot Approved";
    case "REMEDIATION_REQUESTED":
      return "Fixes Requested";
    case "RISK_ACCEPTED":
      return "Risk Accepted";
    case "REJECTED":
      return "Rejected";
    case "SCAN_ERROR_BLOCKED":
      return "Blocked (Scan Error)";
    default:
      return decision;
  }
}

export function renderStatusBadge(status: string) {
  switch (status) {
    case "PASS-WITH-MANUAL-CHECKS":
      return (
        <span
          title="Automated checks passed (PASS-WITH-MANUAL-CHECKS). Manual antivirus/sandbox sign-off may still apply."
          className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/15 px-2.5 py-0.5 text-xs font-semibold text-emerald-200 border border-emerald-500/35"
        >
          <ShieldCheck className="h-3.5 w-3.5 text-emerald-300" aria-hidden="true" />
          Passed
        </span>
      );
    case "REVIEW":
      return (
        <span
          title="Manual review required before release (REVIEW)."
          className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/15 px-2.5 py-0.5 text-xs font-semibold text-amber-200 border border-amber-500/35"
        >
          <ShieldAlert className="h-3.5 w-3.5 text-amber-300" aria-hidden="true" />
          Needs Review
        </span>
      );
    case "REJECT":
      return (
        <span
          title="Blocked due to critical risk (REJECT)."
          className="inline-flex items-center gap-1.5 rounded-full bg-rose-500/15 px-2.5 py-0.5 text-xs font-semibold text-rose-200 border border-rose-500/35"
        >
          <ShieldX className="h-3.5 w-3.5 text-rose-300" aria-hidden="true" />
          Blocked
        </span>
      );
    case "SCAN-ERROR":
      return (
        <span
          title="Scan could not finish cleanly (SCAN-ERROR)."
          className="inline-flex items-center gap-1.5 rounded-full bg-purple-500/20 px-2.5 py-0.5 text-xs font-semibold text-purple-200 border border-purple-500/40"
        >
          <AlertTriangle className="h-3.5 w-3.5 text-purple-300" aria-hidden="true" />
          Scan Error
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center rounded-full bg-slate-700 px-2.5 py-0.5 text-xs font-medium text-slate-200">
          {status}
        </span>
      );
  }
}

export function renderSeverityBadge(sev: string) {
  const map: Record<string, string> = {
    CRITICAL: "bg-rose-500/20 text-rose-200 border-rose-500/40",
    HIGH: "bg-orange-500/20 text-orange-200 border-orange-500/40",
    MEDIUM: "bg-amber-500/20 text-amber-200 border-amber-500/40",
    LOW: "bg-sky-500/20 text-sky-200 border-sky-500/40",
    NONE: "bg-emerald-500/15 text-emerald-200 border-emerald-500/30",
  };
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-bold border ${
        map[sev] || "bg-slate-800 text-slate-200 border-slate-700"
      }`}
    >
      {sev}
    </span>
  );
}
