"use client";

import React from "react";
import { ShieldCheck, Trash2 } from "lucide-react";
import type { AuditEvent, SystemSettings, UserPersona } from "@/lib/api";

interface AdminGovernanceViewProps {
  systemSettings: SystemSettings;
  currentUser: UserPersona | null;
  auditLogsData: {
    chain_integrity_verified: boolean;
    total_records: number;
    records: AuditEvent[];
  } | null;
  onOpenPurgeModal: () => void;
}

export default function AdminGovernanceView({
  systemSettings,
  currentUser,
  auditLogsData,
  onOpenPurgeModal,
}: AdminGovernanceViewProps) {
  const scannerPills = [
    { name: "Trivy", version: systemSettings.trivy_version },
    { name: "Gitleaks", version: systemSettings.gitleaks_version },
    { name: "Semgrep", version: systemSettings.semgrep_version },
    { name: "OSV-Scanner", version: systemSettings.osv_version || "2.7.1" },
    { name: "GuardDog", version: systemSettings.guarddog_version || "3.2.0" },
  ];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Scanner Status */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-base font-bold text-white">
                Scanner Binary Status
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Installed CLI engines inside the backend container.
              </p>
            </div>
            <span
              className={`rounded-lg border px-2.5 py-1 text-xs font-mono font-bold ${
                systemSettings.security_intel_status === "HEALTHY"
                  ? "border-emerald-500/30 bg-emerald-950/40 text-emerald-200"
                  : "border-rose-500/40 bg-rose-950/40 text-rose-200"
              }`}
            >
              {systemSettings.security_intel_status}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
            {scannerPills.map((s) => (
              <div
                key={s.name}
                className="rounded-xl bg-slate-950 border border-slate-800 p-3"
              >
                <div className="text-slate-400 text-xs">{s.name}</div>
                <div className="font-mono font-bold text-white mt-0.5">
                  v{s.version}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ZIP Extraction Limits */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="text-base font-bold text-white">
              Archive Extraction Limits
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Upload safety thresholds checked before scanning.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="rounded-xl bg-slate-950 border border-slate-800 p-3">
              <span className="text-slate-400 block">Max ZIP Size</span>
              <span className="text-base font-mono font-bold text-white">
                {systemSettings.max_zip_size_mb} MB
              </span>
            </div>
            <div className="rounded-xl bg-slate-950 border border-slate-800 p-3">
              <span className="text-slate-400 block">Max Expanded Size</span>
              <span className="text-base font-mono font-bold text-white">
                {systemSettings.max_expanded_size_mb} MB
              </span>
            </div>
            <div className="rounded-xl bg-slate-950 border border-slate-800 p-3">
              <span className="text-slate-400 block">Max File Count</span>
              <span className="text-base font-mono font-bold text-white">
                {systemSettings.max_file_count.toLocaleString()} files
              </span>
            </div>
            <div className="rounded-xl bg-slate-950 border border-slate-800 p-3">
              <span className="text-slate-400 block">Scan Timeout</span>
              <span className="text-base font-mono font-bold text-white">
                {systemSettings.max_scan_seconds}s
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Admin Danger Zone */}
      {currentUser?.role === "ADMIN" && (
        <div className="rounded-2xl border border-rose-900/60 bg-rose-950/20 p-5 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-bold text-rose-200 flex items-center gap-2">
                <Trash2 className="h-4 w-4 text-rose-400" aria-hidden="true" />
                Purge All Scan History
              </h3>
              <p className="text-xs text-slate-300 max-w-xl mt-1">
                Deletes all assessment records, findings, dependencies, and Evidence Vault folders on disk, then writes an immutable purge record to the SHA-256 audit log.
              </p>
            </div>
            <button
              type="button"
              onClick={onOpenPurgeModal}
              className="inline-flex items-center gap-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs px-4 py-2.5 transition shadow focus-visible:ring-2 focus-visible:ring-rose-300"
            >
              <Trash2 className="h-4 w-4" aria-hidden="true" />
              Purge Scan History
            </button>
          </div>
        </div>
      )}

      {/* Audit Log */}
      {auditLogsData && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-base font-bold text-white">
                Audit Log (Database SHA-256 Chain)
              </h3>
              <p className="text-xs text-slate-400">
                Each record hashes the previous entry in PostgreSQL.
              </p>
            </div>
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-mono font-bold border ${
                auditLogsData.chain_integrity_verified
                  ? "bg-emerald-500/15 text-emerald-200 border-emerald-500/30"
                  : "bg-rose-500/20 text-rose-200 border-rose-500/40"
              }`}
            >
              <ShieldCheck className="h-4 w-4" aria-hidden="true" />
              Chain: {auditLogsData.chain_integrity_verified ? "VERIFIED" : "TAMPERED"}
            </span>
          </div>

          <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
            {auditLogsData.records.map((r) => (
              <div
                key={r.id}
                className="rounded-xl bg-slate-950/80 border border-slate-800 p-3 text-xs flex flex-col gap-1"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-emerald-300">
                      #{r.id} {r.event_type}
                    </span>
                    {r.assessment_code && (
                      <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-sky-200">
                        {r.assessment_code}
                      </span>
                    )}
                  </div>
                  <span className="font-mono text-xs text-slate-400">
                    {r.actor_email} [{r.actor_role}]
                  </span>
                </div>
                <p className="text-slate-200">{r.summary}</p>
                <div className="flex flex-wrap items-center justify-between text-xs font-mono text-slate-400 pt-1">
                  <span>
                    {r.previous_state || "N/A"} → {r.new_state || "N/A"}
                  </span>
                  <span>{r.immutable_signature}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
