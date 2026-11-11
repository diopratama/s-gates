"use client";

import React, { useState } from "react";
import { Trash2 } from "lucide-react";
import type { ApplicationSummary, UserPersona } from "@/lib/api";
import { renderSeverityBadge, renderStatusBadge } from "@/components/badges";

interface InventoryViewProps {
  inventoryList: ApplicationSummary[];
  currentUser: UserPersona | null;
  deletingAppId: string | null;
  onDeleteApplication: (sgatesAppId: string, appName: string) => void;
  onOpenAssessment: (assessmentCode: string) => void;
}

export default function InventoryView({
  inventoryList,
  currentUser,
  deletingAppId,
  onDeleteApplication,
  onOpenAssessment,
}: InventoryViewProps) {
  const [invSearch, setInvSearch] = useState("");
  const [invStatusFilter, setInvStatusFilter] = useState("");

  const filteredInventory = inventoryList.filter((app) => {
    if (invStatusFilter && app.security_status !== invStatusFilter) return false;
    if (invSearch.trim()) {
      const q = invSearch.toLowerCase();
      return (
        app.name.toLowerCase().includes(q) ||
        app.sgates_app_id.toLowerCase().includes(q) ||
        app.department.toLowerCase().includes(q) ||
        app.ai_tool.toLowerCase().includes(q)
      );
    }
    return true;
  });

  function resetFilters() {
    setInvSearch("");
    setInvStatusFilter("");
  }

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <h2 className="text-base font-bold text-white">Application Inventory</h2>
          <p className="text-xs text-slate-400">
            Registered applications, owners, risk levels, security status, and scanned versions.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            aria-label="Search applications"
            placeholder="Search app, ID, tool, dept..."
            value={invSearch}
            onChange={(e) => setInvSearch(e.target.value)}
            className="rounded-lg bg-slate-950 border border-slate-800 px-3 py-1.5 text-xs text-white placeholder:text-slate-400 focus-visible:ring-2 focus-visible:ring-emerald-400"
          />
          <select
            aria-label="Filter applications by security status"
            value={invStatusFilter}
            onChange={(e) => setInvStatusFilter(e.target.value)}
            className="rounded-lg bg-slate-950 border border-slate-800 px-3 py-1.5 text-xs text-slate-200 focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            <option value="">All Statuses</option>
            <option value="PASS-WITH-MANUAL-CHECKS">Passed</option>
            <option value="REVIEW">Needs Review</option>
            <option value="REJECT">Blocked</option>
            <option value="SCAN-ERROR">Scan Error</option>
          </select>
        </div>
      </div>

      {filteredInventory.length === 0 ? (
        <div className="py-10 text-center space-y-3">
          <p className="text-xs text-slate-300">
            {inventoryList.length === 0
              ? "No applications registered yet."
              : "No applications match the current filters."}
          </p>
          {inventoryList.length > 0 && (
            <button
              type="button"
              onClick={resetFilters}
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
                <th className="py-2.5 px-3">App ID</th>
                <th className="py-2.5 px-3">Application</th>
                <th className="py-2.5 px-3">Department &amp; Owners</th>
                <th className="py-2.5 px-3">AI Tool</th>
                <th className="py-2.5 px-3">Risk</th>
                <th className="py-2.5 px-3">Security Status</th>
                <th className="py-2.5 px-3">Release State</th>
                <th className="py-2.5 px-3">Versions</th>
                {currentUser?.role === "ADMIN" && (
                  <th className="py-2.5 px-3 text-right">Actions</th>
                )}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filteredInventory.map((app) => (
                <tr key={app.id} className="hover:bg-slate-950/40">
                  <td className="py-3 px-3 font-mono font-bold text-emerald-300">
                    {app.sgates_app_id}
                  </td>
                  <td className="py-3 px-3">
                    <div className="font-bold text-white">{app.name}</div>
                    <span className="font-mono text-xs text-slate-400">
                      v{app.latest_version}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-xs">
                    <div className="text-slate-200 font-semibold">
                      {app.department || "-"}
                    </div>
                    <div className="text-slate-400">
                      Biz: {app.business_owner || "-"}
                    </div>
                    <div className="text-slate-400">
                      Tech: {app.technical_owner || "-"}
                    </div>
                  </td>
                  <td className="py-3 px-3 text-xs">
                    <div className="text-emerald-300 font-semibold">{app.ai_tool}</div>
                    <div className="text-slate-400">{app.data_classification}</div>
                  </td>
                  <td className="py-3 px-3">{renderSeverityBadge(app.risk_level)}</td>
                  <td className="py-3 px-3">{renderStatusBadge(app.security_status)}</td>
                  <td className="py-3 px-3">
                    <span className="rounded bg-slate-800 px-2 py-1 text-xs font-semibold text-sky-200">
                      {app.production_status}
                    </span>
                    <div className="text-xs text-slate-400 mt-1">
                      Next Review: {app.next_review_date}
                    </div>
                  </td>
                  <td className="py-3 px-3">
                    <div className="flex flex-wrap gap-1.5">
                      {app.assessments.map((asmt) => (
                        <button
                          type="button"
                          key={asmt.assessment_code}
                          onClick={() => onOpenAssessment(asmt.assessment_code)}
                          className="rounded bg-slate-950 hover:bg-slate-800 border border-slate-700 px-2 py-1 text-xs font-mono text-emerald-300 transition focus-visible:ring-2 focus-visible:ring-emerald-400"
                        >
                          v{asmt.version} · {asmt.assessment_code}
                        </button>
                      ))}
                    </div>
                  </td>
                  {currentUser?.role === "ADMIN" && (
                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => onDeleteApplication(app.sgates_app_id, app.name)}
                        disabled={deletingAppId === app.sgates_app_id}
                        className="inline-flex items-center gap-1 rounded-lg bg-rose-950/60 hover:bg-rose-900 border border-rose-700/60 px-2.5 py-1.5 text-xs font-semibold text-rose-200 transition disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-rose-400"
                        title={`Delete ${app.sgates_app_id} and all linked assessments`}
                      >
                        <Trash2 className="h-3.5 w-3.5 text-rose-400" aria-hidden="true" />
                        {deletingAppId === app.sgates_app_id ? "Deleting..." : "Delete"}
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
