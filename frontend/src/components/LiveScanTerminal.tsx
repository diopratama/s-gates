"use client";

import React, { useEffect, useRef, useState } from "react";
import {
  ArrowRight,
  CheckCircle2,
  Loader2,
  Terminal,
  Trash2,
  XCircle,
} from "lucide-react";
import type { AssessmentDetail, ScanStreamLogEvent } from "@/lib/api";

export type TerminalScanStatus = "idle" | "running" | "completed" | "failed";

interface LiveScanTerminalProps {
  logs: ScanStreamLogEvent[];
  status: TerminalScanStatus;
  elapsedSeconds: number;
  completedAssessment: AssessmentDetail | null;
  errorMessage?: string;
  onClear: () => void;
  onViewReport: (assessment: AssessmentDetail) => void;
}

const PIPELINE_STAGES = [
  { key: "INTAKE", label: "Intake" },
  { key: "ZIP_GATE", label: "ZIP Gate" },
  { key: "SCANNERS", label: "Scanners" },
  { key: "RISK_ENGINE", label: "Risk Engine" },
  { key: "VAULT", label: "Vault" },
] as const;

const LEVEL_STYLES: Record<ScanStreamLogEvent["level"], string> = {
  INFO: "text-sky-400",
  CMD: "text-purple-400",
  SCAN: "text-amber-300",
  OK: "text-emerald-400",
  WARN: "text-amber-400",
  ERR: "text-rose-400",
};

export default function LiveScanTerminal({
  logs,
  status,
  elapsedSeconds,
  completedAssessment,
  errorMessage,
  onClear,
  onViewReport,
}: LiveScanTerminalProps) {
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && scrollContainerRef.current) {
      scrollContainerRef.current.scrollTop =
        scrollContainerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const seenStages = new Set(logs.map((l) => l.stage));
  const lastStage = logs.length > 0 ? logs[logs.length - 1].stage : null;

  const statusPill = () => {
    switch (status) {
      case "running":
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/15 border border-amber-500/40 px-2.5 py-0.5 text-xs font-mono font-bold text-amber-200">
            <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
            RUNNING
          </span>
        );
      case "completed":
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/40 px-2.5 py-0.5 text-xs font-mono font-bold text-emerald-200">
            <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
            COMPLETED
          </span>
        );
      case "failed":
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-rose-500/15 border border-rose-500/40 px-2.5 py-0.5 text-xs font-mono font-bold text-rose-200">
            <XCircle className="h-3 w-3" aria-hidden="true" />
            FAILED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-800 border border-slate-700 px-2.5 py-0.5 text-xs font-mono font-bold text-slate-300">
            IDLE
          </span>
        );
    }
  };

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/90 overflow-hidden shadow-xl flex flex-col">
      {/* Terminal Window Chrome */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 bg-slate-950 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-rose-500/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/80" />
          </div>
          <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-slate-200">
            <Terminal className="h-3.5 w-3.5 text-emerald-400" />
            <span>Live Backend Terminal</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {status !== "idle" && (
            <span className="text-[11px] font-mono text-slate-400">
              {elapsedSeconds.toFixed(1)}s
            </span>
          )}
          {statusPill()}
        </div>
      </div>

      {/* Pipeline Stage Stepper */}
      <div className="grid grid-cols-5 gap-1 px-3 py-2 bg-slate-900/80 border-b border-slate-800 text-xs font-mono">
        {PIPELINE_STAGES.map((stage) => {
          const isReached = seenStages.has(stage.key);
          const isCurrent = status === "running" && lastStage === stage.key;
          const isDone =
            (isReached && !isCurrent) || status === "completed";

          return (
            <div
              key={stage.key}
              className={`rounded px-1.5 py-1 text-center border transition truncate ${
                isCurrent
                  ? "bg-amber-500/15 border-amber-500/40 text-amber-200 font-bold"
                  : isDone
                    ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-200"
                    : "bg-slate-950/60 border-slate-800 text-slate-400"
              }`}
            >
              {stage.label}
            </div>
          );
        })}
      </div>

      {/* Scrollable Terminal Body */}
      <div
        ref={scrollContainerRef}
        className="h-[430px] overflow-y-auto bg-slate-950 p-3.5 font-mono text-[11px] leading-relaxed space-y-1.5"
      >
        {logs.length === 0 ? (
          <div className="h-full flex flex-col justify-between text-slate-400">
            <div className="space-y-2">
              <div className="text-emerald-400">
                s-gates@scanner-engine:~$ ready --mode=external
              </div>
              <p className="text-slate-400 leading-relaxed font-sans text-xs">
                Backend logs stream here once you start a GitHub or{" "}
                <code className="text-emerald-300">.zip</code> scan.
              </p>
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 space-y-1 text-[11px] text-slate-400">
                <div className="text-slate-200 font-semibold mb-1">
                  Pipeline stages:
                </div>
                <div>1. Repository fetch / ZIP upload intake</div>
                <div>2. ZIP Security Gate (traversal, bomb &amp; SHA-256)</div>
                <div>3. Parallel Trivy, Gitleaks, Semgrep, OSV-Scanner &amp; GuardDog</div>
                <div>4. PyPI &amp; npm Registry Metadata + Risk Decision Engine</div>
                <div>5. Evidence Vault &amp; SHA-256 audit chain write</div>
              </div>
            </div>
            <div className="text-xs text-slate-400 flex items-center gap-1.5">
              <span aria-hidden="true" className="inline-block w-2 h-3.5 bg-emerald-400/70 animate-pulse" />
              <span>Awaiting scan job...</span>
            </div>
          </div>
        ) : (
          <>
            {logs.map((entry, idx) => (
              <div key={idx} className="flex items-start gap-1.5 break-words">
                <span className="text-slate-400 shrink-0">
                  [{entry.timestamp}]
                </span>
                <span
                  className={`font-bold shrink-0 w-11 ${
                    LEVEL_STYLES[entry.level] || "text-slate-300"
                  }`}
                >
                  [{entry.level}]
                </span>
                <span className="text-slate-400 shrink-0">
                  [{entry.stage}]
                </span>
                <span
                  className={
                    entry.level === "ERR"
                      ? "text-rose-300"
                      : entry.level === "CMD"
                        ? "text-purple-200"
                        : entry.level === "OK"
                          ? "text-emerald-200"
                          : "text-slate-200"
                  }
                >
                  {entry.message}
                </span>
              </div>
            ))}
            {status === "running" && (
              <div className="flex items-center gap-2 text-amber-300 pt-1">
                <Loader2 className="h-3 w-3 animate-spin" />
                <span>Executing backend security pipeline...</span>
              </div>
            )}
          </>
        )}
      </div>

      {/* Terminal Controls Bar */}
      <div className="flex items-center justify-between px-3.5 py-2 bg-slate-900/90 border-t border-slate-800 text-[11px]">
        <label className="flex items-center gap-1.5 text-slate-400 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
            className="rounded border-slate-700 bg-slate-950 text-emerald-500"
          />
          <span>Auto-scroll</span>
        </label>
        <button
          type="button"
          onClick={onClear}
          disabled={status === "running" || logs.length === 0}
          className="inline-flex items-center gap-1 text-slate-400 hover:text-slate-200 disabled:opacity-40 transition"
        >
          <Trash2 className="h-3 w-3" />
          Clear Console
        </button>
      </div>

      {/* Post-Scan Summary & CTA Footer */}
      {status === "completed" && completedAssessment && (
        <div className="p-4 bg-emerald-950/30 border-t border-emerald-500/30 space-y-3">
          <div className="flex items-center justify-between gap-2 text-xs">
            <div>
              <div className="font-mono font-bold text-emerald-300">
                {completedAssessment.assessment_code}
              </div>
              <div className="text-[11px] text-slate-300">
                Status:{" "}
                <strong className="text-white">
                  {completedAssessment.technical_status}
                </strong>{" "}
                • Findings: {completedAssessment.findings.length}
              </div>
            </div>
            <span className="rounded bg-slate-900 border border-slate-700 px-2 py-1 text-xs font-mono text-slate-200">
              {completedAssessment.risk_level} RISK
            </span>
          </div>
          <button
            type="button"
            onClick={() => onViewReport(completedAssessment)}
            className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-4 py-2.5 text-xs font-bold text-slate-950 transition shadow-md"
          >
            View Full Assessment Report
            <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      )}

      {status === "failed" && errorMessage && (
        <div className="p-3.5 bg-rose-950/40 border-t border-rose-500/40 text-xs text-rose-200">
          <strong className="text-rose-300 block mb-0.5">Scan Failed:</strong>
          <span>{errorMessage}</span>
        </div>
      )}
    </div>
  );
}

