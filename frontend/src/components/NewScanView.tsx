"use client";

import React, { useState } from "react";
import {
  AlertTriangle,
  ChevronDown,
  FileArchive,
  GitBranch,
  Loader2,
  Settings,
  ShieldCheck,
  Upload,
  X,
} from "lucide-react";
import LiveScanTerminal, {
  TerminalScanStatus,
} from "@/components/LiveScanTerminal";
import type {
  AssessmentDetail,
  ScanStreamLogEvent,
  SystemSettings,
} from "@/lib/api";

const AI_TOOLS = [
  "Cursor",
  "Claude",
  "ChatGPT",
  "Microsoft Copilot",
  "Gemini",
  "Lovable",
  "Bolt",
  "Replit",
  "Claude + Lovable",
  "Bolt + ChatGPT",
  "Traditional / No AI",
];

const EXTERNAL_CONNECTION_OPTIONS = [
  "SharePoint",
  "OneDrive",
  "SAP",
  "Database",
  "External API",
  "Internal REST API",
];

function inferRepoNameFromUrl(url: string): string {
  const cleaned = url.trim().replace(/\/+$/, "").replace(/\.git$/, "");
  const parts = cleaned.split("/").filter(Boolean);
  if (parts.length >= 2) {
    return parts[parts.length - 1];
  }
  return "";
}

interface NewScanViewProps {
  subName: string;
  setSubName: (val: string) => void;
  subVersion: string;
  setSubVersion: (val: string) => void;
  subDept: string;
  setSubDept: (val: string) => void;
  subBizOwner: string;
  setSubBizOwner: (val: string) => void;
  subTechOwner: string;
  setSubTechOwner: (val: string) => void;
  subDesc: string;
  setSubDesc: (val: string) => void;
  subAiTool: string;
  setSubAiTool: (val: string) => void;
  subAppType: string;
  setSubAppType: (val: string) => void;
  subDataClass: string;
  setSubDataClass: (val: string) => void;
  subConns: string[];
  setSubConns: React.Dispatch<React.SetStateAction<string[]>>;
  subUsers: number;
  setSubUsers: (val: number) => void;
  subAdminPriv: boolean;
  setSubAdminPriv: (val: boolean) => void;
  subZipFile: File | null;
  setSubZipFile: (file: File | null) => void;
  githubRepositoryUrl: string;
  setGithubRepositoryUrl: (val: string) => void;
  githubBranch: string;
  setGithubBranch: (val: string) => void;
  githubToken: string;
  setGithubToken: (val: string) => void;
  githubStatus: string;
  githubError: string;
  clearGithubError: () => void;
  submitting: boolean;
  systemSettings: SystemSettings | null;
  onSubmitZip: (e: React.FormEvent) => void;
  onSubmitGithub: () => void;
  terminalLogs: ScanStreamLogEvent[];
  terminalStatus: TerminalScanStatus;
  terminalElapsed: number;
  terminalResult: AssessmentDetail | null;
  terminalError: string;
  onClearTerminal: () => void;
  onViewReport: (assessment: AssessmentDetail) => void;
}

export default function NewScanView({
  subName,
  setSubName,
  subVersion,
  setSubVersion,
  subDept,
  setSubDept,
  subBizOwner,
  setSubBizOwner,
  subTechOwner,
  setSubTechOwner,
  subDesc,
  setSubDesc,
  subAiTool,
  setSubAiTool,
  subAppType,
  setSubAppType,
  subDataClass,
  setSubDataClass,
  subConns,
  setSubConns,
  subUsers,
  setSubUsers,
  subAdminPriv,
  setSubAdminPriv,
  subZipFile,
  setSubZipFile,
  githubRepositoryUrl,
  setGithubRepositoryUrl,
  githubBranch,
  setGithubBranch,
  githubToken,
  setGithubToken,
  githubStatus,
  githubError,
  clearGithubError,
  submitting,
  systemSettings,
  onSubmitZip,
  onSubmitGithub,
  terminalLogs,
  terminalStatus,
  terminalElapsed,
  terminalResult,
  terminalError,
  onClearTerminal,
  onViewReport,
}: NewScanViewProps) {
  const [sourceMode, setSourceMode] = useState<"github" | "zip">("github");
  const [showDetails, setShowDetails] = useState(false);
  const [nameAutoDerived, setNameAutoDerived] = useState(true);

  function handleFormSubmit(e: React.FormEvent) {
    if (sourceMode === "github") {
      e.preventDefault();
      onSubmitGithub();
    } else {
      onSubmitZip(e);
    }
  }

  function handleGitHubUrlChange(val: string) {
    setGithubRepositoryUrl(val);
    if (githubError) clearGithubError();
    if (nameAutoDerived || !subName.trim()) {
      const inferred = inferRepoNameFromUrl(val);
      if (inferred) {
        setSubName(inferred);
        setNameAutoDerived(true);
      }
    }
  }

  function handleZipChange(file: File | null) {
    setSubZipFile(file);
    if (file && (nameAutoDerived || !subName.trim())) {
      setSubName(file.name.replace(/\.zip$/i, ""));
      setNameAutoDerived(true);
    }
  }

  const canSubmit =
    !submitting &&
    subName.trim().length > 0 &&
    (sourceMode === "github"
      ? githubRepositoryUrl.trim().length > 0
      : subZipFile !== null);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
      {/* Left 2 Columns: Unified Scan Intake Form */}
      <form
        onSubmit={handleFormSubmit}
        className="lg:col-span-2 rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-5"
      >
        <div className="border-b border-slate-800 pb-4">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <FileArchive className="h-5 w-5 text-emerald-400" aria-hidden="true" />
            New Code Scan
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Scan a GitHub repository or a local .zip archive inside an isolated workspace.
          </p>
        </div>

        {/* Project Name & Version */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="sm:col-span-2">
            <label
              htmlFor="scan-project-name"
              className="block text-xs font-semibold text-slate-200 mb-1"
            >
              Project Name <span className="text-rose-400">*</span>
            </label>
            <input
              id="scan-project-name"
              type="text"
              required
              value={subName}
              onChange={(e) => {
                setSubName(e.target.value);
                setNameAutoDerived(e.target.value.trim() === "");
              }}
              placeholder="Auto-fills from repository URL or .zip filename"
              className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white placeholder:text-slate-400 focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
            />
          </div>
          <div>
            <label
              htmlFor="scan-project-version"
              className="block text-xs font-semibold text-slate-200 mb-1"
            >
              Version <span className="text-rose-400">*</span>
            </label>
            <input
              id="scan-project-version"
              type="text"
              required
              value={subVersion}
              onChange={(e) => setSubVersion(e.target.value)}
              className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white font-mono focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
            />
          </div>
        </div>

        {/* Segmented Source Switcher */}
        <div className="space-y-3">
          <div
            role="tablist"
            aria-label="Scan source type"
            className="inline-grid grid-cols-2 rounded-xl bg-slate-950 border border-slate-800 p-1 w-full sm:w-auto"
          >
            <button
              type="button"
              role="tab"
              aria-selected={sourceMode === "github"}
              onClick={() => setSourceMode("github")}
              className={`inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition focus-visible:ring-2 focus-visible:ring-emerald-400 ${
                sourceMode === "github"
                  ? "bg-emerald-500 text-slate-950 shadow"
                  : "text-slate-300 hover:text-white"
              }`}
            >
              <GitBranch className="h-3.5 w-3.5" aria-hidden="true" />
              GitHub Repository
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={sourceMode === "zip"}
              onClick={() => setSourceMode("zip")}
              className={`inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition focus-visible:ring-2 focus-visible:ring-emerald-400 ${
                sourceMode === "zip"
                  ? "bg-emerald-500 text-slate-950 shadow"
                  : "text-slate-300 hover:text-white"
              }`}
            >
              <Upload className="h-3.5 w-3.5" aria-hidden="true" />
              Upload .ZIP Archive
            </button>
          </div>

          {sourceMode === "github" ? (
            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 space-y-3">
              <p className="text-xs text-slate-400">
                Supports public and private GitHub repositories (e.g.{" "}
                <code className="text-emerald-300">https://github.com/owner/repo</code>). Tokens are never saved or logged.
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="sm:col-span-2">
                  <label
                    htmlFor="github-repository-url"
                    className="mb-1 block text-xs font-semibold text-slate-200"
                  >
                    Repository URL <span className="text-rose-400">*</span>
                  </label>
                  <input
                    id="github-repository-url"
                    type="url"
                    value={githubRepositoryUrl}
                    onChange={(e) => handleGitHubUrlChange(e.target.value)}
                    placeholder="https://github.com/owner/repository"
                    className="w-full rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-white placeholder:text-slate-400 focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
                  />
                </div>
                <div>
                  <label
                    htmlFor="github-branch"
                    className="mb-1 block text-xs font-semibold text-slate-200"
                  >
                    Branch or Tag (optional)
                  </label>
                  <input
                    id="github-branch"
                    type="text"
                    value={githubBranch}
                    onChange={(e) => setGithubBranch(e.target.value)}
                    placeholder="Default branch (e.g. main)"
                    className="w-full rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-white placeholder:text-slate-400 focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
                  />
                </div>
                <div>
                  <label
                    htmlFor="github-token"
                    className="mb-1 block text-xs font-semibold text-slate-200"
                  >
                    Access Token (private repos only)
                  </label>
                  <input
                    id="github-token"
                    type="password"
                    autoComplete="off"
                    value={githubToken}
                    onChange={(e) => setGithubToken(e.target.value)}
                    placeholder="Fine-grained token (Contents: read)"
                    className="w-full rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-white placeholder:text-slate-400 focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
                  />
                </div>
              </div>

              {githubError && (
                <div
                  role="alert"
                  className="rounded-lg border border-rose-500/40 bg-rose-950/40 px-3 py-2 text-xs text-rose-200 flex items-center gap-2"
                >
                  <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" aria-hidden="true" />
                  <span>{githubError}</span>
                </div>
              )}

              {submitting && githubStatus && (
                <div
                  role="status"
                  className="rounded-lg border border-emerald-500/40 bg-emerald-950/40 px-3 py-2 text-xs text-emerald-200 flex items-center gap-2"
                >
                  <Loader2 className="h-4 w-4 animate-spin shrink-0 text-emerald-400" aria-hidden="true" />
                  <span>{githubStatus}</span>
                </div>
              )}
            </div>
          ) : (
            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 space-y-3">
              <div className="rounded-xl border-2 border-dashed border-slate-700 hover:border-emerald-500/50 bg-slate-900/40 p-6 text-center transition">
                <input
                  id="zip-upload-input"
                  type="file"
                  accept=".zip"
                  onChange={(e) => handleZipChange(e.target.files?.[0] || null)}
                  className="sr-only"
                />
                <label
                  htmlFor="zip-upload-input"
                  className="cursor-pointer flex flex-col items-center"
                >
                  <Upload className="h-7 w-7 text-emerald-400 mb-2" aria-hidden="true" />
                  <span className="text-xs font-semibold text-white">
                    {subZipFile
                      ? `Selected: ${subZipFile.name} (${(subZipFile.size / 1024).toFixed(1)} KB)`
                      : "Choose a .zip source archive from your computer"}
                  </span>
                  <span className="text-xs text-slate-400 mt-1">
                    Max {systemSettings?.max_zip_size_mb || 500} MB · Checked for path traversal and symlink escapes
                  </span>
                </label>
              </div>
              {subZipFile && (
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={() => handleZipChange(null)}
                    className="inline-flex items-center gap-1 text-xs text-slate-300 hover:text-white focus-visible:ring-2 focus-visible:ring-emerald-400 rounded px-2 py-1"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                    Remove selected file
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Shared Collapsible Application Metadata */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden">
          <button
            type="button"
            aria-expanded={showDetails}
            onClick={() => setShowDetails(!showDetails)}
            className="w-full flex items-center justify-between p-3.5 text-xs font-semibold text-slate-200 hover:text-white hover:bg-slate-900/60 transition focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            <span className="flex items-center gap-2">
              <Settings className="h-4 w-4 text-emerald-400" aria-hidden="true" />
              <span>Application Details (Optional)</span>
            </span>
            <span className="flex items-center gap-1.5 text-xs text-slate-400">
              <span>{showDetails ? "Hide" : "Owner, department & data class"}</span>
              <ChevronDown
                aria-hidden="true"
                className={`h-4 w-4 transition-transform ${
                  showDetails ? "rotate-180" : ""
                }`}
              />
            </span>
          </button>

          {showDetails && (
            <div className="p-4 pt-3 border-t border-slate-800 space-y-4 bg-slate-900/40">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label
                    htmlFor="app-department"
                    className="block text-xs font-semibold text-slate-200 mb-1"
                  >
                    Department
                  </label>
                  <input
                    id="app-department"
                    type="text"
                    value={subDept}
                    onChange={(e) => setSubDept(e.target.value)}
                    placeholder="e.g. Engineering"
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white placeholder:text-slate-400 focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
                  />
                </div>
                <div>
                  <label
                    htmlFor="app-biz-owner"
                    className="block text-xs font-semibold text-slate-200 mb-1"
                  >
                    Business Owner
                  </label>
                  <input
                    id="app-biz-owner"
                    type="text"
                    value={subBizOwner}
                    onChange={(e) => setSubBizOwner(e.target.value)}
                    placeholder="Team or lead name"
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white placeholder:text-slate-400 focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
                  />
                </div>
                <div>
                  <label
                    htmlFor="app-tech-owner"
                    className="block text-xs font-semibold text-slate-200 mb-1"
                  >
                    Technical Owner
                  </label>
                  <input
                    id="app-tech-owner"
                    type="text"
                    value={subTechOwner}
                    onChange={(e) => setSubTechOwner(e.target.value)}
                    placeholder="Developer or maintainer"
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white placeholder:text-slate-400 focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
                  />
                </div>
              </div>

              <div>
                <label
                  htmlFor="app-description"
                  className="block text-xs font-semibold text-slate-200 mb-1"
                >
                  Description
                </label>
                <textarea
                  id="app-description"
                  rows={2}
                  value={subDesc}
                  onChange={(e) => setSubDesc(e.target.value)}
                  placeholder="Short summary of what this application does"
                  className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white placeholder:text-slate-400 focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label
                    htmlFor="app-ai-tool"
                    className="block text-xs font-semibold text-slate-200 mb-1"
                  >
                    AI Development Tool
                  </label>
                  <select
                    id="app-ai-tool"
                    value={subAiTool}
                    onChange={(e) => setSubAiTool(e.target.value)}
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
                  >
                    {AI_TOOLS.map((t) => (
                      <option key={t} value={t}>
                        {t}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label
                    htmlFor="app-type"
                    className="block text-xs font-semibold text-slate-200 mb-1"
                  >
                    Application Type
                  </label>
                  <select
                    id="app-type"
                    value={subAppType}
                    onChange={(e) => setSubAppType(e.target.value)}
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
                  >
                    <option>Internal Web Application</option>
                    <option>Automation Script / CLI</option>
                    <option>Background Service / Agent</option>
                    <option>Desktop Executable (.exe / .msi)</option>
                    <option>Data Pipeline / Connector</option>
                  </select>
                </div>
                <div>
                  <label
                    htmlFor="app-data-class"
                    className="block text-xs font-semibold text-slate-200 mb-1"
                  >
                    Data Classification
                  </label>
                  <select
                    id="app-data-class"
                    value={subDataClass}
                    onChange={(e) => setSubDataClass(e.target.value)}
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
                  >
                    <option>Public</option>
                    <option>Internal</option>
                    <option>Confidential</option>
                    <option>Restricted / Personal Data</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 items-center">
                <div className="sm:col-span-2">
                  <span className="block text-xs font-semibold text-slate-200 mb-1.5">
                    External Connections
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {EXTERNAL_CONNECTION_OPTIONS.map((conn) => {
                      const checked = subConns.includes(conn);
                      return (
                        <button
                          type="button"
                          key={conn}
                          aria-pressed={checked}
                          onClick={() =>
                            setSubConns((prev) =>
                              prev.includes(conn)
                                ? prev.filter((c) => c !== conn)
                                : [...prev, conn]
                            )
                          }
                          className={`px-2.5 py-1.5 rounded-md text-xs font-medium border transition focus-visible:ring-2 focus-visible:ring-emerald-400 ${
                            checked
                              ? "bg-emerald-500/20 border-emerald-500/50 text-emerald-200"
                              : "bg-slate-950 border-slate-800 text-slate-300 hover:text-white"
                          }`}
                        >
                          {checked ? "✓ " : "+ "}
                          {conn}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="space-y-2">
                  <div>
                    <label
                      htmlFor="app-expected-users"
                      className="block text-xs font-semibold text-slate-200 mb-1"
                    >
                      Expected Users
                    </label>
                    <input
                      id="app-expected-users"
                      type="number"
                      min={1}
                      value={subUsers}
                      onChange={(e) =>
                        setSubUsers(parseInt(e.target.value || "1", 10))
                      }
                      className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-1.5 text-xs text-white font-mono focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400/70"
                    />
                  </div>
                  <label
                    htmlFor="app-admin-priv"
                    className="flex items-center gap-2 text-xs text-slate-200 cursor-pointer pt-1"
                  >
                    <input
                      id="app-admin-priv"
                      type="checkbox"
                      checked={subAdminPriv}
                      onChange={(e) => setSubAdminPriv(e.target.checked)}
                      className="rounded border-slate-700 bg-slate-950 text-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400"
                    />
                    <span>Requires Admin Privileges</span>
                  </label>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Single Primary CTA */}
        <div className="flex justify-end pt-1">
          <button
            type="submit"
            disabled={!canSubmit}
            className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 px-6 py-2.5 text-xs font-bold text-slate-950 transition shadow-md focus-visible:ring-2 focus-visible:ring-emerald-300"
          >
            {submitting ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <ShieldCheck className="h-4 w-4" aria-hidden="true" />
            )}
            {submitting ? "Running Security Scan..." : "Run Security Scan"}
          </button>
        </div>
      </form>

      {/* Right Column: Live Backend Scan Terminal */}
      <div>
        <LiveScanTerminal
          logs={terminalLogs}
          status={terminalStatus}
          elapsedSeconds={terminalElapsed}
          completedAssessment={terminalResult}
          errorMessage={terminalError}
          onClear={onClearTerminal}
          onViewReport={onViewReport}
        />
      </div>
    </div>
  );
}
