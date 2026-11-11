"use client";

import React, { useCallback, useEffect, useState } from "react";
import { AlertTriangle } from "lucide-react";
import {
  apiDownload,
  apiFetch,
  ApiError,
  ApplicationSummary,
  AssessmentDetail,
  AssessmentSummary,
  AuditEvent,
  clearStoredToken,
  DashboardSummary,
  deleteApplication,
  deleteAssessment,
  getStoredToken,
  NotificationItem,
  purgeAllAssessments,
  ScanStreamLogEvent,
  setStoredToken,
  streamScanRequest,
  SystemSettings,
  UserPersona,
} from "@/lib/api";
import HeaderNav, { ActiveTab } from "@/components/HeaderNav";
import OverviewDashboard from "@/components/OverviewDashboard";
import NewScanView from "@/components/NewScanView";
import AssessmentDetailView, {
  StudioSubTab,
} from "@/components/AssessmentDetailView";
import InventoryView from "@/components/InventoryView";
import AdminGovernanceView from "@/components/AdminGovernanceView";
import GuideView from "@/components/GuideView";
import ConfirmDialog from "@/components/ConfirmDialog";
import type { TerminalScanStatus } from "@/components/LiveScanTerminal";

type ConfirmActionState =
  | { type: "delete-assessment"; code: string }
  | { type: "delete-application"; sgatesAppId: string; appName: string }
  | { type: "purge-history" }
  | null;

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected error";
}

function normalizeGitHubUrl(
  url: string,
  currentBranch: string
): { cleanUrl: string; branch: string } {
  let clean = url.trim();
  let branch = currentBranch.trim();

  if (clean.startsWith("git@github.com:")) {
    clean = "https://github.com/" + clean.slice("git@github.com:".length);
  }
  if (clean.startsWith("github.com/")) {
    clean = "https://" + clean;
  } else if (clean.startsWith("http://github.com/")) {
    clean = "https://" + clean.slice("http://".length);
  }

  const treeMatch = clean.match(
    /^https:\/\/github\.com\/([^/]+)\/([^/]+)\/(?:tree|blob)\/([^/]+)(?:\/.*)?$/
  );
  if (treeMatch) {
    clean = `https://github.com/${treeMatch[1]}/${treeMatch[2]}`;
    if (!branch) {
      branch = decodeURIComponent(treeMatch[3]);
    }
  }

  clean = clean.replace(/\/+$/, "");
  if (clean.endsWith(".git")) {
    clean = clean.slice(0, -4);
  }

  return { cleanUrl: clean, branch };
}

export default function SGatesPortalPage() {
  const [currentUser, setCurrentUser] = useState<UserPersona | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>("dashboard");
  const [studioSubTab, setStudioSubTab] = useState<StudioSubTab>("summary");

  // Dashboard & Inventory State
  const [dashboardData, setDashboardData] = useState<DashboardSummary | null>(null);
  const [assessmentsList, setAssessmentsList] = useState<AssessmentSummary[]>([]);
  const [inventoryList, setInventoryList] = useState<ApplicationSummary[]>([]);
  const [selectedCode, setSelectedCode] = useState<string>("");
  const [selectedAssessment, setSelectedAssessment] =
    useState<AssessmentDetail | null>(null);

  // Admin & Notifications State
  const [systemSettings, setSystemSettings] = useState<SystemSettings | null>(null);
  const [auditLogsData, setAuditLogsData] = useState<{
    chain_integrity_verified: boolean;
    total_records: number;
    records: AuditEvent[];
  } | null>(null);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [showNotifDrawer, setShowNotifDrawer] = useState(false);

  // Submission Form State (clean defaults; populated from signed-in user where applicable)
  const [subName, setSubName] = useState("");
  const [subVersion, setSubVersion] = useState("1.0");
  const [subDept, setSubDept] = useState("");
  const [subBizOwner, setSubBizOwner] = useState("");
  const [subTechOwner, setSubTechOwner] = useState("");
  const [subDesc, setSubDesc] = useState("");
  const [subAiTool, setSubAiTool] = useState("Cursor");
  const [subAppType, setSubAppType] = useState("Internal Web Application");
  const [subDataClass, setSubDataClass] = useState("Internal");
  const [subConns, setSubConns] = useState<string[]>([]);
  const [subUsers, setSubUsers] = useState<number>(10);
  const [subAdminPriv, setSubAdminPriv] = useState<boolean>(false);
  const [subZipFile, setSubZipFile] = useState<File | null>(null);
  const [githubRepositoryUrl, setGithubRepositoryUrl] = useState("");
  const [githubBranch, setGithubBranch] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [githubStatus, setGithubStatus] = useState("");
  const [githubError, setGithubError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Manual Gates & Decision Form State
  const [avStatusInput, setAvStatusInput] = useState("Pending");
  const [avNotesInput, setAvNotesInput] = useState("");
  const [avRefInput, setAvRefInput] = useState("");
  const [sbStatusInput, setSbStatusInput] = useState("Not Required");
  const [sbTechInput, setSbTechInput] = useState("Windows Sandbox");
  const [sbNotesInput, setSbNotesInput] = useState("");
  const [decisionNotes, setDecisionNotes] = useState("");

  // Admin Deletion & History Purge Dialog State
  const [deletingCode, setDeletingCode] = useState<string | null>(null);
  const [deletingAppId, setDeletingAppId] = useState<string | null>(null);
  const [confirmAction, setConfirmAction] = useState<ConfirmActionState>(null);

  // Live Backend Terminal State
  const [terminalLogs, setTerminalLogs] = useState<ScanStreamLogEvent[]>([]);
  const [terminalStatus, setTerminalStatus] =
    useState<TerminalScanStatus>("idle");
  const [terminalElapsed, setTerminalElapsed] = useState<number>(0);
  const [terminalResult, setTerminalResult] =
    useState<AssessmentDetail | null>(null);
  const [terminalError, setTerminalError] = useState<string>("");

  // Auth & Toast State
  const [bannerMsg, setBannerMsg] = useState<{
    type: "success" | "error" | "info";
    text: string;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [needsLogin, setNeedsLogin] = useState(false);
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [loginSubmitting, setLoginSubmitting] = useState(false);

  const notify = useCallback(
    (type: "success" | "error" | "info", text: string) => {
      setBannerMsg({ type, text });
      setTimeout(() => {
        setBannerMsg((prev) => (prev?.text === text ? null : prev));
      }, 6500);
    },
    []
  );

  const applyUserMetadataDefaults = useCallback((user: UserPersona) => {
    setSubDept((prev) => prev || user.department || "");
    setSubTechOwner((prev) => prev || user.full_name || "");
  }, []);

  useEffect(() => {
    if (terminalStatus !== "running") return;
    const startMs = Date.now();
    const interval = window.setInterval(() => {
      setTerminalElapsed((Date.now() - startMs) / 1000);
    }, 100);
    return () => window.clearInterval(interval);
  }, [terminalStatus]);

  const loadAssessmentDetail = useCallback(
    async (code: string) => {
      try {
        const detail = await apiFetch<AssessmentDetail>(
          `/api/v1/assessments/${code}`
        );
        setSelectedCode(code);
        setSelectedAssessment(detail);
        setAvStatusInput(detail.av_status || "Pending");
        setAvNotesInput(detail.av_notes || "");
        setAvRefInput(detail.av_evidence_ref || "");
        setSbStatusInput(detail.sandbox_status || "Not Required");
        setSbTechInput(detail.sandbox_technology || "Windows Sandbox");
        setSbNotesInput(detail.sandbox_notes || "");
        setDecisionNotes(detail.decision_notes || "");
      } catch (err) {
        notify("error", `Could not load ${code}: ${getErrorMessage(err)}`);
      }
    },
    [notify]
  );

  const refreshAllData = useCallback(
    async (codeToLoad?: string) => {
      const [dash, asmts, inv, cfg, logs, notifs] = await Promise.all([
        apiFetch<DashboardSummary>("/api/v1/applications/dashboard-summary"),
        apiFetch<AssessmentSummary[]>("/api/v1/assessments"),
        apiFetch<ApplicationSummary[]>("/api/v1/applications"),
        apiFetch<SystemSettings>("/api/v1/admin/settings"),
        apiFetch<{
          chain_integrity_verified: boolean;
          total_records: number;
          records: AuditEvent[];
        }>("/api/v1/admin/audit-logs"),
        apiFetch<NotificationItem[]>("/api/v1/admin/notifications"),
      ]);
      setDashboardData(dash);
      setAssessmentsList(asmts);
      setInventoryList(inv);
      setSystemSettings(cfg);
      setAuditLogsData(logs);
      setNotifications(notifs);

      const targetCode = codeToLoad || asmts[0]?.assessment_code;
      if (targetCode) {
        await loadAssessmentDetail(targetCode);
      } else {
        setSelectedCode("");
        setSelectedAssessment(null);
      }
    },
    [loadAssessmentDetail]
  );

  useEffect(() => {
    let active = true;
    async function init() {
      const token = getStoredToken();
      if (!token) {
        setNeedsLogin(true);
        setLoading(false);
        return;
      }

      try {
        const user = await apiFetch<UserPersona>("/api/v1/auth/me");
        if (!active) return;
        setCurrentUser(user);
        applyUserMetadataDefaults(user);
        await refreshAllData();
      } catch (err) {
        if (!active) return;
        if (err instanceof ApiError && err.status === 401) {
          clearStoredToken();
          setNeedsLogin(true);
        } else {
          notify("error", `Could not initialize workspace: ${getErrorMessage(err)}`);
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    init();
    return () => {
      active = false;
    };
  }, [applyUserMetadataDefaults, notify, refreshAllData]);

  async function handleLogin(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoginSubmitting(true);
    setLoginError("");
    try {
      const result = await apiFetch<{
        access_token: string;
        user: UserPersona;
      }>("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({ email: loginEmail, password: loginPassword }),
      });
      setStoredToken(result.access_token);
      setCurrentUser(result.user);
      applyUserMetadataDefaults(result.user);
      setNeedsLogin(false);
      setLoginPassword("");
      try {
        await refreshAllData();
      } catch (error) {
        notify("error", `Could not load dashboard data: ${getErrorMessage(error)}`);
      }
    } catch (err) {
      setLoginError(err instanceof Error ? err.message : "Sign-in failed. Check your email and password.");
    } finally {
      setLoginSubmitting(false);
      setLoading(false);
    }
  }

  function handleLogout() {
    clearStoredToken();
    setCurrentUser(null);
    setDashboardData(null);
    setNeedsLogin(true);
  }

  async function handleEvidenceDownload(path: string, filename: string) {
    try {
      const blob = await apiDownload(path);
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    } catch (err) {
      notify("error", err instanceof Error ? err.message : "Download failed.");
    }
  }

  async function executeConfirmedAction() {
    if (!confirmAction) return;

    if (confirmAction.type === "delete-assessment") {
      const { code } = confirmAction;
      try {
        setDeletingCode(code);
        const res = await deleteAssessment(code);
        setConfirmAction(null);
        notify("success", res.message || `Deleted assessment ${code}.`);
        if (selectedCode === code) {
          setSelectedCode("");
          setSelectedAssessment(null);
        }
        await refreshAllData();
      } catch (err) {
        notify("error", `Could not delete ${code}: ${getErrorMessage(err)}`);
      } finally {
        setDeletingCode(null);
      }
      return;
    }

    if (confirmAction.type === "delete-application") {
      const { sgatesAppId } = confirmAction;
      try {
        setDeletingAppId(sgatesAppId);
        const res = await deleteApplication(sgatesAppId);
        setConfirmAction(null);
        notify("success", res.message || `Deleted application ${sgatesAppId}.`);
        if (selectedAssessment?.application?.sgates_app_id === sgatesAppId) {
          setSelectedCode("");
          setSelectedAssessment(null);
        }
        await refreshAllData();
      } catch (err) {
        notify("error", `Could not delete ${sgatesAppId}: ${getErrorMessage(err)}`);
      } finally {
        setDeletingAppId(null);
      }
      return;
    }

    if (confirmAction.type === "purge-history") {
      try {
        setDeletingCode("all");
        const res = await purgeAllAssessments();
        setConfirmAction(null);
        setSelectedCode("");
        setSelectedAssessment(null);
        notify("success", res.message || "Scan history purged.");
        await refreshAllData();
      } catch (err) {
        notify("error", `Could not purge scan history: ${getErrorMessage(err)}`);
      } finally {
        setDeletingCode(null);
      }
    }
  }

  function resolveSubmissionMetadata() {
    return {
      department: subDept.trim() || currentUser?.department || "Engineering",
      business_owner: subBizOwner.trim() || currentUser?.full_name || "Application Owner",
      technical_owner: subTechOwner.trim() || currentUser?.full_name || "Technical Owner",
      description: subDesc.trim() || "Source code security scan",
    };
  }

  async function handleMultipartZipSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!subZipFile) {
      notify("error", "Choose a .zip archive before starting the scan.");
      return;
    }
    const meta = resolveSubmissionMetadata();
    setTerminalLogs([]);
    setTerminalResult(null);
    setTerminalError("");
    setTerminalElapsed(0);
    setTerminalStatus("running");

    try {
      setSubmitting(true);
      const fd = new FormData();
      fd.append("application_name", subName.trim() || subZipFile.name.replace(/\.zip$/i, ""));
      fd.append("version", subVersion.trim() || "1.0");
      fd.append("department", meta.department);
      fd.append("business_owner", meta.business_owner);
      fd.append("technical_owner", meta.technical_owner);
      fd.append("description", meta.description);
      fd.append("ai_tool", subAiTool);
      fd.append("app_type", subAppType);
      fd.append("data_classification", subDataClass);
      fd.append("external_connections", JSON.stringify(subConns));
      fd.append("expected_users", String(subUsers));
      fd.append("requires_admin_privileges", String(subAdminPriv));
      fd.append("source_zip", subZipFile);

      let completedAssessment: AssessmentDetail | null = null;
      await streamScanRequest(
        "/api/v1/assessments/submit-stream",
        { method: "POST", body: fd },
        {
          onLog: (logEv) => setTerminalLogs((prev) => [...prev, logEv]),
          onResult: (assessment) => {
            completedAssessment = assessment;
          },
          onError: (detail) => setTerminalError(detail),
        }
      );

      if (completedAssessment) {
        const res = completedAssessment as AssessmentDetail;
        setTerminalResult(res);
        setTerminalStatus("completed");
        setSelectedCode(res.assessment_code);
        setSelectedAssessment(res);
        notify(
          res.technical_status === "REJECT" ||
            res.technical_status === "SCAN-ERROR"
            ? "error"
            : "success",
          `Scan finished for ${subZipFile.name}: ${res.assessment_code}`
        );
        refreshAllData(res.assessment_code).catch((err) => {
          console.warn("Dashboard refresh warning:", err);
        });
      }
    } catch (err) {
      const errMsg = getErrorMessage(err);
      setTerminalStatus("failed");
      setTerminalError(errMsg);
      notify("error", errMsg);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleGitHubSubmit() {
    setGithubError("");
    const rawUrl = githubRepositoryUrl.trim();
    if (!rawUrl) {
      const msg = "Enter a GitHub repository URL to scan (e.g. https://github.com/owner/repo).";
      setGithubError(msg);
      notify("error", msg);
      return;
    }

    const { cleanUrl, branch: resolvedBranch } = normalizeGitHubUrl(
      rawUrl,
      githubBranch
    );
    setGithubRepositoryUrl(cleanUrl);
    if (resolvedBranch && !githubBranch) {
      setGithubBranch(resolvedBranch);
    }

    const meta = resolveSubmissionMetadata();
    setTerminalLogs([]);
    setTerminalResult(null);
    setTerminalError("");
    setTerminalElapsed(0);
    setTerminalStatus("running");

    try {
      setSubmitting(true);
      setGithubStatus("Running security scan...");
      let completedAssessment: AssessmentDetail | null = null;
      await streamScanRequest(
        "/api/v1/assessments/submit-github-stream",
        {
          method: "POST",
          body: JSON.stringify({
            repository_url: cleanUrl,
            branch: resolvedBranch || null,
            github_token: githubToken || null,
            application_name: subName.trim(),
            version: subVersion.trim() || "1.0",
            department: meta.department,
            business_owner: meta.business_owner,
            technical_owner: meta.technical_owner,
            description: meta.description,
            ai_tool: subAiTool,
            app_type: subAppType,
            data_classification: subDataClass,
            external_connections: subConns,
            expected_users: subUsers,
            requires_admin_privileges: subAdminPriv,
          }),
        },
        {
          onLog: (logEv) => setTerminalLogs((prev) => [...prev, logEv]),
          onResult: (assessment) => {
            completedAssessment = assessment;
          },
          onError: (detail) => setTerminalError(detail),
        }
      );

      if (completedAssessment) {
        const assessment = completedAssessment as AssessmentDetail;
        setTerminalResult(assessment);
        setTerminalStatus("completed");
        setSelectedCode(assessment.assessment_code);
        setSelectedAssessment(assessment);

        notify(
          assessment.technical_status === "REJECT" ||
            assessment.technical_status === "SCAN-ERROR"
            ? "error"
            : "success",
          `Repository scanned: ${assessment.assessment_code}`
        );

        refreshAllData(assessment.assessment_code).catch((err) => {
          console.warn("Dashboard refresh warning:", err);
        });
      }
    } catch (err) {
      const errMsg = getErrorMessage(err);
      setGithubError(errMsg);
      setTerminalStatus("failed");
      setTerminalError(errMsg);
      notify("error", errMsg);
    } finally {
      setSubmitting(false);
      setGithubStatus("");
      setGithubToken("");
    }
  }

  async function handleUpdateFindingStatus(findingId: number, status: string) {
    if (!selectedAssessment) return;
    try {
      const updated = await apiFetch<AssessmentDetail>(
        `/api/v1/assessments/${selectedAssessment.assessment_code}/findings/${findingId}`,
        {
          method: "PATCH",
          body: JSON.stringify({
            status,
            reviewer_comment: `Classified as '${status}' by ${currentUser?.full_name}`,
          }),
        }
      );
      setSelectedAssessment(updated);
      await refreshAllData(updated.assessment_code);
      notify("success", `Finding status updated to ${status}.`);
    } catch (err) {
      notify("error", getErrorMessage(err));
    }
  }

  async function handleUpdateDependencyStatus(
    depId: number,
    reviewer_status: string
  ) {
    if (!selectedAssessment) return;
    try {
      const updated = await apiFetch<AssessmentDetail>(
        `/api/v1/assessments/${selectedAssessment.assessment_code}/dependencies/${depId}`,
        {
          method: "PATCH",
          body: JSON.stringify({ reviewer_status }),
        }
      );
      setSelectedAssessment(updated);
      await refreshAllData(updated.assessment_code);
      notify("success", `Dependency status updated to ${reviewer_status}.`);
    } catch (err) {
      notify("error", getErrorMessage(err));
    }
  }

  async function handleSaveManualGates() {
    if (!selectedAssessment) return;
    try {
      const updated = await apiFetch<AssessmentDetail>(
        `/api/v1/assessments/${selectedAssessment.assessment_code}/manual-gates`,
        {
          method: "PATCH",
          body: JSON.stringify({
            av_status: avStatusInput,
            av_notes: avNotesInput,
            av_evidence_ref: avRefInput,
            sandbox_status: sbStatusInput,
            sandbox_technology: sbTechInput,
            sandbox_notes: sbNotesInput,
          }),
        }
      );
      setSelectedAssessment(updated);
      await refreshAllData(updated.assessment_code);
      notify("success", "Manual checks saved.");
    } catch (err) {
      notify("error", getErrorMessage(err));
    }
  }

  async function handleRecordDecision(decision: string) {
    if (!selectedAssessment) return;
    const notesToUse =
      decisionNotes.trim() ||
      `Formal ${decision} recorded by ${currentUser?.full_name} (${currentUser?.role}).`;
    try {
      const updated = await apiFetch<AssessmentDetail>(
        `/api/v1/assessments/${selectedAssessment.assessment_code}/decision`,
        {
          method: "POST",
          body: JSON.stringify({ decision, notes: notesToUse }),
        }
      );
      setSelectedAssessment(updated);
      await refreshAllData(updated.assessment_code);
      notify("success", `Saved decision for ${updated.assessment_code}.`);
    } catch (err) {
      notify("error", getErrorMessage(err));
    }
  }

  async function handleReevaluateAssessment() {
    if (!selectedAssessment) return;
    try {
      const updated = await apiFetch<AssessmentDetail>(
        `/api/v1/assessments/${selectedAssessment.assessment_code}/re-evaluate`,
        { method: "POST" }
      );
      setSelectedAssessment(updated);
      await refreshAllData(updated.assessment_code);
      notify("success", `Re-evaluated ${updated.assessment_code}.`);
    } catch (err) {
      notify("error", getErrorMessage(err));
    }
  }

  const intelStatus = dashboardData?.security_intelligence?.status || "HEALTHY";

  if (needsLogin) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#070b14] px-4 text-slate-100">
        <form
          onSubmit={handleLogin}
          className="w-full max-w-md space-y-5 rounded-2xl border border-slate-800 bg-slate-900/80 p-8 shadow-2xl"
        >
          <div>
            <h1 className="text-xl font-bold text-white">Sign in to S-Gates</h1>
            <p className="mt-1 text-sm text-slate-400">
              Sign in with your S-Gates email and password.
            </p>
          </div>
          {loginError && (
            <div
              role="alert"
              className="rounded-lg border border-rose-500/40 bg-rose-950/50 p-3 text-sm text-rose-200"
            >
              {loginError}
            </div>
          )}
          <div className="space-y-1.5">
            <label
              htmlFor="login-email"
              className="block text-sm text-slate-200 font-medium"
            >
              Email
            </label>
            <input
              id="login-email"
              type="email"
              autoComplete="username"
              required
              value={loginEmail}
              onChange={(event) => setLoginEmail(event.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-white focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400"
            />
          </div>
          <div className="space-y-1.5">
            <label
              htmlFor="login-password"
              className="block text-sm text-slate-200 font-medium"
            >
              Password
            </label>
            <input
              id="login-password"
              type="password"
              autoComplete="current-password"
              required
              value={loginPassword}
              onChange={(event) => setLoginPassword(event.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-white focus:border-emerald-500 focus-visible:ring-2 focus-visible:ring-emerald-400"
            />
          </div>
          <button
            type="submit"
            disabled={loginSubmitting}
            className="w-full rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-bold text-slate-950 transition hover:bg-emerald-400 disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-emerald-300"
          >
            {loginSubmitting ? "Signing in..." : "Sign in"}
          </button>
        </form>
      </main>
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-[#070b14] text-slate-100">
      {dashboardData?.scanner_mode === "heuristic-demo" && (
        <div
          role="alert"
          className="border-b border-amber-500/50 bg-amber-950/80 px-6 py-2.5 text-xs text-amber-100"
        >
          <strong>DEMO MODE:</strong> External scanner binaries are not installed in this environment. Assessments are marked SCAN-ERROR and cannot be approved.
        </div>
      )}

      {intelStatus !== "HEALTHY" &&
        dashboardData?.scanner_mode !== "heuristic-demo" && (
          <div
            role="alert"
            className="bg-rose-950/90 border-b border-rose-500/50 px-6 py-2.5 flex items-center text-xs text-rose-200 gap-2 font-semibold"
          >
            <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" aria-hidden="true" />
            <span>
              SECURITY INTELLIGENCE STATUS: {intelStatus}. Trivy vulnerability database is unavailable; scans fail closed as Scan Error.
            </span>
          </div>
        )}

      <HeaderNav
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        selectedCode={selectedCode}
        currentUser={currentUser}
        intelStatus={intelStatus}
        scannerMode={dashboardData?.scanner_mode}
        notifications={notifications}
        showNotifDrawer={showNotifDrawer}
        onToggleNotifDrawer={() => setShowNotifDrawer(!showNotifDrawer)}
        onCloseNotifDrawer={() => setShowNotifDrawer(false)}
        onLogout={handleLogout}
      />

      {bannerMsg && (
        <div
          role="status"
          aria-live="polite"
          className="fixed bottom-6 right-6 z-50 max-w-lg w-full px-4"
        >
          <div
            className={`rounded-xl border px-4 py-3.5 text-xs font-semibold flex items-center justify-between shadow-2xl backdrop-blur-md ${
              bannerMsg.type === "error"
                ? "bg-rose-950/95 border-rose-500/70 text-rose-100"
                : bannerMsg.type === "success"
                ? "bg-emerald-950/95 border-emerald-500/70 text-emerald-100"
                : "bg-sky-950/95 border-sky-500/70 text-sky-100"
            }`}
          >
            <div className="flex items-center gap-2.5">
              <span
                aria-hidden="true"
                className={`inline-block w-2.5 h-2.5 rounded-full shrink-0 ${
                  bannerMsg.type === "error"
                    ? "bg-rose-400 animate-pulse"
                    : bannerMsg.type === "success"
                    ? "bg-emerald-400"
                    : "bg-sky-400"
                }`}
              />
              <span className="leading-snug">{bannerMsg.text}</span>
            </div>
            <button
              type="button"
              onClick={() => setBannerMsg(null)}
              className="text-xs underline ml-4 opacity-90 hover:opacity-100 transition shrink-0 focus-visible:ring-2 focus-visible:ring-emerald-400 rounded px-1"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      <main className="mx-auto max-w-[1440px] w-full flex-1 px-6 py-6 space-y-6">
        {loading && !dashboardData && (
          <div aria-label="Loading workspace" className="space-y-6 animate-pulse">
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {[0, 1, 2, 3].map((i) => (
                <div
                  key={i}
                  className="h-24 rounded-xl border border-slate-800 bg-slate-900/60"
                />
              ))}
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {[0, 1, 2, 3].map((i) => (
                <div
                  key={i}
                  className="h-36 rounded-xl border border-slate-800 bg-slate-900/60"
                />
              ))}
            </div>
          </div>
        )}

        {activeTab === "dashboard" && dashboardData && (
          <OverviewDashboard
            dashboardData={dashboardData}
            onStartNewScan={() => setActiveTab("submit")}
            onOpenAssessment={(code) => {
              loadAssessmentDetail(code);
              setActiveTab("studio");
              setStudioSubTab("summary");
            }}
          />
        )}

        {activeTab === "submit" && (
          <NewScanView
            subName={subName}
            setSubName={setSubName}
            subVersion={subVersion}
            setSubVersion={setSubVersion}
            subDept={subDept}
            setSubDept={setSubDept}
            subBizOwner={subBizOwner}
            setSubBizOwner={setSubBizOwner}
            subTechOwner={subTechOwner}
            setSubTechOwner={setSubTechOwner}
            subDesc={subDesc}
            setSubDesc={setSubDesc}
            subAiTool={subAiTool}
            setSubAiTool={setSubAiTool}
            subAppType={subAppType}
            setSubAppType={setSubAppType}
            subDataClass={subDataClass}
            setSubDataClass={setSubDataClass}
            subConns={subConns}
            setSubConns={setSubConns}
            subUsers={subUsers}
            setSubUsers={setSubUsers}
            subAdminPriv={subAdminPriv}
            setSubAdminPriv={setSubAdminPriv}
            subZipFile={subZipFile}
            setSubZipFile={setSubZipFile}
            githubRepositoryUrl={githubRepositoryUrl}
            setGithubRepositoryUrl={setGithubRepositoryUrl}
            githubBranch={githubBranch}
            setGithubBranch={setGithubBranch}
            githubToken={githubToken}
            setGithubToken={setGithubToken}
            githubStatus={githubStatus}
            githubError={githubError}
            clearGithubError={() => setGithubError("")}
            submitting={submitting}
            systemSettings={systemSettings}
            onSubmitZip={handleMultipartZipSubmit}
            onSubmitGithub={handleGitHubSubmit}
            terminalLogs={terminalLogs}
            terminalStatus={terminalStatus}
            terminalElapsed={terminalElapsed}
            terminalResult={terminalResult}
            terminalError={terminalError}
            onClearTerminal={() => {
              setTerminalLogs([]);
              setTerminalStatus("idle");
              setTerminalElapsed(0);
              setTerminalResult(null);
              setTerminalError("");
            }}
            onViewReport={(assessment) => {
              setSelectedCode(assessment.assessment_code);
              setSelectedAssessment(assessment);
              setActiveTab("studio");
              setStudioSubTab("summary");
            }}
          />
        )}

        {activeTab === "studio" && (
          <AssessmentDetailView
            selectedAssessment={selectedAssessment}
            assessmentsList={assessmentsList}
            currentUser={currentUser}
            studioSubTab={studioSubTab}
            setStudioSubTab={setStudioSubTab}
            onSelectAssessment={(code) => loadAssessmentDetail(code)}
            onStartNewScan={() => setActiveTab("submit")}
            onEvidenceDownload={handleEvidenceDownload}
            onReevaluate={handleReevaluateAssessment}
            onDeleteAssessment={(code) =>
              setConfirmAction({ type: "delete-assessment", code })
            }
            deletingCode={deletingCode}
            onUpdateFindingStatus={handleUpdateFindingStatus}
            onUpdateDependencyStatus={handleUpdateDependencyStatus}
            avStatusInput={avStatusInput}
            setAvStatusInput={setAvStatusInput}
            avRefInput={avRefInput}
            setAvRefInput={setAvRefInput}
            avNotesInput={avNotesInput}
            setAvNotesInput={setAvNotesInput}
            sbStatusInput={sbStatusInput}
            setSbStatusInput={setSbStatusInput}
            sbTechInput={sbTechInput}
            setSbTechInput={setSbTechInput}
            sbNotesInput={sbNotesInput}
            setSbNotesInput={setSbNotesInput}
            onSaveManualGates={handleSaveManualGates}
            decisionNotes={decisionNotes}
            setDecisionNotes={setDecisionNotes}
            onRecordDecision={handleRecordDecision}
          />
        )}

        {activeTab === "inventory" && (
          <InventoryView
            inventoryList={inventoryList}
            currentUser={currentUser}
            deletingAppId={deletingAppId}
            onDeleteApplication={(sgatesAppId, appName) =>
              setConfirmAction({
                type: "delete-application",
                sgatesAppId,
                appName,
              })
            }
            onOpenAssessment={(code) => {
              loadAssessmentDetail(code);
              setActiveTab("studio");
              setStudioSubTab("summary");
            }}
          />
        )}

        {activeTab === "governance" && systemSettings && (
          <AdminGovernanceView
            systemSettings={systemSettings}
            currentUser={currentUser}
            auditLogsData={auditLogsData}
            onOpenPurgeModal={() => setConfirmAction({ type: "purge-history" })}
          />
        )}

        {activeTab === "readme" && <GuideView systemSettings={systemSettings} />}

        <ConfirmDialog
          open={confirmAction !== null}
          title={
            confirmAction?.type === "delete-assessment"
              ? `Delete assessment ${confirmAction.code}?`
              : confirmAction?.type === "delete-application"
              ? `Delete application ${confirmAction.appName}?`
              : "Purge all scan history?"
          }
          description={
            confirmAction?.type === "delete-assessment"
              ? `This removes assessment ${confirmAction.code} from PostgreSQL and deletes its Evidence Vault folder on disk.`
              : confirmAction?.type === "delete-application"
              ? `This permanently deletes ${confirmAction.sgatesAppId} (${confirmAction.appName}), all linked assessments, findings, and Evidence Vault files on disk.`
              : "This permanently deletes every assessment, finding, dependency record, and Evidence Vault folder on disk."
          }
          confirmLabel={
            confirmAction?.type === "purge-history"
              ? "Purge All History"
              : "Delete"
          }
          requireTypedWord={
            confirmAction?.type === "purge-history" ? "DELETE" : undefined
          }
          busy={Boolean(deletingCode || deletingAppId)}
          onConfirm={executeConfirmedAction}
          onCancel={() => setConfirmAction(null)}
        />
      </main>
    </div>
  );
}
