"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  AlertTriangle,
  FileArchive,
  Upload,
  CheckCircle2,
  XCircle,
  Search,
  Download,
  ExternalLink,
  RefreshCw,
  Lock,
  Layers,
  Terminal,
  FileText,
  UserCheck,
  Database,
  Bell,
  Settings,
  Activity,
  Package,
  Cpu,
  FolderTree,
  Share2,
  Ticket,
  EyeOff,
  ChevronRight,
  Sparkles,
  Loader2,
  BookOpen,
  Trash2,
  HelpCircle,
  ChevronDown,
  Info,
} from "lucide-react";
import {
  apiFetch,
  AssessmentDetail,
  AssessmentSummary,
  ApplicationSummary,
  AuditEvent,
  ApiError,
  apiDownload,
  deleteApplication,
  deleteAssessment,
  purgeAllAssessments,
  DashboardSummary,
  clearStoredToken,
  getStoredToken,
  NotificationItem,
  ScanStreamLogEvent,
  setStoredToken,
  streamScanRequest,
  SystemSettings,
  UserPersona,
} from "@/lib/api";
import LiveScanTerminal, {
  TerminalScanStatus,
} from "@/components/LiveScanTerminal";

type ActiveTab =
  | "dashboard"
  | "submit"
  | "studio"
  | "inventory"
  | "governance"
  | "readme";

type StudioSubTab =
  | "overview"
  | "findings"
  | "dependencies"
  | "manual-gates"
  | "evidence-vault"
  | "audit-history";

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

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected error";
}

export default function SGatesPortalPage() {
  const [currentUser, setCurrentUser] = useState<UserPersona | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>("dashboard");
  const [studioSubTab, setStudioSubTab] = useState<StudioSubTab>("overview");

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

  // Filters in Findings Dashboard (PRD Section 22)
  const [scannerFilter, setScannerFilter] = useState<string>("ALL");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [findingSearch, setFindingSearch] = useState<string>("");

  // Inventory search/filter
  const [invSearch, setInvSearch] = useState<string>("");
  const [invStatusFilter, setInvStatusFilter] = useState<string>("");

  // Submission Form State (PRD Section 9.1)
  const [subName, setSubName] = useState("Finance Expense Receipt Validator");
  const [subVersion, setSubVersion] = useState("1.0");
  const [subDept, setSubDept] = useState("Finance & Accounting");
  const [subBizOwner, setSubBizOwner] = useState("CFO Regional Office");
  const [subTechOwner, setSubTechOwner] = useState(
    "Alex Rivera (Citizen Developer)"
  );
  const [subDesc, setSubDesc] = useState(
    "Automated receipt OCR & policy verification utility built with Cursor and Claude."
  );
  const [subAiTool, setSubAiTool] = useState("Cursor");
  const [subAppType, setSubAppType] = useState("Internal Web Application");
  const [subDataClass, setSubDataClass] = useState("Confidential");
  const [subConns, setSubConns] = useState<string[]>([
    "SharePoint",
    "Database",
  ]);
  const [subUsers, setSubUsers] = useState<number>(40);
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

  // Admin Deletion & History Purge State
  const [deletingCode, setDeletingCode] = useState<string | null>(null);
  const [deletingAppId, setDeletingAppId] = useState<string | null>(null);
  const [showPurgeModal, setShowPurgeModal] = useState<boolean>(false);
  const [purgeConfirmText, setPurgeConfirmText] = useState<string>("");

  // UI Simplification: Toggle for Advanced Enterprise Settings
  const [showEnterpriseSettings, setShowEnterpriseSettings] = useState<boolean>(false);

  // Live Backend Terminal State
  const [terminalLogs, setTerminalLogs] = useState<ScanStreamLogEvent[]>([]);
  const [terminalStatus, setTerminalStatus] = useState<TerminalScanStatus>("idle");
  const [terminalElapsed, setTerminalElapsed] = useState<number>(0);
  const [terminalResult, setTerminalResult] = useState<AssessmentDetail | null>(null);
  const [terminalError, setTerminalError] = useState<string>("");

  // Toast / Alert feedback
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

  const notify = useCallback((type: "success" | "error" | "info", text: string) => {
    setBannerMsg({ type, text });
    setTimeout(() => {
      setBannerMsg((prev) => (prev?.text === text ? null : prev));
    }, 6500);
  }, []);

  async function handleLogin(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoginSubmitting(true);
    setLoginError("");
    try {
      const result = await apiFetch<{ access_token: string; user: UserPersona }>(
        "/api/v1/auth/login",
        {
          method: "POST",
          body: JSON.stringify({ email: loginEmail, password: loginPassword }),
        }
      );
      setStoredToken(result.access_token);
      setCurrentUser(result.user);
      setNeedsLogin(false);
      setLoginPassword("");
      try {
        await refreshAllData();
      } catch (error) {
        notify("error", `Could not load dashboard data: ${getErrorMessage(error)}`);
      }
    } catch (err) {
      setLoginError(err instanceof Error ? err.message : "Login failed.");
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

  async function handleDeleteAssessment(code: string) {
    if (!code) return;
    const confirmed = window.confirm(
      `Confirm: Delete assessment ${code}?\n\nThis will permanently remove the scan results from the database and delete its Evidence Vault folder from disk.`
    );
    if (!confirmed) return;

    try {
      setDeletingCode(code);
      const res = await deleteAssessment(code);
      notify("success", res.message || `Assessment ${code} deleted successfully.`);
      if (selectedCode === code) {
        setSelectedCode("");
        setSelectedAssessment(null);
      }
      await refreshAllData();
    } catch (err) {
      notify("error", `Failed to delete assessment: ${getErrorMessage(err)}`);
    } finally {
      setDeletingCode(null);
    }
  }

  async function handleDeleteApplication(sgatesAppId: string, appName: string) {
    if (!sgatesAppId) return;
    const confirmed = window.confirm(
      `Confirm: Delete application ${sgatesAppId} (${appName})?\n\nThis will permanently delete the application from inventory along with ALL linked historical assessments, findings, and Evidence Vault artifacts on disk.`
    );
    if (!confirmed) return;

    try {
      setDeletingAppId(sgatesAppId);
      const res = await deleteApplication(sgatesAppId);
      notify(
        "success",
        res.message || `Application ${sgatesAppId} deleted successfully.`
      );
      if (selectedAssessment?.application?.sgates_app_id === sgatesAppId) {
        setSelectedCode("");
        setSelectedAssessment(null);
      }
      await refreshAllData();
    } catch (err) {
      notify("error", `Failed to delete application: ${getErrorMessage(err)}`);
    } finally {
      setDeletingAppId(null);
    }
  }

  async function handlePurgeAllHistory() {
    if (purgeConfirmText.trim().toUpperCase() !== "DELETE") {
      notify("error", 'Type "DELETE" to confirm purging all scan history.');
      return;
    }
    try {
      setDeletingCode("all");
      const res = await purgeAllAssessments();
      setShowPurgeModal(false);
      setPurgeConfirmText("");
      setSelectedCode("");
      setSelectedAssessment(null);
      notify("success", res.message || "All scan history purged successfully.");
      await refreshAllData();
    } catch (err) {
      notify("error", `Failed to purge scan history: ${getErrorMessage(err)}`);
    } finally {
      setDeletingCode(null);
    }
  }

  useEffect(() => {
    if (terminalStatus !== "running") return;
    const startMs = Date.now();
    const interval = window.setInterval(() => {
      setTerminalElapsed((Date.now() - startMs) / 1000);
    }, 100);
    return () => window.clearInterval(interval);
  }, [terminalStatus]);

  const loadAssessmentDetail = useCallback(async (code: string) => {
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
  }, [notify]);

  const refreshAllData = useCallback(async (codeToLoad?: string) => {
    const [dash, asmts, inv, cfg, logs, notifs] = await Promise.all([
      apiFetch<DashboardSummary>("/api/v1/applications/dashboard-summary"),
      apiFetch<AssessmentSummary[]>("/api/v1/assessments"),
      apiFetch<ApplicationSummary[]>("/api/v1/applications"),
      apiFetch<SystemSettings>("/api/v1/admin/settings"),
      apiFetch<{ chain_integrity_verified: boolean; total_records: number; records: AuditEvent[] }>("/api/v1/admin/audit-logs"),
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
  }, [loadAssessmentDetail]);

  // Bootstrap authentication & data after the data callbacks are initialized.
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
        await refreshAllData();
      } catch (err) {
        if (!active) return;
        if (err instanceof ApiError && err.status === 401) {
          clearStoredToken();
          setNeedsLogin(true);
        } else {
          notify("error", `Initialization error: ${getErrorMessage(err)}`);
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    init();
    return () => {
      active = false;
    };
  }, [notify, refreshAllData]);

  async function handleMultipartZipSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!subZipFile) {
      notify("error", "Please select a .zip source archive to upload.");
      return;
    }
    setTerminalLogs([]);
    setTerminalResult(null);
    setTerminalError("");
    setTerminalElapsed(0);
    setTerminalStatus("running");

    try {
      setSubmitting(true);
      const fd = new FormData();
      fd.append("application_name", subName);
      fd.append("version", subVersion);
      fd.append("department", subDept);
      fd.append("business_owner", subBizOwner);
      fd.append("technical_owner", subTechOwner);
      fd.append("description", subDesc);
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
          `Uploaded & scanned ${subZipFile.name} -> ${res.assessment_code} (${res.technical_status})`
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

  function normalizeGitHubUrl(url: string, currentBranch: string): { cleanUrl: string; branch: string } {
    let clean = url.trim();
    let branch = currentBranch.trim();

    // Convert SSH git@github.com:owner/repo.git to https://github.com/owner/repo
    if (clean.startsWith("git@github.com:")) {
      clean = "https://github.com/" + clean.slice("git@github.com:".length);
    }

    // Auto-prepend https:// if missing
    if (clean.startsWith("github.com/")) {
      clean = "https://" + clean;
    } else if (clean.startsWith("http://github.com/")) {
      clean = "https://" + clean.slice("http://".length);
    }

    // Handle /tree/<branch> or /blob/<branch> URLs pasted from browser
    const treeMatch = clean.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)\/(?:tree|blob)\/([^/]+)(?:\/.*)?$/);
    if (treeMatch) {
      clean = `https://github.com/${treeMatch[1]}/${treeMatch[2]}`;
      if (!branch) {
        branch = decodeURIComponent(treeMatch[3]);
      }
    }

    // Strip trailing .git and trailing slashes
    clean = clean.replace(/\/+$/, "");
    if (clean.endsWith(".git")) {
      clean = clean.slice(0, -4);
    }

    return { cleanUrl: clean, branch };
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

    const { cleanUrl, branch: resolvedBranch } = normalizeGitHubUrl(rawUrl, githubBranch);
    setGithubRepositoryUrl(cleanUrl);
    if (resolvedBranch && !githubBranch) {
      setGithubBranch(resolvedBranch);
    }

    setTerminalLogs([]);
    setTerminalResult(null);
    setTerminalError("");
    setTerminalElapsed(0);
    setTerminalStatus("running");

    try {
      setSubmitting(true);
      setGithubStatus("Streaming live security scan from backend...");
      let completedAssessment: AssessmentDetail | null = null;
      await streamScanRequest(
        "/api/v1/assessments/submit-github-stream",
        {
          method: "POST",
          body: JSON.stringify({
            repository_url: cleanUrl,
            branch: resolvedBranch || null,
            github_token: githubToken || null,
            application_name: subName,
            version: subVersion,
            department: subDept,
            business_owner: subBizOwner,
            technical_owner: subTechOwner,
            description: subDesc,
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
          `GitHub repository scanned: ${assessment.assessment_code} (${assessment.technical_status})`
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
      notify(
        "success",
        `Finding status updated to '${status}'. Risk Decision recalculated: ${updated.technical_status}`
      );
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
      notify(
        "success",
        `Dependency status updated to ${reviewer_status}. Assessment status: ${updated.technical_status}`
      );
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
      notify(
        "success",
        `Manual security gates saved. Updated technical status: ${updated.technical_status}`
      );
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
          body: JSON.stringify({
            decision,
            notes: notesToUse,
          }),
        }
      );
      setSelectedAssessment(updated);
      await refreshAllData(updated.assessment_code);
      notify(
        "success",
        `Decision '${decision}' recorded on ${updated.assessment_code}.`
      );
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
      notify(
        "success",
        `Re-evaluated stored findings for ${updated.assessment_code} -> ${updated.technical_status}`
      );
    } catch (err) {
      notify("error", getErrorMessage(err));
    }
  }

  function renderStatusBadge(status: string) {
    switch (status) {
      case "PASS-WITH-MANUAL-CHECKS":
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/15 px-3 py-1 text-xs font-semibold text-emerald-300 border border-emerald-500/30">
            <ShieldCheck className="h-3.5 w-3.5" />
            PASS-WITH-MANUAL-CHECKS
          </span>
        );
      case "REVIEW":
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/15 px-3 py-1 text-xs font-semibold text-amber-300 border border-amber-500/30">
            <ShieldAlert className="h-3.5 w-3.5" />
            REVIEW
          </span>
        );
      case "REJECT":
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-rose-500/15 px-3 py-1 text-xs font-semibold text-rose-300 border border-rose-500/30">
            <ShieldX className="h-3.5 w-3.5" />
            REJECT
          </span>
        );
      case "SCAN-ERROR":
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-purple-500/20 px-3 py-1 text-xs font-semibold text-purple-300 border border-purple-500/40">
            <AlertTriangle className="h-3.5 w-3.5" />
            SCAN-ERROR
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

  function renderSeverityBadge(sev: string) {
    const map: Record<string, string> = {
      CRITICAL: "bg-rose-500/20 text-rose-300 border-rose-500/40",
      HIGH: "bg-orange-500/20 text-orange-300 border-orange-500/40",
      MEDIUM: "bg-amber-500/20 text-amber-300 border-amber-500/40",
      LOW: "bg-sky-500/20 text-sky-300 border-sky-500/40",
      NONE: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
    };
    return (
      <span
        className={`inline-flex items-center rounded px-2 py-0.5 text-[11px] font-bold border ${
          map[sev] || "bg-slate-800 text-slate-300 border-slate-700"
        }`}
      >
        {sev}
      </span>
    );
  }

  const filteredFindings = (selectedAssessment?.findings || []).filter((f) => {
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

  const intelStatus =
    dashboardData?.security_intelligence?.status || "HEALTHY";

  if (needsLogin) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#070b14] px-4 text-slate-100">
        <form
          onSubmit={handleLogin}
          className="w-full max-w-md space-y-5 rounded-2xl border border-slate-800 bg-slate-900/80 p-8 shadow-2xl"
        >
          <div>
            <div className="text-xl font-bold text-white">Sign in to S-Gates</div>
            <p className="mt-1 text-sm text-slate-400">
              Use your provisioned S-Gates account.
            </p>
          </div>
          {loginError && (
            <div role="alert" className="rounded-lg border border-rose-500/40 bg-rose-950/50 p-3 text-sm text-rose-200">
              {loginError}
            </div>
          )}
          <label className="block space-y-1.5 text-sm text-slate-300">
            <span>Email</span>
            <input
              type="email"
              autoComplete="username"
              required
              value={loginEmail}
              onChange={(event) => setLoginEmail(event.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-white focus:border-emerald-500 focus:outline-none"
            />
          </label>
          <label className="block space-y-1.5 text-sm text-slate-300">
            <span>Password</span>
            <input
              type="password"
              autoComplete="current-password"
              required
              value={loginPassword}
              onChange={(event) => setLoginPassword(event.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-white focus:border-emerald-500 focus:outline-none"
            />
          </label>
          <button
            type="submit"
            disabled={loginSubmitting}
            className="w-full rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-bold text-slate-950 transition hover:bg-emerald-400 disabled:opacity-50"
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
        <div role="alert" className="border-b border-amber-500/50 bg-amber-950/80 px-6 py-3 text-sm text-amber-100">
          <strong>DEMO HEURISTICS ONLY:</strong> This build does not execute Trivy, Gitleaks, Semgrep, antivirus, or sandbox tools. Findings are illustrative; assessments are marked SCAN-ERROR and cannot be approved.
        </div>
      )}
      {/* Top Security Intelligence Outdated Alert (PRD Section 30) */}
      {intelStatus !== "HEALTHY" && dashboardData?.scanner_mode !== "heuristic-demo" && (
        <div className="bg-rose-950/90 border-b border-rose-500/50 px-6 py-2.5 flex items-center justify-between text-xs text-rose-200">
          <div className="flex items-center gap-2 font-semibold">
            <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" />
            <span>
              SECURITY INTELLIGENCE STATUS: {intelStatus} — Trivy vulnerability
              database is unavailable. Per PRD Section 30, scans will result in
              SCAN-ERROR (never PASS) and Pilot Approval is blocked.
            </span>
          </div>
        </div>
      )}

      {/* Primary Header */}
      <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-[#0b1120]/95 backdrop-blur">
        <div className="mx-auto max-w-[1440px] px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
          {/* Brand */}
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center shadow-inner">
              <ShieldCheck className="h-6 w-6 text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <span className="text-lg font-bold tracking-tight text-white">
                  S-GATES
                </span>
                <span className="rounded bg-emerald-500/15 border border-emerald-500/30 px-2 py-0.5 text-[11px] font-mono font-semibold text-emerald-300">
                  v1.0 MVP
                </span>
                <span
                  className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-mono font-semibold border ${
                    intelStatus === "HEALTHY"
                      ? "bg-emerald-950/60 border-emerald-500/30 text-emerald-300"
                      : "bg-rose-950/80 border-rose-500/50 text-rose-300"
                  }`}
                >
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      intelStatus === "HEALTHY"
                        ? "bg-emerald-400"
                        : "bg-rose-400 animate-pulse"
                    }`}
                  />
                  {dashboardData?.scanner_mode === "heuristic-demo"
                    ? "Scanner mode: DEMO"
                    : `Intel DB: ${intelStatus}`}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Application Security Gateway —{" "}
                <span className="text-slate-300 italic">
                  Build Fast. Scan First. Deploy with Confidence.
                </span>
              </p>
            </div>
          </div>

          {/* Signed-in user and notifications */}
          <div className="flex items-center gap-3">
            <span className="hidden text-xs text-slate-400 sm:inline">
              {currentUser?.full_name} ({currentUser?.role})
            </span>
            <button
              onClick={handleLogout}
              className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 transition hover:border-slate-500 hover:text-white"
            >
              Sign out
            </button>

            {/* Notification Bell */}
            <div className="relative">
              <button
                onClick={() => setShowNotifDrawer(!showNotifDrawer)}
                className="relative rounded-lg bg-slate-900 border border-slate-800 p-2 text-slate-300 hover:text-white hover:border-slate-700 transition"
                title="In-app workflow notifications"
              >
                <Bell className="h-4 w-4" />
                {notifications.length > 0 && (
                  <span className="absolute -top-1 -right-1 h-4 min-w-[16px] rounded-full bg-emerald-500 px-1 text-[10px] font-bold text-slate-950 flex items-center justify-center">
                    {notifications.length}
                  </span>
                )}
              </button>

              {showNotifDrawer && (
                <div className="absolute right-0 mt-2 w-96 rounded-xl bg-slate-900 border border-slate-700 shadow-2xl p-4 z-50">
                  <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                      S-Gates Event Notifications (Section 36)
                    </span>
                    <button
                      onClick={() => setShowNotifDrawer(false)}
                      className="text-xs text-slate-400 hover:text-white"
                    >
                      Close
                    </button>
                  </div>
                  <div className="max-h-72 overflow-y-auto space-y-2">
                    {notifications.map((n) => (
                      <div
                        key={n.id}
                        className="rounded-lg bg-slate-950/70 border border-slate-800 p-2.5 text-xs"
                      >
                        <div className="flex items-center justify-between text-[11px] text-emerald-400 font-semibold">
                          <span>{n.event_type}</span>
                          <span className="font-mono text-slate-400">
                            {n.assessment_code}
                          </span>
                        </div>
                        <p className="text-slate-200 mt-1">{n.message}</p>
                        <span className="text-[10px] text-slate-500 mt-1 block">
                          Channel: {n.channel}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Navigation Bar */}
        <div className="mx-auto max-w-[1440px] px-6 flex items-center gap-1 overflow-x-auto border-t border-slate-800/60">
          {[
            {
              id: "dashboard",
              label: "1. Overview Dashboard",
              icon: Activity,
            },
            {
              id: "submit",
              label: "2. New Code Scan",
              icon: Upload,
            },
            {
              id: "studio",
              label: selectedCode
                ? `3. Assessment Results (${selectedCode})`
                : "3. Assessment Results",
              icon: Terminal,
            },
            {
              id: "inventory",
              label: "4. Application Inventory",
              icon: Layers,
            },
            {
              id: "governance",
              label: "5. Admin & Audit Trail",
              icon: Settings,
            },
            {
              id: "readme",
              label: "Readme & Guidance",
              icon: BookOpen,
            },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as ActiveTab)}
                className={`flex items-center gap-2 px-4 py-3 text-xs font-semibold border-b-2 transition whitespace-nowrap ${
                  isActive
                    ? "border-emerald-400 text-emerald-300 bg-emerald-500/5"
                    : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40"
                }`}
              >
                <Icon className="h-4 w-4" />
                {tab.label}
              </button>
            );
          })}
        </div>
      </header>

      {/* S-Gates Security Gateway Header Principle */}
      <div className="bg-slate-900/90 border-b border-slate-800 px-6 py-2">
        <div className="mx-auto max-w-[1440px] flex flex-wrap items-center justify-between gap-2 text-xs text-slate-300">
          <div className="flex items-center gap-2">
            <Lock className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
            <span>
              <strong className="text-white">
                S-Gates Security Engine:
              </strong>{" "}
              Powered by Aqua Trivy (CVE/SBOM), Gitleaks (Secrets), Semgrep (SAST), OSV-Scanner (MAL-*), GuardDog (Supply-Chain), and PyPI/npm Metadata checks inside an isolated workspace.
            </span>
          </div>
          {currentUser && (
            <span className="text-[11px] font-mono text-slate-400">
              Signed in as:{" "}
              <strong className="text-emerald-300">
                {currentUser.full_name}
              </strong>{" "}
              ({currentUser.role})
            </span>
          )}
        </div>
      </div>

      {/* Toast Notification Banner (Floating Sticky) */}
      {bannerMsg && (
        <div className="fixed bottom-6 right-6 z-50 max-w-lg w-full px-4 animate-in fade-in slide-in-from-bottom-5 duration-200">
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
              onClick={() => setBannerMsg(null)}
              className="text-xs underline ml-4 opacity-80 hover:opacity-100 transition shrink-0"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Main Content Container */}
      <main className="mx-auto max-w-[1440px] w-full flex-1 px-6 py-6 space-y-6">
        {loading && !dashboardData ? (
          <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-12 text-center text-sm text-slate-400">
            Loading S-Gates Security Engine & Governance Portal...
          </div>
        ) : null}

        {/* ===================================================================
            TAB 1: SECURITY GATEWAY DASHBOARD (PRD Sections 20, 21, 38)
           =================================================================== */}
        {activeTab === "dashboard" && dashboardData && (
          <div className="space-y-6">
            {/* PRD Section 38 Success Metrics Strip */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-4">
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>Scoped Citizen Apps Registered</span>
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                </div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="text-2xl font-bold text-white">
                    {dashboardData.kpis.registered_scoped_apps_pct}%
                  </span>
                  <span className="text-xs text-emerald-400 font-mono">
                    ({dashboardData.kpis.registered_apps_count} Registered Apps)
                  </span>
                </div>
                <p className="mt-1 text-[11px] text-slate-400">
                  {dashboardData.kpis.owners_defined_pct}% business and technical owner accountability
                </p>
              </div>

              <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-4">
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>Unresolved Criticals at Approval</span>
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                </div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="text-2xl font-bold text-emerald-400">
                    {dashboardData.kpis.unresolved_critical_at_approval}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">
                    Target: 0 (KPI Met)
                  </span>
                </div>
                <p className="mt-1 text-[11px] text-slate-400">
                  {dashboardData.kpis.total_vulnerabilities_detected} total
                  vulnerabilities & SAST issues caught pre-pilot
                </p>
              </div>

              <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-4">
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>Exposed Secrets at Approval</span>
                  <EyeOff className="h-4 w-4 text-emerald-400" />
                </div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="text-2xl font-bold text-emerald-400">
                    {dashboardData.kpis.exposed_secrets_at_approval}
                  </span>
                  <span className="text-xs text-rose-300 font-mono">
                    ({dashboardData.kpis.total_secrets_discovered} Blocked &
                    Redacted)
                  </span>
                </div>
                <p className="mt-1 text-[11px] text-slate-400">
                  Finding values are masked; retained source ZIPs remain unmodified.
                </p>
              </div>

              <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-4">
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>Source Code & Evidence Retained</span>
                  <Database className="h-4 w-4 text-emerald-400" />
                </div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="text-2xl font-bold text-white">
                    {dashboardData.kpis.source_code_retained_pct}%
                  </span>
                  <span className="text-xs text-sky-400 font-mono">
                    ({dashboardData.kpis.total_assessments_count} Vault Bundles)
                  </span>
                </div>
                <p className="mt-1 text-[11px] text-slate-400">
                  SHA-256 hashed ZIP + JSON/HTML reports + Audit Trail
                </p>
              </div>
            </div>

            {/* 4-State Risk Decision Engine Overview (PRD Section 20) */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                {
                  status: "PASS-WITH-MANUAL-CHECKS",
                  count:
                    dashboardData.status_breakdown["PASS-WITH-MANUAL-CHECKS"] ||
                    0,
                  desc: "0 Criticals, 0 Secrets, 0 Mandatory-Review SAST. Manual AV/Pilot checks apply.",
                  color: "border-emerald-500/40 bg-emerald-950/20",
                },
                {
                  status: "REVIEW",
                  count: dashboardData.status_breakdown["REVIEW"] || 0,
                  desc: "Heuristic rule match or missing manual evidence; validate all results externally.",
                  color: "border-amber-500/40 bg-amber-950/20",
                },
                {
                  status: "REJECT",
                  count: dashboardData.status_breakdown["REJECT"] || 0,
                  desc: "Confirmed active secret, Critical CVE, malware/typosquatting, traversal, or obfuscation.",
                  color: "border-rose-500/40 bg-rose-950/20",
                },
                {
                  status: "SCAN-ERROR",
                  count: dashboardData.status_breakdown["SCAN-ERROR"] || 0,
                  desc: "ZIP rejection or external scanner unavailable. Never interpreted as PASS.",
                  color: "border-purple-500/40 bg-purple-950/20",
                },
              ].map((card) => (
                <div
                  key={card.status}
                  className={`rounded-xl border p-4 ${card.color}`}
                >
                  <div className="flex items-center justify-between">
                    {renderStatusBadge(card.status)}
                    <span className="text-2xl font-bold text-white font-mono">
                      {card.count}
                    </span>
                  </div>
                  <p className="mt-2.5 text-xs text-slate-300 leading-relaxed">
                    {card.desc}
                  </p>
                </div>
              ))}
            </div>

            {/* Assessment Dashboard Cards (PRD Section 21 Layout) */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-base font-bold text-white">
                    Recent Security Assessments (Click any assessment to open
                    Studio)
                  </h2>
                  <p className="text-xs text-slate-400">
                    Heuristic demo findings only. External scanners and manual
                    verification tools are not installed in this build.
                  </p>
                </div>
                <button
                  onClick={() => setActiveTab("submit")}
                  className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-4 py-2 text-xs font-bold text-slate-950 transition shadow"
                >
                  <Upload className="h-4 w-4" />
                  New Application Assessment
                </button>
              </div>

              {dashboardData.recent_assessments.length === 0 ? (
                <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-8 text-center">
                  <p className="text-sm font-semibold text-slate-200">
                    No assessments yet
                  </p>
                  <p className="mt-1 text-xs text-slate-400">
                    Upload a source ZIP or scan a GitHub repository to see real results here.
                  </p>
                  <button
                    onClick={() => setActiveTab("submit")}
                    className="mt-4 rounded-lg bg-emerald-500 px-4 py-2 text-xs font-bold text-slate-950 transition hover:bg-emerald-400"
                  >
                    Start a scan
                  </button>
                </div>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {dashboardData.recent_assessments.map((a) => (
                  <div
                    key={a.assessment_code}
                    onClick={() => {
                      loadAssessmentDetail(a.assessment_code);
                      setActiveTab("studio");
                    }}
                    className="cursor-pointer rounded-xl border border-slate-800 bg-slate-900/70 hover:border-emerald-500/50 hover:bg-slate-900 transition p-5 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-800">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-bold text-emerald-400">
                              {a.assessment_code}
                            </span>
                            <span className="text-sm font-bold text-white">
                              {a.application_name}
                            </span>
                            <span className="rounded bg-slate-800 px-2 py-0.5 text-[11px] font-mono text-slate-300">
                              v{a.version}
                            </span>
                          </div>
                          <p className="text-xs text-slate-400 mt-0.5">
                            Dept: {a.department} • AI Tool: {a.ai_tool} • Risk:{" "}
                            <strong className="text-slate-200">
                              {a.risk_level}
                            </strong>
                          </p>
                        </div>
                        {renderStatusBadge(a.technical_status)}
                      </div>

                      {/* Scanner mini-grid matching PRD Section 21 */}
                      <div className="grid grid-cols-3 gap-3 my-3 text-xs font-mono">
                        <div className="rounded-lg bg-slate-950/80 border border-slate-800/80 p-2.5">
                          <div className="text-slate-400 font-sans font-semibold mb-1">
                            Dependency rules (demo)
                          </div>
                          <div className="flex justify-between text-[11px]">
                            <span className="text-rose-400">
                              Crit: {a.trivy_summary?.critical || 0}
                            </span>
                            <span className="text-orange-400">
                              High: {a.trivy_summary?.high || 0}
                            </span>
                          </div>
                          <div className="flex justify-between text-[11px] mt-0.5">
                            <span className="text-amber-300">
                              Med: {a.trivy_summary?.medium || 0}
                            </span>
                            <span className="text-sky-300">
                              Low: {a.trivy_summary?.low || 0}
                            </span>
                          </div>
                        </div>

                        <div className="rounded-lg bg-slate-950/80 border border-slate-800/80 p-2.5">
                          <div className="text-slate-400 font-sans font-semibold mb-1">
                            Secret patterns (demo)
                          </div>
                          <div className="text-[11px]">
                            Secrets:{" "}
                            <strong
                              className={
                                (a.gitleaks_summary?.secrets_detected || 0) > 0
                                  ? "text-rose-400"
                                  : "text-emerald-400"
                              }
                            >
                              {a.gitleaks_summary?.secrets_detected || 0}
                            </strong>
                          </div>
                          <div className="text-[10px] text-slate-500 mt-1">
                            Mask: ************
                          </div>
                        </div>

                        <div className="rounded-lg bg-slate-950/80 border border-slate-800/80 p-2.5">
                          <div className="text-slate-400 font-sans font-semibold mb-1">
                            SAST patterns (demo)
                          </div>
                          <div className="flex justify-between text-[11px]">
                            <span className="text-rose-400">
                              Crit: {a.semgrep_summary?.critical || 0}
                            </span>
                            <span className="text-orange-400">
                              High: {a.semgrep_summary?.high || 0}
                            </span>
                          </div>
                          <div className="flex justify-between text-[11px] mt-0.5">
                            <span className="text-amber-300">
                              Med: {a.semgrep_summary?.medium || 0}
                            </span>
                            <span className="text-sky-300">
                              Low: {a.semgrep_summary?.low || 0}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-xs">
                      <div className="flex items-center gap-3 text-[11px] text-slate-400">
                        <span>
                          AV Scan:{" "}
                          <strong className="text-slate-200">
                            {a.av_status}
                          </strong>
                        </span>
                        <span>•</span>
                        <span>
                          Sandbox:{" "}
                          <strong
                            className={
                              a.sandbox_required
                                ? "text-amber-300"
                                : "text-slate-200"
                            }
                          >
                            {a.sandbox_status}
                          </strong>
                        </span>
                      </div>
                      <span className="inline-flex items-center gap-1 text-emerald-400 font-semibold">
                        View Findings & Report
                        <ChevronRight className="h-3.5 w-3.5" />
                      </span>
                    </div>
                  </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ===================================================================
            TAB 2: NEW APPLICATION ASSESSMENT / ZIP SUBMISSION (PRD Sections 9, 11)
           =================================================================== */}
        {activeTab === "submit" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Columns: Application Intake & Scan Form */}
            <div className="lg:col-span-2 rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
              <div className="border-b border-slate-800 pb-4 mb-5">
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <FileArchive className="h-5 w-5 text-emerald-400" />
                  New Application Security Assessment
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Scan a GitHub repository or upload a source-code ZIP archive. S-Gates executes Aqua Trivy (SCA &amp; misconfiguration), Gitleaks (secret detection), and Semgrep (SAST) inside an isolated temporary workspace.
                </p>
              </div>

              <div className="space-y-5">
                {/* Basic App Info */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="sm:col-span-2">
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      Application / Project Name <span className="text-rose-400">*</span>
                    </label>
                    <input
                      type="text"
                      required
                      value={subName}
                      onChange={(e) => setSubName(e.target.value)}
                      placeholder="e.g. Internal Finance Portal"
                      className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      Application Version <span className="text-rose-400">*</span>
                    </label>
                    <input
                      type="text"
                      required
                      value={subVersion}
                      onChange={(e) => setSubVersion(e.target.value)}
                      className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white font-mono focus:border-emerald-500 focus:outline-none"
                    />
                  </div>
                </div>

                {/* Option A: GitHub Repository Scanning */}
                <div className="rounded-xl border border-emerald-500/40 bg-slate-950/80 p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="inline-block w-2.5 h-2.5 rounded-full bg-emerald-400" />
                      <h3 className="text-sm font-semibold text-white">
                        Option A: Scan from GitHub Repository
                      </h3>
                    </div>
                    <span className="text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      Recommended
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Supports public and private repositories. Enter a URL such as <code className="text-emerald-300">https://github.com/owner/repo</code>. Private repository tokens are used strictly for transient archive download and are never persisted or logged.
                  </p>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="sm:col-span-2">
                      <label htmlFor="github-repository-url" className="mb-1 block text-xs font-semibold text-slate-300">
                        GitHub Repository URL <span className="text-rose-400">*</span>
                      </label>
                      <input
                        id="github-repository-url"
                        type="url"
                        value={githubRepositoryUrl}
                        onChange={(e) => {
                          setGithubRepositoryUrl(e.target.value);
                          if (githubError) setGithubError("");
                        }}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            handleGitHubSubmit();
                          }
                        }}
                        placeholder="https://github.com/owner/repository"
                        className="w-full rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                      />
                    </div>
                    <div>
                      <label htmlFor="github-branch" className="mb-1 block text-xs font-semibold text-slate-300">
                        Branch or Tag (optional)
                      </label>
                      <input
                        id="github-branch"
                        type="text"
                        value={githubBranch}
                        onChange={(e) => setGithubBranch(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            handleGitHubSubmit();
                          }
                        }}
                        placeholder="Default branch (e.g. main)"
                        className="w-full rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                      />
                    </div>
                    <div>
                      <label htmlFor="github-token" className="mb-1 block text-xs font-semibold text-slate-300">
                        GitHub Token (private repos only)
                      </label>
                      <input
                        id="github-token"
                        type="password"
                        autoComplete="off"
                        value={githubToken}
                        onChange={(e) => setGithubToken(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            handleGitHubSubmit();
                          }
                        }}
                        placeholder="Fine-grained token (Contents: read)"
                        className="w-full rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                      />
                    </div>
                  </div>

                  {githubError && (
                    <div className="rounded-lg border border-rose-500/40 bg-rose-950/40 px-3 py-2 text-xs text-rose-300 flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
                      <span>{githubError}</span>
                    </div>
                  )}

                  {submitting && githubStatus && (
                    <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/40 px-3 py-2 text-xs text-emerald-300 flex items-center gap-2">
                      <Loader2 className="h-4 w-4 animate-spin shrink-0 text-emerald-400" />
                      <span>{githubStatus}</span>
                    </div>
                  )}

                  <div className="flex justify-end pt-1">
                    <button
                      type="button"
                      onClick={handleGitHubSubmit}
                      disabled={submitting || !githubRepositoryUrl.trim()}
                      className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-5 py-2.5 text-xs font-bold text-slate-950 transition disabled:opacity-50 shadow-md"
                    >
                      {submitting ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <ExternalLink className="h-4 w-4" />
                      )}
                      {submitting ? "Scanning GitHub Repository..." : "Start GitHub Scan"}
                    </button>
                  </div>
                </div>

                {/* Option B: Source Code ZIP Upload Box */}
                <form onSubmit={handleMultipartZipSubmit} className="space-y-4">
                  <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3">
                    <div className="flex items-center gap-2">
                      <span className="inline-block w-2.5 h-2.5 rounded-full bg-sky-400" />
                      <h3 className="text-sm font-semibold text-white">
                        Option B: Upload Source Code .ZIP Archive
                      </h3>
                    </div>
                    <div className="rounded-xl border-2 border-dashed border-slate-700 hover:border-emerald-500/50 bg-slate-900/40 p-5 text-center transition">
                      <input
                        id="zip-upload-input"
                        type="file"
                        accept=".zip"
                        onChange={(e) =>
                          setSubZipFile(e.target.files?.[0] || null)
                        }
                        className="hidden"
                      />
                      <label
                        htmlFor="zip-upload-input"
                        className="cursor-pointer flex flex-col items-center"
                      >
                        <Upload className="h-7 w-7 text-emerald-400 mb-2" />
                        <span className="text-xs font-semibold text-white">
                          {subZipFile
                            ? `Selected archive: ${subZipFile.name} (${(
                                subZipFile.size / 1024
                              ).toFixed(1)} KB)`
                            : "Click to select a source-code .ZIP package from your computer"}
                        </span>
                        <span className="text-[11px] text-slate-400 mt-1">
                          Max ZIP: {systemSettings?.max_zip_size_mb || 500} MB • Protected against Path Traversal &amp; Symlink attacks
                        </span>
                      </label>
                    </div>

                    <div className="flex justify-end pt-1">
                      <button
                        type="submit"
                        disabled={submitting || !subZipFile}
                        className="inline-flex items-center gap-2 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-50 px-5 py-2.5 text-xs font-bold text-slate-950 transition shadow-md"
                      >
                        {submitting ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <ShieldCheck className="h-4 w-4" />
                        )}
                        {submitting
                          ? "Scanning .ZIP Package..."
                          : "Start .ZIP Scan"}
                      </button>
                    </div>
                  </div>

                  {/* Collapsible: Advanced Enterprise & Governance Settings */}
                  <div className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden">
                    <button
                      type="button"
                      onClick={() => setShowEnterpriseSettings(!showEnterpriseSettings)}
                      className="w-full flex items-center justify-between p-3.5 text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-900/60 transition"
                    >
                      <div className="flex items-center gap-2">
                        <Settings className="h-4 w-4 text-emerald-400" />
                        <span>Advanced Enterprise &amp; Governance Settings (Optional)</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
                        <span>{showEnterpriseSettings ? "Hide" : "Show details"}</span>
                        <ChevronDown className={`h-4 w-4 transition-transform ${showEnterpriseSettings ? "rotate-180" : ""}`} />
                      </div>
                    </button>

                    {showEnterpriseSettings && (
                      <div className="p-4 pt-1 border-t border-slate-800 space-y-4 bg-slate-900/40">
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                          <div>
                            <label className="block text-xs font-semibold text-slate-300 mb-1">
                              Department / Division
                            </label>
                            <input
                              type="text"
                              value={subDept}
                              onChange={(e) => setSubDept(e.target.value)}
                              className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                            />
                          </div>
                          <div>
                            <label className="block text-xs font-semibold text-slate-300 mb-1">
                              Business Owner
                            </label>
                            <input
                              type="text"
                              value={subBizOwner}
                              onChange={(e) => setSubBizOwner(e.target.value)}
                              className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                            />
                          </div>
                          <div>
                            <label className="block text-xs font-semibold text-slate-300 mb-1">
                              Technical Owner
                            </label>
                            <input
                              type="text"
                              value={subTechOwner}
                              onChange={(e) => setSubTechOwner(e.target.value)}
                              className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                            />
                          </div>
                        </div>

                        <div>
                          <label className="block text-xs font-semibold text-slate-300 mb-1">
                            Application Description &amp; Business Purpose
                          </label>
                          <textarea
                            rows={2}
                            value={subDesc}
                            onChange={(e) => setSubDesc(e.target.value)}
                            className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                          />
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                          <div>
                            <label className="block text-xs font-semibold text-slate-300 mb-1">
                              AI Development Tool Used
                            </label>
                            <select
                              value={subAiTool}
                              onChange={(e) => setSubAiTool(e.target.value)}
                              className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                            >
                              {AI_TOOLS.map((t) => (
                                <option key={t} value={t}>
                                  {t}
                                </option>
                              ))}
                            </select>
                          </div>
                          <div>
                            <label className="block text-xs font-semibold text-slate-300 mb-1">
                              Application Type
                            </label>
                            <select
                              value={subAppType}
                              onChange={(e) => setSubAppType(e.target.value)}
                              className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                            >
                              <option>Internal Web Application</option>
                              <option>Automation Script / CLI</option>
                              <option>Background Service / Agent</option>
                              <option>Desktop Executable (.exe / .msi)</option>
                              <option>Data Pipeline / Connector</option>
                            </select>
                          </div>
                          <div>
                            <label className="block text-xs font-semibold text-slate-300 mb-1">
                              Data Classification
                            </label>
                            <select
                              value={subDataClass}
                              onChange={(e) => setSubDataClass(e.target.value)}
                              className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
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
                            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                              External / Enterprise Connections
                            </label>
                            <div className="flex flex-wrap gap-2">
                              {EXTERNAL_CONNECTION_OPTIONS.map((conn) => {
                                const checked = subConns.includes(conn);
                                return (
                                  <button
                                    type="button"
                                    key={conn}
                                    onClick={() =>
                                      setSubConns((prev) =>
                                        prev.includes(conn)
                                          ? prev.filter((c) => c !== conn)
                                          : [...prev, conn]
                                      )
                                    }
                                    className={`px-2.5 py-1 rounded-md text-xs font-medium border transition ${
                                      checked
                                        ? "bg-emerald-500/20 border-emerald-500/50 text-emerald-300"
                                        : "bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200"
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
                              <label className="block text-xs font-semibold text-slate-300 mb-1">
                                Expected Number of Users
                              </label>
                              <input
                                type="number"
                                min={1}
                                value={subUsers}
                                onChange={(e) =>
                                  setSubUsers(parseInt(e.target.value || "1", 10))
                                }
                                className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-1.5 text-xs text-white font-mono"
                              />
                            </div>
                            <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer pt-1">
                              <input
                                type="checkbox"
                                checked={subAdminPriv}
                                onChange={(e) => setSubAdminPriv(e.target.checked)}
                                className="rounded border-slate-700 bg-slate-950 text-emerald-500"
                              />
                              <span>Requires Administrator Privileges</span>
                            </label>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </form>
              </div>
            </div>

            {/* Right Column: Live Backend Scan Terminal */}
            <div className="space-y-4">
              <LiveScanTerminal
                logs={terminalLogs}
                status={terminalStatus}
                elapsedSeconds={terminalElapsed}
                completedAssessment={terminalResult}
                errorMessage={terminalError}
                onClear={() => {
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
                  setStudioSubTab("overview");
                }}
              />
            </div>
          </div>
        )}

        {/* ===================================================================
            TAB 3: ASSESSMENT & FINDINGS STUDIO (PRD Sections 12-24, 37)
           =================================================================== */}
        {activeTab === "studio" && !selectedAssessment && (
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-12 text-center max-w-xl mx-auto space-y-4">
            <div className="w-14 h-14 rounded-2xl bg-slate-800/80 border border-slate-700 flex items-center justify-center mx-auto text-slate-400">
              <Terminal className="h-7 w-7 text-emerald-400" />
            </div>
            <h3 className="text-lg font-bold text-white">No Assessment Selected</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Select a previously scanned assessment from the history dropdown below, or launch a new code scan.
            </p>
            {assessmentsList.length > 0 ? (
              <div className="pt-2 flex flex-col items-center gap-2">
                <label className="text-xs text-slate-300 font-semibold">Select assessment history:</label>
                <select
                  onChange={(e) => {
                    if (e.target.value) loadAssessmentDetail(e.target.value);
                  }}
                  className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs font-mono font-bold text-emerald-400"
                  defaultValue=""
                >
                  <option value="" disabled>-- Select Assessment --</option>
                  {assessmentsList.map((a) => (
                    <option key={a.assessment_code} value={a.assessment_code}>
                      {a.assessment_code} — {a.application_name} (v{a.version}) [{a.technical_status}]
                    </option>
                  ))}
                </select>
              </div>
            ) : (
              <div className="pt-2">
                <button
                  type="button"
                  onClick={() => setActiveTab("submit")}
                  className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-4 py-2 text-xs font-bold text-slate-950 transition"
                >
                  <ShieldCheck className="h-4 w-4" />
                  Start Code Scan Now
                </button>
              </div>
            )}
          </div>
        )}

        {activeTab === "studio" && selectedAssessment && (
          <div className="space-y-6">
            {/* Assessment Selector & Top Status Header */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
              <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
                <div className="flex flex-wrap items-center gap-3">
                  <select
                    value={selectedAssessment.assessment_code}
                    onChange={(e) => loadAssessmentDetail(e.target.value)}
                    className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs font-mono font-bold text-emerald-400"
                  >
                    {assessmentsList.map((a) => (
                      <option
                        key={a.assessment_code}
                        value={a.assessment_code}
                      >
                        {a.assessment_code} — {a.application_name} (v{a.version}
                        ) [{a.technical_status}]
                      </option>
                    ))}
                  </select>

                  <div>
                    <div className="flex items-center gap-2">
                      <h1 className="text-lg font-bold text-white">
                        {selectedAssessment.application?.name}
                      </h1>
                      <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-mono text-slate-300">
                        v{selectedAssessment.version}
                      </span>
                      {renderStatusBadge(selectedAssessment.technical_status)}
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5 font-mono">
                      SHA-256: {selectedAssessment.sha256_hash} • Files:{" "}
                      {selectedAssessment.file_count} • Archive:{" "}
                      {selectedAssessment.zip_filename}
                    </p>
                  </div>
                </div>

                {/* Quick Action Bar matching PRD Section 21 */}
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    onClick={() =>
                      handleEvidenceDownload(
                        `/api/v1/evidence/${selectedAssessment.assessment_code}/download?${new URLSearchParams({ path: "Reports/scan-summary.html" })}`,
                        `${selectedAssessment.assessment_code}-scan-summary.html`
                      )
                    }
                    className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 px-3 py-2 text-xs font-semibold text-slate-200 transition"
                  >
                    <ExternalLink className="h-3.5 w-3.5 text-emerald-400" />
                    Download HTML Report
                  </button>
                  <button
                    onClick={() =>
                      handleEvidenceDownload(
                        `/api/v1/evidence/${selectedAssessment.assessment_code}/bundle.zip`,
                        `${selectedAssessment.assessment_code}-Evidence-Vault.zip`
                      )
                    }
                    className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 px-3 py-2 text-xs font-semibold text-slate-200 transition"
                  >
                    <Download className="h-3.5 w-3.5 text-sky-400" />
                    Download Evidence Vault (.zip)
                  </button>
                  <button
                    onClick={handleReevaluateAssessment}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 px-3 py-2 text-xs font-semibold text-slate-200 transition"
                  >
                    <RefreshCw className="h-3.5 w-3.5 text-amber-400" />
                    Re-evaluate stored findings
                  </button>

                  {/* Admin Delete Action */}
                  {currentUser?.role === "ADMIN" && (
                    <button
                      onClick={() => handleDeleteAssessment(selectedAssessment.assessment_code)}
                      disabled={deletingCode === selectedAssessment.assessment_code}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-rose-950/60 hover:bg-rose-900 border border-rose-700/60 px-3 py-2 text-xs font-semibold text-rose-200 transition disabled:opacity-50"
                      title="Delete this assessment from the database and Evidence Vault"
                    >
                      <Trash2 className="h-3.5 w-3.5 text-rose-400" />
                      {deletingCode === selectedAssessment.assessment_code ? "Deleting..." : "Delete Assessment"}
                    </button>
                  )}
                </div>
              </div>

              {/* Studio Sub-Navigation */}
              <div className="flex items-center gap-2 pt-3 overflow-x-auto">
                {[
                  {
                    id: "overview",
                    label: "Assessment Overview (Section 21)",
                    icon: Terminal,
                  },
                  {
                    id: "findings",
                    label: `Findings Dashboard (${selectedAssessment.findings.length})`,
                    icon: ShieldAlert,
                  },
                  {
                    id: "dependencies",
                    label: `Dependency & Abandoned Pkg Review (${selectedAssessment.dependencies.length})`,
                    icon: Package,
                  },
                  {
                    id: "manual-gates",
                    label: "Antivirus & Sandbox Gates (Sections 15-16)",
                    icon: Cpu,
                  },
                  {
                    id: "evidence-vault",
                    label: `Evidence Vault & Reports (${selectedAssessment.vault_artifacts.length})`,
                    icon: FolderTree,
                  },
                  {
                    id: "audit-history",
                    label: `Audit History (${selectedAssessment.audit_history.length})`,
                    icon: FileText,
                  },
                ].map((st) => {
                  const Icon = st.icon;
                  const active = studioSubTab === st.id;
                  return (
                    <button
                      key={st.id}
                      onClick={() => setStudioSubTab(st.id as StudioSubTab)}
                      className={`inline-flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-xs font-semibold transition whitespace-nowrap ${
                        active
                          ? "bg-emerald-500 text-slate-950 shadow"
                          : "bg-slate-950/70 text-slate-300 hover:bg-slate-800 border border-slate-800"
                      }`}
                    >
                      <Icon className="h-3.5 w-3.5" />
                      {st.label}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* SUB-TAB 1: OVERVIEW & PRD SECTION 21 DASHBOARD + APPROVAL WORKFLOW */}
            {studioSubTab === "overview" && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* PRD Section 21 Console Representation */}
                <div className="lg:col-span-2 space-y-6">
                  {/* ZIP Validation Errors if any */}
                  {!selectedAssessment.zip_valid && (
                    <div className="rounded-xl bg-rose-950/80 border border-rose-500/50 p-4">
                      <h3 className="text-sm font-bold text-rose-200 flex items-center gap-2">
                        <XCircle className="h-4 w-4 text-rose-400" />
                        ZIP Security Gate Rejected Archive (PRD Section 11)
                      </h3>
                      <ul className="mt-2 list-disc list-inside text-xs text-rose-200 space-y-1 font-mono">
                        {selectedAssessment.zip_validation_errors.map(
                          (err, i) => (
                            <li key={i}>{err}</li>
                          )
                        )}
                      </ul>
                    </div>
                  )}

                  {/* Risk Decision Engine Triggers */}
                  <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
                    <h3 className="text-sm font-bold text-white mb-2">
                      Risk Decision Engine Evaluation (PRD Section 20)
                    </h3>
                    <ul className="space-y-1.5 text-xs text-slate-300">
                      {selectedAssessment.status_reasons.map((r, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-emerald-400 font-bold">•</span>
                          <span>{r}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Scanner Breakdown Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-bold uppercase tracking-wider text-sky-400">
                          {selectedAssessment.scanner_versions?.mode === "external"
                            ? `Aqua Trivy (v${selectedAssessment.scanner_versions.trivy || selectedAssessment.scanner_versions.trivy_version || "0.58.0"})`
                            : "Dependency SCA (Trivy)"}
                        </span>
                        <span className="text-[11px] font-mono text-slate-400">
                          vuln • config
                        </span>
                      </div>
                      <div className="space-y-1.5 text-xs font-mono">
                        <div className="flex justify-between">
                          <span className="text-slate-400">Critical</span>
                          <span className="text-rose-400 font-bold">
                            {selectedAssessment.trivy_summary.critical || 0}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">High</span>
                          <span className="text-orange-400 font-bold">
                            {selectedAssessment.trivy_summary.high || 0}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Medium</span>
                          <span className="text-amber-300 font-bold">
                            {selectedAssessment.trivy_summary.medium || 0}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Low</span>
                          <span className="text-sky-300 font-bold">
                            {selectedAssessment.trivy_summary.low || 0}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-bold uppercase tracking-wider text-rose-400">
                          {selectedAssessment.scanner_versions?.mode === "external"
                            ? `Gitleaks (v${selectedAssessment.scanner_versions.gitleaks || selectedAssessment.scanner_versions.gitleaks_version || "8.21.2"})`
                            : "Secret Scanner (Gitleaks)"}
                        </span>
                        <span className="text-[11px] font-mono text-emerald-400">
                          Redacted
                        </span>
                      </div>
                      <div className="space-y-1.5 text-xs font-mono">
                        <div className="flex justify-between">
                          <span className="text-slate-400">
                            Active Secrets
                          </span>
                          <span
                            className={`font-bold ${
                              (selectedAssessment.gitleaks_summary
                                .secrets_detected || 0) > 0
                                ? "text-rose-400"
                                : "text-emerald-400"
                            }`}
                          >
                            {selectedAssessment.gitleaks_summary
                              .secrets_detected || 0}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Mask Format</span>
                          <span className="text-slate-300">
                            ********************
                          </span>
                        </div>
                        <p className="text-[11px] font-sans text-slate-400 pt-1">
                          Raw credential values are strictly redacted and never stored or displayed in the UI or reports.
                        </p>
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-bold uppercase tracking-wider text-amber-400">
                          {selectedAssessment.scanner_versions?.mode === "external"
                            ? `Semgrep SAST (v${selectedAssessment.scanner_versions.semgrep || selectedAssessment.scanner_versions.semgrep_version || "1.99.0"})`
                            : "SAST Code Engine (Semgrep)"}
                        </span>
                        <span className="text-[11px] font-mono text-slate-400">
                          OWASP Top 10
                        </span>
                      </div>
                      <div className="space-y-1.5 text-xs font-mono">
                        <div className="flex justify-between">
                          <span className="text-slate-400">Critical</span>
                          <span className="text-rose-400 font-bold">
                            {selectedAssessment.semgrep_summary.critical || 0}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">High</span>
                          <span className="text-orange-400 font-bold">
                            {selectedAssessment.semgrep_summary.high || 0}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Medium</span>
                          <span className="text-amber-300 font-bold">
                            {selectedAssessment.semgrep_summary.medium || 0}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Low</span>
                          <span className="text-sky-300 font-bold">
                            {selectedAssessment.semgrep_summary.low || 0}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Human-Friendly Decision & Action Recommendation Card */}
                  <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 space-y-3">
                    <div className="flex items-center gap-2">
                      <HelpCircle className="h-5 w-5 text-emerald-400" />
                      <h3 className="text-sm font-bold text-white">
                        Action &amp; Remediation Guidance
                      </h3>
                    </div>
                    {selectedAssessment.technical_status === "REJECT" && (
                      <div className="rounded-xl border border-rose-500/40 bg-rose-950/40 p-4 space-y-2 text-xs">
                        <div className="flex items-center gap-2 font-bold text-rose-300 text-sm">
                          <XCircle className="h-4 w-4 text-rose-400" />
                          Decision: Rejected (REJECT)
                        </div>
                        <p className="text-slate-300 leading-relaxed">
                          This application contains critical security risks that could compromise production systems. Common triggers include active hardcoded secrets/API keys, Critical CVEs in dependencies, or unsafe code execution / archive traversal.
                        </p>
                        <div className="pt-1">
                          <strong className="text-white block mb-1">Mandatory Remediation Steps:</strong>
                          <ul className="list-disc list-inside text-rose-200/90 space-y-1">
                            <li>Immediately revoke and rotate any credentials detected in the <em>Findings Dashboard</em> tab.</li>
                            <li>Upgrade vulnerable dependencies to their patched versions.</li>
                            <li>Remove unsafe scripts or remediate injection vulnerabilities.</li>
                            <li>Re-scan your repository or archive after committing the fixes.</li>
                          </ul>
                        </div>
                      </div>
                    )}
                    {selectedAssessment.technical_status === "REVIEW" && (
                      <div className="rounded-xl border border-amber-500/40 bg-amber-950/40 p-4 space-y-2 text-xs">
                        <div className="flex items-center gap-2 font-bold text-amber-300 text-sm">
                          <AlertTriangle className="h-4 w-4 text-amber-400" />
                          Decision: Security Review Required (REVIEW)
                        </div>
                        <p className="text-slate-300 leading-relaxed">
                          This application surfaced High or Medium findings or outdated software packages. It requires verification before proceeding to production deployment.
                        </p>
                        <div className="pt-1">
                          <strong className="text-white block mb-1">Recommended Next Steps:</strong>
                          <ul className="list-disc list-inside text-amber-200/90 space-y-1">
                            <li>Open the <em>Findings Dashboard</em> tab to inspect affected files and line numbers.</li>
                            <li>Coordinate with your security reviewer or lead developer to classify false positives or apply minor dependency patches.</li>
                          </ul>
                        </div>
                      </div>
                    )}
                    {selectedAssessment.technical_status === "PASS-WITH-MANUAL-CHECKS" && (
                      <div className="rounded-xl border border-emerald-500/40 bg-emerald-950/40 p-4 space-y-2 text-xs">
                        <div className="flex items-center gap-2 font-bold text-emerald-300 text-sm">
                          <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                          Decision: Passed Automated Checks (PASS)
                        </div>
                        <p className="text-slate-300 leading-relaxed">
                          No critical CVEs, exposed secrets, or high-risk code execution patterns were found. The source code satisfies all automated baseline security gates.
                        </p>
                        <p className="text-emerald-200/90 text-[11px]">
                          If your organization enforces manual antivirus or sandbox checks, record that evidence under the <em>Antivirus &amp; Sandbox Gates</em> tab.
                        </p>
                      </div>
                    )}
                    {selectedAssessment.technical_status === "SCAN-ERROR" && (
                      <div className="rounded-xl border border-slate-700 bg-slate-950 p-4 space-y-2 text-xs">
                        <div className="flex items-center gap-2 font-bold text-slate-300 text-sm">
                          <AlertTriangle className="h-4 w-4 text-slate-400" />
                          Decision: Scan Interrupted (SCAN-ERROR)
                        </div>
                        <p className="text-slate-400 leading-relaxed">
                          The assessment could not be completed due to a technical interruption. Verify the ZIP archive or GitHub URL/token and re-run the scan.
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Application Registration Metadata */}
                  <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
                    <h3 className="text-sm font-bold text-white mb-3">
                      Application Registration & Governance Metadata
                    </h3>
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs">
                      <div>
                        <span className="text-slate-400 block">
                          S-Gates App ID
                        </span>
                        <span className="font-mono font-semibold text-white">
                          {selectedAssessment.application?.sgates_app_id}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block">
                          Business Owner
                        </span>
                        <span className="font-semibold text-white">
                          {selectedAssessment.application?.business_owner}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block">
                          Technical Owner
                        </span>
                        <span className="font-semibold text-white">
                          {selectedAssessment.application?.technical_owner}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block">
                          AI Development Tool
                        </span>
                        <span className="font-semibold text-emerald-300">
                          {selectedAssessment.application?.ai_tool}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block">
                          Data Classification
                        </span>
                        <span className="font-semibold text-white">
                          {selectedAssessment.application?.data_classification}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block">
                          Admin Privileges Required
                        </span>
                        <span className="font-semibold text-white">
                          {selectedAssessment.application
                            ?.requires_admin_privileges
                            ? "Yes (Elevated Risk)"
                            : "No"}
                        </span>
                      </div>
                      <div className="col-span-2">
                        <span className="text-slate-400 block">
                          External Connections
                        </span>
                        <span className="font-semibold text-white">
                          {(
                            selectedAssessment.application
                              ?.external_connections || []
                          ).join(", ") || "None"}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block">
                          Production Status
                        </span>
                        <span className="font-semibold text-sky-300">
                          {selectedAssessment.application?.production_status}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Right Column: IT & Security Reviewer Approval Gate (PRD Section 21 & 27) */}
                <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 flex flex-col justify-between space-y-4">
                  <div className="space-y-4">
                    <div className="border-b border-slate-800 pb-3">
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        <UserCheck className="h-4 w-4 text-emerald-400" />
                        Reviewer Decision & Pilot Gate
                      </h3>
                      <p className="text-[11px] text-slate-400 mt-1">
                        Current Decision:{" "}
                        <strong className="text-emerald-300 font-mono">
                          {selectedAssessment.final_decision}
                        </strong>
                      </p>
                    </div>

                    <div className="rounded-xl bg-slate-950/90 border border-slate-800 p-3.5 text-xs space-y-1.5">
                      <div className="flex justify-between">
                        <span className="text-slate-400">
                          Manual antivirus evidence:
                        </span>
                        <span className="font-semibold text-white">
                          {selectedAssessment.av_status}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Sandbox Gate:</span>
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
                      <div className="flex justify-between">
                        <span className="text-slate-400">
                          SharePoint Evidence Vault:
                        </span>
                        <span className="font-semibold text-sky-300">
                          {selectedAssessment.sharepoint_synced
                            ? "Synced"
                            : "Local Vault Ready"}
                        </span>
                      </div>
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">
                        Reviewer Decision Notes / Conditions *
                      </label>
                      <textarea
                        rows={3}
                        value={decisionNotes}
                        onChange={(e) => setDecisionNotes(e.target.value)}
                        placeholder="Enter remediation instructions, pilot conditions, or risk acceptance justification..."
                        className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                      />
                    </div>

                    {currentUser?.role === "CITIZEN_DEVELOPER" && (
                      <div className="rounded-lg bg-amber-950/50 border border-amber-500/40 p-3 text-[11px] text-amber-200">
                        <strong>RBAC Notice (PRD Section 27):</strong> As a{" "}
                        <code>CITIZEN_DEVELOPER</code>, you can view assessments
                        and download reports, but cannot approve applications or
                        alter findings. Use the top bar to switch to{" "}
                        <strong>IT Reviewer</strong> or{" "}
                        <strong>Security Reviewer</strong>.
                      </div>
                    )}

                    <div className="space-y-2 pt-1">
                      <button
                        onClick={() => handleRecordDecision("PILOT_APPROVED")}
                        className="w-full rounded-lg bg-emerald-500 hover:bg-emerald-400 py-2.5 text-xs font-bold text-slate-950 transition shadow"
                      >
                        [ Approve Pilot ]
                      </button>
                      <button
                        onClick={() =>
                          handleRecordDecision("REMEDIATION_REQUESTED")
                        }
                        className="w-full rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 py-2 text-xs font-semibold text-amber-200 transition"
                      >
                        [ Request Remediation ]
                      </button>
                      <button
                        onClick={() => handleRecordDecision("RISK_ACCEPTED")}
                        className="w-full rounded-lg bg-sky-500/20 hover:bg-sky-500/30 border border-sky-500/40 py-2 text-xs font-semibold text-sky-200 transition"
                      >
                        [ Record Risk Acceptance (Security Reviewer) ]
                      </button>
                      <button
                        onClick={() => handleRecordDecision("REJECTED")}
                        className="w-full rounded-lg bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 py-2 text-xs font-semibold text-rose-200 transition"
                      >
                        [ Reject Application ]
                      </button>
                    </div>
                  </div>

                  {selectedAssessment.decision_by && (
                    <div className="border-t border-slate-800 pt-3 text-[11px] text-slate-400">
                      Last Decision by:{" "}
                      <strong className="text-slate-200">
                        {selectedAssessment.decision_by}
                      </strong>{" "}
                      ({selectedAssessment.decision_role})
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* SUB-TAB 2: FINDINGS DASHBOARD (PRD Section 22 & 37) */}
            {studioSubTab === "findings" && (
              <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
                  <div>
                    <h3 className="text-base font-bold text-white">
                      Consolidated Findings Dashboard (PRD Section 22)
                    </h3>
                    <p className="text-xs text-slate-400">
                      Filter by Scanner, Severity, Package, Source File, or
                Remediation Status. Potential secret matches are masked in findings
                      to <code>********************</code>.
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <div className="relative">
                      <Search className="h-3.5 w-3.5 text-slate-400 absolute left-2.5 top-2.5" />
                      <input
                        type="text"
                        placeholder="Search file, package, CVE..."
                        value={findingSearch}
                        onChange={(e) => setFindingSearch(e.target.value)}
                        className="rounded-lg bg-slate-950 border border-slate-800 pl-8 pr-3 py-1.5 text-xs text-white"
                      />
                    </div>
                    <select
                      value={scannerFilter}
                      onChange={(e) => setScannerFilter(e.target.value)}
                      className="rounded-lg bg-slate-950 border border-slate-800 px-2.5 py-1.5 text-xs text-slate-200"
                    >
                      <option value="ALL">All Scanners</option>
                      <option value="Trivy">Aqua Trivy (SCA &amp; Config)</option>
                      <option value="OSV-Scanner">OSV-Scanner (OSV &amp; MAL-*)</option>
                      <option value="GuardDog">GuardDog (PyPI/npm Supply-Chain)</option>
                      <option value="RegistryMetadata">Registry Metadata (Typosquatting)</option>
                      <option value="Gitleaks">Gitleaks (Secrets)</option>
                      <option value="Semgrep">Semgrep (SAST)</option>
                      <option value="Legacy heuristic">Legacy rules</option>
                    </select>
                    <select
                      value={severityFilter}
                      onChange={(e) => setSeverityFilter(e.target.value)}
                      className="rounded-lg bg-slate-950 border border-slate-800 px-2.5 py-1.5 text-xs text-slate-200"
                    >
                      <option value="ALL">All Severities</option>
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                    <select
                      value={statusFilter}
                      onChange={(e) => setStatusFilter(e.target.value)}
                      className="rounded-lg bg-slate-950 border border-slate-800 px-2.5 py-1.5 text-xs text-slate-200"
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
                  <div className="py-10 text-center text-xs text-slate-400">
                    No findings match the current filter criteria.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/60">
                          <th className="py-2.5 px-3">ID / Scanner</th>
                          <th className="py-2.5 px-3">Severity</th>
                          <th className="py-2.5 px-3">Source File & Package</th>
                          <th className="py-2.5 px-3">
                            Finding & Recommendation
                          </th>
                          <th className="py-2.5 px-3">Status</th>
                          <th className="py-2.5 px-3 text-right">
                            Reviewer & ITSM Actions
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70">
                        {filteredFindings.map((f) => (
                          <tr
                            key={f.id}
                            className="hover:bg-slate-950/40 align-top"
                          >
                            <td className="py-3 px-3 font-mono whitespace-nowrap">
                              <div className="font-bold text-slate-200">
                                {f.finding_code}
                              </div>
                              <span className="text-[11px] text-emerald-400">
                                {f.scanner} ({f.finding_type})
                              </span>
                            </td>
                            <td className="py-3 px-3 whitespace-nowrap">
                              {renderSeverityBadge(f.severity)}
                            </td>
                            <td className="py-3 px-3 font-mono text-[11px]">
                              <div className="text-sky-300">
                                {f.file_path}:{f.line_number}
                              </div>
                              {f.package_name && f.package_name !== "-" && (
                                <div className="text-slate-400 mt-0.5">
                                  Pkg: {f.package_name} ({f.installed_version}{" "}
                                  → {f.fixed_version})
                                </div>
                              )}
                              {f.finding_type === "secret" && (
                                <div className="mt-1 inline-flex items-center gap-1 rounded bg-rose-950/90 border border-rose-500/40 px-1.5 py-0.5 text-[10px] text-rose-200">
                                  Value: {f.redacted_value}
                                </div>
                              )}
                            </td>
                            <td className="py-3 px-3 max-w-md">
                              <div className="font-bold text-white">
                                {f.title}
                              </div>
                              <p className="text-slate-400 text-[11px] mt-0.5">
                                {f.description}
                              </p>
                              <p className="text-emerald-300/90 text-[11px] mt-1">
                                <strong>Remediation:</strong>{" "}
                                {f.recommendation}
                              </p>
                            </td>
                            <td className="py-3 px-3 whitespace-nowrap">
                              <select
                                value={f.status}
                                onChange={(e) =>
                                  handleUpdateFindingStatus(
                                    f.id,
                                    e.target.value
                                  )
                                }
                                className="rounded bg-slate-950 border border-slate-700 px-2 py-1 text-xs font-semibold text-white"
                              >
                                <option value="Open">Open</option>
                                <option value="Accepted">Accepted</option>
                                <option value="False Positive">
                                  False Positive
                                </option>
                                <option value="Resolved">Resolved</option>
                              </select>
                            </td>
                            <td className="py-3 px-3 text-right whitespace-nowrap">
                              {f.itsm_ticket_id ? (
                                <span className="inline-flex items-center gap-1 rounded bg-sky-500/20 border border-sky-500/40 px-2.5 py-1 text-[11px] font-mono text-sky-300">
                                  <Ticket className="h-3 w-3" />
                                  {f.itsm_ticket_id}
                                </span>
                              ) : (
                                <button
                                  disabled
                                  className="inline-flex items-center gap-1 rounded bg-slate-900 border border-slate-800 px-2.5 py-1 text-[11px] font-semibold text-slate-500 disabled:cursor-not-allowed"
                                  title="Freshservice is not configured in this build."
                                >
                                  <Ticket className="h-3 w-3 text-slate-500" />
                                  ITSM not configured
                                </button>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* SUB-TAB 3: DEPENDENCY RISK, ABANDONED & MALICIOUS PACKAGE REVIEW (PRD Sections 17-19) */}
            {studioSubTab === "dependencies" && (
              <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
                <div>
                  <h3 className="text-base font-bold text-white">
                    Dependency Risk, Abandoned Package & Malicious Supply-Chain
                    Review (PRD Sections 17–19)
                  </h3>
                  <p className="text-xs text-slate-400">
                    Distinguishes between known CVEs, unmaintained/abandoned
                    packages (<code>SUPPORTED</code>,{" "}
                    <code>MAINTENANCE REVIEW</code>, <code>ABANDONED</code>,{" "}
                    <code>UNKNOWN</code>), and potentially
                    malicious/typosquatted packages.
                  </p>
                </div>

                {selectedAssessment.dependencies.length === 0 ? (
                  <div className="py-8 text-center text-xs text-slate-400">
                    No dependency manifests detected in this archive.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/60">
                          <th className="py-2.5 px-3">Package & Version</th>
                          <th className="py-2.5 px-3">Ecosystem</th>
                          <th className="py-2.5 px-3">
                            Known Vulnerability / CVE
                          </th>
                          <th className="py-2.5 px-3">
                            Malicious / Supply-Chain Risk (Sec 19)
                          </th>
                          <th className="py-2.5 px-3">
                            Maintainer & Last Release
                          </th>
                          <th className="py-2.5 px-3">
                            Reviewer Status (Sec 18)
                          </th>
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
                                <div className="text-[11px] text-emerald-400">
                                  Alt: {d.alternative_package}
                                </div>
                              )}
                            </td>
                            <td className="py-3 px-3 uppercase font-mono text-[11px] text-slate-300">
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
                                <div className="text-[11px] text-slate-400 mt-0.5">
                                  Fixed in: {d.fixed_version}
                                </div>
                              )}
                            </td>
                            <td className="py-3 px-3">
                              <span
                                className={`inline-flex rounded px-2 py-0.5 text-[11px] font-semibold border ${
                                  d.malicious_risk.includes("Malicious") ||
                                  d.malicious_risk.includes("Typosquatting")
                                    ? "bg-rose-500/20 text-rose-300 border-rose-500/40"
                                    : d.malicious_risk.includes("Vulnerable")
                                    ? "bg-amber-500/15 text-amber-300 border-amber-500/30"
                                    : "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
                                }`}
                              >
                                {d.malicious_risk}
                              </span>
                            </td>
                            <td className="py-3 px-3 text-[11px] text-slate-300">
                              <div>{d.maintainer_status}</div>
                              <div className="text-slate-500">
                                Last Release: {d.last_release_date} •{" "}
                                {d.publisher_identity}
                              </div>
                            </td>
                            <td className="py-3 px-3">
                              <select
                                value={d.reviewer_status}
                                onChange={(e) =>
                                  handleUpdateDependencyStatus(
                                    d.id,
                                    e.target.value
                                  )
                                }
                                className="rounded bg-slate-950 border border-slate-700 px-2.5 py-1 text-xs font-semibold text-white"
                              >
                                <option value="SUPPORTED">SUPPORTED</option>
                                <option value="MAINTENANCE REVIEW">
                                  MAINTENANCE REVIEW
                                </option>
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

            {/* SUB-TAB 4: MANUAL SECURITY EVIDENCE (PRD Sections 15 & 16) */}
            {studioSubTab === "manual-gates" && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* PRD Section 15: Manual Antivirus Evidence */}
                <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
                  <div className="border-b border-slate-800 pb-3">
                    <h3 className="text-base font-bold text-white">
                      1. Manual Antivirus Evidence (Section 15)
                    </h3>
                    <p className="text-xs text-slate-400 mt-1">
                      S-Gates does not run antivirus scans. Record the result
                      from your approved external tool and its evidence reference. Selecting{" "}
                      <code>Threat Detected</code> automatically transitions the
                      assessment to <code>REJECT</code>.
                    </p>
                  </div>

                  <div className="space-y-3">
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                        External Antivirus Result (manual evidence)
                      </label>
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
                            onClick={() => setAvStatusInput(opt)}
                            className={`py-2 px-3 rounded-lg text-xs font-semibold border transition ${
                              avStatusInput === opt
                                ? opt === "Pending"
                                  ? "bg-slate-500 text-white border-slate-400"
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
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">
                        External Antivirus Evidence Reference ID
                      </label>
                      <input
                        type="text"
                        value={avRefInput}
                        onChange={(e) => setAvRefInput(e.target.value)}
                        className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white font-mono"
                      />
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">
                        Antivirus Scan Notes
                      </label>
                      <textarea
                        rows={3}
                        value={avNotesInput}
                        onChange={(e) => setAvNotesInput(e.target.value)}
                        className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white"
                      />
                    </div>
                  </div>
                </div>

                {/* PRD Section 16: Sandbox Analysis Gate */}
                <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
                  <div className="border-b border-slate-800 pb-3">
                    <h3 className="text-base font-bold text-white">
                      2. Manual Sandbox Evidence (Section 16)
                    </h3>
                    <p className="text-xs text-slate-400 mt-1">
                      S-Gates does not execute a sandbox. Run the package in an
                      approved isolated environment when EXE/MSI binaries,
                      Windows services, background agents, scheduled tasks,
                      admin privileges, sensitive data, obfuscation, or
                      high-risk findings are present.
                    </p>
                  </div>

                  {selectedAssessment.sandbox_reasons.length > 0 ? (
                    <div className="rounded-xl bg-amber-950/40 border border-amber-500/40 p-3 text-xs text-amber-200">
                      <div className="font-bold mb-1">
                        Heuristic Sandbox Review Triggers:
                      </div>
                      <ul className="list-disc list-inside space-y-0.5 text-[11px]">
                        {selectedAssessment.sandbox_reasons.map((r, idx) => (
                          <li key={idx}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <div className="rounded-xl bg-emerald-950/30 border border-emerald-500/30 p-3 text-xs text-emerald-200">
                      No mandatory behavioral sandbox triggers detected for this
                      package.
                    </div>
                  )}

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">
                        Sandbox Validation Status
                      </label>
                      <select
                        value={sbStatusInput}
                        onChange={(e) => setSbStatusInput(e.target.value)}
                        className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white"
                      >
                        <option value="Not Required">Not Required</option>
                        <option value="Required - Pending">
                          Required - Pending
                        </option>
                        <option value="Passed">
                          Passed (Behavioral Check Clean)
                        </option>
                        <option value="Failed">
                          Failed (Malicious Behavior Observed)
                        </option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">
                        Sandbox Environment Used
                      </label>
                      <select
                        value={sbTechInput}
                        onChange={(e) => setSbTechInput(e.target.value)}
                        className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white"
                      >
                        <option value="Windows Sandbox">Windows Sandbox</option>
                        <option value="Hyper-V Isolated VM">
                          Hyper-V Isolated VM
                        </option>
                        <option value="Dedicated Disposable Test VM">
                          Dedicated Disposable Test VM
                        </option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      Sandbox Behavioral Observations & Network Log Summary
                    </label>
                    <textarea
                      rows={3}
                      value={sbNotesInput}
                      onChange={(e) => setSbNotesInput(e.target.value)}
                      placeholder="Record process creation, registry modifications, and outbound network observations..."
                      className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white"
                    />
                  </div>

                  <div className="flex justify-end pt-2">
                    <button
                      type="button"
                      onClick={handleSaveManualGates}
                      className="rounded-lg bg-emerald-500 hover:bg-emerald-400 px-5 py-2 text-xs font-bold text-slate-950 transition shadow"
                    >
                      Save Manual Gate Evidence & Recalculate Status
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* SUB-TAB 5: EVIDENCE VAULT & REPORTS (PRD Sections 23 & 24) */}
            {studioSubTab === "evidence-vault" && (
              <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-4 pb-3 border-b border-slate-800">
                  <div>
                    <h3 className="text-base font-bold text-white flex items-center gap-2">
                      <FolderTree className="h-4 w-4 text-emerald-400" />
                      Structured Evidence Artifacts Vault (PRD Section 24)
                    </h3>
                    <p className="text-xs text-slate-400">
                      Every assessment retains <code>Submission/Source.zip</code>
                      , <code>Inventory/file-inventory.csv</code>,{" "}
                      <code>Reports/*</code>, <code>Evidence/*</code>, and{" "}
                      <code>Approval/decision</code>.
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      disabled
                      title="SharePoint sync is not configured in this build."
                      className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 border border-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-500 disabled:cursor-not-allowed"
                    >
                      <Share2 className="h-3.5 w-3.5" />
                      SharePoint not configured
                    </button>
                    <button
                      onClick={() =>
                        handleEvidenceDownload(
                          `/api/v1/evidence/${selectedAssessment.assessment_code}/bundle.zip`,
                          `${selectedAssessment.assessment_code}-Evidence-Vault.zip`
                        )
                      }
                      className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-3.5 py-2 text-xs font-bold text-slate-950 transition"
                    >
                      <Download className="h-3.5 w-3.5" />
                      Download Complete Vault (.zip)
                    </button>
                  </div>
                </div>

                {selectedAssessment.sharepoint_synced && (
                  <div className="rounded-xl bg-sky-950/50 border border-sky-500/40 p-3 text-xs text-sky-200 flex items-center justify-between">
                    <span>
                      <strong>Stored SharePoint flag (not verified):</strong>{" "}
                      <code className="text-sky-300">
                        {selectedAssessment.sharepoint_url}
                      </code>
                    </span>
                    <span className="text-[11px] font-mono text-emerald-300">
                      RPO: 24h / RTO: 1 Business Day (Section 31)
                    </span>
                  </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {selectedAssessment.vault_artifacts.map((art) => (
                    <div
                      key={art.relative_path}
                      className="rounded-xl bg-slate-950/80 border border-slate-800 p-3.5 flex items-center justify-between"
                    >
                      <div className="min-w-0 pr-2">
                        <div className="text-[10px] font-mono uppercase text-emerald-400">
                          {art.folder}/
                        </div>
                        <div className="text-xs font-mono font-bold text-white truncate">
                          {art.filename}
                        </div>
                        <div className="text-[11px] text-slate-500">
                          {(art.size_bytes / 1024).toFixed(2)} KB
                        </div>
                      </div>
                      <button
                        onClick={() =>
                          handleEvidenceDownload(
                            `/api/v1/evidence/${selectedAssessment.assessment_code}/download?${new URLSearchParams({ path: art.relative_path })}`,
                            `${selectedAssessment.assessment_code}-${art.filename}`
                          )
                        }
                        className="shrink-0 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 px-3 py-1.5 text-xs font-semibold text-slate-200 inline-flex items-center gap-1"
                      >
                        <ExternalLink className="h-3.5 w-3.5 text-emerald-400" />
                        Download
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* SUB-TAB 6: ASSESSMENT AUDIT HISTORY */}
            {studioSubTab === "audit-history" && (
              <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-3">
                <h3 className="text-base font-bold text-white">
                          Assessment Audit History
                </h3>
                <div className="space-y-2">
                  {selectedAssessment.audit_history.map((ev) => (
                    <div
                      key={ev.id}
                      className="rounded-xl bg-slate-950/80 border border-slate-800 p-3.5 text-xs"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-mono font-bold text-emerald-400">
                          {ev.event_type}
                        </span>
                        <span className="font-mono text-[11px] text-slate-400">
                          Actor: {ev.actor_email} ({ev.actor_role})
                        </span>
                      </div>
                      <p className="text-slate-200 mt-1">{ev.summary}</p>
                      <div className="mt-1.5 flex flex-wrap items-center justify-between text-[10px] font-mono text-slate-500">
                        <span>
                          State: {ev.previous_state || "-"} →{" "}
                          {ev.new_state || "-"}
                        </span>
                        <span>
                          SHA-256 Chain Sig:{" "}
                          {ev.immutable_signature.slice(0, 24)}...
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ===================================================================
            TAB 4: CENTRALIZED APPLICATION INVENTORY (PRD Section 25 & 26)
           =================================================================== */}
        {activeTab === "inventory" && (
          <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
              <div>
                <h2 className="text-base font-bold text-white">
                  Centralized Application Inventory & Version Lineage (PRD
                  Section 25 & 26)
                </h2>
                <p className="text-xs text-slate-400">
                  Tracks all registered citizen-developed & AI-generated
                  applications, owners, AI tools, risk classifications,
                  production statuses, and scheduled reassessment dates.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="text"
                  placeholder="Search app, ID, AI tool, dept..."
                  value={invSearch}
                  onChange={(e) => setInvSearch(e.target.value)}
                  className="rounded-lg bg-slate-950 border border-slate-800 px-3 py-1.5 text-xs text-white"
                />
                <select
                  value={invStatusFilter}
                  onChange={(e) => setInvStatusFilter(e.target.value)}
                  className="rounded-lg bg-slate-950 border border-slate-800 px-3 py-1.5 text-xs text-slate-200"
                >
                  <option value="">All Security Statuses</option>
                  <option value="PASS-WITH-MANUAL-CHECKS">
                    PASS-WITH-MANUAL-CHECKS
                  </option>
                  <option value="REVIEW">REVIEW</option>
                  <option value="REJECT">REJECT</option>
                  <option value="SCAN-ERROR">SCAN-ERROR</option>
                </select>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/60">
                    <th className="py-2.5 px-3">S-Gates ID</th>
                    <th className="py-2.5 px-3">Application & Version</th>
                    <th className="py-2.5 px-3">Department & Owners</th>
                    <th className="py-2.5 px-3">AI Tool & Data Class</th>
                    <th className="py-2.5 px-3">Risk Level</th>
                    <th className="py-2.5 px-3">Security Status</th>
                    <th className="py-2.5 px-3">Production Status</th>
                    <th className="py-2.5 px-3">Version History (Sec 25)</th>
                    {currentUser?.role === "ADMIN" && (
                      <th className="py-2.5 px-3 text-right">Actions</th>
                    )}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {filteredInventory.map((app) => (
                    <tr key={app.id} className="hover:bg-slate-950/40">
                      <td className="py-3 px-3 font-mono font-bold text-emerald-400">
                        {app.sgates_app_id}
                      </td>
                      <td className="py-3 px-3">
                        <div className="font-bold text-white">{app.name}</div>
                        <span className="font-mono text-[11px] text-slate-400">
                          Latest: v{app.latest_version}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-[11px]">
                        <div className="text-slate-200 font-semibold">
                          {app.department}
                        </div>
                        <div className="text-slate-400">
                          Biz: {app.business_owner}
                        </div>
                        <div className="text-slate-400">
                          Tech: {app.technical_owner}
                        </div>
                      </td>
                      <td className="py-3 px-3 text-[11px]">
                        <div className="text-emerald-300 font-semibold">
                          {app.ai_tool}
                        </div>
                        <div className="text-slate-400">
                          {app.data_classification}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        {renderSeverityBadge(app.risk_level)}
                      </td>
                      <td className="py-3 px-3">
                        {renderStatusBadge(app.security_status)}
                      </td>
                      <td className="py-3 px-3">
                        <span className="rounded bg-slate-800 px-2 py-1 text-[11px] font-semibold text-sky-300">
                          {app.production_status}
                        </span>
                        <div className="text-[10px] text-slate-500 mt-1">
                          Next Review: {app.next_review_date}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex flex-wrap gap-1.5">
                          {app.assessments.map((asmt) => (
                            <button
                              key={asmt.assessment_code}
                              onClick={() => {
                                loadAssessmentDetail(asmt.assessment_code);
                                setActiveTab("studio");
                              }}
                              className="rounded bg-slate-950 hover:bg-slate-800 border border-slate-700 px-2 py-1 text-[11px] font-mono text-emerald-300 transition"
                            >
                              v{asmt.version} → {asmt.assessment_code}
                            </button>
                          ))}
                        </div>
                      </td>
                      {currentUser?.role === "ADMIN" && (
                        <td className="py-3 px-3 text-right whitespace-nowrap">
                          <button
                            type="button"
                            onClick={() =>
                              handleDeleteApplication(app.sgates_app_id, app.name)
                            }
                            disabled={deletingAppId === app.sgates_app_id}
                            className="inline-flex items-center gap-1 rounded-lg bg-rose-950/60 hover:bg-rose-900 border border-rose-700/60 px-2.5 py-1.5 text-[11px] font-semibold text-rose-200 transition disabled:opacity-50"
                            title={`Delete ${app.sgates_app_id} and all linked assessments`}
                          >
                            <Trash2 className="h-3.5 w-3.5 text-rose-400" />
                            {deletingAppId === app.sgates_app_id
                              ? "Deleting..."
                              : "Delete"}
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ===================================================================
            TAB 5: ADMIN, SCANNER STATUS & AUDIT LOG
           =================================================================== */}
        {activeTab === "governance" && systemSettings && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Scanner Availability */}
              <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
                <div className="border-b border-slate-800 pb-3">
                  <h3 className="text-base font-bold text-white">
                    Real Security Scanner Status
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Runtime readiness of Aqua Trivy, Gitleaks, and Semgrep SAST binaries inside the server container.
                  </p>
                </div>

                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 flex items-center justify-between">
                  <div>
                    <div className="text-xs text-slate-400">
                      Operational Scanner Status:
                    </div>
                    <div
                      className={`text-lg font-mono font-bold mt-0.5 ${
                        systemSettings.security_intel_status === "HEALTHY"
                          ? "text-emerald-400"
                          : "text-rose-400"
                      }`}
                    >
                      {systemSettings.security_intel_status}
                    </div>
                    <div className="text-[11px] text-slate-400 mt-1 font-mono">
                      Trivy: {systemSettings.trivy_version} • Gitleaks:{" "}
                      {systemSettings.gitleaks_version} • Semgrep:{" "}
                      {systemSettings.semgrep_version} • OSV:{" "}
                      {systemSettings.osv_version || "2.7.1"} • GuardDog:{" "}
                      {systemSettings.guarddog_version || "3.2.0"}
                    </div>
                  </div>

                  <span className="rounded-lg border border-emerald-500/30 bg-emerald-950/40 px-3 py-2 text-xs font-semibold text-emerald-300">
                    Scanners Active &amp; Ready
                  </span>
                </div>
              </div>

              {/* PRD Section 11 & 35: ZIP Security Controls Limits */}
              <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
                <div className="border-b border-slate-800 pb-3">
                  <h3 className="text-base font-bold text-white">
                    ZIP Security Gate &amp; Extraction Limits
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Archive safety thresholds enforced prior to isolated sandbox extraction.
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-4 text-xs">
                  <div className="rounded-xl bg-slate-950 border border-slate-800 p-3">
                    <span className="text-slate-400 block">
                      Maximum ZIP Size
                    </span>
                    <span className="text-lg font-mono font-bold text-white">
                      {systemSettings.max_zip_size_mb} MB
                    </span>
                  </div>
                  <div className="rounded-xl bg-slate-950 border border-slate-800 p-3">
                    <span className="text-slate-400 block">
                      Maximum Expanded Size
                    </span>
                    <span className="text-lg font-mono font-bold text-white">
                      {(systemSettings.max_expanded_size_mb / 1024).toFixed(0)}{" "}
                      GB ({systemSettings.max_expanded_size_mb} MB)
                    </span>
                  </div>
                  <div className="rounded-xl bg-slate-950 border border-slate-800 p-3">
                    <span className="text-slate-400 block">
                      Maximum File Count
                    </span>
                    <span className="text-lg font-mono font-bold text-white">
                      {systemSettings.max_file_count.toLocaleString()} files
                    </span>
                  </div>
                  <div className="rounded-xl bg-slate-950 border border-slate-800 p-3">
                    <span className="text-slate-400 block">
                      Scan Execution Timeout
                    </span>
                    <span className="text-lg font-mono font-bold text-white">
                      600s (10 min)
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Admin Danger Zone: Purge Scan History */}
            {currentUser?.role === "ADMIN" && (
              <div className="rounded-2xl border border-rose-900/60 bg-rose-950/20 p-5 space-y-4">
                <div className="border-b border-rose-900/40 pb-3">
                  <h3 className="text-base font-bold text-rose-300 flex items-center gap-2">
                    <Trash2 className="h-5 w-5 text-rose-400" />
                    Administrator Danger Zone
                  </h3>
                  <p className="text-xs text-rose-200/80 mt-1">
                    Actions below are permanent and cannot be undone. Only Administrator accounts are authorized.
                  </p>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-950/80 border border-rose-900/40 rounded-xl p-4">
                  <div className="space-y-1">
                    <div className="text-sm font-semibold text-white">
                      Purge All Scan History
                    </div>
                    <p className="text-xs text-slate-400 max-w-xl">
                      Permanently deletes all assessment records, findings, dependency records, and Evidence Vault directories from disk storage. An immutable purge event is written to the SHA-256 audit chain for compliance traceability.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setPurgeConfirmText("");
                      setShowPurgeModal(true);
                    }}
                    className="inline-flex items-center gap-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs px-4 py-2.5 transition shadow"
                  >
                    <Trash2 className="h-4 w-4" />
                    Purge Scan History
                  </button>
                </div>
              </div>
            )}

            {/* Database-backed tamper-evident audit chain */}
            {auditLogsData && (
              <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
                  <div>
                    <h3 className="text-base font-bold text-white">
                      Tamper-Evident Audit Chain (Database-Backed)
                    </h3>
                    <p className="text-xs text-slate-400">
                      SHA-256 chain over selected audit fields. This is not external WORM storage and does not protect against database administrators.
                    </p>
                  </div>
                  <span
                    className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-mono font-bold border ${
                      auditLogsData.chain_integrity_verified
                        ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
                        : "bg-rose-500/20 text-rose-300 border-rose-500/40"
                    }`}
                  >
                    <ShieldCheck className="h-4 w-4" />
                    SHA-256 Chain Integrity:{" "}
                    {auditLogsData.chain_integrity_verified
                      ? "VERIFIED"
                      : "TAMPERED"}
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
                          <span className="font-mono font-bold text-emerald-400">
                            #{r.id} {r.event_type}
                          </span>
                          {r.assessment_code && (
                            <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-sky-300">
                              {r.assessment_code}
                            </span>
                          )}
                        </div>
                        <span className="font-mono text-[11px] text-slate-400">
                          {r.actor_email} [{r.actor_role}]
                        </span>
                      </div>
                      <p className="text-slate-200">{r.summary}</p>
                      <div className="flex flex-wrap items-center justify-between text-[10px] font-mono text-slate-500 pt-1">
                        <span>
                          Transition: {r.previous_state || "N/A"} →{" "}
                          {r.new_state || "N/A"}
                        </span>
                        <span>Chain Signature: {r.immutable_signature}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ===================================================================
            TAB 6: README & COMPREHENSIVE USER GUIDANCE
           =================================================================== */}
        {activeTab === "readme" && (
          <div className="space-y-8 max-w-5xl mx-auto pb-12">
            {/* Hero Banner */}
            <div className="rounded-3xl border border-emerald-500/30 bg-gradient-to-br from-slate-900 via-slate-900/90 to-emerald-950/20 p-8 shadow-xl">
              <div className="flex flex-wrap items-center gap-4">
                <div className="w-14 h-14 rounded-2xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shrink-0">
                  <ShieldCheck className="h-8 w-8" />
                </div>
                <div>
                  <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-mono font-bold bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 mb-2">
                    <Sparkles className="h-3 w-3" />
                    S-Gates Security Gateway v1.0
                  </div>
                  <h1 className="text-2xl font-black text-white tracking-tight">
                    Complete S-Gates Guide &amp; System Architecture
                  </h1>
                  <p className="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">
                    Application security gateway portal for dependency vulnerability scanning (SCA), credential leak prevention (Secrets), and static code analysis (SAST) before deploying software across your organization.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mt-6 pt-6 border-t border-slate-800/80 text-center">
                <div className="rounded-xl bg-slate-950/60 border border-slate-800 p-3">
                  <div className="text-emerald-400 font-bold text-sm">Aqua Trivy</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">SCA &amp; Config Audit</div>
                </div>
                <div className="rounded-xl bg-slate-950/60 border border-slate-800 p-3">
                  <div className="text-rose-400 font-bold text-sm">Gitleaks</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">Secret Detection</div>
                </div>
                <div className="rounded-xl bg-slate-950/60 border border-slate-800 p-3">
                  <div className="text-amber-400 font-bold text-sm">Semgrep SAST</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">OWASP Top 10</div>
                </div>
                <div className="rounded-xl bg-slate-950/60 border border-slate-800 p-3">
                  <div className="text-purple-400 font-bold text-sm">OSV-Scanner</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">OSV &amp; MAL-* Malware</div>
                </div>
                <div className="rounded-xl bg-slate-950/60 border border-slate-800 p-3">
                  <div className="text-orange-400 font-bold text-sm">GuardDog</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">PyPI / npm Supply-Chain</div>
                </div>
                <div className="rounded-xl bg-slate-950/60 border border-slate-800 p-3">
                  <div className="text-sky-400 font-bold text-sm">Registry Intel</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">Abandonment &amp; Typosquat</div>
                </div>
              </div>
            </div>

            {/* Section 1: What is S-Gates & Why It Matters */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Info className="h-5 w-5 text-emerald-400" />
                1. What is S-Gates &amp; Why Does It Matter?
              </h2>
              <p className="text-xs text-slate-300 leading-relaxed">
                With rapid adoption of AI coding assistants (such as Cursor, Claude, GitHub Copilot, ChatGPT, Lovable, and Bolt), internal applications built by developers and <em>citizen developers</em> ship faster than ever. However, AI-generated or third-party code frequently introduces hidden security risks:
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                <div className="rounded-xl bg-slate-950/80 border border-rose-900/40 p-4 space-y-1.5">
                  <div className="font-bold text-rose-300 flex items-center gap-1.5">
                    <ShieldAlert className="h-4 w-4 text-rose-400" />
                    Credential Leakage
                  </div>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    API keys, GitHub tokens, database connection strings, or private keys accidentally committed inside source files can be exploited if left unchecked.
                  </p>
                </div>
                <div className="rounded-xl bg-slate-950/80 border border-amber-900/40 p-4 space-y-1.5">
                  <div className="font-bold text-amber-300 flex items-center gap-1.5">
                    <Package className="h-4 w-4 text-amber-400" />
                    Vulnerable Dependencies (CVEs)
                  </div>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    AI assistants occasionally import outdated libraries or typosquatted packages carrying known Critical or High CVEs.
                  </p>
                </div>
                <div className="rounded-xl bg-slate-950/80 border border-sky-900/40 p-4 space-y-1.5">
                  <div className="font-bold text-sky-300 flex items-center gap-1.5">
                    <AlertTriangle className="h-4 w-4 text-sky-400" />
                    Unsafe Code Patterns (SAST)
                  </div>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    Unsafe execution constructs such as <code className="text-sky-300">eval()</code>, <code className="text-sky-300">os.system()</code>, SQL Injection, or path traversal bugs.
                  </p>
                </div>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                <strong>S-Gates acts as an automated security gatekeeper</strong> that scans every repository or source archive prior to approval, streams live execution telemetry, generates actionable reports, and preserves verifiable audit records.
              </p>
            </div>

            {/* Section 2: Three Real Security Scanners */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Cpu className="h-5 w-5 text-emerald-400" />
                2. Real Industry-Standard Security Scanners
              </h2>
              <p className="text-xs text-slate-300 leading-relaxed">
                S-Gates executes five real CLI security engines and live package registry intelligence concurrently inside an isolated server workspace:
              </p>

              <div className="space-y-4">
                {/* Scanner 1: Aqua Trivy */}
                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-sky-400" />
                      <h3 className="text-sm font-bold text-white">Aqua Trivy (v0.58.0)</h3>
                      <span className="rounded bg-sky-950 border border-sky-800 px-2 py-0.5 text-[10px] font-mono text-sky-300">
                        SCA &amp; Config Audit
                      </span>
                    </div>
                    <span className="text-xs text-slate-400">By Aqua Security</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Inspects dependency manifests (<code className="text-slate-200">requirements.txt</code>, <code className="text-slate-200">package.json</code>, <code className="text-slate-200">pom.xml</code>, <code className="text-slate-200">go.mod</code>) against global CVE advisories. Also audits Dockerfiles and Infrastructure-as-Code templates for misconfigurations such as running containers as <code className="text-slate-200">root</code>.
                  </p>
                </div>

                {/* Scanner 2: Gitleaks */}
                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-rose-400" />
                      <h3 className="text-sm font-bold text-white">Gitleaks (v8.21.2)</h3>
                      <span className="rounded bg-rose-950 border border-rose-800 px-2 py-0.5 text-[10px] font-mono text-rose-300">
                        Secret Detection &amp; Masking
                      </span>
                    </div>
                    <span className="text-xs text-slate-400">By Zachary Rice</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Scans source trees for over 160 secret patterns including AWS Access Keys, GitHub Personal Access Tokens, SSH/RSA Private Keys, OpenAI API Keys, and database credentials.
                  </p>
                  <div className="rounded-lg bg-rose-950/30 border border-rose-900/50 p-3 text-xs text-rose-200">
                    <strong className="text-rose-100">Strict Redaction Guarantee:</strong> Raw credential values are immediately masked as <code className="font-mono text-white">********************</code> before storage. Raw secrets are never persisted in the database, Evidence Vault, or live terminal logs.
                  </div>
                </div>

                {/* Scanner 3: Semgrep SAST */}
                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
                      <h3 className="text-sm font-bold text-white">Semgrep SAST (v1.95.0)</h3>
                      <span className="rounded bg-amber-950 border border-amber-800 px-2 py-0.5 text-[10px] font-mono text-amber-300">
                        Static Code Analysis
                      </span>
                    </div>
                    <span className="text-xs text-slate-400">By Semgrep / r2c</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Performs semantic static code analysis across Python, JavaScript/TypeScript, Go, Java, and more using OWASP Top 10 rulesets to uncover SQL Injection, Cross-Site Scripting (XSS), Command Injection, and cryptographic flaws.
                  </p>
                </div>

                {/* Scanner 4: Google OSV-Scanner */}
                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-purple-400" />
                      <h3 className="text-sm font-bold text-white">Google OSV-Scanner (v2.7.1)</h3>
                      <span className="rounded bg-purple-950 border border-purple-800 px-2 py-0.5 text-[10px] font-mono text-purple-300">
                        OSV &amp; OpenSSF MAL-* Malware
                      </span>
                    </div>
                    <span className="text-xs text-slate-400">By Google &amp; OpenSSF (Apache-2.0)</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Matches project lockfiles and dependency manifests against the Open Source Vulnerabilities (OSV) database, including <strong>OpenSSF Malicious Packages (<code>MAL-*</code>)</strong> advisories. Confirmed malicious packages automatically flag <code>Potentially Malicious Package</code> and trigger <strong>REJECT</strong>.
                  </p>
                </div>

                {/* Scanner 5: Datadog GuardDog */}
                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-orange-400" />
                      <h3 className="text-sm font-bold text-white">Datadog GuardDog (v3.2.0)</h3>
                      <span className="rounded bg-orange-950 border border-orange-800 px-2 py-0.5 text-[10px] font-mono text-orange-300">
                        PyPI &amp; npm Install-Script Inspection
                      </span>
                    </div>
                    <span className="text-xs text-slate-400">By Datadog (Apache-2.0)</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Inspects direct PyPI and npm manifest packages (up to 20 packages per scan with a 6-hour TTL cache) for supply-chain attack indicators such as malicious <code>setup.py</code> / <code>postinstall</code> scripts, hidden base64 payloads, and environment variable exfiltration.
                  </p>
                </div>

                {/* Scanner 6: PyPI & npm Registry Metadata Checker */}
                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
                      <h3 className="text-sm font-bold text-white">PyPI &amp; npm Registry Metadata Checker</h3>
                      <span className="rounded bg-emerald-950 border border-emerald-800 px-2 py-0.5 text-[10px] font-mono text-emerald-300">
                        Abandonment &amp; Typosquatting
                      </span>
                    </div>
                    <span className="text-xs text-slate-400">Live Public Registry API (6h Cache)</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Queries <code>pypi.org</code> and <code>registry.npmjs.org</code> to populate real <strong>Last Release Date</strong>, <strong>Publisher Identity</strong>, and <strong>Maintainer Status</strong>. Flags packages stale &gt; 2 years as <code>ABANDONED</code> (triggers <strong>REVIEW</strong>), 1–2 years or deprecated as <code>MAINTENANCE REVIEW</code>, and detects typosquatting mimics (e.g. <code>reqeusts</code> vs <code>requests</code>) as <code>Typosquatting Suspect</code> (triggers <strong>REJECT</strong>).
                  </p>
                </div>
              </div>
            </div>

            {/* Section 3: 4-Step Scanning Workflow */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Layers className="h-5 w-5 text-emerald-400" />
                3. End-to-End Scanning Workflow
              </h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center font-bold text-emerald-400">
                    1
                  </div>
                  <h3 className="font-bold text-white">Source Code Intake</h3>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    Provide a public or private GitHub repository URL or upload a <code className="text-slate-300">.zip</code> source archive.
                  </p>
                </div>

                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center font-bold text-sky-400">
                    2
                  </div>
                  <h3 className="font-bold text-white">Sandbox &amp; Live Terminal</h3>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    S-Gates validates ZIP safety, runs Trivy, Gitleaks, Semgrep, OSV-Scanner, GuardDog, and Registry checks concurrently, and streams live progress to the console.
                  </p>
                </div>

                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center font-bold text-amber-400">
                    3
                  </div>
                  <h3 className="font-bold text-white">Risk Decision Engine</h3>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    Consolidates findings and classifies the submission as Pass, Review, or Reject based on severity thresholds.
                  </p>
                </div>

                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center font-bold text-purple-400">
                    4
                  </div>
                  <h3 className="font-bold text-white">Evidence Vault</h3>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    Saves standalone HTML reports, JSON scanner summaries, file inventory CSVs, and SHA-256 chained audit logs.
                  </p>
                </div>
              </div>
            </div>

            {/* Section 4: Risk Decision Outcomes */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                4. Understanding Risk Decision Statuses
              </h2>
              <div className="space-y-3 text-xs">
                <div className="rounded-xl bg-emerald-950/30 border border-emerald-500/30 p-4 flex items-start gap-3">
                  <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
                  <div>
                    <h3 className="font-bold text-emerald-300 text-sm">
                      PASS-WITH-MANUAL-CHECKS (Passed Automated Checks)
                    </h3>
                    <p className="text-slate-300 mt-1 leading-relaxed">
                      Zero critical vulnerabilities, zero leaked secrets, and no high-risk SAST findings detected. Ready for pilot or manual operational verification if required.
                    </p>
                  </div>
                </div>

                <div className="rounded-xl bg-amber-950/30 border border-amber-500/30 p-4 flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <h3 className="font-bold text-amber-300 text-sm">
                      REVIEW (Security Review Required)
                    </h3>
                    <p className="text-slate-300 mt-1 leading-relaxed">
                      Medium or High findings or aging dependencies were detected. Review the Findings Dashboard with your security team or tech lead before releasing to production.
                    </p>
                  </div>
                </div>

                <div className="rounded-xl bg-rose-950/30 border border-rose-500/30 p-4 flex items-start gap-3">
                  <XCircle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
                  <div>
                    <h3 className="font-bold text-rose-300 text-sm">
                      REJECT (Blocked — Critical Risk Detected)
                    </h3>
                    <p className="text-slate-300 mt-1 leading-relaxed">
                      Triggered by active leaked credentials, Critical CVEs, unsafe shell/eval execution, or ZIP path traversal violations. Must be remediated and re-scanned.
                    </p>
                  </div>
                </div>

                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-slate-400 shrink-0 mt-0.5" />
                  <div>
                    <h3 className="font-bold text-slate-300 text-sm">
                      SCAN-ERROR (Scan Interrupted)
                    </h3>
                    <p className="text-slate-400 mt-1 leading-relaxed">
                      The scan could not complete due to technical issues (for example, a corrupted ZIP file, unreachable GitHub repository URL, or invalid private token).
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Section 5: Step-by-Step Usage Guide */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <FileText className="h-5 w-5 text-emerald-400" />
                5. Step-by-Step Usage Guide
              </h2>

              <div className="space-y-4 text-xs">
                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <h3 className="font-bold text-white text-sm">Scanning a GitHub Repository</h3>
                  <ol className="list-decimal list-inside space-y-1.5 text-slate-300 leading-relaxed">
                    <li>Open the <strong>&quot;2. New Code Scan&quot;</strong> tab.</li>
                    <li>Enter your application name in the <em>Application / Project Name</em> field.</li>
                    <li>Under <strong>Option A</strong>, paste the GitHub repository URL (e.g. <code className="text-emerald-300">https://github.com/owner/repository</code>).</li>
                    <li>For private repositories, enter a fine-grained GitHub Personal Access Token with <em>Contents: read</em> permission.</li>
                    <li>Click <strong>&quot;Start GitHub Scan&quot;</strong> and watch real-time backend logs stream in the Live Backend Terminal on the right. Once complete, click <strong>&quot;View Full Assessment Report&quot;</strong>.</li>
                  </ol>
                </div>

                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <h3 className="font-bold text-white text-sm">Scanning a .ZIP Source Archive</h3>
                  <ol className="list-decimal list-inside space-y-1.5 text-slate-300 leading-relaxed">
                    <li>Open the <strong>&quot;2. New Code Scan&quot;</strong> tab.</li>
                    <li>Under <strong>Option B</strong>, click the upload dropzone to choose a <code className="text-sky-300">.zip</code> package from your computer.</li>
                    <li>Click <strong>&quot;Start .ZIP Scan&quot;</strong>. S-Gates validates the archive, computes its SHA-256 hash, and streams scanner progress live.</li>
                  </ol>
                </div>

                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <h3 className="font-bold text-white text-sm">Downloading Reports &amp; Audit Evidence</h3>
                  <ol className="list-decimal list-inside space-y-1.5 text-slate-300 leading-relaxed">
                    <li>Navigate to <strong>&quot;3. Assessment Results&quot;</strong> and select an assessment code.</li>
                    <li>Click <strong>&quot;Download HTML Report&quot;</strong> for a self-contained executive and technical summary viewable offline.</li>
                    <li>Click <strong>&quot;Download Evidence Vault (.zip)&quot;</strong> to retrieve the complete audit package including JSON reports and file inventories.</li>
                  </ol>
                </div>

                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <h3 className="font-bold text-white text-sm">Deleting Assessments, Applications &amp; Purging History (Admin Only)</h3>
                  <ol className="list-decimal list-inside space-y-1.5 text-slate-300 leading-relaxed">
                    <li><strong>Delete Single Assessment:</strong> In <em>Assessment Results</em>, click the red <strong>&quot;Delete Assessment&quot;</strong> button in the header action bar.</li>
                    <li><strong>Delete Application from Inventory:</strong> In <strong>&quot;4. Application Inventory&quot;</strong>, click <strong>&quot;Delete&quot;</strong> in the Actions column to remove the application along with all linked assessments and Evidence Vault directories.</li>
                    <li><strong>Purge All History:</strong> Open <strong>&quot;5. Admin &amp; Audit Trail&quot;</strong>, scroll to the <em>Administrator Danger Zone</em>, click <strong>&quot;Purge Scan History&quot;</strong>, type <strong>DELETE</strong>, and confirm.</li>
                  </ol>
                </div>
              </div>
            </div>

            {/* Section 6: Backend & Technical Architecture */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Database className="h-5 w-5 text-emerald-400" />
                6. Backend &amp; Technical Architecture
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <h3 className="font-bold text-emerald-300">Backend Core</h3>
                  <ul className="space-y-1.5 text-slate-300 text-[11px]">
                    <li>• <strong>Framework:</strong> FastAPI (Python 3.12)</li>
                    <li>• <strong>Database:</strong> PostgreSQL 16 (Relational &amp; JSONB)</li>
                    <li>• <strong>ORM &amp; Validation:</strong> SQLAlchemy 2.0 &amp; Pydantic v2</li>
                    <li>• <strong>Authentication:</strong> JWT Bearer Token with Role-Based Access Control (Admin, Security Reviewer, IT Reviewer, Citizen Developer)</li>
                    <li>• <strong>Audit Trail:</strong> Tamper-evident SHA-256 hash chaining</li>
                  </ul>
                </div>

                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-2">
                  <h3 className="font-bold text-sky-300">Frontend &amp; Streaming</h3>
                  <ul className="space-y-1.5 text-slate-300 text-[11px]">
                    <li>• <strong>Framework:</strong> Next.js 16 (App Router) &amp; React 19</li>
                    <li>• <strong>Styling:</strong> Tailwind CSS &amp; Lucide Icons</li>
                    <li>• <strong>Live Telemetry:</strong> Real-time NDJSON streaming directly to port 8003 over CORS, bypassing proxy timeouts</li>
                    <li>• <strong>Network Bindings:</strong> Port 3003 (Frontend) &amp; 8003 (Backend API) bound to <code className="text-sky-300">0.0.0.0</code> for LAN access</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Section 7: FAQ & Security Guarantees */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <HelpCircle className="h-5 w-5 text-emerald-400" />
                7. Frequently Asked Questions (FAQ)
              </h2>
              <div className="space-y-3 text-xs">
                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-1">
                  <h3 className="font-bold text-white">Is my extracted source directory kept permanently on disk?</h3>
                  <p className="text-slate-400 leading-relaxed">
                    No. Source files are extracted into an isolated temporary workspace only for the duration of the scanner run and cleaned up immediately afterward. Only metadata, HTML/JSON reports, and the Evidence Vault archive are persisted.
                  </p>
                </div>

                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-1">
                  <h3 className="font-bold text-white">How does S-Gates protect leaked tokens or API keys found during a scan?</h3>
                  <p className="text-slate-400 leading-relaxed">
                    S-Gates enforces strict redaction: matched secret values are immediately masked as <code className="text-emerald-300">********************</code> inside the scanner adapter before any database insert, Evidence Vault file write, or UI response.
                  </p>
                </div>

                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-1">
                  <h3 className="font-bold text-white">Can teammates access S-Gates from other laptops on the local network (LAN)?</h3>
                  <p className="text-slate-400 leading-relaxed">
                    Yes. Both frontend and backend bind to <code className="text-emerald-300">0.0.0.0</code> with dynamic LAN CORS support, so colleagues can open the portal directly using your host IP on port <code className="text-emerald-300">3003</code>.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ===================================================================
            PURGE ALL HISTORY CONFIRMATION MODAL
           =================================================================== */}
        {showPurgeModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
            <div className="w-full max-w-md rounded-2xl border border-rose-600 bg-slate-900 p-6 shadow-2xl space-y-4">
              <div className="flex items-center gap-3 text-rose-400">
                <div className="w-10 h-10 rounded-xl bg-rose-950 border border-rose-700 flex items-center justify-center">
                  <Trash2 className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">Confirm Scan History Purge</h3>
                  <p className="text-xs text-rose-300">This action cannot be undone!</p>
                </div>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">
                This will <strong>permanently delete</strong> all scan history, findings, Evidence Vault artifacts on disk, and assessment records.
              </p>

              <div className="rounded-lg bg-slate-950 border border-slate-800 p-3 space-y-2">
                <label className="block text-xs font-semibold text-slate-300">
                  To continue, type <strong className="text-rose-400 font-mono">DELETE</strong> below:
                </label>
                <input
                  type="text"
                  value={purgeConfirmText}
                  onChange={(e) => setPurgeConfirmText(e.target.value)}
                  placeholder="Type DELETE"
                  className="w-full rounded-lg bg-slate-900 border border-slate-700 px-3 py-2 text-xs font-mono text-white focus:border-rose-500 focus:outline-none"
                  autoFocus
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowPurgeModal(false)}
                  disabled={deletingCode === "all"}
                  className="rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-300 transition"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handlePurgeAllHistory}
                  disabled={purgeConfirmText.trim().toUpperCase() !== "DELETE" || deletingCode === "all"}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-40 disabled:cursor-not-allowed px-4 py-2 text-xs font-bold text-white transition shadow"
                >
                  {deletingCode === "all" ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      Purging...
                    </>
                  ) : (
                    <>
                      <Trash2 className="h-3.5 w-3.5" />
                      Purge All History
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
