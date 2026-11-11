"use client";

import React, { useEffect, useRef } from "react";
import {
  Activity,
  Bell,
  BookOpen,
  Layers,
  Plus,
  Settings,
  ShieldCheck,
  Terminal,
  Upload,
} from "lucide-react";
import type { NotificationItem, UserPersona } from "@/lib/api";

export type ActiveTab =
  | "dashboard"
  | "submit"
  | "studio"
  | "inventory"
  | "governance"
  | "readme";

interface HeaderNavProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: ActiveTab) => void;
  selectedCode: string;
  currentUser: UserPersona | null;
  intelStatus: string;
  scannerMode?: string;
  notifications: NotificationItem[];
  showNotifDrawer: boolean;
  onToggleNotifDrawer: () => void;
  onCloseNotifDrawer: () => void;
  onLogout: () => void;
}

export default function HeaderNav({
  activeTab,
  onSelectTab,
  selectedCode,
  currentUser,
  intelStatus,
  scannerMode,
  notifications,
  showNotifDrawer,
  onToggleNotifDrawer,
  onCloseNotifDrawer,
  onLogout,
}: HeaderNavProps) {
  const notifContainerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!showNotifDrawer) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onCloseNotifDrawer();
    }
    function onMouseDown(e: MouseEvent) {
      if (
        notifContainerRef.current &&
        !notifContainerRef.current.contains(e.target as Node)
      ) {
        onCloseNotifDrawer();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    document.addEventListener("mousedown", onMouseDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("mousedown", onMouseDown);
    };
  }, [showNotifDrawer, onCloseNotifDrawer]);

  const canViewAdminTab =
    currentUser?.role === "ADMIN" ||
    currentUser?.role === "SECURITY_REVIEWER" ||
    currentUser?.role === "IT_REVIEWER";

  const tabs: Array<{
    id: ActiveTab;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
  }> = [
    { id: "dashboard", label: "Overview", icon: Activity },
    { id: "submit", label: "New Scan", icon: Upload },
    {
      id: "studio",
      label: selectedCode ? `Results (${selectedCode})` : "Results",
      icon: Terminal,
    },
    { id: "inventory", label: "Inventory", icon: Layers },
    ...(canViewAdminTab
      ? [{ id: "governance" as ActiveTab, label: "Admin & Audit", icon: Settings }]
      : []),
    { id: "readme", label: "User Guide", icon: BookOpen },
  ];

  return (
    <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-[#0b1120]/95 backdrop-blur">
      <div className="mx-auto max-w-[1440px] px-6 py-3 flex flex-wrap items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-xl bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center">
            <ShieldCheck className="h-5 w-5 text-emerald-400" aria-hidden="true" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-base font-bold tracking-tight text-white">
                S-GATES
              </span>
              <span
                className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-mono font-semibold border ${
                  intelStatus === "HEALTHY"
                    ? "bg-emerald-950/60 border-emerald-500/30 text-emerald-200"
                    : "bg-rose-950/80 border-rose-500/50 text-rose-200"
                }`}
              >
                <span
                  aria-hidden="true"
                  className={`h-1.5 w-1.5 rounded-full ${
                    intelStatus === "HEALTHY"
                      ? "bg-emerald-400"
                      : "bg-rose-400 animate-pulse"
                  }`}
                />
                {scannerMode === "heuristic-demo"
                  ? "Demo Mode"
                  : `Scanners: ${intelStatus}`}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Code scanning and release gate for GitHub repositories and source ZIPs
            </p>
          </div>
        </div>

        {/* Right Controls */}
        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => onSelectTab("submit")}
            className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-3.5 py-2 text-xs font-bold text-slate-950 transition shadow focus-visible:ring-2 focus-visible:ring-emerald-300"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            New Scan
          </button>

          <div className="relative" ref={notifContainerRef}>
            <button
              type="button"
              onClick={onToggleNotifDrawer}
              aria-label="Event notifications"
              aria-expanded={showNotifDrawer}
              className="relative rounded-lg bg-slate-900 border border-slate-800 p-2 text-slate-300 hover:text-white hover:border-slate-700 transition focus-visible:ring-2 focus-visible:ring-emerald-400"
              title="Event notifications"
            >
              <Bell className="h-4 w-4" aria-hidden="true" />
              {notifications.length > 0 && (
                <span className="absolute -top-1 -right-1 h-4 min-w-[16px] rounded-full bg-emerald-500 px-1 text-[11px] font-bold text-slate-950 flex items-center justify-center">
                  {notifications.length}
                </span>
              )}
            </button>

            {showNotifDrawer && (
              <div
                role="region"
                aria-label="Event Notifications"
                className="absolute right-0 mt-2 w-96 max-w-[calc(100vw-2rem)] rounded-xl bg-slate-900 border border-slate-700 shadow-2xl p-4 z-50"
              >
                <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-200">
                    Event Notifications
                  </span>
                  <button
                    type="button"
                    onClick={onCloseNotifDrawer}
                    aria-label="Close notifications"
                    className="text-xs text-slate-300 hover:text-white px-1.5 py-0.5 rounded focus-visible:ring-2 focus-visible:ring-emerald-400"
                  >
                    Close
                  </button>
                </div>
                {notifications.length === 0 ? (
                  <p className="py-4 text-center text-xs text-slate-400">
                    No notifications yet.
                  </p>
                ) : (
                  <div className="max-h-72 overflow-y-auto space-y-2">
                    {notifications.map((n) => (
                      <div
                        key={n.id}
                        className="rounded-lg bg-slate-950/70 border border-slate-800 p-2.5 text-xs"
                      >
                        <div className="flex items-center justify-between text-xs text-emerald-300 font-semibold">
                          <span>{n.event_type}</span>
                          <span className="font-mono text-slate-400">
                            {n.assessment_code}
                          </span>
                        </div>
                        <p className="text-slate-200 mt-1">{n.message}</p>
                        <span className="text-xs text-slate-400 mt-1 block">
                          Channel: {n.channel}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {currentUser && (
            <span className="hidden md:inline-flex items-center rounded-lg bg-slate-900 border border-slate-800 px-2.5 py-1.5 text-xs text-slate-300">
              <span className="font-medium text-white">{currentUser.full_name}</span>
              <span className="mx-1.5 text-slate-600" aria-hidden="true">·</span>
              <span className="font-mono text-emerald-300">{currentUser.role}</span>
            </span>
          )}

          <button
            type="button"
            onClick={onLogout}
            className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 transition hover:border-slate-500 hover:text-white focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            Sign out
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav
        aria-label="Primary sections"
        className="mx-auto max-w-[1440px] px-6 flex items-center gap-1 overflow-x-auto border-t border-slate-800/60"
      >
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              type="button"
              key={tab.id}
              onClick={() => onSelectTab(tab.id)}
              aria-current={isActive ? "page" : undefined}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition whitespace-nowrap focus-visible:ring-2 focus-visible:ring-emerald-400 ${
                isActive
                  ? "border-emerald-400 text-emerald-300 bg-emerald-500/5"
                  : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40"
              }`}
            >
              <Icon className="h-3.5 w-3.5" aria-hidden="true" />
              {tab.label}
            </button>
          );
        })}
      </nav>
    </header>
  );
}
