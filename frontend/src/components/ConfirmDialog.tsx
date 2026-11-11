"use client";

import React, { useEffect, useId, useState } from "react";
import { Loader2, Trash2 } from "lucide-react";

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  cancelLabel?: string;
  requireTypedWord?: string;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  cancelLabel = "Cancel",
  requireTypedWord,
  busy = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const [typed, setTyped] = useState("");
  const titleId = useId();
  const inputId = useId();

  useEffect(() => {
    if (!open) return;
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && !busy) {
        setTyped("");
        onCancel();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, busy, onCancel]);

  if (!open) return null;

  function handleCancelClick() {
    setTyped("");
    onCancel();
  }

  function handleConfirmClick() {
    onConfirm();
  }

  const canConfirm =
    !busy &&
    (!requireTypedWord ||
      typed.trim().toUpperCase() === requireTypedWord.toUpperCase());

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      onClick={(e) => {
        if (e.target === e.currentTarget && !busy) {
          handleCancelClick();
        }
      }}
    >
      <div className="w-full max-w-md rounded-2xl border border-rose-600/80 bg-slate-900 p-6 shadow-2xl space-y-4">
        <div className="flex items-center gap-3 text-rose-300">
          <div className="w-10 h-10 rounded-xl bg-rose-950 border border-rose-700 flex items-center justify-center shrink-0">
            <Trash2 className="h-5 w-5" aria-hidden="true" />
          </div>
          <div>
            <h3 id={titleId} className="text-base font-bold text-white">
              {title}
            </h3>
            <p className="text-xs text-rose-300">You cannot undo this.</p>
          </div>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed">{description}</p>

        {requireTypedWord && (
          <div className="rounded-lg bg-slate-950 border border-slate-800 p-3 space-y-2">
            <label
              htmlFor={inputId}
              className="block text-xs font-semibold text-slate-300"
            >
              Type{" "}
              <strong className="text-rose-300 font-mono">
                {requireTypedWord}
              </strong>{" "}
              to confirm:
            </label>
            <input
              id={inputId}
              type="text"
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              placeholder={`Type ${requireTypedWord}`}
              className="w-full rounded-lg bg-slate-900 border border-slate-700 px-3 py-2 text-xs font-mono text-white focus:border-rose-500 focus-visible:ring-2 focus-visible:ring-rose-400"
              autoFocus
            />
          </div>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={handleCancelClick}
            disabled={busy}
            className="rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-200 transition focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            onClick={handleConfirmClick}
            disabled={!canConfirm}
            className="inline-flex items-center gap-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-40 disabled:cursor-not-allowed px-4 py-2 text-xs font-bold text-white transition shadow focus-visible:ring-2 focus-visible:ring-rose-400"
          >
            {busy ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                Deleting...
              </>
            ) : (
              <>
                <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                {confirmLabel}
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
