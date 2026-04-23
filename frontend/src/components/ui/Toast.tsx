"use client";

import { CheckCircle2, AlertCircle, Shield, X } from "lucide-react";
import { ToastItem } from "@/types";

interface ToastProps {
  toast: ToastItem;
  onDismiss: (id: number) => void;
}

const styles = {
  success: "bg-teal-50 dark:bg-teal-900/30 border-teal-200 dark:border-teal-800 text-teal-800 dark:text-teal-200",
  error: "bg-rose-50 dark:bg-rose-900/30 border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-200",
  warning: "bg-amber-50 dark:bg-amber-900/30 border-amber-200 dark:border-amber-800 text-amber-800 dark:text-amber-200",
  info: "bg-cyan-50 dark:bg-cyan-900/30 border-cyan-200 dark:border-cyan-800 text-cyan-800 dark:text-cyan-200",
};

const icons = {
  success: <CheckCircle2 className="w-5 h-5 text-teal-500" />,
  error: <AlertCircle className="w-5 h-5 text-rose-500" />,
  warning: <AlertCircle className="w-5 h-5 text-amber-500" />,
  info: <Shield className="w-5 h-5 text-cyan-500" />,
};

export function Toast({ toast, onDismiss }: ToastProps) {
  return (
    <div
      className={`flex items-center gap-3 px-4 py-3 rounded-lg border shadow-lg animate-in slide-in-from-right ${styles[toast.type]}`}
    >
      {icons[toast.type]}
      <span className="flex-1 text-sm font-medium">{toast.message}</span>
      <button
        onClick={() => onDismiss(toast.id)}
        className="p-1 hover:opacity-70 transition-opacity"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  );
}
