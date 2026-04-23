"use client";

import { AlertCircle, Play, Square } from "lucide-react";
import { useAppStore } from "@/hooks/useAppStore";

interface ActionButtonsProps {
  onStart: () => void;
  onStop: () => void;
}

export function ActionButtons({ onStart, onStop }: ActionButtonsProps) {
  const { state } = useAppStore();
  const session = state.sessions.find((item) => item.id === state.activeSessionId);
  const isRunning = session?.isRunning || false;
  const error = session?.error || "";
  const canStart = (() => {
    if (isRunning) {
      return false;
    }
    if (state.config.targetMode === "multiple") {
      return (state.config.targetUrls?.length || 0) > 0;
    }
    return (session?.targetUrl?.trim() || "") !== "";
  })();

  return (
    <div className="card p-6">
      {error && (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/30">
          <AlertCircle className="mt-0.5 h-5 w-5 flex-shrink-0 text-red-500" />
          <div>
            <p className="text-sm font-medium text-red-800 dark:text-red-200">执行错误</p>
            <p className="mt-1 text-sm text-red-600 dark:text-red-300">{error}</p>
          </div>
        </div>
      )}

      <button
        type="button"
        onClick={isRunning ? onStop : onStart}
        disabled={!isRunning && !canStart}
        className={`flex w-full items-center justify-center gap-2 rounded-lg px-6 py-3 font-medium transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 ${
          isRunning
            ? "bg-red-500 text-white hover:bg-red-600 focus:ring-red-500"
            : "bg-sky-500 text-white hover:bg-sky-600 focus:ring-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
        }`}
      >
        {isRunning ? (
          <>
            <Square className="h-5 w-5" />
            停止渗透测试
          </>
        ) : (
          <>
            <Play className="h-5 w-5" />
            开始渗透测试
          </>
        )}
      </button>

      {!canStart && !error && (
        <p className="mt-2 text-center text-sm text-gray-500 dark:text-gray-400">
          {state.config.targetMode === "multiple" ? "请先添加目标地址" : "请先输入目标地址"}
        </p>
      )}
    </div>
  );
}
