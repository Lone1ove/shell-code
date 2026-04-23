"use client";

import { useRef, useEffect, useCallback } from "react";
import { Terminal } from "lucide-react";
import { useAppStore } from "@/hooks/useAppStore";

interface LogTerminalProps {
  onScroll?: (e: React.UIEvent<HTMLDivElement>) => void;
}

export function LogTerminal({ onScroll }: LogTerminalProps) {
  const { state } = useAppStore();
  const session = state.sessions.find((s) => s.id === state.activeSessionId);
  const logs = session?.logs || [];
  const isRunning = session?.isRunning || false;

  const logsEndRef = useRef<HTMLDivElement>(null);
  const isAtBottomRef = useRef(true);

  // 智能滚动：新日志自动滚到底部
  useEffect(() => {
    if (isAtBottomRef.current && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ block: "end", behavior: "smooth" });
    }
  }, [logs]);

  const handleScroll = useCallback(
    (e: React.UIEvent<HTMLDivElement>) => {
      const target = e.currentTarget;
      const atBottom =
        target.scrollHeight - target.scrollTop - target.clientHeight < 80;
      isAtBottomRef.current = atBottom;
      onScroll?.(e);
    },
    [onScroll]
  );

  const getLineColor = (line: string) => {
    if (line.includes("❌") || line.toLowerCase().includes("error")) {
      return "text-red-600 dark:text-red-400";
    }
    if (line.includes("✅") || line.includes("🎉")) {
      return "text-green-600 dark:text-green-400";
    }
    if (line.includes("🛑")) {
      return "text-yellow-600 dark:text-yellow-400";
    }
    if (line.includes("⚠️")) {
      return "text-yellow-600 dark:text-yellow-400";
    }
    return "text-gray-700 dark:text-gray-300";
  };

  return (
    <div className="card flex flex-col h-full">
      <h2 className="text-lg font-medium text-gray-900 dark:text-white px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center gap-2 shrink-0">
        <Terminal className="w-5 h-5 text-sky-500" />
        运行日志
        {isRunning && (
          <span className="ml-2 inline-flex items-center gap-1.5 text-sm text-gray-500 dark:text-gray-400">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sky-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-sky-500" />
            </span>
            运行中
          </span>
        )}
      </h2>

      {/* 白色终端区域：flex-1 自动填满剩余空间，overflow-y: auto 内部滚动 */}
      <div
        className="flex-1 bg-white dark:bg-slate-900 p-4 overflow-y-auto font-mono text-sm min-h-0"
        onScroll={handleScroll}
      >
        {logs.length === 0 ? (
          <div className="text-gray-400 dark:text-gray-500 h-full flex items-center justify-center">
            等待启动渗透测试...
          </div>
        ) : (
          <div className="space-y-0.5">
            {logs.map((line, i) => (
              <div key={i} className={getLineColor(line)}>
                {line}
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        )}
      </div>
    </div>
  );
}