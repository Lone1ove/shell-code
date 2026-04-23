"use client";

import { CheckCircle, Search, Scan, CheckCircle as Verify, FileText } from "lucide-react";
import { useAppStore } from "@/hooks/useAppStore";

const phases = [
  { id: "collecting" as const, label: "信息收集", icon: <Search className="w-3.5 h-3.5" /> },
  { id: "scanning" as const, label: "漏洞扫描", icon: <Scan className="w-3.5 h-3.5" /> },
  { id: "verifying" as const, label: "漏洞验证", icon: <Verify className="w-3.5 h-3.5" /> },
  { id: "reporting" as const, label: "报告生成", icon: <FileText className="w-3.5 h-3.5" /> },
];

export function PhaseIndicator() {
  const { state } = useAppStore();
  const session = state.sessions.find((s) => s.id === state.activeSessionId);
  const currentPhase = session?.currentPhase || "idle";

  const currentIndex = phases.findIndex((p) => p.id === currentPhase);

  return (
    <div className="card p-4">
      <div className="flex items-center justify-between">
        {phases.map((phase, idx) => {
          const isDone = currentIndex > idx;
          const isActive = currentPhase === phase.id;

          return (
            <div key={phase.id} className="flex items-center">
              <div className="flex flex-col items-center gap-1">
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center border-2 transition-all duration-300 ${
                    isDone
                      ? "bg-cyan-500 border-cyan-500 text-white"
                      : isActive
                      ? "bg-cyan-500 border-cyan-500 text-white animate-pulse shadow-lg shadow-cyan-500/30"
                      : "bg-transparent border-gray-300 text-gray-400 dark:border-gray-600"
                  }`}
                >
                  {isDone ? (
                    <CheckCircle className="w-4 h-4" />
                  ) : (
                    phase.icon
                  )}
                </div>
                <span
                  className={`text-xs font-medium whitespace-nowrap ${
                    isDone || isActive
                      ? "text-cyan-600 dark:text-cyan-400"
                      : "text-gray-400 dark:text-gray-500"
                  }`}
                >
                  {phase.label}
                </span>
              </div>
              {idx < phases.length - 1 && (
                <div
                  className={`h-0.5 flex-1 mx-1 min-w-[20px] transition-all duration-300 ${
                    isDone || isActive ? "bg-cyan-400" : "bg-gray-200 dark:bg-gray-700"
                  }`}
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}