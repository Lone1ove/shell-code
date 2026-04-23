"use client";

import { useEffect, useRef } from "react";
import { Plus, Settings as SettingsIcon, X } from "lucide-react";
import { useAppStore } from "@/hooks/useAppStore";
import { loadConfig, mergeConfig } from "@/lib/config-storage";
import { useAgent } from "@/hooks/useAgent";
import { ActionButtons } from "@/components/workspace/ActionButtons";
import { LogTerminal } from "@/components/workspace/LogTerminal";
import { PhaseIndicator } from "@/components/workspace/PhaseIndicator";
import { ReportPanel } from "@/components/workspace/ReportPanel";
import { TargetForm } from "@/components/workspace/TargetForm";

export function WorkspaceView() {
  const { state, dispatch } = useAppStore();
  const { startAgent, stopAgent } = useAgent();
  const activeSession = state.sessions.find((item) => item.id === state.activeSessionId);
  const configLoadedRef = useRef(false);

  useEffect(() => {
    if (configLoadedRef.current) {
      return;
    }
    configLoadedRef.current = true;

    const saved = loadConfig();
    if (Object.keys(saved).length > 0) {
      dispatch({ type: "SET_CONFIG", config: mergeConfig(state.config, saved) });
    }
  }, [dispatch, state.config]);

  const handleStart = () => {
    if (!activeSession) {
      return;
    }
    const isMultiple =
      state.config.runMode === "pentest" && state.config.targetMode === "multiple";
    const config = {
      ...state.config,
      targetUrl: isMultiple
        ? (state.config.targetUrls || []).join(" ")
        : activeSession.targetUrl,
    };
    startAgent(config, activeSession.id);
  };

  const handleStop = () => {
    if (activeSession) {
      stopAgent(activeSession.id);
    }
  };

  return (
    <div className="flex h-full flex-col overflow-hidden" style={{ height: "calc(100vh - 64px)" }}>
      <div className="flex-shrink-0 px-6 pb-2 pt-4 lg:px-8">
        <div className="flex flex-wrap items-center gap-2">
          {state.sessions.map((session) => (
            <div
              key={session.id}
              className={`flex items-center gap-2 rounded-lg border px-3 py-2 transition-colors ${
                session.id === state.activeSessionId
                  ? "border-sky-300 bg-sky-50 dark:border-sky-700 dark:bg-sky-900/30"
                  : "border-gray-200 bg-white hover:border-sky-300 dark:border-gray-700 dark:bg-gray-800 dark:hover:border-sky-600"
              }`}
            >
              <button
                type="button"
                onClick={() => dispatch({ type: "SET_ACTIVE_SESSION", id: session.id })}
                className="flex items-center gap-2 text-sm font-medium"
              >
                <SettingsIcon className="h-4 w-4 text-gray-500" />
                <span className="text-gray-700 dark:text-gray-300">
                  {session.targetUrl || "新会话"}
                </span>
                {session.isRunning && (
                  <span className="relative flex h-2 w-2">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-sky-400 opacity-75" />
                    <span className="relative inline-flex h-2 w-2 rounded-full bg-sky-500" />
                  </span>
                )}
              </button>
              {state.sessions.length > 1 && (
                <button
                  type="button"
                  onClick={(event) => {
                    event.stopPropagation();
                    dispatch({ type: "REMOVE_SESSION", id: session.id });
                  }}
                  className="rounded p-1 hover:bg-gray-200 dark:hover:bg-gray-700"
                  aria-label={`移除会话 ${session.targetUrl || session.id}`}
                >
                  <X className="h-3 w-3 text-gray-400" />
                </button>
              )}
            </div>
          ))}

          <button
            type="button"
            onClick={() => dispatch({ type: "ADD_SESSION" })}
            className="flex items-center gap-1 rounded-lg border border-dashed border-gray-300 px-3 py-2 text-sm text-gray-600 transition-colors hover:border-sky-400 hover:text-sky-500 dark:border-gray-600 dark:text-gray-400 dark:hover:border-sky-500"
          >
            <Plus className="h-4 w-4" />
            新建会话
          </button>
        </div>
      </div>

      <div className="flex min-h-0 flex-1 gap-3 overflow-hidden px-6 pb-4 lg:px-8">
        <div className="flex min-h-0 w-[calc(50%-6px)] flex-col overflow-y-auto px-1">
          <div className="mb-3 flex-shrink-0">
            <TargetForm />
          </div>
          <div className="mb-3 flex-shrink-0">
            <ActionButtons onStart={handleStart} onStop={handleStop} />
          </div>
          <div className="mb-3 flex-shrink-0">
            <PhaseIndicator />
          </div>
          <div className="flex-shrink-0">
            <ReportPanel />
          </div>
        </div>

        <div className="flex min-h-0 w-[calc(50%-6px)] flex-col overflow-hidden px-1">
          <LogTerminal />
        </div>
      </div>
    </div>
  );
}
