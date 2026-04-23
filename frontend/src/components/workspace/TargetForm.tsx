"use client";

import { useState } from "react";
import { Bot, Cpu, Flag, Plus, Server, Settings, Shield, X } from "lucide-react";
import { useAppStore } from "@/hooks/useAppStore";
import { RunMode, TargetMode } from "@/app/api/types";

export function TargetForm() {
  const { state, dispatch } = useAppStore();
  const session = state.sessions.find((item) => item.id === state.activeSessionId);
  const [newTarget, setNewTarget] = useState("");

  const handleTargetChange = (value: string) => {
    dispatch({ type: "SET_TARGET_URL", url: value });
  };

  const handleRunModeChange = (mode: RunMode) => {
    dispatch({ type: "SET_CONFIG", config: { runMode: mode } });
  };

  const handleTargetModeChange = (mode: TargetMode) => {
    dispatch({ type: "SET_CONFIG", config: { targetMode: mode } });
  };

  const addTarget = () => {
    const value = newTarget.trim();
    if (!value) {
      return;
    }
    const currentTargets = state.config.targetUrls || [];
    if (!currentTargets.includes(value)) {
      dispatch({
        type: "SET_CONFIG",
        config: { targetUrls: [...currentTargets, value] },
      });
    }
    setNewTarget("");
  };

  const removeTarget = (url: string) => {
    const currentTargets = state.config.targetUrls || [];
    dispatch({
      type: "SET_CONFIG",
      config: { targetUrls: currentTargets.filter((item) => item !== url) },
    });
  };

  const formatModelName = (name: string) => {
    if (!name) {
      return "未配置";
    }
    const parts = name.split("/");
    return parts[parts.length - 1] || name;
  };

  const mainModelName = state.config.llmModelName || "未配置";
  const advisorModelName = state.config.advisorModelName || "未配置";
  const isMultipleMode = state.config.targetMode === "multiple";
  const isPentestMode = state.config.runMode === "pentest";

  return (
    <div className="card space-y-6 p-6">
      <div>
        <h2 className="mb-4 flex items-center gap-2 text-lg font-medium text-gray-900 dark:text-white">
          <Settings className="h-5 w-5 text-sky-500" />
          运行模式
        </h2>
        <div className="grid grid-cols-2 gap-3">
          <button
            type="button"
            onClick={() => handleRunModeChange("ctf")}
            disabled={session?.isRunning}
            className={`relative rounded-xl border-2 p-4 text-left transition-all ${
              state.config.runMode === "ctf"
                ? "border-amber-500 bg-amber-50 dark:bg-amber-900/20"
                : "border-gray-200 hover:border-amber-300 dark:border-gray-700 dark:hover:border-amber-700"
            } ${session?.isRunning ? "cursor-not-allowed opacity-50" : "cursor-pointer"}`}
          >
            <div className="flex items-center gap-3">
              <div
                className={`rounded-lg p-2 ${
                  state.config.runMode === "ctf"
                    ? "bg-amber-500 text-white"
                    : "bg-amber-100 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400"
                }`}
              >
                <Flag className="h-5 w-5" />
              </div>
              <div>
                <p className="font-semibold text-gray-900 dark:text-white">CTF 模式</p>
                <p className="text-xs text-gray-500 dark:text-gray-400">面向夺旗竞赛和题目求解</p>
              </div>
            </div>
            {state.config.runMode === "ctf" && (
              <div className="absolute right-2 top-2 h-2 w-2 rounded-full bg-amber-500" />
            )}
          </button>

          <button
            type="button"
            onClick={() => handleRunModeChange("pentest")}
            disabled={session?.isRunning}
            className={`relative rounded-xl border-2 p-4 text-left transition-all ${
              state.config.runMode === "pentest"
                ? "border-sky-500 bg-sky-50 dark:bg-sky-900/20"
                : "border-gray-200 hover:border-sky-300 dark:border-gray-700 dark:hover:border-sky-700"
            } ${session?.isRunning ? "cursor-not-allowed opacity-50" : "cursor-pointer"}`}
          >
            <div className="flex items-center gap-3">
              <div
                className={`rounded-lg p-2 ${
                  state.config.runMode === "pentest"
                    ? "bg-sky-500 text-white"
                    : "bg-sky-100 text-sky-600 dark:bg-sky-900/30 dark:text-sky-400"
                }`}
              >
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <p className="font-semibold text-gray-900 dark:text-white">渗透测试</p>
                <p className="text-xs text-gray-500 dark:text-gray-400">面向漏洞检测与安全评估</p>
              </div>
            </div>
            {state.config.runMode === "pentest" && (
              <div className="absolute right-2 top-2 h-2 w-2 rounded-full bg-sky-500" />
            )}
          </button>
        </div>
      </div>

      {isPentestMode && (
        <div>
          <p className="mb-3 text-sm font-medium text-gray-700 dark:text-gray-300">目标模式</p>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => handleTargetModeChange("single")}
              disabled={session?.isRunning}
              className={`flex-1 rounded-lg px-4 py-2 text-sm font-medium transition-all ${
                state.config.targetMode === "single"
                  ? "bg-sky-500 text-white"
                  : "bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700"
              } ${session?.isRunning ? "cursor-not-allowed opacity-50" : ""}`}
            >
              单目标
            </button>
            <button
              type="button"
              onClick={() => handleTargetModeChange("multiple")}
              disabled={session?.isRunning}
              className={`flex-1 rounded-lg px-4 py-2 text-sm font-medium transition-all ${
                state.config.targetMode === "multiple"
                  ? "bg-sky-500 text-white"
                  : "bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700"
              } ${session?.isRunning ? "cursor-not-allowed opacity-50" : ""}`}
            >
              多目标
            </button>
          </div>
        </div>
      )}

      <div>
        <p className="mb-3 text-sm font-medium text-gray-700 dark:text-gray-300">
          {isMultipleMode && isPentestMode ? "目标列表" : "目标地址"}
        </p>

        {(!isMultipleMode || !isPentestMode) && (
          <input
            type="text"
            value={session?.targetUrl || ""}
            onChange={(event) => handleTargetChange(event.target.value)}
            placeholder={
              state.config.runMode === "ctf"
                ? "输入 CTF 靶场地址，例如 http://ctf.example.com"
                : "输入目标地址，例如 http://example.com 或 IP"
            }
            className="input-field"
            disabled={session?.isRunning || false}
          />
        )}

        {isMultipleMode && isPentestMode && (
          <div className="space-y-3">
            <div className="flex gap-2">
              <input
                type="text"
                value={newTarget}
                onChange={(event) => setNewTarget(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    event.preventDefault();
                    addTarget();
                  }
                }}
                placeholder="输入目标地址后按回车或点击添加"
                className="input-field flex-1"
                disabled={session?.isRunning || false}
              />
              <button
                type="button"
                onClick={addTarget}
                disabled={!newTarget.trim() || session?.isRunning}
                className="rounded-lg bg-sky-500 px-4 py-2 text-white transition-colors hover:bg-sky-600 disabled:cursor-not-allowed disabled:opacity-50"
                aria-label="添加目标"
              >
                <Plus className="h-5 w-5" />
              </button>
            </div>

            {(state.config.targetUrls || []).length > 0 ? (
              <div className="max-h-48 space-y-2 overflow-auto">
                {(state.config.targetUrls || []).map((url, index) => (
                  <div
                    key={`${url}-${index}`}
                    className="flex items-center justify-between rounded-lg bg-gray-50 px-3 py-2 dark:bg-gray-800"
                  >
                    <div className="min-w-0 flex items-center gap-2">
                      <Server className="h-4 w-4 flex-shrink-0 text-sky-500" />
                      <span className="truncate text-sm text-gray-700 dark:text-gray-300">{url}</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => removeTarget(url)}
                      disabled={session?.isRunning}
                      className="rounded p-1 text-red-500 hover:bg-red-50 disabled:opacity-50 dark:hover:bg-red-900/20"
                      aria-label={`移除目标 ${url}`}
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-6 text-center text-sm text-gray-500 dark:text-gray-400">
                暂无目标，请先添加目标地址
              </div>
            )}

            <p className="text-xs text-gray-500">已添加 {(state.config.targetUrls || []).length} 个目标</p>
          </div>
        )}
      </div>

      <div className="border-t border-gray-200 pt-4 dark:border-gray-700">
        <div className="mb-3 flex items-center gap-2">
          <Cpu className="h-4 w-4 text-sky-500" />
          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
            {state.config.runMode === "ctf" ? "CTF 求解 AI 引擎" : "渗透测试 AI 引擎"}
          </span>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="flex items-center gap-2 rounded-lg border border-sky-200 bg-gradient-to-r from-sky-50 to-cyan-50 px-3 py-2 dark:border-sky-800 dark:from-sky-900/20 dark:to-cyan-900/20">
            <div className="rounded-md bg-sky-500 p-1.5">
              <Bot className="h-3.5 w-3.5 text-white" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-xs text-gray-500 dark:text-gray-400">主模型</p>
              <p className="truncate text-sm font-medium text-gray-900 dark:text-white" title={mainModelName}>
                {formatModelName(mainModelName)}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 rounded-lg border border-purple-200 bg-gradient-to-r from-purple-50 to-pink-50 px-3 py-2 dark:border-purple-800 dark:from-purple-900/20 dark:to-pink-900/20">
            <div className="rounded-md bg-purple-500 p-1.5">
              <Bot className="h-3.5 w-3.5 text-white" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-xs text-gray-500 dark:text-gray-400">顾问模型</p>
              <p className="truncate text-sm font-medium text-gray-900 dark:text-white" title={advisorModelName}>
                {formatModelName(advisorModelName)}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
