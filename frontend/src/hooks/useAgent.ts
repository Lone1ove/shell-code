"use client";

import { useCallback, useRef } from "react";
import { AgentConfig } from "@/app/api/types";
import { saveScanRecord } from "@/app/api/history-service";
import { useToast } from "@/components/ui/ToastProvider";
import { useAppStore } from "./useAppStore";
import { detectPhase } from "@/lib/phase-detector";

type StreamMessage =
  | { type: "start"; message?: string }
  | { type: "log"; content: string }
  | { type: "report"; content: string }
  | { type: "reports"; reports: Array<{ filename: string; content: string }> }
  | { type: "error"; message?: string }
  | { type: "end" };

export function useAgent() {
  const { dispatch } = useAppStore();
  const { showToast } = useToast();
  const stoppedRefs = useRef(new Map<string, boolean>());
  const startTimeRefs = useRef(new Map<string, number>());

  const startAgent = useCallback(
    async (config: AgentConfig, sessionId: string) => {
      if (!config.targetUrl.trim()) {
        showToast("请先输入目标地址。", "error");
        return;
      }

      stoppedRefs.current.set(sessionId, false);
      startTimeRefs.current.set(sessionId, Date.now());
      dispatch({ type: "SET_SESSION_RUNNING", id: sessionId, isRunning: true });
      dispatch({ type: "CLEAR_SESSION_LOGS", id: sessionId });
      dispatch({ type: "SET_SESSION_REPORT", id: sessionId, report: "" });
      dispatch({ type: "SET_SESSION_ERROR", id: sessionId, error: "" });
      dispatch({ type: "SET_SESSION_PHASE", id: sessionId, phase: "collecting" });

      let latestReport = "";
      let latestPhase: ReturnType<typeof detectPhase> | "idle" = "collecting";

      try {
        const response = await fetch("/api/run-agent", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(config),
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const reader = response.body?.getReader();
        if (!reader) {
          throw new Error("无法读取流式响应。");
        }

        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) {
            break;
          }

          buffer += decoder.decode(value, { stream: true });

          while (true) {
            const delimiterIndex = buffer.indexOf("\n\n");
            if (delimiterIndex === -1) {
              break;
            }

            const rawEvent = buffer.slice(0, delimiterIndex);
            buffer = buffer.slice(delimiterIndex + 2);

            for (const line of rawEvent.split("\n")) {
              if (!line.startsWith("data: ")) {
                continue;
              }

              try {
                const data = JSON.parse(line.slice(6)) as StreamMessage;

                if (data.type === "log") {
                  const logLines = data.content.split("\n").filter((entry) => entry.trim());
                  if (logLines.length > 0) {
                    dispatch({
                      type: "APPEND_SESSION_LOGS",
                      id: sessionId,
                      logs: logLines,
                    });
                  }

                  const detectedPhase = detectPhase(data.content);
                  if (detectedPhase && detectedPhase !== "idle") {
                    latestPhase = detectedPhase;
                    dispatch({
                      type: "SET_SESSION_PHASE",
                      id: sessionId,
                      phase: detectedPhase,
                    });
                  }
                }

                if (data.type === "report" && !stoppedRefs.current.get(sessionId)) {
                  latestReport = data.content;
                  latestPhase = "reporting";
                  dispatch({ type: "SET_SESSION_REPORT", id: sessionId, report: data.content });
                  dispatch({ type: "SET_SESSION_PHASE", id: sessionId, phase: "reporting" });
                }

                if (data.type === "reports" && !stoppedRefs.current.get(sessionId)) {
                  if (data.reports.length > 0) {
                    latestReport = data.reports[0].content;
                    latestPhase = "reporting";
                  }
                  dispatch({ type: "SET_SESSION_REPORTS", id: sessionId, reports: data.reports });
                  dispatch({ type: "SET_SESSION_PHASE", id: sessionId, phase: "reporting" });
                }

                if (data.type === "error") {
                  const message = data.message || "未知错误";
                  dispatch({ type: "SET_SESSION_ERROR", id: sessionId, error: message });
                }
              } catch {
                // Ignore malformed SSE lines.
              }
            }
          }
        }

        if (stoppedRefs.current.get(sessionId)) {
          showToast("渗透测试已停止。", "info");
          return;
        }

        const startTime = startTimeRefs.current.get(sessionId);
        const duration = startTime ? Math.round((Date.now() - startTime) / 1000) : undefined;

        await saveScanRecord(
          {
            id: `scan_${Date.now()}`,
            targetUrl: config.targetUrl,
            timestamp: new Date().toISOString(),
            config,
            finalPhase: latestPhase || "idle",
            duration,
          },
          latestReport,
        );

        showToast("扫描完成，报告已生成。", "success");
      } catch (error) {
        const message = error instanceof Error ? error.message : "启动失败";
        dispatch({ type: "SET_SESSION_ERROR", id: sessionId, error: message });
        showToast(message, "error");
      } finally {
        dispatch({ type: "SET_SESSION_RUNNING", id: sessionId, isRunning: false });
        dispatch({ type: "SET_SESSION_PHASE", id: sessionId, phase: "idle" });
        stoppedRefs.current.delete(sessionId);
        startTimeRefs.current.delete(sessionId);
      }
    },
    [dispatch, showToast],
  );

  const stopAgent = useCallback(
    async (sessionId: string) => {
      stoppedRefs.current.set(sessionId, true);

      try {
        await fetch("/api/run-agent", { method: "DELETE" });
        dispatch({
          type: "APPEND_SESSION_LOGS",
          id: sessionId,
          logs: ["🛑 已发送停止信号。"],
        });
        showToast("已发送停止信号。", "info");
      } catch {
        showToast("停止失败。", "error");
      }
    },
    [dispatch, showToast],
  );

  return { startAgent, stopAgent };
}
