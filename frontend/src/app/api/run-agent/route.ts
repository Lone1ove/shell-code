import { NextRequest, NextResponse } from "next/server";
import { AgentConfig } from "../types";
import {
  getReportsSince,
  isAgentRunning,
  startAgent,
  stopAgent,
} from "../agent-process";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  try {
    const config = (await request.json()) as AgentConfig;

    if (!config.targetUrl?.trim()) {
      return NextResponse.json({ error: "请先提供目标地址。" }, { status: 400 });
    }

    const encoder = new TextEncoder();
    let logs = "";
    let lastSentLength = 0;

    const { startTime } = startAgent(config, (log) => {
      logs += log;
    });

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const send = (payload: unknown) => {
          controller.enqueue(
            encoder.encode(`data: ${JSON.stringify(payload)}\n\n`)
          );
        };

        send({ type: "start", message: "Agent 已启动。" });

        const logInterval = setInterval(() => {
          if (logs.length <= lastSentLength) {
            return;
          }

          const nextChunk = logs.slice(lastSentLength);
          lastSentLength = logs.length;
          send({ type: "log", content: nextChunk });
        }, 300);

        const finishInterval = setInterval(async () => {
          if (isAgentRunning()) {
            return;
          }

          clearInterval(logInterval);
          clearInterval(finishInterval);

          if (logs.length > lastSentLength) {
            send({ type: "log", content: logs.slice(lastSentLength) });
          }

          send({ type: "end" });

          const reports = await getReportsSince(startTime);
          if (reports.length > 0) {
            send({
              type: "reports",
              reports: reports.map((report) => ({
                filename: report.filename,
                content: report.content,
              })),
            });
            send({ type: "report", content: reports[0].content });
          } else {
            send({ type: "error", message: "未找到本次运行生成的报告。" });
          }

          controller.close();
        }, 500);
      },
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive",
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Agent 执行失败。";
    console.error("Agent execution error:", error);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function DELETE() {
  if (!stopAgent()) {
    return NextResponse.json(
      { error: "当前没有正在运行的 Agent。" },
      { status: 404 }
    );
  }

  return NextResponse.json({ message: "Agent 已停止。" });
}
