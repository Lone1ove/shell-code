import { ChildProcess, spawn } from "child_process";
import { readFile, readdir, stat } from "fs/promises";
import path from "path";
import { AgentConfig } from "./types";

interface AgentProcessState {
  process: ChildProcess;
  config: AgentConfig;
  startTime: number;
}

export interface ReportFile {
  filename: string;
  content: string;
  mtime: Date;
}

const AGENT_PROCESS_KEY = "__shell_agent_process__";

function getProjectRoot(): string {
  return path.resolve(process.cwd(), "..");
}

function getReportsDir(): string {
  return path.join(getProjectRoot(), "reports");
}

function getRunningProcess(): AgentProcessState | null {
  return (globalThis as typeof globalThis & {
    [AGENT_PROCESS_KEY]?: AgentProcessState | null;
  })[AGENT_PROCESS_KEY] ?? null;
}

function setRunningProcess(state: AgentProcessState | null): void {
  (globalThis as typeof globalThis & {
    [AGENT_PROCESS_KEY]?: AgentProcessState | null;
  })[AGENT_PROCESS_KEY] = state;
}

function buildEnvironment(config: AgentConfig): NodeJS.ProcessEnv {
  const isCtfMode = config.runMode === "ctf";

  return {
    ...process.env,
    ENV_MODE: isCtfMode ? "ctf" : "pentest",
    OBJECTIVE_MODE: isCtfMode ? "flag" : "hybrid",
    ...(config.llmProvider ? { LLM_PROVIDER: config.llmProvider } : {}),
    ...(config.llmBaseUrl ? { LLM_BASE_URL: config.llmBaseUrl } : {}),
    ...(config.llmApiKey?.trim() ? { LLM_API_KEY: config.llmApiKey } : {}),
    ...(config.llmModelName ? { LLM_MODEL_NAME: config.llmModelName } : {}),
    ...(config.advisorProvider ? { ADVISOR_PROVIDER: config.advisorProvider } : {}),
    ...(config.advisorBaseUrl ? { ADVISOR_BASE_URL: config.advisorBaseUrl } : {}),
    ...(config.advisorApiKey?.trim() ? { ADVISOR_API_KEY: config.advisorApiKey } : {}),
    ...(config.advisorModelName ? { ADVISOR_MODEL_NAME: config.advisorModelName } : {}),
  };
}

function terminateProcess(processRef: ChildProcess): void {
  if (process.platform === "win32") {
    spawn("taskkill", ["/PID", String(processRef.pid), "/T", "/F"]);
    return;
  }

  processRef.kill("SIGTERM");
}

export function startAgent(
  config: AgentConfig,
  onLog?: (log: string) => void
): { kill: () => void; startTime: number } {
  const projectRoot = getProjectRoot();
  const targets = config.targetUrl.split(/\s+/).filter(Boolean);

  if (targets.length === 0) {
    throw new Error("请先提供目标地址。");
  }

  const modeLabel = config.runMode === "ctf" ? "CTF" : "渗透测试";
  const env = buildEnvironment(config);
  const args = ["run", "main.py", "-t", ...targets];

  onLog?.(`🚀 正在启动 ${modeLabel} Agent...`);
  onLog?.(`🎯 目标: ${targets.join(", ")}`);
  onLog?.(`🧭 模式: ${modeLabel}`);
  onLog?.("");

  const child = spawn("uv", args, {
    cwd: projectRoot,
    env,
    shell: true,
  });

  const processState: AgentProcessState = {
    process: child,
    config,
    startTime: Date.now(),
  };

  setRunningProcess(processState);

  child.stdout?.on("data", (data) => {
    onLog?.(data.toString());
  });

  child.stderr?.on("data", (data) => {
    const text = data.toString();
    if (text.trim()) {
      onLog?.(`[stderr] ${text}`);
    }
  });

  child.on("close", (code) => {
    onLog?.("");
    onLog?.(`🏁 Agent 进程已结束，退出码: ${code}`);
    setRunningProcess(null);
  });

  child.on("error", (error) => {
    onLog?.(`❌ 进程错误: ${error.message}`);
    setRunningProcess(null);
  });

  return {
    kill: () => {
      const running = getRunningProcess();
      if (!running) {
        return;
      }

      onLog?.("");
      onLog?.("🛑 正在停止 Agent...");
      terminateProcess(running.process);
      setRunningProcess(null);
      onLog?.("✅ Agent 已停止。");
    },
    startTime: processState.startTime,
  };
}

export function stopAgent(): boolean {
  const running = getRunningProcess();
  if (!running) {
    return false;
  }

  try {
    terminateProcess(running.process);
    setRunningProcess(null);
    return true;
  } catch {
    return false;
  }
}

export function isAgentRunning(): boolean {
  return getRunningProcess() !== null;
}

export async function getReportsSince(since?: number): Promise<ReportFile[]> {
  const reportsDir = getReportsDir();

  try {
    const files = await readdir(reportsDir);
    const markdownFiles = files.filter((file) => file.endsWith(".md"));

    if (markdownFiles.length === 0) {
      return [];
    }

    const reports = await Promise.all(
      markdownFiles.map(async (file) => {
        const filePath = path.join(reportsDir, file);
        const fileStat = await stat(filePath);
        const content = await readFile(filePath, "utf-8");
        return {
          filename: file,
          content,
          mtime: fileStat.mtime,
          mtimeMs: fileStat.mtimeMs,
        };
      })
    );

    const filtered = typeof since === "number"
      ? reports.filter((report) => report.mtimeMs >= since - 1000)
      : reports;

    return (filtered.length > 0 ? filtered : reports)
      .sort((left, right) => right.mtimeMs - left.mtimeMs)
      .map(({ filename, content, mtime }) => ({ filename, content, mtime }));
  } catch {
    return [];
  }
}

export async function getLatestReport(since?: number): Promise<string | null> {
  const reports = await getReportsSince(since);
  return reports[0]?.content ?? null;
}
