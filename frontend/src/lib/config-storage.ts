"use client";

import { AgentConfig } from "@/app/api/types";

const CONFIG_LS_KEY = "pentest-agent-config";

// 默认配置（从 .env 文件中提取）
export const DEFAULT_CONFIG: StoredConfig = {
  llmProvider: "GLM",
  llmBaseUrl: "https://api.siliconflow.cn/v1",
  llmApiKey: "",
  llmModelName: "Pro/zai-org/GLM-4.7",
  advisorProvider: "MiniMax",
  advisorBaseUrl: "https://api.siliconflow.cn/v1",
  advisorApiKey: "",
  advisorModelName: "Pro/MiniMaxAI/MiniMax-M2.5",
};

export interface StoredConfig {
  llmProvider: string;
  llmBaseUrl: string;
  llmApiKey: string;
  llmModelName: string;
  advisorProvider: string;
  advisorBaseUrl: string;
  advisorApiKey: string;
  advisorModelName: string;
}

export function loadConfig(): Partial<StoredConfig> {
  try {
    const saved = localStorage.getItem(CONFIG_LS_KEY);
    if (saved) {
      return JSON.parse(saved);
    }
  } catch {
    // ignore parse errors
  }
  return {};
}

export function saveConfig(config: Partial<StoredConfig>): void {
  try {
    const existing = loadConfig();
    const merged = { ...existing, ...config };
    localStorage.setItem(CONFIG_LS_KEY, JSON.stringify(merged));
  } catch {
    // ignore storage errors
  }
}

export function mergeConfig(
  current: AgentConfig,
  saved: Partial<StoredConfig>
): AgentConfig {
  return {
    ...current,
    llmProvider: saved.llmProvider ?? current.llmProvider ?? DEFAULT_CONFIG.llmProvider,
    llmBaseUrl: saved.llmBaseUrl ?? current.llmBaseUrl ?? DEFAULT_CONFIG.llmBaseUrl,
    llmApiKey: saved.llmApiKey ?? current.llmApiKey ?? DEFAULT_CONFIG.llmApiKey,
    llmModelName: saved.llmModelName ?? current.llmModelName ?? DEFAULT_CONFIG.llmModelName,
    advisorProvider: saved.advisorProvider ?? current.advisorProvider ?? DEFAULT_CONFIG.advisorProvider,
    advisorBaseUrl: saved.advisorBaseUrl ?? current.advisorBaseUrl ?? DEFAULT_CONFIG.advisorBaseUrl,
    advisorApiKey: saved.advisorApiKey ?? current.advisorApiKey ?? DEFAULT_CONFIG.advisorApiKey,
    advisorModelName: saved.advisorModelName ?? current.advisorModelName ?? DEFAULT_CONFIG.advisorModelName,
  };
}

// 获取带默认值的配置
export function getConfigWithDefaults(): StoredConfig {
  const saved = loadConfig();
  return {
    llmProvider: saved.llmProvider || DEFAULT_CONFIG.llmProvider,
    llmBaseUrl: saved.llmBaseUrl || DEFAULT_CONFIG.llmBaseUrl,
    llmApiKey: saved.llmApiKey || DEFAULT_CONFIG.llmApiKey,
    llmModelName: saved.llmModelName || DEFAULT_CONFIG.llmModelName,
    advisorProvider: saved.advisorProvider || DEFAULT_CONFIG.advisorProvider,
    advisorBaseUrl: saved.advisorBaseUrl || DEFAULT_CONFIG.advisorBaseUrl,
    advisorApiKey: saved.advisorApiKey || DEFAULT_CONFIG.advisorApiKey,
    advisorModelName: saved.advisorModelName || DEFAULT_CONFIG.advisorModelName,
  };
}
