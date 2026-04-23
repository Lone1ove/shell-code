"use client";

export type RunMode = "ctf" | "pentest";
export type TargetMode = "single" | "multiple";

export interface AgentConfig {
  targetUrl: string;
  targetUrls?: string[];
  runMode: RunMode;
  targetMode: TargetMode;
  llmProvider: string;
  llmBaseUrl: string;
  llmApiKey: string;
  llmModelName: string;
  advisorProvider: string;
  advisorBaseUrl: string;
  advisorApiKey: string;
  advisorModelName: string;
}

export type Phase = "idle" | "collecting" | "scanning" | "verifying" | "reporting";
