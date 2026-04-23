"use client";

import { Phase } from "@/app/api/types";

const PHASE_KEYWORDS: Record<Phase, (string | RegExp)[]> = {
  idle: [],
  collecting: [
    "信息收集",
    "收集",
    "收集中",
    "扫描",
    "开始扫描",
    "subdomain",
    "subdomains",
    "whois",
    " reconnaissance",
    "recon",
    "collecting",
    "收集目标",
    "端口扫描",
  ],
  scanning: [
    "漏洞扫描",
    "漏洞",
    "扫描中",
    "nuclei",
    "xray",
    "awvs",
    "扫描漏洞",
    "漏洞检测",
    "poc",
    "scanning",
    "vulnerability",
    "vulnerabilities",
  ],
  verifying: [
    "漏洞验证",
    "验证",
    "验证中",
    "验证漏洞",
    "exp",
    "exploit",
    "验证结果",
    "verifying",
    "verify",
  ],
  reporting: [
    "报告",
    "报告生成",
    "生成报告",
    "markdown",
    "总结",
    "完成",
    "reporting",
    "report",
  ],
};

export function detectPhase(logText: string): Phase | null {
  const lower = logText.toLowerCase();

  // 按顺序检查，后面的阶段优先级更高
  const phaseOrder: Phase[] = ["collecting", "scanning", "verifying", "reporting"];

  for (const phase of phaseOrder) {
    const keywords = PHASE_KEYWORDS[phase];
    for (const kw of keywords) {
      if (typeof kw === "string") {
        if (lower.includes(kw.toLowerCase())) return phase;
      } else {
        if (kw.test(lower)) return phase;
      }
    }
  }

  return null;
}
