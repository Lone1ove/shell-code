import { AgentConfig, Phase } from "@/app/api/types";
import { ScanRecord } from "@/app/api/history-service";

export type View =
  | "dashboard"
  | "workspace"
  | "history"
  | "settings"
  | "skills"
  | "rag"
  | "tools"
  | "cve";

export interface Skill {
  key: string;
  name: string;
  source: string;
  path: string;
  keywords: string[];
  description?: string;
  content?: string;
}

export interface RAGDocument {
  id: string;
  name: string;
  type: string;
  size: number;
  uploadedAt: string;
  chunks?: number;
}

export interface RAGConfig {
  enabled: boolean;
  documentsCount: number;
  totalChunks: number;
  lastUpdated?: string;
}

export interface PentestTool {
  name: string;
  description: string;
  category: string;
  usage?: string;
  installed: boolean;
}

export interface MCPTool {
  id: string;
  name: string;
  description: string;
  serverUrl: string;
  enabled: boolean;
  addedAt: string;
}

export interface CVERecord {
  cve_id: string;
  source: string;
  description: string;
  severity: string;
  cvss?: number;
  product_family: string;
  protocols: string[];
  prerequisites: string[];
  poc_available: boolean;
  references: string[];
  updated_at: string;
}

export type ToastType = "success" | "error" | "info";

export interface ToastItem {
  id: number;
  message: string;
  type: ToastType;
}

export interface ReportForTarget {
  filename: string;
  content: string;
}

export interface Session {
  id: string;
  targetUrl: string;
  logs: string[];
  report: string;
  reports: ReportForTarget[];
  isRunning: boolean;
  currentPhase: Phase;
  error: string;
}

export interface AppState {
  currentView: View;
  isDark: boolean;
  config: AgentConfig;
  viewRecord: ScanRecord | null;
  viewReport: string;
  compareA: ScanRecord | null;
  compareB: ScanRecord | null;
  compareMode: boolean;
  historyRecords: ScanRecord[];
  isHistoryOpen: boolean;
  toasts: ToastItem[];
  sessions: Session[];
  activeSessionId: string;
}

export type AppAction =
  | { type: "SET_VIEW"; view: View }
  | { type: "TOGGLE_DARK" }
  | { type: "SET_DARK"; value: boolean }
  | { type: "SET_CONFIG"; config: Partial<AgentConfig> }
  | { type: "SET_VIEW_RECORD"; record: ScanRecord | null; report?: string }
  | { type: "SET_COMPARE"; a: ScanRecord | null; b: ScanRecord | null }
  | { type: "TOGGLE_COMPARE_MODE" }
  | { type: "SET_HISTORY_RECORDS"; records: ScanRecord[] }
  | { type: "SET_HISTORY_OPEN"; open: boolean }
  | { type: "ADD_TOAST"; toast: ToastItem }
  | { type: "REMOVE_TOAST"; id: number }
  | { type: "ADD_SESSION" }
  | { type: "REMOVE_SESSION"; id: string }
  | { type: "SET_ACTIVE_SESSION"; id: string }
  | { type: "UPDATE_SESSION"; id: string; updates: Partial<Session> }
  | { type: "SET_SESSION_RUNNING"; id: string; isRunning: boolean }
  | { type: "SET_SESSION_REPORT"; id: string; report: string }
  | { type: "SET_SESSION_REPORTS"; id: string; reports: ReportForTarget[] }
  | { type: "APPEND_SESSION_LOGS"; id: string; logs: string[] }
  | { type: "CLEAR_SESSION_LOGS"; id: string }
  | { type: "SET_SESSION_ERROR"; id: string; error: string }
  | { type: "SET_SESSION_PHASE"; id: string; phase: Phase }
  | { type: "SET_TARGET_URL"; url: string };
