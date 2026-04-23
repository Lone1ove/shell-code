"use client";

import React, { createContext, useContext, useReducer, ReactNode } from "react";
import { AppAction, AppState, Session } from "@/types";
import { AgentConfig } from "@/app/api/types";

const initialConfig: AgentConfig = {
  targetUrl: "",
  targetUrls: [],
  runMode: "pentest",
  targetMode: "single",
  llmProvider: "GLM",
  llmBaseUrl: "https://api.siliconflow.cn/v1",
  llmApiKey: "",
  llmModelName: "Pro/zai-org/GLM-4.7",
  advisorProvider: "MiniMax",
  advisorBaseUrl: "https://api.siliconflow.cn/v1",
  advisorApiKey: "",
  advisorModelName: "Pro/MiniMaxAI/MiniMax-M2.5",
};

function createSession(id: string): Session {
  return {
    id,
    targetUrl: "",
    logs: [],
    report: "",
    reports: [],
    isRunning: false,
    currentPhase: "idle",
    error: "",
  };
}

export const initialState: AppState = {
  currentView: "workspace",
  isDark: false,
  config: initialConfig,
  viewRecord: null,
  viewReport: "",
  compareA: null,
  compareB: null,
  compareMode: false,
  historyRecords: [],
  isHistoryOpen: false,
  toasts: [],
  sessions: [createSession("session_1")],
  activeSessionId: "session_1",
};

export function appReducer(state: AppState, action: AppAction): AppState {
  switch (action.type) {
    case "SET_VIEW":
      return { ...state, currentView: action.view };

    case "TOGGLE_DARK":
      return { ...state, isDark: !state.isDark };

    case "SET_DARK":
      return { ...state, isDark: action.value };

    case "SET_CONFIG":
      return { ...state, config: { ...state.config, ...action.config } };

    case "SET_VIEW_RECORD":
      return { ...state, viewRecord: action.record, viewReport: action.report || "" };

    case "SET_COMPARE":
      return { ...state, compareA: action.a, compareB: action.b };

    case "TOGGLE_COMPARE_MODE":
      return {
        ...state,
        compareMode: !state.compareMode,
        compareA: state.compareMode ? null : state.compareA,
        compareB: state.compareMode ? null : state.compareB,
      };

    case "SET_HISTORY_RECORDS":
      return { ...state, historyRecords: action.records };

    case "SET_HISTORY_OPEN":
      return { ...state, isHistoryOpen: action.open };

    case "ADD_TOAST":
      return { ...state, toasts: [...state.toasts, action.toast] };

    case "REMOVE_TOAST":
      return {
        ...state,
        toasts: state.toasts.filter((item) => item.id !== action.id),
      };

    case "ADD_SESSION": {
      const newId = `session_${Date.now()}`;
      return {
        ...state,
        sessions: [...state.sessions, createSession(newId)],
        activeSessionId: newId,
      };
    }

    case "REMOVE_SESSION": {
      const newSessions = state.sessions.filter((session) => session.id !== action.id);
      if (newSessions.length === 0) {
        const newSession = createSession(`session_${Date.now()}`);
        return {
          ...state,
          sessions: [newSession],
          activeSessionId: newSession.id,
        };
      }

      const newActiveId =
        state.activeSessionId === action.id ? newSessions[0].id : state.activeSessionId;

      return {
        ...state,
        sessions: newSessions,
        activeSessionId: newActiveId,
      };
    }

    case "SET_ACTIVE_SESSION":
      return { ...state, activeSessionId: action.id };

    case "UPDATE_SESSION":
      return {
        ...state,
        sessions: state.sessions.map((session) =>
          session.id === action.id ? { ...session, ...action.updates } : session,
        ),
      };

    case "SET_SESSION_RUNNING":
      return {
        ...state,
        sessions: state.sessions.map((session) =>
          session.id === action.id ? { ...session, isRunning: action.isRunning } : session,
        ),
      };

    case "SET_SESSION_REPORT":
      return {
        ...state,
        sessions: state.sessions.map((session) =>
          session.id === action.id ? { ...session, report: action.report } : session,
        ),
      };

    case "SET_SESSION_REPORTS":
      return {
        ...state,
        sessions: state.sessions.map((session) =>
          session.id === action.id
            ? {
                ...session,
                reports: action.reports,
                report: action.reports[0]?.content || session.report,
              }
            : session,
        ),
      };

    case "APPEND_SESSION_LOGS":
      return {
        ...state,
        sessions: state.sessions.map((session) =>
          session.id === action.id
            ? { ...session, logs: [...session.logs, ...action.logs] }
            : session,
        ),
      };

    case "CLEAR_SESSION_LOGS":
      return {
        ...state,
        sessions: state.sessions.map((session) =>
          session.id === action.id ? { ...session, logs: [] } : session,
        ),
      };

    case "SET_SESSION_ERROR":
      return {
        ...state,
        sessions: state.sessions.map((session) =>
          session.id === action.id ? { ...session, error: action.error } : session,
        ),
      };

    case "SET_SESSION_PHASE":
      return {
        ...state,
        sessions: state.sessions.map((session) =>
          session.id === action.id ? { ...session, currentPhase: action.phase } : session,
        ),
      };

    case "SET_TARGET_URL":
      return {
        ...state,
        sessions: state.sessions.map((session) =>
          session.id === state.activeSessionId ? { ...session, targetUrl: action.url } : session,
        ),
      };

    default:
      return state;
  }
}

interface AppContextType {
  state: AppState;
  dispatch: React.Dispatch<AppAction>;
  activeSession: Session | undefined;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

interface AppProviderProps {
  children: ReactNode;
}

export function AppProvider({ children }: AppProviderProps) {
  const [state, dispatch] = useReducer(appReducer, initialState);
  const activeSession = state.sessions.find((session) => session.id === state.activeSessionId);

  return (
    <AppContext.Provider value={{ state, dispatch, activeSession }}>
      {children}
    </AppContext.Provider>
  );
}

export function useAppStore() {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error("useAppStore must be used within AppProvider");
  }
  return context;
}

export function useActiveSession() {
  const { state } = useAppStore();
  const session = state.sessions.find((item) => item.id === state.activeSessionId);
  return { session, activeSessionId: state.activeSessionId };
}
