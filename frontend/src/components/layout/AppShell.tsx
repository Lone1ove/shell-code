"use client";

import { useState, ReactNode } from "react";
import { AppProvider } from "@/hooks/useAppStore";
import { ToastProvider } from "@/components/ui/ToastProvider";
import { Sidebar } from "./Sidebar";
import { Header } from "./Header";
import { MobileDrawer } from "./MobileDrawer";
import { DashboardView } from "@/components/views/DashboardView";
import { WorkspaceView } from "@/components/views/WorkspaceView";
import { HistoryView } from "@/components/views/HistoryView";
import { SettingsView } from "@/components/views/SettingsView";
import { SkillsView } from "@/components/views/SkillsView";
import { RAGView } from "@/components/views/RAGView";
import { ToolsView } from "@/components/views/ToolsView";
import { CVEView } from "@/components/views/CVEView";
import { useAppStore } from "@/hooks/useAppStore";

interface AppShellProps {
  children?: ReactNode;
}

function ViewRouter() {
  const { state } = useAppStore();

  switch (state.currentView) {
    case "dashboard":
      return <DashboardView />;
    case "workspace":
      return <WorkspaceView />;
    case "history":
      return <HistoryView />;
    case "settings":
      return <SettingsView />;
    case "skills":
      return <SkillsView />;
    case "rag":
      return <RAGView />;
    case "tools":
      return <ToolsView />;
    case "cve":
      return <CVEView />;
    default:
      return <WorkspaceView />;
  }
}

export function AppShell({ children }: AppShellProps) {
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  return (
    <AppProvider>
      <ToastProvider>
        <div className="min-h-screen bg-slate-50 dark:bg-slate-900 flex">
          {/* Desktop Sidebar */}
          <Sidebar />

          {/* Mobile Drawer */}
          <MobileDrawer
            isOpen={isDrawerOpen}
            onClose={() => setIsDrawerOpen(false)}
          />

          {/* Main Content Area */}
          <div className="flex-1 flex flex-col min-w-0 lg:ml-64">
            <Header onMenuClick={() => setIsDrawerOpen(true)} />
            <main className="flex-1 overflow-hidden">
              <ViewRouter />
            </main>
          </div>
        </div>
      </ToastProvider>
    </AppProvider>
  );
}
