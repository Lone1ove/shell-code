"use client";

import {
  Bug,
  Database,
  History,
  LayoutDashboard,
  Settings,
  Shield,
  Sparkles,
  Terminal,
  Wrench,
} from "lucide-react";
import { useAppStore } from "@/hooks/useAppStore";
import { View } from "@/types";

const navItems: { id: View; label: string; icon: React.ElementType }[] = [
  { id: "dashboard", label: "仪表盘", icon: LayoutDashboard },
  { id: "workspace", label: "工作区", icon: Terminal },
  { id: "skills", label: "技能配置", icon: Sparkles },
  { id: "rag", label: "知识库", icon: Database },
  { id: "tools", label: "工具管理", icon: Wrench },
  { id: "cve", label: "CVE 情报", icon: Bug },
  { id: "history", label: "历史记录", icon: History },
  { id: "settings", label: "系统设置", icon: Settings },
];

export function Sidebar() {
  const { state, dispatch } = useAppStore();

  return (
    <aside className="fixed hidden h-full w-64 flex-col border-r border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800 lg:flex">
      <div className="border-b border-gray-200 p-6 dark:border-gray-700">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-sky-500 p-2">
            <Shield className="h-6 w-6 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-gray-900 dark:text-white">Shell-Agent</h1>
            <p className="text-xs text-gray-500 dark:text-gray-400">自动化安全测试平台</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 p-4">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = state.currentView === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => dispatch({ type: "SET_VIEW", view: item.id })}
              className={`flex w-full items-center gap-3 rounded-lg px-4 py-3 text-left transition-all ${
                isActive
                  ? "bg-sky-50 text-sky-600 dark:bg-sky-900/30 dark:text-sky-400"
                  : "text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700"
              }`}
            >
              <Icon className="h-5 w-5" />
              <span className="font-medium">{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="border-t border-gray-200 p-4 dark:border-gray-700">
        <p className="text-center text-xs text-gray-400 dark:text-gray-500">v1.0.0 Shell-Agent</p>
      </div>
    </aside>
  );
}
