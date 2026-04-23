"use client";

import { Menu, Moon, Shield, Sun } from "lucide-react";
import { useAppStore } from "@/hooks/useAppStore";
import { useTheme } from "@/hooks/useTheme";

interface HeaderProps {
  onMenuClick: () => void;
}

const VIEW_TITLES: Record<string, string> = {
  dashboard: "仪表盘",
  workspace: "工作区",
  history: "历史记录",
  settings: "系统设置",
  skills: "技能配置",
  rag: "知识库",
  tools: "工具管理",
  cve: "CVE 情报",
};

export function Header({ onMenuClick }: HeaderProps) {
  const { state } = useAppStore();
  const { isDark, toggleDark } = useTheme();
  const title = VIEW_TITLES[state.currentView] || "工作区";

  return (
    <header className="sticky top-0 z-10 flex h-16 items-center justify-between border-b border-gray-200 bg-white px-4 dark:border-gray-700 dark:bg-gray-800 lg:px-6">
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onMenuClick}
          className="rounded-lg p-2 hover:bg-gray-100 dark:hover:bg-gray-700 lg:hidden"
          aria-label="打开导航菜单"
        >
          <Menu className="h-5 w-5 text-gray-600 dark:text-gray-300" />
        </button>

        <div className="flex items-center gap-2">
          <div className="rounded-lg bg-gradient-to-br from-cyan-500 to-sky-600 p-1.5 shadow-md shadow-cyan-500/20">
            <Shield className="h-5 w-5 text-white" />
          </div>
          <h1 className="hidden text-lg font-semibold text-gray-900 dark:text-white sm:block">
            {title}
          </h1>
        </div>
      </div>

      <button
        type="button"
        onClick={toggleDark}
        className="rounded-lg p-2 transition-colors hover:bg-gray-100 dark:hover:bg-gray-700"
        title={isDark ? "切换到浅色模式" : "切换到深色模式"}
        aria-label={isDark ? "切换到浅色模式" : "切换到深色模式"}
      >
        {isDark ? (
          <Sun className="h-5 w-5 text-gray-600 dark:text-gray-300" />
        ) : (
          <Moon className="h-5 w-5 text-gray-600 dark:text-gray-300" />
        )}
      </button>
    </header>
  );
}
