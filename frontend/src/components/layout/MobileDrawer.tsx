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
  X,
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

interface MobileDrawerProps {
  isOpen: boolean;
  onClose: () => void;
}

export function MobileDrawer({ isOpen, onClose }: MobileDrawerProps) {
  const { state, dispatch } = useAppStore();

  if (!isOpen) {
    return null;
  }

  const handleNavClick = (view: View) => {
    dispatch({ type: "SET_VIEW", view });
    onClose();
  };

  return (
    <>
      <button
        type="button"
        className="fixed inset-0 z-40 bg-black/30 lg:hidden"
        onClick={onClose}
        aria-label="关闭导航抽屉"
      />

      <aside className="fixed left-0 top-0 z-50 h-full w-72 bg-white shadow-xl dark:bg-gray-800 lg:hidden">
        <div className="flex h-16 items-center justify-between border-b border-gray-200 px-4 dark:border-gray-700">
          <div className="flex items-center gap-2">
            <div className="rounded-lg bg-sky-500 p-1.5">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <span className="font-bold text-gray-900 dark:text-white">Shell-Agent</span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-2 hover:bg-gray-100 dark:hover:bg-gray-700"
            aria-label="关闭导航抽屉"
          >
            <X className="h-5 w-5 text-gray-600 dark:text-gray-300" />
          </button>
        </div>

        <nav className="space-y-1 p-4">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = state.currentView === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => handleNavClick(item.id)}
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
      </aside>
    </>
  );
}
