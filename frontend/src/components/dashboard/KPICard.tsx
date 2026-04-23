"use client";

import { LucideIcon } from "lucide-react";

interface KPICardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: "up" | "down" | "neutral";
}

export function KPICard({ title, value, subtitle, icon: Icon, trend }: KPICardProps) {
  const trendColors = {
    up: "text-cyan-500",
    down: "text-rose-500",
    neutral: "text-gray-400",
  };

  return (
    <div className="card p-6 hover:shadow-md hover:border-cyan-200 dark:hover:border-cyan-700 transition-all duration-200">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm text-gray-500 dark:text-gray-400">{title}</p>
          <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
            {value}
          </p>
          {subtitle && (
            <p className={`text-xs mt-1 ${trend ? trendColors[trend] : "text-gray-400 dark:text-gray-500"}`}>
              {subtitle}
            </p>
          )}
        </div>
        <div className="p-3 bg-cyan-50 dark:bg-cyan-900/30 rounded-lg">
          <Icon className="w-6 h-6 text-cyan-500" />
        </div>
      </div>
    </div>
  );
}
