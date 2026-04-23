"use client";

import { useEffect, useState } from "react";
import { CheckCircle, Clock, Scan, Shield } from "lucide-react";
import { getScanRecords, ScanRecord } from "@/app/api/history-service";
import { KPICard } from "@/components/dashboard/KPICard";
import { ModelUsageChart, ScanTrendChart } from "@/components/dashboard/Charts";

interface ModelUsageData {
  name: string;
  value: number;
}

interface AggregatedStats {
  totalScans: number;
  avgDuration: number;
  totalDuration: number;
  modelUsage: ModelUsageData[];
  scanTrend: { date: string; count: number }[];
}

function aggregateStats(records: ScanRecord[]): AggregatedStats {
  const totalScans = records.length;
  let totalDuration = 0;
  const modelUsage: Record<string, number> = {};
  const dateCount: Record<string, number> = {};

  for (const record of records) {
    if (record.duration) {
      totalDuration += record.duration;
    }

    const model = record.config.llmModelName || "默认模型";
    modelUsage[model] = (modelUsage[model] || 0) + 1;

    const date = new Date(record.timestamp).toLocaleDateString("zh-CN", {
      month: "short",
      day: "numeric",
    });
    dateCount[date] = (dateCount[date] || 0) + 1;
  }

  const today = new Date();
  const trend: { date: string; count: number }[] = [];
  for (let index = 6; index >= 0; index -= 1) {
    const current = new Date(today);
    current.setDate(current.getDate() - index);
    const dateStr = current.toLocaleDateString("zh-CN", { month: "short", day: "numeric" });
    trend.push({ date: dateStr, count: dateCount[dateStr] || 0 });
  }

  return {
    totalScans,
    avgDuration: totalScans > 0 ? Math.round(totalDuration / totalScans) : 0,
    totalDuration,
    modelUsage: Object.entries(modelUsage).map(([name, value]) => ({ name, value })),
    scanTrend: trend,
  };
}

export function DashboardView() {
  const [stats, setStats] = useState<AggregatedStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadStats() {
      try {
        const records = await getScanRecords();
        setStats(aggregateStats(records));
      } catch (error) {
        console.error("Failed to load stats:", error);
      } finally {
        setLoading(false);
      }
    }

    loadStats();
  }, []);

  if (loading) {
    return (
      <div className="mx-auto max-w-7xl px-4 py-8 lg:px-6">
        <div className="space-y-6 animate-pulse">
          <div className="h-8 w-48 rounded bg-gray-200 dark:bg-gray-700" />
          <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-4">
            {[1, 2, 3, 4].map((item) => (
              <div key={item} className="h-32 rounded-xl bg-gray-200 dark:bg-gray-700" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="mx-auto max-w-7xl px-4 py-8 lg:px-6">
        <p className="text-gray-500 dark:text-gray-400">加载失败</p>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 lg:px-6">
      <h1 className="mb-6 text-2xl font-bold text-gray-900 dark:text-white">仪表盘</h1>

      <div className="mb-8 grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-4">
        <KPICard title="总扫描次数" value={stats.totalScans} icon={Scan} subtitle="所有历史扫描" />
        <KPICard
          title="平均耗时"
          value={stats.avgDuration > 0 ? `${stats.avgDuration} 秒` : "-"}
          icon={Clock}
          subtitle="每次扫描平均"
        />
        <KPICard
          title="总耗时"
          value={stats.totalDuration > 0 ? `${Math.round(stats.totalDuration / 60)} 分钟` : "-"}
          icon={Shield}
          subtitle="累计运行时间"
        />
        <KPICard
          title="完成率"
          value={stats.totalScans > 0 ? "100%" : "-"}
          icon={CheckCircle}
          subtitle="历史任务完成情况"
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <ScanTrendChart data={stats.scanTrend} />
        <ModelUsageChart data={stats.modelUsage} />
      </div>

      {stats.totalScans === 0 && (
        <div className="mt-8 py-12 text-center">
          <Shield className="mx-auto mb-4 h-16 w-16 text-gray-300 dark:text-gray-600" />
          <h3 className="mb-2 text-lg font-medium text-gray-900 dark:text-white">暂无扫描数据</h3>
          <p className="text-gray-500 dark:text-gray-400">开始一次渗透测试后，数据会显示在这里。</p>
        </div>
      )}
    </div>
  );
}
