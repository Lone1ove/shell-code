"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";

interface ScanTrendData {
  date: string;
  count: number;
}

interface ModelUsageData {
  name: string;
  value: number;
}

const COLORS = ["#38bdf8", "#818cf8", "#fbbf24", "#34d399", "#f87171", "#a78bfa"];

interface ScanTrendChartProps {
  data: ScanTrendData[];
}

export function ScanTrendChart({ data }: ScanTrendChartProps) {
  return (
    <div className="card p-6">
      <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
        扫描趋势（近7天）
      </h3>
      <div className="h-[300px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <CartesianGrid strokeDasharray="3 3" className="stroke-gray-200 dark:stroke-gray-700" />
            <XAxis
              dataKey="date"
              className="text-xs fill-gray-500 dark:fill-gray-400"
            />
            <YAxis className="text-xs fill-gray-500 dark:fill-gray-400" />
            <Tooltip
              wrapperClassName="dark:[&_.recharts-tooltip-wrapper]:bg-gray-800 dark:[&_.recharts-tooltip-wrapper]:border-gray-700"
            />
            <Bar dataKey="count" fill="#38bdf8" name="扫描次数" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

interface ModelUsageChartProps {
  data: ModelUsageData[];
}

export function ModelUsageChart({ data }: ModelUsageChartProps) {
  const total = data.reduce((sum, item) => sum + item.value, 0);

  return (
    <div className="card p-6">
      <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
        模型使用统计
      </h3>
      <div className="h-[300px] flex items-center justify-center">
        {data.length === 0 ? (
          <p className="text-gray-400 dark:text-gray-500">暂无数据</p>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={100}
                paddingAngle={2}
                dataKey="value"
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                labelLine={false}
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                wrapperClassName="dark:[&_.recharts-tooltip-wrapper]:bg-gray-800 dark:[&_.recharts-tooltip-wrapper]:border-gray-700"
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>
      {total > 0 && (
        <p className="text-center text-sm text-gray-500 dark:text-gray-400 mt-2">
          总计: {total} 次扫描
        </p>
      )}
    </div>
  );
}
