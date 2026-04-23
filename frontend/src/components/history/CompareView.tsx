"use client";

import { useEffect, useState } from "react";
import { ArrowLeft } from "lucide-react";
import { ScanRecord, getReportById } from "@/app/api/history-service";
import { MarkdownRenderer } from "@/components/ui/MarkdownRenderer";

interface CompareViewProps {
  recordA: ScanRecord;
  recordB: ScanRecord;
  onExit: () => void;
}

export function CompareView({ recordA, recordB, onExit }: CompareViewProps) {
  const [reportA, setReportA] = useState("");
  const [reportB, setReportB] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadReports() {
      try {
        const [a, b] = await Promise.all([
          getReportById(recordA.id),
          getReportById(recordB.id),
        ]);
        setReportA(a);
        setReportB(b);
      } catch (err) {
        console.error("Failed to load reports:", err);
      } finally {
        setLoading(false);
      }
    }
    loadReports();
  }, [recordA.id, recordB.id]);

  if (loading) {
    return (
      <div className="p-8 text-center">
        <div className="animate-pulse">
          <div className="h-4 w-32 mx-auto bg-gray-200 dark:bg-gray-700 rounded mb-4"></div>
          <p className="text-gray-500 dark:text-gray-400">加载中...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center gap-4 mb-4">
        <button
          onClick={onExit}
          className="flex items-center gap-1.5 text-sm text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-white"
        >
          <ArrowLeft className="w-4 h-4" />
          返回
        </button>
        <h2 className="text-lg font-medium text-gray-900 dark:text-white">
          报告对比
        </h2>
      </div>

      {/* A/B Split */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-gray-200 dark:divide-gray-700 overflow-hidden">
        {/* Report A */}
        <div className="flex flex-col overflow-hidden">
          <div className="sticky top-0 z-10 bg-gray-100 dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-4 py-3">
            <p className="text-xs font-medium text-gray-500 dark:text-gray-400 truncate">
              📋 报告 A：{recordA.targetUrl}
            </p>
            <p className="text-xs text-gray-400 dark:text-gray-500">
              {new Date(recordA.timestamp).toLocaleString("zh-CN")}
              {recordA.duration && ` · ${recordA.duration}秒`}
            </p>
          </div>
          <div className="flex-1 overflow-auto p-4">
            {reportA ? (
              <MarkdownRenderer content={reportA} />
            ) : (
              <p className="text-gray-400 dark:text-gray-500">报告为空</p>
            )}
          </div>
        </div>

        {/* Report B */}
        <div className="flex flex-col overflow-hidden">
          <div className="sticky top-0 z-10 bg-gray-100 dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-4 py-3">
            <p className="text-xs font-medium text-gray-500 dark:text-gray-400 truncate">
              📋 报告 B：{recordB.targetUrl}
            </p>
            <p className="text-xs text-gray-400 dark:text-gray-500">
              {new Date(recordB.timestamp).toLocaleString("zh-CN")}
              {recordB.duration && ` · ${recordB.duration}秒`}
            </p>
          </div>
          <div className="flex-1 overflow-auto p-4">
            {reportB ? (
              <MarkdownRenderer content={reportB} />
            ) : (
              <p className="text-gray-400 dark:text-gray-500">报告为空</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
