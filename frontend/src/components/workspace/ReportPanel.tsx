"use client";

import { useMemo, useState } from "react";
import { Download, Shield } from "lucide-react";
import { useAppStore } from "@/hooks/useAppStore";

function normalizeLabel(filename: string): string {
  const base = filename.replace(/\.md$/i, "");
  const parts = base.split("-");

  if (parts.length <= 1) {
    return base;
  }

  const filtered = parts.filter((part) => !/^\d{8}_\d{6}$/.test(part));
  return filtered.join("-") || base;
}

export function ReportPanel() {
  const { state } = useAppStore();
  const session = state.sessions.find((item) => item.id === state.activeSessionId);
  const isRunning = session?.isRunning || false;
  const reports = session?.reports || [];
  const hasMultipleReports = reports.length > 1;
  const [activeIndex, setActiveIndex] = useState(0);

  const currentReport = useMemo(() => {
    if (reports.length > 0) {
      return reports[Math.min(activeIndex, reports.length - 1)];
    }

    if (session?.report?.trim()) {
      return {
        filename: `report-${new Date().toISOString().slice(0, 10)}.md`,
        content: session.report,
      };
    }

    return null;
  }, [activeIndex, reports, session?.report]);

  const hasReport = !!currentReport?.content?.trim();

  const downloadReport = (filename: string, content: string) => {
    const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadCurrent = () => {
    if (!currentReport) {
      return;
    }

    downloadReport(currentReport.filename, currentReport.content);
  };

  const handleDownloadAll = () => {
    if (reports.length === 0) {
      return;
    }

    reports.forEach((report) => {
      downloadReport(report.filename, report.content);
    });
  };

  return (
    <div className="card p-6 h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-medium text-gray-900 dark:text-white flex items-center gap-2">
          <Shield className="w-5 h-5 text-sky-500" />
          渗透测试报告
          {hasMultipleReports && (
            <span className="text-sm font-normal text-gray-500 dark:text-gray-400">
              ({reports.length} 份)
            </span>
          )}
        </h2>

        <div className="flex items-center gap-2">
          {hasMultipleReports && (
            <button
              onClick={handleDownloadAll}
              disabled={isRunning}
              className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all bg-sky-500 hover:bg-sky-600 text-white disabled:bg-gray-100 dark:disabled:bg-gray-700 disabled:text-gray-400"
            >
              下载全部
            </button>
          )}

          <button
            onClick={handleDownloadCurrent}
            disabled={!hasReport || isRunning}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              hasReport && !isRunning
                ? "bg-sky-500 hover:bg-sky-600 text-white"
                : "bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500 cursor-not-allowed"
            }`}
          >
            <Download className="w-3.5 h-3.5" />
            下载报告
          </button>
        </div>
      </div>

      {hasMultipleReports && (
        <div className="flex gap-1 mb-4 border-b border-gray-200 dark:border-gray-700 overflow-x-auto">
          {reports.map((report, index) => (
            <button
              key={report.filename}
              onClick={() => setActiveIndex(index)}
              className={`px-3 py-1.5 text-sm font-medium transition-colors border-b-2 -mb-px whitespace-nowrap ${
                index === activeIndex
                  ? "border-sky-500 text-sky-600 dark:text-sky-400"
                  : "border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
              }`}
            >
              {normalizeLabel(report.filename)}
            </button>
          ))}
        </div>
      )}

      <div className="flex-1 flex items-center">
        <div className="flex-1">
          {isRunning ? (
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 border-2 border-sky-500 border-t-transparent rounded-full animate-spin" />
              <span className="text-sm text-gray-500 dark:text-gray-400">
                报告生成中，请耐心等待...
              </span>
            </div>
          ) : hasReport ? (
            <span className="text-sm font-medium text-green-600 dark:text-green-400">
              报告已生成，可直接下载。
            </span>
          ) : (
            <span className="text-sm text-gray-400 dark:text-gray-500">
              报告尚未生成，请先运行测试。
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
