"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Clock, GitCompare, X } from "lucide-react";
import { useAppStore } from "@/hooks/useAppStore";
import {
  deleteScanRecord,
  getReportById,
  getScanRecords,
  ScanRecord,
} from "@/app/api/history-service";
import { CompareView } from "@/components/history/CompareView";
import { HistoryTable } from "@/components/history/HistoryTable";
import { MarkdownRenderer } from "@/components/ui/MarkdownRenderer";
import { useToast } from "@/components/ui/ToastProvider";

export function HistoryView() {
  const { state, dispatch } = useAppStore();
  const { showToast } = useToast();
  const [loading, setLoading] = useState(true);
  const [viewingRecord, setViewingRecord] = useState<ScanRecord | null>(null);
  const [viewingReport, setViewingReport] = useState("");
  const [reportLoading, setReportLoading] = useState(false);
  const reportRef = useRef<HTMLDivElement>(null);

  const { compareMode, compareA, compareB } = state;

  const loadHistory = useCallback(async () => {
    try {
      const records = await getScanRecords();
      dispatch({ type: "SET_HISTORY_RECORDS", records });
    } catch (error) {
      console.error("Failed to load history:", error);
      showToast("加载历史记录失败", "error");
    } finally {
      setLoading(false);
    }
  }, [dispatch, showToast]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const handleView = async (record: ScanRecord) => {
    if (viewingRecord?.id === record.id) {
      setViewingRecord(null);
      setViewingReport("");
      return;
    }

    setViewingRecord(record);
    setViewingReport("");
    setReportLoading(true);

    try {
      const report = await getReportById(record.id);
      setViewingReport(report);
      setTimeout(() => reportRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
    } catch {
      showToast("加载报告失败", "error");
      setViewingRecord(null);
    } finally {
      setReportLoading(false);
    }
  };

  const handleDownload = async (record: ScanRecord) => {
    try {
      const report = await getReportById(record.id);
      const blob = new Blob([report], { type: "text/markdown;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `report-${record.targetUrl.replace(/[^a-z0-9]/gi, "-")}-${new Date(record.timestamp).toISOString().slice(0, 10)}.md`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      showToast("报告下载成功", "success");
    } catch {
      showToast("下载报告失败", "error");
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("确定要删除这条记录吗？")) {
      return;
    }

    try {
      await deleteScanRecord(id);
      showToast("已删除", "success");
      await loadHistory();
    } catch {
      showToast("删除失败", "error");
    }
  };

  const handleToggleCompare = (record: ScanRecord) => {
    if (!compareA) {
      dispatch({ type: "SET_COMPARE", a: record, b: compareB });
      return;
    }
    if (!compareB || compareB.id === record.id) {
      dispatch({
        type: "SET_COMPARE",
        a: compareA.id === record.id ? null : compareA,
        b: compareB?.id === record.id ? null : record,
      });
      return;
    }
    dispatch({ type: "SET_COMPARE", a: compareA, b: record });
  };

  if (compareA && compareB && !compareMode) {
    return (
      <div className="mx-auto h-[calc(100vh-8rem)] max-w-7xl px-4 py-8 lg:px-6">
        <CompareView
          recordA={compareA}
          recordB={compareB}
          onExit={() => dispatch({ type: "SET_COMPARE", a: null, b: null })}
        />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 lg:px-6">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-bold text-gray-900 dark:text-white">
          <Clock className="h-6 w-6" />
          扫描历史
        </h1>

        <button
          type="button"
          onClick={() => dispatch({ type: "TOGGLE_COMPARE_MODE" })}
          className={`flex items-center gap-2 rounded-lg px-4 py-2 transition-colors ${
            compareMode
              ? "bg-sky-500 text-white"
              : "bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700"
          }`}
        >
          <GitCompare className="h-4 w-4" />
          对比模式
        </button>
      </div>

      {compareMode && (
        <div className="mb-4 rounded-lg border border-sky-200 bg-sky-50 p-4 dark:border-sky-800 dark:bg-sky-900/30">
          <p className="text-sm text-sky-800 dark:text-sky-300">
            {!compareA && !compareB && "点击记录选择第一个报告（A）。"}
            {compareA && !compareB && "已选择报告 A，请选择第二个报告（B）。"}
            {compareA && compareB && "已选择两个报告，可以开始对比。"}
          </p>

          {compareA && compareB && (
            <button
              type="button"
              onClick={() => dispatch({ type: "TOGGLE_COMPARE_MODE" })}
              className="mt-2 rounded-lg bg-sky-500 px-4 py-2 text-sm text-white transition-colors hover:bg-sky-600"
            >
              开始对比
            </button>
          )}

          {(compareA || compareB) && (
            <button
              type="button"
              onClick={() => dispatch({ type: "SET_COMPARE", a: null, b: null })}
              className="ml-2 mt-2 rounded-lg bg-gray-200 px-4 py-2 text-sm text-gray-700 transition-colors hover:bg-gray-300 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-gray-600"
            >
              清空选择
            </button>
          )}
        </div>
      )}

      <div className="card overflow-hidden">
        {loading ? (
          <div className="p-8 text-center">
            <div className="animate-pulse">
              <div className="mx-auto mb-4 h-4 w-32 rounded bg-gray-200 dark:bg-gray-700" />
              <p className="text-gray-500 dark:text-gray-400">加载中...</p>
            </div>
          </div>
        ) : (
          <HistoryTable
            records={state.historyRecords}
            compareMode={compareMode}
            compareA={compareA}
            compareB={compareB}
            onView={handleView}
            onDelete={handleDelete}
            onToggleCompare={handleToggleCompare}
            onDownload={handleDownload}
            viewingId={viewingRecord?.id}
          />
        )}
      </div>

      {viewingRecord && (
        <div ref={reportRef} className="card mt-6 overflow-hidden">
          <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3 dark:border-gray-700">
            <div>
              <h2 className="text-base font-semibold text-gray-900 dark:text-white">报告内容</h2>
              <p className="mt-0.5 break-all text-xs text-gray-500 dark:text-gray-400">
                {viewingRecord.targetUrl} · {new Date(viewingRecord.timestamp).toLocaleString("zh-CN")}
              </p>
            </div>
            <button
              type="button"
              onClick={() => {
                setViewingRecord(null);
                setViewingReport("");
              }}
              className="rounded-lg p-1.5 text-gray-500 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-700"
              title="关闭"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="max-h-[60vh] overflow-y-auto p-4">
            {reportLoading ? (
              <div className="py-8 text-center">
                <div className="mx-auto mb-2 h-6 w-6 animate-spin rounded-full border-2 border-sky-500 border-t-transparent" />
                <p className="text-sm text-gray-500 dark:text-gray-400">加载报告中...</p>
              </div>
            ) : viewingReport ? (
              <MarkdownRenderer content={viewingReport} />
            ) : (
              <p className="py-8 text-center text-sm text-gray-500 dark:text-gray-400">暂无报告内容</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
