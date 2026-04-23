"use client";

import { Clock, Download, Eye, Trash2 } from "lucide-react";
import { ScanRecord } from "@/app/api/history-service";

interface HistoryTableProps {
  records: ScanRecord[];
  compareMode: boolean;
  compareA: ScanRecord | null;
  compareB: ScanRecord | null;
  onView: (record: ScanRecord) => void;
  onDelete: (id: string) => void;
  onToggleCompare: (record: ScanRecord) => void;
  onDownload?: (record: ScanRecord) => void;
  viewingId?: string;
}

export function HistoryTable({
  records,
  compareMode,
  compareA,
  compareB,
  onView,
  onDelete,
  onToggleCompare,
  onDownload,
  viewingId,
}: HistoryTableProps) {
  const isSelectedA = (record: ScanRecord) => compareA?.id === record.id;
  const isSelectedB = (record: ScanRecord) => compareB?.id === record.id;

  if (records.length === 0) {
    return (
      <div className="py-12 text-center">
        <Clock className="mx-auto mb-4 h-16 w-16 text-gray-300 dark:text-gray-600" />
        <p className="text-gray-500 dark:text-gray-400">暂无历史记录</p>
        <p className="mt-2 text-sm text-gray-400 dark:text-gray-500">已完成的扫描会显示在这里。</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-gray-200 dark:border-gray-700">
            <th className="px-4 py-3 text-left text-sm font-medium text-gray-500 dark:text-gray-400">目标地址</th>
            <th className="px-4 py-3 text-left text-sm font-medium text-gray-500 dark:text-gray-400">扫描时间</th>
            <th className="px-4 py-3 text-left text-sm font-medium text-gray-500 dark:text-gray-400">耗时</th>
            <th className="px-4 py-3 text-left text-sm font-medium text-gray-500 dark:text-gray-400">模型</th>
            <th className="px-4 py-3 text-left text-sm font-medium text-gray-500 dark:text-gray-400">状态</th>
            <th className="px-4 py-3 text-right text-sm font-medium text-gray-500 dark:text-gray-400">操作</th>
          </tr>
        </thead>
        <tbody>
          {records.map((record) => (
            <tr
              key={record.id}
              className={`border-b border-gray-100 hover:bg-gray-50 dark:border-gray-800 dark:hover:bg-gray-800/50 ${
                viewingId === record.id ? "bg-sky-50 dark:bg-sky-900/20" : ""
              }`}
            >
              <td className="px-4 py-3">
                <span className="break-all text-sm font-medium text-gray-900 dark:text-white">
                  {record.targetUrl}
                </span>
              </td>
              <td className="px-4 py-3">
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  {new Date(record.timestamp).toLocaleString("zh-CN", {
                    month: "short",
                    day: "numeric",
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </span>
              </td>
              <td className="px-4 py-3">
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  {record.duration ? `${record.duration} 秒` : "-"}
                </span>
              </td>
              <td className="px-4 py-3">
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  {record.config.llmModelName || "默认模型"}
                </span>
              </td>
              <td className="px-4 py-3">
                <span className="inline-flex items-center rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800 dark:bg-green-900/30 dark:text-green-400">
                  {record.finalPhase === "reporting" ? "完成" : record.finalPhase}
                </span>
              </td>
              <td className="px-4 py-3">
                <div className="flex items-center justify-end gap-1">
                  {compareMode ? (
                    <button
                      type="button"
                      onClick={() => onToggleCompare(record)}
                      className={`rounded-lg p-2 transition-colors ${
                        isSelectedA(record)
                          ? "bg-sky-100 text-sky-600 dark:bg-sky-900/30 dark:text-sky-400"
                          : isSelectedB(record)
                            ? "bg-purple-100 text-purple-600 dark:bg-purple-900/30 dark:text-purple-400"
                            : "text-gray-600 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-700"
                      }`}
                      title="选择用于对比"
                    >
                      <span className="text-xs font-bold">
                        {isSelectedA(record) ? "A" : isSelectedB(record) ? "B" : "选择"}
                      </span>
                    </button>
                  ) : (
                    <>
                      <button
                        type="button"
                        onClick={() => onView(record)}
                        className={`rounded-lg p-2 transition-colors ${
                          viewingId === record.id
                            ? "bg-sky-100 text-sky-600 dark:bg-sky-900/30 dark:text-sky-400"
                            : "text-gray-600 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-700"
                        }`}
                        title={viewingId === record.id ? "收起报告" : "查看报告"}
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                      {onDownload && (
                        <button
                          type="button"
                          onClick={() => onDownload(record)}
                          className="rounded-lg p-2 text-gray-600 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-700"
                          title="下载报告"
                        >
                          <Download className="h-4 w-4" />
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => onDelete(record.id)}
                        className="rounded-lg p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/30"
                        title="删除"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
