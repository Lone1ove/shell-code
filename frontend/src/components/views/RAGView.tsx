"use client";

import { useState, useEffect, useRef } from "react";
import {
  Database,
  Upload,
  Trash2,
  FileText,
  RefreshCw,
  Power,
  AlertTriangle,
  CheckCircle,
  File,
  FileJson,
  FileCode,
  HardDrive,
  Clock,
} from "lucide-react";
import { RAGDocument, RAGConfig } from "@/types";

export function RAGView() {
  const [config, setConfig] = useState<RAGConfig | null>(null);
  const [documents, setDocuments] = useState<RAGDocument[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetchRAGData();
  }, []);

  const fetchRAGData = async () => {
    try {
      const res = await fetch("/api/rag");
      const data = await res.json();
      if (data.success) {
        setConfig(data.config);
        setDocuments(data.documents);
      }
    } catch (error) {
      console.error("Failed to fetch RAG data:", error);
    } finally {
      setLoading(false);
    }
  };

  const [uploadProgress, setUploadProgress] = useState<{ current: number; total: number } | null>(null);

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;

    setUploading(true);
    setUploadProgress({ current: 0, total: files.length });

    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        setUploadProgress({ current: i + 1, total: files.length });

        const formData = new FormData();
        formData.append("action", "upload");
        formData.append("file", file);

        await fetch("/api/rag", {
          method: "POST",
          body: formData,
        });
      }
      fetchRAGData();
    } catch (error) {
      console.error("Failed to upload:", error);
    } finally {
      setUploading(false);
      setUploadProgress(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    }
  };

  const deleteDocument = async (id: string) => {
    try {
      const formData = new FormData();
      formData.append("action", "delete");
      formData.append("id", id);

      const res = await fetch("/api/rag", {
        method: "POST",
        body: formData,
      });
      const data = await res.json();
      if (data.success) {
        fetchRAGData();
      }
    } catch (error) {
      console.error("Failed to delete:", error);
    }
  };

  const resetKnowledgeBase = async () => {
    try {
      const formData = new FormData();
      formData.append("action", "reset");

      const res = await fetch("/api/rag", {
        method: "POST",
        body: formData,
      });
      const data = await res.json();
      if (data.success) {
        setShowResetConfirm(false);
        fetchRAGData();
      }
    } catch (error) {
      console.error("Failed to reset:", error);
    }
  };

  const toggleRAG = async () => {
    try {
      const formData = new FormData();
      formData.append("action", "toggle");

      const res = await fetch("/api/rag", {
        method: "POST",
        body: formData,
      });
      const data = await res.json();
      if (data.success) {
        setConfig((prev) => prev ? { ...prev, enabled: data.enabled } : null);
      }
    } catch (error) {
      console.error("Failed to toggle:", error);
    }
  };

  const getFileIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case "json":
        return <FileJson className="w-5 h-5 text-yellow-500" />;
      case "md":
      case "txt":
        return <FileText className="w-5 h-5 text-blue-500" />;
      case "py":
      case "js":
      case "ts":
        return <FileCode className="w-5 h-5 text-green-500" />;
      default:
        return <File className="w-5 h-5 text-gray-500" />;
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString("zh-CN", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 lg:px-6 py-8">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin w-8 h-8 border-2 border-emerald-500 border-t-transparent rounded-full" />
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-6 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-br from-emerald-500 to-teal-500 rounded-xl">
            <Database className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              知识库配置
            </h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              RAG 检索增强生成，导入文档增强 AI 能力
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowResetConfirm(true)}
            className="flex items-center gap-2 px-4 py-2 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            重置知识库
          </button>
          <button
            onClick={toggleRAG}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
              config?.enabled
                ? "bg-emerald-500 text-white hover:bg-emerald-600"
                : "bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600"
            }`}
          >
            <Power className="w-4 h-4" />
            {config?.enabled ? "已启用" : "已禁用"}
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-emerald-100 dark:bg-emerald-900/30 rounded-lg">
              <FileText className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">文档数量</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {documents.length}
              </p>
            </div>
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
              <HardDrive className="w-5 h-5 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">总大小</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {formatFileSize(documents.reduce((acc, d) => acc + d.size, 0))}
              </p>
            </div>
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
              <Clock className="w-5 h-5 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">最后更新</p>
              <p className="text-lg font-semibold text-gray-900 dark:text-white">
                {config?.lastUpdated ? formatDate(config.lastUpdated) : "从未"}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Upload Area */}
      <div className="card p-6 mb-6">
        <div
          className={`border-2 border-dashed rounded-xl p-8 text-center transition-colors ${
            uploading
              ? "border-emerald-500 bg-emerald-50 dark:bg-emerald-900/20"
              : "border-gray-300 dark:border-gray-600 hover:border-emerald-500 dark:hover:border-emerald-500"
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            multiple
            onChange={handleUpload}
            className="hidden"
            accept=".txt,.md,.json,.pdf,.py,.js,.ts,.html,.xml,.yaml,.yml"
          />
          {uploading ? (
            <div className="flex flex-col items-center">
              <div className="animate-spin w-10 h-10 border-2 border-emerald-500 border-t-transparent rounded-full" />
              <p className="mt-4 text-emerald-600 dark:text-emerald-400 font-medium">
                {uploadProgress
                  ? `上传中 (${uploadProgress.current}/${uploadProgress.total})...`
                  : "上传中..."}
              </p>
            </div>
          ) : (
            <>
              <Upload className="w-12 h-12 text-gray-400 mx-auto" />
              <p className="mt-4 text-gray-600 dark:text-gray-300 font-medium">
                拖拽文件到此处或点击上传（支持批量）
              </p>
              <p className="mt-2 text-sm text-gray-500">
                支持 TXT、MD、JSON、PDF、代码文件等，可同时选择多个文件
              </p>
              <button
                onClick={() => fileInputRef.current?.click()}
                className="mt-4 px-6 py-2 bg-gradient-to-r from-emerald-500 to-teal-500 text-white rounded-lg hover:from-emerald-600 hover:to-teal-600 transition-all shadow-lg shadow-emerald-500/25"
              >
                选择文件
              </button>
            </>
          )}
        </div>
      </div>

      {/* Documents List */}
      <div className="card overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="font-semibold text-gray-900 dark:text-white">
            已导入文档
          </h3>
        </div>
        {documents.length === 0 ? (
          <div className="p-12 text-center">
            <Database className="w-12 h-12 text-gray-300 mx-auto" />
            <p className="mt-4 text-gray-500">暂无文档，请上传文件</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-100 dark:divide-gray-700">
            {documents.map((doc) => (
              <div
                key={doc.id}
                className="px-6 py-4 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
              >
                <div className="flex items-center gap-4">
                  {getFileIcon(doc.type)}
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      {doc.name}
                    </p>
                    <p className="text-sm text-gray-500">
                      {formatFileSize(doc.size)} · {formatDate(doc.uploadedAt)}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => deleteDocument(doc.id)}
                  className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Reset Confirm Modal */}
      {showResetConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-2xl w-full max-w-md shadow-2xl p-6">
            <div className="flex items-center gap-3 text-red-500 mb-4">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="text-lg font-semibold">确认重置知识库</h3>
            </div>
            <p className="text-gray-600 dark:text-gray-300 mb-6">
              此操作将删除所有已导入的文档，且无法恢复。确定要继续吗？
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowResetConfirm(false)}
                className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                取消
              </button>
              <button
                onClick={resetKnowledgeBase}
                className="px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors"
              >
                确认重置
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
