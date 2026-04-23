"use client";

import { useState, useEffect } from "react";
import {
  Bug,
  Plus,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  AlertTriangle,
  Shield,
  X,
  Save,
  CheckCircle,
  Clock,
  Tag,
} from "lucide-react";
import { CVERecord } from "@/types";

const severityColors: Record<string, string> = {
  critical: "bg-red-500 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-white",
  low: "bg-blue-500 text-white",
  unknown: "bg-gray-500 text-white",
};

const severityBadgeColors: Record<string, string> = {
  critical: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
  high: "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400",
  medium: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
  low: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
  unknown: "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400",
};

export function CVEView() {
  const [records, setRecords] = useState<CVERecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState("");
  const [selectedFamily, setSelectedFamily] = useState("");
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [stats, setStats] = useState<{
    total: number;
    severityCounts: Record<string, number>;
    familyCounts: Record<string, number>;
    pocAvailable: number;
  } | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedCVE, setSelectedCVE] = useState<CVERecord | null>(null);
  const [newCVE, setNewCVE] = useState({
    cve_id: "",
    description: "",
    severity: "unknown",
    cvss: "",
    product_family: "",
    poc_available: false,
    references: "",
  });

  useEffect(() => {
    fetchCVEs();
  }, [page, searchTerm, selectedSeverity, selectedFamily]);

  const fetchCVEs = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        pageSize: "20",
        search: searchTerm,
        severity: selectedSeverity,
        family: selectedFamily,
      });
      const res = await fetch(`/api/cve?${params}`);
      const data = await res.json();
      if (data.success) {
        setRecords(data.records);
        setTotalPages(data.pagination.totalPages);
        setStats(data.stats);
      }
    } catch (error) {
      console.error("Failed to fetch CVEs:", error);
    } finally {
      setLoading(false);
    }
  };

  const addCVE = async () => {
    if (!newCVE.cve_id.trim()) return;
    try {
      const res = await fetch("/api/cve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "add",
          cve: {
            ...newCVE,
            cvss: newCVE.cvss ? parseFloat(newCVE.cvss) : undefined,
            references: newCVE.references
              .split("\n")
              .map((r) => r.trim())
              .filter(Boolean),
          },
        }),
      });
      const data = await res.json();
      if (data.success) {
        setShowAddModal(false);
        setNewCVE({
          cve_id: "",
          description: "",
          severity: "unknown",
          cvss: "",
          product_family: "",
          poc_available: false,
          references: "",
        });
        fetchCVEs();
      }
    } catch (error) {
      console.error("Failed to add CVE:", error);
    }
  };

  const deleteCVE = async (cve_id: string) => {
    if (!confirm("确定要删除此 CVE 吗？")) return;
    try {
      const res = await fetch("/api/cve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "delete", cve: { cve_id } }),
      });
      const data = await res.json();
      if (data.success) {
        setSelectedCVE(null);
        fetchCVEs();
      }
    } catch (error) {
      console.error("Failed to delete CVE:", error);
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString("zh-CN", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  };

  const topFamilies = stats
    ? Object.entries(stats.familyCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
    : [];

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-6 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-br from-red-500 to-rose-500 rounded-xl">
            <Bug className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              CVE 情报库
            </h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              漏洞情报管理，支持 NVD、Vulhub 等多源数据
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-red-500 to-rose-500 text-white rounded-lg hover:from-red-600 hover:to-rose-600 transition-all shadow-lg shadow-red-500/25"
        >
          <Plus className="w-4 h-4" />
          添加 CVE
        </button>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
          <div className="card p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">总计</p>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {stats.total.toLocaleString()}
            </p>
          </div>
          {["critical", "high", "medium", "low"].map((sev) => (
            <div key={sev} className="card p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400 capitalize">
                {sev === "critical" ? "严重" : sev === "high" ? "高危" : sev === "medium" ? "中危" : "低危"}
              </p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {(stats.severityCounts[sev.toUpperCase()] || stats.severityCounts[sev] || 0).toLocaleString()}
              </p>
            </div>
          ))}
        </div>
      )}

      {/* Search and Filters */}
      <div className="card p-4 mb-6">
        <div className="flex flex-col lg:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="搜索 CVE ID、描述、产品..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setPage(1);
              }}
              className="w-full pl-10 pr-4 py-2.5 bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent transition-all"
            />
          </div>
          <div className="flex gap-2 flex-wrap">
            <select
              value={selectedSeverity}
              onChange={(e) => {
                setSelectedSeverity(e.target.value);
                setPage(1);
              }}
              className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg text-sm focus:ring-2 focus:ring-red-500"
            >
              <option value="">所有严重级别</option>
              <option value="critical">严重 (Critical)</option>
              <option value="high">高危 (High)</option>
              <option value="medium">中危 (Medium)</option>
              <option value="low">低危 (Low)</option>
            </select>
            <select
              value={selectedFamily}
              onChange={(e) => {
                setSelectedFamily(e.target.value);
                setPage(1);
              }}
              className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg text-sm focus:ring-2 focus:ring-red-500"
            >
              <option value="">所有产品</option>
              {topFamilies.map(([family]) => (
                <option key={family} value={family}>
                  {family}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* CVE List */}
        <div className="lg:col-span-2">
          <div className="card overflow-hidden">
            {loading ? (
              <div className="p-12 text-center">
                <div className="animate-spin w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full mx-auto" />
                <p className="mt-4 text-gray-500">加载中...</p>
              </div>
            ) : records.length === 0 ? (
              <div className="p-12 text-center">
                <Bug className="w-12 h-12 text-gray-300 mx-auto" />
                <p className="mt-4 text-gray-500">未找到匹配的 CVE</p>
              </div>
            ) : (
              <>
                <div className="divide-y divide-gray-100 dark:divide-gray-700">
                  {records.map((cve) => (
                    <div
                      key={cve.cve_id}
                      className={`p-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 cursor-pointer transition-colors ${
                        selectedCVE?.cve_id === cve.cve_id
                          ? "bg-red-50 dark:bg-red-900/20 border-l-2 border-red-500"
                          : ""
                      }`}
                      onClick={() => setSelectedCVE(cve)}
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono font-semibold text-gray-900 dark:text-white">
                              {cve.cve_id}
                            </span>
                            <span
                              className={`px-2 py-0.5 rounded text-xs font-medium ${
                                severityBadgeColors[cve.severity.toLowerCase()] ||
                                severityBadgeColors.unknown
                              }`}
                            >
                              {cve.severity}
                            </span>
                            {cve.poc_available && (
                              <span className="px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400">
                                PoC
                              </span>
                            )}
                          </div>
                          <p className="mt-1 text-sm text-gray-600 dark:text-gray-400 line-clamp-2">
                            {cve.description || "暂无描述"}
                          </p>
                          <div className="mt-2 flex items-center gap-3 text-xs text-gray-500">
                            <span className="flex items-center gap-1">
                              <Tag className="w-3 h-3" />
                              {cve.product_family}
                            </span>
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {formatDate(cve.updated_at)}
                            </span>
                          </div>
                        </div>
                        {cve.cvss && (
                          <div
                            className={`px-2 py-1 rounded text-sm font-bold ${
                              cve.cvss >= 9
                                ? "bg-red-500 text-white"
                                : cve.cvss >= 7
                                ? "bg-orange-500 text-white"
                                : cve.cvss >= 4
                                ? "bg-yellow-500 text-white"
                                : "bg-blue-500 text-white"
                            }`}
                          >
                            {cve.cvss.toFixed(1)}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Pagination */}
                <div className="px-4 py-3 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between">
                  <p className="text-sm text-gray-500">
                    第 {page} / {totalPages} 页
                  </p>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                      disabled={page === 1}
                      className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <ChevronLeft className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                      disabled={page === totalPages}
                      className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>

        {/* CVE Detail */}
        <div className="lg:col-span-1">
          {selectedCVE ? (
            <div className="card sticky top-4">
              <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                <h3 className="font-semibold text-gray-900 dark:text-white font-mono">
                  {selectedCVE.cve_id}
                </h3>
                <button
                  onClick={() => setSelectedCVE(null)}
                  className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="p-4 space-y-4">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className={`px-2 py-1 rounded text-sm font-medium ${
                      severityBadgeColors[selectedCVE.severity.toLowerCase()] ||
                      severityBadgeColors.unknown
                    }`}
                  >
                    {selectedCVE.severity}
                  </span>
                  {selectedCVE.cvss && (
                    <span className="px-2 py-1 rounded text-sm font-bold bg-gray-100 dark:bg-gray-700">
                      CVSS: {selectedCVE.cvss.toFixed(1)}
                    </span>
                  )}
                  {selectedCVE.poc_available && (
                    <span className="px-2 py-1 rounded text-sm font-medium bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400">
                      <CheckCircle className="w-3 h-3 inline mr-1" />
                      PoC 可用
                    </span>
                  )}
                </div>

                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">
                    描述
                  </h4>
                  <p className="text-sm text-gray-700 dark:text-gray-300">
                    {selectedCVE.description || "暂无描述"}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">
                      产品
                    </h4>
                    <p className="text-sm text-gray-700 dark:text-gray-300">
                      {selectedCVE.product_family}
                    </p>
                  </div>
                  <div>
                    <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">
                      来源
                    </h4>
                    <p className="text-sm text-gray-700 dark:text-gray-300">
                      {selectedCVE.source}
                    </p>
                  </div>
                </div>

                {selectedCVE.protocols.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">
                      协议
                    </h4>
                    <div className="flex flex-wrap gap-1">
                      {selectedCVE.protocols.map((p) => (
                        <span
                          key={p}
                          className="px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs"
                        >
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {selectedCVE.references.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">
                      参考链接
                    </h4>
                    <div className="space-y-1 max-h-32 overflow-auto">
                      {selectedCVE.references.slice(0, 5).map((ref, i) => (
                        <a
                          key={i}
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400 hover:underline truncate"
                        >
                          <ExternalLink className="w-3 h-3 flex-shrink-0" />
                          <span className="truncate">{ref}</span>
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {selectedCVE.source === "custom" && (
                  <button
                    onClick={() => deleteCVE(selectedCVE.cve_id)}
                    className="w-full mt-4 px-4 py-2 text-red-600 border border-red-200 dark:border-red-800 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                  >
                    删除此 CVE
                  </button>
                )}
              </div>
            </div>
          ) : (
            <div className="card p-8 text-center">
              <Shield className="w-12 h-12 text-gray-300 mx-auto" />
              <p className="mt-4 text-gray-500">选择 CVE 查看详情</p>
            </div>
          )}
        </div>
      </div>

      {/* Add CVE Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-2xl w-full max-w-lg shadow-2xl max-h-[90vh] overflow-auto">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between sticky top-0 bg-white dark:bg-gray-800">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                添加 CVE
              </h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  CVE ID *
                </label>
                <input
                  type="text"
                  value={newCVE.cve_id}
                  onChange={(e) => setNewCVE({ ...newCVE, cve_id: e.target.value.toUpperCase() })}
                  placeholder="CVE-2024-XXXXX"
                  className="input-field font-mono"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  描述
                </label>
                <textarea
                  value={newCVE.description}
                  onChange={(e) => setNewCVE({ ...newCVE, description: e.target.value })}
                  placeholder="漏洞描述..."
                  rows={3}
                  className="input-field"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    严重级别
                  </label>
                  <select
                    value={newCVE.severity}
                    onChange={(e) => setNewCVE({ ...newCVE, severity: e.target.value })}
                    className="input-field"
                  >
                    <option value="unknown">未知</option>
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中危</option>
                    <option value="low">低危</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    CVSS 评分
                  </label>
                  <input
                    type="number"
                    step="0.1"
                    min="0"
                    max="10"
                    value={newCVE.cvss}
                    onChange={(e) => setNewCVE({ ...newCVE, cvss: e.target.value })}
                    placeholder="0.0 - 10.0"
                    className="input-field"
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  产品/框架
                </label>
                <input
                  type="text"
                  value={newCVE.product_family}
                  onChange={(e) => setNewCVE({ ...newCVE, product_family: e.target.value })}
                  placeholder="例如: struts2, spring, tomcat"
                  className="input-field"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  参考链接 (每行一个)
                </label>
                <textarea
                  value={newCVE.references}
                  onChange={(e) => setNewCVE({ ...newCVE, references: e.target.value })}
                  placeholder="https://example.com/advisory&#10;https://github.com/..."
                  rows={3}
                  className="input-field font-mono text-sm"
                />
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="poc_available"
                  checked={newCVE.poc_available}
                  onChange={(e) => setNewCVE({ ...newCVE, poc_available: e.target.checked })}
                  className="w-4 h-4 text-red-500 rounded focus:ring-red-500"
                />
                <label htmlFor="poc_available" className="text-sm text-gray-700 dark:text-gray-300">
                  PoC 可用
                </label>
              </div>
            </div>
            <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-3 sticky bottom-0 bg-white dark:bg-gray-800">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                取消
              </button>
              <button
                onClick={addCVE}
                disabled={!newCVE.cve_id.trim()}
                className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-red-500 to-rose-500 text-white rounded-lg hover:from-red-600 hover:to-rose-600 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Save className="w-4 h-4" />
                添加
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
