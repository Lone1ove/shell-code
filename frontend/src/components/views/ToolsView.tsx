"use client";

import { useState, useEffect } from "react";
import {
  Wrench,
  Plus,
  Search,
  Server,
  Terminal,
  Shield,
  Globe,
  Key,
  Zap,
  X,
  Save,
  Power,
  Trash2,
  ExternalLink,
  CheckCircle,
  AlertCircle,
} from "lucide-react";
import { PentestTool, MCPTool } from "@/types";

const categoryIcons: Record<string, React.ElementType> = {
  "网络扫描": Globe,
  "Web 漏洞": Shield,
  "漏洞扫描": Zap,
  "Web 扫描": Globe,
  "目录扫描": Terminal,
  "Fuzzing": Terminal,
  "密码破解": Key,
  "漏洞利用": Shield,
  "Web 测试": Globe,
  "信息收集": Search,
  "CMS 扫描": Globe,
  "SSL 测试": Shield,
  "HTTP 工具": Globe,
  "爬虫": Globe,
};

export function ToolsView() {
  const [builtinTools, setBuiltinTools] = useState<PentestTool[]>([]);
  const [mcpTools, setMcpTools] = useState<MCPTool[]>([]);
  const [categories, setCategories] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [showAddMCP, setShowAddMCP] = useState(false);
  const [newMCP, setNewMCP] = useState({ name: "", description: "", serverUrl: "" });

  useEffect(() => {
    fetchTools();
  }, []);

  const fetchTools = async () => {
    try {
      const res = await fetch("/api/tools");
      const data = await res.json();
      if (data.success) {
        setBuiltinTools(data.builtinTools);
        setMcpTools(data.mcpTools);
        setCategories(data.categories);
      }
    } catch (error) {
      console.error("Failed to fetch tools:", error);
    } finally {
      setLoading(false);
    }
  };

  const addMCPTool = async () => {
    if (!newMCP.name.trim() || !newMCP.serverUrl.trim()) return;
    try {
      const res = await fetch("/api/tools", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "add", tool: newMCP }),
      });
      const data = await res.json();
      if (data.success) {
        setShowAddMCP(false);
        setNewMCP({ name: "", description: "", serverUrl: "" });
        fetchTools();
      }
    } catch (error) {
      console.error("Failed to add MCP tool:", error);
    }
  };

  const removeMCPTool = async (id: string) => {
    if (!confirm("确定要删除此 MCP 工具吗？")) return;
    try {
      const res = await fetch("/api/tools", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "remove", tool: { id } }),
      });
      const data = await res.json();
      if (data.success) {
        fetchTools();
      }
    } catch (error) {
      console.error("Failed to remove MCP tool:", error);
    }
  };

  const toggleMCPTool = async (id: string) => {
    try {
      const res = await fetch("/api/tools", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "toggle", tool: { id } }),
      });
      const data = await res.json();
      if (data.success) {
        setMcpTools((prev) =>
          prev.map((t) => (t.id === id ? { ...t, enabled: !t.enabled } : t))
        );
      }
    } catch (error) {
      console.error("Failed to toggle MCP tool:", error);
    }
  };

  const filteredTools = builtinTools.filter((tool) => {
    const matchesSearch =
      tool.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      tool.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = !selectedCategory || tool.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  const groupedTools = filteredTools.reduce((acc, tool) => {
    if (!acc[tool.category]) acc[tool.category] = [];
    acc[tool.category].push(tool);
    return acc;
  }, {} as Record<string, PentestTool[]>);

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 lg:px-6 py-8">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full" />
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-6 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-br from-indigo-500 to-purple-500 rounded-xl">
            <Wrench className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              渗透测试工具
            </h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              查看内置工具，通过 MCP 协议扩展新工具
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowAddMCP(true)}
          className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-indigo-500 to-purple-500 text-white rounded-lg hover:from-indigo-600 hover:to-purple-600 transition-all shadow-lg shadow-indigo-500/25"
        >
          <Plus className="w-4 h-4" />
          添加 MCP 工具
        </button>
      </div>

      {/* Search and Filter */}
      <div className="flex flex-col md:flex-row gap-4 mb-6">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="搜索工具名称或描述..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-3 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
          />
        </div>
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={() => setSelectedCategory(null)}
            className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
              !selectedCategory
                ? "bg-indigo-500 text-white"
                : "bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700"
            }`}
          >
            全部
          </button>
          {categories.slice(0, 5).map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                selectedCategory === cat
                  ? "bg-indigo-500 text-white"
                  : "bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700"
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* MCP Tools Section */}
      {mcpTools.length > 0 && (
        <div className="card mb-6 overflow-hidden">
          <div className="px-6 py-4 bg-gradient-to-r from-indigo-50 to-purple-50 dark:from-indigo-900/20 dark:to-purple-900/20 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center gap-2">
              <Server className="w-5 h-5 text-indigo-500" />
              <span className="font-semibold text-gray-900 dark:text-white">
                MCP 扩展工具
              </span>
              <span className="ml-2 text-xs text-gray-500 bg-gray-200 dark:bg-gray-700 px-2 py-0.5 rounded-full">
                {mcpTools.length}
              </span>
            </div>
          </div>
          <div className="divide-y divide-gray-100 dark:divide-gray-700">
            {mcpTools.map((tool) => (
              <div
                key={tool.id}
                className="px-6 py-4 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
              >
                <div className="flex items-center gap-4">
                  <div
                    className={`p-2 rounded-lg ${
                      tool.enabled
                        ? "bg-green-100 dark:bg-green-900/30"
                        : "bg-gray-100 dark:bg-gray-800"
                    }`}
                  >
                    <Server
                      className={`w-5 h-5 ${
                        tool.enabled
                          ? "text-green-600 dark:text-green-400"
                          : "text-gray-500"
                      }`}
                    />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="font-medium text-gray-900 dark:text-white">
                        {tool.name}
                      </p>
                      {tool.enabled ? (
                        <CheckCircle className="w-4 h-4 text-green-500" />
                      ) : (
                        <AlertCircle className="w-4 h-4 text-gray-400" />
                      )}
                    </div>
                    <p className="text-sm text-gray-500">{tool.description}</p>
                    <p className="text-xs text-gray-400 mt-1 font-mono">
                      {tool.serverUrl}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => toggleMCPTool(tool.id)}
                    className={`p-2 rounded-lg transition-colors ${
                      tool.enabled
                        ? "text-green-500 hover:bg-green-50 dark:hover:bg-green-900/20"
                        : "text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700"
                    }`}
                  >
                    <Power className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => removeMCPTool(tool.id)}
                    className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Builtin Tools */}
      <div className="space-y-6">
        {Object.entries(groupedTools).map(([category, tools]) => {
          const CategoryIcon = categoryIcons[category] || Terminal;
          return (
            <div key={category} className="card overflow-hidden">
              <div className="px-6 py-4 bg-gradient-to-r from-gray-50 to-gray-100 dark:from-gray-800 dark:to-gray-750 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-center gap-2">
                  <CategoryIcon className="w-5 h-5 text-indigo-500" />
                  <span className="font-semibold text-gray-900 dark:text-white">
                    {category}
                  </span>
                  <span className="ml-2 text-xs text-gray-500 bg-gray-200 dark:bg-gray-700 px-2 py-0.5 rounded-full">
                    {tools.length}
                  </span>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-gray-100 dark:bg-gray-700">
                {tools.map((tool) => (
                  <div
                    key={tool.name}
                    className="p-4 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/80 transition-colors"
                  >
                    <div className="flex items-start gap-3">
                      <div className="p-2 bg-indigo-100 dark:bg-indigo-900/30 rounded-lg flex-shrink-0">
                        <Terminal className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <h4 className="font-medium text-gray-900 dark:text-white">
                            {tool.name}
                          </h4>
                          {tool.installed && (
                            <span className="text-xs text-green-600 bg-green-100 dark:bg-green-900/30 dark:text-green-400 px-1.5 py-0.5 rounded">
                              已安装
                            </span>
                          )}
                        </div>
                        <p className="mt-1 text-sm text-gray-600 dark:text-gray-400 line-clamp-2">
                          {tool.description}
                        </p>
                        {tool.usage && (
                          <code className="mt-2 block text-xs text-gray-500 bg-gray-100 dark:bg-gray-900 px-2 py-1 rounded font-mono">
                            {tool.usage}
                          </code>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      {filteredTools.length === 0 && (
        <div className="card p-12 text-center">
          <Wrench className="w-12 h-12 text-gray-300 mx-auto" />
          <p className="mt-4 text-gray-500">未找到匹配的工具</p>
        </div>
      )}

      {/* Add MCP Modal */}
      {showAddMCP && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-2xl w-full max-w-lg shadow-2xl">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="w-5 h-5 text-indigo-500" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  添加 MCP 工具
                </h3>
              </div>
              <button
                onClick={() => setShowAddMCP(false)}
                className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div className="p-4 bg-indigo-50 dark:bg-indigo-900/20 rounded-lg">
                <p className="text-sm text-indigo-700 dark:text-indigo-300">
                  MCP (Model Context Protocol) 允许您通过标准协议连接外部工具服务器，
                  扩展 AI Agent 的能力。
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  工具名称
                </label>
                <input
                  type="text"
                  value={newMCP.name}
                  onChange={(e) => setNewMCP({ ...newMCP, name: e.target.value })}
                  placeholder="例如: Custom Scanner"
                  className="input-field"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  描述
                </label>
                <input
                  type="text"
                  value={newMCP.description}
                  onChange={(e) => setNewMCP({ ...newMCP, description: e.target.value })}
                  placeholder="简要描述工具功能"
                  className="input-field"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  服务器地址
                </label>
                <input
                  type="text"
                  value={newMCP.serverUrl}
                  onChange={(e) => setNewMCP({ ...newMCP, serverUrl: e.target.value })}
                  placeholder="例如: http://localhost:8080/mcp"
                  className="input-field font-mono"
                />
              </div>
            </div>
            <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-3">
              <button
                onClick={() => setShowAddMCP(false)}
                className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                取消
              </button>
              <button
                onClick={addMCPTool}
                disabled={!newMCP.name.trim() || !newMCP.serverUrl.trim()}
                className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-indigo-500 to-purple-500 text-white rounded-lg hover:from-indigo-600 hover:to-purple-600 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
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
