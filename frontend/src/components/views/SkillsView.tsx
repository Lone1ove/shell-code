"use client";

import { useState, useEffect, useRef } from "react";
import {
  Sparkles,
  Plus,
  Search,
  Eye,
  Trash2,
  Upload,
  FileText,
  Code,
  ChevronRight,
  X,
  Save,
  FolderOpen,
  Play,
  RefreshCw,
  CheckCircle,
  AlertCircle,
  FileCode,
  Terminal,
  Server,
} from "lucide-react";

interface SkillFile {
  name: string;
  type: "markdown" | "python" | "shell" | "other";
  size: number;
  executable: boolean;
}

interface Skill {
  key: string;
  name: string;
  source: string;
  path: string;
  keywords: string[];
  description?: string;
  files?: SkillFile[];
  hasScripts?: boolean;
  syncedToDocker?: boolean;
}

export function SkillsView() {
  const [skills, setSkills] = useState<Skill[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSkill, setSelectedSkill] = useState<Skill | null>(null);
  const [skillContent, setSkillContent] = useState("");
  const [skillFiles, setSkillFiles] = useState<SkillFile[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [dockerRunning, setDockerRunning] = useState(false);
  const [dockerSkillsPath, setDockerSkillsPath] = useState("");
  const [syncing, setSyncing] = useState<string | null>(null);

  // 新建技能表单
  const [newSkill, setNewSkill] = useState({
    key: "",
    name: "",
    description: "",
    content: "",
  });
  const [uploadedFiles, setUploadedFiles] = useState<File[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetchSkills();
  }, []);

  const fetchSkills = async () => {
    try {
      const res = await fetch("/api/skills");
      const data = await res.json();
      if (data.success) {
        setSkills(data.skills);
        setDockerRunning(data.dockerRunning);
        setDockerSkillsPath(data.dockerSkillsPath);
      }
    } catch (error) {
      console.error("Failed to fetch skills:", error);
    } finally {
      setLoading(false);
    }
  };

  const viewSkill = async (skill: Skill) => {
    try {
      const res = await fetch("/api/skills", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "get", key: skill.key }),
      });
      const data = await res.json();
      if (data.success) {
        setSelectedSkill(skill);
        setSkillContent(data.content);
        setSkillFiles(data.files || []);
      }
    } catch (error) {
      console.error("Failed to get skill content:", error);
    }
  };

  const createSkill = async () => {
    if (!newSkill.key.trim()) return;

    try {
      const formData = new FormData();
      formData.append("action", "create");
      formData.append("key", newSkill.key.toLowerCase().replace(/\s+/g, "-"));
      formData.append("name", newSkill.name || newSkill.key);
      formData.append("description", newSkill.description);
      formData.append("content", newSkill.content);

      // 添加上传的文件
      for (const file of uploadedFiles) {
        formData.append("files", file);
      }

      const res = await fetch("/api/skills", {
        method: "POST",
        body: formData,
      });
      const data = await res.json();

      if (data.success) {
        setShowCreateModal(false);
        setNewSkill({ key: "", name: "", description: "", content: "" });
        setUploadedFiles([]);
        fetchSkills();
      }
    } catch (error) {
      console.error("Failed to create skill:", error);
    }
  };

  const deleteSkill = async (key: string) => {
    if (!confirm("确定要删除此技能吗？这将同时删除容器中的脚本。")) return;
    try {
      const res = await fetch("/api/skills", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "delete", key }),
      });
      const data = await res.json();
      if (data.success) {
        fetchSkills();
        if (selectedSkill?.key === key) {
          setSelectedSkill(null);
          setSkillContent("");
          setSkillFiles([]);
        }
      }
    } catch (error) {
      console.error("Failed to delete skill:", error);
    }
  };

  const syncSkill = async (key: string) => {
    setSyncing(key);
    try {
      const res = await fetch("/api/skills", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "sync", key }),
      });
      const data = await res.json();
      if (data.success) {
        fetchSkills();
      } else {
        alert(data.message || "同步失败");
      }
    } catch (error) {
      console.error("Failed to sync skill:", error);
    } finally {
      setSyncing(null);
    }
  };

  const syncAllSkills = async () => {
    setSyncing("all");
    try {
      const res = await fetch("/api/skills", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "sync-all" }),
      });
      const data = await res.json();
      if (data.success) {
        fetchSkills();
      }
    } catch (error) {
      console.error("Failed to sync all skills:", error);
    } finally {
      setSyncing(null);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    setUploadedFiles((prev) => [...prev, ...files]);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  const removeUploadedFile = (index: number) => {
    setUploadedFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const getFileIcon = (file: SkillFile) => {
    if (file.type === "python") return <FileCode className="w-4 h-4 text-yellow-500" />;
    if (file.type === "shell") return <Terminal className="w-4 h-4 text-green-500" />;
    if (file.type === "markdown") return <FileText className="w-4 h-4 text-blue-500" />;
    return <FileText className="w-4 h-4 text-gray-500" />;
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const filteredSkills = skills.filter(
    (s) =>
      s.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.key.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.description?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const groupedSkills = filteredSkills.reduce((acc, skill) => {
    const source = skill.source || "builtin";
    if (!acc[source]) acc[source] = [];
    acc[source].push(skill);
    return acc;
  }, {} as Record<string, Skill[]>);

  const skillsWithScripts = skills.filter((s) => s.hasScripts);

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-6 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-br from-amber-500 to-orange-500 rounded-xl">
            <Sparkles className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              技能配置
            </h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              管理渗透测试技能模块，支持自定义脚本扩展
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {skillsWithScripts.length > 0 && (
            <button
              onClick={syncAllSkills}
              disabled={!dockerRunning || syncing === "all"}
              className="flex items-center gap-2 px-4 py-2 text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-900/20 rounded-lg transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${syncing === "all" ? "animate-spin" : ""}`} />
              同步全部脚本
            </button>
          )}
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-amber-500 to-orange-500 text-white rounded-lg hover:from-amber-600 hover:to-orange-600 transition-all shadow-lg shadow-amber-500/25"
          >
            <Plus className="w-4 h-4" />
            新建技能
          </button>
        </div>
      </div>

      {/* Docker Status */}
      <div className={`mb-6 p-4 rounded-xl flex items-center gap-3 ${
        dockerRunning
          ? "bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800"
          : "bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800"
      }`}>
        <Server className={`w-5 h-5 ${dockerRunning ? "text-green-500" : "text-yellow-500"}`} />
        <div className="flex-1">
          <p className={`font-medium ${dockerRunning ? "text-green-700 dark:text-green-300" : "text-yellow-700 dark:text-yellow-300"}`}>
            {dockerRunning ? "Docker 容器运行中" : "Docker 容器未运行"}
          </p>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            {dockerRunning
              ? `脚本将同步到容器内 ${dockerSkillsPath}/`
              : "启动容器后可同步脚本到执行环境"}
          </p>
        </div>
        {dockerRunning && (
          <CheckCircle className="w-5 h-5 text-green-500" />
        )}
      </div>

      {/* Search */}
      <div className="relative mb-6">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
        <input
          type="text"
          placeholder="搜索技能名称、关键词..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full pl-10 pr-4 py-3 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl focus:ring-2 focus:ring-amber-500 focus:border-transparent transition-all"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Skills List */}
        <div className="lg:col-span-1 space-y-4">
          {loading ? (
            <div className="card p-8 text-center">
              <div className="animate-spin w-8 h-8 border-2 border-amber-500 border-t-transparent rounded-full mx-auto" />
              <p className="mt-4 text-gray-500">加载中...</p>
            </div>
          ) : (
            Object.entries(groupedSkills).map(([source, sourceSkills]) => (
              <div key={source} className="card overflow-hidden">
                <div className="px-4 py-3 bg-gradient-to-r from-gray-50 to-gray-100 dark:from-gray-800 dark:to-gray-750 border-b border-gray-200 dark:border-gray-700">
                  <div className="flex items-center gap-2">
                    <FolderOpen className="w-4 h-4 text-amber-500" />
                    <span className="font-medium text-gray-700 dark:text-gray-300">
                      {source === "builtin" ? "内置技能" : source}
                    </span>
                    <span className="ml-auto text-xs text-gray-500 bg-gray-200 dark:bg-gray-700 px-2 py-0.5 rounded-full">
                      {sourceSkills.length}
                    </span>
                  </div>
                </div>
                <div className="divide-y divide-gray-100 dark:divide-gray-700">
                  {sourceSkills.map((skill) => (
                    <div
                      key={skill.key}
                      className={`p-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 cursor-pointer transition-colors ${
                        selectedSkill?.key === skill.key
                          ? "bg-amber-50 dark:bg-amber-900/20 border-l-2 border-amber-500"
                          : ""
                      }`}
                      onClick={() => viewSkill(skill)}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <Code className="w-4 h-4 text-amber-500 flex-shrink-0" />
                            <span className="font-medium text-gray-900 dark:text-white truncate">
                              {skill.name}
                            </span>
                            {skill.hasScripts && (
                              <span className="px-1.5 py-0.5 text-xs bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400 rounded">
                                脚本
                              </span>
                            )}
                          </div>
                          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400 line-clamp-2">
                            {skill.description || skill.key}
                          </p>
                        </div>
                        <ChevronRight className="w-4 h-4 text-gray-400 flex-shrink-0 ml-2" />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))
          )}

          {!loading && filteredSkills.length === 0 && (
            <div className="card p-8 text-center">
              <FileText className="w-12 h-12 text-gray-300 mx-auto" />
              <p className="mt-4 text-gray-500">未找到匹配的技能</p>
            </div>
          )}
        </div>

        {/* Skill Detail */}
        <div className="lg:col-span-2">
          {selectedSkill ? (
            <div className="card h-full flex flex-col">
              <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                      {selectedSkill.name}
                    </h3>
                    {selectedSkill.hasScripts && (
                      <span className="px-2 py-0.5 text-xs bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400 rounded">
                        包含脚本
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-gray-500">{selectedSkill.key}</p>
                </div>
                <div className="flex items-center gap-2">
                  {selectedSkill.hasScripts && dockerRunning && (
                    <button
                      onClick={() => syncSkill(selectedSkill.key)}
                      disabled={syncing === selectedSkill.key}
                      className="flex items-center gap-1 px-3 py-1.5 text-sm text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-900/20 rounded-lg transition-colors"
                    >
                      <RefreshCw className={`w-4 h-4 ${syncing === selectedSkill.key ? "animate-spin" : ""}`} />
                      同步
                    </button>
                  )}
                  <button
                    onClick={() => deleteSkill(selectedSkill.key)}
                    className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                    title="删除技能"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => {
                      setSelectedSkill(null);
                      setSkillContent("");
                      setSkillFiles([]);
                    }}
                    className="p-2 text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Files List */}
              {skillFiles.length > 0 && (
                <div className="px-6 py-3 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                  <p className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    包含文件
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {skillFiles.map((file) => (
                      <div
                        key={file.name}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm ${
                          file.executable
                            ? "bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300"
                            : "bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300"
                        }`}
                      >
                        {getFileIcon(file)}
                        <span>{file.name}</span>
                        <span className="text-xs opacity-60">{formatFileSize(file.size)}</span>
                        {file.executable && (
                          <Play className="w-3 h-3" />
                        )}
                      </div>
                    ))}
                  </div>
                  {selectedSkill.hasScripts && dockerRunning && (
                    <p className="mt-2 text-xs text-gray-500">
                      脚本路径: <code className="bg-gray-200 dark:bg-gray-700 px-1 rounded">{dockerSkillsPath}/{selectedSkill.key}/</code>
                    </p>
                  )}
                </div>
              )}

              <div className="flex-1 p-6 overflow-auto">
                <pre className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap font-mono bg-gray-50 dark:bg-gray-800/50 p-4 rounded-lg">
                  {skillContent}
                </pre>
              </div>
            </div>
          ) : (
            <div className="card h-full flex items-center justify-center p-12">
              <div className="text-center">
                <div className="w-16 h-16 bg-gradient-to-br from-amber-100 to-orange-100 dark:from-amber-900/30 dark:to-orange-900/30 rounded-2xl flex items-center justify-center mx-auto">
                  <Eye className="w-8 h-8 text-amber-500" />
                </div>
                <h3 className="mt-4 text-lg font-medium text-gray-900 dark:text-white">
                  选择技能查看详情
                </h3>
                <p className="mt-2 text-sm text-gray-500">
                  点击左侧列表中的技能查看其内容和脚本
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-2xl w-full max-w-2xl shadow-2xl max-h-[90vh] overflow-auto">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between sticky top-0 bg-white dark:bg-gray-800">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                新建技能
              </h3>
              <button
                onClick={() => {
                  setShowCreateModal(false);
                  setUploadedFiles([]);
                }}
                className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              {/* 基本信息 */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    技能标识 (key) *
                  </label>
                  <input
                    type="text"
                    value={newSkill.key}
                    onChange={(e) =>
                      setNewSkill({
                        ...newSkill,
                        key: e.target.value.toLowerCase().replace(/\s+/g, "-"),
                      })
                    }
                    placeholder="例如: custom-exploit"
                    className="input-field"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    技能名称
                  </label>
                  <input
                    type="text"
                    value={newSkill.name}
                    onChange={(e) => setNewSkill({ ...newSkill, name: e.target.value })}
                    placeholder="例如: 自定义漏洞利用"
                    className="input-field"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  描述
                </label>
                <input
                  type="text"
                  value={newSkill.description}
                  onChange={(e) => setNewSkill({ ...newSkill, description: e.target.value })}
                  placeholder="简要描述技能用途"
                  className="input-field"
                />
              </div>

              {/* 脚本上传 */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  上传脚本文件 (可选)
                </label>
                <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-xl p-4 text-center hover:border-amber-500 transition-colors">
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    accept=".py,.sh,.bash,.pl,.rb,.txt,.json,.yaml,.yml"
                    onChange={handleFileSelect}
                    className="hidden"
                  />
                  <Upload className="w-8 h-8 text-gray-400 mx-auto" />
                  <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
                    支持 Python、Shell、Perl、Ruby 脚本
                  </p>
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="mt-2 px-4 py-1.5 text-sm text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-900/20 rounded-lg transition-colors"
                  >
                    选择文件
                  </button>
                </div>

                {/* 已上传文件列表 */}
                {uploadedFiles.length > 0 && (
                  <div className="mt-3 space-y-2">
                    {uploadedFiles.map((file, index) => (
                      <div
                        key={index}
                        className="flex items-center justify-between px-3 py-2 bg-gray-50 dark:bg-gray-700 rounded-lg"
                      >
                        <div className="flex items-center gap-2">
                          <FileCode className="w-4 h-4 text-amber-500" />
                          <span className="text-sm text-gray-700 dark:text-gray-300">
                            {file.name}
                          </span>
                          <span className="text-xs text-gray-500">
                            {formatFileSize(file.size)}
                          </span>
                        </div>
                        <button
                          onClick={() => removeUploadedFile(index)}
                          className="p-1 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                {uploadedFiles.length > 0 && dockerRunning && (
                  <p className="mt-2 text-xs text-green-600 dark:text-green-400 flex items-center gap-1">
                    <CheckCircle className="w-3 h-3" />
                    脚本将自动同步到 Docker 容器
                  </p>
                )}
              </div>

              {/* 技能内容 */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  技能内容 (Markdown)
                  <span className="ml-2 text-xs text-gray-500 font-normal">
                    留空将自动生成模板
                  </span>
                </label>
                <textarea
                  value={newSkill.content}
                  onChange={(e) => setNewSkill({ ...newSkill, content: e.target.value })}
                  placeholder="# 技能标题&#10;&#10;## 使用方法&#10;...&#10;&#10;（留空将根据上传的脚本自动生成文档）"
                  rows={8}
                  className="input-field font-mono text-sm"
                />
              </div>
            </div>
            <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-3 sticky bottom-0 bg-white dark:bg-gray-800">
              <button
                onClick={() => {
                  setShowCreateModal(false);
                  setUploadedFiles([]);
                }}
                className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                取消
              </button>
              <button
                onClick={createSkill}
                disabled={!newSkill.key.trim()}
                className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-amber-500 to-orange-500 text-white rounded-lg hover:from-amber-600 hover:to-orange-600 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Save className="w-4 h-4" />
                创建
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
