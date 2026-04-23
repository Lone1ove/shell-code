"use client";

import { useEffect, useRef } from "react";
import { useAppStore } from "@/hooks/useAppStore";
import { loadConfig, saveConfig, DEFAULT_CONFIG } from "@/lib/config-storage";

export function LLMConfigForm() {
  const { state, dispatch } = useAppStore();
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const loadedRef = useRef(false);

  // 从 localStorage 加载配置（仅在首次挂载时）
  useEffect(() => {
    if (loadedRef.current) return;
    loadedRef.current = true;
    const saved = loadConfig();
    dispatch({
      type: "SET_CONFIG",
      config: {
        llmProvider: saved.llmProvider || DEFAULT_CONFIG.llmProvider,
        llmBaseUrl: saved.llmBaseUrl || DEFAULT_CONFIG.llmBaseUrl,
        llmApiKey: saved.llmApiKey || state.config.llmApiKey,
        llmModelName: saved.llmModelName || DEFAULT_CONFIG.llmModelName,
      },
    });
  }, []);

  const handleChange = (field: string, value: string) => {
    dispatch({
      type: "SET_CONFIG",
      config: { [field]: value },
    });
  };

  // 防抖保存到 localStorage
  useEffect(() => {
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    saveTimerRef.current = setTimeout(() => {
      saveConfig({
        llmProvider: state.config.llmProvider,
        llmBaseUrl: state.config.llmBaseUrl,
        llmApiKey: state.config.llmApiKey,
        llmModelName: state.config.llmModelName,
      });
    }, 500);

    return () => {
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    };
  }, [state.config.llmProvider, state.config.llmBaseUrl, state.config.llmApiKey, state.config.llmModelName]);

  return (
    <div className="space-y-4">
      <div className="p-3 bg-sky-50 dark:bg-sky-900/20 rounded-lg text-sm text-sky-700 dark:text-sky-300">
        主 AI 模型配置，用于执行渗透测试任务
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Provider
        </label>
        <input
          type="text"
          value={state.config.llmProvider}
          onChange={(e) => handleChange("llmProvider", e.target.value)}
          placeholder={DEFAULT_CONFIG.llmProvider}
          className="input-field"
        />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Base URL
        </label>
        <input
          type="text"
          value={state.config.llmBaseUrl}
          onChange={(e) => handleChange("llmBaseUrl", e.target.value)}
          placeholder={DEFAULT_CONFIG.llmBaseUrl}
          className="input-field"
        />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          API Key
        </label>
        <input
          type="password"
          value={state.config.llmApiKey}
          onChange={(e) => handleChange("llmApiKey", e.target.value)}
          placeholder="sk-..."
          className="input-field"
        />
        <p className="mt-1 text-xs text-gray-500">留空则使用 .env 文件中的配置</p>
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Model Name
        </label>
        <input
          type="text"
          value={state.config.llmModelName}
          onChange={(e) => handleChange("llmModelName", e.target.value)}
          placeholder={DEFAULT_CONFIG.llmModelName}
          className="input-field"
        />
      </div>
    </div>
  );
}