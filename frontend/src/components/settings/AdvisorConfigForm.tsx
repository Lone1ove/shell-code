"use client";

import { useEffect, useRef } from "react";
import { useAppStore } from "@/hooks/useAppStore";
import { loadConfig, saveConfig, DEFAULT_CONFIG } from "@/lib/config-storage";

export function AdvisorConfigForm() {
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
        advisorProvider: saved.advisorProvider || DEFAULT_CONFIG.advisorProvider,
        advisorBaseUrl: saved.advisorBaseUrl || DEFAULT_CONFIG.advisorBaseUrl,
        advisorApiKey: saved.advisorApiKey || state.config.advisorApiKey,
        advisorModelName: saved.advisorModelName || DEFAULT_CONFIG.advisorModelName,
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
        advisorProvider: state.config.advisorProvider,
        advisorBaseUrl: state.config.advisorBaseUrl,
        advisorApiKey: state.config.advisorApiKey,
        advisorModelName: state.config.advisorModelName,
      });
    }, 500);

    return () => {
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    };
  }, [state.config.advisorProvider, state.config.advisorBaseUrl, state.config.advisorApiKey, state.config.advisorModelName]);

  return (
    <div className="space-y-4">
      <div className="p-3 bg-purple-50 dark:bg-purple-900/20 rounded-lg text-sm text-purple-700 dark:text-purple-300">
        辅助 AI 模型配置，用于提供策略建议和二次验证
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Provider
        </label>
        <input
          type="text"
          value={state.config.advisorProvider}
          onChange={(e) => handleChange("advisorProvider", e.target.value)}
          placeholder={DEFAULT_CONFIG.advisorProvider}
          className="input-field"
        />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Base URL
        </label>
        <input
          type="text"
          value={state.config.advisorBaseUrl}
          onChange={(e) => handleChange("advisorBaseUrl", e.target.value)}
          placeholder={DEFAULT_CONFIG.advisorBaseUrl}
          className="input-field"
        />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          API Key
        </label>
        <input
          type="password"
          value={state.config.advisorApiKey}
          onChange={(e) => handleChange("advisorApiKey", e.target.value)}
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
          value={state.config.advisorModelName}
          onChange={(e) => handleChange("advisorModelName", e.target.value)}
          placeholder={DEFAULT_CONFIG.advisorModelName}
          className="input-field"
        />
      </div>
    </div>
  );
}