"use client";

import { Settings as SettingsIcon } from "lucide-react";
import { CollapsibleSection } from "@/components/ui/CollapsibleSection";
import { LLMConfigForm } from "@/components/settings/LLMConfigForm";
import { AdvisorConfigForm } from "@/components/settings/AdvisorConfigForm";

export function SettingsView() {
  return (
    <div className="max-w-4xl mx-auto px-4 lg:px-6 py-8">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-6 flex items-center gap-2">
        <SettingsIcon className="w-6 h-6" />
        系统设置
      </h1>

      <div className="space-y-6">
        <CollapsibleSection title="LLM 配置" icon={<SettingsIcon className="w-4 h-4" />} defaultOpen={true}>
          <LLMConfigForm />
        </CollapsibleSection>

        <CollapsibleSection title="Advisor 配置" icon={<SettingsIcon className="w-4 h-4" />} defaultOpen={true}>
          <AdvisorConfigForm />
        </CollapsibleSection>

        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            关于
          </h3>
          <div className="text-sm text-gray-500 dark:text-gray-400 space-y-2">
            <p>Shell-Agent - 自动化渗透测试</p>
            <p>版本: 1.0.0</p>
            <p>基于大语言模型的自动化渗透测试系统</p>
          </div>
        </div>
      </div>
    </div>
  );
}
