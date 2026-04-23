"""
Retry strategy module.
"""

import os
from typing import Tuple

from shell_agent.common import log_system_event
from shell_agent.model import create_advisor_model, create_model


class RetryStrategy:
    """Manage the fixed main/advisor LLM pair used across retries."""

    def __init__(self, config):
        self.config = config
        self.main_llm = create_model(config=config)
        try:
            self.advisor_llm = create_advisor_model(config=config)
        except Exception as exc:
            log_system_event(
                "[重试策略] 顾问模型初始化失败，已回退到主模型实例",
                {"error": str(exc)},
            )
            self.advisor_llm = self.main_llm
        self.enable_role_swap = os.getenv("ENABLE_ROLE_SWAP_RETRY", "false").strip().lower() == "true"

        self.same_model_instance = self.main_llm is self.advisor_llm

        log_system_event(
            "[重试策略] 初始化完成",
            {
                "main_model": config.llm_model_name,
                "advisor_model": os.getenv("ADVISOR_MODEL_NAME") or config.llm_model_name,
                "same_instance": self.same_model_instance,
                "role_swap_enabled": self.enable_role_swap,
            },
        )

    def get_llm_pair(self, retry_count: int) -> Tuple[object, object, str]:
        """
        Return (main_llm, advisor_llm, strategy_description) by retry count.
        """
        if self.same_model_instance:
            return self.main_llm, self.advisor_llm, "Single-Provider Fixed Roles"

        if not self.enable_role_swap:
            if retry_count > 0:
                return self.main_llm, self.advisor_llm, f"Fixed Roles (retry {retry_count})"
            return self.main_llm, self.advisor_llm, "Fixed Roles (main + advisor)"

        is_even = retry_count % 2 == 0
        if is_even:
            strategy_desc = "Primary (main) + Advisor"
            if retry_count > 0:
                strategy_desc += f" [retry {retry_count}]"
            return self.main_llm, self.advisor_llm, strategy_desc

        log_system_event(
            "[重试策略] 角色互换：Advisor 作为主控模型",
            {"retry_count": retry_count},
        )
        return (
            self.advisor_llm,
            self.main_llm,
            f"Advisor (main) + Primary [retry {retry_count}]",
        )

    @staticmethod
    def format_attempt_history(attempt_history: list) -> str:
        if not attempt_history:
            return ""

        formatted_parts = ["## 历史尝试记录（避免重复失败路径）\n"]

        for i, attempt in enumerate(attempt_history, 1):
            strategy = attempt.get("strategy", "unknown")
            attempts_count = attempt.get("attempts", 0)
            failed_methods = attempt.get("failed_methods", [])
            key_findings = attempt.get("key_findings", [])

            formatted_parts.append(f"\n### 尝试 {i}: {strategy}\n")
            formatted_parts.append(f"- 工具调用数: {attempts_count}\n")

            if failed_methods:
                formatted_parts.append("- 已失败的方法:\n")
                for method in failed_methods[:10]:
                    formatted_parts.append(f"  - {method}\n")

            if key_findings:
                formatted_parts.append("- 关键发现:\n")
                for finding in key_findings[:5]:
                    formatted_parts.append(f"  - {finding}\n")

        formatted_parts.append("\n请优先换验证思路，不要机械重复同一路径。\n")
        return "".join(formatted_parts)

    @staticmethod
    def extract_attempt_summary(final_state: dict, strategy: str) -> dict:
        action_history = final_state.get("action_history", [])
        messages = final_state.get("messages", [])

        failed_methods = []
        for action in action_history:
            lowered = str(action).lower()
            if any(keyword in lowered for keyword in ["失败", "错误", "error", "failed"]):
                failed_methods.append(str(action))

        key_findings = final_state.get("potential_vulnerabilities", [])
        attempts_count = len([m for m in messages if hasattr(m, "tool_calls") and m.tool_calls])

        return {
            "strategy": strategy,
            "attempts": attempts_count,
            "failed_methods": failed_methods,
            "key_findings": [str(v) for v in key_findings] if key_findings else [],
            "timestamp": final_state.get("start_time"),
        }
