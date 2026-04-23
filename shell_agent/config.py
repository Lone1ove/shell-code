import os
from typing import Any, Optional
from urllib.parse import urlparse

from dotenv import load_dotenv


def _is_placeholder_key(value: Optional[str]) -> bool:
    if not value:
        return True
    normalized = value.strip().lower()
    placeholders = {
        "sk-xxx",
        "your-api-key-here",
        "your-api-key",
        "changeme",
        "replace_me",
    }
    return normalized in placeholders or "xxx" in normalized


class AgentConfig:
    def __init__(
        self,
        llm_api_key: str,
        llm_base_url: str,
        llm_model_name: str = "deepseek-v3.1-terminus",
        env_mode: str = "pentest",
        docker_container_name: Optional[str] = None,
        sandbox_enabled: bool = False,
        sandbox_name: str = "Shell-sandbox",
    ):
        self.llm_api_key = llm_api_key
        self.llm_base_url = llm_base_url
        self.llm_model_name = llm_model_name
        self.env_mode = env_mode
        self.docker_container_name = docker_container_name
        self.sandbox_enabled = sandbox_enabled
        self.sandbox_name = sandbox_name


def _normalize_base_url(value: Optional[str], default: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return default
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"配置错误: 非法的 Base URL: {raw}")
    return raw.rstrip("/")


def _optional_runtime_value(name: str) -> Optional[str]:
    value = os.getenv(name, "").strip()
    if not value or _is_placeholder_key(value):
        return None
    return value


def summarize_runtime_config(config: AgentConfig) -> dict[str, Any]:
    advisor_provider = (os.getenv("ADVISOR_PROVIDER") or os.getenv("LLM_PROVIDER", "deepseek")).strip()
    advisor_api_key = _optional_runtime_value("ADVISOR_API_KEY")
    advisor_base_url = os.getenv("ADVISOR_BASE_URL", "").strip()
    advisor_model_name = os.getenv("ADVISOR_MODEL_NAME", "").strip()
    dedicated_advisor = any(
        [
            bool(os.getenv("ADVISOR_PROVIDER", "").strip()),
            bool(advisor_api_key),
            bool(advisor_base_url),
            bool(advisor_model_name),
        ]
    )

    return {
        "main_provider": (os.getenv("LLM_PROVIDER", "deepseek")).strip() or "deepseek",
        "main_model": config.llm_model_name,
        "main_base_url": config.llm_base_url,
        "advisor_provider": advisor_provider or "deepseek",
        "advisor_model": advisor_model_name or config.llm_model_name,
        "advisor_base_url": advisor_base_url.rstrip("/") if advisor_base_url else config.llm_base_url,
        "advisor_uses_dedicated_config": dedicated_advisor,
        "advisor_has_dedicated_api_key": bool(advisor_api_key),
        "env_mode": config.env_mode,
        "sandbox_enabled": config.sandbox_enabled,
        "docker_container_name": config.docker_container_name or "",
    }


def validate_runtime_environment(config: AgentConfig) -> dict[str, Any]:
    config.llm_base_url = _normalize_base_url(config.llm_base_url, "https://api.deepseek.com/v1")
    summary = summarize_runtime_config(config)

    advisor_base_url = os.getenv("ADVISOR_BASE_URL", "").strip()
    if advisor_base_url:
        summary["advisor_base_url"] = _normalize_base_url(advisor_base_url, config.llm_base_url)

    optional_int_fields = (
        "ADVISOR_MAX_TOKENS",
        "ADVISOR_TIMEOUT",
        "ADVISOR_MAX_RETRIES",
        "MAX_RETRIES",
        "MAX_CONCURRENT_TASKS",
    )
    for name in optional_int_fields:
        raw = os.getenv(name, "").strip()
        if not raw:
            continue
        try:
            value = int(raw)
        except ValueError as exc:
            raise ValueError(f"配置错误: {name} 不是合法整数: {raw}") from exc
        if value < 0:
            raise ValueError(f"配置错误: {name} 不能小于 0: {value}")
        if name in {"ADVISOR_MAX_TOKENS", "ADVISOR_TIMEOUT", "ADVISOR_MAX_RETRIES", "MAX_CONCURRENT_TASKS"} and value < 1:
            raise ValueError(f"配置错误: {name} 不能小于 1: {value}")

    for name in ("MAIN_TEMPERATURE", "LLM_TEMPERATURE", "ADVISOR_TEMPERATURE", "LLM_ADVISOR_TEMPERATURE"):
        raw = os.getenv(name, "").strip()
        if not raw:
            continue
        try:
            float(raw)
        except ValueError as exc:
            raise ValueError(f"配置错误: {name} 不是合法数字: {raw}") from exc

    return summary


def load_agent_config() -> AgentConfig:
    load_dotenv()

    llm_api_key = (
        os.getenv("LLM_API_KEY")
        or os.getenv("DEEPSEEK_API_KEY")
        or os.getenv("OPENAI_API_KEY")
    )
    if not llm_api_key:
        raise ValueError(
            "配置错误: 未找到 LLM API Key。请设置 LLM_API_KEY（或兼容的 DEEPSEEK_API_KEY/OPENAI_API_KEY）。"
        )
    if _is_placeholder_key(llm_api_key):
        raise ValueError(
            "配置错误: LLM_API_KEY（或兼容 Key）仍是占位符，请填写真实可用的 API Key。"
        )

    llm_base_url = _normalize_base_url(
        os.getenv(
            "LLM_BASE_URL",
            os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
        ),
        "https://api.deepseek.com/v1",
    )
    llm_model_name = os.getenv("LLM_MODEL_NAME", "deepseek-v3.1-terminus")

    env_mode = os.getenv("ENV_MODE", "pentest").strip().lower()
    if not env_mode:
        env_mode = "pentest"

    docker_container_name = os.getenv("DOCKER_CONTAINER_NAME")
    sandbox_enabled = os.getenv("SANDBOX_ENABLED", "false").lower() == "true"
    sandbox_name = os.getenv("SANDBOX_NAME", "Shell-sandbox")

    return AgentConfig(
        llm_api_key=llm_api_key,
        llm_base_url=llm_base_url,
        llm_model_name=llm_model_name,
        env_mode=env_mode,
        docker_container_name=docker_container_name,
        sandbox_enabled=sandbox_enabled,
        sandbox_name=sandbox_name,
    )
