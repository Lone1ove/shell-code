import os
from typing import Optional

from langchain_core.language_models import BaseChatModel
from langchain_deepseek import ChatDeepSeek
from langchain_openai import ChatOpenAI

from shell_agent.common import log_system_event
from shell_agent.config import AgentConfig, _is_placeholder_key, _normalize_base_url


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except Exception:
        return default


def _int_env(name: str, default: int, minimum: int = 0) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except Exception:
        return default
    if value < minimum:
        return default
    return value


def _normalize_provider(provider: Optional[str], default: str = "openai") -> str:
    normalized = (provider or default).strip().lower()
    aliases = {
        "minimax": "openai",
        "openai-compatible": "openai",
        "siliconflow": "openai",
        "deepseek-compatible": "deepseek",
    }
    return aliases.get(normalized, normalized or default)


def _advisor_runtime_settings(config: AgentConfig) -> tuple[str, str, str, str, bool]:
    provider = os.getenv("ADVISOR_PROVIDER", "").strip()
    api_key = os.getenv("ADVISOR_API_KEY", "").strip()
    base_url = os.getenv("ADVISOR_BASE_URL", "").strip()
    model_name = os.getenv("ADVISOR_MODEL_NAME", "").strip()

    has_dedicated_config = any([provider, api_key, base_url, model_name])
    if not has_dedicated_config:
        return (
            _normalize_provider(os.getenv("LLM_PROVIDER", "deepseek"), "deepseek"),
            config.llm_base_url,
            config.llm_api_key,
            config.llm_model_name,
            False,
        )

    fallback_reason = None
    if api_key and _is_placeholder_key(api_key):
        fallback_reason = "ADVISOR_API_KEY 仍是占位符"
    elif base_url:
        try:
            base_url = _normalize_base_url(base_url, config.llm_base_url)
        except ValueError as exc:
            fallback_reason = str(exc)

    if fallback_reason:
        log_system_event(
            "[模型] 顾问模型配置无效，已回退到主模型配置",
            {
                "reason": fallback_reason,
                "advisor_provider": provider or "(empty)",
                "advisor_model": model_name or "(empty)",
                "advisor_base_url": base_url or "(empty)",
            },
        )
        return (
            _normalize_provider(os.getenv("LLM_PROVIDER", "deepseek"), "deepseek"),
            config.llm_base_url,
            config.llm_api_key,
            config.llm_model_name,
            False,
        )

    return (
        _normalize_provider(provider or os.getenv("LLM_PROVIDER", "deepseek"), "deepseek"),
        base_url or config.llm_base_url,
        api_key or config.llm_api_key,
        model_name or config.llm_model_name,
        True,
    )


def _build_chat_model(
    provider: str,
    base_url: str,
    api_key: str,
    model_name: str,
    temperature: float,
    max_tokens: int,
    timeout: int,
    max_retries: int,
) -> BaseChatModel:
    provider_norm = _normalize_provider(provider)

    if provider_norm in {"deepseek", "lkeap"}:
        safe_max_tokens = min(max_tokens, 8192)
        return ChatDeepSeek(
            api_base=base_url,
            api_key=api_key,
            model=model_name,
            temperature=temperature,
            max_tokens=safe_max_tokens,
            timeout=timeout,
            max_retries=max_retries,
            streaming=False,
        )

    return ChatOpenAI(
        base_url=base_url,
        api_key=api_key,
        model=model_name,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        max_retries=max_retries,
    )


def create_model(
    config: AgentConfig,
    temperature: Optional[float] = None,
    max_tokens: int = 8192,
    timeout: int = 600,
    max_retries: int = 20,
) -> BaseChatModel:
    provider = _normalize_provider(os.getenv("LLM_PROVIDER", "deepseek"), "deepseek")
    if temperature is None:
        temperature = _float_env("MAIN_TEMPERATURE", _float_env("LLM_TEMPERATURE", 0.2))
    model = _build_chat_model(
        provider=provider,
        base_url=config.llm_base_url,
        api_key=config.llm_api_key,
        model_name=config.llm_model_name,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        max_retries=max_retries,
    )

    log_system_event(
        "[模型] 创建主模型实例",
        {
            "provider": provider,
            "model": config.llm_model_name,
            "base_url": config.llm_base_url,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": timeout,
            "max_retries": max_retries,
        },
    )
    return model


def create_advisor_model(config: AgentConfig) -> BaseChatModel:
    advisor_provider, advisor_base_url, advisor_api_key, advisor_model_name, dedicated = _advisor_runtime_settings(config)
    advisor_temperature = _float_env(
        "ADVISOR_TEMPERATURE",
        _float_env("LLM_ADVISOR_TEMPERATURE", 0.3),
    )

    advisor_model = _build_chat_model(
        provider=advisor_provider,
        base_url=advisor_base_url,
        api_key=advisor_api_key,
        model_name=advisor_model_name,
        temperature=advisor_temperature,
        max_tokens=_int_env("ADVISOR_MAX_TOKENS", 8192, minimum=1),
        timeout=_int_env("ADVISOR_TIMEOUT", 600, minimum=1),
        max_retries=_int_env("ADVISOR_MAX_RETRIES", 10, minimum=1),
    )

    log_system_event(
        "[模型] 创建顾问模型实例",
        {
            "provider": advisor_provider,
            "model": advisor_model_name,
            "base_url": advisor_base_url,
            "dedicated_config": dedicated,
        },
    )
    return advisor_model
