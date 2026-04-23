import json
import logging
import re
import sys
import textwrap
import os
from typing import Any, Optional
from datetime import datetime
from pathlib import Path
from contextvars import ContextVar

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def _force_utf8_stdio() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


_force_utf8_stdio()


# ⭐ 新增：当前题目的上下文变量（用于多线程日志隔离）
# 使用 contextvars 而不是 threading.local，因为支持 asyncio
_current_challenge_code: ContextVar[Optional[str]] = ContextVar('current_challenge_code', default=None)
_challenge_loggers: dict[str, logging.Logger] = {}  # 题目 -> Logger 映射

# 彩色代码
RESET = "\033[0m"
CATEGORY_STYLES = {
    "LLM": "\033[95m",
    "TOOL": "\033[96m",
    "STATE": "\033[92m",
    "SECURITY": "\033[93m",
    "SYSTEM": "\033[94m",
}
LEVEL_STYLES = {
    "DEBUG": "\033[37m",
    "INFO": "\033[97m",
    "WARNING": "\033[93m",
    "ERROR": "\033[91m",
    "CRITICAL": "\033[41m",
}


def _supports_color() -> bool:
    """检测当前终端是否支持彩色输出。"""
    return sys.stdout.isatty()


_COLOR_ENABLED = _supports_color()


class ColoredConsoleFormatter(logging.Formatter):
    """带颜色的控制台格式化器"""
    
    def format(self, record):
        # 保存原始消息
        original_msg = record.getMessage()
        
        # 应用彩色（如果终端支持）
        if _COLOR_ENABLED and hasattr(record, 'category'):
            category = record.category.upper()
            style = CATEGORY_STYLES.get(category, "")
            if style:
                # 只给 [CATEGORY] 部分上色
                record.msg = record.msg.replace(f"[{category}]", f"{style}[{category}]{RESET}")
        
        return super().format(record)


class PlainFileFormatter(logging.Formatter):
    """纯文本文件格式化器（不带颜色代码）"""
    
    def format(self, record):
        # 确保文件中不包含任何颜色代码
        formatted = super().format(record)
        # 移除所有 ANSI 颜色代码
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', formatted)


# 全局 logger 实例（单例模式）
_logger_initialized = False
logger = None


def _init_logger():
    """初始化 logger（单例模式，只执行一次）"""
    global _logger_initialized, logger

    if _logger_initialized:
        return logger

    # 创建日志目录
    LOG_DIR = Path(__file__).parent.parent / "logs"
    LOG_DIR.mkdir(exist_ok=True)

    # 生成日志文件名（按日期时间）
    log_filename = f"shell_agent_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_filepath = LOG_DIR / log_filename

    # 配置 logger
    logger = logging.getLogger("ShellAgent")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()  # 清除已有的 handler

    # 控制台处理器（带颜色）
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColoredConsoleFormatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(console_handler)

    # 文件处理器（纯文本）
    file_handler = logging.FileHandler(log_filepath, encoding='utf-8')
    file_handler.setFormatter(PlainFileFormatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(file_handler)

    logger.propagate = False

    # 记录日志文件位置（只打印一次）
    print(f"📁 日志文件: {log_filepath}")
    print(f"📁 日志目录: {LOG_DIR}\n")

    _logger_initialized = True
    return logger


# 初始化 logger（模块导入时执行一次）
logger = _init_logger()


# ⭐ 新增：题目日志管理
def set_challenge_context(challenge_code: str, retry_count: int = 0):
    """
    设置当前题目上下文（在解题任务开始时调用）

    Args:
        challenge_code: 题目代码（如 "web001"）
        retry_count: 重试次数（0 = 首次尝试，1 = 第1次重试，...）

    作用：
    - 设置当前线程的题目上下文
    - 创建该题目的独立日志文件（首次）或复用已有文件（重试）
    """
    global _challenge_loggers

    # 设置上下文变量
    _current_challenge_code.set(challenge_code)

    # 如果该题目的 logger 已存在，记录重试分隔符后直接返回
    if challenge_code in _challenge_loggers:
        challenge_logger = _challenge_loggers[challenge_code]
        # ⭐ 添加重试分隔符
        separator = f"\n{'='*80}\n🔄 重试 #{retry_count} 开始（{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}）\n{'='*80}\n"
        challenge_logger.info(separator)
        return

    # 创建题目日志目录
    LOG_DIR = Path(__file__).parent.parent / "logs"
    CHALLENGE_LOG_DIR = LOG_DIR / "challenges"
    CHALLENGE_LOG_DIR.mkdir(exist_ok=True)

    # 生成题目日志文件名
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    challenge_log_filename = f"{challenge_code}_{timestamp}.log"
    challenge_log_filepath = CHALLENGE_LOG_DIR / challenge_log_filename

    # 创建题目专属 logger
    challenge_logger = logging.getLogger(f"ShellAgent.{challenge_code}")
    challenge_logger.setLevel(logging.INFO)
    challenge_logger.handlers.clear()

    # 只写入文件，不输出到控制台（避免重复）
    file_handler = logging.FileHandler(challenge_log_filepath, encoding='utf-8')
    file_handler.setFormatter(PlainFileFormatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    challenge_logger.addHandler(file_handler)

    challenge_logger.propagate = False

    # 保存到全局字典
    _challenge_loggers[challenge_code] = challenge_logger

    # 记录题目日志文件位置
    logger.info(f"📝 题目日志: {challenge_log_filepath}")

    # ⭐ 添加首次尝试的标记
    if retry_count == 0:
        header = f"\n{'='*80}\n🎯 题目: {challenge_code} - 首次尝试（{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}）\n{'='*80}\n"
    else:
        header = f"\n{'='*80}\n🔄 重试 #{retry_count} 开始（{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}）\n{'='*80}\n"
    challenge_logger.info(header)


def clear_challenge_context():
    """清除当前题目上下文（在解题任务结束时调用）"""
    _current_challenge_code.set(None)


def get_current_challenge_logger() -> Optional[logging.Logger]:
    """获取当前题目的 logger（如果存在）"""
    challenge_code = _current_challenge_code.get()
    if challenge_code:
        return _challenge_loggers.get(challenge_code)
    return None


def _apply_style(style: str, text: str) -> str:
    """Apply color style for console output."""
    if not _COLOR_ENABLED or not style:
        return text
    return f"{style}{text}{RESET}"


def _repair_mojibake(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text
    suspicious_markers = (
        "\u95c1", "\u93c9", "\u951f", "\u923f", "\u9983", "\ufffd", "Ã", "Â", "Ð", "Ñ",
        "鎻", "寤", "鍙", "鍏", "鏈", "绔", "澶", "鏈", "鍘", "妫", "娴", "婕", "鎴",
    )
    if not any(m in text for m in suspicious_markers):
        return text

    candidates = [text]
    for enc, dec in (("latin1", "utf-8"), ("gb18030", "utf-8"), ("gbk", "utf-8")):
        try:
            candidates.append(text.encode(enc, errors="strict").decode(dec, errors="strict"))
        except Exception:
            continue

    def bad_score(s: str) -> tuple[int, int]:
        bad_hits = sum(s.count(m) for m in suspicious_markers)
        replacement_hits = s.count("\ufffd")
        return (bad_hits, replacement_hits)

    return min(candidates, key=bad_score)


def normalize_text_content(text: Any) -> str:
    """
    Normalize LLM-facing text before it is re-used in prompts/state/logs.

    This keeps accidental mojibake, NUL bytes, and excessive blank lines from
    polluting later planning rounds.
    """
    value = str(text or "")
    if not value:
        return ""
    value = value.replace("\x00", "")
    value = _repair_mojibake(value)
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = value.replace("\ufeff", "")
    value = "\n".join(line.rstrip() for line in value.split("\n"))
    value = value.strip()
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value


def calibrated_finding_probability(finding: Any) -> float:
    """
    Convert internal heuristic finding signals into a conservative user-facing
    existence estimate.
    """
    if not isinstance(finding, dict):
        return 0.0

    def _num(value: Any) -> Optional[float]:
        if isinstance(value, (int, float)):
            return float(value)
        return None

    explicit_existence = _num(finding.get("existence_rate"))
    if explicit_existence is None:
        explicit_existence = _num(finding.get("type_probability"))
    if explicit_existence is not None:
        return max(0.0, min(1.0, explicit_existence))

    score = _num(finding.get("score"))
    confidence = _num(finding.get("confidence"))
    base = score if score is not None else confidence
    if base is None:
        base = 0.0
    if score is None and confidence is not None:
        base = confidence * 0.6

    checks = dict(finding.get("verification_checks") or {})
    runtime_signal = bool(checks.get("runtime_signal"))
    explicit_success = bool(checks.get("explicit_success_signal"))
    has_request = bool(checks.get("has_request_evidence"))
    has_response = bool(checks.get("has_response_evidence"))
    no_negative_signal = bool(checks.get("no_negative_signal", True))
    not_status_only = bool(checks.get("not_status_only", True))
    strict_verified = bool(finding.get("strict_verified", False))
    status = str(finding.get("status") or "").strip().lower()
    cve_verdict = str(finding.get("cve_verdict") or "").strip().lower()

    if runtime_signal:
        base += 0.14
    if explicit_success:
        base += 0.10
    if has_request:
        base += 0.04
    if has_response:
        base += 0.04
    if not no_negative_signal:
        base -= 0.18
    if not not_status_only:
        base -= 0.12

    if strict_verified and status == "confirmed":
        base = max(base, 0.95)
    elif status == "confirmed":
        base = min(max(base, 0.72), 0.89)
    elif status == "suspected":
        if not runtime_signal and not explicit_success:
            base = min(base, 0.49)
        else:
            base = min(base, 0.74)
    elif status == "rejected":
        base = min(base, 0.20)

    if cve_verdict == "confirmed" and strict_verified and status == "confirmed":
        base += 0.02

    return max(0.0, min(1.0, base))


def calibrated_cve_probability(finding: Any, type_probability: Optional[float] = None) -> float:
    """
    Conservative CVE attribution probability, separated from workflow score and
    vulnerability existence estimate.
    """
    if not isinstance(finding, dict):
        return 0.0

    if type_probability is None:
        type_probability = calibrated_finding_probability(finding)
    type_probability = max(0.0, min(1.0, float(type_probability or 0.0)))

    cve = str(finding.get("cve") or "").strip()
    if not cve:
        return 0.0

    explicit_prob = finding.get("cve_probability")
    if isinstance(explicit_prob, (int, float)):
        return max(0.0, min(1.0, float(explicit_prob)))

    base = 0.0
    cve_confidence = finding.get("cve_confidence")
    if isinstance(cve_confidence, (int, float)):
        base = float(cve_confidence)

    verdict = str(finding.get("cve_verdict") or "").strip().lower()
    status = str(finding.get("status") or "").strip().lower()
    strict_verified = bool(finding.get("strict_verified"))

    if verdict == "confirmed":
        base = max(base, 0.78)
    elif verdict == "weak_match":
        base = min(max(base, 0.28), 0.62)
    elif verdict in {"unverified", "invalid_format"}:
        base = min(max(base, 0.10), 0.32)
    else:
        base = min(base, 0.20)

    if not strict_verified or status != "confirmed":
        base = min(base, type_probability * 0.75)
    else:
        base = min(base, type_probability)

    return max(0.0, min(1.0, base))


def has_strong_verification_signal(finding: Any) -> bool:
    if not isinstance(finding, dict):
        return False
    if bool(finding.get("strict_verified", False)):
        return True
    checks = dict(finding.get("verification_checks") or {})
    return bool(checks.get("runtime_signal")) or bool(checks.get("explicit_success_signal"))


def is_high_value_active_finding(finding: Any) -> bool:
    if not isinstance(finding, dict):
        return False
    status = str(finding.get("status") or "").strip().lower()
    if status not in {"suspected", "confirmed"}:
        return False
    if has_strong_verification_signal(finding):
        return True
    checks = dict(finding.get("verification_checks") or {})
    has_req = bool(checks.get("has_request_evidence"))
    has_resp = bool(checks.get("has_response_evidence"))
    score = calibrated_finding_probability(finding)
    cve_verdict = str(finding.get("cve_verdict") or "").strip().lower()
    if status == "confirmed":
        return cve_verdict == "confirmed" and has_req and has_resp and score >= 0.68
    return score >= 0.68 and has_req and has_resp and cve_verdict == "confirmed"


def is_actionable_confirmed_finding(finding: Any) -> bool:
    if not isinstance(finding, dict):
        return False
    status = str(finding.get("status") or "").strip().lower()
    if status != "confirmed":
        return False
    return has_strong_verification_signal(finding) or is_high_value_active_finding(finding)


def is_actionable_suspected_finding(finding: Any) -> bool:
    if not isinstance(finding, dict):
        return False
    status = str(finding.get("status") or "").strip().lower()
    if status != "suspected":
        return False
    return is_high_value_active_finding(finding)


def count_actionable_findings(findings: Any) -> dict[str, int]:
    values = [item for item in list(findings or []) if isinstance(item, dict)]
    confirmed = sum(1 for item in values if is_actionable_confirmed_finding(item))
    suspected = sum(1 for item in values if is_actionable_suspected_finding(item))
    rejected = sum(1 for item in values if (item.get("status") or "").strip().lower() == "rejected")
    return {
        "confirmed": confirmed,
        "suspected": suspected,
        "rejected": rejected,
        "total": len(values),
    }


def has_actionable_confirmed_findings(findings: Any) -> bool:
    return count_actionable_findings(findings).get("confirmed", 0) > 0


def has_actionable_active_findings(findings: Any) -> bool:
    counts = count_actionable_findings(findings)
    return counts.get("confirmed", 0) > 0 or counts.get("suspected", 0) > 0


def _normalize_log_value(value: Any) -> Any:
    if isinstance(value, str):
        return normalize_text_content(value)
    if isinstance(value, list):
        return [_normalize_log_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _normalize_log_value(v) for k, v in value.items()}
    return value

def _format_payload(payload: Any) -> Optional[str]:
    if payload is None:
        return None
    payload = _normalize_log_value(payload)
    if isinstance(payload, (dict, list)):
        text = json.dumps(payload, ensure_ascii=False, indent=2)
    else:
        text = str(payload)
    return textwrap.indent(text, "  ")

def _log_with_category(category: str, title: str, payload: Any, *, level: int) -> None:
    """
    记录日志（控制台带颜色，文件纯文本）

    ⭐ 双日志系统：
    - 全局日志：所有题目的日志混合（用于查看整体进度）
    - 题目日志：当前题目的独立日志（用于深入分析）
    """
    category_key = category.upper()
    style = CATEGORY_STYLES.get(category_key, "")

    # 构建消息（带颜色标记）
    label = _apply_style(style, f"[{category_key}]")
    safe_title = _repair_mojibake(str(title))
    message_lines = [f"{label} {safe_title}"]
    formatted_payload = _format_payload(payload)
    if formatted_payload:
        message_lines.append(formatted_payload)
    message = "\n".join(message_lines)

    # 确保 level 是整数
    if not isinstance(level, int):
        raise TypeError(f"level must be an integer, got {type(level)} with value {level}")

    # 添加 category 属性用于格式化器识别
    extra = {'category': category_key}

    # 1. 写入全局日志（始终写入）
    logger.log(level, message, extra=extra)

    # 2. 写入题目日志（如果存在）
    challenge_logger = get_current_challenge_logger()
    if challenge_logger:
        challenge_logger.log(level, message, extra=extra)


def log_agent_thought(title: str, payload: Any = None) -> None:
    """记录LLM的思考与输出。"""
    _log_with_category("LLM", title, payload, level=logging.INFO)


def log_tool_event(title: str, payload: Any = None, *, level: int = logging.INFO) -> None:
    """记录工具调用及其结果。"""
    _log_with_category("TOOL", title, payload, level=level)


def log_state_update(title: str, payload: Any = None, *, level: int = logging.INFO) -> None:
    """记录状态更新或关键结论。"""
    _log_with_category("STATE", title, payload, level=level)


def log_security_event(title: str, payload: Any = None, *, level: int = logging.INFO) -> None:
    """记录安全审查相关的消息。"""
    _log_with_category("SECURITY", title, payload, level=level)


def log_system_event(title: str, payload: Any = None, *, level: int = logging.INFO) -> None:
    """记录系统级别的提示，如初始化等。"""
    _log_with_category("SYSTEM", title, payload, level=level)


