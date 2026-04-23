"""
智能失败检测模块
=====================================

使用 LLM 进行语义层面的失败检测，避免简单关键字匹配的局限性。

作者：shell-agent
日期：2025-11-11
"""
import logging
import re
from typing import Optional, Tuple
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage

from shell_agent.common import log_system_event, normalize_text_content
from shell_agent.utils.util import retry_llm_call


# ==================== 配置：跳过智能检测的工具白名单 ====================
# 这些工具有明确的成功/失败标识，不需要 LLM 语义检测
SKIP_DETECTION_TOOLS = {
    "submit_flag",           # 已有 flag_validator 验证，返回明确的"答案正确"/"答案错误"
    "get_challenge_list",    # API 调用，HTTP 状态码足够判断成功/失败
    "view_challenge_hint",   # API 调用，返回格式固定
}


def _normalize_detection_text(tool_output: str) -> str:
    value = normalize_text_content(tool_output)
    return value if value else str(tool_output or "")


def _has_positive_verification_signal(text: str) -> bool:
    lower = text.lower()
    markers = [
        "[result] pass",
        "result: pass",
        "结论: pass",
        "[结论] pass",
        "verdict: pass",
        "[success]",
        "success: marker",
        "pass - vulnerability confirmed",
        "vulnerability confirmed",
        "[status] vulnerable",
        "vulnerable: true",
        '"vulnerable": true',
        "漏洞存在",
        "确认漏洞",
        "uid=",
        "gid=",
        "whoami",
        "root:x:",
        "x-check: s2-045-test",
        "x-cmd-result:",
        "x-user-name:",
        "x-test-bypass: ok",
        "command execution successful",
        "exploit success",
        "response header injection successful",
        "response header contains x-ognl-test",
        "response header contains x-cmd-result",
        "response header contains x-check",
        "response header contains x-user-name",
        "found in response header",
        "found in response header x-ognl-verify",
        "x-ognl-verify",
        "ognl_verify_",
        "deterministic evidence of ognl expression execution",
        "ognl injection works and response contains",
    ]
    negative_context_markers = [
        "expected marker",
        "expected result",
        "if ognl injection works",
        "if command execution works",
        "payload:",
        "payload command:",
        "no command output",
        "no command execution detected",
        "not vulnerable",
        "failed",
        "verdict: fail",
        "result: fail",
    ]
    for line in lower.splitlines():
        if not any(marker in line for marker in markers):
            continue
        if any(marker in line for marker in negative_context_markers):
            continue
        return True
    return False


def _has_negative_verification_signal(text: str) -> bool:
    lower = text.lower()
    markers = [
        "[result] fail",
        "result: fail",
        "[---] result: fail",
        "结论: fail",
        "[结论] fail",
        "final result: fail",
        "not vulnerable",
        "vulnerable: false",
        '"vulnerable": false',
        "未检测到",
        "未发现",
        "failed to exploit",
        "payload not executed",
        "execution failed",
        "failed or blocked",
        "verdict: fail",
        "rce blocked",
        "no rce evidence",
        "no rce evidence found",
        "no command injection vulnerability detected",
        "no 'uid=' markers found",
        "no uid= markers found",
        "no command output",
        "no ognl evaluation detected",
        "no command execution detected",
        "response does not contain",
        "could not find",
        "target may not be vulnerable",
        "contains '54289': false",
        "contains 'vuln_check_12345': false",
        "contains 'echo': false",
        "status: not vulnerable",
    ]
    return any(marker in lower for marker in markers)


def _has_transport_failure_signal(text: str) -> bool:
    lower = text.lower()
    markers = [
        "connection broken",
        "incomplete read",
        "incompleteread",
        "remote end closed connection",
        "remotedisconnected",
        "chunkedencodingerror",
        "protocolerror",
        "connection aborted",
        "connection reset by peer",
        "broken pipe",
        "read timed out",
        "readtimeout",
        "unexpected eof",
        "ssl: unexpected eof",
    ]
    return any(marker in lower for marker in markers)


def _has_partial_processing_signal(text: str) -> bool:
    lower = text.lower()
    markers = [
        "processing detected",
        "ognl processing detected",
        "struts/ognl processing detected",
        "x-ognl header present: false",
        "header present: false",
        "injection not successful",
        "利用不完整",
        "注入未成功",
        "未成功",
    ]
    return any(marker in lower for marker in markers)


def _extract_final_verdict(text: str) -> str:
    normalized = _normalize_detection_text(text)
    if not normalized:
        return "unknown"
    lower = normalized.lower()
    matches = []
    patterns = [
        r"\bverdict\s*[:=\]]\s*(pass|fail)\b",
        r"\bresult\s*[:=\]]\s*(pass|fail)\b",
        r"\bfinal result\s*[:=]\s*(pass|fail)\b",
        r"\[结论\]\s*(pass|fail)\b",
        r"结论\s*[:：]\s*(pass|fail)\b",
    ]
    for pattern in patterns:
        for m in re.finditer(pattern, lower, flags=re.IGNORECASE):
            matches.append((m.start(), m.group(1).lower()))
    if not matches:
        return "unknown"
    matches.sort(key=lambda x: x[0])
    return matches[-1][1]


def _is_surface_only_positive(text: str) -> bool:
    lower = text.lower()
    positive_surface_markers = [
        "endpoint accepts multipart post requests",
        "exposes controllable upload surface",
        "surface verification",
        "surface-pivot verification",
        "controllable upload surface",
        "upload functionality detected",
        "supports get and post requests",
        "endpoint exists and is reachable",
        "file upload endpoint",
        "testing common upload parameter names",
        "testing post with multipart/form-data",
        "upload-related keywords found",
        "contains multipart enctype",
        "response differs from get baseline - parameterized behavior detected",
        "surface pivot:",
    ]
    regex_surface_markers = [
        r"found\s+\d+\s+form\(s\)",
        r"found\s+\d+\s+input field\(s\)",
    ]
    strong_runtime_markers = [
        "uid=",
        "gid=",
        "root:x:",
        "vulnerability confirmed",
        "command execution successful",
        "response header contains x-ognl-test",
        "response header injection successful",
        '"vulnerable": true',
    ]
    has_surface_marker = any(marker in lower for marker in positive_surface_markers) or any(
        re.search(pattern, lower) for pattern in regex_surface_markers
    )
    return has_surface_marker and not any(
        marker in lower for marker in strong_runtime_markers
    )


def _deterministic_failure_detection(tool_output: str) -> Optional[Tuple[bool, str, str]]:
    normalized = _normalize_detection_text(tool_output)
    lower = normalized.lower()

    if "submit_flag: command not found" in lower:
        message = (
            "submit_flag 是 LangChain 工具，不是 shell 命令。"
            "请直接调用 submit_flag 工具。"
        )
        return True, message, f"• {message}"

    exit_code_zero = "exit code: 0" in lower
    nonzero_exit_match = None
    for marker in [
        "exit code: 1",
        "exit code: 2",
        "exit code: 126",
        "exit code: 127",
        "traceback (most recent call last)",
        "unhandled exception",
        "exception:",
        "command not found",
    ]:
        if marker in lower:
            nonzero_exit_match = marker
            break

    has_positive = _has_positive_verification_signal(normalized)
    has_negative = _has_negative_verification_signal(normalized)
    final_verdict = _extract_final_verdict(normalized)
    has_transport_failure = _has_transport_failure_signal(normalized)
    has_partial_processing = _has_partial_processing_signal(normalized)
    has_surface_only_positive = _is_surface_only_positive(normalized)
    has_final_fail_verdict = any(
        marker in lower
        for marker in [
            "result: fail",
            "[---] result: fail",
            "final result: fail",
            "verdict: fail - no command injection vulnerability detected",
            "no rce evidence found",
            "rce blocked",
            "no command output",
            "no ognl evaluation detected",
        ]
    )
    has_explicit_final_pass = any(
        marker in lower
        for marker in [
            "verdict: pass",
            "result: pass",
            "[result] pass",
            "final result: pass",
            "结论: pass",
        ]
    )
    if final_verdict == "pass":
        has_negative = False
        has_positive = True
    elif final_verdict == "fail":
        has_negative = True

    if nonzero_exit_match:
        reason = f"执行器返回失败信号：{nonzero_exit_match}"
        return True, reason, f"• {reason}"

    if has_positive and has_negative and not has_explicit_final_pass:
        reason = "工具输出包含相互矛盾的成功/失败结论，视为验证失败并要求收敛为单一最终结论"
        return True, reason, "• 同时出现 PASS 与 FAIL 信号\n• 当前输出不满足可审计的单一结论要求"

    if has_final_fail_verdict:
        reason = "工具输出包含最终 FAIL 结论，优先级高于中途成功字样和 Exit Code: 0"
        return True, reason, "• 最终 VERDICT 为 FAIL\n• 存在明确负向验证结论"

    if has_negative:
        reason = "工具输出包含明确 FAIL/not vulnerable 结论，优先级高于 Exit Code: 0"
        return True, reason, "• 明确失败结论出现\n• 当前输出不支持漏洞成立"

    if has_transport_failure and not has_positive:
        if has_partial_processing:
            reason = "工具输出只显示部分处理迹象，但缺少成功证据且伴随传输层中断"
            return True, reason, "• 存在弱处理迹象，但未形成明确成功证据\n• 传输层异常中断了验证链\n• 当前结果只能视为未完成验证"
        reason = "工具输出包含传输层异常，当前验证未完成"
        return True, reason, "• 发生连接/读取异常\n• 当前轮次无法作为成功验证依据"

    if has_partial_processing and not has_positive:
        reason = "工具输出只有部分处理迹象，缺少显式成功信号"
        return True, reason, "• 观察到弱处理迹象\n• 未观察到显式成功或运行时成功证据\n• 当前结果更适合作为继续复检的线索"

    if has_surface_only_positive and not has_negative:
        reason = "当前输出仅证明目标 surface 存在或可交互，验证链尚未成立"
        return True, reason, "• 已确认存在可交互 surface 或输入点\n• 尚未观察到运行时漏洞成功证据\n• 当前轮次不能记为漏洞验证成功，只能作为下一步验证线索"

    if has_positive and not has_negative:
        reason = "工具输出包含明确 PASS/运行时成功证据"
        return False, reason, "• 明确成功结论出现\n• 已观察到运行时成功证据"

    if exit_code_zero and has_negative:
        reason = "Exit Code: 0 仅表示脚本执行完成，不代表漏洞验证成功"
        return True, reason, "• 脚本成功运行\n• 但漏洞验证结论为 FAIL/not vulnerable"

    return None


async def detect_failure_with_llm(
    tool_output: str,
    tool_name: str = "unknown",
    llm: BaseChatModel = None,
    limiter = None
) -> Tuple[bool, str, str]:
    """
    使用 LLM 进行语义层面的失败检测，并提取关键信息

    Args:
        tool_output: 工具输出内容
        tool_name: 工具名称
        llm: 用于判断的 LLM
        limiter: 速率限制器

    Returns:
        (is_failure, reason, key_info): 是否失败、失败原因/成功总结、关键信息摘要

    设计理念：
        - 如果成功：key_info 包含关键发现（如发现的漏洞、获取的数据等）
        - 如果失败：reason 说明失败原因，key_info 补充上下文
        - 无论成败，都保留关键信息供 Agent 决策
    """
    tool_output = _normalize_detection_text(tool_output)

    deterministic = _deterministic_failure_detection(tool_output)
    if deterministic is not None:
        is_failure, reason, key_info = deterministic
        log_system_event(
            f"[智能失败检测] {tool_name} → {'❌ 失败' if is_failure else '✅ 成功'}（确定性规则）",
            {
                "tool": tool_name,
                "is_failure": is_failure,
                "reason": reason,
                "key_info": key_info,
            }
        )
        return deterministic

    if llm is None:
        raise ValueError("必须提供 LLM 实例")

    # 构建判断提示词（重点：要求提取关键信息）
    detection_prompt = f"""你是一个安全测试结果分析专家。请分析以下工具执行输出，判断操作是否失败，并提取关键信息。

**工具名称**: {tool_name}

**输出内容**:
```
{tool_output}  
```

**分析任务**:
1. 判断操作是否失败
   - 认证/授权失败：登录失败、密码错误、未授权访问、需要认证等
   - HTTP错误：4xx/5xx状态码、错误响应
   - 业务逻辑失败：虽然HTTP 200但内容包含错误提示（如"Incorrect"、"Failed"、alert-danger等）
   - 执行错误：命令执行失败、异常、超时等

2. 提取关键信息（无论成败都要提取）
   - 成功时：发现的漏洞、获取的数据、暴露的接口、可利用的信息等
   - 失败时：错误类型、阻塞原因、需要的前置条件等

**输出格式**（严格遵守，用---分隔）:
第一行：SUCCESS 或 FAILURE
第二行：---
第三行及之后：关键信息摘要（3-5个要点，每行一个，用 • 开头）

**示例1（失败）**:
FAILURE
---
• 登录失败，返回"Incorrect username or password"
• 需要有效的用户名和密码
• 可能需要先进行用户名枚举

**示例2（成功）**:
SUCCESS
---
• 成功获取API文档，发现3个未授权端点
• 端点路径：/api/users, /api/admin, /api/config
• 返回了用户列表，包含5个用户账号
• 发现admin用户，可能存在权限提升漏洞

现在请分析上述输出："""

    try:
        # 调用 LLM 进行判断（使用速率限制）
        if limiter:
            response = await retry_llm_call(
                llm.ainvoke,
                [HumanMessage(content=detection_prompt)],
                limiter=limiter,
                max_retries=2  # 失败检测可以快速失败
            )
        else:
            response = await llm.ainvoke([HumanMessage(content=detection_prompt)])

        result = _normalize_detection_text(response.content)
        
        # 解析结果（格式：状态 + --- + 关键信息）
        parts = result.split('---', 1)
        status_line = parts[0].strip()
        key_info = parts[1].strip() if len(parts) > 1 else "无关键信息提取"

        is_failure = status_line.upper() == "FAILURE"
        
        # reason 用于简短描述（从关键信息中提取第一条）
        key_lines = [line.strip() for line in key_info.split('\n') if line.strip()]
        reason = key_lines[0].lstrip('•').strip() if key_lines else ("失败" if is_failure else "成功")

        deterministic = _deterministic_failure_detection(tool_output)
        if deterministic is not None:
            is_failure, reason, key_info = deterministic

        log_system_event(
            f"[智能失败检测] {tool_name} → {'❌ 失败' if is_failure else '✅ 成功'}",
            {
                "tool": tool_name,
                "is_failure": is_failure,
                "reason": reason,
                "key_info": key_info
            }
        )

        return is_failure, reason, key_info

    except Exception as e:
        log_system_event(
            f"[智能失败检测] ⚠️ LLM判断失败，回退到关键字检测",
            {"error": str(e)},
            level=logging.WARNING
        )
        # 回退到基础关键字检测
        is_fail, reason = _fallback_keyword_detection(tool_output)
        return is_fail, reason, ""  # 关键字检测不提取信息


def _fallback_keyword_detection(tool_output: str) -> Tuple[bool, str]:
    """
    回退方案：基于关键字的失败检测

    注意：这是简化版本，不提取关键信息（仅用于 LLM 调用失败时的回退）

    Args:
        tool_output: 工具输出内容

    Returns:
        (is_failure, reason): 是否失败以及失败原因
    """
    tool_output = _normalize_detection_text(tool_output)
    lower = tool_output.lower()

    # ⭐ 特殊检测：捕获"使用 execute_command 调用 submit_flag"的错误
    if "submit_flag: command not found" in lower:
        return True, (
            "❌ 错误：submit_flag 是 LangChain 工具，不是 shell 命令！\n"
            "请直接调用 submit_flag 工具，不要通过 execute_command 执行。\n"
            "正确用法：submit_flag(challenge_code='xxx', flag='FLAG{...}')"
        )

    # 明显的错误关键字（优先级高）
    critical_failures = [
        ("exception", "发现异常"),
        ("error:", "命令执行错误"),
        ("failed:", "操作失败"),
        ("command not found", "命令未找到"),
        ("bash:", "Bash脚本错误"),
        ("timeout", "连接超时"),
        ("timed out", "操作超时"),
        ("connecttimeout", "连接超时"),
        ("connectionerror", "连接错误"),
        ("connection refused", "连接被拒绝"),
        ("max retries exceeded", "重试次数超限"),
        ("errno 110", "连接超时 (Errno 110)"),
    ]

    # 检查明显错误
    for keyword, reason in critical_failures:
        if keyword in lower:
            return True, reason

    # 业务逻辑失败关键字
    business_failures = [
        "error", "failed", "无法", "错误", "失败",
        "not found", "denied", "incorrect", "unauthorized",
        "alert-danger", "not authenticated", "invalid credentials",
        "permission denied", "access denied", "authentication failed"
    ]

    # 检查业务逻辑失败
    if any(kw in lower for kw in business_failures):
        return True, "关键字匹配检测到失败"

    return False, "关键字检测无异常"


def detect_failure_hybrid(
    tool_output: str,
    tool_name: str = "unknown",
    enable_llm: bool = True,
    llm: BaseChatModel = None,
    limiter = None
) -> Tuple[bool, str]:
    """
    混合检测方案：优先使用关键字快速检测，模糊情况交给 LLM

    Args:
        tool_output: 工具输出内容
        tool_name: 工具名称
        enable_llm: 是否启用 LLM 检测
        llm: LLM 实例
        limiter: 速率限制器

    Returns:
        (is_failure, reason): 是否失败以及失败原因
    """
    # 第一阶段：快速关键字检测（明显的失败）
    critical_failures = [
        ("exception", "发现异常"),
        ("error:", "命令执行错误"),
        ("failed:", "操作失败"),
        ("command not found", "命令未找到"),
    ]

    for keyword, reason in critical_failures:
        if keyword in tool_output.lower():
            log_system_event(
                f"[混合检测] {tool_name} → ❌ 明显失败（关键字）",
                {"reason": reason}
            )
            return True, reason

    # 第二阶段：如果没有明显错误，且启用了 LLM，交给 LLM 判断
    if enable_llm and llm:
        # 这里需要在异步上下文中调用，所以先返回一个特殊标记
        # 调用方需要在异步环境中处理
        return None, "需要LLM判断"  # 返回None表示需要进一步LLM判断

    # 第三阶段：LLM未启用，使用完整关键字检测
    return _fallback_keyword_detection(tool_output)

