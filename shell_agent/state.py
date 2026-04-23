"""
状态定义模块
============

定义 Shell Agent 的状态结构和 reduce 函数。

设计理念：
- 使用 TypedDict 提供类型安全
- 定义 reduce 函数统一处理列表字段的合并逻辑
- 支持 LangGraph ToolNode 架构（messages 字段）
- 清晰的状态字段分类
"""
from typing import List, Dict, Optional, TypedDict, Annotated, Sequence
from operator import add
from langchain_core.messages import BaseMessage, ToolMessage, HumanMessage


# ==================== 关键证据标记 ====================
CRITICAL_EVIDENCE_MARKERS = [
    "flag{", "FLAG{", "ctf{", "CTF{",
    "uid=", "gid=", "whoami", "root:x:", "daemon:x:",
    "x-cmd-result:", "x-check:", "x-ognl-test:", "x-user-name:", "x-test-bypass:",
    "vulnerable: true", '"vulnerable": true', "vulnerability confirmed",
    "pass - vulnerability confirmed", "[status] vulnerable",
    "command execution successful", "exploit success",
    "cve-", "CVE-",
    "漏洞存在", "确认漏洞", "验证成功",
]


def _is_critical_evidence_message(content: str) -> bool:
    if not content:
        return False
    lower = content.lower()
    return any(marker.lower() in lower for marker in CRITICAL_EVIDENCE_MARKERS)


def _extract_key_lines(content: str, max_chars: int = 400) -> str:
    if not content or len(content) <= max_chars:
        return content

    key_markers = [
        "result", "status", "vulnerable", "confirmed", "pass", "fail",
        "uid=", "gid=", "flag", "evidence", "payload", "target",
        "x-cmd", "x-check", "x-ognl", "cve-", "exploit",
        "结论", "验证", "证据", "漏洞",
    ]

    lines = content.split('\n')
    key_lines = []
    other_lines = []

    for line in lines:
        line = line.strip()
        if not line:
            continue
        lower = line.lower()
        if any(marker in lower for marker in key_markers):
            key_lines.append(line)
        else:
            other_lines.append(line)

    result_lines = key_lines[:10]
    current_len = sum(len(l) for l in result_lines)

    for line in other_lines:
        if current_len + len(line) + 1 > max_chars:
            break
        result_lines.append(line)
        current_len += len(line) + 1

    result = '\n'.join(result_lines)
    if len(result) > max_chars:
        result = result[:max_chars - 20] + "\n...[truncated]"

    return result


def compress_messages(left: Sequence[BaseMessage], right: Sequence[BaseMessage]) -> Sequence[BaseMessage]:
    """
    消息压缩合并函数 - 只保留最近的工具消息，旧消息合并为摘要

    策略：
    1. 保留所有非工具消息（AI、Human、System）
    2. 只保留最近 N 条工具消息
    3. 将旧的工具消息合并为一条摘要
    4. 包含关键证据的消息永不压缩，完整保留

    Args:
        left: 现有消息列表
        right: 新增消息列表

    Returns:
        压缩后的消息列表
    """
    MAX_RECENT_TOOL_MESSAGES = 10  # 只保留最近 10 条工具消息

    # 合并所有消息
    all_messages = list(left) + list(right)

    # ⭐ 改进 1: 先移除旧的摘要消息（避免摘要累积）
    filtered_messages = []
    for msg in all_messages:
        # 跳过旧的摘要消息
        if isinstance(msg, HumanMessage) and msg.content.startswith("📦 **历史工具调用摘要**"):
            continue
        filtered_messages.append(msg)

    # ⭐ 改进 2: 标记工具消息索引，同时识别关键证据消息
    tool_message_indices = []
    critical_evidence_indices = set()

    for idx, msg in enumerate(filtered_messages):
        if isinstance(msg, ToolMessage):
            tool_message_indices.append(idx)
            content = getattr(msg, 'content', '') or ''
            if _is_critical_evidence_message(content):
                critical_evidence_indices.add(idx)

    # 如果工具消息超过限制，进行压缩
    tool_count = len(tool_message_indices)
    compressible_count = tool_count - len(critical_evidence_indices)
    if compressible_count > MAX_RECENT_TOOL_MESSAGES:
        non_critical_indices = [idx for idx in tool_message_indices if idx not in critical_evidence_indices]
        recent_non_critical = set(non_critical_indices[-MAX_RECENT_TOOL_MESSAGES:])
        recent_tool_indices = recent_non_critical | critical_evidence_indices
        old_tool_indices = set(tool_message_indices) - recent_tool_indices

        # 收集需要压缩的旧工具消息
        old_tool_messages = []
        for idx in old_tool_indices:
            old_tool_messages.append(filtered_messages[idx])

        # 创建摘要
        summary_parts = []
        for msg in old_tool_messages:
            tool_name = getattr(msg, 'name', 'unknown')
            content = msg.content if msg.content else ""
            content_preview = content[:400] if len(content) <= 400 else _extract_key_lines(content, max_chars=400)
            summary_parts.append(f"- [{tool_name}]: {content_preview}...")

        summary_content = (
            f"📦 **历史工具调用摘要**（已压缩 {len(old_tool_messages)} 条消息）\n\n"
            + "\n".join(summary_parts)
        )
        summary_message = HumanMessage(content=summary_content)

        # ⭐ 改进 3: 保持消息顺序，只替换旧的工具消息
        result = []
        summary_inserted = False

        for idx, msg in enumerate(filtered_messages):
            # 跳过旧的工具消息
            if idx in old_tool_indices:
                # 在第一个被跳过的位置插入摘要
                if not summary_inserted:
                    result.append(summary_message)
                    summary_inserted = True
                continue

            # 保留其他所有消息（最近的工具消息、AI/Human/System 消息）
            result.append(msg)

        # 日志输出
        from shell_agent.common import log_system_event
        log_system_event(
            f"[消息压缩] 压缩旧工具消息",
            {
                "total_tool_messages": tool_count,
                "compressed": len(old_tool_messages),
                "kept_recent": len(recent_tool_indices)
            }
        )

        return result
    else:
        # 不需要压缩，返回过滤后的消息（已移除旧摘要）
        return filtered_messages


class PenetrationTesterState(TypedDict):
    """
    渗透测试 Agent 的状态

    字段说明：
    - messages: LangGraph 消息序列（用于 ToolNode 架构）
    - flag: 找到的 FLAG
    - is_finished: 是否完成任务
    - action_history: 操作历史（使用 add 合并）
    - last_node: 最后一个执行的业务节点名称（用于 ToolNode 路由）
    """
    # --- LangGraph 消息流（ToolNode 架构核心）---
    messages: Annotated[Sequence[BaseMessage], compress_messages]

    # --- CTF 比赛相关 ---
    challenges: Optional[List[Dict]]  # 赛题列表（从 API 获取）
    current_challenge: Optional[Dict]  # 当前赛题（包含目标 URL）
    total_challenges: int  # 总题数
    solved_count: int  # 已解答题数
    unsolved_count: int  # 未解答题数

    # --- 比赛状态 ---
    current_score: int  # 当前总积分
    start_time: Optional[float]  # 比赛开始时间（时间戳）

    # --- 执行与结果 ---
    flag: Optional[str]
    is_finished: bool
    findings: Annotated[List[Dict], add]  # 结构化漏洞发现列表
    vulnerability_detected: bool  # 是否已确认漏洞（不依赖 FLAG）
    detection_metrics: Optional[Dict]  # 评分层统计：误报率、平均检测时长、CVE族覆盖分布

    # --- 审计与元数据 ---
    action_history: Annotated[List[str], add]
    last_node: str  # 最后一个业务节点名称（用于 ToolNode 返回路由）
    execution_attempts: int  # 统一的真实执行尝试次数（仅执行层/ToolNode 成功落地后递增）

    # --- 多 Agent 协作 ---
    advisor_suggestion: Optional[str]  # 顾问 Agent 的建议（多 Agent 模式）
    last_skill_context_signature: Optional[str]  # 上次已注入的 skill 上下文签名（避免重复注入）
    last_execution_outcome: Optional[Dict]  # 最近一轮执行结果的统一语义表示

    # --- 智能路由控制（优化：减少不必要的 Advisor 调用）---
    consecutive_failures: int  # 连续失败次数（用于判断是否需要 Advisor 介入）
    connectivity_failures: int  # 连续连接失败次数（用于不可达目标快速终止）
    total_connectivity_failures: int  # 累计连接失败次数（用于避免间歇重置导致的死循环）
    no_action_rounds: int  # Main Agent 连续无可执行输出的轮次（防止规划死循环）
    no_progress_rounds: int  # 执行链路连续无有效进展轮次（防止有动作但无收敛）
    advisor_loop_rounds: int  # 连续顾问复盘但无实际执行动作的轮次（防止 Main<->Advisor 空转）
    request_advisor_help: bool  # Main Agent 主动请求 Advisor 帮助的标记
    last_task_signature: Optional[str]  # 上一次分发任务签名（用于检测重复规划）
    repeated_task_rounds: int  # 连续重复任务轮次（用于触发去重与复盘）
    last_hypothesis_signature: Optional[str]  # 上一次分发任务的漏洞族/场景族假设签名
    repeated_hypothesis_rounds: int  # 连续命中相同漏洞族假设的轮次（防止围绕同一假设打转）
    candidate_surface_hints: Annotated[List[str], add]  # 从侦察/执行输出中抽取的候选入口提示
    blocked_hypothesis_signatures: Annotated[List[str], add]  # 已被明确失败证据否定的假设签名
    post_confirm_rounds: int  # 确认到漏洞后继续探索的轮次计数
    post_confirm_no_new_rounds: int  # 确认后连续无新增有效发现的轮次

    # --- 三层架构任务分发（V2 架构）---
    pending_task: Optional[Dict]  # Main Agent 分发给执行层的任务 {"agent": "poc/docker", "task": "..."}
    pending_flag: Optional[str]  # 待提交的 FLAG（Main Agent 解析出的 FLAG）

    # --- 协作运行计数（用于验证双智能体+执行层是否按预期运行）---
    advisor_rounds: Annotated[int, add]
    main_rounds: Annotated[int, add]
    poc_rounds: Annotated[int, add]
    docker_rounds: Annotated[int, add]
    tool_rounds: Annotated[int, add]



