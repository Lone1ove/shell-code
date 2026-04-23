"""
Shell command execution tool.
Runs commands in the configured isolated executor and returns bounded output to LLM.
"""

import os
from langchain_core.tools import tool

from shell_agent.core.singleton import get_config_manager
from shell_agent.core.constants import Timeouts
from shell_agent.common import log_tool_event


def _validate_command(command: str) -> tuple[bool, str]:
    if not command or not command.strip():
        return False, "错误：命令不能为空"
    return True, ""


def _truncate_for_llm(text: str, max_chars: int) -> str:
    if not isinstance(text, str):
        text = str(text)
    if max_chars <= 0 or len(text) <= max_chars:
        return text

    head = int(max_chars * 0.7)
    tail = max_chars - head - 120
    if tail < 0:
        tail = 0
    omitted = len(text) - (head + tail)
    return (
        text[:head]
        + f"\n\n...[OUTPUT TRUNCATED, omitted {omitted} chars]...\n\n"
        + (text[-tail:] if tail > 0 else "")
    )


@tool
async def execute_command(command: str, timeout: int = Timeouts.COMMAND_EXECUTION) -> str:
    """
    在 Docker/Kali 执行 shell 命令。

    Args:
        command: 待执行命令
        timeout: 超时时间（秒）

    Returns:
        标准化执行输出（长度受限，避免撑爆 LLM 上下文）
    """
    is_valid, error_msg = _validate_command(command)
    if not is_valid:
        return error_msg

    log_tool_event("[Shell] 执行命令", {"command": command, "timeout": timeout})

    config_manager = get_config_manager()
    executor = config_manager.executor
    result = executor.execute(command, timeout=timeout)

    output_full = f"""Exit Code: {result.exit_code}

--- STDOUT ---
{result.stdout}

--- STDERR ---
{result.stderr}
"""

    # Keep tool output compact by default to avoid prompt/context overflow.
    max_chars = int(os.getenv("TOOL_OUTPUT_MAX_CHARS", "8000"))
    output = _truncate_for_llm(output_full, max_chars)
    preview = _truncate_for_llm(output, 3000)

    log_tool_event(
        "[Shell] 命令完成，返回结果给 LLM",
        {
            "exit_code": result.exit_code,
            "stdout_length": len(result.stdout),
            "stderr_length": len(result.stderr),
            "full_output_preview": preview if preview else "(空)",
            "output_truncated": len(output_full) > len(output),
            "output_length": len(output),
        },
    )
    return output

