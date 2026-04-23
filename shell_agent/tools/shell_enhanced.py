"""
Python PoC execution tool.
Runs Python code in isolated executor and returns bounded output to LLM.
"""

import os
from langchain_core.tools import tool

from shell_agent.core.constants import Timeouts
from shell_agent.common import log_tool_event


def _validate_code(code: str) -> tuple[bool, str]:
    if not code or not code.strip():
        return False, "错误：代码不能为空"

    try:
        compile(code, "<string>", "exec")
    except SyntaxError as e:
        return False, f"语法错误（第 {e.lineno} 行）: {e.msg}"
    except IndentationError as e:
        return False, f"缩进错误（第 {e.lineno} 行）: {e.msg}"
    except Exception as e:
        return False, f"代码校验失败: {str(e)}"

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
async def execute_python_poc(code: str, timeout: int = Timeouts.COMMAND_EXECUTION) -> str:
    """
    在隔离 Python 执行器中运行 PoC 代码。

    Args:
        code: Python 代码
        timeout: 超时时间（秒）

    Returns:
        标准化执行输出（长度受限，避免撑爆 LLM 上下文）
    """
    is_valid, error_msg = _validate_code(code)
    if not is_valid:
        log_tool_event("[Python PoC] 代码校验失败", {"error": error_msg})
        return f"❌ {error_msg}\n\n请修复代码后重试。"

    log_tool_event("[Python PoC] 执行代码", {"code_length": len(code), "timeout": timeout})

    from shell_agent.core.singleton import get_config_manager
    from shell_agent.executor.factory import get_python_executor
    from shell_agent.executor.microsandbox import MicrosandboxExecutor

    config_manager = get_config_manager()
    executor = get_python_executor(config_manager.config)

    if isinstance(executor, MicrosandboxExecutor):
        result = await executor.execute_async(code, timeout=timeout)
    else:
        result = executor.execute(code, timeout=timeout)

    output_full = f"""Exit Code: {result.exit_code}
--- OUTPUT ---
{result.stdout}
--- ERRORS ---
{result.stderr}
"""

    # Keep tool output compact by default to avoid prompt/context overflow.
    max_chars = int(os.getenv("TOOL_OUTPUT_MAX_CHARS", "8000"))
    output = _truncate_for_llm(output_full, max_chars)
    preview = _truncate_for_llm(output, 3000)

    log_tool_event(
        "[Python PoC] 执行完成，返回结果给 LLM",
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

