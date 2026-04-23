"""Shell Agent main entrypoint (pentest mode).

Mode:
1. Single target mode (-t): run vulnerability detection and verification against one target.
   Example: python main.py -t http://192.168.1.100:8080

Modules:
- task_manager.py: task lifecycle handling
- retry_strategy.py: retry strategy with fixed main/advisor roles
- challenge_solver.py: single-target solve workflow
"""
import argparse
import asyncio
import os
import logging
import json
from pathlib import Path
from urllib.parse import urlparse
from dotenv import load_dotenv
from langfuse import get_client
from langfuse.langchain import CallbackHandler

from shell_agent.core.singleton import get_config_manager
from shell_agent.task_manager import ChallengeTaskManager
from shell_agent.retry_strategy import RetryStrategy
from shell_agent.common import log_system_event
from shell_agent.config import validate_runtime_environment
from shell_agent.utils.util import is_authentication_error
from shell_agent.working_memory import clear_working_memory


# 在模块级常量读取前加载 .env，避免启动时吃默认值
load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")


# ==================== 并发控制 ====================
MAX_CONCURRENT_TASKS = max(1, min(int(os.getenv("MAX_CONCURRENT_TASKS", "5")), 5))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "4"))  # 4 次重试 = 共 5 次机会（首次 + 4 次重试）


def _has_real_env_value(name: str) -> bool:
    value = os.getenv(name, "").strip().lower()
    if not value:
        return False
    if "xxx" in value or "your" in value or value in {"changeme", "replace_me"}:
        return False
    return True


def _benchmark_priors_enabled() -> bool:
    return os.getenv("ENABLE_BENCHMARK_PRIORS", "false").strip().lower() == "true"


def _langfuse_enabled() -> bool:
    return os.getenv("LANGFUSE_ENABLED", "false").strip().lower() == "true"


def _load_benchmark_profile(target_id: str, benchmark_path: str) -> dict:
    path = Path(benchmark_path)
    if not path.exists():
        raise ValueError(f"Benchmark file not found: {benchmark_path}")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    for item in data.get("targets", []):
        if (item.get("id") or "").strip() == target_id:
            return item
    raise ValueError(f"Target id not found in benchmark: {target_id}")


def _resolve_execution_host(host: str) -> str:
    if host in {"127.0.0.1", "localhost", "::1"}:
        mapped_host = os.getenv("LOCAL_TARGET_HOST", "host.docker.internal").strip()
        return mapped_host or "host.docker.internal"
    return host


def parse_target_url(target: str, target_id: str = "", benchmark_path: str = "") -> dict:
    """
    解析目标 URL，构造虚拟 challenge 对象

    支持格式：
    - http://192.168.1.100:8080
    - https://example.com
    - 192.168.1.100:8080 (默认 http)
    - 192.168.1.100 (默认端口 80)

    Returns:
        虚拟 challenge 字典
    """
    # 如果没有协议前缀，添加 http://
    if not target.startswith(('http://', 'https://')):
        target = f"http://{target}"

    parsed = urlparse(target)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    execution_host = _resolve_execution_host(host)
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    execution_target_url = f"{parsed.scheme}://{execution_host}:{port}{path}{query}"

    benchmark_profile = None
    expected_cves = []
    expected_family = ""
    challenge_code = f"manual_{host}_{port}"
    hint_prefix = ""
    if target_id:
        default_benchmark = Path(__file__).resolve().parent / "benchmarks" / "known_cve_targets.json"
        profile = _load_benchmark_profile(target_id, benchmark_path or str(default_benchmark))
        benchmark_profile = profile
        expected_cves = [x.upper() for x in (profile.get("expected_cves") or []) if x]
        expected_family = (profile.get("family") or "").strip()
        challenge_code = target_id
        if _benchmark_priors_enabled():
            hint_prefix = (
                f"[ARENA_TARGET]\n"
                f"- target_id: {target_id}\n"
                f"- platform: {profile.get('platform', 'unknown')}\n"
                f"- expected_cves: {', '.join(expected_cves) if expected_cves else 'N/A'}\n"
                f"- expected_family: {expected_family or 'N/A'}\n"
            )

    # 构造虚拟 challenge
    challenge = {
        "challenge_code": challenge_code,
        "difficulty": "unknown",
        "points": 0,
        "hint_viewed": False,
        "solved": False,
        "target_info": {
            "ip": host,  # 保持字段名兼容，实际可能是域名
            "port": [port]
        },
        # 标记为手动模式，跳过 API 调用
        "_manual_mode": True,
        "_target_url": target,
        "_execution_target_url": execution_target_url,
        "_execution_host": execution_host,
        "_benchmark_target_id": target_id or None,
        "_benchmark_profile": benchmark_profile or {},
        "_expected_cves": expected_cves,
        "_expected_family": expected_family,
        "hint_content": hint_prefix or "",
    }

    return challenge


async def run_single_target(
    target: str,
    max_retries: int = 0,
    target_id: str = "",
    benchmark_path: str = "",
):
    """
    单目标模式 - 直接对指定目标进行渗透测试

    Args:
        target: 目标 URL (如 http://192.168.1.100:8080)
        max_retries: 最大重试次数 (默认 0，不重试)
    """
    from shell_agent.challenge_solver import solve_single_challenge

    # ==================== 0. 配置验证 ====================
    try:
        config_manager = get_config_manager()
        config = config_manager.config
        runtime_summary = validate_runtime_environment(config)
        log_system_event("[配置] 运行时配置检查通过", runtime_summary)
    except Exception as e:
        log_system_event(
            f"❌ 配置加载失败: {str(e)}\n"
            "请确保 .env 文件中包含必需的配置项",
            level=logging.ERROR
        )
        raise

    # ==================== 1. 解析目标 ====================
    challenge = parse_target_url(target, target_id=target_id, benchmark_path=benchmark_path)
    if challenge.get("_execution_target_url") != challenge.get("_target_url"):
        log_system_event(
            "[目标映射] 检测到本地环回地址，执行层将自动改用容器可访问地址",
            {
                "display_target": challenge.get("_target_url"),
                "execution_target": challenge.get("_execution_target_url"),
                "execution_host": challenge.get("_execution_host"),
            },
        )

    log_system_event(
        "=" * 80 + "\n" +
        "🎯 Shell Agent 单目标模式启动\n" +
        "=" * 80
    )
    log_system_event(
        f"[目标信息]",
        {
            "URL": challenge["_target_url"],
            "IP": challenge["target_info"]["ip"],
            "端口": challenge["target_info"]["port"],
            "任务ID": challenge["challenge_code"]
        }
    )

    # ==================== 2. 初始化 Langfuse ====================
    challenge_code = challenge["challenge_code"]
    target_url = challenge["_target_url"]
    langfuse_handler = None
    if _langfuse_enabled() and _has_real_env_value("LANGFUSE_SECRET_KEY") and _has_real_env_value("LANGFUSE_PUBLIC_KEY"):
        try:
            get_client()  # 验证连接
            # Langfuse 3.x: update_trace=True 让 trace 使用 chain 的 name/input/output
            try:
                langfuse_handler = CallbackHandler(update_trace=True)
            except TypeError:
                langfuse_handler = CallbackHandler()
            log_system_event("[✓] Langfuse 初始化完成")
        except Exception as e:
            log_system_event(
                f"⚠️ Langfuse 初始化失败，将继续运行: {str(e)}",
                level=logging.WARNING
            )
    else:
        log_system_event(
            "[Langfuse] 已禁用或未配置有效 key，已跳过。",
            level=logging.INFO
        )

    # Langfuse 元数据（通过 RunnableConfig 传递）
    langfuse_metadata = {
        "langfuse_session_id": challenge_code,
        "langfuse_tags": ["ctf", "manual"],
        "target": target_url
    }

    # ==================== 3. 初始化重试策略 ====================
    try:
        retry_strategy = RetryStrategy(config=config)
        log_system_event("[✓] 重试策略初始化完成")
    except ValueError as e:
        log_system_event(
            f"❌ 重试策略初始化失败（配置错误）: {str(e)}",
            level=logging.ERROR
        )
        raise

    # ==================== 4. 初始化任务管理器 ====================
    task_manager = ChallengeTaskManager(max_retries=max_retries)
    concurrent_semaphore = asyncio.Semaphore(1)  # 单目标模式只需要 1 个并发

    # ==================== 5. 获取 LLM 对 ====================
    main_llm, advisor_llm, strategy_desc = retry_strategy.get_llm_pair(0)
    log_system_event(f"[✓] LLM 策略: {strategy_desc}")

    # ==================== 6. 开始渗透测试 ====================
    if max_retries > 0:
        log_system_event(f"[重试] 最大重试次数: {max_retries}")

    log_system_event(
        "\n" + "="*80 + "\n" +
        "🚀 开始渗透测试...\n" +
        "- 按 Ctrl+C 可以中断\n" +
        "="*80
    )

    attempt = 0
    result = None
    attempt_history = []

    try:
        while attempt <= max_retries:
            if attempt > 0:
                log_system_event(f"\n[重试] 第 {attempt}/{max_retries} 次重试...")
                # 固定双智能体角色，仅复用同一主模型/顾问模型组合
                main_llm, advisor_llm, strategy_desc = retry_strategy.get_llm_pair(attempt)
                log_system_event(f"[✓] LLM 策略: {strategy_desc}")

            result = await solve_single_challenge(
                challenge=challenge,
                main_llm=main_llm,
                advisor_llm=advisor_llm,
                config=config,
                langfuse_handler=langfuse_handler,
                task_manager=task_manager,
                concurrent_semaphore=concurrent_semaphore,
                retry_strategy=retry_strategy,
                attempt_history=attempt_history if attempt > 0 else None,
                strategy_description=strategy_desc,
                langfuse_metadata=langfuse_metadata
            )

            # 成功则退出循环
            if result.get("success"):
                break

            if is_authentication_error(result.get("error", "")):
                log_system_event(
                    "[鉴权失败] 检测到不可恢复的 401/鉴权错误，停止后续重试。请检查 API Key 是否有效。",
                    level=logging.ERROR
                )
                break

            # 记录本次尝试历史
            attempt_history.append({
                "attempt": attempt + 1,
                "summary": result.get("summary", "未知"),
                "attempts_count": result.get("attempts", 0)
            })

            attempt += 1

        # ==================== 7. 输出结果 ====================
        log_system_event("\n" + "="*80)
        if result and result.get("success"):
            findings = result.get("findings", []) if result else []
            metrics = result.get("detection_metrics", {}) if result else {}
            log_system_event(
                f"🎉 检测任务成功！",
                {
                    "漏洞检测": "已确认漏洞" if result.get("vulnerability_detected") else "未确认",
                    "漏洞数量": len(findings),
                    "Confirmed": metrics.get("confirmed_count", 0),
                    "Suspected": metrics.get("suspected_count", 0),
                    "误报率(FPR)": metrics.get("false_positive_rate", 0.0),
                    "CVE族分布": metrics.get("cve_family_distribution", {}),
                    "漏洞详情": findings[:5] if findings else "N/A",
                    "FLAG": result.get("flag", "N/A") if result.get("flag") else "未发现",
                    "报告(Markdown)": result.get("report_markdown", "N/A"),
                    "报告(Word)": result.get("report_docx", "N/A"),
                    "尝试次数": result.get("attempts", 0),
                    "重试次数": attempt,
                    "目标模式": result.get("objective_mode", "hybrid")
                }
            )
        else:
            findings = result.get("findings", []) if result else []
            metrics = result.get("detection_metrics", {}) if result else {}
            log_system_event(
                f"❌ 检测任务未成功",
                {
                    "尝试次数": result.get("attempts", 0) if result else 0,
                    "重试次数": attempt,
                    "漏洞数量": len(findings),
                    "Confirmed": metrics.get("confirmed_count", 0),
                    "Suspected": metrics.get("suspected_count", 0),
                    "误报率(FPR)": metrics.get("false_positive_rate", 0.0),
                    "报告(Markdown)": result.get("report_markdown", "N/A") if result else "N/A",
                    "报告(Word)": result.get("report_docx", "N/A") if result else "N/A",
                    "原因": "未确认漏洞证据或达到最大尝试次数"
                }
            )
        log_system_event("="*80)

    except KeyboardInterrupt:
        log_system_event(
            "\n🛑 收到中断信号，正在退出...",
            level=logging.WARNING
        )
    except Exception as e:
        log_system_event(
            f"❌ 渗透测试异常: {str(e)}",
            level=logging.ERROR
        )
        raise
    finally:
        log_system_event("[工作记忆] 清理单目标中间过程文件", {"challenge_code": challenge_code})
        clear_working_memory(challenge_code)


async def run_multi_targets(
    targets: list[str],
    max_retries: int = 0,
    target_id: str = "",
    benchmark_path: str = "",
):
    """
    多目标并发模式：
    - 通过 `-t url1 url2 ...` 传入多个目标
    - 并发上限受 MAX_CONCURRENT_TASKS 控制，且硬上限为 5
    """
    clean_targets = [str(t).strip() for t in (targets or []) if str(t).strip()]
    if not clean_targets:
        raise ValueError("未提供有效目标 URL。")

    if len(clean_targets) > 1 and target_id:
        log_system_event(
            "[多目标] 检测到 --target-id 与多目标同时使用，已自动忽略 --target-id/--benchmark（仅单目标支持）。",
            level=logging.WARNING,
        )
        target_id = ""
        benchmark_path = ""

    concurrency = MAX_CONCURRENT_TASKS
    sem = asyncio.Semaphore(concurrency)

    log_system_event(
        "[多目标] 启动并发渗透测试",
        {
            "targets_count": len(clean_targets),
            "max_concurrent_tasks": concurrency,
        },
    )

    async def _worker(idx: int, target: str):
        async with sem:
            log_system_event(
                "[多目标] 开始目标测试",
                {"index": idx + 1, "total": len(clean_targets), "target": target},
            )
            try:
                await run_single_target(
                    target=target,
                    max_retries=max_retries,
                    target_id=target_id if len(clean_targets) == 1 else "",
                    benchmark_path=benchmark_path if len(clean_targets) == 1 else "",
                )
            except Exception as exc:
                log_system_event(
                    "[多目标] 目标测试异常",
                    {"target": target, "error": str(exc)},
                    level=logging.ERROR,
                )

    await asyncio.gather(*[_worker(i, t) for i, t in enumerate(clean_targets)])


async def run_api_mode():
    """已废弃：旧比赛 API 模式。"""
    raise RuntimeError(
        "API mode has been deprecated in pentest-focused builds. "
        "Please use single-target mode: `python main.py -t <target>`."
    )
    # 延迟导入，仅在比赛模式使用
    from shell_agent.task_launcher import start_challenge_task
    from shell_agent.scheduler import (
        check_and_start_pending_challenges,
        periodic_fetch_challenges,
        status_monitor,
        print_final_status
    )

    # ==================== 0. 配置验证 ====================
    try:
        config_manager = get_config_manager()
        config = config_manager.config
        runtime_summary = validate_runtime_environment(config)
        log_system_event("[配置] 运行时配置检查通过", runtime_summary)
    except Exception as e:
        log_system_event(
            f"❌ 配置加载失败: {str(e)}\n"
            "请确保 .env 文件中包含必需的配置项",
            level=logging.ERROR
        )
        raise

    # ==================== 1. 初始化全局变量 ====================
    concurrent_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
    task_manager = ChallengeTaskManager(max_retries=MAX_RETRIES)

    log_system_event(
        f"[并发控制] 最大并发任务数: {MAX_CONCURRENT_TASKS}",
        {"可通过环境变量 MAX_CONCURRENT_TASKS 调整"}
    )
    log_system_event(
        f"[重试策略] 最大重试次数: {MAX_RETRIES}（共 {MAX_RETRIES + 1} 次机会）",
        {"可通过环境变量 MAX_RETRIES 调整"}
    )

    log_system_event(
        "=" * 80 + "\n" +
        "🚀 Shell Agent 比赛模式启动\n" +
        "=" * 80
    )

    # ==================== 2. 初始化 Langfuse ====================
    langfuse_handler = None
    if _langfuse_enabled() and _has_real_env_value("LANGFUSE_SECRET_KEY") and _has_real_env_value("LANGFUSE_PUBLIC_KEY"):
        try:
            get_client()  # 验证连接
            langfuse_handler = CallbackHandler()
            log_system_event("[✓] Langfuse 初始化完成")
        except Exception as e:
            log_system_event(
                f"⚠️ Langfuse 初始化失败，将继续运行: {str(e)}",
                level=logging.WARNING
            )
    else:
        log_system_event(
            "[Langfuse] 已禁用或未配置有效 key，已跳过。",
            level=logging.INFO
        )

    # ==================== 3. 初始化重试策略 ====================
    try:
        retry_strategy = RetryStrategy(config=config)
        log_system_event("[✓] 重试策略初始化完成")
    except ValueError as e:
        log_system_event(
            f"❌ 重试策略初始化失败（配置错误）: {str(e)}",
            level=logging.ERROR
        )
        raise

    # ==================== 4. 初始化 API 客户端 ====================
    try:
        from shell_agent.tools.competition_api_tools import CompetitionAPIClient
        api_client = CompetitionAPIClient()
        log_system_event("[✓] API 客户端初始化完成")
    except Exception as e:
        log_system_event(
            f"❌ API 客户端初始化失败: {str(e)}",
            level=logging.ERROR
        )
        raise

    # ==================== 5. 创建任务启动函数（闭包） ====================
    async def start_task_wrapper(challenge, retry_strategy, config, langfuse_handler):
        """任务启动包装函数"""
        return await start_challenge_task(
            challenge=challenge,
            retry_strategy=retry_strategy,
            config=config,
            langfuse_handler=langfuse_handler,
            task_manager=task_manager,
            concurrent_semaphore=concurrent_semaphore
        )

    # ⭐ 创建空位回填回调函数（立即重试）
    async def refill_slots_callback():
        """
        任务完成后立即触发的空位回填回调

        作用：
        - 失败任务完成后，立即启动重试或新任务
        - 避免等待 10 分钟的定时任务
        - 提高并发槽位利用率
        """
        log_system_event("[立即回填] 任务完成，触发空位回填...")
        await check_and_start_pending_challenges(
            api_client=api_client,
            task_manager=task_manager,
            retry_strategy=retry_strategy,
            config=config,
            langfuse_handler=langfuse_handler,
            start_task_func=start_task_wrapper,
            max_concurrent_tasks=MAX_CONCURRENT_TASKS
        )

    # ⭐ 设置任务完成回调
    task_manager.set_completion_callback(refill_slots_callback)
    log_system_event("[✓] 已设置立即回填机制（任务完成后自动填充空位）")

    # ==================== 6. 首次拉取题目并启动初始任务 ====================
    log_system_event("[*] 首次拉取题目...")
    await check_and_start_pending_challenges(
        api_client=api_client,
        task_manager=task_manager,
        retry_strategy=retry_strategy,
        config=config,
        langfuse_handler=langfuse_handler,
        start_task_func=start_task_wrapper,
        max_concurrent_tasks=MAX_CONCURRENT_TASKS
    )

    # ==================== 7. 启动后台任务 ====================
    # 定时拉取新题目的任务
    fetch_interval = int(os.getenv("FETCH_INTERVAL_SECONDS", "600"))
    fetch_task = asyncio.create_task(
        periodic_fetch_challenges(
            api_client=api_client,
            task_manager=task_manager,
            retry_strategy=retry_strategy,
            config=config,
            langfuse_handler=langfuse_handler,
            start_task_func=start_task_wrapper,
            max_concurrent_tasks=MAX_CONCURRENT_TASKS,
            interval_seconds=fetch_interval
        )
    )

    # 状态监控任务
    monitor_interval = int(os.getenv("MONITOR_INTERVAL_SECONDS", "300"))
    monitor_task = asyncio.create_task(
        status_monitor(
            task_manager=task_manager,
            interval_seconds=monitor_interval
        )
    )

    log_system_event(
        "[✓] 后台任务启动完成",
        {
            "定时拉取间隔": f"{fetch_interval//60} 分钟",
            "状态监控间隔": f"{monitor_interval//60} 分钟"
        }
    )

    # ==================== 8. 持续运行 ====================
    log_system_event(
        "\n" + "="*80 + "\n" +
        "✅ 系统正在运行中...\n" +
        "- 按 Ctrl+C 可以优雅退出\n" +
        "- 系统会自动拉取新题目并创建解题任务\n" +
        "- 失败的题目会自动重试（固定双智能体协作）\n" +
        "- 任务完成后会动态填充槽位\n" +
        "="*80
    )

    try:
        # 等待所有后台任务（无限期运行）
        await asyncio.gather(fetch_task, monitor_task)
    except KeyboardInterrupt:
        log_system_event(
            "\n🛑 收到中断信号，正在优雅退出...",
            level=logging.WARNING
        )

        # 取消后台任务
        fetch_task.cancel()
        monitor_task.cancel()

        # 等待后台任务完成取消
        try:
            await asyncio.gather(fetch_task, monitor_task, return_exceptions=True)
        except Exception:
            pass

        # 打印最终状态
        await print_final_status(task_manager)

        log_system_event("👋 程序已退出")


def main():
    """主入口 - 解析命令行参数并启动单目标渗透测试"""
    parser = argparse.ArgumentParser(
        description="Shell Agent - AI 驱动的自动化渗透测试工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 单目标模式 - 直接指定目标进行渗透测试
  python main.py -t http://192.168.1.100:8080
  python main.py -t https://example.com
  python main.py -t 192.168.1.100:8080

  # 多目标并发模式（并发上限由 MAX_CONCURRENT_TASKS 控制，且最多为 5）
  python main.py -t http://192.168.1.10:8080 http://192.168.1.11:8080 http://192.168.1.12:8080

  # 单目标模式 + 重试
  python main.py -t http://192.168.1.100:8080 -r 3
        """
    )

    parser.add_argument(
        "-t", "--target",
        type=str,
        nargs="+",
        required=True,
        metavar="URL",
        help="指定一个或多个目标 URL，多个目标用空格分隔。"
    )

    # 可选参数
    parser.add_argument(
        "-r", "--retry",
        type=int,
        default=0,
        metavar="N",
        help="单目标模式: 最大重试次数 (默认 0，不重试)"
    )

    parser.add_argument(
        "--target-id",
        type=str,
        default="",
        help="Arena benchmark target id (example: vulhub.struts2.s2_045).",
    )
    parser.add_argument(
        "--benchmark",
        type=str,
        default="",
        help="Benchmark json path used with --target-id.",
    )
    parser.add_argument(
        "--hint",
        type=str,
        default="",
        help="单目标模式：手动注入提示文本（例如：Flask/Jinja2 SSTI）。",
    )

    args = parser.parse_args()

    if args.hint:
        os.environ["MANUAL_HINT_CONTENT"] = args.hint
    asyncio.run(
        run_multi_targets(
            targets=args.target,
            max_retries=args.retry,
            target_id=args.target_id,
            benchmark_path=args.benchmark,
        )
    )


if __name__ == "__main__":
    main()


