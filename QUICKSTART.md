# QUICKSTART

适用环境：`Python 3.11+`

## 1. 安装依赖

```bash
git clone https://github.com/Lone1ove/shell-code
cd shell-agent
uv sync
```

## 2. 配置环境变量

```bash
cp .env.example .env
```

最小必填示例：

```bash
LLM_PROVIDER=GLM
LLM_BASE_URL=https://api.siliconflow.cn/v1
LLM_API_KEY=sk-xxx
LLM_MODEL_NAME=Pro/zai-org/GLM-5

ADVISOR_PROVIDER=MiniMax
ADVISOR_BASE_URL=https://api.siliconflow.cn/v1
ADVISOR_API_KEY=sk-xxx
ADVISOR_MODEL_NAME=Pro/MiniMaxAI/MiniMax-M2.5

DOCKER_CONTAINER_NAME=kali-pentest
OBJECTIVE_MODE=hybrid
ENABLE_TOOL_SUMMARY=true
ENABLE_SMART_FAILURE_DETECTION=true
ENABLE_CVE_RAG_MATCHING=true
ENABLE_CVE_TASK_GUIDANCE=true
CVE_TASK_GUIDANCE_TOP_K=3
CVE_TASK_GUIDANCE_MIN_SEVERITY=low
RAG_ALLOW_IN_REVIEW_MODE=true
```

## 3. 启动 Kali 容器

```bash
cd docker
docker-compose up -d
```

## 4. 命令行运行

Windows PowerShell 推荐入口：

```powershell
.\run.ps1 main.py -t http://192.168.1.100:8080
```

常用示例：

```bash
# 单目标
uv run main.py -t http://192.168.1.100:8080

# 单目标 + 自动重试
uv run main.py -t http://192.168.1.100:8080 -r 3

# 多目标并发
uv run main.py -t http://192.168.1.101:8080 http://192.168.1.102:8080 http://192.168.1.103:8080
```

如果看到这类提示：

```text
warning: VIRTUAL_ENV=... does not match the project environment path .venv
```

说明当前 shell 里残留了其他项目的虚拟环境。处理方式：

- 直接使用 `.\run.ps1 ...`
- 或先执行 `Remove-Item Env:VIRTUAL_ENV`

## 5. Web 前端启动

首次安装依赖或依赖变更后执行：

```bash
cd frontend
npm ci
```

日常开发启动：

```bash
npm run dev
```

说明：

- `npm run dev` 会自动清理 `.next` 缓存，并以 `webpack` 模式启动
- 正常重启前端时，不需要每次都重新执行 `npm ci`
- 如果页面表现异常，先彻底关闭旧的前端进程，再重新执行 `npm run dev`
- 推荐访问 `http://localhost:3000`

生产模式：

```bash
npm run build
npm run start -- --hostname 127.0.0.1 --port 3000
```

启动前请确认：

- 根目录 `.env` 已配置完成
- 已执行 `uv sync`
- 相关 Docker 容器已正常启动

## 6. CVE 情报更新流程

如果你想让项目匹配更多新的 `CVE`，推荐使用下面这套流程。

方案 A：一键刷新整套 CVE 知识

这个命令会做两件事：

1. 同步本地 `intel` 缓存
2. 自动重建 `CVE-RAG` 索引

```bash
uv run python scripts/refresh_cve_knowledge.py
```

可选参数：

```bash
# 只同步最近 15 天，且每个远程源最多拉 200 条
uv run python scripts/refresh_cve_knowledge.py --days 15 --limit 200

# 只更新本地 intel，不重建 CVE-RAG 索引
uv run python scripts/refresh_cve_knowledge.py --skip-rag-index
```

方案 B：只更新本地 CVE intel 缓存

```bash
uv run python scripts/update_cve_intel.py
```

方案 C：只重建 CVE-RAG 索引

```bash
uv run python -m shell_agent.rag.cve_indexer
```

推荐执行顺序：

```bash
cd shell-agent
uv sync
uv run python scripts/refresh_cve_knowledge.py
uv run main.py -t http://127.0.0.1:8080
```

更新后如何确认生效：

- `data/cve_intel/cve_intel.json`
- `data/cve_intel/sync_status.json`
- `shell_agent/rag/data/id_map.json`
- `shell_agent/rag/data/keyword_index.json`

## 7. Benchmark / CVE 覆盖验证

```bash
# 按 benchmark 目标运行
uv run main.py -t http://127.0.0.1:8080 --target-id vulhub.struts2.s2_057 --benchmark benchmarks/known_cve_targets.json

# 校验 benchmark 文件
uv run python scripts/validate_benchmark.py --benchmark benchmarks/known_cve_targets.json

# 家族覆盖缺口分析
uv run python scripts/benchmark_family_gap.py --benchmark benchmarks/known_cve_targets.json

# 已生成报告的 CVE 覆盖率评估
uv run python scripts/evaluate_cve_coverage.py --benchmark benchmarks/known_cve_targets.json
```

## 8. 输出目录

- `logs/`: 主日志
- `logs/challenges/`: 分题日志
- `reports/`: 自动生成的 `Markdown` 和 `Word(.docx)` 渗透测试报告

## 9. 核心架构

1. 规划层：`advisor` + `main_agent`
2. 执行层：`poc_agent` + `docker_agent`
3. 知识层：`skills/` + `RAG` + `CVE matcher`

## 10. 常见问题

1. `execute_command` 不工作  
   检查 `DOCKER_CONTAINER_NAME` 对应容器是否正常运行。

2. 本地 `127.0.0.1` 目标在容器内无法访问  
   使用 `LOCAL_TARGET_HOST=host.docker.internal`。

3. 报告里出现疑似误报  
   检查 `reports/` 中是否存在运行时成功证据，并结合 `.env` 中的 `CONFIRMED_THRESHOLD`、`SUSPECTED_THRESHOLD` 调整阈值。

4. 新增的 `CVE` 没有被匹配到  
   先运行：

   ```bash
   uv run python scripts/refresh_cve_knowledge.py
   ```

   再重新测试。

## 11. 免责声明

仅用于授权安全测试、教学和研究，禁止用于未授权目标。
