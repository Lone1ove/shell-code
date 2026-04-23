# CVE 匹配架构重构方案

当前项目的 CVE 匹配改为四层链路：

1. 漏洞族规则层
   - 由 `shell_agent/cve/templates.py` 提供。
   - 只负责回答“更像哪一类漏洞/产品族”，不负责穷举所有 CVE。
   - 输出 `primary_template`，给后续候选召回提供产品族、确认标记和默认探测方式。

2. 候选召回层
   - 由 `shell_agent/cve/matcher.py` 提供。
   - 先汇总直接信号：
     - 工具输出显式提到的 CVE
     - finding 自带 `cve/cve_candidates`
     - 模型/工具证据中的产品族与向量词
   - 再按优先级召回候选：
     - 本地 `intel` 缓存优先
     - 候选不足时，受限使用 `CVE-RAG`
   - 最终输出一个小规模候选集，而不是全量扫描。

3. 小范围验证与排序层
   - 由 `shell_agent/cve/engine.py` 提供。
   - 对候选进行：
     - exploit vector 一致性检查
     - 运行时证据检查
     - 漏洞类型一致性检查
     - family / template 一致性加权
   - 输出 `cve_rankings`，并稳定选择最终 `cve`。

4. 证据定级与收敛层
   - 仍由 `engine.py` 完成。
   - 没有强运行时证据时，即使有候选 CVE，也只能到 `suspected`。
   - 只有漏洞确认和 CVE 归因同时满足严格验证时，才提升为高置信确认。

## 与四项目标的对应关系

1. 把本地 intel 从“手工知识库”改成“自动同步缓存”
   - 已匹配。
   - `shell_agent/cve/intel.py` 会从 `NVD / CVEProject / GitHub PoC / benchmark seed / mainstream seed / vulhub seed` 同步并合并到本地 `data/cve_intel/cve_intel.json`。
   - 本地 intel 现在更像缓存层，而不是只能手工维护的唯一知识库。

2. 把模板从“按具体 CVE 写死”改成“按漏洞族 / 产品族写规则”
   - 已匹配。
   - `data/cve_templates/families.json` 与 `shell_agent/cve/templates.py` 现在主要描述 family、product、fingerprint、confirm markers、default probe，而不是维护每个具体 CVE 的独立模板。

3. 让“具体 CVE”更多从外部情报自动长出来
   - 已匹配。
   - `shell_agent/cve/matcher.py` 会优先结合本地 intel 召回候选，候选不足时再受限使用 `CVE-RAG`，让具体 CVE 更多来自外部情报而不是本地硬编码。

4. 给项目做一个“情报更新流水线”，不要靠手工改仓库
   - 现已补齐。
   - 入口脚本：
     - `python scripts/update_cve_intel.py`
     - `python scripts/refresh_cve_knowledge.py`
   - 推荐用后者，它会先同步本地 intel，再自动重建 `CVE-RAG` 索引。

## 为什么这样改

旧链路的问题是：

- 本地 template/intel 不全面时，长尾 CVE 很难进入候选池。
- RAG 之前更多是“补文本”，不是正式候选召回层。
- engine 容易直接围绕单个当前 CVE 猜测，缺少统一的候选计划。

新链路的目标是：

- 模板只做“缩小范围”，不承担“穷举所有 CVE”。
- 本地 intel 作为可更新的缓存层，不再是唯一知识源。
- RAG 只在候选不足时，补充少量长尾 CVE。
- 归因永远要经过 runtime evidence 和 vector consistency。

## 当前新增的关键实现

- `shell_agent/cve/matcher.py`
  - `build_cve_match_plan(...)`
  - 对 finding 构建 `profile`
  - 从本地 intel 和 RAG 召回少量候选
  - 输出排序后的候选列表

- `shell_agent/cve/engine.py`
  - 使用 matcher 的候选列表来稳定 `cve_candidates`
  - `cve_rankings` 会吸收 matcher 分数，而不是只看当前/expected/extracted

## 可调参数

建议关注这些环境变量：

- `ENABLE_CVE_RAG_MATCHING`
- `CVE_RAG_TOP_K`
- `CVE_RAG_MIN_SEVERITY`
- `CVE_LOCAL_CANDIDATE_LIMIT`
- `CVE_TOTAL_CANDIDATE_LIMIT`
- `CVE_LOCAL_MIN_SCORE`
- `CVE_RAG_TRIGGER_MAX_LOCAL`
- `CVE_RAG_SKIP_LOCAL_SCORE`
- `CVE_MATCH_VECTOR_TERM_LIMIT`

## 后续扩展建议

如果要匹配更多 CVE，优先做这三件事：

1. 扩充 `data/cve_intel/cve_intel.json` 的同步来源，而不是手工加代码。
2. 继续维护漏洞族模板，而不是单独维护每个 CVE 模板。
3. 为常见产品族补更多“区分性验证”规则，而不是扩大盲扫范围。
