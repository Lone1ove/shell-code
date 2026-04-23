"""
Skills loader
- Load built-in skills under `shell_agent/skills`
- Merge external skill packs (e.g. ../general-skills)
- Auto-detect relevant skills from hint/response
"""

import os
import re
import logging
from pathlib import Path
from typing import Optional, List, Dict, Tuple

from shell_agent.common import log_system_event


# Built-in skills directory
SKILLS_DIR = Path(__file__).parent
PROJECT_ROOT = SKILLS_DIR.parent.parent  # shell-agent/
WORKSPACE_ROOT = PROJECT_ROOT.parent

GENERIC_STOPWORDS = {
    "the", "and", "for", "with", "from", "into", "that", "this", "your", "you",
    "are", "was", "were", "will", "can", "should", "about", "when", "where",
    "which", "what", "how", "using", "used", "use", "test", "testing", "report",
    "security", "vulnerability", "attack", "skill", "skills", "tool", "tools",
    "http", "https", "www", "com", "org", "net", "json", "yaml", "markdown",
    "agent", "context", "response", "hint", "target", "manual", "auto",
}


# 默认不注入流程型大 skill，避免干扰漏洞判定
CONTEXT_EXCLUDED_SKILLS = {
    "pentest-master",
    "recon",
    "vuln-assess",
    "exploitation",
    "post-exploit",
    "reporting",
    "toolbox",
}

# 技能按职责分层：流程族 / 侦察族 / 漏洞族 / 场景族 / 情报族 / 后渗透 / 工具族
SKILL_CATEGORIES: Dict[str, str] = {
    "pentest-master": "process",
    "recon": "recon",
    "web-recon": "recon",
    "vuln-assess": "process",
    "exploitation": "process",
    "reporting": "process",
    "post-exploit": "post",
    "toolbox": "tooling",
    "struts2-ognl": "family",
    "rce": "family",
    "ssti": "family",
    "sqli": "family",
    "xss": "family",
    "xxe": "family",
    "file-inclusion": "family",
    "ssrf": "family",
    "auth-bypass": "family",
    "modern-web": "scenario",
    "cloud-native": "scenario",
    "cve-2024-2025": "intel",
}

STAGE_ALLOWED_CATEGORIES: Dict[str, set[str]] = {
    "recon": {"process", "recon", "tooling"},
    "transition": {"process", "recon", "family", "scenario", "tooling"},
    "vuln": {"process", "family", "scenario", "intel"},
    "post": {"process", "family", "scenario", "intel", "post", "tooling"},
    "auto": {"process", "recon", "family", "scenario", "intel", "post", "tooling"},
}

SKILL_CATEGORY_LIMITS: Dict[str, int] = {
    "process": 1,
    "recon": 1,
    "family": 1,
    "scenario": 1,
    "intel": 1,
    "post": 1,
    "tooling": 1,
}

CATEGORY_MIN_CONTEXT_SCORES: Dict[str, int] = {
    "process": 8,
    "recon": 8,
    "family": 8,
    "scenario": 10,
    "intel": 14,
    "post": 8,
    "tooling": 10,
    "unknown": 8,
}

SKILL_SUPPRESSION_RULES: Dict[str, Dict[str, set[str]]] = {
    "rce": {"blocked_by": {"struts2-ognl", "ssti"}},
}


# 技能路由规则：required_any + keywords + negative + mutex_group
SKILL_ROUTING_RULES: Dict[str, Dict] = {
    "struts2-ognl": {
        "required_any": [
            "struts2",
            "ognl",
            "xwork",
        ],
        "keywords": [
            "content-type: %{",
            ".multipart/form-data",
            "multipartrequestwrapper",
            "strutsproblemreporter",
            "namespace",
            "redirect:${",
            "/${",
            "%24%7b",
            "doupload.action",
            "actionchain",
            "showcase",
            "whoami",
            "uid=",
        ],
        "negative": ["twig", "jinja2", "{{7*7}}"],
        "mutex_group": "struts2_family",
    },
    "ssti": {
        "required_any": [
            "ssti",
            "template injection",
            "jinja",
            "jinja2",
            "twig",
            "freemarker",
            "velocity",
            "{{7*7}}",
            "{{233*233}}",
        ],
        "keywords": [
            "{{",
            "}}",
            "__globals__",
            "__builtins__",
            "config.__class__",
            "class.__mro__",
            "subclasses()",
            "os.popen",
            "render_template",
            "54289",
            "hello 49",
        ],
        "negative": ["struts2", "ognl", "content-type: %{", "multipart/form-data"],
        "mutex_group": "execution_family",
    },
    "sqli": {
        "required_any": ["sql injection", "sqli", "union select", "sql syntax", "you have an error in your sql syntax"],
        "keywords": ["mysql", "postgresql", "sqlite", "oracle", "mssql", "sleep(", "benchmark(", "database error", "sql注入"],
    },
    "xss": {
        "required_any": ["xss", "<script>alert", "onerror=", "javascript:alert", "payload reflected"],
        "keywords": ["document.cookie", "dom xss", "stored xss", "reflected xss", "跨站脚本"],
    },
    "rce": {
        "required_any": ["rce", "remote code execution", "command execution", "uid=", "whoami", "command output"],
        "keywords": ["runtime.getruntime().exec", "os.system", "subprocess", "popen", "webshell", "命令执行", "远程代码执行"],
        "negative": ["struts2", "ognl", "ssti", "template injection", "jinja", "jinja2"],
        "mutex_group": "execution_family",
    },
    "xxe": {
        "required_any": ["xxe", "external entity", "<!entity", "xml external entity", "file:///etc/passwd"],
        "keywords": ["dtd", "doctype", "file://", "parameter entity", "xml parser", "system \"file:///"],
        "negative": ["<!doctype html", "<html", "template"],
    },
    "file-inclusion": {
        "required_any": ["lfi", "rfi", "path traversal", "../", "..%2f", ".%2e%2f", "/etc/passwd", "php://", "file://"],
        "keywords": ["file inclusion", "目录遍历", "路径穿越", "文件包含", "win.ini", "/proc/self/environ"],
    },
    "ssrf": {
        "required_any": ["ssrf", "169.254.169.254", "metadata", "gopher://", "dict://", "internal service", "localhost response"],
        "keywords": ["request forgery", "cloud metadata", "内网", "服务端请求伪造"],
        "negative": ["kubernetes", "k8s", "kubelet", "etcd", "serviceaccount", "docker.sock"],
    },
    "auth-bypass": {
        "required_any": ["auth bypass", "authentication bypass", "authorization bypass", "idor", "broken access control", "unauthorized access"],
        "keywords": ["越权", "认证绕过", "权限绕过", "admin panel", "privilege escalation"],
    },
    "web-recon": {
        "required_any": ["recon", "fingerprint", "directory scan", "port scan", "whatweb", "nmap", "dirsearch", "ffuf"],
        "keywords": ["信息收集", "扫描", "指纹", "discover", "enumerate"],
    },
    "modern-web": {
        "required_any": [
            "graphql",
            "jwt",
            "websocket",
            "request smuggling",
            "prototype pollution",
            "oauth",
            "oidc",
            "csrf via websocket",
        ],
        "keywords": [
            "__schema",
            "graphiql",
            "alg=none",
            "jku",
            "x5u",
            "kid",
            "transfer-encoding",
            "content-length",
            "__proto__",
            "constructor.prototype",
        ],
    },
    "cloud-native": {
        "required_any": [
            "kubernetes",
            "k8s",
            "kubelet",
            "etcd",
            "docker escape",
            "container escape",
            "serviceaccount",
            "169.254.169.254",
            "metadata service",
        ],
        "keywords": [
            "kubectl",
            "api server",
            "hostnetwork",
            "hostpid",
            "privileged",
            "/var/run/secrets/kubernetes.io/serviceaccount",
            "imds",
            "cloud metadata",
            "docker.sock",
        ],
    },
    "cve-2024-2025": {
        "required_any": [
            "cve-2024-",
            "cve-2025-",
            "regresshion",
            "ivanti",
            "teamcity",
            "php-cgi",
            "pan-os",
            "globalprotect",
            "xz backdoor",
        ],
        "keywords": [
            "cve-2024-4577",
            "cve-2024-23897",
            "cve-2024-3400",
            "cve-2024-27198",
            "cve-2024-3094",
            "soft hyphen",
            "jenkins cli",
            "connect secure",
            "teamcity",
            "openssh",
        ],
    },
}


# 技能提纯：优先使用短摘要，避免长文与乱码污染上下文
SKILL_DISTILLED_OVERRIDES: Dict[str, str] = {
    "struts2-ognl": (
        "## Struts2 OGNL 漏洞族验证\n"
        "- 先识别注入位置：请求头/上传链路（偏 `Content-Type`、`multipart`、`doUpload.action`）或路径/命名空间链路（偏 `namespace`、`ActionChain`、路径级 OGNL）。\n"
        "- 对上传链路，若使用 `Content-Type` 头注入，payload 末尾是否保持 `.multipart/form-data` 会直接影响验证结果。\n"
        "- 必须提供可重复运行时证据（如 whoami / uid= / 固定算术回显）。\n"
        "- 先记录基线响应，再做低风险探测，再做运行时验证；仅 200/302 页面变化、普通上传页、showcase 页面都不能确认。\n"
        "- 仅状态码变化、普通页面回显、单次偶然结果都不能确认。\n"
        "- 若只拿到模板/表达式探测结果而无运行时证据，不得把 Struts2 OGNL 误写成 SSTI 或已确认 RCE。\n"
        "- 类型确认与 CVE 归因分离：先确认 OGNL 命令执行，再给候选 CVE 概率。\n"
    ),
    "pentest-master": (
        "## 渗透测试总调度\n"
        "- 阶段顺序：信息收集 -> 漏洞研判 -> 验证利用 -> 报告输出。\n"
        "- 每轮先给下一步最小动作，再执行并记录证据，避免空转规划。\n"
    ),
    "web-recon": (
        "## Web 侦察\n"
        "- 目标指纹识别、端点发现、参数发现。\n"
        "- 输出可利用入口清单，为后续漏洞验证提供输入。\n"
    ),
    "vuln-assess": (
        "## 漏洞研判\n"
        "- 先判定漏洞类型，再进入对应验证路径。\n"
        "- 同类漏洞并存时必须做区分验证，避免误报到错误 CVE。\n"
    ),
    "exploitation": (
        "## 利用阶段\n"
        "- 以低破坏验证优先，逐步提升到命令执行或数据读取证据。\n"
        "- 每一步都要记录请求、响应与结论，避免跳步确认。\n"
    ),
    "reporting": (
        "## 报告输出\n"
        "- 已验证漏洞优先展示；未验证项按概率排序并标注证据不足点。\n"
        "- 漏洞类型与 CVE 归因分离描述，避免重复或冲突条目。\n"
    ),
    "rce": "## RCE 验证\n- 使用最小化 payload。\n- 以可重复运行时证据确认（uid/whoami）。\n- 类型确认与 CVE 归因分离处理。",
    "ssti": (
        "## SSTI 验证\n"
        "- 先用确定性表达式验证服务端求值，如 `{{7*7}}` 或等价语法。\n"
        "- 若进一步触发命令执行，根因仍归类为 SSTI，不要直接泛化成普通 RCE。\n"
        "- 仅模板回显、状态码变化或静态页面差异不能确认。"
    ),
    "sqli": "## SQLi 验证\n- 区分报错/布尔/时间盲注。\n- 记录参数、响应差异和数据库证据，避免单点误判。",
    "xss": "## XSS 验证\n- 明确上下文（HTML/属性/JS/URL）后选 payload。\n- 必须证明可执行，单纯回显不确认为 XSS。",
    "xxe": (
        "## XXE 验证\n"
        "- 先确认目标确实走 XML 解析链路，再构造外部实体探测。\n"
        "- 需要文件读取、实体解析或外联证据；普通 XML 报错不能直接确认为 XXE。\n"
        "- 若证据更接近 XMLDecoder/反序列化 RCE，应转入对应漏洞族验证。"
    ),
    "file-inclusion": "## 文件包含验证\n- 以目标文件特征内容作为证据。\n- 仅状态码变化或普通页面不确认。",
    "ssrf": "## SSRF 验证\n- 先外部回连，再内网/元数据探测。\n- 需要命中证据或响应特征。",
    "auth-bypass": "## 越权验证\n- 对比同会话不同对象/角色访问结果。\n- 记录原权限、绕过动作、绕过后资源。",
    "modern-web": (
        "## 现代 Web 漏洞\n"
        "- 聚焦 GraphQL、JWT、Request Smuggling、Prototype Pollution、WebSocket/OAuth 类场景。\n"
        "- 必须先识别协议与上下文，再进入对应验证路径，避免把现代 Web 特征误归到传统漏洞类型。\n"
    ),
    "cloud-native": (
        "## 云原生/容器场景\n"
        "- 聚焦 Kubernetes、Kubelet、etcd、ServiceAccount、元数据服务与容器逃逸相关风险。\n"
        "- 仅在存在云原生/容器指示器时使用，避免对普通 Web 目标注入无关上下文。\n"
    ),
    "cve-2024-2025": (
        "## 2024-2025 高危 CVE\n"
        "- 聚焦近期高危产品族，如 Ivanti、TeamCity、PHP-CGI、Jenkins、PAN-OS、OpenSSH 等。\n"
        "- 仅在上下文中出现明确产品与近期 CVE 信号时启用，防止近期漏洞知识污染通用推理。\n"
    ),
}

MOJIBAKE_MARKERS = ["锛", "銆", "鍙", "妫", "璇", "鏃", "鍑", "鏈", "绔", "缁"]


def _candidate_external_roots() -> List[Path]:
    # Default behavior: only load in-project skills.
    # External packs are opt-in via EXTRA_SKILL_DIRS.
    candidates: List[Path] = []

    extra = os.getenv("EXTRA_SKILL_DIRS", "").strip()
    if extra:
        for item in extra.split(os.pathsep):
            item = item.strip()
            if item:
                candidates.append(Path(item))

    uniq: List[Path] = []
    seen = set()
    for p in candidates:
        rp = p.resolve() if p.exists() else p
        if str(rp) in seen:
            continue
        seen.add(str(rp))
        uniq.append(p)
    return uniq


def _valid_skill_subdir(d: Path) -> bool:
    if not d.is_dir():
        return False
    name = d.name
    if name.startswith("._") or name == "__MACOSX":
        return False
    return (d / "SKILL.md").exists()


def _split_tokens(text: str) -> List[str]:
    parts = re.split(r"[^a-zA-Z0-9\u4e00-\u9fff]+", text.lower())
    return [p for p in parts if len(p) >= 4 and p not in GENERIC_STOPWORDS]


def _rule_keyword_match(lower: str, keyword: str) -> bool:
    kw = str(keyword or "").strip().lower()
    if not kw:
        return False
    if re.fullmatch(r"[a-z0-9_-]+", kw):
        return bool(re.search(rf"\b{re.escape(kw)}\b", lower))
    return kw in lower


def _extract_frontmatter(skill_text: str) -> Tuple[str, str]:
    """Return (name, description) from YAML frontmatter best-effort."""
    skill_text = (skill_text or "").lstrip("\ufeff")
    if not skill_text.startswith("---"):
        return "", ""
    end_idx = skill_text.find("\n---", 3)
    if end_idx == -1:
        return "", ""
    fm = skill_text[3:end_idx]
    name_match = re.search(r"(?m)^name:\s*(.+)$", fm)
    desc_match = re.search(r"(?m)^description:\s*(.+)$", fm)
    name = name_match.group(1).strip() if name_match else ""
    desc = desc_match.group(1).strip() if desc_match else ""
    return name, desc


def _build_skill_index() -> Tuple[Dict[str, Dict], Dict[str, List[str]], Dict[str, List[str]]]:
    """
    Build skill index.
    Returns:
      - index: key -> {name, path, source, keywords}
      - aliases: basename -> [keys]
      - source_roots: source -> [path strings]
    """
    index: Dict[str, Dict] = {}
    aliases: Dict[str, List[str]] = {}
    source_roots: Dict[str, List[str]] = {"builtin": [str(SKILLS_DIR)]}

    def add_skill(path: Path, source: str):
        base_name = path.name
        key = base_name
        if key in index:
            key = f"{source}:{base_name}"

        try:
            text = (path / "SKILL.md").read_text(encoding="utf-8")
        except Exception:
            return

        fm_name, fm_desc = _extract_frontmatter(text)
        display_name = fm_name or base_name
        keyword_seed = " ".join([
            base_name,
            display_name,
            str(path.parent.name),
        ])
        keywords = sorted(set(_split_tokens(keyword_seed)))[:40]

        index[key] = {
            "name": display_name,
            "path": path / "SKILL.md",
            "source": source,
            "keywords": keywords,
        }
        aliases.setdefault(base_name, []).append(key)

    # 1) Built-in skills first (preferred)
    for d in SKILLS_DIR.iterdir():
        if _valid_skill_subdir(d):
            add_skill(d, "builtin")

    # 2) External packs
    for ext_root in _candidate_external_roots():
        if not ext_root.exists() or not ext_root.is_dir():
            continue
        source = f"external:{ext_root.name}"
        source_roots.setdefault(source, []).append(str(ext_root))
        for d in ext_root.iterdir():
            if _valid_skill_subdir(d):
                add_skill(d, source)

    return index, aliases, source_roots


_SKILL_INDEX, _SKILL_ALIASES, _SKILL_SOURCE_ROOTS = _build_skill_index()


def _resolve_skill_key(skill_name: str) -> Optional[str]:
    if skill_name in _SKILL_INDEX:
        return skill_name
    # basename alias fallback: prefer builtin then external
    keys = _SKILL_ALIASES.get(skill_name, [])
    if not keys:
        return None
    keys = sorted(keys, key=lambda k: (0 if _SKILL_INDEX[k]["source"] == "builtin" else 1, k))
    return keys[0]


def get_available_skills() -> List[str]:
    return sorted(_SKILL_INDEX.keys())


def _looks_like_mojibake(text: str) -> bool:
    hits = sum(text.count(m) for m in MOJIBAKE_MARKERS)
    return hits >= 12


def _distill_skill_content(key: str, raw_content: str, max_chars: int) -> str:
    override = SKILL_DISTILLED_OVERRIDES.get(key)
    if override:
        return override.strip()[:max_chars]

    text = (raw_content or "").strip()
    if not text:
        return text

    # 优先抽取关键章节，避免把整本字典灌入上下文
    preferred_headers = [
        "## Fast fingerprint",
        "## Verification strategy",
        "## Common failure causes",
        "## Reporting requirements",
        "## 常见指示器",
        "## 检测方法",
        "## 攻击向量",
        "## 误报",
        "## 报告",
        "## 最佳实践",
    ]
    lines = text.splitlines()
    keep: List[str] = []
    capturing = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## "):
            capturing = any(stripped.startswith(h) for h in preferred_headers)
            if capturing:
                keep.append(stripped)
            continue
        if capturing and stripped:
            keep.append(stripped)
        if len("\n".join(keep)) >= max_chars:
            break

    candidate = "\n".join(keep).strip() or text
    return candidate[:max_chars]


def load_skill(skill_name: str, for_context: bool = False) -> Optional[str]:
    key = _resolve_skill_key(skill_name)
    if not key:
        log_system_event(
            f"[Skills] Skill not found: {skill_name}",
            {"available_count": len(_SKILL_INDEX)},
            level=logging.WARNING,
        )
        return None

    skill_meta = _SKILL_INDEX[key]
    skill_path = skill_meta["path"]

    try:
        content = skill_path.read_text(encoding="utf-8")
        content = content.lstrip("\ufeff")
        # strip yaml front matter
        if content.startswith("---"):
            end_idx = content.find("\n---", 3)
            if end_idx != -1:
                content = content[end_idx + 4 :].strip()

        if for_context:
            max_chars = int(os.getenv("SKILL_SINGLE_CONTEXT_MAX_CHARS", "2200"))
            if _looks_like_mojibake(content):
                distilled = SKILL_DISTILLED_OVERRIDES.get(key, "")
                if distilled:
                    content = distilled
                else:
                    content = _distill_skill_content(key, content, max_chars=max_chars)
            else:
                content = _distill_skill_content(key, content, max_chars=max_chars)

        log_system_event(
            f"[Skills] Loaded skill: {key}",
            {
                "source": skill_meta["source"],
                "path": str(skill_path),
                "length": len(content),
                "for_context": for_context,
            },
        )
        return content

    except Exception as e:
        log_system_event(
            f"[Skills] Load failed: {key}",
            {"error": str(e), "path": str(skill_path)},
            level=logging.ERROR,
        )
        return None


def _score_routing_rule(lower: str, rule: Dict) -> int:
    required_any = [str(x).lower() for x in (rule.get("required_any") or []) if str(x).strip()]
    keywords = [str(x).lower() for x in (rule.get("keywords") or []) if str(x).strip()]
    negative = [str(x).lower() for x in (rule.get("negative") or []) if str(x).strip()]

    required_hits = sum(1 for k in required_any if _rule_keyword_match(lower, k))
    if required_any and required_hits == 0:
        return 0

    kw_hits = 0
    for kw in keywords:
        if _rule_keyword_match(lower, kw):
            kw_hits += 1

    neg_hits = sum(1 for k in negative if _rule_keyword_match(lower, k))
    score = required_hits * 8 + kw_hits * 2 - neg_hits * 5
    return max(score, 0)


def _apply_mutex_group(ranked: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    selected: List[Tuple[str, int]] = []
    used_groups = set()
    for key, score in ranked:
        base_key = key.rsplit(":", 1)[-1] if ":" in key else key
        rule = SKILL_ROUTING_RULES.get(base_key, {})
        group = rule.get("mutex_group")
        if group and group in used_groups:
            continue
        selected.append((key, score))
        if group:
            used_groups.add(group)
    return selected


def _base_skill_key(key: str) -> str:
    return key.rsplit(":", 1)[-1] if ":" in key else key


def _skill_category(key: str) -> str:
    return SKILL_CATEGORIES.get(_base_skill_key(key), "unknown")


def _suppress_shadowed_skills(ranked: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    present = {_base_skill_key(key) for key, _ in ranked}
    suppressed: List[Tuple[str, int]] = []
    for key, score in ranked:
        base_key = _base_skill_key(key)
        blocked_by = SKILL_SUPPRESSION_RULES.get(base_key, {}).get("blocked_by", set())
        if blocked_by and (present & blocked_by):
            continue
        suppressed.append((key, score))
    return suppressed


def _phase_allows_skill(stage: str, key: str) -> bool:
    stage = (stage or "auto").strip().lower()
    allowed = STAGE_ALLOWED_CATEGORIES.get(stage, STAGE_ALLOWED_CATEGORIES["auto"])
    return _skill_category(key) in allowed


def _rank_skills_from_text(text: str, min_score: int = 2) -> List[Tuple[str, int]]:
    if not text:
        return []
    lower = text.lower()
    scores: Dict[str, int] = {}

    # A) rule-based high precision routing
    for skill_name, rule in SKILL_ROUTING_RULES.items():
        resolved = _resolve_skill_key(skill_name)
        if not resolved:
            continue
        score = _score_routing_rule(lower, rule)
        if score > 0:
            scores[resolved] = scores.get(resolved, 0) + score

    # B) metadata-based weak fallback
    for key, meta in _SKILL_INDEX.items():
        score = 0
        for kw in meta.get("keywords", []):
            if not kw or len(kw) < 4:
                continue
            if _rule_keyword_match(lower, kw):
                score += 1
        if score >= 2:
            scores[key] = scores.get(key, 0) + score

    ranked = sorted(
        [(k, v) for k, v in scores.items() if v >= min_score],
        key=lambda x: x[1],
        reverse=True
    )
    return _apply_mutex_group(ranked)

def detect_skill_from_hint(hint: str) -> List[str]:
    ranked = _rank_skills_from_text(hint or "", min_score=2)
    if ranked:
        log_system_event(
            "[Skills] Detected from hint",
            {"hint_preview": (hint or "")[:120], "matches": ranked[:8]},
        )
    return [k for k, _ in ranked]


def detect_skill_from_response(response: str) -> List[str]:
    ranked = _rank_skills_from_text(response or "", min_score=2)
    return [k for k, _ in ranked]


def load_skills_for_context(
    hint: Optional[str] = None,
    response: Optional[str] = None,
    explicit_skills: Optional[List[str]] = None,
    max_skills: int = 2,
    stage: str = "auto",
) -> str:
    score_map: Dict[str, int] = {}
    explicit_resolved = set()

    # 1) explicit skills
    for s in explicit_skills or []:
        key = _resolve_skill_key(s)
        if key:
            score_map[key] = score_map.get(key, 0) + 100
            explicit_resolved.add(key)

    # 2) hint + response detections
    for idx, key in enumerate(detect_skill_from_hint(hint or "")):
        score_map[key] = score_map.get(key, 0) + max(20 - idx, 1)
    for idx, key in enumerate(detect_skill_from_response(response or "")):
        score_map[key] = score_map.get(key, 0) + max(10 - idx, 1)

    if not score_map:
        log_system_event("[Skills] No relevant skills detected")
        return ""

    ranked = sorted(score_map.items(), key=lambda x: x[1], reverse=True)
    # 默认屏蔽流程型大 skill，除非显式指定
    ranked = [
        (k, v)
        for (k, v) in ranked
        if (k in explicit_resolved) or (k not in CONTEXT_EXCLUDED_SKILLS)
    ]
    if not ranked:
        log_system_event("[Skills] All detected skills filtered by context exclusion")
        return ""

    stage = (stage or "auto").strip().lower()
    ranked = [
        (k, v)
        for (k, v) in ranked
        if (k in explicit_resolved) or _phase_allows_skill(stage, k)
    ]
    if not ranked:
        log_system_event(
            "[Skills] All detected skills filtered by stage",
            {"stage": stage},
        )
        return ""

    min_context_score = int(os.getenv("MIN_SKILL_CONTEXT_SCORE", "8"))
    filtered: List[Tuple[str, int]] = []
    for key, score in ranked:
        category = _skill_category(key)
        threshold = max(min_context_score, CATEGORY_MIN_CONTEXT_SCORES.get(category, min_context_score))
        if key in explicit_resolved:
            threshold = 0
        if score >= threshold:
            filtered.append((key, score))
    if not filtered:
        log_system_event(
            "[Skills] Ranked but skipped due low context score",
            {"top_matches": ranked[:8], "min_context_score": min_context_score},
        )
        return ""
    filtered = _suppress_shadowed_skills(filtered)
    if not filtered:
        log_system_event("[Skills] All filtered skills suppressed by higher-specificity skills")
        return ""
    selected: List[str] = []
    category_counts: Dict[str, int] = {}
    for key, score in filtered:
        if len(selected) >= max(1, max_skills):
            break
        category = _skill_category(key)
        category_limit = SKILL_CATEGORY_LIMITS.get(category, 1)
        if category_counts.get(category, 0) >= category_limit:
            continue
        selected.append(key)
        category_counts[category] = category_counts.get(category, 0) + 1

    loaded = []
    for key in selected:
        content = load_skill(key, for_context=True)
        if not content:
            continue
        meta = _SKILL_INDEX.get(key, {})
        loaded.append(
            f"## {meta.get('name', key)} ({key})\n"
            f"**source**: {meta.get('source', 'unknown')}\n\n"
            f"{content}"
        )

    if not loaded:
        return ""

    log_system_event(
        f"[Skills] Loaded {len(loaded)} skills",
        {
            "selected": selected,
            "categories": {key: _skill_category(key) for key in selected},
            "sources": _SKILL_SOURCE_ROOTS,
            "stage": stage,
        },
    )
    return "\n\n---\n\n".join(loaded)


def get_skill_summary() -> str:
    lines = [
        "## Available Skills",
        "",
        "| Key | Category | Source | Path |",
        "|-----|----------|--------|------|",
    ]
    for key in sorted(_SKILL_INDEX.keys()):
        meta = _SKILL_INDEX[key]
        lines.append(f"| {key} | {_skill_category(key)} | {meta.get('source','?')} | {meta.get('path')} |")
    return "\n".join(lines)



