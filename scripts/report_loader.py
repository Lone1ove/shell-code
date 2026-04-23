import json
import re
from pathlib import Path
from typing import Dict, List


def _reports_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "reports"


def _parse_markdown_report(path: Path) -> Dict:
    text = path.read_text(encoding="utf-8-sig")
    report: Dict = {
        "report_meta": {},
        "summary": {},
        "detection_metrics": {},
        "findings": [],
    }

    current_finding: Dict | None = None
    lines = text.splitlines()
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("- 任务ID:"):
            report["report_meta"]["challenge_code"] = line.split("`")[1] if "`" in line else line.split(":", 1)[1].strip()
        elif line.startswith("- 目标地址:"):
            report["report_meta"]["target"] = line.split("`")[1] if "`" in line else line.split(":", 1)[1].strip()
        elif line.startswith("- 执行结果:"):
            value = line.split("`")[1] if "`" in line else line.split(":", 1)[1].strip()
            report["summary"]["success"] = value == "成功"
        elif line.startswith("- 运行模式:"):
            report["summary"]["objective_mode"] = line.split("`")[1] if "`" in line else line.split(":", 1)[1].strip()
        elif line.startswith("- 是否检测到漏洞:"):
            value = line.split("`")[1] if "`" in line else line.split(":", 1)[1].strip()
            report["summary"]["vulnerability_detected"] = value == "是"
        elif line.startswith("- 漏洞总数:"):
            report["summary"]["findings_count"] = int(re.findall(r"\d+", line)[0])
        elif line.startswith("- 已验证漏洞数:"):
            report["summary"]["verified_findings_count"] = int(re.findall(r"\d+", line)[0])
        elif line.startswith("- 严格验证通过数:"):
            report["summary"]["strict_verified_findings_count"] = int(re.findall(r"\d+", line)[0])
        elif line.startswith("- 已确认数量:"):
            report["detection_metrics"]["confirmed_count"] = int(re.findall(r"\d+", line)[0])
        elif line.startswith("- 疑似数量:"):
            report["detection_metrics"]["suspected_count"] = int(re.findall(r"\d+", line)[0])
        elif line.startswith("- 已排除数量:"):
            report["detection_metrics"]["rejected_count"] = int(re.findall(r"\d+", line)[0])
        elif line.startswith("- 误报率:"):
            nums = re.findall(r"\d+(?:\.\d+)?", line)
            report["detection_metrics"]["false_positive_rate"] = float(nums[0]) if nums else 0.0
        elif line.startswith("### 5."):
            if current_finding:
                report["findings"].append(current_finding)
            current_finding = {"status": "suspected", "cve_verdict": "absent"}
        elif current_finding is not None and line.startswith("- 漏洞类型:"):
            current_finding["vuln_type"] = line.split("`")[1] if "`" in line else line.split(":", 1)[1].strip()
        elif current_finding is not None and line.startswith("- 类型结论:"):
            value = line.split("`")[1] if "`" in line else line.split(":", 1)[1].strip()
            current_finding["status"] = "confirmed" if "已确认" in value else "suspected"
        elif current_finding is not None and line.startswith("- 严格验证:"):
            current_finding["strict_verified"] = "通过" in line
        elif current_finding is not None and line.startswith("- 对应CVE:"):
            match = re.search(r"(CVE-\d{4}-\d{4,7})", line, re.IGNORECASE)
            if match:
                current_finding["cve"] = match.group(1).upper()
                current_finding["cve_verdict"] = "confirmed"
        elif current_finding is not None and line.startswith("- 可能CVE（按概率）:"):
            match = re.search(r"(CVE-\d{4}-\d{4,7})", line, re.IGNORECASE)
            if match:
                current_finding["cve"] = match.group(1).upper()
                current_finding["cve_verdict"] = "weak_match"

    if current_finding:
        report["findings"].append(current_finding)

    return report


def load_reports(limit: int = 200) -> List[Dict]:
    reports_dir = _reports_dir()
    all_files = sorted(reports_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    dedup: List[Path] = []
    seen_stems = set()
    for p in all_files:
        if p.suffix.lower() not in {".json", ".md"}:
            continue
        stem = p.stem
        if stem in seen_stems:
            continue
        seen_stems.add(stem)
        dedup.append(p)

    out: List[Dict] = []

    for p in dedup:
        if len(out) >= limit:
            break
        try:
            if p.suffix.lower() == ".json":
                payload = json.loads(p.read_text(encoding="utf-8-sig"))
            elif p.suffix.lower() == ".md":
                payload = _parse_markdown_report(p)
            else:
                continue
            if "report_meta" in payload and "findings" in payload:
                out.append(payload)
        except Exception:
            continue

    return out
