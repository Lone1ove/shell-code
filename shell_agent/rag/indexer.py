"""
WooYun RAG 索引构建脚本。
用法: python -m shell_agent.rag.indexer
"""
import os
import re
import json
import time
import requests
from pathlib import Path
from typing import List, Dict

DATA_DIR = Path(__file__).parent / "data"
CATEGORIES_URL = "https://api.github.com/repos/tanweai/wooyun-legacy/contents/categories"
RAW_BASE = "https://raw.githubusercontent.com/tanweai/wooyun-legacy/main/categories"

# 漏洞类型映射
VULN_TYPE_MAP = {
    "sql-injection": "sqli",
    "command-execution": "rce",
    "xss": "xss",
    "ssrf": "ssrf",
    "file-upload": "upload",
    "file-traversal": "lfi",
    "xxe": "xxe",
    "csrf": "csrf",
    "unauthorized-access": "auth",
    "info-disclosure": "info",
    "weak-password": "weak",
    "logic-flaws": "logic",
    "misconfig": "misconfig",
    "rce": "rce",
    "other": "other",
}


def parse_wooyun_entry(text: str, vuln_type: str) -> Dict:
    """解析单条 WooYun 记录"""
    entry = {"type": vuln_type, "raw": text[:3000]}

    title_match = re.search(r"###\s*\[([^\]]+)\]\s*(.+)", text)
    if title_match:
        entry["id"] = title_match.group(1)
        entry["title"] = title_match.group(2).strip()

    for field, pattern in [
        ("vendor", r"\*\*厂商\*\*:\s*([^\|]+)"),
        ("year", r"\*\*年份\*\*:\s*(\d+)"),
        ("poc", r"\*\*POC\*\*:\s*(.+?)(?=\*\*|---|$)"),
        ("bypass", r"\*\*绕过\*\*:\s*(.+?)(?=\*\*|---|$)"),
        ("detail", r"\*\*详情\*\*:\s*(.+?)(?=\*\*|---|$)"),
    ]:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            entry[field] = match.group(1).strip()[:1500]

    return entry


def download_file(url: str, retries: int = 3) -> str:
    """带重试的下载"""
    for i in range(retries):
        try:
            resp = requests.get(url, timeout=300, stream=True)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            print(f"  Retry {i+1}/{retries}: {e}")
            time.sleep(2)
    return ""


def download_and_parse() -> List[Dict]:
    """下载并解析所有 WooYun 数据"""
    entries = []

    resp = requests.get(CATEGORIES_URL, timeout=30)
    files = resp.json()

    for f in files:
        if not f["name"].endswith(".md"):
            continue

        vuln_type = VULN_TYPE_MAP.get(f["name"].replace(".md", ""), "other")
        size_kb = f.get("size", 0) // 1024
        print(f"Downloading {f['name']} ({size_kb}KB)...")

        raw_url = f"{RAW_BASE}/{f['name']}"
        content = download_file(raw_url)
        if not content:
            print(f"  Failed to download {f['name']}, skipping")
            continue

        chunks = re.split(r"\n---\n", content)
        count = 0
        for chunk in chunks:
            chunk = chunk.strip()
            if not chunk or "###" not in chunk:
                continue
            entry = parse_wooyun_entry(chunk, vuln_type)
            if entry.get("title"):
                entries.append(entry)
                count += 1
        print(f"  Parsed {count} entries")

    return entries


def build_index(entries: List[Dict]):
    """构建简单的关键词索引"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    by_type: Dict[str, List[Dict]] = {}
    for e in entries:
        t = e.get("type", "other")
        by_type.setdefault(t, []).append(e)

    for vuln_type, type_entries in by_type.items():
        path = DATA_DIR / f"{vuln_type}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(type_entries, f, ensure_ascii=False, indent=2)
        print(f"Saved {len(type_entries)} entries to {path.name}")

    keyword_index: Dict[str, List[str]] = {}
    for e in entries:
        eid = e.get("id", "")
        if not eid:
            continue
        text = f"{e.get('title', '')} {e.get('detail', '')} {e.get('poc', '')}"
        words = set(re.findall(r"[a-zA-Z]{3,}|[\u4e00-\u9fa5]{2,}", text.lower()))
        for w in words:
            keyword_index.setdefault(w, []).append(eid)

    with open(DATA_DIR / "keyword_index.json", "w", encoding="utf-8") as f:
        json.dump(keyword_index, f, ensure_ascii=False)

    id_map = {e["id"]: e for e in entries if e.get("id")}
    with open(DATA_DIR / "id_map.json", "w", encoding="utf-8") as f:
        json.dump(id_map, f, ensure_ascii=False)

    print(f"Index built: {len(id_map)} entries, {len(keyword_index)} keywords")


def main():
    print("Starting WooYun data indexing...")
    entries = download_and_parse()
    print(f"Total: {len(entries)} entries")
    build_index(entries)
    try:
        from shell_agent.rag.cve_indexer import main as build_cve_rag_index

        print("Merging local CVE intelligence into RAG index...")
        build_cve_rag_index()
    except Exception as exc:
        print(f"Skip CVE merge: {exc}")
    print("Done!")


if __name__ == "__main__":
    main()
