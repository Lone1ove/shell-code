import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RAG_DATA_DIR = ROOT / "shell_agent" / "rag" / "data"


def _sanitize_text(text: str) -> str:
    value = str(text or "")
    if "\ufffd" not in value:
        return value
    value = value.replace("\ufffd", "")
    value = re.sub(r"[ \t]{2,}", " ", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def _sanitize(value):
    if isinstance(value, str):
        return _sanitize_text(value)
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize(item) for key, item in value.items()}
    return value


def main() -> None:
    repaired_files = 0
    repaired_fields = 0

    for path in sorted(RAG_DATA_DIR.glob("*.json")):
        raw_text = path.read_text(encoding="utf-8")
        before = raw_text.count("\ufffd")
        if before == 0:
            continue

        data = json.loads(raw_text)
        repaired = _sanitize(data)
        path.write_text(json.dumps(repaired, ensure_ascii=False, indent=2), encoding="utf-8")

        repaired_files += 1
        repaired_fields += before
        print(f"repaired {path.name}: removed {before} replacement characters")

    print(f"done: files={repaired_files}, replacement_chars_removed={repaired_fields}")


if __name__ == "__main__":
    main()
