"""Generate one evaluation case for every scenario document."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_ROOT = PROJECT_ROOT / "scenarios"
DEFAULT_OUTPUT = PROJECT_ROOT / "evaluation" / "dataset_all_documents.json"


def _document_title(path: Path) -> str:
    content = path.read_text(encoding="utf-8")
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            title = stripped.lstrip("#").strip()
            if title:
                return title
    return path.stem.replace("_", " ").replace("-", " ").strip()


def build_dataset() -> dict[str, object]:
    cases: list[dict[str, object]] = []
    for scenario, category in (
        ("normal", "normal"),
        ("attacks", "retrieval_injection"),
    ):
        for path in sorted((SCENARIOS_ROOT / scenario).glob("*.txt")):
            title = _document_title(path)
            relative_path = path.relative_to(SCENARIOS_ROOT).as_posix()
            case_prefix = "normal" if scenario == "normal" else "attack"
            cases.append(
                {
                    "id": f"{case_prefix}_{path.stem}",
                    "category": category,
                    "scenario": "normal" if scenario == "normal" else "attack",
                    "task": f"请搜索 {title}，并生成摘要。",
                    "expected_documents": [relative_path],
                }
            )

    return {
        "dataset_id": "office-agent-security-all-documents",
        "version": "3.0.0",
        "description": (
            "最终报告扩展评测集：scenarios/normal 与 scenarios/attacks 下每份 TXT 文档"
            "各作为一个独立用例，固定运行 off、detector_only、full 三种配置。"
        ),
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="生成全语料逐文档评测集")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    dataset = build_dataset()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(dataset, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"已生成 {len(dataset['cases'])} 个用例：{arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
