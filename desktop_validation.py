"""在真实发布程序中执行资源检查和可选的在线链路检查。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from desktop_config import application_root, resource_root


def verify_package(*, online: bool = False) -> int:
    # 此导入会触发 SDK 的提示词资源读取，不能仅检查页面能否打开。
    import agents
    from llm_guard.input_scanners import PromptInjection
    from agent.agent import run_office_task
    from security.detector import detector_metadata
    from tools.read_file import load_sensitive_paths
    from tools.search_documents import search_documents

    prompts = list((Path(agents.__file__).parent / "sandbox" / "memory" / "prompts").glob("*.md"))
    if not prompts or not all(path.read_text(encoding="utf-8").strip() for path in prompts):
        raise RuntimeError("发布包缺少 Agents SDK 提示词资源。")
    load_sensitive_paths()
    search_result = search_documents("Q4")
    if not search_result["ok"]:
        raise RuntimeError("发布包场景检索失败。")
    detector = detector_metadata()
    installed_llm_guard_version = version("llm-guard")
    if installed_llm_guard_version != detector["package_version"]:
        raise RuntimeError("发布包中的 LLM Guard 版本与检测器配置不一致。")
    if PromptInjection.__name__ != "PromptInjection":
        raise RuntimeError("发布包无法导入 LLM Guard PromptInjection。")
    results = []
    if online:
        for scenario, mode in (("normal", "full"), ("attack", "off"), ("attack", "full")):
            result = run_office_task(
                "请搜索 Q4 项目交付计划，并整理摘要。",
                mode="dashscope", scenario=scenario, protection_mode=mode,
            )
            results.append({
                "scenario": scenario, "protection_mode": mode,
                "ok": result.ok, "trace_id": result.trace_id,
                "attack_outcome": result.attack_outcome,
                "error_code": result.error.get("code") if result.error else None,
                "tool_count": len(result.tool_calls),
            })
    report = {
        "checked_at": datetime.now(UTC).isoformat(), "online": online,
        "sdk_import": "ok", "prompt_file_count": len(prompts),
        "sdk_version": getattr(agents, "__version__", "unknown"),
        "detector": detector,
        "runs": results,
    }
    destination = application_root() / "package-validation.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False), flush=True)
    return 0 if all(result["ok"] for result in results) else 1
