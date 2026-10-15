from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent.agent import extract_search_query, run_office_task
from agent.llm_client import summarize_locally
from tools.registry import ToolRegistry


@pytest.mark.parametrize(
    ("task", "expected"),
    [
        ("请搜索项目资料，并生成一份摘要。", "项目资料"),
        ("检索安全模块里程碑，然后总结", "安全模块里程碑"),
        ("Search for Demo Environment and summarize it.", "Demo Environment"),
    ],
)
def test_extract_search_query(task: str, expected: str) -> None:
    assert extract_search_query(task) == expected


def test_normal_user_task_runs_search_and_local_summary(tmp_path: Path) -> None:
    audit_path = tmp_path / "events.jsonl"
    registry = ToolRegistry(audit_path=audit_path)

    result = run_office_task(
        "请搜索项目资料，并生成一份摘要。",
        registry=registry,
        trace_id="task-normal",
    )

    assert result.ok is True
    assert result.search_query == "项目资料"
    assert result.documents
    assert "摘要如下" in result.answer
    assert [step.stage for step in result.steps] == [
        "task_parsing",
        "document_search",
        "injection_detection",
        "summary_generation",
    ]
    assert all(step.status == "completed" for step in result.steps)
    event = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])
    assert event["tool"] == "search_documents"
    assert event["trace_id"] == "task-normal"
    assert event["argument_sources"]["query"]["source_type"] == "user_input"


def test_local_summary_treats_injected_document_text_as_data(tmp_path: Path) -> None:
    result = run_office_task(
        "请搜索项目启动计划，并生成摘要。",
        scenario="attack",
        registry=ToolRegistry(audit_path=tmp_path / "events.jsonl"),
    )

    assert result.ok is True
    assert any(path["relative_path"].startswith("attacks/") for path in result.documents)
    assert "secret.txt" not in result.answer
    assert "attacker@example.com" not in result.answer
    assert "read_file" not in result.answer
    assert "send_email" not in result.answer


def test_local_summary_handles_no_documents() -> None:
    assert summarize_locally([]) == "没有检索到与任务相关的资料，暂时无法生成摘要。"


def test_no_match_is_a_successful_task_with_clear_answer(tmp_path: Path) -> None:
    result = run_office_task(
        "请搜索火星农业，并生成摘要。",
        registry=ToolRegistry(audit_path=tmp_path / "events.jsonl"),
    )

    assert result.ok is True
    assert result.documents == []
    assert "没有检索到" in result.answer


def test_dashscope_mode_without_key_returns_explicit_error(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("DASHSCOPE_API_KEY", raising=False)

    result = run_office_task(
        "请搜索项目资料，并生成摘要。",
        mode="dashscope",
        registry=ToolRegistry(audit_path=tmp_path / "events.jsonl"),
    )

    assert result.ok is False
    assert result.error == {
        "code": "DASHSCOPE_API_KEY_MISSING",
        "message": "阿里云百炼模式需要设置 DASHSCOPE_API_KEY。",
    }


def test_dashscope_mode_uses_compatible_client_without_exposing_tools(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("DASHSCOPE_API_KEY", "test-key-not-used")
    monkeypatch.delenv("DASHSCOPE_MODEL", raising=False)
    monkeypatch.setenv("DASHSCOPE_BASE_URL", "https://example.test/compatible-mode/v1")
    with patch(
        "agents.Runner.run_sync",
        return_value=SimpleNamespace(final_output="在线摘要结果"),
    ) as run_sync:
        result = run_office_task(
            "请搜索项目资料，并生成摘要。",
            mode="dashscope",
            registry=ToolRegistry(audit_path=tmp_path / "events.jsonl"),
        )

    assert result.ok is True
    assert result.answer == "在线摘要结果"
    summary_agent = run_sync.call_args.args[0]
    assert summary_agent.tools == []
    assert summary_agent.model.model == "qwen-flash"
    assert str(summary_agent.model._client.base_url) == "https://example.test/compatible-mode/v1/"
    assert run_sync.call_args.kwargs["max_turns"] == 2


def test_empty_user_task_is_rejected_without_tool_call(tmp_path: Path) -> None:
    audit_path = tmp_path / "events.jsonl"

    result = run_office_task("  ", registry=ToolRegistry(audit_path=audit_path))

    assert result.ok is False
    assert result.error["code"] == "EMPTY_USER_TASK"
    assert not audit_path.exists()
