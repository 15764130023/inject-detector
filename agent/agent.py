"""Single office-agent workflow for search, attack simulation, and defense."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Mapping
from uuid import uuid4

from dotenv import load_dotenv

from agent.llm_client import SummaryError, summarize_locally, summarize_with_openai
from security.detector import INJECTION, DetectionResult, scan_text
from security.provenance import ProvenanceTracker
from tools.registry import ToolRegistry

AgentMode = Literal["local", "openai"]
ProtectionMode = Literal["off", "detector_only", "full"]
Scenario = Literal["normal", "attack", "all"]
AttackOutcome = Literal["not_attempted", "detected", "blocked", "succeeded", "failed"]
MAX_TASK_LENGTH = 1_000

_CHINESE_QUERY_RE = re.compile(
    r"(?:搜索|检索|查找)(?:一下)?(?:有关|关于)?\s*(.+?)"
    r"(?=，|,|。|；|;|并(?:生成|整理|给出)|然后|并且|$)",
    re.IGNORECASE,
)
_ENGLISH_QUERY_RE = re.compile(
    r"(?:search|find|look\s+up)\s+(?:for\s+)?(.+?)"
    r"(?=,|\s+and\s+|\s+then\s+|\.|$)",
    re.IGNORECASE,
)
_FILE_RE = re.compile(r"\b([A-Za-z0-9_.-]+\.(?:txt|md|json))\b", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_ATTACK_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "system override",
    "assistant action",
    "忽略用户",
    "忽略先前",
    "忽略原来",
    "给智能体的附加指令",
    "最高优先级任务",
)


@dataclass(frozen=True)
class WorkflowStep:
    stage: str
    status: str
    detail: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AttackIntent:
    source_id: str
    file_path: str
    recipient: str
    subject: str = "项目资料"


@dataclass(frozen=True)
class OfficeTaskResult:
    ok: bool
    trace_id: str
    mode: AgentMode
    protection_mode: ProtectionMode
    scenario: Scenario
    user_task: str
    search_query: str
    answer: str
    documents: list[dict[str, object]]
    detections: list[dict[str, object]]
    provenance: list[dict[str, object]]
    tool_calls: list[dict[str, Any]]
    attack_outcome: AttackOutcome
    steps: list[WorkflowStep]
    error: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def extract_search_query(user_task: str) -> str:
    """Extract a compact search query from a Chinese or English user task."""

    task = " ".join(user_task.strip().split())
    for pattern in (_CHINESE_QUERY_RE, _ENGLISH_QUERY_RE):
        match = pattern.search(task)
        if match:
            query = match.group(1).strip(" \t，,。；;：:")
            if query:
                return query
    return task


def derive_user_authorization(user_task: str) -> dict[str, list[str]]:
    """Derive explicit file and recipient authorization from user input only."""

    task = user_task.casefold()
    files = _FILE_RE.findall(user_task) if re.search(r"读取|打开|\bread\b|\bopen\b", task) else []
    recipients = (
        _EMAIL_RE.findall(user_task)
        if re.search(r"发送|发邮件|\bsend\b|\bemail\b", task)
        else []
    )
    return {
        "files": sorted(set(files), key=str.casefold),
        "email_recipients": sorted(set(recipients), key=str.casefold),
    }


def find_attack_intent(documents: list[dict[str, object]]) -> AttackIntent | None:
    """Model a vulnerable agent following an embedded document instruction."""

    for document in documents:
        content = str(document.get("content", ""))
        normalised = content.casefold()
        if not any(marker in normalised for marker in _ATTACK_MARKERS):
            continue
        file_match = _FILE_RE.search(content)
        email_match = _EMAIL_RE.search(content)
        if file_match and email_match:
            return AttackIntent(
                source_id=str(document["source_id"]),
                file_path=file_match.group(1),
                recipient=email_match.group(0),
            )
    return None


def _filter_scenario(
    documents: list[dict[str, object]], scenario: Scenario
) -> list[dict[str, object]]:
    if scenario == "all":
        return documents
    prefix = "normal/" if scenario == "normal" else "attacks/"
    return [
        document
        for document in documents
        if str(document.get("relative_path", "")).startswith(prefix)
    ]


def _failed_result(
    *,
    trace_id: str,
    mode: AgentMode,
    protection_mode: ProtectionMode,
    scenario: Scenario,
    user_task: str,
    search_query: str = "",
    documents: list[dict[str, object]] | None = None,
    detections: list[dict[str, object]] | None = None,
    provenance: list[dict[str, object]] | None = None,
    tool_calls: list[dict[str, Any]] | None = None,
    attack_outcome: AttackOutcome = "not_attempted",
    steps: list[WorkflowStep] | None = None,
    code: str,
    message: str,
) -> OfficeTaskResult:
    return OfficeTaskResult(
        False,
        trace_id,
        mode,
        protection_mode,
        scenario,
        user_task,
        search_query,
        "",
        documents or [],
        detections or [],
        provenance or [],
        tool_calls or [],
        attack_outcome,
        steps or [],
        {"code": code, "message": message},
    )


def _scan_documents(
    documents: list[dict[str, object]],
    *,
    registry: ToolRegistry,
    trace_id: str,
) -> tuple[list[DetectionResult], list[dict[str, object]]]:
    results: list[DetectionResult] = []
    serialized_results: list[dict[str, object]] = []
    for document in documents:
        result = scan_text(str(document["content"]), source_id=str(document["source_id"]))
        serialized = result.to_dict()
        results.append(result)
        serialized_results.append(serialized)
        registry.record_event(
            trace_id,
            "prompt_injection_scan",
            {"source_id": result.source_id, "detection": serialized},
        )
    return results, serialized_results


def _tool_call_record(
    tool: str,
    arguments: Mapping[str, Any],
    argument_sources: Mapping[str, Any],
    result: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "tool": tool,
        "arguments": dict(arguments),
        "argument_sources": dict(argument_sources),
        "result": dict(result),
    }


def _track_tool_result(
    tracker: ProvenanceTracker,
    result: Mapping[str, Any],
    *,
    parent_source_id: str,
) -> str:
    """Register every tool return as untrusted data in the provenance graph."""

    call_id = result.get("meta", {}).get("call_id")
    if not isinstance(call_id, str) or not call_id:
        raise ValueError("工具结果缺少 call_id，无法建立来源关系。")
    source_id = f"tool_result:{call_id}"
    tracker.add_source(
        source_id,
        "tool_result",
        trusted=False,
        parent_source_id=parent_source_id,
    )
    return source_id


def _run_attack_actions(
    intent: AttackIntent,
    *,
    registry: ToolRegistry,
    tracker: ProvenanceTracker,
    trace_id: str,
    protection_mode: ProtectionMode,
    authorization: Mapping[str, Any],
    detection_results: Mapping[str, Any],
) -> tuple[AttackOutcome, list[dict[str, Any]], list[WorkflowStep]]:
    tool_calls: list[dict[str, Any]] = []
    steps: list[WorkflowStep] = []
    gateway_enabled = protection_mode == "full"

    read_arguments = {"path": intent.file_path}
    read_sources = tracker.argument_sources(path=intent.source_id)
    read_result = registry.invoke(
        "read_file",
        read_arguments,
        trace_id=trace_id,
        argument_sources=read_sources,
        detection_results=detection_results,
        protection_enabled=gateway_enabled,
        user_authorization=authorization,
    )
    read_result_source_id = _track_tool_result(
        tracker,
        read_result,
        parent_source_id=intent.source_id,
    )
    tool_calls.append(_tool_call_record("read_file", read_arguments, read_sources, read_result))
    read_policy = read_result.get("meta", {}).get("policy") or {}
    steps.append(
        WorkflowStep(
            "read_file",
            "executed" if read_result.get("ok") else "blocked",
            "已读取本地虚构敏感文件。"
            if read_result.get("ok")
            else str(read_result.get("error", {}).get("message", "文件读取失败。")),
            {"policy": read_policy},
        )
    )

    if read_result.get("ok"):
        file_source_id = str(read_result["data"]["source_id"])
        tracker.add_source(
            file_source_id,
            str(read_result["data"]["source_type"]),
            trusted=False,
            parent_source_id=read_result_source_id,
        )
        email_body = str(read_result["data"]["content"])
        body_source_id = file_source_id
    else:
        email_body = "未能取得目标文件内容。"
        body_source_id = intent.source_id

    email_arguments = {
        "to": intent.recipient,
        "subject": intent.subject,
        "body": email_body,
    }
    email_sources = tracker.argument_sources(
        to=intent.source_id,
        subject=intent.source_id,
        body=body_source_id,
    )
    email_result = registry.invoke(
        "send_email",
        email_arguments,
        trace_id=trace_id,
        argument_sources=email_sources,
        detection_results=detection_results,
        protection_enabled=gateway_enabled,
        user_authorization=authorization,
    )
    _track_tool_result(
        tracker,
        email_result,
        parent_source_id=body_source_id,
    )
    tool_calls.append(
        _tool_call_record("send_email", email_arguments, email_sources, email_result)
    )
    email_policy = email_result.get("meta", {}).get("policy") or {}
    steps.append(
        WorkflowStep(
            "send_email",
            "executed" if email_result.get("ok") else "blocked",
            "邮件已写入本地模拟发件箱。"
            if email_result.get("ok")
            else str(email_result.get("error", {}).get("message", "邮件发送失败。")),
            {"policy": email_policy},
        )
    )

    if read_result.get("ok") and email_result.get("ok"):
        return "succeeded", tool_calls, steps
    if any(
        call["result"].get("error", {}).get("code") == "TOOL_BLOCKED"
        for call in tool_calls
    ):
        return "blocked", tool_calls, steps
    return "failed", tool_calls, steps


def run_office_task(
    user_task: str,
    *,
    mode: AgentMode = "local",
    protection_mode: ProtectionMode = "full",
    scenario: Scenario = "normal",
    registry: ToolRegistry | None = None,
    trace_id: str | None = None,
    protection_enabled: bool | None = None,
) -> OfficeTaskResult:
    """Run the search, detection, attack simulation, policy, and summary workflow."""

    if protection_enabled is not None:
        protection_mode = "full" if protection_enabled else "off"
    trace_id = trace_id or f"task-{uuid4().hex}"
    task = user_task.strip() if isinstance(user_task, str) else ""
    if not task:
        return _failed_result(
            trace_id=trace_id,
            mode=mode,
            protection_mode=protection_mode,
            scenario=scenario,
            user_task=task,
            code="EMPTY_USER_TASK",
            message="用户任务不能为空。",
        )
    if len(task) > MAX_TASK_LENGTH:
        return _failed_result(
            trace_id=trace_id,
            mode=mode,
            protection_mode=protection_mode,
            scenario=scenario,
            user_task=task,
            code="USER_TASK_TOO_LONG",
            message=f"用户任务不能超过 {MAX_TASK_LENGTH} 个字符。",
        )
    if mode not in {"local", "openai"}:
        return _failed_result(
            trace_id=trace_id,
            mode="local",
            protection_mode=protection_mode,
            scenario=scenario,
            user_task=task,
            code="INVALID_AGENT_MODE",
            message="mode 必须是 local 或 openai。",
        )
    if protection_mode not in {"off", "detector_only", "full"}:
        return _failed_result(
            trace_id=trace_id,
            mode=mode,
            protection_mode="full",
            scenario=scenario,
            user_task=task,
            code="INVALID_PROTECTION_MODE",
            message="protection_mode 必须是 off、detector_only 或 full。",
        )
    if scenario not in {"normal", "attack", "all"}:
        return _failed_result(
            trace_id=trace_id,
            mode=mode,
            protection_mode=protection_mode,
            scenario="normal",
            user_task=task,
            code="INVALID_SCENARIO",
            message="scenario 必须是 normal、attack 或 all。",
        )

    steps: list[WorkflowStep] = []
    active_registry = registry or ToolRegistry()
    tracker = ProvenanceTracker()
    tracker.add_source("system_prompt", "system_prompt", trusted=True)
    tracker.add_source("user_task", "user_input", trusted=True)
    authorization = derive_user_authorization(task)
    query = extract_search_query(task)
    steps.append(
        WorkflowStep(
            "task_parsing",
            "completed",
            f"提取检索词：{query}",
            {"user_authorization": authorization},
        )
    )

    search_sources = tracker.argument_sources(query="user_task")
    search_result = active_registry.invoke(
        "search_documents",
        {"query": query},
        trace_id=trace_id,
        argument_sources=search_sources,
        protection_enabled=protection_mode == "full",
    )
    if not search_result.get("ok"):
        error = dict(search_result.get("error", {}))
        steps.append(WorkflowStep("document_search", "failed", error.get("message", "检索失败")))
        return _failed_result(
            trace_id=trace_id,
            mode=mode,
            protection_mode=protection_mode,
            scenario=scenario,
            user_task=task,
            search_query=query,
            provenance=tracker.snapshot(),
            steps=steps,
            code=str(error.get("code", "SEARCH_FAILED")),
            message=str(error.get("message", "检索失败。")),
        )

    search_result_source_id = _track_tool_result(
        tracker,
        search_result,
        parent_source_id="user_task",
    )
    documents = _filter_scenario(list(search_result["data"]["documents"]), scenario)
    for document in documents:
        tracker.add_document(document, parent_source_id=search_result_source_id)
    steps.append(
        WorkflowStep(
            "document_search",
            "completed",
            f"检索到 {len(documents)} 份 {scenario} 场景资料。",
            {
                "call_id": search_result["meta"]["call_id"],
                "sources": [document["source_id"] for document in documents],
            },
        )
    )

    detection_objects: list[DetectionResult] = []
    detections: list[dict[str, object]] = []
    if protection_mode != "off":
        detection_objects, detections = _scan_documents(
            documents,
            registry=active_registry,
            trace_id=trace_id,
        )
        highest_score = max((result.risk_score for result in detection_objects), default=0.0)
        steps.append(
            WorkflowStep(
                "injection_detection",
                "completed",
                f"扫描 {len(detections)} 份资料，最高风险分 {highest_score:.2f}。",
                {"detections": detections},
            )
        )

    detection_context = {
        result.source_id: result.to_dict() for result in detection_objects
    }

    attack_intent = find_attack_intent(documents)
    attack_outcome: AttackOutcome = "not_attempted"
    tool_calls: list[dict[str, Any]] = []
    if attack_intent is not None:
        detected_source_ids = {
            result.source_id for result in detection_objects if result.label == INJECTION
        }
        if (
            protection_mode == "detector_only"
            and attack_intent.source_id in detected_source_ids
        ):
            attack_outcome = "detected"
            steps.append(
                WorkflowStep(
                    "attack_handling",
                    "blocked",
                    "检测器识别出注入，未向危险工具提交调用。",
                    {"source_id": attack_intent.source_id},
                )
            )
            active_registry.record_event(
                trace_id,
                "attack_suppressed_by_detector",
                {"source_id": attack_intent.source_id},
            )
        else:
            attack_outcome, tool_calls, attack_steps = _run_attack_actions(
                attack_intent,
                registry=active_registry,
                tracker=tracker,
                trace_id=trace_id,
                protection_mode=protection_mode,
                authorization=authorization,
                detection_results=detection_context,
            )
            steps.extend(attack_steps)

    try:
        answer = (
            summarize_locally(documents)
            if mode == "local"
            else summarize_with_openai(task, documents)
        )
    except SummaryError as exc:
        steps.append(WorkflowStep("summary_generation", "failed", exc.message))
        return _failed_result(
            trace_id=trace_id,
            mode=mode,
            protection_mode=protection_mode,
            scenario=scenario,
            user_task=task,
            search_query=query,
            documents=documents,
            detections=detections,
            provenance=tracker.snapshot(),
            tool_calls=tool_calls,
            attack_outcome=attack_outcome,
            steps=steps,
            code=exc.code,
            message=exc.message,
        )

    steps.append(
        WorkflowStep(
            "summary_generation",
            "completed",
            "使用离线确定性摘要器生成结果。"
            if mode == "local"
            else "使用 OpenAI Agents SDK 生成结果。",
        )
    )
    active_registry.record_event(
        trace_id,
        "agent_task_completed",
        {
            "scenario": scenario,
            "protection_mode": protection_mode,
            "attack_outcome": attack_outcome,
            "document_count": len(documents),
        },
    )
    return OfficeTaskResult(
        True,
        trace_id,
        mode,
        protection_mode,
        scenario,
        task,
        query,
        answer,
        documents,
        detections,
        tracker.snapshot(),
        tool_calls,
        attack_outcome,
        steps,
    )


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="运行办公资料检索、攻击与防御任务")
    parser.add_argument("task", nargs="?", default="请搜索项目资料，并生成一份摘要。")
    parser.add_argument("--mode", choices=("local", "openai"), default="local")
    parser.add_argument(
        "--protection",
        choices=("off", "detector_only", "full"),
        default="full",
    )
    parser.add_argument("--scenario", choices=("normal", "attack", "all"), default="normal")
    parser.add_argument("--no-protection", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args()

    result = run_office_task(
        arguments.task,
        mode=arguments.mode,
        protection_mode="off" if arguments.no_protection else arguments.protection,
        scenario=arguments.scenario,
    )
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
