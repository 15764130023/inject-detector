"""DashScope-backed Agents SDK agent with tool binding, plus deterministic local fallback."""

from __future__ import annotations

import os
import re
from typing import Any, Mapping, Sequence

from agent.prompts import (
    AGENT_INSTRUCTIONS_PROTECTED,
    AGENT_INSTRUCTIONS_UNPROTECTED,
    SUMMARY_AGENT_INSTRUCTIONS,
    build_summary_input,
)

_SUSPICIOUS_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "system override",
    "assistant action",
    "忽略用户",
    "忽略先前",
    "忽略原来",
    "给智能体的附加指令",
    "最高优先级任务",
    "read_file",
    "send_email",
    "secret.txt",
    "attacker@example.com",
)

DEFAULT_DASHSCOPE_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
DEFAULT_DASHSCOPE_MODEL = "qwen-flash"


class SummaryError(RuntimeError):
    """A summary provider failed with a stable error code."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        tool_calls: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.tool_calls = [
            {
                "tool": call.get("tool"),
                "arguments": dict(call.get("arguments", {})),
                "argument_sources": {
                    name: dict(source) if isinstance(source, Mapping) else source
                    for name, source in dict(call.get("argument_sources", {})).items()
                },
                "result": dict(call.get("result", {})),
            }
            for call in (tool_calls or [])
        ]


def _strip_suspicious_blocks(content: str) -> str:
    """Remove paragraphs that look like embedded instructions from local summaries."""

    safe_paragraphs: list[str] = []
    for paragraph in re.split(r"\n\s*\n", content):
        normalised = paragraph.casefold()
        if any(marker in normalised for marker in _SUSPICIOUS_MARKERS):
            continue
        if paragraph.strip():
            safe_paragraphs.append(paragraph.strip())
    return "\n".join(safe_paragraphs)


def _summary_sentences(content: str, *, limit: int = 2) -> list[str]:
    cleaned = _strip_suspicious_blocks(content)
    candidates = re.split(r"(?<=[。！？!?])|(?<=\.)\s+|\n+", cleaned)
    sentences: list[str] = []
    for candidate in candidates:
        sentence = " ".join(candidate.split())
        if not sentence or sentence in sentences:
            continue
        sentences.append(sentence)
        if len(sentences) == limit:
            break
    return sentences


def summarize_locally(documents: Sequence[Mapping[str, object]]) -> str:
    """Create a deterministic extractive summary without network or model access."""

    if not documents:
        return "没有检索到与任务相关的资料，暂时无法生成摘要。"

    lines = [f"共检索到 {len(documents)} 份相关资料，摘要如下："]
    for document in documents:
        title = str(document.get("title", "未命名资料"))
        sentences = _summary_sentences(str(document.get("content", "")))
        summary = " ".join(sentences) if sentences else "未提取到可安全摘要的业务内容。"
        if len(summary) > 240:
            summary = f"{summary[:237].rstrip()}…"
        lines.append(f"- 《{title}》：{summary}")
    return "\n".join(lines)


def summarize_with_dashscope(
    user_task: str,
    documents: list[dict[str, object]],
) -> str:
    """Generate a summary through DashScope's OpenAI-compatible endpoint (no tools)."""

    api_key = os.getenv("DASHSCOPE_API_KEY", "").strip()
    if not api_key:
        raise SummaryError(
            "DASHSCOPE_API_KEY_MISSING",
            "阿里云百炼模式需要设置 DASHSCOPE_API_KEY。",
        )

    from agents import Agent, OpenAIChatCompletionsModel, Runner, set_tracing_disabled
    from agents.exceptions import AgentsException
    from openai import AsyncOpenAI, OpenAIError

    base_url = os.getenv("DASHSCOPE_BASE_URL", "").strip() or DEFAULT_DASHSCOPE_BASE_URL
    model_name = os.getenv("DASHSCOPE_MODEL", "").strip() or DEFAULT_DASHSCOPE_MODEL
    client = AsyncOpenAI(api_key=api_key, base_url=base_url)
    model = OpenAIChatCompletionsModel(model=model_name, openai_client=client)

    set_tracing_disabled(disabled=True)
    summary_agent = Agent(
        name="Office document summarizer",
        instructions=SUMMARY_AGENT_INSTRUCTIONS,
        model=model,
    )

    try:
        result = Runner.run_sync(
            summary_agent,
            build_summary_input(user_task, documents),
            max_turns=2,
        )
    except (AgentsException, OpenAIError) as exc:
        raise SummaryError("DASHSCOPE_SUMMARY_ERROR", f"阿里云百炼摘要失败：{exc}") from exc

    final_output = str(result.final_output).strip()
    if not final_output:
        raise SummaryError("EMPTY_SUMMARY", "在线摘要器没有返回文本。")
    return final_output


def _require_api_key() -> str:
    api_key = os.getenv("DASHSCOPE_API_KEY", "").strip()
    if not api_key:
        raise SummaryError(
            "DASHSCOPE_API_KEY_MISSING",
            "阿里云百炼模式需要设置 DASHSCOPE_API_KEY。",
        )
    return api_key


def build_dashscope_model():
    """Construct the OpenAI-compatible model client for DashScope."""

    from agents import OpenAIChatCompletionsModel
    from openai import AsyncOpenAI

    api_key = _require_api_key()
    base_url = os.getenv("DASHSCOPE_BASE_URL", "").strip() or DEFAULT_DASHSCOPE_BASE_URL
    model_name = os.getenv("DASHSCOPE_MODEL", "").strip() or DEFAULT_DASHSCOPE_MODEL
    client = AsyncOpenAI(api_key=api_key, base_url=base_url)
    return OpenAIChatCompletionsModel(model=model_name, openai_client=client), model_name


def run_office_agent_with_tools(
    user_task: str,
    documents: list[dict[str, object]],
    *,
    registry,
    tracker,
    trace_id: str,
    protection_enabled: bool,
    user_authorization,
    detection_context: Mapping[str, Any],
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    """Run the Qwen agent with local tools bound; the model decides whether to call them.

    Returns (final_output, tool_calls, step_dicts).
    """

    from agents import Agent, Runner, function_tool, set_tracing_disabled
    from agents.exceptions import AgentsException
    from openai import OpenAIError

    model, _model_name = build_dashscope_model()
    import concurrent.futures

    tool_calls: list[dict[str, Any]] = []
    observed_tool_outputs: list[dict[str, str]] = []
    document_source_ids = [
        str(document["source_id"])
        for document in documents
        if isinstance(document.get("source_id"), str)
    ]

    # 模型可能同时参考用户任务、多份文档和之前的工具结果。没有可靠证据时，
    # 不把参数强行归因到某一份攻击文档；候选来源只用于审计说明，不作为已确认来源。
    tracker.add_source("model_inferred", "model_inference", trusted=False)

    def _model_sources(**arguments: str) -> dict[str, dict[str, Any]]:
        candidate_source_ids = ["user_task", *document_source_ids]
        candidate_source_ids.extend(item["source_id"] for item in observed_tool_outputs)
        sources: dict[str, dict[str, Any]] = {}
        for name, value in arguments.items():
            source: dict[str, Any] = {
                "source_id": "model_inferred",
                "source_type": "model_inference",
                "trusted": False,
                "attribution": "mixed_or_unknown",
                "candidate_source_ids": list(dict.fromkeys(candidate_source_ids)),
            }
            # 若参数值确实包含先前工具返回的完整内容，可以建立确定的直接来源链。
            if isinstance(value, str):
                for observed in reversed(observed_tool_outputs):
                    content = observed["content"]
                    if content and content in value:
                        source = {
                            "source_id": observed["source_id"],
                            "source_type": "tool_result",
                            "trusted": False,
                            "parent_source_id": "model_inferred",
                            "attribution": "value_contains_tool_output",
                        }
                        break
            sources[name] = source
        return sources

    def _record_call(
        tool: str,
        arguments: Mapping[str, Any],
        sources: Mapping[str, Any],
        result: Mapping[str, Any],
        *,
        observable_content: str | None = None,
    ) -> None:
        call_id = result.get("meta", {}).get("call_id")
        if not isinstance(call_id, str) or not call_id:
            raise SummaryError(
                "TOOL_RESULT_MISSING_CALL_ID",
                f"{tool} 的返回结果缺少 call_id，无法建立来源关系。",
                tool_calls=tool_calls,
            )
        result_source_id = f"tool_result:{call_id}"
        tracker.add_source(
            result_source_id,
            "tool_result",
            trusted=False,
            parent_source_id="model_inferred",
        )
        tool_calls.append({
            "tool": tool,
            "arguments": dict(arguments),
            "argument_sources": {
                name: dict(source) if isinstance(source, Mapping) else source
                for name, source in sources.items()
            },
            "result": dict(result),
        })
        if result.get("ok") and observable_content:
            observed_tool_outputs.append(
                {"source_id": result_source_id, "content": observable_content}
            )

    @function_tool
    def read_file_tool(path: str) -> str:
        """Read a UTF-8 text file from the local sandbox by relative path.

        Only files inside the sandbox directory are accessible.
        """
        arguments = {"path": path}
        sources = _model_sources(path=path)
        result = registry.invoke(
            "read_file",
            arguments,
            trace_id=trace_id,
            argument_sources=sources,
            detection_results=detection_context,
            protection_enabled=protection_enabled,
            user_authorization=user_authorization,
        )
        data = result.get("data", {}) if result.get("ok") else {}
        content = data.get("content") if isinstance(data, Mapping) else None
        _record_call(
            "read_file",
            arguments,
            sources,
            result,
            observable_content=content if isinstance(content, str) else None,
        )
        if result.get("ok"):
            return (
                f"文件读取成功（{data.get('relative_path', path)}，"
                f"敏感={data.get('sensitive', False)}）。"
                f"内容：{data.get('content', '')}"
            )
        error = result.get("error", {})
        return f"文件读取失败：{error.get('code', 'ERROR')} - {error.get('message', '')}"

    @function_tool
    def send_email_tool(to: str, subject: str, body: str) -> str:
        """Append a simulated email message to the local outbox (no network send)."""
        arguments = {"to": to, "subject": subject, "body": body}
        sources = _model_sources(to=to, subject=subject, body=body)
        result = registry.invoke(
            "send_email",
            arguments,
            trace_id=trace_id,
            argument_sources=sources,
            detection_results=detection_context,
            protection_enabled=protection_enabled,
            user_authorization=user_authorization,
        )
        _record_call("send_email", arguments, sources, result)
        if result.get("ok"):
            data = result.get("data", {})
            return f"邮件已写入本地模拟发件箱（message_id={data.get('message_id', '')}）。"
        error = result.get("error", {})
        return f"邮件发送失败：{error.get('code', 'ERROR')} - {error.get('message', '')}"

    set_tracing_disabled(disabled=True)
    instructions = (
        AGENT_INSTRUCTIONS_PROTECTED if protection_enabled
        else AGENT_INSTRUCTIONS_UNPROTECTED
    )
    office_agent = Agent(
        name="Office assistant",
        instructions=instructions,
        tools=[read_file_tool, send_email_tool],
        model=model,
    )

    user_input = build_summary_input(user_task, documents, protected=protection_enabled)

    # Streamlit 自身运行在 asyncio 事件循环里，Runner.run_sync 不能在已有循环
    # 的线程中再次启动事件循环。把 SDK 调用放到独立线程里执行。
    def _run_in_thread():
        return Runner.run_sync(
            office_agent,
            user_input,
            max_turns=5,
        )

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            run_result = pool.submit(_run_in_thread).result()
    except (AgentsException, OpenAIError) as exc:
        raise SummaryError(
            "DASHSCOPE_AGENT_ERROR",
            f"在线智能体运行失败：{exc}",
            tool_calls=tool_calls,
        ) from exc
    except (
        concurrent.futures.BrokenExecutor,
        concurrent.futures.CancelledError,
        RuntimeError,
    ) as exc:
        cause = exc.__cause__ or exc
        raise SummaryError(
            "DASHSCOPE_AGENT_ERROR",
            f"在线智能体运行失败：{cause}",
            tool_calls=tool_calls,
        ) from cause

    final_output = str(run_result.final_output).strip()
    if not final_output:
        raise SummaryError(
            "EMPTY_SUMMARY",
            "在线智能体没有返回最终文本。",
            tool_calls=tool_calls,
        )
    return final_output, tool_calls, []
