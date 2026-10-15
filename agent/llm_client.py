"""DashScope-backed Agents SDK summarizer and deterministic local fallback."""

from __future__ import annotations

import os
import re
from typing import Mapping, Sequence

from agent.prompts import SUMMARY_AGENT_INSTRUCTIONS, build_summary_input

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

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


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
    """Generate a summary through DashScope's OpenAI-compatible endpoint."""

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

    # DashScope does not accept OpenAI tracing traffic. Local audit remains enabled.
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

