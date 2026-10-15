"""Unified policy-enforced registration and invocation for all tools."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

from audit.logger import append_event
from security.policy_engine import (
    ALLOW,
    PolicyDecision,
    UserAuthorization,
    evaluate_tool_request,
)
from tools.common import ToolResult, failure
from tools.read_file import read_file
from tools.search_documents import search_documents
from tools.send_email import send_email

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDIT_PATH = PROJECT_ROOT / "audit" / "events.jsonl"


@dataclass(frozen=True)
class ToolSpec:
    handler: Callable[..., ToolResult]
    required_arguments: frozenset[str]


class ToolRegistry:
    """Validate, authorize, execute, and audit local tool calls."""

    def __init__(
        self,
        *,
        audit_path: Path | None = DEFAULT_AUDIT_PATH,
        rules_path: Path | None = None,
    ) -> None:
        self.audit_path = audit_path
        self.rules_path = rules_path
        self._tools: dict[str, ToolSpec] = {
            "search_documents": ToolSpec(search_documents, frozenset({"query"})),
            "read_file": ToolSpec(
                lambda path: read_file(path, rules_path=self.rules_path),
                frozenset({"path"}),
            ),
            "send_email": ToolSpec(send_email, frozenset({"to", "subject", "body"})),
        }

    @property
    def tool_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def invoke(
        self,
        tool: str,
        arguments: Mapping[str, Any],
        *,
        trace_id: str | None = None,
        argument_sources: Mapping[str, Any] | None = None,
        detection_results: Mapping[str, Any] | None = None,
        protection_enabled: bool = True,
        user_authorization: Mapping[str, Any] | UserAuthorization | None = None,
    ) -> ToolResult:
        trace_id = trace_id or f"trace-{uuid4().hex}"
        call_id = f"call-{uuid4().hex}"
        sources = dict(argument_sources or {})
        timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")

        if not isinstance(arguments, Mapping):
            result = failure(tool, "INVALID_ARGUMENTS", "arguments 必须是对象。")
            self._audit(timestamp, trace_id, call_id, tool, {}, sources, None, result)
            return self._with_meta(result, trace_id, call_id, None)

        copied_arguments = dict(arguments)
        spec = self._tools.get(tool)
        if spec is None:
            decision = PolicyDecision(
                "BLOCK", "工具未注册。", "UNKNOWN_TOOL_BLOCKED", "high"
            )
            result = failure(tool, "TOOL_BLOCKED", decision.reason)
            self._audit(
                timestamp,
                trace_id,
                call_id,
                tool,
                copied_arguments,
                sources,
                decision,
                result,
            )
            return self._with_meta(result, trace_id, call_id, decision)

        provided_arguments = frozenset(copied_arguments)
        if provided_arguments != spec.required_arguments:
            missing = sorted(spec.required_arguments - provided_arguments)
            unexpected = sorted(provided_arguments - spec.required_arguments)
            details = []
            if missing:
                details.append(f"缺少：{', '.join(missing)}")
            if unexpected:
                details.append(f"多余：{', '.join(unexpected)}")
            result = failure(tool, "INVALID_ARGUMENTS", "；".join(details))
            self._audit(
                timestamp,
                trace_id,
                call_id,
                tool,
                copied_arguments,
                sources,
                None,
                result,
            )
            return self._with_meta(result, trace_id, call_id, None)

        try:
            authorization = (
                user_authorization
                if isinstance(user_authorization, UserAuthorization)
                else UserAuthorization.from_mapping(user_authorization)
            )
        except ValueError as exc:
            result = failure(tool, "INVALID_AUTHORIZATION", str(exc))
            self._audit(
                timestamp,
                trace_id,
                call_id,
                tool,
                copied_arguments,
                sources,
                None,
                result,
            )
            return self._with_meta(result, trace_id, call_id, None)

        decision = evaluate_tool_request(
            tool,
            copied_arguments,
            protection_enabled=protection_enabled,
            user_authorization=authorization,
            argument_sources=sources,
            detection_results=detection_results,
            rules_path=self.rules_path,
        )
        if decision.decision != ALLOW:
            result = failure(tool, "TOOL_BLOCKED", decision.reason)
        else:
            result = spec.handler(**copied_arguments)

        self._audit(
            timestamp,
            trace_id,
            call_id,
            tool,
            copied_arguments,
            sources,
            decision,
            result,
        )
        return self._with_meta(result, trace_id, call_id, decision)

    def record_event(
        self,
        trace_id: str,
        event_type: str,
        details: Mapping[str, Any],
    ) -> None:
        """Append a non-tool security event to the same trace audit stream."""

        if self.audit_path is None:
            return
        append_event(
            self.audit_path,
            {
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "trace_id": trace_id,
                "call_id": None,
                "event_type": event_type,
                **dict(details),
            },
        )

    @staticmethod
    def _with_meta(
        result: ToolResult,
        trace_id: str,
        call_id: str,
        decision: PolicyDecision | None,
    ) -> ToolResult:
        enriched = dict(result)
        enriched["meta"] = {
            "trace_id": trace_id,
            "call_id": call_id,
            "policy": decision.to_dict() if decision is not None else None,
        }
        return enriched

    def _audit(
        self,
        timestamp: str,
        trace_id: str,
        call_id: str,
        tool: str,
        arguments: Mapping[str, Any],
        argument_sources: Mapping[str, Any],
        decision: PolicyDecision | None,
        result: ToolResult,
    ) -> None:
        if self.audit_path is None:
            return
        event_type = "tool_executed" if result.get("ok") else "tool_failed"
        if decision is not None and decision.decision != ALLOW:
            event_type = "tool_blocked"
        append_event(
            self.audit_path,
            {
                "timestamp": timestamp,
                "trace_id": trace_id,
                "call_id": call_id,
                "event_type": event_type,
                "tool": tool,
                "arguments": dict(arguments),
                "argument_sources": dict(argument_sources),
                "policy": decision.to_dict() if decision is not None else None,
                "outcome": {
                    "ok": bool(result.get("ok")),
                    "error": result.get("error"),
                },
            },
        )


default_registry = ToolRegistry()


def invoke_tool(
    tool: str,
    arguments: Mapping[str, Any],
    **context: Any,
) -> ToolResult:
    """Invoke a registered tool through the default policy and audit path."""

    return default_registry.invoke(tool, arguments, **context)

