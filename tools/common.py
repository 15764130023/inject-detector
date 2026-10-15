"""Shared result helpers for local simulated tools."""

from __future__ import annotations

from typing import Any


ToolResult = dict[str, Any]


def success(tool: str, data: dict[str, Any]) -> ToolResult:
    """Build a successful tool result."""

    return {"ok": True, "tool": tool, "data": data}


def failure(tool: str, code: str, message: str) -> ToolResult:
    """Build a failed tool result with a stable machine-readable code."""

    return {
        "ok": False,
        "tool": tool,
        "error": {"code": code, "message": message},
    }

