"""Append-only JSON Lines audit event logger."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Mapping

_AUDIT_LOCK = threading.Lock()


def append_event(path: Path, event: Mapping[str, Any]) -> None:
    """Append exactly one UTF-8 JSON event to an audit file."""

    encoded = json.dumps(dict(event), ensure_ascii=False, separators=(",", ":"))
    with _AUDIT_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="\n") as audit_file:
            audit_file.write(encoded)
            audit_file.write("\n")


def load_events(path: Path, *, trace_id: str | None = None) -> list[dict[str, Any]]:
    """Load validated JSONL audit events, optionally restricted to one trace."""

    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"无法读取审计日志：{exc}") from exc

    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"审计日志第 {line_number} 行不是有效 JSON：{exc}") from exc
        if not isinstance(event, dict):
            raise ValueError(f"审计日志第 {line_number} 行必须是 JSON 对象。")
        if trace_id is None or event.get("trace_id") == trace_id:
            events.append(event)
    return events

