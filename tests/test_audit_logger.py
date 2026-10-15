from __future__ import annotations

from pathlib import Path

import pytest

from audit.logger import append_event, load_events


def test_load_events_filters_one_trace(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    append_event(path, {"trace_id": "trace-a", "event_type": "tool_executed"})
    append_event(path, {"trace_id": "trace-b", "event_type": "tool_blocked"})

    assert load_events(path, trace_id="trace-b") == [
        {"trace_id": "trace-b", "event_type": "tool_blocked"}
    ]


def test_load_events_reports_invalid_json_line(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text('{"trace_id":"ok"}\nnot-json\n', encoding="utf-8")

    with pytest.raises(ValueError, match="第 2 行不是有效 JSON"):
        load_events(path)
