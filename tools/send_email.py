"""Write simulated email messages to a local JSON outbox."""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from tools.common import ToolResult, failure, success

TOOL_NAME = "send_email"
OUTBOX_PATH = Path(__file__).resolve().parents[1] / "scenarios" / "outbox.json"
MAX_ADDRESS_LENGTH = 254
MAX_SUBJECT_LENGTH = 200
MAX_BODY_LENGTH = 10_000

_EMAIL_RE = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$",
    re.IGNORECASE,
)
_OUTBOX_LOCK = threading.Lock()


def load_outbox() -> tuple[list[dict[str, object]] | None, ToolResult | None]:
    """Load the local simulated outbox for tool execution or UI display."""

    if not OUTBOX_PATH.exists():
        return [], None
    try:
        data = json.loads(OUTBOX_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, failure(TOOL_NAME, "OUTBOX_READ_ERROR", f"无法读取本地发件箱：{exc}")
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        return None, failure(TOOL_NAME, "OUTBOX_INVALID", "本地发件箱必须是 JSON 对象数组。")
    return data, None


def _write_outbox(messages: list[dict[str, object]]) -> ToolResult | None:
    temporary_path: Path | None = None
    try:
        OUTBOX_PATH.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=OUTBOX_PATH.parent,
            prefix=f".{OUTBOX_PATH.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            json.dump(messages, temporary_file, ensure_ascii=False, indent=2)
            temporary_file.write("\n")
            temporary_path = Path(temporary_file.name)
        os.replace(temporary_path, OUTBOX_PATH)
    except OSError as exc:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        return failure(TOOL_NAME, "OUTBOX_WRITE_ERROR", f"无法写入本地发件箱：{exc}")
    return None


def send_email(to: str, subject: str, body: str) -> ToolResult:
    """Append one simulated message to the local outbox; no network is used."""

    if not all(isinstance(value, str) for value in (to, subject, body)):
        return failure(TOOL_NAME, "INVALID_ARGUMENT", "to、subject 和 body 必须是字符串。")

    recipient = to.strip()
    normalised_subject = subject.strip()
    if not recipient or len(recipient) > MAX_ADDRESS_LENGTH or not _EMAIL_RE.fullmatch(recipient):
        return failure(TOOL_NAME, "INVALID_RECIPIENT", "to 必须是单个有效邮箱地址。")
    if not normalised_subject:
        return failure(TOOL_NAME, "EMPTY_SUBJECT", "subject 不能为空。")
    if len(normalised_subject) > MAX_SUBJECT_LENGTH:
        return failure(
            TOOL_NAME,
            "SUBJECT_TOO_LONG",
            f"subject 不能超过 {MAX_SUBJECT_LENGTH} 个字符。",
        )
    if not body.strip():
        return failure(TOOL_NAME, "EMPTY_BODY", "body 不能为空。")
    if len(body) > MAX_BODY_LENGTH:
        return failure(
            TOOL_NAME,
            "BODY_TOO_LONG",
            f"body 不能超过 {MAX_BODY_LENGTH} 个字符。",
        )

    message: dict[str, object] = {
        "message_id": f"mail-{uuid4().hex}",
        "to": recipient,
        "subject": normalised_subject,
        "body": body,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "status": "sent_simulated",
    }
    with _OUTBOX_LOCK:
        messages, load_error = load_outbox()
        if load_error is not None:
            return load_error
        assert messages is not None
        messages.append(message)
        write_error = _write_outbox(messages)
        if write_error is not None:
            return write_error
    return success(TOOL_NAME, message)

