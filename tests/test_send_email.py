from __future__ import annotations

import json
from pathlib import Path

import tools.send_email as email_module


def test_send_email_appends_simulated_message(tmp_path: Path, monkeypatch) -> None:
    outbox = tmp_path / "outbox.json"
    outbox.write_text("[]\n", encoding="utf-8")
    monkeypatch.setattr(email_module, "OUTBOX_PATH", outbox)

    result = email_module.send_email(
        "teacher@example.com", "项目摘要", "这是模拟邮件正文。"
    )

    assert result["ok"] is True
    assert result["data"]["status"] == "sent_simulated"
    messages = json.loads(outbox.read_text(encoding="utf-8"))
    assert messages == [result["data"]]


def test_send_email_rejects_invalid_recipient_without_side_effect(
    tmp_path: Path, monkeypatch
) -> None:
    outbox = tmp_path / "outbox.json"
    outbox.write_text("[]\n", encoding="utf-8")
    monkeypatch.setattr(email_module, "OUTBOX_PATH", outbox)

    result = email_module.send_email("a@example.com,b@example.com", "主题", "正文")

    assert result["error"]["code"] == "INVALID_RECIPIENT"
    assert json.loads(outbox.read_text(encoding="utf-8")) == []


def test_send_email_rejects_empty_subject_and_body(tmp_path: Path, monkeypatch) -> None:
    outbox = tmp_path / "outbox.json"
    monkeypatch.setattr(email_module, "OUTBOX_PATH", outbox)

    assert email_module.send_email("a@example.com", " ", "正文")["error"]["code"] == "EMPTY_SUBJECT"
    assert email_module.send_email("a@example.com", "主题", " ")["error"]["code"] == "EMPTY_BODY"
    assert not outbox.exists()

