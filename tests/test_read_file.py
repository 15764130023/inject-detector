from __future__ import annotations

import os
from pathlib import Path

import pytest
import tools.read_file as read_module


def _configure_sandbox(tmp_path: Path, monkeypatch) -> tuple[Path, Path]:
    sandbox = tmp_path / "sandbox_files"
    sandbox.mkdir()
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "version: 1\nsandbox:\n  sensitive_files:\n    - secret.txt\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(read_module, "SANDBOX_ROOT", sandbox)
    monkeypatch.setattr(read_module, "RULES_PATH", rules_path)
    return sandbox, rules_path


def test_read_file_reports_content_source_and_sensitivity(tmp_path: Path, monkeypatch) -> None:
    sandbox, _ = _configure_sandbox(tmp_path, monkeypatch)
    (sandbox / "secret.txt").write_text("虚构秘密", encoding="utf-8")

    result = read_module.read_file("secret.txt")

    assert result["ok"] is True
    assert result["data"]["content"] == "虚构秘密"
    assert result["data"]["sensitive"] is True
    assert result["data"]["source_id"] == "file:sandbox/secret.txt"


@pytest.mark.parametrize(
    "unsafe_path",
    ["../secret.txt", "nested/../../secret.txt", "C:\\Windows\\win.ini", "/etc/passwd"],
)
def test_read_file_rejects_unsafe_paths(tmp_path: Path, monkeypatch, unsafe_path: str) -> None:
    _configure_sandbox(tmp_path, monkeypatch)

    result = read_module.read_file(unsafe_path)

    assert result["ok"] is False
    assert result["error"]["code"] == "INVALID_PATH"


def test_read_file_rejects_directory_and_missing_file(tmp_path: Path, monkeypatch) -> None:
    sandbox, _ = _configure_sandbox(tmp_path, monkeypatch)
    (sandbox / "folder").mkdir()

    directory_result = read_module.read_file("folder")
    missing_result = read_module.read_file("missing.txt")

    assert directory_result["error"]["code"] == "NOT_A_FILE"
    assert missing_result["error"]["code"] == "FILE_NOT_FOUND"


def test_read_file_rejects_non_utf8_content(tmp_path: Path, monkeypatch) -> None:
    sandbox, _ = _configure_sandbox(tmp_path, monkeypatch)
    (sandbox / "binary.txt").write_bytes(b"\xff\xfe")

    result = read_module.read_file("binary.txt")

    assert result["error"]["code"] == "FILE_ENCODING_ERROR"


def test_read_file_rejects_oversized_content(tmp_path: Path, monkeypatch) -> None:
    sandbox, _ = _configure_sandbox(tmp_path, monkeypatch)
    (sandbox / "large.txt").write_bytes(b"x" * (read_module.MAX_FILE_BYTES + 1))

    result = read_module.read_file("large.txt")

    assert result["error"]["code"] == "FILE_TOO_LARGE"


def test_read_file_rejects_symlink_that_resolves_outside_sandbox(
    tmp_path: Path, monkeypatch
) -> None:
    sandbox, _ = _configure_sandbox(tmp_path, monkeypatch)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = sandbox / "link.txt"
    try:
        os.symlink(outside, link)
    except OSError:
        pytest.skip("当前 Windows 配置不允许创建符号链接")

    result = read_module.read_file("link.txt")

    assert result["error"]["code"] == "PATH_OUTSIDE_SANDBOX"

