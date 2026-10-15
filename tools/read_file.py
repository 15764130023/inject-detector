"""Read UTF-8 text files through a strict local sandbox boundary."""

from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import yaml

from tools.common import ToolResult, failure, success

TOOL_NAME = "read_file"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SANDBOX_ROOT = PROJECT_ROOT / "scenarios" / "sandbox_files"
RULES_PATH = PROJECT_ROOT / "security" / "rules.yaml"
MAX_FILE_BYTES = 256 * 1024


def normalise_relative_path(raw_path: str) -> str | None:
    """Return a portable relative path, or ``None`` for unsafe input."""

    if not isinstance(raw_path, str):
        return None
    stripped = raw_path.strip()
    if not stripped or "\x00" in stripped:
        return None
    if PureWindowsPath(stripped).is_absolute() or PurePosixPath(stripped).is_absolute():
        return None

    portable = PurePosixPath(stripped.replace("\\", "/"))
    if any(part in {"", ".", ".."} for part in portable.parts):
        return None
    return portable.as_posix()


def load_sensitive_paths(rules_path: Path | None = None) -> set[str]:
    """Load normalised sensitive sandbox paths from the policy configuration."""

    path = rules_path or RULES_PATH
    try:
        raw_rules: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"无法读取安全规则：{exc}") from exc

    try:
        configured_paths = raw_rules["sandbox"]["sensitive_files"]
    except (KeyError, TypeError) as exc:
        raise ValueError("安全规则缺少 sandbox.sensitive_files 列表。") from exc
    if not isinstance(configured_paths, list) or not all(
        isinstance(item, str) for item in configured_paths
    ):
        raise ValueError("sandbox.sensitive_files 必须是字符串列表。")

    normalised_paths: set[str] = set()
    for configured_path in configured_paths:
        normalised = normalise_relative_path(configured_path)
        if normalised is None:
            raise ValueError(f"敏感路径不合法：{configured_path!r}")
        normalised_paths.add(normalised.casefold())
    return normalised_paths


def is_sensitive_path(relative_path: str, rules_path: Path | None = None) -> bool:
    normalised = normalise_relative_path(relative_path)
    if normalised is None:
        return False
    return normalised.casefold() in load_sensitive_paths(rules_path)


def read_file(path: str, *, rules_path: Path | None = None) -> ToolResult:
    """Read a text file located strictly inside ``SANDBOX_ROOT``."""

    if not isinstance(path, str):
        return failure(TOOL_NAME, "INVALID_PATH", "path 必须是字符串。")
    relative_path = normalise_relative_path(path)
    if relative_path is None:
        return failure(TOOL_NAME, "INVALID_PATH", "path 必须是沙箱内的安全相对路径。")

    try:
        sandbox_root = SANDBOX_ROOT.resolve(strict=True)
    except OSError as exc:
        return failure(TOOL_NAME, "SANDBOX_UNAVAILABLE", f"沙箱目录不可用：{exc}")

    candidate = sandbox_root / Path(*PurePosixPath(relative_path).parts)
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError:
        return failure(TOOL_NAME, "FILE_NOT_FOUND", f"文件不存在：{relative_path}")
    except OSError as exc:
        return failure(TOOL_NAME, "FILE_ACCESS_ERROR", f"无法访问文件：{relative_path}（{exc}）")

    if not resolved.is_relative_to(sandbox_root):
        return failure(TOOL_NAME, "PATH_OUTSIDE_SANDBOX", "文件解析后位于沙箱之外。")
    if not resolved.is_file():
        return failure(TOOL_NAME, "NOT_A_FILE", f"目标不是普通文件：{relative_path}")

    try:
        size_bytes = resolved.stat().st_size
    except OSError as exc:
        return failure(TOOL_NAME, "FILE_ACCESS_ERROR", f"无法检查文件：{relative_path}（{exc}）")
    if size_bytes > MAX_FILE_BYTES:
        return failure(
            TOOL_NAME,
            "FILE_TOO_LARGE",
            f"文件超过 {MAX_FILE_BYTES} 字节限制：{relative_path}",
        )

    try:
        content = resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return failure(TOOL_NAME, "FILE_ENCODING_ERROR", f"文件不是 UTF-8：{relative_path}")
    except OSError as exc:
        return failure(TOOL_NAME, "FILE_READ_ERROR", f"无法读取文件：{relative_path}（{exc}）")

    try:
        sensitive = is_sensitive_path(relative_path, rules_path)
    except ValueError as exc:
        return failure(TOOL_NAME, "POLICY_CONFIG_ERROR", str(exc))
    return success(
        TOOL_NAME,
        {
            "source_id": f"file:sandbox/{relative_path}",
            "source_type": "sandbox_file",
            "relative_path": relative_path,
            "content": content,
            "sensitive": sensitive,
            "size_bytes": size_bytes,
        },
    )

