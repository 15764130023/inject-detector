"""桌面版配置：只从明确的应用目录读取配置。"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from dotenv import load_dotenv, set_key


def application_root() -> Path:
    if getattr(sys, "frozen", False):
        local_data = os.getenv("LOCALAPPDATA")
        return (Path(local_data) if local_data else Path.home() / "AppData" / "Local") / "PromptInjectDefense"
    return Path(__file__).resolve().parent


def resource_root() -> Path:
    """只读资源由单文件启动器解压，不能用于持久化数据。"""
    return Path(sys._MEIPASS) if getattr(sys, "frozen", False) else Path(__file__).resolve().parent


def load_configuration() -> None:
    load_dotenv(application_root() / ".env")


def save_api_key(value: str, *, root: Path | None = None) -> None:
    key = value.strip()
    if not key or any(character.isspace() for character in key) or "\x00" in key:
        raise ValueError("密钥不能为空，也不能包含空白字符。")
    target = (root or application_root()) / ".env"
    target.parent.mkdir(parents=True, exist_ok=True)
    # 原子替换，保存失败时不改变当前进程配置。
    descriptor, temporary = tempfile.mkstemp(prefix=".env-", dir=target.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if target.exists():
                handle.write(target.read_text(encoding="utf-8"))
        set_key(str(temporary_path), "DASHSCOPE_API_KEY", key)
        os.replace(temporary_path, target)
    finally:
        temporary_path.unlink(missing_ok=True)
    os.environ["DASHSCOPE_API_KEY"] = key
