"""Windows 免安装版启动入口；安全逻辑仍由原应用提供。"""

from __future__ import annotations

import argparse
import ctypes
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser

from desktop_config import application_root, load_configuration, resource_root


def configure_console() -> None:
    """Use UTF-8 on Windows and keep startup output free of ANSI escape codes."""
    if os.name == "nt":
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleOutputCP(65001)
        kernel32.SetConsoleCP(65001)
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def open_when_ready(port: int, *, open_browser: bool = True) -> None:
    url = f"http://127.0.0.1:{port}"
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(120):
        try:
            with client.open(f"{url}/_stcore/health", timeout=1) as response:
                if response.status == 200:
                    print(f"页面已就绪：{url}", flush=True)
                    if open_browser and not webbrowser.open(url):
                        print("浏览器未能自动打开，请手动访问上述地址。", flush=True)
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.5)
    print("启动超时，请查看窗口中的错误信息。", flush=True)


def main() -> None:
    configure_console()
    parser = argparse.ArgumentParser(description="提示注入防护系统")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--verify-package", action="store_true", help="检查发布包资源后退出")
    parser.add_argument("--online", action="store_true", help="配合资源检查运行三条真实在线链路")
    arguments = parser.parse_args()
    root = resource_root()
    data_root = application_root()
    data_root.mkdir(parents=True, exist_ok=True)
    os.chdir(root)
    load_configuration()
    if arguments.verify_package:
        from desktop_validation import verify_package
        raise SystemExit(verify_package(online=arguments.online))
    # 明确校验发布目录可写；不写入临时解包目录。
    probe = data_root / ".startup-write-check"
    try:
        with probe.open("x", encoding="utf-8") as handle:
            handle.write("")
    except OSError as exc:
        raise SystemExit("Windows 用户数据目录不可写，请检查目录权限后重试。") from exc
    else:
        probe.unlink()
    port = arguments.port or available_port()
    print("提示注入防护系统正在启动。关闭此窗口或按 Ctrl+C 退出。", flush=True)
    print(f"访问地址：http://127.0.0.1:{port}", flush=True)
    threading.Thread(target=open_when_ready, args=(port,), kwargs={"open_browser": not arguments.no_browser}, daemon=True).start()
    from streamlit.web import bootstrap

    options = {
        "server.address": "127.0.0.1",
        "server.port": port,
        "server.headless": True,
        "server.fileWatcherType": "none",
        "browser.gatherUsageStats": False,
        "global.developmentMode": False,
        "logger.level": "info",
        "logger.hideWelcomeMessage": True,
    }
    bootstrap.load_config_options(options)
    bootstrap.run(str(root / "app.py"), False, [], options)


if __name__ == "__main__":
    main()
