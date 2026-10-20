from pathlib import Path

import pytest

from desktop_config import application_root, save_api_key
from desktop_launcher import available_port, configure_console


def test_save_configuration_preserves_other_values(tmp_path, monkeypatch):
    monkeypatch.delenv("DASHSCOPE_API_KEY", raising=False)
    config = tmp_path / ".env"
    config.write_text("DASHSCOPE_MODEL=qwen-flash\n", encoding="utf-8")
    save_api_key("fictional-test-key", root=tmp_path)
    from dotenv import dotenv_values
    assert dotenv_values(config) == {"DASHSCOPE_MODEL": "qwen-flash", "DASHSCOPE_API_KEY": "fictional-test-key"}
    assert not list(tmp_path.glob(".env-*"))


@pytest.mark.parametrize("key", ["", "   ", "bad\nkey", "bad key", "bad\x00key"])
def test_invalid_key_does_not_change_configuration(tmp_path, key):
    with pytest.raises(ValueError):
        save_api_key(key, root=tmp_path)
    assert not (tmp_path / ".env").exists()


def test_frozen_root_ignores_working_directory(tmp_path, monkeypatch):
    import sys
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "应用程序.exe"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "用户数据"))
    assert application_root() == tmp_path / "用户数据" / "PromptInjectDefense"


def test_port_selection():
    assert 0 < available_port() < 65536


def test_console_reconfigured_as_utf8(monkeypatch):
    import desktop_launcher
    calls = []
    class Stream:
        def reconfigure(self, **kwargs):
            calls.append(kwargs)
    monkeypatch.setattr(desktop_launcher.os, "name", "posix")
    monkeypatch.setattr(desktop_launcher.sys, "stdout", Stream())
    monkeypatch.setattr(desktop_launcher.sys, "stderr", Stream())
    configure_console()
    assert calls == [
        {"encoding": "utf-8", "errors": "replace"},
        {"encoding": "utf-8", "errors": "replace"},
    ]


def test_sdk_prompt_resources_are_included_in_build():
    from importlib.metadata import distribution
    resources = distribution("openai-agents")
    assert any(Path(str(source)).name == "memory_consolidation_prompt.md" for source in resources.files)
    spec = (Path(__file__).resolve().parents[1] / "PromptInjectDefense.spec").read_text(encoding="utf-8")
    assert "collect_data_files('agents')" in spec


def test_llm_guard_is_included_in_build_and_package_validation():
    project_root = Path(__file__).resolve().parents[1]
    spec = (project_root / "PromptInjectDefense.spec").read_text(encoding="utf-8")
    validation = (project_root / "desktop_validation.py").read_text(encoding="utf-8")

    assert "copy_metadata('llm-guard'" in spec
    assert "collect_submodules('llm_guard')" in spec
    assert "from llm_guard.input_scanners import PromptInjection" in validation


def test_sidebar_reopen_control_is_not_hidden_by_toolbar_css():
    source = (Path(__file__).resolve().parents[1] / "app.py").read_text(encoding="utf-8")
    assert '[data-testid="stToolbar"] { display: none' not in source
    assert '[data-testid="stAppDeployButton"] { display: none' in source


def test_onefile_restart_keeps_configuration_outside_extraction(tmp_path, monkeypatch):
    import desktop_config
    import sys
    from dotenv import dotenv_values
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "用户目录"))
    monkeypatch.setenv("DASHSCOPE_API_KEY", "")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "unpack-first"), raising=False)
    desktop_config.save_api_key("fictional-test-key")
    saved_root = application_root()
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "unpack-second"))
    assert desktop_config.resource_root() == tmp_path / "unpack-second"
    assert application_root() == saved_root
    assert dotenv_values(saved_root / ".env")["DASHSCOPE_API_KEY"] == "fictional-test-key"
    assert not (tmp_path / "unpack-first").exists()


def test_launcher_applies_loopback_configuration_before_start(tmp_path, monkeypatch):
    import sys
    import desktop_launcher
    from streamlit.web import bootstrap
    calls = []
    monkeypatch.setattr(sys, "argv", ["desktop_launcher", "--no-browser", "--port", "18555"])
    monkeypatch.setattr(desktop_launcher, "application_root", lambda: tmp_path)
    monkeypatch.setattr(desktop_launcher, "resource_root", lambda: tmp_path)
    monkeypatch.setattr(desktop_launcher, "load_configuration", lambda: None)
    monkeypatch.setattr(desktop_launcher.threading.Thread, "start", lambda self: None)
    monkeypatch.setattr(bootstrap, "load_config_options", lambda options: calls.append(("config", options)))
    monkeypatch.setattr(bootstrap, "run", lambda *args: calls.append(("run", args)))
    monkeypatch.chdir(tmp_path)
    desktop_launcher.main()
    assert [call[0] for call in calls] == ["config", "run"]
    assert calls[0][1]["server.address"] == "127.0.0.1"
    assert calls[0][1]["server.port"] == 18555
    assert calls[0][1]["global.developmentMode"] is False
    assert calls[0][1]["logger.hideWelcomeMessage"] is True


def test_ui_configuration_and_missing_key(monkeypatch):
    monkeypatch.setenv("DASHSCOPE_API_KEY", "")
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py")).run()
    assert not app.exception
    assert any("尚未设置" in warning.value for warning in app.warning)


def test_ui_can_save_key_to_application_directory(tmp_path, monkeypatch):
    import desktop_config
    monkeypatch.setattr(desktop_config, "application_root", lambda: tmp_path)
    monkeypatch.setenv("DASHSCOPE_API_KEY", "")
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py")).run()
    app.text_input[0].input("fictional-test-key")
    app.sidebar.button[0].click().run()
    assert not app.exception
    assert app.success
    assert "fictional-test-key" in (tmp_path / ".env").read_text(encoding="utf-8")
    assert not app.warning
