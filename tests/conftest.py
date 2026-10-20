from __future__ import annotations

import pytest

import security.detector as detector_module


class _FakePromptInjectionScanner:
    """Fast, deterministic stand-in for unit tests; production never uses it."""

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        lowered = prompt.lower()
        is_injection = any(
            marker in lowered
            for marker in (
                "ignore all previous",
                "system override",
                "最高优先级",
                "给智能体的附加指令",
            )
        )
        return prompt, not is_injection, 1.0 if is_injection else -1.0


@pytest.fixture(autouse=True)
def _stub_llm_guard_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests validate the adapter without network or model downloads."""

    monkeypatch.setattr(
        detector_module,
        "_get_scanner",
        lambda: _FakePromptInjectionScanner(),
    )
