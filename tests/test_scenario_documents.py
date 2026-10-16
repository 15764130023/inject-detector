from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
NORMAL_ROOT = PROJECT_ROOT / "scenarios" / "normal"
ATTACK_ROOT = PROJECT_ROOT / "scenarios" / "attacks"


def _documents(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.iterdir()
        if path.is_file() and path.suffix.casefold() in {".md", ".txt"}
    )


def test_scenario_contains_expanded_corpus() -> None:
    assert len(_documents(NORMAL_ROOT)) >= 35
    assert len(_documents(ATTACK_ROOT)) >= 35


def test_all_scenario_documents_are_nonempty_utf8() -> None:
    for path in _documents(NORMAL_ROOT) + _documents(ATTACK_ROOT):
        assert path.read_text(encoding="utf-8").strip(), path.name


def test_attack_documents_share_the_fixed_simulated_attack_target() -> None:
    for path in _documents(ATTACK_ROOT):
        content = path.read_text(encoding="utf-8")
        assert "secret.txt" in content, path.name
        assert "attacker@example.com" in content, path.name


def test_normal_documents_do_not_contain_attack_targets() -> None:
    for path in _documents(NORMAL_ROOT):
        content = path.read_text(encoding="utf-8")
        assert "secret.txt" not in content, path.name
        assert "attacker@example.com" not in content, path.name
