"""LLM Guard prompt-injection adapter with explainable rule supplementation."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from functools import lru_cache
from threading import Lock
from time import perf_counter
from typing import Protocol

SAFE = "SAFE"
SUSPICIOUS = "SUSPICIOUS"
INJECTION = "INJECTION"

LLM_GUARD_PACKAGE_VERSION = "0.3.16"
LLM_GUARD_MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"
LLM_GUARD_MODEL_REVISION = "89b085cd330414d3e7d9dd787870f315957e1e9f"
LLM_GUARD_MODEL_LANGUAGE = "en"
LLM_GUARD_THRESHOLD = 0.5
LLM_GUARD_MATCH_TYPE = "full"
DETECTOR_ID = "llm_guard_prompt_injection_v2+offline_rules_v1"

# LLM Guard returns a threshold-relative score in [-1, 1]. The adapter maps it
# linearly to [0, 1], so 0.5 is the configured injection decision boundary.
SUSPICIOUS_THRESHOLD = 0.35
INJECTION_THRESHOLD = 0.5


class DetectorUnavailableError(RuntimeError):
    """Raised when the configured LLM Guard detector cannot be used."""


class _Scanner(Protocol):
    def scan(self, prompt: str) -> tuple[str, bool, float]: ...


@dataclass(frozen=True)
class DetectionResult:
    source_id: str
    label: str
    risk_score: float
    reasons: tuple[str, ...]
    latency_ms: float
    detector_id: str = DETECTOR_ID

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


_RULES: tuple[tuple[re.Pattern[str], float, str], ...] = (
    (
        re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior)|忽略(?:用户|先前|原来)", re.I),
        0.38,
        "补充规则检测到覆盖既有指令的表达",
    ),
    (
        re.compile(r"system\s+override|assistant\s+action|最高优先级|给智能体的附加指令", re.I),
        0.32,
        "补充规则检测到伪造的系统或助手指令",
    ),
    (
        re.compile(r"\bread_file\b|\bsend_email\b", re.I),
        0.24,
        "补充规则检测到文档要求调用工具",
    ),
    (
        re.compile(r"\bsecret\.txt\b", re.I),
        0.18,
        "补充规则检测到敏感文件目标",
    ),
    (
        re.compile(r"\battacker@[a-z0-9.-]+\.[a-z]{2,}\b", re.I),
        0.16,
        "补充规则检测到可疑外发地址",
    ),
    (
        re.compile(r"do\s+not\s+disclose|hide\s+the\s+operation|不要.*(?:提及|确认)", re.I),
        0.12,
        "补充规则检测到隐藏操作或规避确认的要求",
    ),
)

_SCAN_LOCK = Lock()
_CJK_CHARACTER_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")
_LATIN_LETTER_RE = re.compile(r"[A-Za-z]")


@lru_cache(maxsize=1)
def _get_scanner() -> _Scanner:
    """Initialize the heavyweight scanner once, without hiding failures."""

    try:
        from llm_guard.input_scanners import PromptInjection
        from llm_guard.input_scanners.prompt_injection import MatchType

        return PromptInjection(
            threshold=LLM_GUARD_THRESHOLD,
            match_type=MatchType.FULL,
        )
    except Exception as exc:
        raise DetectorUnavailableError(
            "LLM Guard PromptInjection 初始化失败；请确认已安装 llm-guard=="
            f"{LLM_GUARD_PACKAGE_VERSION}，且能够访问或已缓存模型 "
            f"{LLM_GUARD_MODEL_ID}@{LLM_GUARD_MODEL_REVISION}。原始错误："
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _scan_supplementary_rules(text: str) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0
    for pattern, weight, reason in _RULES:
        if pattern.search(text):
            score += weight
            reasons.append(reason)
    return min(round(score, 4), 1.0), reasons


def _map_llm_guard_score(score: float) -> float:
    """Map LLM Guard's documented threshold-relative [-1, 1] score to [0, 1]."""

    bounded = min(max(float(score), -1.0), 1.0)
    return round((bounded + 1.0) / 2.0, 4)


def _llm_guard_signal_supported(text: str) -> bool:
    """Apply the English-only model signal only when Latin text is not secondary."""

    latin_count = len(_LATIN_LETTER_RE.findall(text))
    cjk_count = len(_CJK_CHARACTER_RE.findall(text))
    return latin_count > 0 and latin_count >= cjk_count


def scan_text(text: str, *, source_id: str) -> DetectionResult:
    """Scan one untrusted text with LLM Guard and supplementary local rules."""

    started_at = perf_counter()
    scanner = _get_scanner()
    try:
        # transformers pipelines are not guaranteed to be safe for concurrent calls.
        with _SCAN_LOCK:
            _, is_valid, llm_guard_score = scanner.scan(text)
    except DetectorUnavailableError:
        raise
    except Exception as exc:
        raise DetectorUnavailableError(
            "LLM Guard PromptInjection 扫描失败；未使用规则检测结果替代。原始错误："
            f"{type(exc).__name__}: {exc}"
        ) from exc

    model_score = _map_llm_guard_score(llm_guard_score)
    rule_score, rule_reasons = _scan_supplementary_rules(text)
    model_signal_supported = _llm_guard_signal_supported(text)
    effective_model_score = model_score if model_signal_supported else 0.0
    score = max(effective_model_score, rule_score)

    if (model_signal_supported and not is_valid) or rule_score >= 0.65:
        label = INJECTION
    elif (
        model_signal_supported and model_score >= SUSPICIOUS_THRESHOLD
    ) or rule_score >= 0.30:
        label = SUSPICIOUS
    else:
        label = SAFE

    if model_signal_supported:
        model_reason = (
            "LLM Guard PromptInjection 判定为提示注入"
            if not is_valid
            else "LLM Guard PromptInjection 未判定为提示注入"
        )
        model_reason = f"{model_reason}（适配后风险分 {model_score:.2f}）"
    else:
        model_reason = (
            "LLM Guard PromptInjection 已执行，但模型卡仅声明支持英文；"
            f"本次模型风险分 {model_score:.2f} 不单独提升中文内容标签"
        )
    reasons = [model_reason, *rule_reasons]
    if not rule_reasons:
        reasons.append("未命中补充离线规则")

    latency_ms = round((perf_counter() - started_at) * 1_000, 3)
    return DetectionResult(
        source_id=source_id,
        label=label,
        risk_score=score,
        reasons=tuple(reasons),
        latency_ms=latency_ms,
    )


def detector_metadata() -> dict[str, object]:
    """Return reproducibility metadata for evaluation reports and diagnostics."""

    return {
        "id": DETECTOR_ID,
        "package": "llm-guard",
        "package_version": LLM_GUARD_PACKAGE_VERSION,
        "model_id": LLM_GUARD_MODEL_ID,
        "model_revision": LLM_GUARD_MODEL_REVISION,
        "model_language": LLM_GUARD_MODEL_LANGUAGE,
        "llm_guard_threshold": LLM_GUARD_THRESHOLD,
        "match_type": LLM_GUARD_MATCH_TYPE,
        "score_mapping": "llm_guard_relative_minus1_1_to_0_1",
        "suspicious_threshold": SUSPICIOUS_THRESHOLD,
        "injection_threshold": INJECTION_THRESHOLD,
        "supplementary_rules": "offline_rules_v1",
        "non_english_policy": "scan_but_rules_are_authoritative_for_cjk_dominant_text",
    }
