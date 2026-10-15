"""Pre-execution authorization decisions for local simulated tools."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

from tools.read_file import RULES_PATH, is_sensitive_path, normalise_relative_path

ALLOW = "ALLOW"
BLOCK = "BLOCK"
REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"


@dataclass(frozen=True)
class UserAuthorization:
    """Explicit permissions derived only from the user's task."""

    files: frozenset[str] = field(default_factory=frozenset)
    email_recipients: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "UserAuthorization":
        if value is None:
            return cls()

        raw_files = value.get("files", [])
        raw_recipients = value.get("email_recipients", [])
        if not isinstance(raw_files, (list, tuple, set, frozenset)) or not all(
            isinstance(item, str) for item in raw_files
        ):
            raise ValueError("user_authorization.files 必须是字符串集合。")
        if not isinstance(raw_recipients, (list, tuple, set, frozenset)) or not all(
            isinstance(item, str) for item in raw_recipients
        ):
            raise ValueError("user_authorization.email_recipients 必须是字符串集合。")

        normalised_files: set[str] = set()
        for item in raw_files:
            normalised = normalise_relative_path(item)
            if normalised is None:
                raise ValueError("user_authorization.files 包含不安全路径。")
            normalised_files.add(normalised.casefold())
        normalised_recipients: set[str] = set()
        for item in raw_recipients:
            normalised = item.strip().casefold()
            if not normalised:
                raise ValueError("user_authorization.email_recipients 包含空地址。")
            normalised_recipients.add(normalised)
        return cls(frozenset(normalised_files), frozenset(normalised_recipients))


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    reason: str
    policy_id: str
    risk_level: str
    risk_factors: tuple[str, ...] = ()
    source_ids: tuple[str, ...] = ()
    max_detection_label: str | None = None
    max_detection_score: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _source_risk_context(
    argument_sources: Mapping[str, Any] | None,
    detection_results: Mapping[str, Any] | None,
) -> tuple[tuple[str, ...], tuple[str, ...], str | None, float | None]:
    """Summarise trust and detector evidence for tool-argument sources."""

    source_ids: set[str] = set()
    untrusted = False
    for source in (argument_sources or {}).values():
        if not isinstance(source, Mapping):
            continue
        source_id = source.get("source_id")
        if isinstance(source_id, str) and source_id:
            source_ids.add(source_id)
        parent_source_id = source.get("parent_source_id")
        if isinstance(parent_source_id, str) and parent_source_id:
            source_ids.add(parent_source_id)
        if source.get("trusted") is False:
            untrusted = True

    highest_label: str | None = None
    highest_score: float | None = None
    label_priority = {"SAFE": 0, "SUSPICIOUS": 1, "INJECTION": 2}
    for source_id in source_ids:
        raw_detection = (detection_results or {}).get(source_id)
        if not isinstance(raw_detection, Mapping):
            continue
        raw_score = raw_detection.get("risk_score")
        score = float(raw_score) if isinstance(raw_score, (int, float)) else 0.0
        label = str(raw_detection.get("label", "SAFE"))
        if highest_score is None or score > highest_score:
            highest_score = score
        if label_priority.get(label, -1) > label_priority.get(highest_label or "", -1):
            highest_label = label

    factors: list[str] = []
    if untrusted:
        factors.append("UNTRUSTED_ARGUMENT_SOURCE")
    if highest_label == "SUSPICIOUS":
        factors.append("SUSPICIOUS_SOURCE_DETECTED")
    elif highest_label == "INJECTION":
        factors.append("INJECTION_SOURCE_DETECTED")
    return tuple(factors), tuple(sorted(source_ids)), highest_label, highest_score


def evaluate_tool_request(
    tool: str,
    arguments: Mapping[str, Any],
    *,
    protection_enabled: bool,
    user_authorization: UserAuthorization,
    argument_sources: Mapping[str, Any] | None = None,
    detection_results: Mapping[str, Any] | None = None,
    rules_path: Path | None = None,
) -> PolicyDecision:
    """Evaluate a tool request without executing the tool."""

    risk_factors, source_ids, detection_label, detection_score = _source_risk_context(
        argument_sources,
        detection_results,
    )

    def decide(
        decision: str,
        reason: str,
        policy_id: str,
        risk_level: str,
    ) -> PolicyDecision:
        return PolicyDecision(
            decision,
            reason,
            policy_id,
            risk_level,
            risk_factors,
            source_ids,
            detection_label,
            detection_score,
        )

    if not protection_enabled:
        return decide(
            ALLOW,
            "防护已关闭；仅允许在隔离的本地模拟环境中执行。",
            "PROTECTION_DISABLED_LOCAL_SIMULATION",
            "high" if tool in {"read_file", "send_email"} else "low",
        )

    if tool == "search_documents":
        return decide(
            ALLOW,
            "本地知识库检索属于低风险操作，返回内容仍标记为不可信。",
            "SEARCH_LOCAL_DOCUMENTS",
            "low",
        )

    if tool == "read_file":
        raw_path = arguments.get("path")
        if not isinstance(raw_path, str):
            return decide(
                BLOCK,
                "文件路径缺失或类型不正确。",
                "FILE_PATH_REQUIRED",
                "high",
            )
        normalised_path = normalise_relative_path(raw_path)
        if normalised_path is None:
            return decide(
                BLOCK,
                "文件路径不是安全的沙箱相对路径。",
                "FILE_PATH_OUTSIDE_SANDBOX",
                "high",
            )
        try:
            sensitive = is_sensitive_path(normalised_path, rules_path or RULES_PATH)
        except ValueError as exc:
            return decide(BLOCK, str(exc), "POLICY_CONFIG_ERROR", "high")
        if detection_label == "INJECTION":
            return decide(
                BLOCK,
                "文件参数来自已确认的提示注入来源。",
                "INJECTION_SOURCE_HIGH_RISK_TOOL_BLOCKED",
                "high",
            )
        if sensitive and normalised_path.casefold() not in user_authorization.files:
            return decide(
                BLOCK,
                "用户未明确授权读取该敏感文件。",
                "SENSITIVE_FILE_REQUIRE_EXPLICIT_AUTHORIZATION",
                "high",
            )
        return decide(
            ALLOW,
            "文件位于沙箱内，且所需敏感文件授权已满足；不可信来源已提升风险等级。"
            if "UNTRUSTED_ARGUMENT_SOURCE" in risk_factors
            else "文件位于沙箱内，且所需敏感文件授权已满足。",
            "FILE_SANDBOX_AND_AUTHORIZATION_VALID",
            "high" if sensitive or risk_factors else "medium",
        )

    if tool == "send_email":
        recipient = arguments.get("to")
        if not isinstance(recipient, str) or not recipient.strip():
            return decide(
                BLOCK,
                "收件地址缺失或类型不正确。",
                "EMAIL_RECIPIENT_REQUIRED",
                "high",
            )
        if detection_label == "INJECTION":
            return decide(
                BLOCK,
                "邮件参数来自已确认的提示注入来源。",
                "INJECTION_SOURCE_HIGH_RISK_TOOL_BLOCKED",
                "high",
            )
        if recipient.strip().casefold() not in user_authorization.email_recipients:
            return decide(
                BLOCK,
                "用户未明确授权向该地址发送邮件。",
                "EMAIL_REQUIRE_EXPLICIT_AUTHORIZATION",
                "high",
            )
        return decide(
            ALLOW,
            "收件地址与用户明确授权的地址一致。",
            "EMAIL_RECIPIENT_AUTHORIZED",
            "high",
        )

    return decide(
        BLOCK,
        "工具未在授权策略中注册。",
        "UNKNOWN_TOOL_BLOCKED",
        "high",
    )

