"""In-memory source and tool-argument provenance tracking."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    source_type: str
    trusted: bool
    parent_source_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ProvenanceTracker:
    """Track sources and materialize structured argument-source mappings."""

    def __init__(self) -> None:
        self._sources: dict[str, SourceRecord] = {}

    def add_source(
        self,
        source_id: str,
        source_type: str,
        *,
        trusted: bool,
        parent_source_id: str | None = None,
    ) -> SourceRecord:
        record = SourceRecord(source_id, source_type, trusted, parent_source_id)
        existing = self._sources.get(source_id)
        if existing is not None and existing != record:
            raise ValueError(f"来源 {source_id!r} 已存在且元数据不一致。")
        self._sources[source_id] = record
        return record

    def add_document(
        self,
        document: dict[str, object],
        *,
        parent_source_id: str | None = None,
    ) -> SourceRecord:
        return self.add_source(
            str(document["source_id"]),
            str(document["source_type"]),
            trusted=bool(document["trusted"]),
            parent_source_id=parent_source_id,
        )

    def get(self, source_id: str) -> SourceRecord:
        try:
            return self._sources[source_id]
        except KeyError as exc:
            raise ValueError(f"未知来源：{source_id}") from exc

    def argument_sources(self, **sources: str) -> dict[str, dict[str, Any]]:
        return {argument: self.get(source_id).to_dict() for argument, source_id in sources.items()}

    def snapshot(self) -> list[dict[str, object]]:
        return [self._sources[source_id].to_dict() for source_id in sorted(self._sources)]

