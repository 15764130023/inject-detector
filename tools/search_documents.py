"""Deterministic keyword search over local scenario documents."""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from tools.common import ToolResult, failure, success

TOOL_NAME = "search_documents"
SCENARIOS_ROOT = Path(__file__).resolve().parents[1] / "scenarios"
SEARCH_DIRECTORIES = ("normal", "attacks")
ALLOWED_EXTENSIONS = {".md", ".txt"}
MAX_RESULTS = 20
MAX_QUERY_LENGTH = 200
MAX_DOCUMENT_BYTES = 256 * 1024

_LATIN_TOKEN_RE = re.compile(r"[a-z0-9]+")
_CJK_SEQUENCE_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]+")


def _normalise(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold()


def _query_tokens(query: str) -> list[str]:
    """Tokenise English words and Chinese text without external models."""

    normalised = _normalise(query)
    tokens = set(_LATIN_TOKEN_RE.findall(normalised))
    for sequence in _CJK_SEQUENCE_RE.findall(normalised):
        if len(sequence) == 1:
            tokens.add(sequence)
        else:
            tokens.update(sequence[index : index + 2] for index in range(len(sequence) - 1))
    return sorted(tokens)


def _document_title(path: Path, content: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            title = stripped.lstrip("#").strip()
            if title:
                return title
    return path.stem.replace("_", " ").replace("-", " ").strip()


def _match_score(query: str, tokens: list[str], title: str, content: str) -> int:
    normalised_query = _normalise(query)
    normalised_title = _normalise(title)
    normalised_content = _normalise(content)

    score = 0
    if normalised_query in normalised_title:
        score += 40
    if normalised_query in normalised_content:
        score += 20
    for token in tokens:
        score += normalised_title.count(token) * 5
        score += normalised_content.count(token)
    return score


def _document_paths() -> list[Path]:
    paths: list[Path] = []
    for directory_name in SEARCH_DIRECTORIES:
        directory = SCENARIOS_ROOT / directory_name
        if not directory.exists():
            continue
        paths.extend(
            path
            for path in directory.rglob("*")
            if path.is_file() and path.suffix.casefold() in ALLOWED_EXTENSIONS
        )
    return sorted(paths, key=lambda path: path.relative_to(SCENARIOS_ROOT).as_posix())


def search_documents(query: str) -> ToolResult:
    """Search scenario documents and return up to five complete documents."""

    if not isinstance(query, str):
        return failure(TOOL_NAME, "INVALID_QUERY", "query 必须是字符串。")
    query = query.strip()
    if not query:
        return failure(TOOL_NAME, "EMPTY_QUERY", "query 不能为空。")
    if len(query) > MAX_QUERY_LENGTH:
        return failure(
            TOOL_NAME,
            "QUERY_TOO_LONG",
            f"query 不能超过 {MAX_QUERY_LENGTH} 个字符。",
        )

    tokens = _query_tokens(query)
    ranked_documents: list[tuple[int, str, dict[str, object]]] = []
    for path in _document_paths():
        relative_path = path.relative_to(SCENARIOS_ROOT).as_posix()
        allowed_root = (SCENARIOS_ROOT / relative_path.split("/", 1)[0]).resolve()
        try:
            resolved_path = path.resolve(strict=True)
        except OSError as exc:
            return failure(TOOL_NAME, "DOCUMENT_ACCESS_ERROR", f"无法访问文档：{relative_path}（{exc}）")
        if not resolved_path.is_relative_to(allowed_root):
            return failure(
                TOOL_NAME,
                "DOCUMENT_OUTSIDE_SEARCH_ROOT",
                f"文档解析后位于知识库目录之外：{relative_path}",
            )
        try:
            size_bytes = resolved_path.stat().st_size
        except OSError as exc:
            return failure(TOOL_NAME, "DOCUMENT_STAT_ERROR", f"无法检查文档：{relative_path}（{exc}）")
        if size_bytes > MAX_DOCUMENT_BYTES:
            return failure(
                TOOL_NAME,
                "DOCUMENT_TOO_LARGE",
                f"文档超过 {MAX_DOCUMENT_BYTES} 字节限制：{relative_path}",
            )
        try:
            content = resolved_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return failure(TOOL_NAME, "DOCUMENT_ENCODING_ERROR", f"文档不是 UTF-8：{relative_path}")
        except OSError as exc:
            return failure(TOOL_NAME, "DOCUMENT_READ_ERROR", f"无法读取文档：{relative_path}（{exc}）")

        title = _document_title(path, content)
        score = _match_score(query, tokens, title, content)
        if score <= 0:
            continue
        document = {
            "source_id": f"document:{relative_path}",
            "source_type": "retrieved_document",
            "title": title,
            "relative_path": relative_path,
            "content": content,
            "match_score": score,
            "trusted": False,
        }
        ranked_documents.append((score, relative_path, document))

    ranked_documents.sort(key=lambda item: (-item[0], item[1]))
    documents = [item[2] for item in ranked_documents[:MAX_RESULTS]]
    return success(
        TOOL_NAME,
        {"query": query, "count": len(documents), "documents": documents},
    )

