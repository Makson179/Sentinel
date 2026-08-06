"""Controller-owned exact code navigation for Bello's optimization 5.

The service is deliberately separate from Context Mode.  It is advertised to
the coder through Codex AppServer ``dynamicTools`` and never writes to the
workspace.  Structured edits are syntax-checked patch previews; the native
Codex file-edit path remains the only writer.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import difflib
import hashlib
import io
import json
import os
import stat
import threading
import time
import tokenize
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from supervisor.policy import is_secret_path


STRUCTURED_CODE_TOOL_MODES = ("off", "read", "preview")
CODE_CONTEXT_NAMESPACE = "code_context"
READ_TOOL_NAMES = frozenset(
    {"list_symbols", "read_symbol", "find_references", "read_raw"}
)
CODE_CONTEXT_TOOL_NAMES = frozenset({*READ_TOOL_NAMES, "prepare_symbol_edit"})

DEFAULT_PAGE_BYTES = 8 * 1024
MAX_PAGE_BYTES = 12 * 1024
MAX_REPLACEMENT_BYTES = 48 * 1024
MAX_REFERENCE_FILES = 500
MAX_REFERENCE_BYTES = 64 * 1024 * 1024
MAX_REFERENCE_RESULTS = 2_000
MAX_REFERENCE_DIRECTORIES = 2_000
MAX_REFERENCE_ENTRIES = 20_000
DEFAULT_MAX_PARSE_BYTES = 1024 * 1024
MAX_SYNTAX_NODES = 100_000
MAX_PYTHON_TOKENS = 150_000
MAX_CACHE_ENTRIES = 128
SERVICE_TIMEOUT_SECONDS = 20.0
SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        ".supervisor",
        ".venv",
        "venv",
        "node_modules",
        "target",
        "dist",
        "build",
        "__pycache__",
    }
)
SUPPORTED_SUFFIXES = frozenset({".py", ".pyi", ".c", ".h", ".rs"})
CODE_CONTEXT_ERROR_CODES = frozenset(
    {
        "ambiguous_symbol",
        "binary_file",
        "candidate_too_large",
        "encoding_error",
        "file_changed",
        "file_too_large",
        "internal_error",
        "invalid_arguments",
        "invalid_cursor",
        "invalid_hash",
        "invalid_path",
        "invalid_qualified_name",
        "invalid_selector",
        "no_change",
        "parse_error",
        "parse_file_too_large",
        "parse_too_complex",
        "parser_unavailable",
        "patch_too_large",
        "path_escape",
        "protected_path",
        "replacement_too_large",
        "resource_limit",
        "result_too_large",
        "scan_budget_exhausted",
        "service_closed",
        "stale_cursor",
        "stale_file",
        "stale_symbol",
        "symbol_not_found",
        "syntax_validation_failed",
        "timeout",
        "tool_not_enabled",
        "unknown_tool",
        "unreadable_file",
        "unsupported_file",
        "unsupported_language",
    }
)
CODE_CONTEXT_INTEGER_RANGE_FIELDS = frozenset(
    {"end_line", "limit", "max_bytes", "start_line"}
)
CODE_CONTEXT_ERROR_REASONS = frozenset(
    {
        *CODE_CONTEXT_ERROR_CODES,
        "delete_replacement_invalid",
        "kinds_invalid",
        "preview_operation_invalid",
        "query_invalid",
        "replacement_invalid",
        "schema_mismatch",
        "scope_invalid",
        "symbol_identity_invalid",
        *(f"{field}_not_integer" for field in CODE_CONTEXT_INTEGER_RANGE_FIELDS),
        *(f"{field}_out_of_range" for field in CODE_CONTEXT_INTEGER_RANGE_FIELDS),
    }
)


class CodeContextError(RuntimeError):
    def __init__(self, code: str, message: str, *, reason: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.reason = reason or code


@dataclass(frozen=True)
class SymbolRecord:
    selector: str
    name: str
    qualified_name: str
    kind: str
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int
    symbol_sha256: str

    def metadata(self) -> dict[str, Any]:
        name, name_truncated = _bounded_metadata_text(self.name, 512)
        qualified_name, qualified_name_truncated = _bounded_metadata_text(
            self.qualified_name,
            1024,
        )
        metadata = {
            "selector": self.selector,
            "name": name,
            "qualified_name": qualified_name,
            "kind": self.kind,
            "start_byte": self.start_byte,
            "end_byte": self.end_byte,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "symbol_sha256": self.symbol_sha256,
        }
        if name_truncated:
            metadata["name_truncated"] = True
        if qualified_name_truncated:
            metadata["qualified_name_truncated"] = True
        return metadata


@dataclass(frozen=True)
class ParsedFile:
    relative_path: str
    data: bytes
    encoding: str
    text: str
    language: str
    file_sha256: str
    symbols: tuple[SymbolRecord, ...]
    syntax_ok: bool
    syntax_error: str | None
    syntax_tree: Any = None
    estimated_cache_bytes: int = 0


def normalize_structured_code_tools(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("structured_code_tools must be a string")
    normalized = value.strip().lower()
    if normalized not in STRUCTURED_CODE_TOOL_MODES:
        expected = ", ".join(STRUCTURED_CODE_TOOL_MODES)
        raise ValueError(f"structured_code_tools must be one of: {expected}")
    return normalized


def code_context_prompt_guidance(mode: str) -> str:
    normalized = normalize_structured_code_tools(mode)
    if normalized == "off":
        return ""
    edit_sentence = (
        " In preview mode, prepare_symbol_edit never writes; it only returns a syntax-checked patch preview. "
        "apply any accepted patch with the native file-edit tool."
        if normalized == "preview"
        else ""
    )
    return (
        "Bello provides controller-owned code_context tools, separate from Context Mode. "
        "When a path and qualified symbol name are known, call read_symbol directly; use "
        "list_symbols only for discovery. Use read_raw when a "
        "parser is unsupported, ambiguous, or surrounding invariants matter. "
        "find_references is syntactic evidence, not a semantic call graph; inspect its "
        "scan_incomplete flag before relying on a negative result."
        + edit_sentence
    )


def dynamic_tool_specs(mode: str) -> list[dict[str, Any]]:
    normalized = normalize_structured_code_tools(mode)
    if normalized == "off":
        return []
    names = READ_TOOL_NAMES if normalized == "read" else CODE_CONTEXT_TOOL_NAMES
    tools = [_tool_spec(name) for name in _TOOL_ORDER if name in names]
    return [
        {
            "type": "namespace",
            "name": CODE_CONTEXT_NAMESPACE,
            "description": (
                "Bounded exact code reads and non-writing edit previews owned by Bello. "
                "This namespace is independent of Context Mode."
            ),
            "tools": tools,
        }
    ]


def _object_schema(
    properties: Mapping[str, Any],
    required: Iterable[str],
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": dict(properties),
        "required": list(required),
        "additionalProperties": False,
    }


_PATH_SCHEMA = {
    "type": "string",
    "minLength": 1,
    "maxLength": 4096,
    "description": "Workspace-relative file path; absolute paths and traversal are rejected.",
}
_HASH_SCHEMA = {
    "type": "string",
    "pattern": "^[0-9a-f]{64}$",
    "description": "Exact sha256 returned by a preceding code_context read.",
}
_CURSOR_SCHEMA = {"type": "string", "minLength": 1, "maxLength": 2048}
_QUALIFIED_NAME_SCHEMA = {"type": "string", "minLength": 1, "maxLength": 1024}

_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "list_symbols": _object_schema(
        {
            "path": _PATH_SCHEMA,
            "query": {"type": "string", "maxLength": 256},
            "kinds": {
                "type": "array",
                "items": {"type": "string", "maxLength": 64},
                "maxItems": 16,
                "uniqueItems": True,
            },
            "cursor": _CURSOR_SCHEMA,
            "limit": {"type": "integer", "minimum": 1, "maximum": 200},
        },
        ("path",),
    ),
    "read_symbol": {
        **_object_schema(
            {
                "path": _PATH_SCHEMA,
                "selector": {"type": "string", "minLength": 1, "maxLength": 128},
                "qualified_name": _QUALIFIED_NAME_SCHEMA,
                "expected_file_sha256": _HASH_SCHEMA,
                "cursor": _CURSOR_SCHEMA,
                "max_bytes": {
                    "type": "integer",
                    "minimum": 256,
                    "maximum": MAX_PAGE_BYTES,
                },
            },
            ("path",),
        ),
        "oneOf": [{"required": ["selector"]}, {"required": ["qualified_name"]}],
    },
    "find_references": {
        **_object_schema(
            {
                "path": _PATH_SCHEMA,
                "selector": {"type": "string", "minLength": 1, "maxLength": 128},
                "qualified_name": _QUALIFIED_NAME_SCHEMA,
                "expected_file_sha256": _HASH_SCHEMA,
                "scope": {"type": "string", "enum": ["file", "workspace"]},
                "cursor": _CURSOR_SCHEMA,
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            },
            ("path",),
        ),
        "oneOf": [{"required": ["selector"]}, {"required": ["qualified_name"]}],
    },
    "read_raw": _object_schema(
        {
            "path": _PATH_SCHEMA,
            "expected_file_sha256": _HASH_SCHEMA,
            "start_line": {"type": "integer", "minimum": 1},
            "end_line": {"type": "integer", "minimum": 1},
            "cursor": _CURSOR_SCHEMA,
            "max_bytes": {"type": "integer", "minimum": 256, "maximum": MAX_PAGE_BYTES},
        },
        ("path",),
    ),
    "prepare_symbol_edit": _object_schema(
        {
            "path": _PATH_SCHEMA,
            "selector": {"type": "string", "minLength": 1, "maxLength": 128},
            "expected_file_sha256": _HASH_SCHEMA,
            "expected_symbol_sha256": _HASH_SCHEMA,
            "operation": {
                "type": "string",
                "enum": ["replace", "delete", "insert_before", "insert_after"],
            },
            "replacement": {"type": "string", "maxLength": MAX_REPLACEMENT_BYTES},
        },
        (
            "path",
            "selector",
            "expected_file_sha256",
            "expected_symbol_sha256",
            "replacement",
        ),
    ),
}

_TOOL_DESCRIPTIONS = {
    "list_symbols": "List parser-derived symbols and stable selectors without returning whole bodies.",
    "read_symbol": (
        "Read an exact symbol range by selector or exact qualified name. A known qualified "
        "name needs no preceding list call; results and pages remain hash-bound."
    ),
    "find_references": (
        "Find bounded syntactic name/call references; results are not a semantic call graph. "
        "Check scan_incomplete/files_skipped before treating absence as evidence."
    ),
    "read_raw": "Read an exact raw text range with hash binding and paging; use as the lossless fallback.",
    "prepare_symbol_edit": (
        "Build and syntax-check a symbol edit patch preview. This tool never writes files."
    ),
}
_TOOL_ORDER = (
    "list_symbols",
    "read_symbol",
    "find_references",
    "read_raw",
    "prepare_symbol_edit",
)


def _tool_spec(name: str) -> dict[str, Any]:
    return {
        "type": "function",
        "name": name,
        "description": _TOOL_DESCRIPTIONS[name],
        "inputSchema": _TOOL_SCHEMAS[name],
    }


class CodeContextService:
    """Bounded in-process parser/index service for one active coder workspace."""

    def __init__(
        self,
        workspace: Path,
        *,
        denied_roots: Iterable[str | Path] = (),
        max_file_bytes: int = 2 * 1024 * 1024,
        max_parse_bytes: int = DEFAULT_MAX_PARSE_BYTES,
        max_result_bytes: int = 12 * 1024,
        cache_bytes: int = 64 * 1024 * 1024,
        mode: str = "read",
    ):
        self.workspace = Path(workspace).resolve(strict=True)
        if not self.workspace.is_dir():
            raise ValueError("code context workspace must be a directory")
        self.mode = normalize_structured_code_tools(mode)
        if self.mode == "off":
            raise ValueError("an off code context service must not be constructed")
        self.max_file_bytes = _bounded_positive(max_file_bytes, "max_file_bytes")
        self.max_parse_bytes = _bounded_positive(max_parse_bytes, "max_parse_bytes")
        if self.max_parse_bytes > self.max_file_bytes:
            raise ValueError("max_parse_bytes must not exceed max_file_bytes")
        self.max_result_bytes = _bounded_positive(max_result_bytes, "max_result_bytes")
        self.cache_bytes = _bounded_positive(cache_bytes, "cache_bytes")
        if self.max_result_bytes < 1024:
            raise ValueError("max_result_bytes must be at least 1024")
        self.denied_roots = tuple(self._normalize_denied_root(root) for root in denied_roots)
        self._cache: OrderedDict[tuple[str, str], ParsedFile] = OrderedDict()
        self._cache_size = 0
        self._cache_lock = threading.RLock()
        self._metrics_lock = threading.RLock()
        self._metrics: dict[str, int] = {}
        # Python's stdlib AST is materialized before it can be node-counted.
        # Serialize cold parses so two adversarial files cannot create two
        # simultaneous transient AST peaks; cached reads remain inexpensive.
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="bello-code-context",
        )
        self._slots = asyncio.Semaphore(4)
        self._closed = False

    async def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self._closed:
            return self._error_response("service_closed", "structured code service is closed")
        if tool not in CODE_CONTEXT_TOOL_NAMES:
            return self._error_response("unknown_tool", "unknown structured code tool")
        if self.mode == "read" and tool == "prepare_symbol_edit":
            return self._error_response(
                "tool_not_enabled",
                "symbol edit previews require preview mode",
            )
        if not isinstance(arguments, dict):
            return self._error_response("invalid_arguments", "tool arguments must be an object")
        self._metric("calls_total")
        self._metric(f"calls_{tool}_total")
        cancel_event = threading.Event()
        try:
            async with self._slots:
                deadline = time.monotonic() + SERVICE_TIMEOUT_SECONDS
                concurrent_future = self._executor.submit(
                    self._call_sync,
                    tool,
                    arguments,
                    deadline,
                    cancel_event,
                )
                # Polling avoids depending on a thread->event-loop wakeup for
                # correctness; the controller remains non-blocking, and the
                # bounded interval is negligible beside parser work.
                while not concurrent_future.done():
                    if time.monotonic() >= deadline:
                        cancel_event.set()
                        concurrent_future.cancel()
                        raise asyncio.TimeoutError
                    await asyncio.sleep(0.005)
                payload = concurrent_future.result()
        except asyncio.TimeoutError:
            self._metric("timeouts_total")
            return self._error_response(
                "timeout",
                "structured code request exceeded its time limit",
            )
        except asyncio.CancelledError:
            cancel_event.set()
            if "concurrent_future" in locals():
                concurrent_future.cancel()
            raise
        except Exception as exc:
            self._metric("internal_errors_total")
            return self._error_response(
                "internal_error",
                f"structured code request failed ({exc.__class__.__name__})",
            )
        response = self._payload_response(payload)
        self._metric("success_total" if response["success"] else "errors_total")
        return response

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Drain parser workers before the disposable workspace can be removed.
        self._executor.shutdown(wait=True, cancel_futures=True)
        with self._cache_lock:
            self._cache.clear()
            self._cache_size = 0

    def metrics_snapshot(self) -> dict[str, int]:
        with self._metrics_lock:
            return dict(self._metrics)

    def _call_sync(
        self,
        tool: str,
        arguments: dict[str, Any],
        deadline: float | None = None,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        try:
            if _request_expired(deadline, cancel_event):
                raise CodeContextError("timeout", "structured code request deadline expired")
            if tool == "list_symbols":
                return self._list_symbols(arguments)
            if tool == "read_symbol":
                return self._read_symbol(arguments)
            if tool == "find_references":
                return self._find_references(
                    arguments,
                    deadline=deadline,
                    cancel_event=cancel_event,
                )
            if tool == "read_raw":
                return self._read_raw(arguments)
            if tool == "prepare_symbol_edit":
                return self._prepare_symbol_edit(arguments)
            raise CodeContextError("unknown_tool", "unknown structured code tool")
        except CodeContextError as exc:
            return {
                "ok": False,
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "reason": exc.reason,
                },
            }
        except (MemoryError, RecursionError):
            return {
                "ok": False,
                "error": {
                    "code": "resource_limit",
                    "message": "parser resource limit reached; use a smaller raw range",
                    "reason": "resource_limit",
                },
            }
        except Exception as exc:
            return {
                "ok": False,
                "error": {
                    "code": "internal_error",
                    "message": f"structured code operation failed ({exc.__class__.__name__})",
                    "reason": "internal_error",
                },
            }

    def _payload_response(self, payload: dict[str, Any]) -> dict[str, Any]:
        text = _compact_json(payload)
        if len(text.encode("utf-8")) > self.max_result_bytes:
            return self._error_response(
                "result_too_large",
                "bounded result did not fit; request a smaller page or limit",
            )
        return {
            "contentItems": [{"type": "inputText", "text": text}],
            "success": payload.get("ok") is True,
        }

    def _error_response(
        self,
        code: str,
        message: str,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return self._payload_response(
            {
                "ok": False,
                "error": {
                    "code": code,
                    "message": message,
                    "reason": reason or code,
                },
            }
        )

    def _metric(self, name: str, amount: int = 1) -> None:
        with self._metrics_lock:
            self._metrics[name] = int(self._metrics.get(name, 0)) + amount

    def _normalize_denied_root(self, root: str | Path) -> Path:
        path = Path(root).expanduser()
        if not path.is_absolute():
            path = self.workspace / path
        return path.resolve(strict=False)

    def _resolve_path(self, raw_path: Any) -> tuple[Path, str]:
        if not isinstance(raw_path, str) or not raw_path or len(raw_path) > 4096:
            raise CodeContextError("invalid_path", "path must be a bounded non-empty string")
        if "\x00" in raw_path:
            raise CodeContextError("invalid_path", "path contains an invalid character")
        path = Path(raw_path)
        if path.is_absolute() or any(part == ".." for part in path.parts):
            raise CodeContextError("path_escape", "path must remain inside the coder workspace")
        if not path.parts or any(part in SKIPPED_DIRECTORIES for part in path.parts):
            raise CodeContextError("protected_path", "runtime and metadata paths are not readable")
        if is_secret_path(path):
            raise CodeContextError("protected_path", "secret-like paths are not readable")
        try:
            resolved = (self.workspace / path).resolve(strict=True)
            relative = resolved.relative_to(self.workspace).as_posix()
        except (OSError, ValueError):
            raise CodeContextError("path_escape", "path is unavailable inside the coder workspace") from None
        resolved_relative = Path(relative)
        if any(part in SKIPPED_DIRECTORIES for part in resolved_relative.parts) or is_secret_path(
            resolved_relative
        ):
            raise CodeContextError("protected_path", "resolved target is not readable")
        for denied in self.denied_roots:
            if _path_contains(denied, resolved):
                raise CodeContextError("protected_path", "protected paths are not readable")
        return resolved, relative

    def _read_file(
        self,
        raw_path: Any,
        *,
        byte_budget: int | None = None,
    ) -> tuple[str, bytes]:
        _, relative = self._resolve_path(raw_path)
        try:
            descriptor = self._open_workspace_file(relative)
        except OSError:
            raise CodeContextError("unreadable_file", "file could not be opened safely") from None
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise CodeContextError("unsupported_file", "path must name a regular file")
            if before.st_size > self.max_file_bytes:
                raise CodeContextError(
                    "file_too_large",
                    f"file exceeds the {self.max_file_bytes}-byte read limit; use another inspection",
                )
            if byte_budget is not None:
                if byte_budget < 0:
                    raise CodeContextError("scan_budget_exhausted", "reference scan byte budget is exhausted")
                if before.st_size > byte_budget:
                    raise CodeContextError(
                        "scan_budget_exhausted",
                        "next file exceeds the remaining reference scan byte budget",
                    )
            chunks: list[bytes] = []
            read_limit = (
                self.max_file_bytes
                if byte_budget is None
                else min(self.max_file_bytes, byte_budget)
            )
            remaining = read_limit + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(128 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            after = os.fstat(descriptor)
            identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            if identity_before != identity_after or len(data) != after.st_size:
                raise CodeContextError("file_changed", "file changed while it was being read")
            if len(data) > self.max_file_bytes:
                raise CodeContextError("file_too_large", "file exceeds the read limit")
            if byte_budget is not None and len(data) > byte_budget:
                raise CodeContextError(
                    "scan_budget_exhausted",
                    "reference scan byte budget was exhausted during read",
                )
            return relative, data
        finally:
            os.close(descriptor)

    def _open_workspace_file(self, relative: str) -> int:
        """Open every path component with no-follow semantics.

        Resolving once and then calling ``open`` is vulnerable to an
        intermediate-directory swap by the concurrently running coder.  An
        openat walk pins each directory and rejects symlinks at every level.
        """

        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
            os, "O_DIRECTORY", 0
        ) | nofollow
        file_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | nofollow
        )
        parts = Path(relative).parts
        if not parts:
            raise OSError("empty path")
        descriptors: list[int] = []
        try:
            current = os.open(self.workspace, directory_flags)
            descriptors.append(current)
            for part in parts[:-1]:
                current = os.open(part, directory_flags, dir_fd=current)
                descriptors.append(current)
            return os.open(parts[-1], file_flags, dir_fd=current)
        finally:
            for directory in reversed(descriptors):
                os.close(directory)

    def _raw_file(self, raw_path: Any) -> ParsedFile:
        """Read and decode a file without constructing a syntax tree.

        Raw fallback must remain cheap even when a supported source file is too
        large or too syntactically dense for the bounded parser path.
        """

        relative, data = self._read_file(raw_path)
        language = _language_for_path(relative)
        encoding, text = _decode_raw_source(data, language)
        return ParsedFile(
            relative_path=relative,
            data=data,
            encoding=encoding,
            text=text,
            language=language or "text",
            file_sha256=_sha256(data),
            symbols=(),
            syntax_ok=False,
            syntax_error=None,
            estimated_cache_bytes=_raw_cache_weight(data, text),
        )

    def _parsed_file(self, raw_path: Any) -> ParsedFile:
        relative, data = self._read_file(raw_path)
        return self._parsed_data(relative, data)

    def _parsed_data(self, relative: str, data: bytes) -> ParsedFile:
        if len(data) > self.max_parse_bytes:
            self._metric("parse_file_too_large_total")
            raise CodeContextError(
                "parse_file_too_large",
                f"file exceeds the {self.max_parse_bytes}-byte syntax parser limit; use read_raw",
            )
        file_sha256 = _sha256(data)
        key = (relative, file_sha256)
        with self._cache_lock:
            cached = self._cache.get(key)
            if cached is not None:
                self._cache.move_to_end(key)
                self._metric("cache_hits_total")
                return cached
        self._metric("cache_misses_total")
        parsed = _parse_source(relative, data, require_supported=True)
        with self._cache_lock:
            previous = self._cache.pop(key, None)
            if previous is not None:
                self._cache_size -= previous.estimated_cache_bytes
            if parsed.estimated_cache_bytes <= self.cache_bytes:
                self._cache[key] = parsed
                self._cache_size += parsed.estimated_cache_bytes
            while self._cache and (
                self._cache_size > self.cache_bytes or len(self._cache) > MAX_CACHE_ENTRIES
            ):
                _, evicted = self._cache.popitem(last=False)
                self._cache_size -= evicted.estimated_cache_bytes
        return parsed

    def _require_syntax(self, parsed: ParsedFile) -> None:
        if parsed.syntax_ok:
            return
        self._metric("raw_fallbacks_total")
        raise CodeContextError(
            "parse_error",
            "source could not be parsed safely; use read_raw for exact evidence",
        )

    def _list_symbols(self, arguments: dict[str, Any]) -> dict[str, Any]:
        _validate_argument_keys(
            arguments,
            required={"path"},
            optional={"query", "kinds", "cursor", "limit"},
        )
        parsed = self._parsed_file(arguments["path"])
        self._require_syntax(parsed)
        query = arguments.get("query", "")
        if not isinstance(query, str) or len(query) > 256:
            raise CodeContextError(
                "invalid_arguments",
                "query must be a bounded string",
                reason="query_invalid",
            )
        raw_kinds = arguments.get("kinds", [])
        if not isinstance(raw_kinds, list) or len(raw_kinds) > 16 or not all(
            isinstance(kind, str) and kind and len(kind) <= 64 for kind in raw_kinds
        ):
            raise CodeContextError(
                "invalid_arguments",
                "kinds must be a bounded string list",
                reason="kinds_invalid",
            )
        kinds = set(raw_kinds)
        filter_sha256 = _sha256(
            _compact_json(
                {"query": query, "kinds": sorted(kinds)}
            ).encode("utf-8")
        )
        symbols = [
            symbol
            for symbol in parsed.symbols
            if (not query or query.casefold() in symbol.qualified_name.casefold())
            and (not kinds or symbol.kind in kinds)
        ]
        limit = _bounded_int(arguments.get("limit", 100), "limit", 1, 200)
        cursor = arguments.get("cursor")
        offset = 0
        if cursor is not None:
            state = _decode_cursor(cursor, tool="list_symbols")
            _require_cursor_binding(state, parsed, arguments["path"])
            if state.get("filter_sha256") != filter_sha256:
                raise CodeContextError(
                    "stale_cursor",
                    "cursor does not match the requested symbol filters",
                )
            offset = _cursor_int(state, "offset")
        page = symbols[offset : offset + limit]
        next_offset = offset + len(page)
        payload = {
            "ok": True,
            "path": parsed.relative_path,
            "language": parsed.language,
            "file_sha256": parsed.file_sha256,
            "filter_sha256": filter_sha256,
            "symbols": [symbol.metadata() for symbol in page],
            "total_symbols": len(symbols),
            "next_cursor": (
                _encode_cursor(
                    "list_symbols",
                    path_sha256=_sha256(parsed.relative_path.encode("utf-8")),
                    file_sha256=parsed.file_sha256,
                    filter_sha256=filter_sha256,
                    offset=next_offset,
                )
                if next_offset < len(symbols)
                else None
            ),
        }
        return _fit_list_payload(payload, "symbols", self.max_result_bytes)

    def _read_symbol(self, arguments: dict[str, Any]) -> dict[str, Any]:
        _validate_argument_keys(
            arguments,
            required={"path"},
            optional={
                "selector",
                "qualified_name",
                "expected_file_sha256",
                "cursor",
                "max_bytes",
            },
        )
        parsed = self._parsed_file(arguments["path"])
        expected = arguments.get("expected_file_sha256")
        if expected is not None:
            self._require_expected_hash(expected, parsed.file_sha256)
        self._require_syntax(parsed)
        symbol = _select_symbol_argument(parsed, arguments)
        max_bytes = _bounded_int(
            arguments.get("max_bytes", DEFAULT_PAGE_BYTES),
            "max_bytes",
            256,
            MAX_PAGE_BYTES,
        )
        start = symbol.start_byte
        cursor = arguments.get("cursor")
        if cursor is not None:
            state = _decode_cursor(cursor, tool="read_symbol")
            _require_cursor_binding(state, parsed, arguments["path"])
            if state.get("selector") != symbol.selector or state.get("range_end") != symbol.end_byte:
                raise CodeContextError("stale_cursor", "cursor does not match this symbol")
            start = _cursor_int(state, "offset")
        if start < symbol.start_byte or start > symbol.end_byte:
            raise CodeContextError("invalid_cursor", "cursor is outside the symbol range")
        return self._paged_content_payload(
            parsed,
            start=start,
            end=symbol.end_byte,
            max_bytes=max_bytes,
            tool="read_symbol",
            cursor_fields={"selector": symbol.selector, "range_end": symbol.end_byte},
            extra={"symbol": symbol.metadata()},
        )

    def _read_raw(self, arguments: dict[str, Any]) -> dict[str, Any]:
        _validate_argument_keys(
            arguments,
            required={"path"},
            optional={
                "expected_file_sha256",
                "start_line",
                "end_line",
                "cursor",
                "max_bytes",
            },
        )
        parsed = self._raw_file(arguments["path"])
        expected = arguments.get("expected_file_sha256")
        if expected is not None:
            self._require_expected_hash(expected, parsed.file_sha256)
        max_bytes = _bounded_int(
            arguments.get("max_bytes", DEFAULT_PAGE_BYTES),
            "max_bytes",
            256,
            MAX_PAGE_BYTES,
        )
        line_starts = _line_start_offsets(parsed.data)
        start_line = _bounded_int(arguments.get("start_line", 1), "start_line", 1, len(line_starts))
        end_line_value = arguments.get("end_line")
        if end_line_value is None:
            end_line = len(line_starts)
        else:
            end_line = _bounded_int(end_line_value, "end_line", start_line, len(line_starts))
        range_start = line_starts[start_line - 1]
        range_end = line_starts[end_line] if end_line < len(line_starts) else len(parsed.data)
        start = range_start
        cursor = arguments.get("cursor")
        if cursor is not None:
            state = _decode_cursor(cursor, tool="read_raw")
            _require_cursor_binding(state, parsed, arguments["path"])
            if state.get("range_start") != range_start or state.get("range_end") != range_end:
                raise CodeContextError("stale_cursor", "cursor does not match this raw range")
            start = _cursor_int(state, "offset")
        if start < range_start or start > range_end:
            raise CodeContextError("invalid_cursor", "cursor is outside the raw range")
        return self._paged_content_payload(
            parsed,
            start=start,
            end=range_end,
            max_bytes=max_bytes,
            tool="read_raw",
            cursor_fields={"range_start": range_start, "range_end": range_end},
            extra={"start_line": start_line, "end_line": end_line},
        )

    def _paged_content_payload(
        self,
        parsed: ParsedFile,
        *,
        start: int,
        end: int,
        max_bytes: int,
        tool: str,
        cursor_fields: Mapping[str, Any],
        extra: Mapping[str, Any],
    ) -> dict[str, Any]:
        requested = max_bytes
        while requested >= 256:
            page_end, content = _decode_page(
                parsed.data,
                encoding=parsed.encoding,
                start=start,
                end=end,
                maximum=requested,
            )
            next_cursor = (
                _encode_cursor(
                    tool,
                    path_sha256=_sha256(parsed.relative_path.encode("utf-8")),
                    file_sha256=parsed.file_sha256,
                    offset=page_end,
                    **dict(cursor_fields),
                )
                if page_end < end
                else None
            )
            payload = {
                "ok": True,
                "path": parsed.relative_path,
                "language": parsed.language,
                "encoding": parsed.encoding,
                "file_sha256": parsed.file_sha256,
                "content": content,
                "content_sha256": _sha256(parsed.data[start:page_end]),
                "start_byte": start,
                "end_byte": page_end,
                "range_end_byte": end,
                "next_cursor": next_cursor,
                **dict(extra),
            }
            if len(_compact_json(payload).encode("utf-8")) <= self.max_result_bytes:
                return payload
            requested //= 2
        raise CodeContextError("result_too_large", "content cannot fit in a bounded result page")

    @staticmethod
    def _require_expected_hash(expected: Any, actual: str) -> None:
        if not isinstance(expected, str) or not _is_sha256(expected):
            raise CodeContextError("invalid_hash", "expected hash must be 64 lowercase hex characters")
        if expected != actual:
            raise CodeContextError("stale_file", "file hash changed; list/read the file again")

    def _find_references(
        self,
        arguments: dict[str, Any],
        *,
        deadline: float | None = None,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        _validate_argument_keys(
            arguments,
            required={"path"},
            optional={
                "selector",
                "qualified_name",
                "expected_file_sha256",
                "scope",
                "cursor",
                "limit",
            },
        )
        defining_file = self._parsed_file(arguments["path"])
        expected = arguments.get("expected_file_sha256")
        if expected is not None:
            self._require_expected_hash(expected, defining_file.file_sha256)
        self._require_syntax(defining_file)
        symbol = _select_symbol_argument(defining_file, arguments)
        scope = arguments.get("scope", "file")
        if scope not in {"file", "workspace"}:
            raise CodeContextError(
                "invalid_arguments",
                "scope must be file or workspace",
                reason="scope_invalid",
            )
        limit = _bounded_int(arguments.get("limit", 100), "limit", 1, 200)
        references: list[dict[str, Any]] = []
        files_scanned = 0
        files_skipped = 0
        skipped_reasons: dict[str, int] = {}
        bytes_scanned = 0
        scan_truncated = False
        if scope == "file":
            paths = [defining_file.relative_path]
        else:
            paths, scan_truncated = self._workspace_source_paths(
                deadline=deadline,
                cancel_event=cancel_event,
            )
        for relative in paths:
            if _request_expired(deadline, cancel_event):
                scan_truncated = True
                break
            if files_scanned >= MAX_REFERENCE_FILES or bytes_scanned >= MAX_REFERENCE_BYTES:
                scan_truncated = True
                break
            files_scanned += 1
            remaining_bytes = MAX_REFERENCE_BYTES - bytes_scanned
            if relative == defining_file.relative_path:
                candidate = defining_file
                if len(candidate.data) > remaining_bytes:
                    scan_truncated = True
                    break
                bytes_scanned += len(candidate.data)
            else:
                try:
                    candidate_relative, candidate_data = self._read_file(
                        relative,
                        byte_budget=remaining_bytes,
                    )
                except CodeContextError as exc:
                    if exc.code == "scan_budget_exhausted":
                        scan_truncated = True
                        break
                    files_skipped += 1
                    skipped_reasons[exc.code] = skipped_reasons.get(exc.code, 0) + 1
                    continue
                bytes_scanned += len(candidate_data)
                try:
                    candidate = self._parsed_data(candidate_relative, candidate_data)
                except CodeContextError as exc:
                    files_skipped += 1
                    skipped_reasons[exc.code] = skipped_reasons.get(exc.code, 0) + 1
                    continue
            if not candidate.syntax_ok:
                files_skipped += 1
                skipped_reasons["parse_error"] = skipped_reasons.get("parse_error", 0) + 1
                continue
            remaining_results = MAX_REFERENCE_RESULTS - len(references)
            candidate_references = _references_in_file(
                candidate,
                symbol.name,
                limit=remaining_results + 1,
            )
            if len(candidate_references) > remaining_results:
                references.extend(candidate_references[:remaining_results])
                scan_truncated = True
                break
            references.extend(candidate_references)
            if len(references) >= MAX_REFERENCE_RESULTS:
                scan_truncated = True
                break
        references.sort(
            key=lambda ref: (
                str(ref.get("path")),
                int(ref.get("line") or 0),
                int(ref.get("column") or 0),
                str(ref.get("reference_kind")),
            )
        )
        scan_incomplete = scan_truncated or files_skipped > 0
        result_sha256 = _sha256(
            _compact_json(
                {
                    "references": references,
                    "files_scanned": files_scanned,
                    "files_skipped": files_skipped,
                    "skipped_reasons": skipped_reasons,
                    "bytes_scanned": bytes_scanned,
                    "scan_truncated": scan_truncated,
                }
            ).encode("utf-8")
        )
        offset = 0
        cursor = arguments.get("cursor")
        if cursor is not None:
            state = _decode_cursor(cursor, tool="find_references")
            _require_cursor_binding(state, defining_file, arguments["path"])
            if (
                state.get("selector") != symbol.selector
                or state.get("scope") != scope
                or state.get("result_sha256") != result_sha256
            ):
                raise CodeContextError("stale_cursor", "cursor does not match this reference query")
            offset = _cursor_int(state, "offset")
        page = references[offset : offset + limit]
        next_offset = offset + len(page)
        payload = {
            "ok": True,
            "path": defining_file.relative_path,
            "file_sha256": defining_file.file_sha256,
            "symbol": symbol.metadata(),
            "scope": scope,
            "semantics": "syntactic_name_reference",
            "result_sha256": result_sha256,
            "references": page,
            "total_references": len(references),
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
            "skipped_reasons": skipped_reasons,
            "bytes_scanned": bytes_scanned,
            "scan_truncated": scan_truncated,
            "scan_incomplete": scan_incomplete,
            "next_cursor": (
                _encode_cursor(
                    "find_references",
                    path_sha256=_sha256(defining_file.relative_path.encode("utf-8")),
                    file_sha256=defining_file.file_sha256,
                    selector=symbol.selector,
                    scope=scope,
                    result_sha256=result_sha256,
                    offset=next_offset,
                )
                if next_offset < len(references)
                else None
            ),
        }
        return _fit_list_payload(payload, "references", self.max_result_bytes)

    def _workspace_source_paths(
        self,
        *,
        deadline: float | None = None,
        cancel_event: threading.Event | None = None,
    ) -> tuple[list[str], bool]:
        results: list[str] = []
        files_yielded = 0
        directories_seen = 0
        entries_seen = 0
        pending = [self.workspace]
        while pending:
            if _request_expired(deadline, cancel_event):
                return results, True
            root = pending.pop()
            directories_seen += 1
            if directories_seen > MAX_REFERENCE_DIRECTORIES:
                return results, True
            try:
                entries = os.scandir(root)
            except OSError:
                continue
            with entries:
                for entry in entries:
                    if _request_expired(deadline, cancel_event):
                        return results, True
                    entries_seen += 1
                    if entries_seen > MAX_REFERENCE_ENTRIES:
                        return results, True
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name not in SKIPPED_DIRECTORIES:
                                pending.append(Path(entry.path))
                            continue
                        if (
                            not entry.is_file(follow_symlinks=False)
                            or Path(entry.name).suffix.lower() not in SUPPORTED_SUFFIXES
                        ):
                            continue
                        relative = Path(entry.path).relative_to(self.workspace).as_posix()
                        self._resolve_path(relative)
                    except (CodeContextError, OSError, ValueError):
                        continue
                    results.append(relative)
                    files_yielded += 1
                    if files_yielded >= MAX_REFERENCE_FILES:
                        return results, True
        return results, False

    def _prepare_symbol_edit(self, arguments: dict[str, Any]) -> dict[str, Any]:
        _validate_argument_keys(
            arguments,
            required={
                "path",
                "selector",
                "expected_file_sha256",
                "expected_symbol_sha256",
                "replacement",
            },
            optional={"operation"},
        )
        parsed = self._parsed_file(arguments["path"])
        self._require_expected_hash(arguments["expected_file_sha256"], parsed.file_sha256)
        self._require_syntax(parsed)
        symbol = _select_symbol(parsed, arguments["selector"])
        expected_symbol = arguments["expected_symbol_sha256"]
        if not isinstance(expected_symbol, str) or not _is_sha256(expected_symbol):
            raise CodeContextError("invalid_hash", "expected symbol hash must be 64 lowercase hex")
        if expected_symbol != symbol.symbol_sha256:
            raise CodeContextError("stale_symbol", "symbol changed; read it again before editing")
        replacement = arguments["replacement"]
        if not isinstance(replacement, str):
            raise CodeContextError(
                "invalid_arguments",
                "replacement must be a string",
                reason="replacement_invalid",
            )
        normalized_replacement = _normalize_newlines(
            replacement,
            _dominant_newline(parsed.data),
        )
        try:
            replacement_bytes = _encode_fragment(normalized_replacement, parsed.encoding)
        except UnicodeError:
            raise CodeContextError(
                "encoding_error",
                "replacement cannot be represented in the source file encoding",
            ) from None
        if len(replacement_bytes) > MAX_REPLACEMENT_BYTES:
            raise CodeContextError("replacement_too_large", "replacement exceeds 48 KiB")
        operation = arguments.get("operation", "replace")
        if operation not in {"replace", "delete", "insert_before", "insert_after"}:
            raise CodeContextError(
                "invalid_arguments",
                "unsupported preview edit operation",
                reason="preview_operation_invalid",
            )
        if operation == "replace":
            candidate = (
                parsed.data[: symbol.start_byte]
                + replacement_bytes
                + parsed.data[symbol.end_byte :]
            )
        elif operation == "delete":
            if replacement:
                raise CodeContextError(
                    "invalid_arguments",
                    "delete requires an empty replacement",
                    reason="delete_replacement_invalid",
                )
            candidate = parsed.data[: symbol.start_byte] + parsed.data[symbol.end_byte :]
        elif operation == "insert_before":
            candidate = (
                parsed.data[: symbol.start_byte]
                + replacement_bytes
                + parsed.data[symbol.start_byte :]
            )
        else:
            candidate = (
                parsed.data[: symbol.end_byte]
                + replacement_bytes
                + parsed.data[symbol.end_byte :]
            )
        if len(candidate) > self.max_file_bytes + MAX_REPLACEMENT_BYTES:
            raise CodeContextError("candidate_too_large", "candidate exceeds the preview parser limit")
        candidate_parsed = _parse_source(parsed.relative_path, candidate, require_supported=True)
        if not candidate_parsed.syntax_ok:
            raise CodeContextError(
                "syntax_validation_failed",
                "candidate introduces syntax errors; no patch preview was produced",
            )
        try:
            candidate_text = candidate.decode(parsed.encoding)
        except UnicodeError:
            raise CodeContextError("encoding_error", "candidate no longer decodes as the source encoding") from None
        diff = _unified_diff(
            parsed.text,
            candidate_text,
            relative_path=parsed.relative_path,
        )
        if not diff:
            raise CodeContextError("no_change", "candidate is identical to the current file")
        payload = {
            "ok": True,
            "applied": False,
            "path": parsed.relative_path,
            "language": parsed.language,
            "operation": operation,
            "base_file_sha256": parsed.file_sha256,
            "base_symbol_sha256": symbol.symbol_sha256,
            "candidate_file_sha256": _sha256(candidate),
            "syntax_valid": True,
            "newline_normalized": normalized_replacement != replacement,
            "patch": diff,
            "instruction": "Review and apply this preview through the native file-edit tool.",
        }
        if len(_compact_json(payload).encode("utf-8")) > self.max_result_bytes:
            raise CodeContextError(
                "patch_too_large",
                "validated patch preview exceeds the bounded result limit; split the edit",
            )
        return payload


def _parse_source(relative_path: str, data: bytes, *, require_supported: bool) -> ParsedFile:
    language = _language_for_path(relative_path)
    if language is None and require_supported:
        raise CodeContextError(
            "unsupported_language",
            "symbol parsing supports Python, C, and Rust; use read_raw for this file",
        )
    encoding, text = _decode_source(data, language)
    file_sha256 = _sha256(data)
    if language is None:
        return ParsedFile(
            relative_path=relative_path,
            data=data,
            encoding=encoding,
            text=text,
            language="text",
            file_sha256=file_sha256,
            symbols=(),
            syntax_ok=True,
            syntax_error=None,
            estimated_cache_bytes=_raw_cache_weight(data, text),
        )
    if language == "python":
        return _parse_python(relative_path, data, encoding, text, file_sha256)
    return _parse_tree_sitter(relative_path, data, encoding, text, file_sha256, language)


def _language_for_path(relative_path: str) -> str | None:
    return {
        ".py": "python",
        ".pyi": "python",
        ".c": "c",
        ".h": "c",
        ".rs": "rust",
    }.get(Path(relative_path).suffix.lower())


def _decode_source(data: bytes, language: str | None) -> tuple[str, str]:
    if b"\x00" in data:
        raise CodeContextError("binary_file", "binary files are not available through code reads")
    encoding = _source_encoding(data, language)
    try:
        text = data.decode(encoding)
    except UnicodeError:
        raise CodeContextError("encoding_error", "source file could not be decoded safely") from None
    return encoding, text


def _decode_raw_source(data: bytes, language: str | None) -> tuple[str, str]:
    """Decode raw evidence losslessly, even when the language codec is invalid."""

    if b"\x00" in data:
        raise CodeContextError("binary_file", "binary files are not available through code reads")
    try:
        encoding = _source_encoding(data, language)
        return encoding, data.decode(encoding)
    except (CodeContextError, LookupError, UnicodeError):
        # Latin-1 is a one-byte mapping, so the caller can reconstruct every
        # original byte.  Structured parsing still rejects the invalid codec;
        # only the mandatory raw fallback uses this representation.
        return "latin-1", data.decode("latin-1")


def _raw_cache_weight(data: bytes, text: str) -> int:
    # CPython's compact strings use between one and four bytes per code point.
    # Four is deliberately conservative and includes non-ASCII source safely.
    return len(data) + (len(text) * 4) + 1024


def _parsed_cache_weight(
    data: bytes,
    text: str,
    *,
    node_count: int,
    symbol_count: int,
    bytes_per_node: int,
) -> int:
    return (
        _raw_cache_weight(data, text)
        + node_count * bytes_per_node
        + symbol_count * 1024
    )


def _bounded_python_node_count(tree: ast.AST) -> int:
    count = 0
    pending = [tree]
    while pending:
        node = pending.pop()
        count += 1
        if count > MAX_SYNTAX_NODES:
            raise CodeContextError(
                "parse_too_complex",
                f"Python syntax tree exceeds {MAX_SYNTAX_NODES} nodes; use read_raw",
            )
        pending.extend(ast.iter_child_nodes(node))
    return count


def _require_bounded_python_tokens(data: bytes) -> None:
    """Reject token-dense input before CPython allocates its complete AST."""

    count = 0
    try:
        tokens = tokenize.tokenize(io.BytesIO(data).readline)
        for _token in tokens:
            count += 1
            if count > MAX_PYTHON_TOKENS:
                raise CodeContextError(
                    "parse_too_complex",
                    f"Python source exceeds {MAX_PYTHON_TOKENS} tokens; use read_raw",
                )
    except (IndentationError, SyntaxError, tokenize.TokenError):
        # ast.parse below remains the syntax authority.  The preflight exists
        # only to cap dense valid input before full-tree allocation.
        return


def _bounded_tree_node_count(root: Any, language: str) -> int:
    count = 0
    pending = [root]
    while pending:
        node = pending.pop()
        count += 1
        if count > MAX_SYNTAX_NODES:
            raise CodeContextError(
                "parse_too_complex",
                f"{language} syntax tree exceeds {MAX_SYNTAX_NODES} nodes; use read_raw",
            )
        pending.extend(node.children)
    return count


def _source_encoding(data: bytes, language: str | None) -> str:
    if language == "python":
        try:
            encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
            return encoding
        except (SyntaxError, LookupError):
            raise CodeContextError("encoding_error", "Python source encoding is invalid") from None
    return "utf-8"


def _encode_fragment(text: str, encoding: str) -> bytes:
    # ``utf-8-sig`` is a whole-file codec: encoding a replacement fragment
    # with it would inject a second BOM in the middle of the file.
    fragment_encoding = "utf-8" if encoding.lower().replace("_", "-") == "utf-8-sig" else encoding
    return text.encode(fragment_encoding)


def _parse_python(
    relative_path: str,
    data: bytes,
    encoding: str,
    text: str,
    file_sha256: str,
) -> ParsedFile:
    _require_bounded_python_tokens(data)
    try:
        tree = ast.parse(text, filename=relative_path, type_comments=True)
    except (SyntaxError, ValueError) as exc:
        return ParsedFile(
            relative_path=relative_path,
            data=data,
            encoding=encoding,
            text=text,
            language="python",
            file_sha256=file_sha256,
            symbols=(),
            syntax_ok=False,
            syntax_error=getattr(exc, "msg", exc.__class__.__name__),
            estimated_cache_bytes=_raw_cache_weight(data, text),
        )
    node_count = _bounded_python_node_count(tree)
    line_offsets = _line_start_offsets(data)
    records: list[SymbolRecord] = []

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.stack: list[tuple[str, str]] = []

        def _record(self, node: ast.AST, name: str, base_kind: str) -> None:
            parent_kind = self.stack[-1][1] if self.stack else ""
            if base_kind == "function" and parent_kind == "class":
                kind = "method"
            elif base_kind == "async_function" and parent_kind == "class":
                kind = "async_method"
            else:
                kind = base_kind
            decorator_lines = [
                decorator.lineno
                for decorator in getattr(node, "decorator_list", ())
                if isinstance(getattr(decorator, "lineno", None), int)
            ]
            start_line = min([getattr(node, "lineno", 1), *decorator_lines])
            end_line = getattr(node, "end_lineno", None) or getattr(node, "lineno", start_line)
            start_byte = _line_offset(line_offsets, start_line, len(data))
            if start_line == 1 and data.startswith(b"\xef\xbb\xbf"):
                # The UTF-8 BOM is file metadata, not part of a declaration.
                # Keeping it outside the symbol range prevents a first-symbol
                # replacement from silently removing it.
                start_byte = max(start_byte, 3)
            end_byte = _line_offset(line_offsets, end_line + 1, len(data))
            qualified_name = ".".join([entry[0] for entry in self.stack] + [name])
            records.append(
                _symbol_record(
                    language="python",
                    kind=kind,
                    name=name,
                    qualified_name=qualified_name,
                    start_byte=start_byte,
                    end_byte=end_byte,
                    start_line=start_line,
                    end_line=end_line,
                    data=data,
                )
            )

        def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
            self._record(node, node.name, "class")
            self.stack.append((node.name, "class"))
            self.generic_visit(node)
            self.stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
            self._record(node, node.name, "function")
            self.stack.append((node.name, "function"))
            self.generic_visit(node)
            self.stack.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
            self._record(node, node.name, "async_function")
            self.stack.append((node.name, "function"))
            self.generic_visit(node)
            self.stack.pop()

    Visitor().visit(tree)
    records.sort(key=lambda record: (record.start_byte, record.end_byte, record.qualified_name))
    return ParsedFile(
        relative_path=relative_path,
        data=data,
        encoding=encoding,
        text=text,
        language="python",
        file_sha256=file_sha256,
        symbols=tuple(records),
        syntax_ok=True,
        syntax_error=None,
        syntax_tree=tree,
        estimated_cache_bytes=_parsed_cache_weight(
            data,
            text,
            node_count=node_count,
            symbol_count=len(records),
            bytes_per_node=768,
        ),
    )


def _parse_tree_sitter(
    relative_path: str,
    data: bytes,
    encoding: str,
    text: str,
    file_sha256: str,
    language: str,
) -> ParsedFile:
    try:
        from tree_sitter import Language, Parser

        if language == "c":
            import tree_sitter_c as grammar
        else:
            import tree_sitter_rust as grammar
        parser = Parser(Language(grammar.language()))
        tree = parser.parse(data)
    except (ImportError, OSError, TypeError, ValueError) as exc:
        raise CodeContextError(
            "parser_unavailable",
            f"{language} parser is unavailable ({exc.__class__.__name__}); use read_raw",
        ) from None
    node_count = _bounded_tree_node_count(tree.root_node, language)
    records: list[SymbolRecord] = []
    _collect_tree_symbols(tree.root_node, data, language, (), records)
    records.sort(key=lambda record: (record.start_byte, record.end_byte, record.qualified_name))
    return ParsedFile(
        relative_path=relative_path,
        data=data,
        encoding=encoding,
        text=text,
        language=language,
        file_sha256=file_sha256,
        symbols=tuple(records),
        syntax_ok=not tree.root_node.has_error,
        syntax_error="tree-sitter parse contains an error node" if tree.root_node.has_error else None,
        syntax_tree=tree,
        estimated_cache_bytes=_parsed_cache_weight(
            data,
            text,
            node_count=node_count,
            symbol_count=len(records),
            bytes_per_node=256,
        ),
    )


_C_SYMBOL_KINDS = {
    "function_definition": "function",
    "struct_specifier": "struct",
    "union_specifier": "union",
    "enum_specifier": "enum",
    "type_definition": "typedef",
}
_RUST_SYMBOL_KINDS = {
    "function_item": "function",
    "function_signature_item": "function",
    "struct_item": "struct",
    "enum_item": "enum",
    "trait_item": "trait",
    "impl_item": "impl",
    "mod_item": "module",
    "type_item": "type",
}


def _collect_tree_symbols(
    node: Any,
    data: bytes,
    language: str,
    stack: tuple[str, ...],
    records: list[SymbolRecord],
) -> None:
    kind_map = _C_SYMBOL_KINDS if language == "c" else _RUST_SYMBOL_KINDS
    kind = kind_map.get(node.type)
    next_stack = stack
    if language == "c" and node.type == "declaration":
        # File-scope C prototypes are declaration nodes, unlike definitions.
        # Inspect only grammar-labelled declarators and require the operator
        # nearest the declared identifier to be a function operator.  This
        # distinguishes `int foo(int);` from `int (*callback)(int);`.
        if _c_declaration_is_file_scope(node):
            for name in _c_function_declaration_names(node, data):
                records.append(
                    _symbol_record(
                        language=language,
                        kind="function",
                        name=name,
                        qualified_name=name,
                        start_byte=node.start_byte,
                        end_byte=node.end_byte,
                        start_line=node.start_point.row + 1,
                        end_line=node.end_point.row + 1,
                        data=data,
                    )
                )
    elif language == "c" and node.type == "type_definition":
        # A C typedef may declare more than one alias, and the identifier that
        # names an alias is not necessarily the last identifier below the
        # type_definition.  Array bounds and function parameters are also
        # identifiers, so a recursive "last identifier" search is incorrect.
        # Follow each grammar-labelled declarator to its declared identifier.
        for name in _c_typedef_names(node, data):
            records.append(
                _symbol_record(
                    language=language,
                    kind="typedef",
                    name=name,
                    qualified_name=name,
                    start_byte=node.start_byte,
                    end_byte=node.end_byte,
                    start_line=node.start_point.row + 1,
                    end_line=node.end_point.row + 1,
                    data=data,
                )
            )
        # C tags and typedef names occupy distinct namespaces; a tag nested in
        # a typedef declaration is not qualified by the typedef alias.
        next_stack = stack
    elif kind is not None:
        if (
            language == "c"
            and node.type in {"struct_specifier", "union_specifier", "enum_specifier"}
            and not _c_tag_specifier_is_symbol(node)
        ):
            name = None
        else:
            name = _tree_symbol_name(node, data, language)
        if name:
            qualified_name = "::".join((*stack, name))
            start_byte, start_line = _tree_symbol_start(node, language)
            records.append(
                _symbol_record(
                    language=language,
                    kind=kind,
                    name=name,
                    qualified_name=qualified_name,
                    start_byte=start_byte,
                    end_byte=node.end_byte,
                    start_line=start_line,
                    end_line=node.end_point.row + 1,
                    data=data,
                )
            )
            # C has no lexical type namespace corresponding to Rust modules,
            # traits, or impl blocks.  Keeping the stack flat also prevents an
            # anonymous enum's enumerator from being reported as Alias::Item.
            next_stack = stack if language == "c" else (*stack, name)
    for child in node.children:
        _collect_tree_symbols(child, data, language, next_stack, records)


def _tree_symbol_start(node: Any, language: str) -> tuple[int, int]:
    if language != "rust":
        return node.start_byte, node.start_point.row + 1
    start = node
    previous = node.prev_named_sibling
    while previous is not None:
        if previous.type == "attribute_item" or _rust_outer_doc_comment(previous):
            start = previous
            previous = previous.prev_named_sibling
            continue
        if previous.type in {"line_comment", "block_comment"}:
            # Comments may legally separate an outer attribute/doc comment
            # from its item.  Scan across them, but do not move the range start
            # unless an owning attribute is actually found.
            previous = previous.prev_named_sibling
            continue
        break
    return start.start_byte, start.start_point.row + 1


def _rust_outer_doc_comment(node: Any) -> bool:
    return (
        node.type in {"line_comment", "block_comment"}
        and node.child_by_field_name("outer") is not None
    )


def _tree_symbol_name(node: Any, data: bytes, language: str) -> str | None:
    if language == "c":
        if node.type == "function_definition":
            name_node = _c_declarator_name_node(
                node.child_by_field_name("declarator")
            )
        elif node.type in {"struct_specifier", "union_specifier", "enum_specifier"}:
            # Anonymous tags have no symbol name.  Never fall through to a
            # field/enumerator identifier inside the body.
            name_node = node.child_by_field_name("name")
        else:
            name_node = node.child_by_field_name("name")
        return _tree_node_text(name_node, data)

    name_node = node.child_by_field_name("name")
    if name_node is None and node.type == "function_definition":
        name_node = _first_tree_node(
            node.child_by_field_name("declarator") or node,
            {"identifier", "field_identifier"},
        )
    if name_node is None and node.type == "type_definition":
        candidates = list(_tree_nodes(node, {"type_identifier", "identifier"}))
        name_node = candidates[-1] if candidates else None
    if name_node is None and node.type == "impl_item":
        name_node = node.child_by_field_name("type") or node.child_by_field_name("trait")
    if name_node is None:
        name_node = _first_tree_node(node, {"type_identifier", "identifier"})
    if name_node is None:
        return None
    raw = data[name_node.start_byte : name_node.end_byte]
    try:
        name = raw.decode("utf-8").strip()
    except UnicodeError:
        return None
    if not name or len(name) > 256:
        return None
    return name


_C_DECLARATOR_WRAPPERS = frozenset(
    {
        "abstract_array_declarator",
        "abstract_function_declarator",
        "abstract_parenthesized_declarator",
        "abstract_pointer_declarator",
        "array_declarator",
        "attributed_declarator",
        "function_declarator",
        "parenthesized_declarator",
        "pointer_declarator",
    }
)


def _c_typedef_names(node: Any, data: bytes) -> tuple[str, ...]:
    names: list[str] = []
    for declarator in node.children_by_field_name("declarator"):
        name = _tree_node_text(_c_declarator_name_node(declarator), data)
        if name and name not in names:
            names.append(name)
    return tuple(names)


def _c_function_declaration_names(node: Any, data: bytes) -> tuple[str, ...]:
    names: list[str] = []
    for declarator in node.children_by_field_name("declarator"):
        name_node, nearest_operator = _c_declarator_identity(declarator)
        if nearest_operator != "function_declarator":
            continue
        name = _tree_node_text(name_node, data)
        if name and name not in names:
            names.append(name)
    return tuple(names)


def _c_tag_specifier_is_symbol(node: Any) -> bool:
    """Keep C tag definitions and file-scope forward declarations only.

    A named specifier without a body is commonly just a type reference in a
    return type, parameter, variable declaration, or typedef.  Tree-sitter
    represents all of those with the same `*_specifier` node used by a tag, so
    the surrounding grammar position is required to avoid duplicate symbols.
    """

    if node.child_by_field_name("name") is None:
        return False
    if node.child_by_field_name("body") is not None:
        return True
    parent = getattr(node, "parent", None)
    while parent is not None and parent.type.startswith("preproc_"):
        parent = getattr(parent, "parent", None)
    return parent is not None and parent.type == "translation_unit"


def _c_declaration_is_file_scope(node: Any) -> bool:
    parent = getattr(node, "parent", None)
    while parent is not None:
        if parent.type == "compound_statement":
            return False
        if parent.type == "translation_unit":
            return True
        parent = getattr(parent, "parent", None)
    return False


def _c_declarator_identity(node: Any | None) -> tuple[Any | None, str | None]:
    """Return a declarator's name and the operator nearest that name."""

    operators: list[str] = []
    current = node
    while current is not None:
        if current.type in {"identifier", "type_identifier", "field_identifier"}:
            return current, operators[-1] if operators else None
        if current.type in {
            "array_declarator",
            "function_declarator",
            "pointer_declarator",
        }:
            operators.append(current.type)
        nested = current.child_by_field_name("declarator")
        if nested is not None:
            current = nested
            continue
        if current.type in _C_DECLARATOR_WRAPPERS:
            candidates = [
                child
                for child in current.named_children
                if child.type in _C_DECLARATOR_WRAPPERS
                or child.type in {"identifier", "type_identifier", "field_identifier"}
            ]
            current = candidates[0] if candidates else None
            continue
        return None, None
    return None, None


def _c_declarator_name_node(node: Any | None) -> Any | None:
    """Return only the identifier declared by a C declarator.

    The traversal deliberately follows declarator fields/wrappers rather than
    arbitrary descendants.  That excludes array-size identifiers and function
    parameter names from typedef symbol selection.
    """

    if node is None:
        return None
    if node.type in {"identifier", "type_identifier", "field_identifier"}:
        return node
    nested = node.child_by_field_name("declarator")
    if nested is not None:
        return _c_declarator_name_node(nested)
    if node.type in _C_DECLARATOR_WRAPPERS:
        for child in node.named_children:
            if child.type in _C_DECLARATOR_WRAPPERS or child.type in {
                "identifier",
                "type_identifier",
                "field_identifier",
            }:
                found = _c_declarator_name_node(child)
                if found is not None:
                    return found
    return None


def _tree_node_text(node: Any | None, data: bytes) -> str | None:
    if node is None:
        return None
    raw = data[node.start_byte : node.end_byte]
    try:
        name = raw.decode("utf-8").strip()
    except UnicodeError:
        return None
    if not name or len(name) > 256:
        return None
    return name


def _tree_nodes(node: Any, types: set[str]) -> Iterable[Any]:
    if node.type in types:
        yield node
    for child in node.children:
        yield from _tree_nodes(child, types)


def _first_tree_node(node: Any, types: set[str]) -> Any | None:
    return next(iter(_tree_nodes(node, types)), None)


def _symbol_record(
    *,
    language: str,
    kind: str,
    name: str,
    qualified_name: str,
    start_byte: int,
    end_byte: int,
    start_line: int,
    end_line: int,
    data: bytes,
) -> SymbolRecord:
    body_hash = _sha256(data[start_byte:end_byte])
    identity = "\x00".join(
        (language, kind, qualified_name, str(start_byte), str(end_byte), body_hash)
    ).encode("utf-8")
    selector = f"sym_{language[:2]}_{hashlib.sha256(identity).hexdigest()[:32]}"
    return SymbolRecord(
        selector=selector,
        name=name,
        qualified_name=qualified_name,
        kind=kind,
        start_byte=start_byte,
        end_byte=end_byte,
        start_line=start_line,
        end_line=end_line,
        symbol_sha256=body_hash,
    )


def _references_in_file(
    parsed: ParsedFile,
    name: str,
    *,
    limit: int,
) -> list[dict[str, Any]]:
    if parsed.language == "python":
        return _python_references(parsed, name, limit=limit)
    if parsed.language in {"c", "rust"}:
        return _tree_references(parsed, name, limit=limit)
    return []


def _python_references(
    parsed: ParsedFile,
    name: str,
    *,
    limit: int,
) -> list[dict[str, Any]]:
    tree = parsed.syntax_tree
    if not isinstance(tree, ast.AST):
        return []
    lines = parsed.text.splitlines()
    references: dict[tuple[int, int], dict[str, Any]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called_name = _python_expression_name(node.func)
        if called_name != name:
            continue
        line, column, confidence = _python_name_location(node.func, name)
        references[(line, column)] = _reference_payload(
            parsed,
            line=line,
            column=column,
            reference_kind="call",
            confidence=confidence,
            lines=lines,
        )
        if len(references) >= limit:
            return list(references.values())
    for node in ast.walk(tree):
        matched = False
        confidence = "name_only"
        if isinstance(node, ast.Name) and node.id == name:
            matched = True
        elif isinstance(node, ast.Attribute) and node.attr == name:
            matched = True
            confidence = "attribute_name_only"
        if not matched:
            continue
        line, column, location_confidence = _python_name_location(node, name)
        if isinstance(node, ast.Attribute):
            confidence = location_confidence
        references.setdefault(
            (line, column),
            _reference_payload(
                parsed,
                line=line,
                column=column,
                reference_kind="identifier",
                confidence=confidence,
                lines=lines,
            ),
        )
        if len(references) >= limit:
            break
    return list(references.values())


def _python_expression_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _python_name_location(node: ast.AST, name: str) -> tuple[int, int, str]:
    if isinstance(node, ast.Attribute) and node.attr == name:
        line = int(getattr(node, "end_lineno", getattr(node, "lineno", 1)))
        end_column = int(
            getattr(node, "end_col_offset", getattr(node, "col_offset", 0))
        )
        column = max(0, end_column - len(name.encode("utf-8")))
        return line, column, "attribute_name_only"
    return (
        int(getattr(node, "lineno", 1)),
        int(getattr(node, "col_offset", 0)),
        "name_only",
    )


def _tree_references(
    parsed: ParsedFile,
    name: str,
    *,
    limit: int,
) -> list[dict[str, Any]]:
    tree = parsed.syntax_tree
    root = getattr(tree, "root_node", None)
    if root is None:
        return []
    lines = parsed.text.splitlines()
    results: dict[tuple[int, int], dict[str, Any]] = {}
    for node in _tree_nodes(root, {"identifier", "field_identifier", "type_identifier"}):
        try:
            node_name = parsed.data[node.start_byte : node.end_byte].decode("utf-8")
        except UnicodeError:
            continue
        if node_name != name:
            continue
        line = node.start_point.row + 1
        column = node.start_point.column
        reference_kind = "call" if _tree_identifier_is_call(node) else "identifier"
        confidence = "attribute_name_only" if node.type == "field_identifier" else "name_only"
        key = (line, column)
        existing = results.get(key)
        if existing is None or reference_kind == "call":
            results[key] = _reference_payload(
                parsed,
                line=line,
                column=column,
                reference_kind=reference_kind,
                confidence=confidence,
                lines=lines,
            )
            if len(results) >= limit:
                break
    return list(results.values())


def _tree_identifier_is_call(node: Any) -> bool:
    current = node
    for _ in range(4):
        parent = getattr(current, "parent", None)
        if parent is None:
            return False
        if parent.type == "call_expression":
            function = parent.child_by_field_name("function")
            return bool(
                function is not None
                and function.start_byte <= node.start_byte
                and node.end_byte <= function.end_byte
            )
        current = parent
    return False


def _reference_payload(
    parsed: ParsedFile,
    *,
    line: int,
    column: int,
    reference_kind: str,
    confidence: str,
    lines: list[str],
) -> dict[str, Any]:
    line_text = lines[line - 1] if 0 < line <= len(lines) else ""
    if len(line_text) > 500:
        line_text = line_text[:497] + "..."
    return {
        "path": parsed.relative_path,
        "line": line,
        "column": column,
        "reference_kind": reference_kind,
        "confidence": confidence,
        "line_text": line_text,
    }


def _select_symbol(parsed: ParsedFile, selector: Any) -> SymbolRecord:
    if not isinstance(selector, str) or not selector or len(selector) > 128:
        raise CodeContextError("invalid_selector", "selector must be a bounded non-empty string")
    matches = [symbol for symbol in parsed.symbols if symbol.selector == selector]
    if len(matches) != 1:
        raise CodeContextError("symbol_not_found", "symbol selector is absent or stale")
    return matches[0]


def _select_symbol_argument(
    parsed: ParsedFile,
    arguments: Mapping[str, Any],
) -> SymbolRecord:
    selector = arguments.get("selector")
    qualified_name = arguments.get("qualified_name")
    if (selector is None) == (qualified_name is None):
        raise CodeContextError(
            "invalid_arguments",
            "provide exactly one of selector or qualified_name",
            reason="symbol_identity_invalid",
        )
    if selector is not None:
        return _select_symbol(parsed, selector)
    if (
        not isinstance(qualified_name, str)
        or not qualified_name
        or len(qualified_name) > 1024
    ):
        raise CodeContextError(
            "invalid_qualified_name",
            "qualified_name must be a bounded non-empty string",
        )
    matches = [
        symbol for symbol in parsed.symbols if symbol.qualified_name == qualified_name
    ]
    if not matches:
        raise CodeContextError(
            "symbol_not_found",
            "qualified symbol name is absent; use list_symbols for discovery",
        )
    if len(matches) != 1:
        raise CodeContextError(
            "ambiguous_symbol",
            "qualified symbol name is ambiguous; use a selector from list_symbols",
        )
    return matches[0]


def _validate_argument_keys(
    arguments: Mapping[str, Any],
    *,
    required: set[str],
    optional: set[str],
) -> None:
    keys = set(arguments)
    missing = required - keys
    unknown = keys - required - optional
    if missing or unknown:
        raise CodeContextError(
            "invalid_arguments",
            "tool arguments do not match the declared schema",
            reason="schema_mismatch",
        )


def _bounded_positive(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > 1024**3:
        raise ValueError(f"{field} must be a bounded positive integer")
    return value


def _request_expired(
    deadline: float | None,
    cancel_event: threading.Event | None,
) -> bool:
    return bool(
        (cancel_event is not None and cancel_event.is_set())
        or (deadline is not None and time.monotonic() >= deadline)
    )


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    reason_field = field if field in CODE_CONTEXT_INTEGER_RANGE_FIELDS else "integer"
    if isinstance(value, bool) or not isinstance(value, int):
        raise CodeContextError(
            "invalid_arguments",
            f"{field} must be an integer between {minimum} and {maximum}",
            reason=f"{reason_field}_not_integer",
        )
    if value < minimum or value > maximum:
        raise CodeContextError(
            "invalid_arguments",
            f"{field} must be an integer between {minimum} and {maximum}",
            reason=f"{reason_field}_out_of_range",
        )
    return value


def _path_contains(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _compact_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _bounded_metadata_text(value: str, maximum: int) -> tuple[str, bool]:
    if len(value) <= maximum:
        return value, False
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    suffix = f"…[sha256:{digest}]"
    return value[: max(0, maximum - len(suffix))] + suffix, True


def _dominant_newline(data: bytes) -> str:
    crlf = data.count(b"\r\n")
    bare_lf = data.count(b"\n") - crlf
    bare_cr = data.count(b"\r") - crlf
    if crlf >= max(bare_lf, bare_cr) and crlf:
        return "\r\n"
    if bare_cr > bare_lf:
        return "\r"
    return "\n"


def _normalize_newlines(text: str, newline: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", newline)


def _unified_diff(before: str, after: str, *, relative_path: str) -> str:
    lines = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{relative_path}",
        tofile=f"b/{relative_path}",
        n=3,
    )
    rendered: list[str] = []
    for line in lines:
        if line.endswith(("\n", "\r")):
            rendered.append(line)
            continue
        rendered.append(line + "\n")
        if line[:1] in {" ", "+", "-"}:
            rendered.append("\\ No newline at end of file\n")
    return "".join(rendered)


def _line_start_offsets(data: bytes) -> list[int]:
    starts = [0]
    offset = 0
    for line in data.splitlines(keepends=True):
        offset += len(line)
        if offset < len(data):
            starts.append(offset)
    return starts


def _line_offset(starts: list[int], one_based_line: int, file_size: int) -> int:
    if one_based_line <= 1:
        return 0
    index = one_based_line - 1
    return starts[index] if index < len(starts) else file_size


def _decode_page(
    data: bytes,
    *,
    encoding: str,
    start: int,
    end: int,
    maximum: int,
) -> tuple[int, str]:
    page_end = min(end, start + maximum)
    while page_end >= start:
        try:
            return page_end, data[start:page_end].decode(encoding)
        except UnicodeDecodeError as exc:
            # A forged cursor can start inside a code point; shrinking the end
            # cannot repair that and must fail closed.
            if exc.start == 0 and start > 0:
                raise CodeContextError("invalid_cursor", "cursor splits an encoded character") from None
            page_end -= 1
    raise CodeContextError("encoding_error", "content page could not be decoded")


def _encode_cursor(tool: str, **fields: Any) -> str:
    raw = _compact_json({"v": 1, "tool": tool, **fields}).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(value: Any, *, tool: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise CodeContextError("invalid_cursor", "cursor must be a bounded string")
    try:
        padded = value + "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        state = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        raise CodeContextError("invalid_cursor", "cursor is malformed") from None
    if not isinstance(state, dict) or state.get("v") != 1 or state.get("tool") != tool:
        raise CodeContextError("invalid_cursor", "cursor does not match this tool")
    return state


def _require_cursor_binding(state: Mapping[str, Any], parsed: ParsedFile, raw_path: Any) -> None:
    del raw_path  # The canonical relative path below is the authority.
    if (
        state.get("path_sha256") != _sha256(parsed.relative_path.encode("utf-8"))
        or state.get("file_sha256") != parsed.file_sha256
    ):
        raise CodeContextError("stale_cursor", "cursor file identity changed")


def _cursor_int(state: Mapping[str, Any], field: str) -> int:
    value = state.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CodeContextError("invalid_cursor", f"cursor {field} is invalid")
    return value


def _fit_list_payload(
    payload: dict[str, Any],
    list_key: str,
    maximum_bytes: int,
) -> dict[str, Any]:
    items = payload.get(list_key)
    if not isinstance(items, list):
        return payload
    original_page_length = len(items)
    total_key = "total_symbols" if list_key == "symbols" else "total_references"
    total = int(payload.get(total_key) or 0)
    original_cursor = payload.get("next_cursor")
    if isinstance(original_cursor, str):
        state = _decode_cursor(original_cursor, tool="list_symbols" if list_key == "symbols" else "find_references")
        original_next = _cursor_int(state, "offset")
    else:
        original_next = total
    base_offset = max(0, original_next - len(items))
    while True:
        next_offset = base_offset + len(items)
        if next_offset < total:
            if list_key == "symbols":
                payload["next_cursor"] = _encode_cursor(
                    "list_symbols",
                    path_sha256=_sha256(str(payload["path"]).encode("utf-8")),
                    file_sha256=payload["file_sha256"],
                    filter_sha256=payload["filter_sha256"],
                    offset=next_offset,
                )
            else:
                payload["next_cursor"] = _encode_cursor(
                    "find_references",
                    path_sha256=_sha256(str(payload["path"]).encode("utf-8")),
                    file_sha256=payload["file_sha256"],
                    selector=payload["symbol"]["selector"],
                    scope=payload["scope"],
                    result_sha256=payload["result_sha256"],
                    offset=next_offset,
                )
        else:
            payload["next_cursor"] = None
        if len(items) < original_page_length:
            payload["result_page_reduced_for_size"] = True
        else:
            payload.pop("result_page_reduced_for_size", None)
        if len(_compact_json(payload).encode("utf-8")) <= maximum_bytes:
            return payload
        if items:
            items.pop()
            continue
        if original_page_length:
            raise CodeContextError(
                "result_too_large",
                "one result item exceeds the bounded response limit; use read_raw",
            )
        raise CodeContextError("result_too_large", "metadata cannot fit in a bounded result")
