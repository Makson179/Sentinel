from __future__ import annotations

import json
from pathlib import Path

import pytest

import supervisor.code_context as code_context
from supervisor.code_context import CodeContextService


def _payload(response: dict) -> dict:
    return json.loads(response["contentItems"][0]["text"])


async def _call(service: CodeContextService, tool: str, arguments: dict) -> dict:
    return _payload(await service.call(tool, arguments))


@pytest.mark.asyncio
async def test_raw_read_of_supported_source_never_constructs_syntax_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "sample.py").write_text("def target():\n    return 1\n", encoding="utf-8")

    def forbidden_parse(*_args, **_kwargs):
        raise AssertionError("read_raw invoked the parser")

    monkeypatch.setattr(code_context, "_parse_source", forbidden_parse)
    service = CodeContextService(tmp_path, mode="read")
    try:
        result = await _call(service, "read_raw", {"path": "sample.py"})
        assert result["ok"] is True
        assert result["content"] == "def target():\n    return 1\n"
        assert service._cache_size == 0
    finally:
        service.close()


@pytest.mark.asyncio
async def test_parse_byte_limit_fails_bounded_while_raw_read_still_works(
    tmp_path: Path,
) -> None:
    source = "\n".join(f"value_{index} = {index}" for index in range(20)) + "\n"
    (tmp_path / "sample.py").write_text(source, encoding="utf-8")
    service = CodeContextService(
        tmp_path,
        mode="read",
        max_parse_bytes=64,
        max_file_bytes=4096,
    )
    try:
        structured = await _call(service, "list_symbols", {"path": "sample.py"})
        assert structured["ok"] is False
        assert structured["error"]["code"] == "parse_file_too_large"

        raw = await _call(service, "read_raw", {"path": "sample.py", "end_line": 2})
        assert raw["ok"] is True
        assert raw["content"] == "value_0 = 0\nvalue_1 = 1\n"
    finally:
        service.close()


@pytest.mark.asyncio
async def test_token_dense_python_is_rejected_before_ast_allocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "sample.py").write_text(
        "\n".join(f"value_{index} = {index}" for index in range(30)) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(code_context, "MAX_PYTHON_TOKENS", 20)

    def forbidden_ast_parse(*_args, **_kwargs):
        raise AssertionError("token-dense source reached ast.parse")

    monkeypatch.setattr(code_context.ast, "parse", forbidden_ast_parse)
    service = CodeContextService(tmp_path, mode="read")
    try:
        result = await _call(service, "list_symbols", {"path": "sample.py"})
        assert result["ok"] is False
        assert result["error"]["code"] == "parse_too_complex"
        assert service._cache_size == 0
    finally:
        service.close()


@pytest.mark.asyncio
async def test_ast_cache_uses_estimated_tree_weight_not_only_source_bytes(
    tmp_path: Path,
) -> None:
    (tmp_path / "sample.py").write_text(
        "\n".join(f"def function_{index}():\n    return {index}" for index in range(20))
        + "\n",
        encoding="utf-8",
    )
    service = CodeContextService(tmp_path, mode="read", cache_bytes=4096)
    try:
        first = await _call(service, "list_symbols", {"path": "sample.py"})
        second = await _call(service, "list_symbols", {"path": "sample.py"})
        assert first["ok"] is True
        assert second["ok"] is True
        assert service._cache_size == 0
        assert service.metrics_snapshot()["cache_misses_total"] == 2
    finally:
        service.close()


@pytest.mark.asyncio
async def test_list_symbols_size_reduced_cursor_keeps_filter_binding(
    tmp_path: Path,
) -> None:
    source = "\n".join(
        f"def apple_{index}_{'x' * 80}():\n    return {index}" for index in range(100)
    )
    (tmp_path / "sample.py").write_text(source + "\n", encoding="utf-8")
    service = CodeContextService(tmp_path, mode="read", max_result_bytes=4096)
    try:
        first = await _call(
            service,
            "list_symbols",
            {"path": "sample.py", "query": "apple", "limit": 100},
        )
        assert first["ok"] is True
        assert first["result_page_reduced_for_size"] is True
        assert first["next_cursor"]

        second = await _call(
            service,
            "list_symbols",
            {
                "path": "sample.py",
                "query": "apple",
                "limit": 100,
                "cursor": first["next_cursor"],
            },
        )
        assert second["ok"] is True
        assert second["symbols"]

        rebound = await _call(
            service,
            "list_symbols",
            {
                "path": "sample.py",
                "query": "different",
                "limit": 100,
                "cursor": first["next_cursor"],
            },
        )
        assert rebound["ok"] is False
        assert rebound["error"]["code"] == "stale_cursor"
    finally:
        service.close()


@pytest.mark.asyncio
async def test_cursor_size_is_independent_of_long_workspace_path(tmp_path: Path) -> None:
    relative = Path(
        *(
            f"segment_{index:02d}_{'x' * 65}"
            for index in range(22)
        )
    ) / "sample.py"
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_text(
        "def target():\n    return '" + ("x" * 2000) + "'\n",
        encoding="utf-8",
    )
    relative_text = relative.as_posix()
    assert len(relative_text) > 1500
    service = CodeContextService(tmp_path, mode="read")
    try:
        listed = await _call(service, "list_symbols", {"path": relative_text})
        target = listed["symbols"][0]
        first = await _call(
            service,
            "read_symbol",
            {
                "path": relative_text,
                "selector": target["selector"],
                "expected_file_sha256": listed["file_sha256"],
                "max_bytes": 256,
            },
        )
        assert first["ok"] is True
        assert first["next_cursor"]
        assert len(first["next_cursor"]) <= 2048

        second = await _call(
            service,
            "read_symbol",
            {
                "path": relative_text,
                "selector": target["selector"],
                "expected_file_sha256": listed["file_sha256"],
                "max_bytes": 256,
                "cursor": first["next_cursor"],
            },
        )
        assert second["ok"] is True
    finally:
        service.close()


@pytest.mark.asyncio
async def test_reference_collection_stops_at_global_result_bound(tmp_path: Path) -> None:
    calls = "\n".join(f"result_{index} = target()" for index in range(2500))
    (tmp_path / "sample.py").write_text(
        "def target():\n    return 1\n" + calls + "\n",
        encoding="utf-8",
    )
    service = CodeContextService(tmp_path, mode="read")
    try:
        listed = await _call(service, "list_symbols", {"path": "sample.py"})
        target = listed["symbols"][0]
        references = await _call(
            service,
            "find_references",
            {
                "path": "sample.py",
                "selector": target["selector"],
                "expected_file_sha256": listed["file_sha256"],
                "scope": "file",
                "limit": 200,
            },
        )
        assert references["ok"] is True
        assert references["total_references"] == code_context.MAX_REFERENCE_RESULTS
        assert references["scan_truncated"] is True
        assert len(references["references"]) <= 200
    finally:
        service.close()


@pytest.mark.asyncio
async def test_workspace_reference_budget_counts_files_that_cannot_be_parsed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "a_definition.py").write_text(
        "def target():\n    return 1\n",
        encoding="utf-8",
    )
    # Each candidate is readable but exceeds this service's syntax parse cap.
    for name in ("b_large.py", "c_large.py", "d_large.py"):
        (tmp_path / name).write_text("value = 1\n" * 10, encoding="utf-8")
    monkeypatch.setattr(code_context, "MAX_REFERENCE_BYTES", 220)
    service = CodeContextService(
        tmp_path,
        mode="read",
        max_parse_bytes=64,
        max_file_bytes=1024,
    )
    try:
        result = await _call(
            service,
            "find_references",
            {
                "path": "a_definition.py",
                "qualified_name": "target",
                "scope": "workspace",
            },
        )
        assert result["ok"] is True
        assert result["scan_truncated"] is True
        assert result["bytes_scanned"] <= code_context.MAX_REFERENCE_BYTES
        assert result["bytes_scanned"] >= len((tmp_path / "b_large.py").read_bytes())
        assert result["files_scanned"] >= 2
    finally:
        service.close()


@pytest.mark.asyncio
async def test_raw_fallback_preserves_non_utf8_source_bytes(tmp_path: Path) -> None:
    data = b"int value = \xff;\n"
    (tmp_path / "sample.c").write_bytes(data)
    service = CodeContextService(tmp_path, mode="read")
    try:
        structured = await _call(service, "list_symbols", {"path": "sample.c"})
        assert structured["ok"] is False
        assert structured["error"]["code"] == "encoding_error"

        raw = await _call(service, "read_raw", {"path": "sample.c"})
        assert raw["ok"] is True
        assert raw["encoding"] == "latin-1"
        assert raw["content"].encode("latin-1") == data
        assert raw["content_sha256"] == code_context._sha256(data)
    finally:
        service.close()
