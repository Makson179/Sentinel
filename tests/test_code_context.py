from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from supervisor.code_context import (
    CODE_CONTEXT_NAMESPACE,
    CodeContextService,
    code_context_prompt_guidance,
    dynamic_tool_specs,
)


def _payload(response: dict) -> dict:
    assert set(response) == {"contentItems", "success"}
    return json.loads(response["contentItems"][0]["text"])


async def _call(service: CodeContextService, tool: str, arguments: dict) -> dict:
    return _payload(await service.call(tool, arguments))


def test_dynamic_specs_are_mode_scoped_and_context_independent() -> None:
    assert dynamic_tool_specs("off") == []
    read = dynamic_tool_specs("read")[0]
    preview = dynamic_tool_specs("preview")[0]

    assert read["type"] == "namespace"
    assert read["name"] == CODE_CONTEXT_NAMESPACE
    assert {tool["name"] for tool in read["tools"]} == {
        "list_symbols",
        "read_symbol",
        "find_references",
        "read_raw",
    }
    assert {tool["name"] for tool in preview["tools"]} == {
        "list_symbols",
        "read_symbol",
        "find_references",
        "read_raw",
        "prepare_symbol_edit",
    }
    assert all(tool["inputSchema"]["additionalProperties"] is False for tool in preview["tools"])
    assert code_context_prompt_guidance("off") == ""
    assert "never writes" in code_context_prompt_guidance("preview")


@pytest.mark.asyncio
async def test_raw_range_errors_expose_stable_machine_reasons(tmp_path: Path) -> None:
    (tmp_path / "TASK.md").write_text("# Task\n\nhello\n", encoding="utf-8")
    service = CodeContextService(tmp_path, mode="read")
    try:
        max_bytes = await _call(
            service,
            "read_raw",
            {"path": "TASK.md", "max_bytes": 200, "end_line": 200},
        )
        assert max_bytes["error"]["code"] == "invalid_arguments"
        assert max_bytes["error"]["reason"] == "max_bytes_out_of_range"

        end_line = await _call(
            service,
            "read_raw",
            {"path": "TASK.md", "max_bytes": 256, "end_line": 200},
        )
        assert end_line["error"]["code"] == "invalid_arguments"
        assert end_line["error"]["reason"] == "end_line_out_of_range"

        wrong_type = await _call(
            service,
            "read_raw",
            {"path": "TASK.md", "max_bytes": "256"},
        )
        assert wrong_type["error"]["code"] == "invalid_arguments"
        assert wrong_type["error"]["reason"] == "max_bytes_not_integer"
    finally:
        service.close()


@pytest.mark.asyncio
async def test_python_symbols_and_paged_read_reconstruct_exact_locus(tmp_path: Path) -> None:
    source = (
        "value = 1\n\n"
        "@decorator\n"
        "async def target(arg: str) -> str:\n"
        + "    # exact body\n"
        + "    return arg + 'x' * 700\n"
        + "\nclass Box:\n    def method(self):\n        return target('v')\n"
    )
    path = tmp_path / "sample.py"
    path.write_text(source, encoding="utf-8")
    service = CodeContextService(tmp_path, mode="read")
    try:
        listed = await _call(service, "list_symbols", {"path": "sample.py"})
        assert listed["ok"] is True
        target = next(symbol for symbol in listed["symbols"] if symbol["name"] == "target")
        assert target["kind"] == "async_function"
        assert any(symbol["qualified_name"] == "Box.method" for symbol in listed["symbols"])

        chunks: list[str] = []
        cursor = None
        while True:
            arguments = {
                "path": "sample.py",
                "selector": target["selector"],
                "expected_file_sha256": listed["file_sha256"],
                "max_bytes": 256,
            }
            if cursor is not None:
                arguments["cursor"] = cursor
            page = await _call(service, "read_symbol", arguments)
            assert page["ok"] is True
            chunks.append(page["content"])
            cursor = page["next_cursor"]
            if cursor is None:
                break

        assert "".join(chunks) == (
            "@decorator\nasync def target(arg: str) -> str:\n"
            "    # exact body\n    return arg + 'x' * 700\n"
        )
    finally:
        service.close()


@pytest.mark.asyncio
async def test_known_qualified_name_reads_symbol_in_one_tool_call(tmp_path: Path) -> None:
    (tmp_path / "sample.py").write_text(
        "class Box:\n    def target(self):\n        return 42\n",
        encoding="utf-8",
    )
    service = CodeContextService(tmp_path, mode="read")
    try:
        result = await _call(
            service,
            "read_symbol",
            {"path": "sample.py", "qualified_name": "Box.target"},
        )
        assert result["ok"] is True
        assert result["symbol"]["qualified_name"] == "Box.target"
        assert result["content"] == "    def target(self):\n        return 42\n"
        assert service.metrics_snapshot()["calls_read_symbol_total"] == 1
        assert service.metrics_snapshot().get("calls_list_symbols_total", 0) == 0

        invalid = await _call(
            service,
            "read_symbol",
            {
                "path": "sample.py",
                "qualified_name": "Box.target",
                "selector": result["symbol"]["selector"],
            },
        )
        assert invalid["ok"] is False
        assert invalid["error"]["code"] == "invalid_arguments"
    finally:
        service.close()


@pytest.mark.asyncio
async def test_known_qualified_name_finds_references_without_list_call(tmp_path: Path) -> None:
    (tmp_path / "sample.py").write_text(
        "def target():\n    return 1\n\nvalue = target()\n",
        encoding="utf-8",
    )
    service = CodeContextService(tmp_path, mode="read")
    try:
        result = await _call(
            service,
            "find_references",
            {
                "path": "sample.py",
                "qualified_name": "target",
                "scope": "file",
            },
        )
        assert result["ok"] is True
        assert any(
            reference["reference_kind"] == "call"
            for reference in result["references"]
        )
        assert service.metrics_snapshot()["calls_find_references_total"] == 1
        assert service.metrics_snapshot().get("calls_list_symbols_total", 0) == 0
    finally:
        service.close()


@pytest.mark.asyncio
async def test_raw_read_is_lossless_fallback_and_hash_bound(tmp_path: Path) -> None:
    path = tmp_path / "unknown.xyz"
    path.write_text("α\nsecond\nthird\n", encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    service = CodeContextService(tmp_path, mode="read")
    try:
        result = await _call(
            service,
            "read_raw",
            {
                "path": "unknown.xyz",
                "expected_file_sha256": digest,
                "start_line": 2,
                "end_line": 3,
            },
        )
        assert result["ok"] is True
        assert result["content"] == "second\nthird\n"

        path.write_text("changed\n", encoding="utf-8")
        stale = await _call(
            service,
            "read_raw",
            {"path": "unknown.xyz", "expected_file_sha256": digest},
        )
        assert stale["ok"] is False
        assert stale["error"]["code"] == "stale_file"
    finally:
        service.close()


@pytest.mark.asyncio
async def test_find_references_is_explicitly_syntactic(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "def target():\n    return 1\n\ndef caller():\n    return target()\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text("from a import target\nvalue = target()\n", encoding="utf-8")
    service = CodeContextService(tmp_path, mode="read")
    try:
        listed = await _call(service, "list_symbols", {"path": "a.py"})
        target = next(symbol for symbol in listed["symbols"] if symbol["name"] == "target")
        result = await _call(
            service,
            "find_references",
            {
                "path": "a.py",
                "selector": target["selector"],
                "expected_file_sha256": listed["file_sha256"],
                "scope": "workspace",
            },
        )
        assert result["ok"] is True
        assert result["semantics"] == "syntactic_name_reference"
        calls = [ref for ref in result["references"] if ref["reference_kind"] == "call"]
        assert {ref["path"] for ref in calls} == {"a.py", "b.py"}

        first_page = await _call(
            service,
            "find_references",
            {
                "path": "a.py",
                "selector": target["selector"],
                "expected_file_sha256": listed["file_sha256"],
                "scope": "workspace",
                "limit": 1,
            },
        )
        assert first_page["next_cursor"]
        (tmp_path / "b.py").write_text(
            "from a import target\nvalue = target()\nother = target()\n",
            encoding="utf-8",
        )
        stale_page = await _call(
            service,
            "find_references",
            {
                "path": "a.py",
                "selector": target["selector"],
                "expected_file_sha256": listed["file_sha256"],
                "scope": "workspace",
                "limit": 1,
                "cursor": first_page["next_cursor"],
            },
        )
        assert stale_page["ok"] is False
        assert stale_page["error"]["code"] == "stale_cursor"
    finally:
        service.close()


@pytest.mark.asyncio
async def test_python_attribute_reference_reports_attribute_column(tmp_path: Path) -> None:
    (tmp_path / "sample.py").write_text(
        "def target():\n    return 1\n\ndef caller(obj):\n    return obj.target()\n",
        encoding="utf-8",
    )
    service = CodeContextService(tmp_path, mode="read")
    try:
        result = await _call(
            service,
            "find_references",
            {
                "path": "sample.py",
                "qualified_name": "target",
                "scope": "file",
            },
        )
        call = next(
            reference
            for reference in result["references"]
            if reference["reference_kind"] == "call"
        )
        assert call["line"] == 5
        assert call["column"] == 15
        assert call["confidence"] == "attribute_name_only"
        assert call["line_text"][call["column"] :].startswith("target")
    finally:
        service.close()


@pytest.mark.asyncio
async def test_workspace_references_report_parse_failed_files_as_incomplete(
    tmp_path: Path,
) -> None:
    (tmp_path / "a.py").write_text("def target():\n    pass\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text(
        "target()\ndef broken(:\n",
        encoding="utf-8",
    )
    service = CodeContextService(tmp_path, mode="read")
    try:
        result = await _call(
            service,
            "find_references",
            {
                "path": "a.py",
                "qualified_name": "target",
                "scope": "workspace",
            },
        )
        assert result["ok"] is True
        assert result["total_references"] == 0
        assert result["files_scanned"] == 2
        assert result["files_skipped"] == 1
        assert result["skipped_reasons"] == {"parse_error": 1}
        assert result["scan_truncated"] is False
        assert result["scan_incomplete"] is True
    finally:
        service.close()


@pytest.mark.asyncio
async def test_prepare_edit_validates_without_writing(tmp_path: Path) -> None:
    path = tmp_path / "sample.py"
    original = b"def target():\n    return 1\n\ndef other():\n    return 2\n"
    path.write_bytes(original)
    service = CodeContextService(tmp_path, mode="preview")
    try:
        listed = await _call(service, "list_symbols", {"path": "sample.py"})
        target = next(symbol for symbol in listed["symbols"] if symbol["name"] == "target")
        arguments = {
            "path": "sample.py",
            "selector": target["selector"],
            "expected_file_sha256": listed["file_sha256"],
            "expected_symbol_sha256": target["symbol_sha256"],
            "replacement": "def target():\n    return 42\n",
        }
        preview = await _call(service, "prepare_symbol_edit", arguments)
        assert preview["ok"] is True
        assert preview["applied"] is False
        assert preview["syntax_valid"] is True
        assert "+    return 42" in preview["patch"]
        assert path.read_bytes() == original

        invalid = await _call(
            service,
            "prepare_symbol_edit",
            {**arguments, "replacement": "def target(:\n"},
        )
        assert invalid["ok"] is False
        assert invalid["error"]["code"] == "syntax_validation_failed"
        assert path.read_bytes() == original
    finally:
        service.close()


@pytest.mark.asyncio
async def test_paths_fail_closed_for_runtime_secret_and_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text("def hidden():\n    pass\n", encoding="utf-8")
    (tmp_path / "link.py").symlink_to(outside)
    runtime = tmp_path / ".supervisor"
    runtime.mkdir()
    (runtime / "state.py").write_text("def internal():\n    pass\n", encoding="utf-8")
    (tmp_path / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    (tmp_path / "innocent.txt").symlink_to(tmp_path / ".env")
    service = CodeContextService(tmp_path, mode="read")
    try:
        for path in (
            "../escape.py",
            "link.py",
            ".supervisor/state.py",
            ".env",
            "innocent.txt",
        ):
            result = await _call(service, "read_raw", {"path": path})
            assert result["ok"] is False
            assert result["error"]["code"] in {"path_escape", "protected_path"}
    finally:
        service.close()
        outside.unlink()


@pytest.mark.asyncio
async def test_preview_preserves_crlf_and_renders_no_newline_markers(tmp_path: Path) -> None:
    path = tmp_path / "sample.py"
    path.write_bytes(b"def target():\r\n    return 1")
    service = CodeContextService(tmp_path, mode="preview")
    try:
        listed = await _call(service, "list_symbols", {"path": "sample.py"})
        target = listed["symbols"][0]
        preview = await _call(
            service,
            "prepare_symbol_edit",
            {
                "path": "sample.py",
                "selector": target["selector"],
                "expected_file_sha256": listed["file_sha256"],
                "expected_symbol_sha256": target["symbol_sha256"],
                "replacement": "def target():\n    return 2",
            },
        )
        assert preview["ok"] is True
        assert preview["newline_normalized"] is True
        assert "\\ No newline at end of file" in preview["patch"]
        assert path.read_bytes() == b"def target():\r\n    return 1"
    finally:
        service.close()


@pytest.mark.asyncio
async def test_repeated_calls_complete_without_blocking_event_loop(tmp_path: Path) -> None:
    (tmp_path / "sample.py").write_text("def target():\n    return 1\n", encoding="utf-8")
    service = CodeContextService(tmp_path, mode="read")
    try:
        for _ in range(5):
            result = await _call(service, "list_symbols", {"path": "sample.py"})
            assert result["ok"] is True
        assert service.metrics_snapshot()["cache_hits_total"] == 4
    finally:
        service.close()


@pytest.mark.asyncio
async def test_fifo_is_rejected_without_blocking_workers_or_shutdown(tmp_path: Path) -> None:
    fifo = tmp_path / "blocked.py"
    fifo.parent.mkdir(exist_ok=True)
    import os

    os.mkfifo(fifo)
    service = CodeContextService(tmp_path, mode="read")
    response = await asyncio.wait_for(service.call("read_raw", {"path": "blocked.py"}), 1)
    assert response["success"] is False
    assert _payload(response)["error"]["code"] == "unsupported_file"
    service.close()


@pytest.mark.asyncio
async def test_utf8_bom_preview_does_not_inject_second_bom(tmp_path: Path) -> None:
    path = tmp_path / "sample.py"
    original = b"\xef\xbb\xbfdef first():\n    return 1\n\ndef second():\n    return 2\n"
    path.write_bytes(original)
    service = CodeContextService(tmp_path, mode="preview")
    try:
        listed = await _call(service, "list_symbols", {"path": "sample.py"})
        second = next(symbol for symbol in listed["symbols"] if symbol["name"] == "second")
        preview = await _call(
            service,
            "prepare_symbol_edit",
            {
                "path": "sample.py",
                "selector": second["selector"],
                "expected_file_sha256": listed["file_sha256"],
                "expected_symbol_sha256": second["symbol_sha256"],
                "replacement": "def second():\n    return 3\n",
            },
        )
        assert preview["ok"] is True
        assert preview["syntax_valid"] is True
        assert path.read_bytes() == original
    finally:
        service.close()


@pytest.mark.asyncio
async def test_utf8_bom_preview_of_first_symbol_preserves_file_bom(tmp_path: Path) -> None:
    path = tmp_path / "sample.py"
    original = b"\xef\xbb\xbfdef first():\n    return 1\n\ndef second():\n    return 2\n"
    path.write_bytes(original)
    service = CodeContextService(tmp_path, mode="preview")
    try:
        listed = await _call(service, "list_symbols", {"path": "sample.py"})
        first = next(symbol for symbol in listed["symbols"] if symbol["name"] == "first")
        assert first["start_byte"] == 3
        replacement = b"def first():\n    return 3\n"
        expected_candidate = replacement.join(
            (original[: first["start_byte"]], original[first["end_byte"] :])
        )
        preview = await _call(
            service,
            "prepare_symbol_edit",
            {
                "path": "sample.py",
                "selector": first["selector"],
                "expected_file_sha256": listed["file_sha256"],
                "expected_symbol_sha256": first["symbol_sha256"],
                "replacement": replacement.decode("utf-8"),
            },
        )
        assert preview["ok"] is True
        assert preview["candidate_file_sha256"] == hashlib.sha256(expected_candidate).hexdigest()
        assert expected_candidate.startswith(b"\xef\xbb\xbf")
        assert path.read_bytes() == original
    finally:
        service.close()


@pytest.mark.asyncio
async def test_oversized_identifier_has_finite_bounded_symbol_page(tmp_path: Path) -> None:
    name = "symbol_" + "x" * 14_000
    (tmp_path / "sample.py").write_text(f"def {name}():\n    return 1\n", encoding="utf-8")
    service = CodeContextService(tmp_path, mode="read")
    try:
        listed = await _call(service, "list_symbols", {"path": "sample.py"})
        assert listed["ok"] is True
        assert listed["total_symbols"] == 1
        assert len(listed["symbols"]) == 1
        assert listed["symbols"][0]["name_truncated"] is True
        assert listed["next_cursor"] is None
    finally:
        service.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("filename", "source", "expected"),
    [
        ("sample.c", "struct Box { int value; };\nint answer(void) { return 42; }\n", {"Box", "answer"}),
        ("sample.rs", "struct Box { value: i32 }\nfn answer() -> i32 { 42 }\n", {"Box", "answer"}),
    ],
)
async def test_tree_sitter_c_and_rust_symbols(
    tmp_path: Path,
    filename: str,
    source: str,
    expected: set[str],
) -> None:
    (tmp_path / filename).write_text(source, encoding="utf-8")
    service = CodeContextService(tmp_path, mode="read")
    try:
        result = await _call(service, "list_symbols", {"path": filename})
        assert result["ok"] is True
        assert expected <= {symbol["name"] for symbol in result["symbols"]}
    finally:
        service.close()


@pytest.mark.asyncio
async def test_c_array_typedef_uses_declarator_not_array_bound(tmp_path: Path) -> None:
    (tmp_path / "sample.c").write_text(
        "#define SIZE 8\ntypedef int Foo[SIZE];\n",
        encoding="utf-8",
    )
    service = CodeContextService(tmp_path, mode="read")
    try:
        result = await _call(service, "list_symbols", {"path": "sample.c"})
        typedefs = {
            symbol["name"]
            for symbol in result["symbols"]
            if symbol["kind"] == "typedef"
        }
        assert typedefs == {"Foo"}
    finally:
        service.close()


@pytest.mark.asyncio
async def test_c_function_pointer_typedef_ignores_parameter_name(tmp_path: Path) -> None:
    (tmp_path / "sample.c").write_text(
        "typedef int (*Callback)(int x);\n",
        encoding="utf-8",
    )
    service = CodeContextService(tmp_path, mode="read")
    try:
        result = await _call(service, "list_symbols", {"path": "sample.c"})
        typedefs = {
            symbol["name"]
            for symbol in result["symbols"]
            if symbol["kind"] == "typedef"
        }
        assert typedefs == {"Callback"}
    finally:
        service.close()


@pytest.mark.asyncio
async def test_c_anonymous_struct_typedef_indexes_every_alias(tmp_path: Path) -> None:
    (tmp_path / "sample.c").write_text(
        "typedef struct { int x; int y; } Pair, *PairPtr;\n",
        encoding="utf-8",
    )
    service = CodeContextService(tmp_path, mode="read")
    try:
        result = await _call(service, "list_symbols", {"path": "sample.c"})
        typedefs = {
            symbol["name"]
            for symbol in result["symbols"]
            if symbol["kind"] == "typedef"
        }
        assert typedefs == {"Pair", "PairPtr"}
    finally:
        service.close()


@pytest.mark.asyncio
async def test_c_anonymous_enum_does_not_invent_nested_symbol(tmp_path: Path) -> None:
    (tmp_path / "sample.c").write_text(
        "typedef enum { A, B } Kind;\n",
        encoding="utf-8",
    )
    service = CodeContextService(tmp_path, mode="read")
    try:
        result = await _call(service, "list_symbols", {"path": "sample.c"})
        symbols = result["symbols"]
        assert {
            symbol["name"]
            for symbol in symbols
            if symbol["kind"] == "typedef"
        } == {"Kind"}
        assert all(symbol["qualified_name"] != "Kind::A" for symbol in symbols)
        assert all(symbol["kind"] != "enum" for symbol in symbols)
    finally:
        service.close()


@pytest.mark.asyncio
async def test_c_function_prototypes_are_symbols_without_definition_duplicates(
    tmp_path: Path,
) -> None:
    (tmp_path / "sample.c").write_text(
        "int foo(int);\n"
        "extern void bar(void);\n"
        "int (*callback)(int);\n"
        "int implemented(void) { return 1; }\n",
        encoding="utf-8",
    )
    service = CodeContextService(tmp_path, mode="read")
    try:
        result = await _call(service, "list_symbols", {"path": "sample.c"})
        functions = [
            symbol["name"]
            for symbol in result["symbols"]
            if symbol["kind"] == "function"
        ]
        assert functions.count("foo") == 1
        assert functions.count("bar") == 1
        assert functions.count("implemented") == 1
        assert "callback" not in functions
    finally:
        service.close()


@pytest.mark.asyncio
async def test_rust_trait_required_signature_is_a_function_without_default_duplicate(
    tmp_path: Path,
) -> None:
    (tmp_path / "sample.rs").write_text(
        "trait Worker {\n"
        "    fn required(&self);\n"
        "    fn defaulted(&self) {}\n"
        "}\n",
        encoding="utf-8",
    )
    service = CodeContextService(tmp_path, mode="read")
    try:
        result = await _call(service, "list_symbols", {"path": "sample.rs"})
        functions = [
            symbol["qualified_name"]
            for symbol in result["symbols"]
            if symbol["kind"] == "function"
        ]
        assert functions.count("Worker::required") == 1
        assert functions.count("Worker::defaulted") == 1
    finally:
        service.close()


@pytest.mark.asyncio
async def test_c_tag_type_uses_do_not_duplicate_definition_or_break_qualified_read(
    tmp_path: Path,
) -> None:
    source = (
        "struct Foo { int value; };\n"
        "struct Foo *make(void);\n"
        "void consume(struct Foo *value);\n"
        "typedef struct Foo FooAlias;\n"
        "struct ForwardStruct;\n"
        "union ForwardUnion;\n"
        "enum ForwardEnum;\n"
    )
    (tmp_path / "sample.c").write_text(source, encoding="utf-8")
    service = CodeContextService(tmp_path, mode="read")
    try:
        listed = await _call(service, "list_symbols", {"path": "sample.c"})
        assert listed["ok"] is True
        foo_tags = [
            symbol
            for symbol in listed["symbols"]
            if symbol["qualified_name"] == "Foo" and symbol["kind"] == "struct"
        ]
        assert len(foo_tags) == 1
        assert {
            (symbol["qualified_name"], symbol["kind"])
            for symbol in listed["symbols"]
            if symbol["qualified_name"].startswith("Forward")
        } == {
            ("ForwardStruct", "struct"),
            ("ForwardUnion", "union"),
            ("ForwardEnum", "enum"),
        }

        read = await _call(
            service,
            "read_symbol",
            {
                "path": "sample.c",
                "qualified_name": "Foo",
                "expected_file_sha256": listed["file_sha256"],
            },
        )
        assert read["ok"] is True
        assert read["content"] == "struct Foo { int value; }"
    finally:
        service.close()


@pytest.mark.asyncio
async def test_rust_symbol_range_owns_outer_attributes_during_delete_preview(
    tmp_path: Path,
) -> None:
    path = tmp_path / "sample.rs"
    original = (
        b"#[cfg(feature=\"a\")]\n"
        b"#[inline]\n"
        b"fn first() {}\n\n"
        b"fn second() {}\n"
    )
    path.write_bytes(original)
    service = CodeContextService(tmp_path, mode="preview")
    try:
        listed = await _call(service, "list_symbols", {"path": "sample.rs"})
        first = next(symbol for symbol in listed["symbols"] if symbol["name"] == "first")
        assert first["start_byte"] == 0
        read = await _call(
            service,
            "read_symbol",
            {
                "path": "sample.rs",
                "selector": first["selector"],
                "expected_file_sha256": listed["file_sha256"],
            },
        )
        assert read["content"].startswith("#[cfg")
        assert "#[inline]\nfn first" in read["content"]

        expected_candidate = original[first["end_byte"] :]
        preview = await _call(
            service,
            "prepare_symbol_edit",
            {
                "path": "sample.rs",
                "selector": first["selector"],
                "expected_file_sha256": listed["file_sha256"],
                "expected_symbol_sha256": first["symbol_sha256"],
                "operation": "delete",
                "replacement": "",
            },
        )
        assert preview["ok"] is True
        assert preview["candidate_file_sha256"] == hashlib.sha256(expected_candidate).hexdigest()
        assert "-#[cfg(feature=\"a\")]" in preview["patch"]
        assert "-#[inline]" in preview["patch"]
        assert path.read_bytes() == original
    finally:
        service.close()
