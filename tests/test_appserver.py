from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest

from supervisor.appserver import (
    AppServerClient,
    AppServerProtocolError,
    AppServerTimeoutError,
    _app_server_environment,
    _create_isolated_codex_home,
)


def test_appserver_environment_drops_parent_codex_execution_context() -> None:
    source = {
        "PATH": "/usr/bin",
        "CODEX_HOME": "/tmp/codex-home",
        "CODEX_PERMISSION_PROFILE": ":danger-full-access",
        "CODEX_SANDBOX": "seatbelt",
        "CODEX_SANDBOX_NETWORK_DISABLED": "1",
        "CODEX_NETWORK_PROXY_ACTIVE": "1",
        "CODEX_THREAD_ID": "parent-thread",
    }

    result = _app_server_environment(source)

    assert result == {"PATH": "/usr/bin", "CODEX_HOME": "/tmp/codex-home"}


def test_isolated_codex_home_preserves_configuration_but_not_user_rules(tmp_path: Path) -> None:
    source = tmp_path / "codex-home"
    source.mkdir()
    (source / "auth.json").write_text('{"token": "test"}\n', encoding="utf-8")
    (source / "config.toml").write_text('model = "gpt-test"\n', encoding="utf-8")
    (source / "skills").mkdir()
    (source / "rules").mkdir()
    (source / "rules" / "default.rules").write_text(
        'prefix_rule(pattern=["curl"], decision="allow")\n',
        encoding="utf-8",
    )

    isolated = _create_isolated_codex_home(source)
    try:
        assert (isolated / "auth.json").is_symlink()
        assert (isolated / "config.toml").read_text(encoding="utf-8") == 'model = "gpt-test"\n'
        assert (isolated / "skills").is_symlink()
        assert (isolated / "rules").is_dir()
        assert not (isolated / "rules").is_symlink()
        assert list((isolated / "rules").iterdir()) == []
        assert (source / "rules" / "default.rules").exists()
    finally:
        shutil.rmtree(isolated)


async def test_request_times_out_without_appserver_response() -> None:
    class FakeStdin:
        def write(self, data):
            self.data = data

        async def drain(self):
            return None

    class FakeProcess:
        stdin = FakeStdin()

    client = AppServerClient()
    client.process = FakeProcess()  # type: ignore[assignment]

    with pytest.raises(AppServerTimeoutError) as exc_info:
        await client.request("model/list", {}, timeout=0.01)

    assert "app-server RPC model/list response timed out after 0.01s" in str(exc_info.value)


async def test_reader_reports_oversized_stdout_line_without_hanging() -> None:
    errors: list[BaseException] = []
    reader = asyncio.StreamReader(limit=64)
    reader.feed_data(b'{"method":"notification","params":{"output":"' + (b"x" * 128) + b'"}}\n')
    reader.feed_eof()

    class FakeProcess:
        stdout = reader

    async def on_transport_error(error: BaseException) -> None:
        errors.append(error)

    client = AppServerClient(transport_error_handler=on_transport_error, stdout_limit=64)
    client.process = FakeProcess()  # type: ignore[assignment]
    pending = asyncio.get_running_loop().create_future()
    client._pending[1] = pending

    await asyncio.wait_for(client._read_loop(), timeout=0.5)

    assert len(errors) == 1
    assert isinstance(errors[0], AppServerProtocolError)
    assert "stdout line exceeded stream limit" in str(errors[0])
    assert pending.done()
    with pytest.raises(AppServerProtocolError):
        pending.result()
