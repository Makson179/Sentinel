from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path

import pytest

from supervisor.appserver import (
    AppServerClient,
    AppServerError,
    AppServerMessage,
    AppServerProtocolError,
    AppServerTimeoutError,
    ClientRole,
    PendingRequestKey,
    _app_server_environment,
    _create_isolated_codex_home,
    _validate_app_server_frame,
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


def test_appserver_environment_applies_explicit_overrides_after_filtering() -> None:
    result = _app_server_environment(
        {"PATH": "/usr/bin", "DROP_ME": "yes", "CODEX_SANDBOX": "ambient"},
        overrides={"DROP_ME": None, "ROLE_POLICY": "supervisor", "CODEX_SANDBOX": "explicit"},
    )

    assert result == {"PATH": "/usr/bin", "ROLE_POLICY": "supervisor", "CODEX_SANDBOX": "explicit"}


def test_appserver_environment_drops_ambient_loaders_and_unrelated_credentials() -> None:
    result = _app_server_environment(
        {
            "PATH": "/usr/bin",
            "OPENAI_API_KEY": "provider-only",
            "LD_PRELOAD": "/tmp/inject.so",
            "DYLD_INSERT_LIBRARIES": "/tmp/inject.dylib",
            "NODE_OPTIONS": "--require=/tmp/inject.js",
            "PYTHONPATH": "/tmp/inject",
            "SSH_AUTH_SOCK": "/tmp/agent.sock",
            "AWS_SECRET_ACCESS_KEY": "cloud-secret",
            "NPM_TOKEN": "package-secret",
            "UNRELATED_USER_VALUE": "ambient",
        }
    )

    assert result == {"PATH": "/usr/bin", "OPENAI_API_KEY": "provider-only"}


def test_appserver_environment_rejects_invalid_explicit_overrides() -> None:
    with pytest.raises(AppServerProtocolError, match="override"):
        _app_server_environment({}, overrides={"NODE_OPTIONS": "bad\x00value"})


def test_json_rpc_boolean_id_cannot_alias_integer_request() -> None:
    message = AppServerMessage({"id": True, "result": {"ok": True}})
    assert message.request_id is None
    assert AppServerMessage({"id": 1, "result": {}}).request_id == 1


def test_pinned_appserver_frame_union_rejects_extra_and_ambiguous_fields() -> None:
    assert _validate_app_server_frame({"method": "ready", "params": {}}) == {
        "method": "ready",
        "params": {},
    }
    with pytest.raises(AppServerProtocolError, match="fields mismatch"):
        _validate_app_server_frame({"method": "ready", "params": {}, "unexpected": True})
    with pytest.raises(AppServerProtocolError, match="fields mismatch"):
        _validate_app_server_frame({"id": 1, "result": {}, "error": {}})
    with pytest.raises(AppServerProtocolError, match="params must be an object"):
        _validate_app_server_frame({"method": "ready", "params": []})


def test_pinned_notification_accepts_only_schema_defined_emission_timestamp() -> None:
    frame = {
        "method": "remoteControl/status/changed",
        "params": {"status": "disabled"},
        "emittedAtMs": 1_785_698_613_737,
    }
    assert _validate_app_server_frame(frame) == frame
    with pytest.raises(AppServerProtocolError, match="non-negative integer"):
        _validate_app_server_frame({**frame, "emittedAtMs": True})
    with pytest.raises(AppServerProtocolError, match="fields mismatch"):
        _validate_app_server_frame({**frame, "id": 4})


@pytest.mark.parametrize("request_id", [True, {"nested": "id"}])
def test_pending_request_key_rejects_non_json_rpc_ids(request_id: object) -> None:
    with pytest.raises(AppServerProtocolError, match="pending request JSON-RPC id"):
        PendingRequestKey(ClientRole.CODER, 2, request_id)  # type: ignore[arg-type]


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
    assert exc_info.value.role is ClientRole.SUPERVISOR
    assert exc_info.value.process_epoch == 0


async def test_response_to_dead_transport_never_starts_replacement_process() -> None:
    class FakeStdin:
        def write(self, _data):
            raise AssertionError("dead transport must not be written")

        async def drain(self):
            raise AssertionError("dead transport must not be drained")

    class DeadProcess:
        stdin = FakeStdin()
        returncode = 1

    client = AppServerClient(role=ClientRole.CODER)
    client.process = DeadProcess()  # type: ignore[assignment]
    starts = 0

    async def unexpected_start() -> None:
        nonlocal starts
        starts += 1

    client.start = unexpected_start  # type: ignore[method-assign]
    with pytest.raises(AppServerError, match="not writable"):
        await client.respond(9, {"decision": "decline"})
    assert starts == 0


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


async def test_request_fails_fast_when_reader_already_failed() -> None:
    class FakeStdin:
        def write(self, _data: bytes) -> None:
            raise AssertionError("a transport with a dead reader must not be written")

        async def drain(self) -> None:
            raise AssertionError("a transport with a dead reader must not be drained")

    class FakeProcess:
        stdin = FakeStdin()
        returncode = None

    client = AppServerClient(role=ClientRole.CODER)
    client.process = FakeProcess()  # type: ignore[assignment]
    reader_error = AppServerProtocolError(
        "app-server stdout line exceeded stream limit",
        role=ClientRole.CODER,
        process_epoch=1,
        app_server_instance_id="dead-reader",
    )
    client.reader_error = reader_error

    with pytest.raises(AppServerProtocolError) as exc_info:
        await asyncio.wait_for(client.request("turn/interrupt", {}, timeout=3600), timeout=0.1)

    assert exc_info.value is reader_error


async def test_process_launcher_receives_configured_stdout_limit() -> None:
    received: dict[str, object] = {}

    async def launch_process(**kwargs: object) -> asyncio.subprocess.Process:
        received.update(kwargs)
        command = kwargs["command"]
        assert isinstance(command, tuple)
        return await asyncio.create_subprocess_exec(
            *command,
            cwd=kwargs["cwd"],
            env=kwargs["environment"],
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=kwargs["stdout_limit"],
            start_new_session=True,
        )

    client = AppServerClient(
        command=[sys.executable, "-c", "import time; time.sleep(60)"],
        role=ClientRole.CODER,
        process_launcher=launch_process,  # type: ignore[arg-type]
        stdout_limit=123_457,
    )
    try:
        await client.start()
        assert received["stdout_limit"] == 123_457
        assert received["role"] is ClientRole.CODER
    finally:
        await client.stop()


async def test_start_restart_uses_run_owned_paths_and_monotonic_origin(tmp_path: Path) -> None:
    codex_home = tmp_path / "coder-home"
    launch_cwd = tmp_path / "neutral-cwd"
    codex_home.mkdir()
    launch_cwd.mkdir()
    marker = codex_home / "owned-by-controller"
    marker.write_text("keep", encoding="utf-8")
    notifications: list[AppServerMessage] = []
    ready = [asyncio.Event(), asyncio.Event()]

    async def on_notification(message: AppServerMessage) -> None:
        notifications.append(message)
        ready[len(notifications) - 1].set()

    script = (
        "import json,os,time;"
        "print(json.dumps({'method':'ready','params':{"
        "'cwd':os.getcwd(),'home':os.environ.get('CODEX_HOME'),"
        "'role':os.environ.get('BELLO_APP_SERVER_ROLE'),"
        "'epoch':os.environ.get('BELLO_APP_SERVER_PROCESS_EPOCH'),"
        "'instance':os.environ.get('BELLO_APP_SERVER_INSTANCE_ID')}}),flush=True);"
        "time.sleep(60)"
    )
    client = AppServerClient(
        command=[sys.executable, "-c", script],
        role="coder",
        codex_home=codex_home,
        launch_cwd=launch_cwd,
        notification_handler=on_notification,
    )

    try:
        await client.start()
        await asyncio.wait_for(ready[0].wait(), timeout=2)
        first_instance = client.app_server_instance_id
        assert client.role is ClientRole.CODER
        assert client.process_epoch == 1
        assert notifications[0].role is ClientRole.CODER
        assert notifications[0].process_epoch == 1
        assert notifications[0].app_server_instance_id == first_instance
        assert notifications[0].params == {
            "cwd": str(launch_cwd),
            "home": str(codex_home),
            "role": "coder",
            "epoch": "1",
            "instance": first_instance,
        }

        await client.stop()
        assert marker.read_text(encoding="utf-8") == "keep"
        assert launch_cwd.is_dir()

        await client.start()
        await asyncio.wait_for(ready[1].wait(), timeout=2)
        assert client.process_epoch == 2
        assert client.app_server_instance_id != first_instance
        assert notifications[1].process_epoch == 2
    finally:
        await client.stop()


async def test_late_epoch_message_cannot_resolve_current_pending_request() -> None:
    class FakeProcess:
        pass

    process = FakeProcess()
    client = AppServerClient(role=ClientRole.CODER)
    client.process = process  # type: ignore[assignment]
    client.process_epoch = 2
    client.app_server_instance_id = "current-instance"
    client._active_process_epoch = 2
    client._active_app_server_instance_id = "current-instance"
    pending = asyncio.get_running_loop().create_future()
    key = PendingRequestKey(ClientRole.CODER, 2, 1)
    client._pending[key] = pending

    late = AppServerMessage(
        {"id": 1, "result": {"source": "old"}},
        role=ClientRole.CODER,
        process_epoch=1,
        app_server_instance_id="old-instance",
    )
    await client._dispatch(
        late,
        process=process,  # type: ignore[arg-type]
        process_epoch=1,
        app_server_instance_id="old-instance",
    )
    assert not pending.done()

    current = AppServerMessage(
        {"id": 1, "result": {"source": "current"}},
        role=ClientRole.CODER,
        process_epoch=2,
        app_server_instance_id="current-instance",
    )
    await client._dispatch(
        current,
        process=process,  # type: ignore[arg-type]
        process_epoch=2,
        app_server_instance_id="current-instance",
    )
    assert pending.result() == {"source": "current"}


async def test_stderr_capture_is_bounded_and_tracks_truncation() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(b"0123456789")
    reader.feed_eof()

    class FakeProcess:
        stderr = reader

    process = FakeProcess()
    client = AppServerClient(stderr_limit=4)
    client.process = process  # type: ignore[assignment]

    await client._drain_stderr()

    assert client.stderr_output == b"0123"
    assert client.stderr_text == "0123"
    assert client.stderr_total_bytes == 10
    assert client.stderr_truncated is True
