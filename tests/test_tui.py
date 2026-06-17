from __future__ import annotations

from supervisor.tui import TerminalTUI


class _EofStdin:
    def fileno(self) -> int:
        return 9

    def readline(self) -> str:
        return ""


class _FakeLoop:
    def __init__(self) -> None:
        self.removed: list[int] = []

    def remove_reader(self, fd: int) -> None:
        self.removed.append(fd)


def test_tui_unregisters_stdin_reader_on_eof(monkeypatch) -> None:
    tui = TerminalTUI()
    loop = _FakeLoop()
    tui._loop = loop  # type: ignore[assignment]
    tui._reader_registered = True
    monkeypatch.setattr("supervisor.tui.sys.stdin", _EofStdin())

    tui._on_stdin_ready()

    assert loop.removed == [9]
    assert tui._reader_registered is False
