from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Coroutine

import click

from supervisor.controller import SentinelController
from supervisor.schemas import SentinelStatus
from supervisor.task_select import TaskSelectionError


@click.command(name="sentinel")
@click.option("--task", "task_path", type=click.Path(exists=False, dir_okay=False, path_type=Path))
@click.option("--model", default=None, help="Model to use for coder and supervisor turns.")
@click.option("--start-over", is_flag=True, help="Reinitialize .supervisor state files.")
@click.option(
    "--protected-path",
    "protected_paths",
    multiple=True,
    type=click.Path(exists=False, path_type=Path),
    help="Path declared by the harness as hidden/grading material. Repeated.",
)
@click.option(
    "--clean",
    is_flag=True,
    help="Delete everything in the current folder except the selected task file before starting.",
)
@click.option(
    "--adversary",
    is_flag=True,
    help="Run the adversarial tester before final completion.",
)
def cli(
    task_path: Path | None,
    model: str | None,
    start_over: bool,
    protected_paths: tuple[Path, ...],
    clean: bool,
    adversary: bool,
) -> None:
    try:
        _run_async_cleanly(_run_sentinel(task_path, model, start_over, protected_paths, clean, adversary))
    except TaskSelectionError as exc:
        raise click.ClickException(str(exc)) from exc
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc


def _run_async_cleanly(coro: Coroutine[Any, Any, Any]) -> None:
    loop = asyncio.new_event_loop()
    exit_code = 0
    try:
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(coro)
        if isinstance(result, int):
            exit_code = result
    finally:
        pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.run_until_complete(loop.shutdown_default_executor())
        asyncio.set_event_loop(None)
        loop.close()
    sys.exit(exit_code)


async def _run_sentinel(
    task_path: Path | None,
    model: str | None,
    start_over: bool,
    protected_paths: tuple[Path, ...],
    clean: bool,
    adversary: bool,
) -> int:
    controller = SentinelController(
        Path.cwd(),
        task_path=task_path,
        model=model,
        overwrite_state=start_over,
        declared_grading_roots=protected_paths,
        clean_workspace=clean,
        adversary_enabled=True if adversary else None,
    )
    await controller.run()
    status = controller.store.get_sentinel_config().status
    if status == SentinelStatus.PROVIDER_FAILURE:
        return 2
    return 0


if __name__ == "__main__":
    cli()
