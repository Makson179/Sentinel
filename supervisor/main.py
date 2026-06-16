from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Coroutine

import click

from supervisor.controller import SentinelController
from supervisor.task_select import TaskSelectionError


@click.command()
@click.option("--task", "task_path", type=click.Path(exists=False, dir_okay=False, path_type=Path))
@click.option("--model", default=None, help="Model to use for coder and supervisor turns.")
@click.option("--start-over", is_flag=True, help="Reinitialize .supervisor state files.")
@click.option(
    "--clean",
    is_flag=True,
    help="Delete everything in the current folder except the selected task file before starting.",
)
def cli(
    task_path: Path | None,
    model: str | None,
    start_over: bool,
    clean: bool,
) -> None:
    try:
        _run_async_cleanly(_run_sentinel(task_path, model, start_over, clean))
    except TaskSelectionError as exc:
        raise click.ClickException(str(exc)) from exc
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc


def _run_async_cleanly(coro: Coroutine[Any, Any, Any]) -> None:
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(coro)
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
    sys.exit(0)


async def _run_sentinel(
    task_path: Path | None,
    model: str | None,
    start_over: bool,
    clean: bool,
) -> None:
    controller = SentinelController(
        Path.cwd(),
        task_path=task_path,
        model=model,
        overwrite_state=start_over,
        clean_workspace=clean,
    )
    await controller.run()


if __name__ == "__main__":
    cli()
