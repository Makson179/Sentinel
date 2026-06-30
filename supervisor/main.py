from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Coroutine

import click

from supervisor.controller import DEFAULT_MODEL, SentinelController
from supervisor.schemas import SentinelStatus
from supervisor.task_select import TaskSelectionError


@click.command()
@click.option("--task", "task_path", type=click.Path(exists=False, dir_okay=False, path_type=Path))
@click.option("--model", default=None, help=f"Model to use for both coder and supervisor turns. Default: {DEFAULT_MODEL}.")
@click.option("--coder-mod", "coder_model", default=None, help="Model to use for coder turns. Must be used with --super-mod.")
@click.option("--super-mod", "supervisor_model", default=None, help="Model to use for supervisor turns. Must be used with --coder-mod.")
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
    coder_model: str | None,
    supervisor_model: str | None,
    start_over: bool,
    protected_paths: tuple[Path, ...],
    clean: bool,
    adversary: bool,
) -> None:
    try:
        selected_coder_model, selected_supervisor_model = _resolve_model_flags(
            model=model,
            coder_model=coder_model,
            supervisor_model=supervisor_model,
        )
        _run_async_cleanly(
            _run_sentinel(
                task_path,
                selected_coder_model,
                selected_supervisor_model,
                start_over,
                protected_paths,
                clean,
                adversary,
            )
        )
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
    coder_model: str,
    supervisor_model: str,
    start_over: bool,
    protected_paths: tuple[Path, ...],
    clean: bool,
    adversary: bool,
) -> int:
    controller = SentinelController(
        Path.cwd(),
        task_path=task_path,
        coder_model=coder_model,
        supervisor_model=supervisor_model,
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


def _resolve_model_flags(
    *,
    model: str | None,
    coder_model: str | None,
    supervisor_model: str | None,
) -> tuple[str, str]:
    if model and (coder_model or supervisor_model):
        raise RuntimeError("--model cannot be combined with --coder-mod or --super-mod")
    if bool(coder_model) != bool(supervisor_model):
        raise RuntimeError("--coder-mod and --super-mod must be used together")
    if model:
        return model, model
    if coder_model and supervisor_model:
        return coder_model, supervisor_model
    return DEFAULT_MODEL, DEFAULT_MODEL


if __name__ == "__main__":
    cli()
