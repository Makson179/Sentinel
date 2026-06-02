from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Coroutine

import click

from supervisor.controller import SentinelController
from supervisor.schemas import RunConfig
from supervisor.task_select import TaskSelectionError
from supervisor.version import probe_claude, probe_codex
from supervisor.wrapper import SupervisorWrapper


@click.group(invoke_without_command=True)
@click.option("--task", "task_path", type=click.Path(exists=False, dir_okay=False, path_type=Path))
@click.option("--model", default=None, help="Model to use for coder and supervisor turns.")
@click.option("--start-over", is_flag=True, help="Reinitialize .supervisor state files.")
@click.option(
    "--clean",
    is_flag=True,
    help="Delete everything in the current folder except the selected task file before starting.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    task_path: Path | None,
    model: str | None,
    start_over: bool,
    clean: bool,
) -> None:
    if ctx.invoked_subcommand is None:
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


@cli.command()
@click.option("--plan", "plan_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--mode", type=click.Choice(["subscription", "api"]), default="subscription")
@click.option("--model", default=None)
@click.option("--start-over", is_flag=True, help="Reinitialize .supervisor state files.")
def claude(plan_path: Path, mode: str, model: str | None, start_over: bool) -> None:
    asyncio.run(_run("claude", plan_path, mode, model, start_over))


@cli.command()
@click.option("--plan", "plan_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--mode", type=click.Choice(["subscription", "api"]), default="subscription")
@click.option("--model", default=None)
@click.option("--start-over", is_flag=True, help="Reinitialize .supervisor state files.")
def codex(plan_path: Path, mode: str, model: str | None, start_over: bool) -> None:
    asyncio.run(_run("codex", plan_path, mode, model, start_over))


async def _run(platform: str, plan_path: Path, mode: str, model: str | None, start_over: bool) -> None:
    workspace = Path.cwd().resolve()
    report = probe_claude() if platform == "claude" else probe_codex()
    if not report.ok:
        missing = ", ".join(report.missing) or "unknown capability"
        raise click.ClickException(f"{platform} startup probe failed: {missing}. Upgrade or configure the vendor CLI.")
    config = RunConfig(platform=platform, mode=mode, supervisor_model=model, plan_file_path=str(plan_path.resolve()))
    wrapper = SupervisorWrapper(workspace, config)
    wrapper.initialize_state(overwrite=start_over)
    await wrapper.start_ipc()
    try:
        try:
            await wrapper.prepare_platform()
            wrapper.launch_supervisee()
            if wrapper.process:
                while wrapper.process.poll() is None:
                    await asyncio.sleep(1)
        except (KeyboardInterrupt, asyncio.CancelledError):
            wrapper.preserve_codex_hooks_on_cleanup = False
            raise
        except RuntimeError as exc:
            raise click.ClickException(str(exc)) from exc
    finally:
        wrapper.cleanup_platform()
        await wrapper.stop_ipc()
    click.echo(wrapper.final_report())


if __name__ == "__main__":
    cli()
