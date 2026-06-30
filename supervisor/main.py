from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any, Coroutine

import click

from supervisor import doctor, update_check
from supervisor.controller import DEFAULT_MODEL, SentinelController
from supervisor.schemas import SentinelStatus
from supervisor.task_select import TaskSelectionError


@click.group(
    name="sentinel",
    invoke_without_command=True,
    no_args_is_help=False,
    subcommand_metavar="[COMMAND] [ARGS]...",
    context_settings={"help_option_names": ["-h", "--help"]},
)
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
@click.option(
    "--version",
    "-V",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=lambda ctx, param, value: _version_callback(ctx, value),
)
@click.pass_context
def cli(
    ctx: click.Context,
    task_path: Path | None,
    model: str | None,
    coder_model: str | None,
    supervisor_model: str | None,
    start_over: bool,
    protected_paths: tuple[Path, ...],
    clean: bool,
    adversary: bool,
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    _startup_update_gate()
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


@cli.command("update")
def update_command() -> None:
    status = update_check.check_for_update()
    info = status.install_info
    if status.state == update_check.UpdateState.UNKNOWN:
        raise click.ClickException(status.warning or "Could not check for Sentinel updates")
    if status.state == update_check.UpdateState.CURRENT:
        click.echo("Sentinel is up to date.")
        click.echo(f"Installed: {update_check.short_sha(info.installed_commit)}")
        return

    assert status.latest_commit is not None
    old_commit = info.installed_commit
    try:
        update_check.run_update(info)
    except update_check.UpdateCheckError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo("Sentinel updated.")
    click.echo(f"Previous: {update_check.short_sha(old_commit)}")
    click.echo(f"Current:  {update_check.short_sha(status.latest_commit)}")


@cli.command("doctor")
def doctor_command() -> None:
    raise click.exceptions.Exit(doctor.run_doctor())


def _version_callback(ctx: click.Context, value: bool) -> None:
    if not value or ctx.resilient_parsing:
        return
    click.echo(_format_version_report())
    ctx.exit(0)


def _format_version_report() -> str:
    status = update_check.check_for_update()
    info = status.install_info
    lines = [f"Sentinel {info.version}"]
    if status.state == update_check.UpdateState.CURRENT:
        lines.append(f"commit: {update_check.short_sha(info.installed_commit)}")
        lines.append("status: up to date")
    elif status.state == update_check.UpdateState.OUTDATED:
        lines.append(f"installed commit: {update_check.short_sha(info.installed_commit)}")
        lines.append(f"latest commit:    {update_check.short_sha(status.latest_commit)}")
        lines.append("status: update available")
        lines.extend(["", "Run:", "  sentinel update"])
    else:
        lines.append(f"commit: {update_check.short_sha(info.installed_commit)}")
        lines.append("status: unknown")
        lines.append(f"warning: Could not check for Sentinel updates: {status.warning or 'unknown error'}")
    return "\n".join(lines)


def _startup_update_gate() -> None:
    if update_check.skip_update_check_enabled():
        return
    status = update_check.check_for_update()
    if status.state == update_check.UpdateState.UNKNOWN:
        click.echo(
            f"Warning: Could not check for Sentinel updates: {status.warning or 'unknown error'}",
            err=True,
        )
        return
    if status.state == update_check.UpdateState.CURRENT:
        return

    if not sys.stdin.isatty():
        click.echo(_format_update_available_message(status), err=True)
        click.echo(
            f"Sentinel is not running from a TTY. Set {update_check.SKIP_UPDATE_CHECK_ENV}=1 to bypass this check.",
            err=True,
        )
        raise click.exceptions.Exit(update_check.NONINTERACTIVE_UPDATE_EXIT_CODE)

    click.echo(_format_update_available_message(status))
    while True:
        selection = input("Selection [u/c/q]: ").strip().lower()
        if selection == "u":
            _update_and_reexec(status)
            return
        if selection == "c":
            return
        if selection == "q":
            raise click.exceptions.Exit(0)
        click.echo("Please choose u, c, or q.")


def _format_update_available_message(status: update_check.UpdateStatus) -> str:
    info = status.install_info
    return "\n".join(
        [
            "A newer Sentinel version is available.",
            "",
            f"Installed: {update_check.short_sha(info.installed_commit)}",
            f"Latest:    {update_check.short_sha(status.latest_commit)}",
            f"Source:    {info.source_display}",
            "",
            "Choose:",
            "  [u] update now and rerun this command",
            "  [c] continue with the installed version",
            "  [q] quit",
            "",
        ]
    )


def _update_and_reexec(status: update_check.UpdateStatus) -> None:
    try:
        update_check.run_update(status.install_info)
    except update_check.UpdateCheckError as exc:
        raise click.ClickException(str(exc)) from exc
    os.execvp(sys.argv[0], sys.argv)


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
