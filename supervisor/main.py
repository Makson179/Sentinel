from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Coroutine

import click

from supervisor.config_editor import run_config_editor
from supervisor import doctor, update_check
from supervisor.controller import SentinelController
from supervisor.project_config import (
    INTELLIGENCE_CHOICES,
    ProjectConfig,
    ProjectConfigError,
    intelligence_choices_for_model,
    load_project_config,
    project_config_path,
)
from supervisor.schemas import SentinelStatus
from supervisor.task_select import TaskSelectionError


OPTIONAL_BOOL_FLAGS = {"--fast", "--start-over", "--clean", "--adversary", "--completion-review"}


class SentinelClickGroup(click.Group):
    def main(self, args: list[str] | tuple[str, ...] | None = None, **extra: Any) -> Any:
        normalized_args = _normalize_optional_bool_args(list(args) if args is not None else sys.argv[1:])
        return super().main(args=normalized_args, **extra)


@click.group(
    name="sentinel",
    cls=SentinelClickGroup,
    invoke_without_command=True,
    no_args_is_help=False,
    subcommand_metavar="[COMMAND] [ARGS]...",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option("--task", "task_path", type=click.Path(exists=False, dir_okay=False, path_type=Path))
@click.option("--coder-mod", "coder_model", default=None, help="Model to use for coder turns.")
@click.option("--runtime-mod", "runtime_model", default=None, help="Model to use for runtime supervisor turns.")
@click.option("--completion-mod", "completion_model", default=None, help="Model to use for completion review turns.")
@click.option("--adversary-mod", "adversary_model", default=None, help="Model to use for adversarial tester turns.")
@click.option(
    "--super-mod",
    "legacy_supervisor_model",
    default=None,
    hidden=True,
    help="Legacy alias that sets both runtime and completion models.",
)
@click.option(
    "--coder-intelligence",
    default=None,
    type=click.Choice(INTELLIGENCE_CHOICES),
    help="Reasoning effort for coder turns.",
)
@click.option(
    "--runtime-intelligence",
    "runtime_intelligence",
    default=None,
    type=click.Choice(INTELLIGENCE_CHOICES),
    help="Reasoning effort for runtime supervisor turns.",
)
@click.option(
    "--completion-intelligence",
    default=None,
    type=click.Choice(INTELLIGENCE_CHOICES),
    help="Reasoning effort for completion review turns.",
)
@click.option(
    "--adversary-intelligence",
    default=None,
    type=click.Choice(INTELLIGENCE_CHOICES),
    help="Reasoning effort for adversarial tester turns.",
)
@click.option(
    "--super-intelligence",
    "legacy_supervisor_intelligence",
    default=None,
    hidden=True,
    type=click.Choice(INTELLIGENCE_CHOICES),
    help="Legacy alias that sets both runtime and completion reasoning effort.",
)
@click.option(
    "--fast",
    default=None,
    type=click.BOOL,
    metavar="[true|false]",
    help="Use Codex Fast service tier for both coder and supervisor turns. Bare --fast means true.",
)
@click.option(
    "--start-over",
    default=None,
    type=click.BOOL,
    metavar="[true|false]",
    help="Reinitialize .supervisor state files. Bare --start-over means true.",
)
@click.option(
    "--protected-path",
    "protected_paths",
    multiple=True,
    type=click.Path(exists=False, path_type=Path),
    help="Path declared by the harness as hidden/grading material. Repeated.",
)
@click.option(
    "--clean",
    default=None,
    type=click.BOOL,
    metavar="[true|false]",
    help="Delete everything in the current folder except the selected task file before starting.",
)
@click.option(
    "--completion-review",
    "completion_review",
    default=None,
    type=click.BOOL,
    metavar="[true|false]",
    help=(
        "Run the completion review before finishing. false finishes on the coder's "
        "readiness marker and disables the adversary, which runs inside the review."
    ),
)
@click.option(
    "--adversary",
    default=None,
    type=click.BOOL,
    metavar="[true|false]",
    help="Run the adversarial tester before final completion; requires completion review.",
)
@click.option(
    "--adversary-runs",
    default=None,
    type=click.IntRange(min=0),
    metavar="N",
    help="Maximum adversarial tester passes before final completion (default 1; 0 disables).",
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
    coder_model: str | None,
    runtime_model: str | None,
    completion_model: str | None,
    adversary_model: str | None,
    legacy_supervisor_model: str | None,
    coder_intelligence: str | None,
    runtime_intelligence: str | None,
    completion_intelligence: str | None,
    adversary_intelligence: str | None,
    legacy_supervisor_intelligence: str | None,
    fast: bool | None,
    start_over: bool | None,
    protected_paths: tuple[Path, ...],
    clean: bool | None,
    completion_review: bool | None,
    adversary: bool | None,
    adversary_runs: int | None,
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    _startup_update_gate()
    try:
        project_config = load_project_config(Path.cwd(), create=True)
        run_settings = _resolve_run_settings(
            project_config=project_config,
            task_path=task_path,
            coder_model=coder_model,
            runtime_model=runtime_model,
            completion_model=completion_model,
            adversary_model=adversary_model,
            legacy_supervisor_model=legacy_supervisor_model,
            coder_intelligence=coder_intelligence,
            runtime_intelligence=runtime_intelligence,
            completion_intelligence=completion_intelligence,
            adversary_intelligence=adversary_intelligence,
            legacy_supervisor_intelligence=legacy_supervisor_intelligence,
            fast=fast,
            start_over=start_over,
            protected_paths=protected_paths,
            clean=clean,
            completion_review=completion_review,
            adversary=adversary,
            adversary_runs=adversary_runs,
        )
        _run_async_cleanly(_run_sentinel(run_settings))
    except ProjectConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    except TaskSelectionError as exc:
        raise click.ClickException(str(exc)) from exc
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command("update")
@click.option("--check", "check_only", is_flag=True, help="Check for updates without installing them.")
@click.option("--json", "json_output", is_flag=True, help="Emit update status as JSON. Implies --check.")
def update_command(check_only: bool, json_output: bool) -> None:
    status = update_check.check_for_update()
    info = status.install_info
    if check_only or json_output:
        if json_output:
            click.echo(json.dumps(_update_status_payload(status), sort_keys=True))
        else:
            click.echo(_format_update_check_report(status))
        return

    if status.state == update_check.UpdateState.UNKNOWN:
        raise click.ClickException(status.warning or "Could not check for Sentinel updates")
    if status.state == update_check.UpdateState.CURRENT:
        click.echo("Sentinel is up to date.")
        click.echo(f"Installed: {info.version}")
        return

    assert status.latest_version is not None
    old_version = info.version
    try:
        update_check.run_update(info)
    except update_check.UpdateCheckError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo("Sentinel updated.")
    click.echo(f"Previous: {old_version}")
    click.echo(f"Current:  {status.latest_version}")


def _update_status_payload(status: update_check.UpdateStatus) -> dict[str, Any]:
    info = status.install_info
    return {
        "package": info.package_name,
        "installed_version": info.version,
        "latest_version": status.latest_version,
        "state": status.state.value,
        "update_available": status.state == update_check.UpdateState.OUTDATED,
        "install_mode": info.install_mode,
        "warning": status.warning,
    }


def _format_update_check_report(status: update_check.UpdateStatus) -> str:
    info = status.install_info
    lines = [f"Sentinel {info.version}"]
    if status.state == update_check.UpdateState.CURRENT:
        lines.append("status: up to date")
        lines.append(f"latest: {status.latest_version or info.version}")
    elif status.state == update_check.UpdateState.OUTDATED:
        lines.append("status: update available")
        lines.append(f"installed: {info.version}")
        lines.append(f"latest:    {status.latest_version}")
    else:
        lines.append("status: unknown")
        lines.append(f"warning: Could not check for Sentinel updates: {status.warning or 'unknown error'}")
    return "\n".join(lines)


@cli.command("doctor")
def doctor_command() -> None:
    raise click.exceptions.Exit(doctor.run_doctor())


@cli.command("config")
def config_command() -> None:
    try:
        config = run_config_editor(Path.cwd())
    except (ProjectConfigError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Saved Sentinel config: {project_config_path(Path.cwd())}")
    click.echo(f"coder-mod: {config.coder_mod}")
    click.echo(f"runtime-mod: {config.runtime_mod}")
    click.echo(f"completion-mod: {config.completion_mod}")
    click.echo(f"adversary-mod: {config.adversary_mod}")


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
        lines.append(f"latest: {status.latest_version or info.version}")
        lines.append("status: up to date")
    elif status.state == update_check.UpdateState.OUTDATED:
        lines.append(f"installed: {info.version}")
        lines.append(f"latest:    {status.latest_version}")
        lines.append("status: update available")
        lines.extend(["", "Run:", "  sentinel update"])
    else:
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
            f"Sentinel is not running from a TTY; continuing without prompting. "
            f"Set {update_check.SKIP_UPDATE_CHECK_ENV}=1 to bypass this check.",
            err=True,
        )
        return

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
            f"Installed: {info.version}",
            f"Latest:    {status.latest_version}",
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


async def _run_sentinel(settings: RunSettings) -> int:
    controller = SentinelController(
        Path.cwd(),
        task_path=settings.task_path,
        coder_model=settings.coder_model,
        runtime_model=settings.runtime_model,
        completion_model=settings.completion_model,
        adversary_model=settings.adversary_model,
        coder_intelligence=settings.coder_intelligence,
        runtime_intelligence=settings.runtime_intelligence,
        completion_intelligence=settings.completion_intelligence,
        adversary_intelligence=settings.adversary_intelligence,
        fast=settings.fast,
        overwrite_state=settings.start_over,
        declared_grading_roots=settings.protected_paths,
        clean_workspace=settings.clean,
        adversary_enabled=settings.adversary,
        adversary_runs=settings.adversary_runs,
        completion_review=settings.completion_review,
        project_config=load_project_config(Path.cwd(), create=False),
    )
    await controller.run()
    status = controller.store.get_sentinel_config().status
    if status == SentinelStatus.PROVIDER_FAILURE:
        return 2
    return 0


@dataclass(frozen=True)
class RunSettings:
    task_path: Path | None
    coder_model: str
    runtime_model: str
    completion_model: str
    adversary_model: str
    coder_intelligence: str
    runtime_intelligence: str
    completion_intelligence: str
    adversary_intelligence: str
    fast: bool
    start_over: bool
    protected_paths: tuple[Path, ...]
    clean: bool
    completion_review: bool
    adversary: bool
    adversary_runs: int


def _resolve_run_settings(
    *,
    project_config: ProjectConfig,
    task_path: Path | None = None,
    coder_model: str | None = None,
    runtime_model: str | None = None,
    completion_model: str | None = None,
    adversary_model: str | None = None,
    legacy_supervisor_model: str | None = None,
    coder_intelligence: str | None = None,
    runtime_intelligence: str | None = None,
    completion_intelligence: str | None = None,
    adversary_intelligence: str | None = None,
    legacy_supervisor_intelligence: str | None = None,
    fast: bool | None = None,
    start_over: bool | None = None,
    protected_paths: tuple[Path, ...] = (),
    clean: bool | None = None,
    completion_review: bool | None = None,
    adversary: bool | None = None,
    adversary_runs: int | None = None,
) -> RunSettings:
    if legacy_supervisor_model is not None:
        if runtime_model is not None or completion_model is not None:
            raise RuntimeError("--super-mod cannot be combined with --runtime-mod or --completion-mod")
        runtime_model = legacy_supervisor_model
        completion_model = legacy_supervisor_model
    if legacy_supervisor_intelligence is not None:
        if runtime_intelligence is not None or completion_intelligence is not None:
            raise RuntimeError(
                "--super-intelligence cannot be combined with --runtime-intelligence or --completion-intelligence"
            )
        runtime_intelligence = legacy_supervisor_intelligence
        completion_intelligence = legacy_supervisor_intelligence

    selected_coder_model = coder_model or project_config.coder_mod
    selected_runtime_model = runtime_model or project_config.runtime_mod
    selected_completion_model = completion_model or project_config.completion_mod
    selected_adversary_model = adversary_model or project_config.adversary_mod
    selected_coder_intelligence = coder_intelligence or project_config.coder_intelligence
    selected_runtime_intelligence = runtime_intelligence or project_config.runtime_intelligence
    selected_completion_intelligence = completion_intelligence or project_config.completion_intelligence
    selected_adversary_intelligence = adversary_intelligence or project_config.adversary_intelligence
    _validate_model_intelligence("coder", selected_coder_model, selected_coder_intelligence)
    _validate_model_intelligence("runtime", selected_runtime_model, selected_runtime_intelligence)
    _validate_model_intelligence("completion", selected_completion_model, selected_completion_intelligence)
    _validate_model_intelligence("adversary", selected_adversary_model, selected_adversary_intelligence)
    selected_task = task_path if task_path is not None else Path(project_config.task) if project_config.task else None
    selected_protected_paths = protected_paths or tuple(Path(path) for path in project_config.protected_path)
    return RunSettings(
        task_path=selected_task,
        coder_model=selected_coder_model,
        runtime_model=selected_runtime_model,
        completion_model=selected_completion_model,
        adversary_model=selected_adversary_model,
        coder_intelligence=selected_coder_intelligence,
        runtime_intelligence=selected_runtime_intelligence,
        completion_intelligence=selected_completion_intelligence,
        adversary_intelligence=selected_adversary_intelligence,
        fast=project_config.fast if fast is None else fast,
        start_over=project_config.start_over if start_over is None else start_over,
        protected_paths=selected_protected_paths,
        clean=project_config.clean if clean is None else clean,
        completion_review=project_config.completion_review if completion_review is None else completion_review,
        # An explicit --adversary wins; otherwise an explicit --adversary-runs implies on/off (0 = off).
        adversary=(
            adversary
            if adversary is not None
            else (adversary_runs > 0 if adversary_runs is not None else project_config.adversary)
        ),
        adversary_runs=project_config.adversary_runs if adversary_runs is None else adversary_runs,
    )


def _validate_model_intelligence(role: str, model: str, intelligence: str) -> None:
    supported = intelligence_choices_for_model(model)
    if intelligence in supported:
        return
    choices = ", ".join(supported)
    raise RuntimeError(f"{role} model {model} does not support reasoning effort {intelligence}; choose one of: {choices}")


def _normalize_optional_bool_args(args: list[str]) -> list[str]:
    normalized: list[str] = []
    for index, arg in enumerate(args):
        if arg in OPTIONAL_BOOL_FLAGS:
            next_arg = args[index + 1] if index + 1 < len(args) else None
            normalized.append(arg)
            if next_arg is None or next_arg.startswith("-"):
                normalized.append("true")
            continue
        normalized.append(arg)
    return normalized


if __name__ == "__main__":
    cli()
