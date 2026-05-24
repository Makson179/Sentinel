from __future__ import annotations

import asyncio
from pathlib import Path

import click

from supervisor.schemas import RunConfig
from supervisor.version import probe_claude, probe_codex
from supervisor.wrapper import SupervisorWrapper


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx: click.Context) -> None:
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


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
