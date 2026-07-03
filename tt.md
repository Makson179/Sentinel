# Sentinel Command Order

Rule: write command parts in the same order as this file. If item A should be
before item B in a command, item A has a smaller line number here.

`pipx install "git+https://github.com/Makson179/Sentinel.git"` - install Sentinel from the default GitHub branch.
`SENTINEL_SKIP_UPDATE_CHECK=1` - skip the startup update check for one command.
`sentinel` - main command; run it from the project directory.
`doctor` - check Python, Git, Codex, auth, app-server support, install metadata, and update status.
`update` - update Sentinel, then use the updated install for future runs.
`--version` - print Sentinel version, installed commit, and update status.
`-V` - short form of `--version`.
`--help` - show command help.
`-h` - short form of `--help`.
`--task TASK.md` - choose the markdown task file explicitly.
`--coder-mod MODEL` - choose the Codex model for coder turns; must be used with `--super-mod`.
`--super-mod MODEL` - choose the Codex model for supervisor turns; must be used with `--coder-mod`.
`--coder-intelligence VALUE` - choose coder reasoning effort.
`--super-intelligence VALUE` - choose supervisor reasoning effort.
`--start-over[=true|false]` - reset `.supervisor` state and start fresh.
`--clean[=true|false]` - delete workspace files except the selected task file before starting; use only in disposable folders.
`--adversary[=true|false]` - run the adversarial tester before final completion.
`--protected-path PATH` - mark a hidden or grading path as protected; repeat this option for multiple paths.
`config` - open the interactive project config editor.

Examples:

```bash
sentinel doctor
sentinel --version
sentinel update
sentinel config
sentinel --task TASK.md --coder-mod gpt-5 --super-mod gpt-5 --start-over
sentinel --task TASK.md --coder-mod gpt-5.5 --super-mod gpt-5.5
SENTINEL_SKIP_UPDATE_CHECK=1 sentinel --task TASK.md
```
