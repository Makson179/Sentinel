# Sentinel Install And Use Quick Start

Sentinel is installed and run as the `sentinel` command. It supervises Codex
through `codex app-server`, so Codex must be installed and logged in before the
first Sentinel run.

## Requirements

Install these first:

- Python 3.11 or newer.
- Git.
- pipx.
- Codex CLI on `PATH`.
- A logged-in Codex account.

Check the tools:

```bash
python3 --version
git --version
pipx --version
codex --version
```

Log in to Codex if needed:

```bash
codex login
```

## Install Sentinel With pipx

Install Sentinel from the default GitHub branch:

```bash
pipx install "git+https://github.com/Makson179/Sentinel.git"
```

Verify the install:

```bash
sentinel --version
sentinel doctor
sentinel --help
```

`sentinel doctor` should find Python, Git, Codex, Codex app-server support,
Sentinel metadata, and the `sentinel` executable. If it reports a Codex auth
problem, run `codex login` and try again.

## Update Sentinel

For normal task runs, Sentinel checks whether the installed Git commit is up to
date. If a newer commit is available, it prompts:

```text
[u] update now and rerun this command
[c] continue with the installed version
[q] quit
```

You can also update manually:

```bash
sentinel update
```

If you need to bypass the startup update check once:

```bash
SENTINEL_SKIP_UPDATE_CHECK=1 sentinel --task TASK.md
```

## Run Sentinel On A Task

Go to the project Sentinel should work on:

```bash
cd /path/to/your/project
```

Create or choose a markdown task file, for example `TASK.md`:

```bash
cat > TASK.md <<'EOF'
Create hello.py that prints "hello from sentinel".
Run python3 hello.py to validate it.
EOF
```

Start Sentinel:

```bash
sentinel --task TASK.md
```

Start over from fresh `.supervisor` state:

```bash
sentinel --task TASK.md --start-over
```

Use a specific model:

```bash
sentinel --task TASK.md --model gpt-5
```

If you omit `--task`, Sentinel scans for markdown task files:

```bash
sentinel
```

## Install From Source For Development

Clone the repository:

```bash
git clone https://github.com/Makson179/Sentinel.git
cd Sentinel
```

Create a virtual environment and install:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
```

Run the local command:

```bash
.venv/bin/sentinel --help
```

On Windows PowerShell:

```powershell
.venv\Scripts\sentinel.exe --help
```

Run the test suite from the repository:

```bash
.venv/bin/python -m pytest -q
```
