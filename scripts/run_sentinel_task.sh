#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  printf 'usage: %s WORKDIR TASK_MD LOG_FILE [SUPERVISOR_ARGS...]\n' "$0" >&2
  exit 2
fi

workdir=$1
task=$2
log_file=$3
shift 3

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
sentinel_bin=${SENTINEL_BIN:-"$repo_root/.venv/bin/sentinel"}

if [[ "$log_file" != /* ]]; then
  log_file="$(pwd)/$log_file"
fi

mkdir -p "$(dirname "$log_file")"

cd "$workdir"
set +e
"$sentinel_bin" --task "$task" "$@" 2>&1 | tee "$log_file"
rc=${PIPESTATUS[0]}
set -e

exit "$rc"
