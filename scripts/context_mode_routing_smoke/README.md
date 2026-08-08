# Context Mode routing smoke

This deliberately small failing project exercises Bello's routing policy
without naming Context Mode tools in the task itself. A compliant coder should
normally use 5–10 `ctx_*` calls: initial indexing, focused search, current-file
derivation, a pre-edit behavior probe, changed-file re-indexing/current lookup,
and batched compile/test validation.

Copy this directory to a temporary location before running it because Bello
edits the project:

```bash
cp -R scripts/context_mode_routing_smoke /tmp/bello-context-routing-smoke
cd /tmp/bello-context-routing-smoke
BELLO_SKIP_UPDATE_CHECK=1 \
PYTHONPATH=/path/to/Bello \
python3 -m supervisor.main \
  --task TASK.md \
  --start-over=true \
  --context-mode \
  --keep-context-mode-data \
  --context-mode-debug \
  --completion-review=false \
  --adversary=false \
  --coder-mod gpt-5.5 \
  --runtime-mod gpt-5.5 \
  --coder-intelligence xhigh \
  --runtime-intelligence xhigh
```

The smoke passes when Bello exits normally with `status=complete`, the fixture
tests pass, and the run records between 5 and 10 completed Context Mode calls
with no provenance failure. Exact tool names are retained in the run-local
native broker receipt journal when `--keep-context-mode-data` is enabled.
