## Time And Usage Benchmark System

Sentinel must include a benchmark layer separate from unit and controller tests.

Benchmark purpose:
  Measure wall-clock time, supervisor overhead, supervisor context size, token usage, and Codex quota movement.

Modules:
  supervisor/bench/runner.py
  supervisor/bench/report.py
  supervisor/bench/metrics.py
  supervisor/bench/context_usage.py
  supervisor/bench/token_usage.py
  supervisor/bench/variants.py

Benchmark data:
  evals/time/smoke.yaml
  evals/time/benchmark.yaml
  evals/reports/

Benchmark variants:
  sentinel-full
    normal product behavior

  sentinel-deterministic-only
    same controller/app-server/coder setup, but no stateless supervisor calls except final completion check

  raw-codex-autoapprove
    same app-server coder path, no supervisor, auto-accept benchmark approvals in disposable worktrees only

Sentinel writes .supervisor/perf.jsonl during benchmark runs.

Each perf event includes:
  run_id
  task_id
  variant
  sequence
  generation
  timestamp_wall
  timestamp_monotonic_ns
  event
  role
  thread_id
  turn_id
  metadata

Record these benchmark events:
  run_started
  appserver_started
  appserver_initialized
  coder_thread_started
  coder_turn_started
  first_coder_item_started
  first_tool_started
  approval_requested
  approval_decided
  supervisor_context_built
  supervisor_call_started
  supervisor_call_finished
  supervisor_decision_applied
  turn_completed
  validation_started
  validation_finished
  restart_started
  restart_finished
  final_report_written
  run_finished
  token_usage_updated
  rate_limits_read

Time metrics:
  wall_time_to_success_ms
  startup_time_ms
  time_to_first_action_ms
  approval_latency_ms
  supervisor_call_latency_ms
  supervisor_apply_latency_ms
  restart_recovery_time_ms
  validation_time_ms
  supervisor_wait_time_ms
  supervision_overhead_ratio

Supervisor context metrics:
  supervisor_context_tokens_median
  supervisor_context_tokens_p90
  supervisor_context_tokens_max
  supervisor_context_budget_ratio_p90
  supervisor_context_truncation_count
  largest_context_section
  recent_events_context_share
  diff_context_share

Token metrics:
  coder_input_tokens
  coder_cached_input_tokens
  coder_output_tokens
  coder_total_tokens
  supervisor_input_tokens
  supervisor_cached_input_tokens
  supervisor_output_tokens
  supervisor_total_tokens
  total_input_tokens
  total_cached_input_tokens
  total_output_tokens
  total_tokens
  supervisor_token_share
  supervisor_tokens_per_action
  supervisor_tokens_per_decision
  tokens_per_success

Quota metrics:
  rate_limit_used_percent_start
  rate_limit_used_percent_end
  rate_limit_used_percent_delta
  rate_limit_window_mins
  rate_limit_reached_type
  credits_start if present
  credits_end if present
  credits_delta if present

Token usage source:
  Use app-server thread/tokenUsage/updated events.
  Attribute supervisor usage by fresh supervisor thread.
  Attribute coder usage by cumulative snapshot delta on the persistent coder thread.
  Generate app-server JSON schema for the installed Codex version and store raw token payloads.

Context usage source:
  Measure the supervisor wake packet before every supervisor call.
  Store section-level char counts and estimated token counts.
  Actual billing/usage tokens come from app-server token usage events, not from estimates.

Benchmark command:
  supervisor bench run --suite evals/time/smoke.yaml --variant sentinel-full --repetitions 3 --out evals/reports/smoke.jsonl
  supervisor bench report evals/reports/smoke.jsonl

Comparison rule:
  Compare median and p90 over successful runs only.
  Failed, timeout, stuck, or provider-failure runs are reported separately and excluded from wall-time medians.