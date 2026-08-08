import { getStore, closeStore } from "./store.mjs";

const MAX_INPUT_BYTES = 256 * 1024;
const MAX_MEMORY_BYTES = 16 * 1024;
const EVENTS = Object.freeze({
  pretooluse: "PreToolUse",
  posttooluse: "PostToolUse",
  sessionstart: "SessionStart",
  precompact: "PreCompact",
  userpromptsubmit: "UserPromptSubmit",
  stop: "Stop",
});

const ROUTING = `Bello Context Mode is available only for local workspace reduction.
Use ctx_execute for bounded local code or command output, ctx_execute_file to derive a small answer from a file through FILE_CONTENT, and ctx_batch_execute for related commands.
Use ctx_index and ctx_search for durable local retrieval. Use ctx_stats and ctx_doctor for bounded diagnostics. Call ctx_purge only after the user explicitly approves deletion.
Large results remain in the local FTS5 index; retrieve focused excerpts instead of requesting the raw result again.`;

function canonicalEvent(value) {
  if (typeof value !== "string" || value.length === 0) throw new Error("hook event is required");
  const direct = Object.values(EVENTS).find((event) => event === value);
  const event = direct ?? EVENTS[value.toLowerCase()];
  if (!event) throw new Error("hook event is not in the pinned catalogue");
  return event;
}

async function readInput() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += value.length;
    if (size > MAX_INPUT_BYTES) throw new Error("hook input exceeds the hard limit");
    chunks.push(value);
  }
  if (size === 0) return {};
  const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("hook input must be a JSON object");
  }
  return payload;
}

function boundedJson(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  const raw = Buffer.from(text, "utf8");
  return raw.length <= MAX_MEMORY_BYTES
    ? text
    : `${raw.subarray(0, MAX_MEMORY_BYTES - 64).toString("utf8")}\n[bounded hook memory]`;
}

function memoryValue(event, input) {
  if (event === "UserPromptSubmit") return input.prompt ?? input.visible?.prompt;
  if (event === "PostToolUse") {
    return {
      tool_name: input.tool_name ?? input.visible?.tool_name,
      tool_response: input.tool_response ?? input.visible?.tool_response,
    };
  }
  if (event === "Stop") return input.last_assistant_message ?? input.visible?.last_assistant_message;
  if (event === "PreCompact") return input.custom_instructions ?? input.visible?.custom_instructions;
  return undefined;
}

function resumeContext() {
  const rows = getStore().recent(12);
  if (rows.length === 0) return "";
  const body = rows
    .reverse()
    .map((row) => `### ${row.source}\n${row.body}`)
    .join("\n\n");
  return `\n\nRecovered bounded local session memory after compaction:\n${boundedJson(body)}`;
}

function hookOutput(event, additionalContext = "") {
  if (event === "SessionStart" || event === "UserPromptSubmit" || event === "PostToolUse") {
    return {
      hookSpecificOutput: {
        hookEventName: event,
        additionalContext,
      },
    };
  }
  if (event === "PreToolUse") {
    return { hookSpecificOutput: { hookEventName: event } };
  }
  return {};
}

export async function runHook(rawEvent) {
  let event;
  try {
    event = canonicalEvent(rawEvent);
    const input = await readInput();
    const declared = input.hook_event_name ?? input.hookEventName;
    if (declared !== undefined && canonicalEvent(declared) !== event) {
      throw new Error("hook event does not match the invocation");
    }
    const memory = memoryValue(event, input);
    if (memory !== undefined && memory !== null && boundedJson(memory).trim()) {
      getStore().index(boundedJson(memory), `memory:${event}`);
    }
    let context = "";
    if (event === "SessionStart") {
      const source = input.source ?? input.visible?.source;
      context = ROUTING + (source === "compact" || source === "resume" || source === "recovery" ? resumeContext() : "");
    }
    process.stdout.write(`${JSON.stringify(hookOutput(event, context))}\n`);
  } catch (error) {
    process.stderr.write(`offline hook failed: ${error instanceof Error ? error.message : String(error)}\n`);
    if (event) process.stdout.write(`${JSON.stringify(hookOutput(event))}\n`);
    process.exitCode = 1;
  } finally {
    closeStore();
  }
}
