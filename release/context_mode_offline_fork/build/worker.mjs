import { randomUUID } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import readline from "node:readline";

import {
  assertCode,
  executeCode,
  readWorkspaceFile,
  resolveWorkspacePath,
  walkWorkspaceFiles,
  workspaceRoot,
} from "./executor.mjs";
import { closeStore, getStore } from "./store.mjs";

const VERSION = "1.0.169";
const PROTOCOL_VERSION = "2025-06-18";
const MAX_REQUEST_BYTES = 1024 * 1024;
const MAX_MODEL_RESULT_BYTES = 64 * 1024;
// The controller enforces both a 64 KiB wire limit and a conservative
// 8,000-token estimate (four UTF-8 bytes per token) over the complete signed
// MCP result. The model text is intentionally present in both CallToolResult
// representations, so reserve 4 KiB for the broker's provenance envelope and
// fit the complete worker result into the remaining conservative byte budget.
const MAX_ESTIMATED_MODEL_RESULT_BYTES = 8_000 * 4;
const RESULT_PROVENANCE_HEADROOM = 4 * 1024;
const MAX_WORKER_RESULT_BYTES = Math.min(
  MAX_MODEL_RESULT_BYTES,
  MAX_ESTIMATED_MODEL_RESULT_BYTES - RESULT_PROVENANCE_HEADROOM,
);
const RESULT_TEXT_BUDGET = 12 * 1024;
const AUTO_INDEX_BYTES = 8 * 1024;
const MAX_INDEX_INPUT_BYTES = 8 * 1024 * 1024;
const TOOL_NAMES = Object.freeze([
  "ctx_execute",
  "ctx_execute_file",
  "ctx_batch_execute",
  "ctx_index",
  "ctx_search",
  "ctx_stats",
  "ctx_doctor",
  "ctx_purge",
]);

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schemas = JSON.parse(readFileSync(path.join(packageRoot, "configs", "bello-tool-schemas.json"), "utf8"));
if (
  Object.keys(schemas).length !== TOOL_NAMES.length
  || TOOL_NAMES.some((name) => !Object.hasOwn(schemas, name))
) {
  throw new Error("tool schema catalogue does not cover the exact worker catalogue");
}

const descriptions = Object.freeze({
  ctx_execute: "Run local shell, JavaScript, or Python code and return bounded output. Large output is retained in the local index.",
  ctx_execute_file: "Run code over one workspace file through FILE_CONTENT and return only the computed bounded output.",
  ctx_batch_execute: "Run a bounded sequential batch of local shell commands, index their combined output, and optionally search it.",
  ctx_index: "Index supplied text or bounded workspace files in the local SQLite FTS5 knowledge base.",
  ctx_search: "Search indexed local content with Porter/BM25 and trigram retrieval.",
  ctx_stats: "Return bounded local worker and knowledge-base statistics.",
  ctx_doctor: "Check the pinned worker, SQLite, FTS5, state, and tool catalogue.",
  ctx_purge: "Permanently clear the active epoch knowledge base after explicit approval.",
});

let sourceSequence = 0;

function nowMs(started) {
  return Number((process.hrtime.bigint() - started) / 1_000_000n);
}

function utf8Prefix(text, byteLimit) {
  const raw = Buffer.from(text, "utf8");
  if (raw.length <= byteLimit) return text;
  let end = byteLimit;
  let value = raw.subarray(0, end).toString("utf8");
  while (Buffer.byteLength(value, "utf8") > byteLimit) {
    end -= 1;
    value = raw.subarray(0, end).toString("utf8");
  }
  return value;
}

function boundText(text, byteLimit = RESULT_TEXT_BUDGET) {
  if (byteLimit <= 0) return "";
  if (Buffer.byteLength(text, "utf8") <= byteLimit) return text;
  const suffix = "\n\n[bounded at the worker result limit; full data remains in the local index]";
  const suffixBytes = Buffer.byteLength(suffix, "utf8");
  if (byteLimit <= suffixBytes) return utf8Prefix(suffix, byteLimit);
  return utf8Prefix(text, byteLimit - suffixBytes) + suffix;
}

function setResultText(value, text) {
  value.content[0].text = text;
  value.structuredContent.modelText = text;
  value.structuredContent._belloWorker.returned_bytes = Buffer.byteLength(text, "utf8");
}

function fitResultText(value, sourceText) {
  if (Buffer.byteLength(JSON.stringify(value), "utf8") <= MAX_WORKER_RESULT_BYTES) return;

  let lower = 0;
  let upper = Math.min(Buffer.byteLength(sourceText, "utf8"), RESULT_TEXT_BUDGET);
  let fitted = "";
  while (lower <= upper) {
    const candidateLimit = Math.floor((lower + upper) / 2);
    const candidate = boundText(sourceText, candidateLimit);
    setResultText(value, candidate);
    if (Buffer.byteLength(JSON.stringify(value), "utf8") <= MAX_WORKER_RESULT_BYTES) {
      fitted = candidate;
      lower = candidateLimit + 1;
    } else {
      upper = candidateLimit - 1;
    }
  }
  setResultText(value, fitted);
}

function result(text, { sourceBytes = 0, indexedBytes = null, durationMs = 0, isError = false } = {}) {
  const sourceText = String(text);
  const bounded = boundText(sourceText);
  const value = {
    content: [{ type: "text", text: bounded }],
    structuredContent: {
      modelText: bounded,
      _belloWorker: {
        duration_ms: Math.max(0, Math.trunc(durationMs)),
        indexed_bytes: indexedBytes === null ? null : Math.max(0, Math.trunc(indexedBytes)),
        returned_bytes: Buffer.byteLength(bounded, "utf8"),
        source_bytes: Math.max(0, Math.trunc(sourceBytes)),
      },
    },
  };
  if (isError) value.isError = true;
  fitResultText(value, sourceText);
  return value;
}

function exactObject(value, allowed, required = []) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("arguments must be an object");
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new Error(`unknown argument: ${key}`);
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) throw new Error(`missing argument: ${key}`);
  }
  return value;
}

function boundedString(value, name, maximum, { optional = false } = {}) {
  if (optional && value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    throw new Error(`${name} must be a non-empty NUL-free string`);
  }
  if (Buffer.byteLength(value, "utf8") > maximum) throw new Error(`${name} exceeds ${maximum} bytes`);
  return value;
}

function executionText(execution) {
  const sections = [];
  const stdout = execution.stdout.toString("utf8");
  const stderr = execution.stderr.toString("utf8");
  if (stdout) sections.push(stdout.replace(/\s+$/, ""));
  if (stderr) sections.push(`[stderr]\n${stderr.replace(/\s+$/, "")}`);
  const status = execution.timedOut
    ? "timed out"
    : execution.overflowed
      ? "stream limit exceeded"
      : execution.signal
        ? `signal ${execution.signal}`
        : `exit ${execution.exitCode}`;
  sections.push(`[${status}; ${execution.durationMs} ms]`);
  return sections.join("\n\n");
}

function nextSource(kind) {
  sourceSequence += 1;
  return `${kind}:${Date.now()}:${sourceSequence}:${randomUUID().slice(0, 8)}`;
}

function formatHits(query, hits) {
  const lines = [`## ${query}`];
  if (hits.length === 0) lines.push("No indexed matches.");
  for (const hit of hits) {
    lines.push(`- ${hit.source} / ${hit.title}\n  ${String(hit.snippet).replaceAll("\n", " ")}`);
  }
  return lines.join("\n");
}

function reduceAndIndex(text, { kind, intent }) {
  const sourceBytes = Buffer.byteLength(text, "utf8");
  if (sourceBytes <= AUTO_INDEX_BYTES) {
    return { text, indexedBytes: null, source: null };
  }
  const source = nextSource(kind);
  const indexed = getStore().index(text, source);
  let reduced;
  if (intent) {
    reduced = formatHits(intent, getStore().searchOne(intent, { limit: 5, source }));
  } else {
    const head = utf8Prefix(text, 8 * 1024);
    const tailBuffer = Buffer.from(text, "utf8");
    const tail = tailBuffer.subarray(Math.max(0, tailBuffer.length - 4 * 1024)).toString("utf8");
    reduced = `${head}\n\n… ${sourceBytes} source bytes indexed as ${source} …\n\n${tail}`;
  }
  return {
    text: `${reduced}\n\nUse ctx_search with source ${source} for focused retrieval.`,
    indexedBytes: indexed.indexedBytes,
    source,
  };
}

function executionFailed(execution) {
  return execution.timedOut || execution.overflowed || execution.signal !== null || execution.exitCode !== 0;
}

async function handleExecute(args, started) {
  exactObject(args, ["code", "cwd", "intent", "language", "timeout"], ["code", "language"]);
  assertCode(args.code);
  boundedString(args.language, "language", 32);
  boundedString(args.intent, "intent", 2048, { optional: true });
  const execution = await executeCode(args);
  const raw = executionText(execution);
  const reduced = reduceAndIndex(raw, { kind: "execution", intent: args.intent });
  return result(reduced.text, {
    sourceBytes: execution.stdoutBytes + execution.stderrBytes,
    indexedBytes: reduced.indexedBytes,
    durationMs: nowMs(started),
    isError: executionFailed(execution),
  });
}

async function handleExecuteFile(args, started) {
  exactObject(args, ["code", "intent", "language", "path", "timeout"], ["code", "language", "path"]);
  assertCode(args.code);
  boundedString(args.language, "language", 32);
  boundedString(args.intent, "intent", 2048, { optional: true });
  const input = readWorkspaceFile(args.path);
  const execution = await executeCode({
    language: args.language,
    code: args.code,
    timeout: args.timeout,
    input: input.content,
  });
  const raw = executionText(execution);
  const reduced = reduceAndIndex(raw, { kind: "file-execution", intent: args.intent });
  return result(reduced.text, {
    sourceBytes: input.content.length,
    indexedBytes: reduced.indexedBytes,
    durationMs: nowMs(started),
    isError: executionFailed(execution),
  });
}

async function handleBatch(args, started) {
  exactObject(args, ["commands", "concurrency", "cwd", "queries", "timeout"], ["commands"]);
  if (!Array.isArray(args.commands) || args.commands.length < 1 || args.commands.length > 32) {
    throw new Error("commands must contain 1 to 32 entries");
  }
  if (args.concurrency !== undefined && args.concurrency !== 1) {
    throw new Error("offline batch concurrency is fixed at 1");
  }
  if (args.queries !== undefined && (!Array.isArray(args.queries) || args.queries.length > 16)) {
    throw new Error("queries must be an array with at most 16 entries");
  }
  const records = [];
  let sourceBytes = 0;
  let failed = false;
  for (const entry of args.commands) {
    exactObject(entry, ["command", "label"], ["command", "label"]);
    const command = boundedString(entry.command, "command", 64 * 1024);
    const label = boundedString(entry.label, "label", 160);
    const execution = await executeCode({
      language: "shell",
      code: command,
      cwd: args.cwd,
      timeout: args.timeout,
    });
    sourceBytes += execution.stdoutBytes + execution.stderrBytes;
    failed ||= executionFailed(execution);
    records.push(`## ${label}\n\n${executionText(execution)}`);
  }
  const raw = records.join("\n\n");
  const source = nextSource("batch");
  const indexed = getStore().index(raw, source);
  const queries = args.queries ?? [];
  const text = queries.length > 0
    ? queries.map((query) => {
        boundedString(query, "query", 2048);
        return formatHits(query, getStore().searchOne(query, { limit: 5, source }));
      }).join("\n\n")
    : `${records.map((record) => utf8Prefix(record, 2048)).join("\n\n")}\n\nFull batch output indexed as ${source}.`;
  return result(text, {
    sourceBytes,
    indexedBytes: indexed.indexedBytes,
    durationMs: nowMs(started),
    isError: failed,
  });
}

function indexOne(content, source) {
  if (Buffer.byteLength(content, "utf8") > MAX_INDEX_INPUT_BYTES) {
    throw new Error(`index input exceeds ${MAX_INDEX_INPUT_BYTES} bytes`);
  }
  return getStore().index(content, source);
}

async function handleIndex(args, started) {
  exactObject(args, ["content", "maxDepth", "maxFiles", "path", "source"]);
  const hasContent = args.content !== undefined;
  const hasPath = args.path !== undefined;
  if (hasContent === hasPath) throw new Error("provide exactly one of content or path");
  const labels = [];
  let sourceBytes = 0;
  let indexedBytes = 0;
  let chunks = 0;
  if (hasContent) {
    const content = boundedString(args.content, "content", MAX_INDEX_INPUT_BYTES);
    const source = boundedString(args.source ?? "manual", "source", 512);
    const indexed = indexOne(content, source);
    sourceBytes += Buffer.byteLength(content, "utf8");
    indexedBytes += indexed.indexedBytes;
    chunks += indexed.chunks;
    labels.push(source);
  } else {
    const lexical = resolveWorkspacePath(args.path);
    const info = statSync(lexical);
    const files = info.isDirectory()
      ? walkWorkspaceFiles(args.path, { maxDepth: args.maxDepth, maxFiles: args.maxFiles })
      : [lexical];
    if (files.length === 0) throw new Error("no indexable workspace files found");
    for (const file of files) {
      const input = readWorkspaceFile(file);
      const relative = path.relative(workspaceRoot(), file);
      const source = args.source
        ? `${boundedString(args.source, "source", 400)}:${relative}`
        : relative;
      const content = input.content.toString("utf8");
      const indexed = indexOne(content, source);
      sourceBytes += input.content.length;
      indexedBytes += indexed.indexedBytes;
      chunks += indexed.chunks;
      labels.push(source);
    }
  }
  return result(
    `Indexed ${labels.length} source(s), ${chunks} section(s), ${indexedBytes} bytes.\nSources: ${labels.slice(0, 20).join(", ")}`,
    { sourceBytes, indexedBytes, durationMs: nowMs(started) },
  );
}

async function handleSearch(args, started) {
  exactObject(args, ["limit", "queries", "source"], ["queries"]);
  if (!Array.isArray(args.queries) || args.queries.length < 1 || args.queries.length > 16) {
    throw new Error("queries must contain 1 to 16 strings");
  }
  if (args.limit !== undefined && (!Number.isInteger(args.limit) || args.limit < 1 || args.limit > 10)) {
    throw new Error("limit must be an integer from 1 to 10");
  }
  boundedString(args.source, "source", 512, { optional: true });
  let sourceBytes = 0;
  const sections = args.queries.map((query) => {
    boundedString(query, "query", 2048);
    const hits = getStore().searchOne(query, { limit: args.limit, source: args.source });
    sourceBytes += hits.reduce((total, hit) => total + Buffer.byteLength(String(hit.snippet), "utf8"), 0);
    return formatHits(query, hits);
  });
  return result(sections.join("\n\n"), { sourceBytes, durationMs: nowMs(started) });
}

async function handleStats(args, started) {
  exactObject(args, []);
  const stats = getStore().stats();
  return result(
    [
      "Context Mode offline worker statistics",
      `- indexed sections: ${stats.chunks}`,
      `- stored bytes: ${stats.storedBytes}`,
      `- indexed bytes total: ${stats.counters.indexed_bytes ?? 0}`,
      `- indexed documents total: ${stats.counters.indexed_documents ?? 0}`,
      `- SQLite: ${stats.sqliteVersion}`,
    ].join("\n"),
    { sourceBytes: 0, durationMs: nowMs(started) },
  );
}

async function handleDoctor(args, started) {
  exactObject(args, []);
  const store = getStore();
  const check = store.db.prepare("PRAGMA integrity_check").get().integrity_check;
  const compileOptions = store.db.prepare("PRAGMA compile_options").all().map((row) => Object.values(row)[0]);
  const ftsTables = store.db.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE name IN ('documents_fts','documents_tri')").get().count;
  const checks = [
    ["worker version", VERSION === "1.0.169"],
    ["exact tool catalogue", TOOL_NAMES.length === 8 && Object.keys(schemas).length === 8],
    ["SQLite integrity", check === "ok"],
    ["FTS5 tables", Number(ftsTables) === 2],
    ["thread-safe SQLite", compileOptions.some((value) => String(value).startsWith("THREADSAFE="))],
    ["offline launch", process.env.BELLO_OFFLINE === "1"],
  ];
  const ok = checks.every(([, passed]) => passed);
  return result(
    ["Context Mode doctor", ...checks.map(([name, passed]) => `[${passed ? "OK" : "FAIL"}] ${name}`)].join("\n"),
    { sourceBytes: 0, durationMs: nowMs(started), isError: !ok },
  );
}

async function handlePurge(args, started) {
  exactObject(args, ["confirm"], ["confirm"]);
  if (args.confirm !== true) throw new Error("confirm must be true");
  const before = getStore().purge();
  return result(
    `Purged active epoch knowledge base: ${before.chunks} section(s), ${before.storedBytes} bytes.`,
    { sourceBytes: before.storedBytes, durationMs: nowMs(started) },
  );
}

const handlers = new Map([
  ["ctx_execute", handleExecute],
  ["ctx_execute_file", handleExecuteFile],
  ["ctx_batch_execute", handleBatch],
  ["ctx_index", handleIndex],
  ["ctx_search", handleSearch],
  ["ctx_stats", handleStats],
  ["ctx_doctor", handleDoctor],
  ["ctx_purge", handlePurge],
]);

function writeMessage(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function rpcError(id, code, message) {
  writeMessage({ jsonrpc: "2.0", id, error: { code, message: boundText(message) } });
}

async function dispatch(message) {
  if (message === null || typeof message !== "object" || Array.isArray(message) || message.jsonrpc !== "2.0") {
    rpcError(message?.id ?? null, -32600, "Invalid Request");
    return;
  }
  const id = message.id;
  if (id === undefined) return;
  if (typeof message.method !== "string") {
    rpcError(id, -32600, "Invalid Request");
    return;
  }
  if (message.method === "initialize") {
    writeMessage({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "bello_context_mode", version: VERSION },
      },
    });
    return;
  }
  if (message.method === "ping") {
    writeMessage({ jsonrpc: "2.0", id, result: {} });
    return;
  }
  if (message.method === "tools/list") {
    writeMessage({
      jsonrpc: "2.0",
      id,
      result: {
        tools: TOOL_NAMES.map((name) => ({
          name,
          description: descriptions[name],
          inputSchema: schemas[name],
        })),
      },
    });
    return;
  }
  if (message.method === "tools/call") {
    const params = message.params;
    if (params === null || typeof params !== "object" || Array.isArray(params)) {
      rpcError(id, -32602, "Invalid tools/call parameters");
      return;
    }
    const handler = handlers.get(params.name);
    if (!handler) {
      rpcError(id, -32602, "Unknown tool");
      return;
    }
    const started = process.hrtime.bigint();
    try {
      const toolResult = await handler(params.arguments ?? {}, started);
      writeMessage({ jsonrpc: "2.0", id, result: toolResult });
    } catch (error) {
      const messageText = error instanceof Error ? error.message : String(error);
      writeMessage({
        jsonrpc: "2.0",
        id,
        result: result(`Context Mode worker error: ${messageText}`, {
          durationMs: nowMs(started),
          isError: true,
        }),
      });
    }
    return;
  }
  rpcError(id, -32601, "Method not found");
}

getStore();

const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity, terminal: false });
lines.on("line", (line) => {
  if (Buffer.byteLength(line, "utf8") > MAX_REQUEST_BYTES) {
    rpcError(null, -32700, "Request exceeds the hard limit");
    return;
  }
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    rpcError(null, -32700, "Parse error");
    return;
  }
  void dispatch(message).catch((error) => {
    process.stderr.write(`worker dispatch failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
});

function shutdown() {
  lines.close();
  closeStore();
  process.exit(0);
}

process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
process.once("exit", closeStore);
