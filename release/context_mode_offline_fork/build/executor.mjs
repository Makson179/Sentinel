import { spawn } from "node:child_process";
import { lstatSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import path from "node:path";

export const MAX_STREAM_BYTES = 8 * 1024 * 1024;
export const MAX_FILE_BYTES = 8 * 1024 * 1024;
export const DEFAULT_TIMEOUT_MS = 120_000;
export const MAX_TIMEOUT_MS = 3_600_000;
export const MAX_CODE_BYTES = 64 * 1024;

const WORKSPACE = realpathSync(process.cwd());

function isWithin(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

export function workspaceRoot() {
  return WORKSPACE;
}

export function resolveWorkspacePath(value = ".", { requireFile = false, requireDirectory = false } = {}) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    throw new Error("workspace path must be a non-empty NUL-free string");
  }
  const lexical = path.resolve(WORKSPACE, value);
  if (!isWithin(WORKSPACE, lexical)) throw new Error("workspace path escapes the active workspace");
  const resolved = realpathSync(lexical);
  if (!isWithin(WORKSPACE, resolved)) throw new Error("workspace path resolves outside the active workspace");
  const info = statSync(resolved);
  if (requireFile && !info.isFile()) throw new Error("workspace path is not a regular file");
  if (requireDirectory && !info.isDirectory()) throw new Error("workspace path is not a directory");
  return resolved;
}

export function boundedTimeout(value) {
  if (value === undefined) return DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(value) || value < 1 || value > MAX_TIMEOUT_MS) {
    throw new Error(`timeout must be an integer from 1 to ${MAX_TIMEOUT_MS}`);
  }
  return value;
}

export function assertCode(value) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    throw new Error("code must be a non-empty NUL-free string");
  }
  if (Buffer.byteLength(value, "utf8") > MAX_CODE_BYTES) {
    throw new Error(`code exceeds ${MAX_CODE_BYTES} bytes`);
  }
  return value;
}

function languageCommand(language, code, fileMode) {
  if (language === "shell") {
    const prefix = fileMode ? 'FILE_CONTENT="$(cat)"\n' : "";
    return { executable: "sh", args: ["-lc", `${prefix}${code}`] };
  }
  if (language === "javascript") {
    const prefix = fileMode
      ? 'const FILE_CONTENT=require("node:fs").readFileSync(0,"utf8");\n'
      : "";
    return { executable: process.execPath, args: ["-e", `${prefix}${code}`] };
  }
  if (language === "python") {
    const prefix = fileMode ? "import sys\nFILE_CONTENT=sys.stdin.read()\n" : "";
    return { executable: "python3", args: ["-c", `${prefix}${code}`] };
  }
  throw new Error("language must be shell, javascript, or python");
}

function terminateTree(child) {
  if (!child.pid) return;
  try {
    if (process.platform !== "win32") process.kill(-child.pid, "SIGKILL");
    else child.kill("SIGKILL");
  } catch {
    try {
      child.kill("SIGKILL");
    } catch {
      // The process tree already exited.
    }
  }
}

function collect(stream, onOverflow) {
  const chunks = [];
  let size = 0;
  stream.on("data", (chunk) => {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const remaining = MAX_STREAM_BYTES - size;
    if (remaining > 0) chunks.push(value.subarray(0, remaining));
    size += value.length;
    if (size > MAX_STREAM_BYTES) onOverflow();
  });
  return {
    bytes: () => Math.min(size, MAX_STREAM_BYTES),
    value: () => Buffer.concat(chunks),
    overflowed: () => size > MAX_STREAM_BYTES,
  };
}

export async function executeCode({ language, code, cwd, timeout, input }) {
  assertCode(code);
  const runCwd = resolveWorkspacePath(cwd ?? ".", { requireDirectory: true });
  const timeoutMs = boundedTimeout(timeout);
  const command = languageCommand(language, code, input !== undefined);
  const started = process.hrtime.bigint();
  return await new Promise((resolve, reject) => {
    let timedOut = false;
    let overflowed = false;
    let settled = false;
    let child;
    try {
      child = spawn(command.executable, command.args, {
        cwd: runCwd,
        detached: process.platform !== "win32",
        env: process.env,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (error) {
      reject(error);
      return;
    }
    const overflow = () => {
      if (overflowed) return;
      overflowed = true;
      terminateTree(child);
    };
    const stdout = collect(child.stdout, overflow);
    const stderr = collect(child.stderr, overflow);
    const timer = setTimeout(() => {
      timedOut = true;
      terminateTree(child);
    }, timeoutMs);
    timer.unref();
    child.once("error", (error) => {
      clearTimeout(timer);
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
    child.once("close", (codeValue, signal) => {
      clearTimeout(timer);
      if (settled) return;
      settled = true;
      const durationMs = Number((process.hrtime.bigint() - started) / 1_000_000n);
      resolve({
        argv: [command.executable, ...command.args],
        cwd: runCwd,
        durationMs,
        exitCode: codeValue,
        signal,
        timedOut,
        overflowed: overflowed || stdout.overflowed() || stderr.overflowed(),
        stdout: stdout.value(),
        stderr: stderr.value(),
        stdoutBytes: stdout.bytes(),
        stderrBytes: stderr.bytes(),
      });
    });
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
}

export function readWorkspaceFile(value) {
  const resolved = resolveWorkspacePath(value, { requireFile: true });
  const info = statSync(resolved);
  if (info.size > MAX_FILE_BYTES) throw new Error(`file exceeds ${MAX_FILE_BYTES} bytes`);
  return { path: resolved, content: readFileSync(resolved) };
}

const DEFAULT_EXTENSIONS = new Set([
  ".c", ".cc", ".cpp", ".css", ".go", ".h", ".hpp", ".html", ".java", ".js",
  ".json", ".jsx", ".md", ".mjs", ".py", ".rb", ".rs", ".sh", ".toml", ".ts",
  ".tsx", ".txt", ".xml", ".yaml", ".yml",
]);
const SKIPPED_DIRECTORIES = new Set([".git", ".codex", ".bello", ".supervisor", "node_modules"]);

export function walkWorkspaceFiles(value, { maxDepth = 5, maxFiles = 200 } = {}) {
  if (!Number.isInteger(maxDepth) || maxDepth < 0 || maxDepth > 20) throw new Error("maxDepth is invalid");
  if (!Number.isInteger(maxFiles) || maxFiles < 1 || maxFiles > 1000) throw new Error("maxFiles is invalid");
  const root = resolveWorkspacePath(value, { requireDirectory: true });
  const result = [];
  const visit = (directory, depth) => {
    if (depth > maxDepth || result.length >= maxFiles) return;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (result.length >= maxFiles) return;
      if (entry.isSymbolicLink()) continue;
      const candidate = path.join(directory, entry.name);
      const info = lstatSync(candidate);
      if (info.isDirectory()) {
        if (!SKIPPED_DIRECTORIES.has(entry.name)) visit(candidate, depth + 1);
      } else if (
        info.isFile()
        && info.size <= MAX_FILE_BYTES
        && DEFAULT_EXTENSIONS.has(path.extname(entry.name).toLowerCase())
      ) {
        const resolved = realpathSync(candidate);
        if (isWithin(WORKSPACE, resolved)) result.push(resolved);
      }
    }
  };
  visit(root, 0);
  return result;
}
