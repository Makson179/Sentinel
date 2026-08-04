#!/usr/bin/env node

const [mode, eventName] = process.argv.slice(2);

if (mode === undefined || mode === "mcp") {
  await import("./build/worker.mjs");
} else if (mode === "hook") {
  const { runHook } = await import("./build/hook.mjs");
  await runHook(eventName);
} else {
  process.stderr.write("usage: cli.bundle.mjs [mcp|hook EVENT]\n");
  process.exitCode = 2;
}
