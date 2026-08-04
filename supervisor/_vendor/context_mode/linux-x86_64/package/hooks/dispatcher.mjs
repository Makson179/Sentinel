#!/usr/bin/env node

import { runHook } from "../build/hook.mjs";

await runHook(process.argv[2]);
