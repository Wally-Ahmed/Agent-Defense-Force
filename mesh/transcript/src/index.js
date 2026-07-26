// index.js — public surface of the transcript tap.

export { runTap, DEFAULTS, stripAnsi, lastOverwrite, splitBytes, LineSplitter } from "./tap.js";
export { KIND, Sequencer, makeFrame, renderChat, serialize, shortIncident } from "./frame.js";
export { Spool, readSpool, transcriptPaths, runsDir, REPO_ROOT } from "./spool.js";
export { createSink, PublishQueue } from "./sinks/index.js";
export { createFileSink } from "./sinks/file.js";
export { createCotalSink, loadCotalSdk, transcriptChannelFallback } from "./sinks/cotal.js";
export { redact, makeRedactor, secretsFromEnv, PATTERNS } from "./redact.js";
export { makePemGuard, toDisplayLines } from "./tap.js";
export {
  ADAPTERS,
  AGENT_RUNTIME,
  AGENT_MODEL,
  adapterForAgent,
  adapterForRuntime,
  loadChannelFn,
} from "./adapters/index.js";
export { spawnCaptured, killGroup, ptyArgv, shellQuote } from "./pty.js";
