// pty.js — pseudo-TTY wrapping and process-group termination.
//
// Why a pty at all: the `agy` CLI silently drops its final answer when stdout
// is not a TTY. Several harnesses also switch to a terse, non-interactive
// renderer off-TTY, which is exactly the output we are trying NOT to lose.
// Running under `script` gives the child a real tty, so we capture what a human
// would actually see — and `script`'s own stdout is our capture point.
//
// Because `script` is the direct child and the harness is its grandchild, a
// plain kill(pid) leaves the harness running. Every pty-wrapped spawn is
// therefore detached into its own process group and killed with kill(-pid).

import { spawn } from "node:child_process";
import os from "node:os";

/**
 * Wrap an argv in `script` so the child sees a tty.
 *
 * util-linux:  script -qec '<shell string>' /dev/null
 * BSD/macOS:   script -q /dev/null <cmd> <args...>   (no shell, no quoting bugs)
 */
export function ptyArgv(command, args) {
  if (os.platform() === "darwin") {
    return { command: "script", args: ["-q", "/dev/null", command, ...args] };
  }
  const shellString = [command, ...args].map(shellQuote).join(" ");
  return { command: "script", args: ["-qec", shellString, "/dev/null"] };
}

export function shellQuote(s) {
  if (/^[A-Za-z0-9_./:@%+=-]+$/.test(s)) return s;
  return "'" + String(s).replace(/'/g, `'\\''`) + "'";
}

/**
 * Spawn a child, optionally under a pty, always in its own process group.
 *
 * @returns {{child: import("node:child_process").ChildProcess, argv: string[], pty: boolean}}
 */
export function spawnCaptured({ command, args, env, cwd, pty = false }) {
  const eff = pty ? ptyArgv(command, args) : { command, args };
  const child = spawn(eff.command, eff.args, {
    cwd,
    env,
    // Own process group so timeout can kill the whole tree (script + harness).
    detached: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
  return { child, argv: [eff.command, ...eff.args], pty };
}

/**
 * Kill a whole process group: SIGTERM, then SIGKILL after `graceMs`.
 * Returns a promise that resolves once the SIGKILL timer is cleared.
 */
export function killGroup(child, graceMs = 5000) {
  const pid = child.pid;
  if (!pid) return Promise.resolve("no-pid");
  const target = -pid; // negative pid == the whole process group

  const send = (sig) => {
    try {
      process.kill(target, sig);
      return true;
    } catch {
      // Group already gone, or we never got one (spawn failed). Fall back to
      // the direct pid so a non-grouped child is still terminated.
      try {
        child.kill(sig);
        return true;
      } catch {
        return false;
      }
    }
  };

  send("SIGTERM");
  return new Promise((resolve) => {
    const t = setTimeout(() => {
      send("SIGKILL");
      resolve("sigkill");
    }, graceMs);
    child.once("exit", () => {
      clearTimeout(t);
      resolve("sigterm");
    });
  });
}
