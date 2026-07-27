// dm.js — deliver one assessment to the coordinator.
//
// ############################################################################
// # UNICAST DM ONLY. NEVER A BROADCAST. NEVER PUBLISHED ON sec.incident.      #
// #                                                                          #
// # Responder independence is the entire point of this system. Five models   #
// # judge the same incident WITHOUT seeing each other, and the coordinator    #
// # counts verdicts that were formed alone. That independence is enforced     #
// # mechanically by the ACL in contracts/mesh/channels.yaml — every responder #
// # has publish [] on sec.incident — not by anyone remembering to be careful. #
// #                                                                          #
// # A broadcast here would destroy it. One assessment on a channel any        #
// # responder subscribes to and the remaining verdicts are contaminated: the  #
// # count stops being five independent judgements and becomes one judgement   #
// # plus four reactions to it, while still LOOKING like five. That failure is #
// # invisible in the output, which is what makes it dangerous.                #
// #                                                                          #
// # So: this module only ever addresses `coordinator` directly. If the SDK    #
// # exposes no unicast method, it degrades to the file drop and reports that  #
// # honestly. It does NOT "fall back" to a channel publish. There is no code  #
// # path here that publishes to a channel, and adding one would be a security #
// # regression, not a feature.                                               #
// ############################################################################
//
// The file drop is not a consolation prize: runs/<run_id>/assessments/<agent>.json
// is the durable artifact the coordinator and the run report actually read, so
// it is written FIRST and the DM is layered on top. Cotal being down loses chat
// visibility, never an assessment.

import fs from "node:fs";
import { assessmentPath } from "../../lib/paths.js";
import { loadCotalSdk } from "../../transcript/src/sinks/cotal.js";

/** The one and only recipient. Not a channel — a mesh identity. */
export const COORDINATOR = "coordinator";

/**
 * Method names a Cotal SDK might expose for unicast, most explicit first.
 * `send` is included ONLY with an object recipient ({to}), never with a string
 * second argument — `send(text, "sec.incident")` is the channel-publish form and
 * calling it by accident is exactly the mistake this file exists to prevent.
 */
const DM_METHODS = ["sendDm", "sendDM", "sendTo", "sendDirect", "dm", "direct"];

/**
 * @param {object} assessment a validated assessment.v1
 * @param {{runId:string, agentId:string, transport?:string|object}} opts
 *        transport: "auto" (default) | "file" | "cotal" | an injected
 *        {name, sendDm(payload, to)} object for tests.
 * @returns {Promise<{ok:boolean, path:string, transport:string, to:string,
 *                    broadcast:false, errors:string[]}>}
 */
export async function sendAssessment(assessment, opts = {}) {
  const { runId, agentId } = opts;
  const mode = typeof opts.transport === "string" ? opts.transport : opts.transport ? "inject" : "auto";
  const errors = [];

  // 1. Durable artifact first. Everything else is best-effort on top of this.
  const file = assessmentPath(runId, agentId);
  fs.writeFileSync(file, JSON.stringify(assessment, null, 2) + "\n", "utf8");

  const result = {
    ok: true,
    path: file,
    transport: "file",
    to: COORDINATOR,
    broadcast: false, // asserted in the artifact so an audit can check it
    errors,
  };

  if (mode === "file") return result;

  // 2. Injected transport (tests, or a caller that already holds a mesh agent).
  if (mode === "inject") {
    try {
      await opts.transport.sendDm(assessment, COORDINATOR);
      result.transport = opts.transport.name || "injected";
      return result;
    } catch (err) {
      errors.push(`injected transport failed: ${err.message}`);
      return result; // file drop already succeeded
    }
  }

  // 3. Cotal, if it is up. Never throws — a missing mesh degrades to the file.
  try {
    const sdk = await loadCotalSdk();
    const { MeshAgent, configFromEnv } = sdk;
    if (typeof MeshAgent !== "function" || typeof configFromEnv !== "function") {
      errors.push("cotal SDK loaded but exposes no MeshAgent/configFromEnv");
      return result;
    }
    const agent = new MeshAgent(configFromEnv());
    if (typeof agent.start === "function") await agent.start();
    try {
      const sent = await unicast(agent, assessment);
      if (sent) result.transport = `cotal:${sent}`;
      else {
        // Deliberate refusal, not a bug. Broadcasting instead would be worse
        // than not delivering: it would corrupt the other four verdicts.
        errors.push(
          "cotal SDK exposes no unicast DM method — refusing to broadcast; " +
            "delivered by file drop only",
        );
      }
    } finally {
      try {
        if (typeof agent.stop === "function") await agent.stop();
        else if (typeof agent.close === "function") await agent.close();
      } catch {
        /* teardown is best-effort */
      }
    }
  } catch (err) {
    errors.push(`cotal transport unavailable: ${err.message}`);
  }
  return result;
}

/** Try each unicast method in turn. Returns the method name used, or null. */
async function unicast(agent, assessment) {
  const payload = JSON.stringify(assessment);
  for (const m of DM_METHODS) {
    if (typeof agent[m] !== "function") continue;
    await agent[m](payload, COORDINATOR);
    return m;
  }
  // Object-recipient form. `{to: "coordinator"}` is unambiguous — an SDK that
  // reads it as a channel name would be sending to a channel literally called
  // "coordinator", which no identity subscribes to, so this cannot leak to the
  // other responders even if the SDK's semantics differ from ours.
  if (typeof agent.send === "function" && agent.send.length >= 2) {
    try {
      await agent.send(payload, { to: COORDINATOR });
      return "send({to})";
    } catch {
      return null;
    }
  }
  return null;
}
