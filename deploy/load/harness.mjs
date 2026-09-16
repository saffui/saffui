#!/usr/bin/env node
// Drives the three hot paths of one instance and prints what they cost:
// a machine signing in, discovery, and a person's claims. The rig is torn
// down, volumes included, whatever the outcome, unless --keep is given.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { login as consoleLogin } from "../lib/console.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const COMPOSE = join(here, "compose.yaml");
const BASE = "http://localhost:48080";
const OPS = "http://localhost:48081";
const REALM = "main";
const CLIENT = "saffui-console";
const REDIRECT = `${BASE}/console/login/return`;
const PASSWORD = process.env.SAFFUI_USER_PASSWORD ?? "a-password-of-decent-length";
const KEEP = process.argv.includes("--keep");

function argued(name, fallback) {
  const held = process.argv.find((arg) => arg.startsWith(`--${name}=`));
  if (!held) return fallback;
  const asked = Number(held.slice(name.length + 3));
  assert.ok(Number.isInteger(asked) && asked > 0, `--${name} takes a whole number above zero`);
  return asked;
}
const SECONDS = argued("seconds", 10);
const WORKERS = argued("workers", 16);

const doExec = promisify(execFile);
async function sh(command, args) {
  const { stdout } = await doExec(command, args, { maxBuffer: 64 * 1024 * 1024 });
  return stdout.trim();
}
const compose = (...args) => sh("docker", ["compose", "-f", COMPOSE, ...args]);

let step = 0;
function act(title) {
  step += 1;
  console.log(`\n[${step}] ${title}`);
}

async function waitFor(label, check, timeoutMs = 120_000, everyMs = 250) {
  const until = Date.now() + timeoutMs;
  for (;;) {
    let outcome;
    try {
      outcome = await check();
    } catch {
      outcome = false;
    }
    if (outcome) return outcome;
    assert.ok(Date.now() < until, `waited too long for ${label}`);
    await new Promise((resolve) => setTimeout(resolve, everyMs));
  }
}

/// What the plane counted for itself, so the harness's own count can be read
/// against it. The counter is found by name rather than assumed: a rig that
/// guesses a metric name reports zero and calls it a result.
async function requestsCounted() {
  const answer = await fetch(`${OPS}/metrics`);
  if (!answer.ok) return null;
  const text = await answer.text();
  let held = null;
  for (const line of text.split("\n")) {
    if (line.startsWith("#") || !line.includes("requests_total")) continue;
    const value = Number(line.slice(line.lastIndexOf(" ") + 1));
    if (Number.isFinite(value)) held = (held ?? 0) + value;
  }
  return held;
}

function percentile(sorted, share) {
  if (!sorted.length) return 0;
  const at = Math.min(sorted.length - 1, Math.floor(sorted.length * share));
  return sorted[at];
}

/// One path driven by several workers for a fixed stretch. Every answer is
/// timed by the harness itself, and a refusal is counted rather than thrown:
/// what a path does under load includes how it refuses.
async function drive(name, once) {
  const timings = [];
  let refused = 0;
  const until = Date.now() + SECONDS * 1000;
  const worker = async () => {
    while (Date.now() < until) {
      const began = performance.now();
      let ok = false;
      try {
        ok = await once();
      } catch {
        ok = false;
      }
      const took = performance.now() - began;
      if (ok) timings.push(took);
      else refused += 1;
    }
  };
  await Promise.all(Array.from({ length: WORKERS }, worker));
  timings.sort((one, other) => one - other);
  const rate = timings.length / SECONDS;
  console.log(
    `    ${name.padEnd(22)} ${String(timings.length).padStart(6)} answers  ` +
      `${String(refused).padStart(4)} refused  ` +
      `p50 ${percentile(timings, 0.5).toFixed(1)} ms  ` +
      `p95 ${percentile(timings, 0.95).toFixed(1)} ms  ` +
      `p99 ${percentile(timings, 0.99).toFixed(1)} ms  ` +
      `${rate.toFixed(0)}/s`,
  );
  return { name, answers: timings.length, refused };
}

/// A whole sign-in: the authorization endpoint opens it, the password is
/// answered, and the code is exchanged. The heaviest path a person walks.
async function wholeLogin() {
  return consoleLogin(
    { realm: REALM, client: CLIENT, redirect: REDIRECT, username: "ada", password: PASSWORD },
    BASE,
  );
}

async function main() {
  act("bring the rig up");
  await compose("down", "-v", "--remove-orphans");
  await compose("up", "-d");
  await waitFor("saffui to be ready", async () => (await fetch(`${OPS}/readyz`)).ok);

  act("check each path answers once before it is driven");
  const discovered = await fetch(`${BASE}/realms/${REALM}/.well-known/openid-configuration`);
  assert.equal(discovered.status, 200, `discovery refused: ${await discovered.text()}`);
  const tokens = await wholeLogin();
  const claimed = await fetch(`${BASE}/realms/${REALM}/protocol/openid-connect/userinfo`, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  assert.equal(claimed.status, 200, `userinfo refused: ${await claimed.text()}`);

  act(`drive each path for ${SECONDS}s with ${WORKERS} workers`);
  const before = await requestsCounted();
  const driven = [];
  driven.push(
    await drive("a whole sign-in", async () => Boolean((await wholeLogin()).access_token)),
  );
  driven.push(
    await drive("discovery", async () => {
      const answer = await fetch(`${BASE}/realms/${REALM}/.well-known/openid-configuration`);
      return answer.ok;
    }),
  );
  driven.push(
    await drive("a person's claims", async () => {
      const answer = await fetch(`${BASE}/realms/${REALM}/protocol/openid-connect/userinfo`, {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      });
      return answer.ok;
    }),
  );
  const after = await requestsCounted();

  act("what the plane counted for itself");
  if (before === null || after === null) {
    console.log("    the operations port served no requests_total counter to read");
  } else {
    const drivenCount = driven.reduce((held, path) => held + path.answers + path.refused, 0);
    console.log(
      `    the plane counted ${(after - before).toFixed(0)} requests, the harness drove ${drivenCount}`,
    );
  }

  act("what the rig may assert");
  for (const path of driven) {
    assert.ok(path.answers > 0, `${path.name} answered nothing`);
    assert.equal(path.refused, 0, `${path.name} refused ${path.refused} times`);
  }
  console.log("\nevery path answered, none refused. These numbers are this machine's, not a deployment's.");
}

try {
  await main();
} catch (refused) {
  console.error(`\nthe bench stopped: ${refused.message}`);
  try {
    console.error(await compose("ps", "--all"));
    console.error(await compose("logs", "--tail", "40", "saffui"));
  } catch {
    // The rig may be down already; the first error is the one that matters.
  }
  process.exitCode = 1;
} finally {
  if (KEEP) {
    console.log(`\nthe rig stays up: ${BASE} for the plane, ${OPS} for its operations port`);
  } else {
    await compose("down", "-v", "--remove-orphans").catch(() => {});
  }
}
