#!/usr/bin/env node
// Proves the telemetry plane whole, from the outside: one login driven
// under one W3C trace lands as one trace in Jaeger spanning authorize,
// login and token; an admin write made under another trace is joinable
// from Jaeger to the audit journal on the same id; Prometheus holds the
// request families; and the journal still verifies.
//
//   docker build -t saffui:local .
//   node deploy/observability/harness.mjs [--keep]

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { login } from "../lib/console.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const COMPOSE = join(here, "compose.yaml");
const SAFFUI = "http://localhost:38080";
const OPS = "http://localhost:38081";
const JAEGER = "http://localhost:36686";
const PROMETHEUS = "http://localhost:39090";
const REALM = "main";
const KEEP = process.argv.includes("--keep");

const WHO = {
  realm: REALM,
  client: "saffui-console",
  redirect: "http://localhost:38080/console/login/return",
  username: "ada",
  password: "a-password-of-decent-length",
};

const doExec = promisify(execFile);
async function sh(command, args) {
  const { stdout } = await doExec(command, args, { maxBuffer: 64 * 1024 * 1024 });
  return stdout.trim();
}
const compose = (...args) => sh("docker", ["compose", "-f", COMPOSE, ...args]);
const psql = (sql) =>
  compose("exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "saffui", "-tAc", sql);

let step = 0;
function act(title) {
  step += 1;
  console.log(`\n[${step}] ${title}`);
}

async function waitFor(label, check, timeoutMs = 60_000, everyMs = 500) {
  const until = Date.now() + timeoutMs;
  for (;;) {
    let outcome;
    try {
      outcome = await check();
    } catch {
      outcome = false;
    }
    if (outcome) {
      return outcome;
    }
    if (Date.now() > until) {
      throw new Error(`waited ${timeoutMs}ms in vain for ${label}`);
    }
    await sleep(everyMs);
  }
}

/// A parent nobody minted: a fresh trace id the server must join, sampled.
function traceparent() {
  const trace = randomBytes(16).toString("hex");
  return { trace, header: `00-${trace}-${randomBytes(8).toString("hex")}-01` };
}

async function spansOf(trace) {
  const asked = await fetch(`${JAEGER}/api/traces/${trace}`);
  if (!asked.ok) {
    return [];
  }
  const body = await asked.json();
  return (body.data ?? []).flatMap((held) => held.spans ?? []);
}

async function main() {
  act("a clean slate, then the whole stack");
  await sh("docker", ["image", "inspect", "saffui:local"]).catch(() => {
    throw new Error("no saffui:local image; build it first: docker build -t saffui:local .");
  });
  await compose("down", "-v", "--remove-orphans");
  await compose("up", "-d");
  await waitFor("saffui to be ready", async () => (await fetch(`${OPS}/readyz`)).ok, 120_000);
  await waitFor("jaeger to answer", async () => (await fetch(`${JAEGER}/`)).ok, 60_000);
  await waitFor("prometheus to be ready", async () => (await fetch(`${PROMETHEUS}/-/ready`)).ok, 60_000);

  act("one login, driven under one caller trace");
  const walked = traceparent();
  const bearer = (
    await login({ ...WHO, headers: { traceparent: walked.header } }, SAFFUI)
  ).access_token;

  act("one admin write, under a trace of its own");
  const written = traceparent();
  const created = await fetch(`${SAFFUI}/admin/realms/${REALM}/users`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bearer}`,
      "content-type": "application/json",
      traceparent: written.header,
    },
    body: JSON.stringify({ user_name: "traced-person" }),
  });
  assert.equal(created.status, 201, await created.text());

  act("jaeger holds the login as one trace across its three doors");
  const loginSpans = await waitFor(
    "the login trace to arrive",
    async () => {
      const spans = await spansOf(walked.trace);
      return spans.length >= 3 ? spans : false;
    },
    60_000,
  );
  const doors = loginSpans
    .flatMap((span) => span.tags ?? [])
    .filter((tag) => tag.key === "route")
    .map((tag) => String(tag.value));
  for (const door of [
    "/realms/{realm}/protocol/openid-connect/auth",
    "/realms/{realm}/protocol/openid-connect/login",
    "/realms/{realm}/protocol/openid-connect/token",
  ]) {
    assert.ok(doors.includes(door), `the trace is missing ${door}: ${doors.join(", ")}`);
  }
  console.log(`    ${loginSpans.length} spans, all three doors, one trace`);

  act("the journal row and the jaeger trace join on one id");
  const journalled = await waitFor(
    "the write to be journalled under its trace",
    async () =>
      (await psql(
        `SELECT count(*) FROM audit_events WHERE trace_id = '${written.trace}' AND kind = 'admin.write'`,
      )) === "1",
    30_000,
  );
  assert.ok(journalled);
  await waitFor(
    "the write's trace to arrive in jaeger",
    async () => (await spansOf(written.trace)).length >= 1,
    60_000,
  );
  console.log(`    audit_events.trace_id = ${written.trace} = jaeger trace`);

  act("prometheus scraped the request families");
  await waitFor(
    "the counter family to be queryable",
    async () => {
      const asked = await fetch(
        `${PROMETHEUS}/api/v1/query?query=${encodeURIComponent("saffui_http_requests_total")}`,
      );
      if (!asked.ok) {
        return false;
      }
      const body = await asked.json();
      return body.status === "success" && (body.data?.result?.length ?? 0) > 0;
    },
    60_000,
  );

  act("the journal verifies whole");
  const verified = await fetch(`${SAFFUI}/admin/realms/${REALM}/journal/verify`, {
    headers: { authorization: `Bearer ${bearer}` },
  });
  const chain = await verified.json();
  assert.equal(verified.status, 200, JSON.stringify(chain));
  assert.equal(chain.holds, true, JSON.stringify(chain));

  console.log("\nthe plane holds: one id joins the log, the trace and the journal");
}

main()
  .then(async () => {
    if (!KEEP) {
      await compose("down", "-v", "--remove-orphans");
    }
    process.exit(0);
  })
  .catch(async (why) => {
    console.error(`\nTHE RIG FAILED: ${why?.stack ?? why}`);
    try {
      console.error("\n--- compose ps ---");
      console.error(await compose("ps", "--all"));
      console.error("\n--- last words of saffui ---");
      console.error(await compose("logs", "--tail", "30", "saffui"));
    } catch {
      // Diagnostics are best effort; the failure above is the story.
    }
    if (!KEEP) {
      await compose("down", "-v", "--remove-orphans").catch(() => {});
    }
    process.exit(1);
  });
