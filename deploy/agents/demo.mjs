#!/usr/bin/env node
// What the capability rails promise, exercised against a real deployment:
// an agent is registered keyless and then deliberately keyed, mints itself
// a narrow capability token over the native MCP door, a witness resource
// server admits exactly what the token names and nothing more, attenuation
// only ever narrows, one revocation kills every minted token at once, and
// a realm switched off refuses the whole door in its own words.
//
//   docker build -t saffui:local .
//   node deploy/agents/demo.mjs [--keep]
//
// `--keep` leaves the stack up for a look around; without it the stack is
// torn down, volumes included, whatever the outcome.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { login } from "../lib/console.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const COMPOSE = join(here, "..", "local", "compose.yaml");
const BASE = "http://localhost:8080";
const OPS = "http://localhost:8081";
const WITNESS = 19080;
const REALM = "main";
const AGENT = "scribe-demo";
const PASSWORD = process.env.SAFFUI_USER_PASSWORD ?? "a-password-of-decent-length";
const WITNESS_SECRET =
  process.env.SAFFUI_CLIENT_SECRET ?? "a-conformance-client-secret-of-thirty-two-bytes-or-more";
const KEEP = process.argv.includes("--keep");

const doExec = promisify(execFile);
async function sh(command, args) {
  const { stdout } = await doExec(command, args, { maxBuffer: 16 * 1024 * 1024 });
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
    if (outcome) {
      return outcome;
    }
    if (Date.now() > until) {
      throw new Error(`waited ${timeoutMs}ms in vain for ${label}`);
    }
    await sleep(everyMs);
  }
}

async function admin(token, method, path, payload) {
  const response = await fetch(`${BASE}/admin/realms/${REALM}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(payload === undefined ? {} : { "content-type": "application/json" }),
    },
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
  const text = await response.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: response.status, body };
}

/// One JSON-RPC call at the MCP door. A tool's answer rides
/// `result.content[0].text` with `isError` saying which way it went; the
/// door's own refusals ride `error`.
async function mcp(method, params, bearer) {
  const response = await fetch(`${BASE}/realms/${REALM}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: step, method, params }),
  });
  if (response.status !== 200) {
    return { status: response.status, body: null };
  }
  return { status: 200, body: await response.json() };
}

async function minted(bearer, tool, capabilities) {
  const { status, body } = await mcp("tools/call", { name: tool, arguments: { capabilities } }, bearer);
  return { status, body, said: body?.result?.content?.[0]?.text, isError: body?.result?.isError };
}

async function introspected(token) {
  const response = await fetch(`${BASE}/realms/${REALM}/protocol/openid-connect/introspect`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      token,
      client_id: "conformance",
      client_secret: WITNESS_SECRET,
    }),
  });
  assert.equal(response.status, 200, "the introspection endpoint refused the witness");
  return response.json();
}

/// The reader's grammar, the witness's half: an exact name is admitted by
/// itself or by a prefix that covers it. The witness never widens either.
function admitted(held, wanted) {
  const prefix = held.endsWith("*") ? held.slice(0, -1) : null;
  return prefix === null ? held === wanted : wanted.startsWith(prefix);
}

/// The witness resource server: it trusts nothing but what introspection
/// tells it about the presented token, and it maps each of its doors to
/// the one tool name that opens it.
function witness() {
  const doors = {
    "GET /notes": "demo.notes.read",
    "POST /notes": "demo.notes.write",
    "DELETE /repo": "github.delete_repo",
  };
  const server = createServer(async (request, response) => {
    const wanted = doors[`${request.method} ${request.url}`];
    if (!wanted) {
      response.writeHead(404).end();
      return;
    }
    const presented = request.headers.authorization?.replace(/^Bearer /, "");
    const told = presented ? await introspected(presented) : { active: false };
    if (!told.active) {
      response.writeHead(401).end();
      return;
    }
    const held = Array.isArray(told.cap) ? told.cap : [];
    if (!held.some((one) => admitted(one, wanted))) {
      response.writeHead(403).end(JSON.stringify({ refused: wanted, actor: told.client_id }));
      return;
    }
    response
      .writeHead(200, { "content-type": "application/json" })
      .end(JSON.stringify({ opened: wanted, actor: told.client_id, chain: told.act ?? null }));
  });
  return new Promise((resolve) => server.listen(WITNESS, () => resolve(server)));
}

async function knock(method, path, bearer) {
  const response = await fetch(`http://localhost:${WITNESS}${path}`, {
    method,
    headers: bearer ? { authorization: `Bearer ${bearer}` } : {},
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

/// The switch is turned the way the console and the CLI turn it: the realm
/// read whole, the one flag changed, the realm written back.
async function turned(bearer, wanted) {
  const read = await admin(bearer, "GET", "?briefRepresentation=false");
  assert.equal(read.status, 200, `the realm could not be read: ${JSON.stringify(read.body)}`);
  const put = await admin(bearer, "PUT", "", { ...read.body, agent_exchange_enabled: wanted });
  assert.equal(put.status, 200, `the switch would not turn: ${JSON.stringify(put.body)}`);
}

async function main() {
  act("a clean slate, then the whole deployment");
  await sh("docker", ["image", "inspect", "saffui:local"]).catch(() => {
    throw new Error("no saffui:local image; build it first: docker build -t saffui:local .");
  });
  await compose("down", "-v", "--remove-orphans");
  // A fresh postgres restarts itself once while initialising, and its
  // health probe can answer inside that window; one retry outlives it.
  await compose("up", "-d").catch(async () => {
    await compose("down", "-v", "--remove-orphans");
    await compose("up", "-d");
  });
  await waitFor("the server to be ready", async () => (await fetch(`${OPS}/readyz`)).ok);

  act("an administrator signs in and turns the realm's agent surface on");
  const bearer = (
    await login(
      {
        realm: REALM,
        client: "saffui-console",
        redirect: `${BASE}/console/login/return`,
        username: "ada",
        password: PASSWORD,
      },
      BASE,
    )
  ).access_token;
  await turned(bearer, true);

  act("an agent is born whole and keyless, with a two-tool root");
  const registered = await admin(bearer, "POST", "/agents", {
    client_id: AGENT,
    capabilities: ["demo.notes.*", "github.create_issue"],
    session_seconds: 600,
  });
  assert.equal(registered.status, 201, `the birth was refused: ${JSON.stringify(registered.body)}`);
  assert.equal(registered.body.keyed, false, "registration stored a credential");
  console.log(`    ${AGENT} holds ${registered.body.capabilities.join(", ")}, keyless`);

  act("a lawless root is refused at the door, in words, leaving no trace");
  const lawless = await admin(bearer, "POST", "/agents", {
    client_id: "lawless-demo",
    capabilities: ["*"],
  });
  assert.equal(lawless.status, 422);
  assert.match(JSON.stringify(lawless.body), /grants everything/);
  const traced = await admin(bearer, "GET", "/agents/lawless-demo");
  assert.equal(traced.status, 404, "a refused registration left a half-born agent");

  act("the operator keys the agent deliberately, for this rig without platform rails");
  const keyed = await admin(bearer, "POST", `/clients/${AGENT}/secret`, {});
  assert.equal(keyed.status, 200, `the rotation refused: ${JSON.stringify(keyed.body)}`);
  const secret = keyed.body.client_secret;
  const shown = await admin(bearer, "GET", `/agents/${AGENT}`);
  assert.equal(shown.body.keyed, true, "the deliberate keying is not visible on the agent");

  act("the agent signs in as itself");
  const asked = await fetch(`${BASE}/realms/${REALM}/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: AGENT,
      client_secret: secret,
    }),
  });
  const signedIn = await asked.json();
  assert.equal(asked.status, 200, `the sign-in refused: ${JSON.stringify(signedIn)}`);

  act("the MCP door introduces itself and lists its two tools");
  const hello = await mcp("initialize", {});
  assert.equal(hello.body.result?.serverInfo?.name, "saffui", JSON.stringify(hello.body));
  const tools = await mcp("tools/list", {});
  assert.deepEqual(
    tools.body.result.tools.map((tool) => tool.name),
    ["capability.mint", "capability.attenuate"],
  );

  act("the agent mints a capability token naming exactly two tools");
  const mint = await minted(signedIn.access_token, "capability.mint", "demo.notes.read demo.notes.write");
  assert.equal(mint.isError, false, `the mint refused: ${mint.said}`);
  const cap = JSON.parse(mint.said);
  assert.ok(cap.expires_in <= 600, "the token outlives the agent's own span");
  console.log(`    minted, ${cap.expires_in}s to live`);

  act("asking outside the root refuses whole");
  const outside = await minted(signedIn.access_token, "capability.mint", "admin.everything");
  assert.equal(outside.isError, true, "a mint outside the root was granted");

  act("a witness resource server opens only what the token names");
  const ear = await witness();
  const read = await knock("GET", "/notes", cap.access_token);
  assert.equal(read.status, 200, `the witness refused a named tool: ${JSON.stringify(read.body)}`);
  assert.equal(read.body.actor, AGENT, "the witness could not name who acted");
  const write = await knock("POST", "/notes", cap.access_token);
  assert.equal(write.status, 200);
  const beyond = await knock("DELETE", "/repo", cap.access_token);
  assert.equal(beyond.status, 403, "the witness opened a door the token never named");
  console.log(`    read and write opened as ${read.body.actor}; delete refused flat`);

  act("attenuation narrows to one tool, and the act chain says who asked");
  const narrower = await minted(cap.access_token, "capability.attenuate", "demo.notes.read");
  assert.equal(narrower.isError, false, `the attenuation refused: ${narrower.said}`);
  const narrow = JSON.parse(narrower.said);
  const stillRead = await knock("GET", "/notes", narrow.access_token);
  assert.equal(stillRead.status, 200);
  assert.ok(stillRead.body.chain, "the narrowed token carries no acting chain");
  const noWrite = await knock("POST", "/notes", narrow.access_token);
  assert.equal(noWrite.status, 403, "attenuation did not narrow");

  act("asking wider than what is held refuses whole");
  const wider = await minted(narrow.access_token, "capability.attenuate", "demo.notes.*");
  assert.equal(wider.isError, true, "an attenuation widened");

  act("one revocation kills every minted token at once");
  await sleep(2000);
  const cut = await admin(bearer, "PUT", `/clients/${AGENT}`, {
    not_before: Math.floor(Date.now() / 1000),
  });
  assert.equal(cut.status, 200, `the cut refused: ${JSON.stringify(cut.body)}`);
  assert.equal((await introspected(cap.access_token)).active, false, "the minted token survived");
  assert.equal((await introspected(narrow.access_token)).active, false, "the narrowed token survived");
  assert.equal((await knock("GET", "/notes", cap.access_token)).status, 401);
  const dead = await mcp(
    "tools/call",
    { name: "capability.attenuate", arguments: { capabilities: "demo.notes.read" } },
    cap.access_token,
  );
  assert.equal(dead.status, 401, "the MCP door still admits a revoked token");

  act("off is off: the switch turned back refuses the whole door, in words");
  await turned(bearer, false);
  const refused = await mcp("initialize", {});
  assert.equal(refused.body.error?.message, "this realm does not mint capability tokens");

  ear.close();
  console.log("\nall promises held");
}

main()
  .then(async () => {
    if (!KEEP) {
      await compose("down", "-v", "--remove-orphans");
    }
    process.exit(0);
  })
  .catch(async (trouble) => {
    console.error(`\ndemo failed: ${trouble.stack ?? trouble}`);
    if (!KEEP) {
      await compose("down", "-v", "--remove-orphans").catch(() => {});
    }
    process.exit(1);
  });
