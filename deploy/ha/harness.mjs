#!/usr/bin/env node
// Drives the two-instance rig end to end and asserts what high availability
// promises: logins land through either instance and across them, the audit
// chain two concurrent writers feed never forks, an instance killed in the
// middle of a delivery pass loses no outbox event, no event's effect lands
// twice at the far side, and a rolling restart drains before it stops.
//
//   docker build -t saffui:local .
//   node deploy/ha/harness.mjs [--keep]
//
// `--keep` leaves the stack up for a look around; without it the stack is
// torn down, volumes included, whatever the outcome.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const here = dirname(fileURLToPath(import.meta.url));
const COMPOSE = join(here, "compose.yaml");
const A = "http://localhost:18080";
const B = "http://localhost:28080";
const OPS = { [A]: "http://localhost:18081", [B]: "http://localhost:28081" };
const EAR = "http://localhost:19999";
const REALM = "main";
const CONSOLE = "saffui-console";
const REDIRECT = "http://localhost:18080/console/login/return";
const PASSWORD = process.env.SAFFUI_USER_PASSWORD ?? "a-password-of-decent-length";
const EAR_BEARER = "an-ear-bearer-of-decent-length-for-the-rig";
const KEEP = process.argv.includes("--keep");

const CREATED = 40;
const UPDATED = 10;
const DELETED = 10;
/// The connector registration plus every acknowledged mutation, which is
/// what the journal must hold at least: reads are not journalled, and
/// neither are logins.
const JOURNALLED = 1 + CREATED + UPDATED + DELETED;

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

async function waitFor(label, check, timeoutMs = 60_000, everyMs = 250) {
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

function cookieHeader(jar) {
  return [...jar.entries()].map(([name, value]) => `${name}=${value}`).join("; ");
}

function drink(jar, response) {
  for (const line of response.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = pair.indexOf("=");
    if (eq > 0) {
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (value === "") {
        jar.delete(name);
      } else {
        jar.set(name, value);
      }
    }
  }
}

function pkce() {
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

/// One whole code-flow login as the console client. Opening, answering and
/// exchanging each name their instance, so a login can hop: the state lives
/// in the one database, and the cookie is the only thing the browser carries.
async function login(openAt, answerAt = openAt, tokenAt = openAt) {
  const jar = new Map();
  const { verifier, challenge } = pkce();
  const query = new URLSearchParams({
    client_id: CONSOLE,
    redirect_uri: REDIRECT,
    response_type: "code",
    scope: "openid profile admin",
    state: randomBytes(8).toString("base64url"),
    nonce: randomBytes(8).toString("base64url"),
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  const opened = await fetch(
    `${openAt}/realms/${REALM}/protocol/openid-connect/auth?${query}`,
    { redirect: "manual" },
  );
  drink(jar, opened);
  assert.ok(
    jar.has("saffui_auth_session"),
    `no login opened at ${openAt}: ${opened.status} ${await opened.text()}`,
  );

  const answered = await fetch(`${answerAt}/realms/${REALM}/protocol/openid-connect/login`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: cookieHeader(jar) },
    body: JSON.stringify({ username: "ada", password: PASSWORD }),
    redirect: "manual",
  });
  const outcome = await answered.json();
  assert.equal(
    outcome.status,
    "admitted",
    `the login answered at ${answerAt} was not admitted: ${JSON.stringify(outcome)}`,
  );
  const code = new URL(outcome.redirect_to).searchParams.get("code");
  assert.ok(code, `no code rode the admission: ${outcome.redirect_to}`);

  const exchanged = await fetch(`${tokenAt}/realms/${REALM}/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT,
      client_id: CONSOLE,
      code_verifier: verifier,
    }),
  });
  const tokens = await exchanged.json();
  assert.equal(
    exchanged.status,
    200,
    `the exchange at ${tokenAt} refused: ${JSON.stringify(tokens)}`,
  );
  assert.ok(tokens.access_token, "no access token came back");
  return tokens;
}

async function admin(base, token, method, path, payload) {
  const response = await fetch(`${base}/admin/realms/${REALM}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(payload === undefined ? {} : { "content-type": "application/json" }),
    },
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { raw: text };
  }
  return { status: response.status, body };
}

async function tally() {
  const response = await fetch(`${EAR}/tally`);
  return response.json();
}

/// `n` jobs, at most `width` in flight: enough parallelism to actually race
/// the two writers, bounded so the harness is not the bottleneck under test.
async function pooled(jobs, width) {
  const results = new Array(jobs.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(width, jobs.length) }, async () => {
      while (next < jobs.length) {
        const mine = next++;
        results[mine] = await jobs[mine]();
      }
    }),
  );
  return results;
}

const bare = (address) => address.replace(/^::ffff:/, "");

async function ipOf(container) {
  return sh("docker", [
    "inspect",
    "-f",
    "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
    container,
  ]);
}

async function ready(base) {
  const probe = await fetch(`${OPS[base]}/readyz`).catch(() => null);
  return probe !== null && probe.status === 200;
}

/// Keep whole logins flowing against one instance until told to stop.
/// Every failure is kept with its words; zero is the only acceptable count.
function loginLoop(base) {
  const held = { ok: 0, failed: [], stop: false, done: null };
  held.done = (async () => {
    while (!held.stop) {
      try {
        await login(base);
        held.ok += 1;
      } catch (why) {
        held.failed.push(String(why));
      }
      await sleep(150);
    }
  })();
  return held;
}

/// Watch one instance being told to stop: readiness must fail while the
/// traffic port still answers, which is the drain an orchestrator needs to
/// route around a pod before it goes.
async function observeDrain(base) {
  const until = Date.now() + 20_000;
  let observed = false;
  while (Date.now() < until) {
    const [probe, traffic] = await Promise.all([
      fetch(`${OPS[base]}/readyz`).catch(() => null),
      fetch(`${base}/realms/${REALM}/protocol/openid-connect/certs`).catch(() => null),
    ]);
    if (traffic === null) {
      // The traffic port is gone: the stop completed, drained or not.
      return observed;
    }
    if (probe !== null && probe.status !== 200 && traffic.status === 200) {
      observed = true;
    }
    await sleep(100);
  }
  return observed;
}

/// One graceful stop-and-start of `service`, with logins flowing against
/// `through` the whole time: the restart is only zero-downtime if not one
/// of them fails.
async function rollOver(service, base, through) {
  const flowing = loginLoop(through);
  const drainWatch = observeDrain(base);
  await compose("stop", "-t", "30", service);
  const drained = await drainWatch;
  assert.ok(
    drained,
    `${service} stopped without draining: readiness never failed while traffic still answered`,
  );
  await compose("start", service);
  await waitFor(`${service} to be ready again`, () => ready(base), 60_000);
  flowing.stop = true;
  await flowing.done;
  assert.equal(
    flowing.failed.length,
    0,
    `logins through ${through} failed while ${service} restarted:\n${flowing.failed.join("\n")}`,
  );
  assert.ok(flowing.ok > 0, `no login flowed through ${through} during the restart`);
  console.log(`    ${service} drained, stopped, returned; ${flowing.ok} logins flowed on`);
}

async function main() {
  act("a clean slate, then the whole stack");
  await sh("docker", ["image", "inspect", "saffui:local"]).catch(() => {
    throw new Error("no saffui:local image; build it first: docker build -t saffui:local .");
  });
  await compose("down", "-v", "--remove-orphans");
  await compose("up", "-d");
  await waitFor("instance a to be ready", () => ready(A), 120_000);
  await waitFor("instance b to be ready", () => ready(B), 120_000);
  await waitFor("the ear to answer", async () => (await fetch(`${EAR}/tally`)).ok, 30_000);
  const [ipA, ipB] = await Promise.all([ipOf("saffui-ha-a"), ipOf("saffui-ha-b")]);
  console.log(`    a=${ipA} b=${ipB}`);

  act("an administrator signs in through instance a");
  const bearer = (await login(A)).access_token;
  const sanity = await admin(A, bearer, "GET", "/users?max=1");
  assert.equal(sanity.status, 200, `the admin plane refused: ${JSON.stringify(sanity.body)}`);

  act("the ear becomes the realm's provisioned application");
  const wired = await admin(A, bearer, "POST", "/identity-providers", {
    provider_id: "the-ear",
    name: "the-ear",
    display_name: "",
    description: "",
    trust_email: false,
    configs: {
      kind: { Str: "scim-outbound" },
      base_url: { Str: "http://ear:9999/scim/v2" },
      bearer: { Str: EAR_BEARER },
    },
  });
  assert.equal(wired.status, 201, `the connector was refused: ${JSON.stringify(wired.body)}`);

  act("logins land through either instance, and across them");
  await login(B);
  await login(A);
  await login(B);
  // Opened on one instance, answered on the other: the login's state lives
  // in the database, and the cookie is all the browser carries between them.
  await login(A, B);
  console.log("    four more logins: a, b, b, and one opened on a but answered by b");

  act(`${CREATED} people born through both instances at once`);
  const created = await pooled(
    Array.from({ length: CREATED }, (_, n) => async () => {
      const base = n % 2 === 0 ? A : B;
      const answered = await admin(base, bearer, "POST", "/users", {
        user_name: `ha-person-${n}`,
        email: `ha-${n}@example.test`,
        enabled: true,
      });
      assert.equal(
        answered.status,
        201,
        `person ${n} was refused at ${base}: ${JSON.stringify(answered.body)}`,
      );
      assert.ok(answered.body.user_id, `person ${n} came back without an identity`);
      return { n, user_id: answered.body.user_id };
    }),
    8,
  );

  act(`${UPDATED} corrected and ${DELETED} deleted, still through both`);
  const updated = created.slice(0, UPDATED);
  const deleted = created.slice(CREATED - DELETED);
  await pooled(
    [
      ...updated.map((person, n) => async () => {
        const base = n % 2 === 0 ? B : A;
        const answered = await admin(base, bearer, "PUT", `/users/${person.user_id}`, {
          email: `ha-${person.n}-corrected@example.test`,
        });
        assert.equal(
          answered.status,
          200,
          `the correction of ${person.user_id} was refused: ${JSON.stringify(answered.body)}`,
        );
      }),
      ...deleted.map((person, n) => async () => {
        const base = n % 2 === 0 ? A : B;
        const answered = await admin(base, bearer, "DELETE", `/users/${person.user_id}`);
        assert.ok(
          answered.status === 200 || answered.status === 204,
          `the deletion of ${person.user_id} was refused: ${answered.status}`,
        );
      }),
    ],
    8,
  );
  console.log(`    ${CREATED + UPDATED + DELETED} outbox events now owed to the ear`);

  act("one instance is killed in the middle of its delivery pass");
  await waitFor(
    "a delivery pass to be underway",
    async () => {
      const heard = await tally();
      const creates = Object.values(heard.perSource).reduce((sum, s) => sum + s.creates, 0);
      return creates >= 5;
    },
    120_000,
    150,
  );
  const midPass = await tally();
  const delivering = Object.entries(midPass.perSource)
    .map(([source, counts]) => [bare(source), counts.total])
    .filter(([source]) => source === ipA || source === ipB)
    .sort((one, other) => other[1] - one[1])[0][0];
  const victim = delivering === ipA ? "saffui-ha-a" : "saffui-ha-b";
  const victimService = delivering === ipA ? "saffui-a" : "saffui-b";
  await sh("docker", ["kill", victim]);
  const atKill = midPass.calls;
  console.log(`    ${victim} killed after ${atKill} far-side calls; the pass was not done`);
  assert.ok(
    atKill < 2 * (CREATED + UPDATED + DELETED),
    "the pass had already finished when the kill landed; the ear's delay is too short",
  );

  act("the survivor finishes what the dead instance dropped");
  await waitFor(
    "every outbox event to be delivered",
    async () => (await psql("SELECT count(*) FROM event_outbox WHERE state <> 'delivered'")) === "0",
    300_000,
    1_000,
  );
  const drainedTally = await waitFor(
    "the ear to hear nothing more",
    async () => {
      const heard = await tally();
      return Date.now() - heard.lastCallAt > 4_000 ? heard : false;
    },
    60_000,
    500,
  );

  act("the ear's count: every event landed, not one landed twice");
  assert.equal(drainedTally.wrongBearer, 0, "a delivery carried the wrong bearer");
  for (const [externalId, counts] of Object.entries(drainedTally.perExternal)) {
    assert.ok(
      counts.creates <= 1,
      `${externalId} was created ${counts.creates} times at the far side`,
    );
  }
  const gone = new Set(deleted.map((person) => person.user_id));
  for (const person of created) {
    const counts = drainedTally.perExternal[person.user_id];
    assert.ok(counts, `${person.user_id} never reached the far side`);
    assert.equal(counts.creates, 1, `${person.user_id} was created ${counts?.creates} times`);
    if (gone.has(person.user_id)) {
      assert.ok(counts.deletes >= 1, `${person.user_id} was deleted here but never there`);
      assert.ok(
        !(person.user_id in drainedTally.held),
        `${person.user_id} was deleted here but still stands there`,
      );
    } else {
      assert.ok(
        person.user_id in drainedTally.held,
        `${person.user_id} stands here but not there`,
      );
    }
  }
  for (const person of updated) {
    assert.ok(
      drainedTally.perExternal[person.user_id].patches >= 1,
      `${person.user_id} was corrected here but never there`,
    );
  }
  console.log(
    `    ${Object.keys(drainedTally.perExternal).length} people accounted for over ${drainedTally.calls} calls, exactly once each`,
  );

  act("the killed instance returns and serves");
  await compose("start", victimService);
  const victimBase = victim === "saffui-ha-a" ? A : B;
  await waitFor(`${victim} to be ready`, () => ready(victimBase), 60_000);
  await login(victimBase);

  act("a rolling restart, with logins flowing the whole time");
  await rollOver("saffui-b", B, A);
  await rollOver("saffui-a", A, B);

  act("the journal verifies from both instances, one chain, no fork");
  const freshBearer = (await login(A)).access_token;
  const [verifiedByA, verifiedByB] = await Promise.all([
    admin(A, freshBearer, "GET", "/journal/verify"),
    admin(B, freshBearer, "GET", "/journal/verify"),
  ]);
  assert.equal(verifiedByA.status, 200, JSON.stringify(verifiedByA.body));
  assert.equal(verifiedByB.status, 200, JSON.stringify(verifiedByB.body));
  assert.equal(verifiedByA.body.holds, true, `the chain broke: ${JSON.stringify(verifiedByA.body)}`);
  assert.equal(verifiedByB.body.holds, true, `the chain broke: ${JSON.stringify(verifiedByB.body)}`);
  assert.equal(
    verifiedByA.body.entries,
    verifiedByB.body.entries,
    "the two instances read different chains",
  );
  assert.ok(
    verifiedByA.body.entries >= JOURNALLED,
    `the chain holds ${verifiedByA.body.entries} entries where at least ${JOURNALLED} writes were acknowledged`,
  );
  console.log(`    ${verifiedByA.body.entries} entries, verified whole by both instances`);

  console.log(`\nthe rig holds: ${victim} died mid-pass and nothing was lost or doubled`);
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
      console.error("\n--- last words of a ---");
      console.error(await compose("logs", "--tail", "30", "saffui-a"));
      console.error("\n--- last words of b ---");
      console.error(await compose("logs", "--tail", "30", "saffui-b"));
      console.error("\n--- the ear's tally ---");
      console.error(JSON.stringify(await tally()));
    } catch {
      // Diagnostics are best effort; the failure above is the story.
    }
    if (!KEEP) {
      await compose("down", "-v", "--remove-orphans").catch(() => {});
    }
    process.exit(1);
  });
