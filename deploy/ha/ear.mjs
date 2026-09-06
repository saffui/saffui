// The ear: a SCIM-shaped far side that counts. It plays the provisioned
// application the outbox delivers into, faithfully enough for the server's
// reconcile-then-write to behave as it would against a real one, and it
// remembers every call so the harness can assert what "exactly once" means
// from the outside: every acknowledged person created here exactly once,
// a redelivery landing as a patch and never as a second creation.
//
// It answers slowly on purpose (EAR_DELAY_MS per SCIM call), so a delivery
// pass stays open long enough for the harness to kill the instance holding
// it. `/tally` answers at once and is never delayed.

import http from "node:http";
import { setTimeout as sleep } from "node:timers/promises";

const BEARER = process.env.EAR_BEARER ?? "";
const DELAY = Number(process.env.EAR_DELAY_MS ?? "0");

/** externalId -> { id, userName, active, emails } */
const people = new Map();
/** every SCIM call, in order: { at, source, method, kind, externalId, ok } */
const calls = [];
let minted = 0;
let wrongBearer = 0;

function record(request, kind, externalId, ok) {
  calls.push({
    at: Date.now(),
    source: request.socket.remoteAddress ?? "",
    method: request.method,
    kind,
    externalId,
    ok,
  });
}

function body(request) {
  return new Promise((resolve) => {
    let held = "";
    request.on("data", (chunk) => {
      held += chunk;
    });
    request.on("end", () => {
      try {
        resolve(held ? JSON.parse(held) : {});
      } catch {
        resolve({});
      }
    });
  });
}

function answer(response, status, payload) {
  const text = payload === undefined ? "" : JSON.stringify(payload);
  response.writeHead(status, { "content-type": "application/scim+json" });
  response.end(text);
}

function tally() {
  const perExternal = {};
  const perSource = {};
  for (const call of calls) {
    if (call.externalId) {
      const held = (perExternal[call.externalId] ??= {
        creates: 0,
        patches: 0,
        deletes: 0,
        lookups: 0,
      });
      if (call.kind === "create") held.creates += 1;
      if (call.kind === "patch") held.patches += 1;
      if (call.kind === "delete") held.deletes += 1;
      if (call.kind === "lookup") held.lookups += 1;
    }
    const source = (perSource[call.source] ??= { total: 0, creates: 0 });
    source.total += 1;
    if (call.kind === "create") source.creates += 1;
  }
  return {
    held: Object.fromEntries(
      [...people.entries()].map(([externalId, person]) => [externalId, person.userName]),
    ),
    perExternal,
    perSource,
    wrongBearer,
    calls: calls.length,
    lastCallAt: calls.length ? calls[calls.length - 1].at : 0,
  };
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", "http://ear");

  // The harness's window, never delayed and never guarded.
  if (url.pathname === "/tally") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(tally()));
    return;
  }

  if (!url.pathname.startsWith("/scim/v2/")) {
    response.writeHead(404);
    response.end();
    return;
  }
  if (DELAY > 0) {
    await sleep(DELAY);
  }
  // A wrong bearer is remembered and refused: the delivery fails, retries
  // pile up, and the harness times out with the tally naming the cause.
  if (BEARER && request.headers.authorization !== `Bearer ${BEARER}`) {
    wrongBearer += 1;
    record(request, "unauthorized", "", false);
    answer(response, 401, { detail: "the bearer is not the one provisioned" });
    return;
  }

  const rest = url.pathname.slice("/scim/v2/".length);
  if (request.method === "GET" && rest === "Users") {
    const filter = url.searchParams.get("filter") ?? "";
    const matched = /externalId eq "([^"]+)"/.exec(filter);
    const externalId = matched ? matched[1] : "";
    const found = externalId ? people.get(externalId) : undefined;
    record(request, "lookup", externalId, true);
    answer(response, 200, {
      schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
      totalResults: found ? 1 : 0,
      Resources: found ? [{ id: found.id, userName: found.userName }] : [],
    });
    return;
  }
  if (request.method === "POST" && rest === "Users") {
    const asked = await body(request);
    const externalId = String(asked.externalId ?? "");
    minted += 1;
    const person = {
      id: `ear-${minted}`,
      userName: String(asked.userName ?? ""),
      active: asked.active,
      emails: asked.emails,
    };
    people.set(externalId, person);
    record(request, "create", externalId, true);
    answer(response, 201, { id: person.id, externalId });
    return;
  }
  const one = /^Users\/(.+)$/.exec(rest);
  if (one) {
    const id = decodeURIComponent(one[1]);
    const entry = [...people.entries()].find(([, person]) => person.id === id);
    const externalId = entry ? entry[0] : "";
    if (request.method === "PATCH") {
      const asked = await body(request);
      if (entry) {
        const value = asked?.Operations?.[0]?.value ?? {};
        entry[1].active = value.active ?? entry[1].active;
        entry[1].emails = value.emails ?? entry[1].emails;
      }
      record(request, "patch", externalId, Boolean(entry));
      answer(response, entry ? 200 : 404, entry ? { id } : { detail: "no such person" });
      return;
    }
    if (request.method === "DELETE") {
      if (entry) {
        people.delete(externalId);
      }
      record(request, "delete", externalId, Boolean(entry));
      answer(response, entry ? 204 : 404, entry ? undefined : { detail: "no such person" });
      return;
    }
  }
  record(request, "unhandled", "", false);
  answer(response, 400, { detail: `the ear does not speak ${request.method} ${rest}` });
});

server.listen(9999, () => {
  console.log(`the ear listens on 9999, delaying ${DELAY}ms per SCIM call`);
});
