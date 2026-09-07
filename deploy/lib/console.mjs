// The browser a harness plays: a cookie jar, PKCE, and one whole code-flow
// login as the console client. Shared by the deploy rigs, so the login they
// drive is the same one, and a rig that needs to ride extra headers (a
// traceparent, say) hands them in rather than forking the flow.

import { createHash, randomBytes } from "node:crypto";

export function cookieHeader(jar) {
  return [...jar.entries()].map(([name, value]) => `${name}=${value}`).join("; ");
}

export function drink(jar, response) {
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

export function pkce() {
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

/// One whole login. `who` says the world: realm, client, redirect, username,
/// password, and optionally `headers` to ride on every request. Opening,
/// answering and exchanging each name their base, so a login can hop
/// between instances whose state lives in one database.
export async function login(who, openAt, answerAt = openAt, tokenAt = openAt) {
  const assert = (held, said) => {
    if (!held) {
      throw new Error(said);
    }
  };
  const extra = who.headers ?? {};
  const jar = new Map();
  const { verifier, challenge } = pkce();
  const query = new URLSearchParams({
    client_id: who.client,
    redirect_uri: who.redirect,
    response_type: "code",
    scope: "openid profile admin",
    state: randomBytes(8).toString("base64url"),
    nonce: randomBytes(8).toString("base64url"),
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  const opened = await fetch(
    `${openAt}/realms/${who.realm}/protocol/openid-connect/auth?${query}`,
    { redirect: "manual", headers: { ...extra } },
  );
  drink(jar, opened);
  assert(
    jar.has("saffui_auth_session"),
    `no login opened at ${openAt}: ${opened.status} ${await opened.text()}`,
  );

  const answered = await fetch(`${answerAt}/realms/${who.realm}/protocol/openid-connect/login`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: cookieHeader(jar), ...extra },
    body: JSON.stringify({ username: who.username, password: who.password }),
    redirect: "manual",
  });
  const outcome = await answered.json();
  assert(
    outcome.status === "admitted",
    `the login answered at ${answerAt} was not admitted: ${JSON.stringify(outcome)}`,
  );
  const code = new URL(outcome.redirect_to).searchParams.get("code");
  assert(code, `no code rode the admission: ${outcome.redirect_to}`);

  const exchanged = await fetch(`${tokenAt}/realms/${who.realm}/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...extra },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: who.redirect,
      client_id: who.client,
      code_verifier: verifier,
    }),
  });
  const tokens = await exchanged.json();
  assert(exchanged.status === 200, `the exchange at ${tokenAt} refused: ${JSON.stringify(tokens)}`);
  assert(tokens.access_token, "no access token came back");
  return tokens;
}
