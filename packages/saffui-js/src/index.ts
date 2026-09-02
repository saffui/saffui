// The browser client for saffui: the OAuth code flow with PKCE, spelled out
// once and owned. No dependencies; tokens live where the caller puts them,
// which should be memory.

export interface SaffuiConfig {
  /// The server's origin, e.g. "https://id.example". Empty means same origin.
  url?: string;
  realm: string;
  clientId: string;
}

export interface Tokens {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in: number;
  token_type: string;
  scope?: string;
}

export interface LoginAsked {
  redirectUri: string;
  scope?: string;
  /// Extra authorize parameters: organization, ui_locales, acr_values, prompt.
  extra?: Record<string, string>;
}

const STATE_KEY = "saffui-js-login";

export class Saffui {
  private held: SaffuiConfig;

  constructor(config: SaffuiConfig) {
    this.held = config;
  }

  endpoint(leaf: string): string {
    const base = this.held.url ?? "";
    return `${base}/realms/${encodeURIComponent(this.held.realm)}/protocol/openid-connect/${leaf}`;
  }

  /// Send the browser to the realm's sign-in. Resolves never in practice:
  /// the page navigates away.
  async login(asked: LoginAsked): Promise<void> {
    const { verifier, challenge } = await pkce();
    const state = base64url(crypto.getRandomValues(new Uint8Array(16)));
    sessionStorage.setItem(
      STATE_KEY,
      JSON.stringify({ verifier, state, redirectUri: asked.redirectUri }),
    );
    const query = new URLSearchParams({
      client_id: this.held.clientId,
      redirect_uri: asked.redirectUri,
      response_type: "code",
      scope: asked.scope ?? "openid",
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
      ...asked.extra,
    });
    location.assign(`${this.endpoint("auth")}?${query}`);
  }

  /// Read the answer the redirect carried back and redeem the code. Call on
  /// the page `redirectUri` names, with that page's query.
  async handleRedirect(query: URLSearchParams): Promise<Tokens> {
    const kept = sessionStorage.getItem(STATE_KEY);
    sessionStorage.removeItem(STATE_KEY);
    if (!kept) throw new SaffuiError("no_login", "no login is in progress here");
    const { verifier, state, redirectUri } = JSON.parse(kept) as {
      verifier: string;
      state: string;
      redirectUri: string;
    };
    if (query.get("state") !== state) {
      throw new SaffuiError("state_mismatch", "the answer is not this login's");
    }
    const code = query.get("code");
    if (!code) {
      throw new SaffuiError(query.get("error") ?? "access_denied", "the login was refused");
    }
    return this.grant({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    });
  }

  /// Trade a refresh token for a fresh set; throws when the server says no,
  /// which is the moment to sign in again.
  async renew(refreshToken: string): Promise<Tokens> {
    return this.grant({ grant_type: "refresh_token", refresh_token: refreshToken });
  }

  /// End the server-side session this browser holds.
  async logout(idTokenHint?: string): Promise<void> {
    const query = new URLSearchParams();
    if (idTokenHint) query.set("id_token_hint", idTokenHint);
    await fetch(`${this.endpoint("logout")}?${query}`, { credentials: "include" });
  }

  private async grant(form: Record<string, string>): Promise<Tokens> {
    const answer = await fetch(this.endpoint("token"), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: this.held.clientId, ...form }),
    });
    const told = (await answer.json().catch(() => ({}))) as Record<string, unknown>;
    if (!answer.ok) {
      throw new SaffuiError(
        String(told.error ?? "server_error"),
        String(told.error_description ?? "the grant was refused"),
      );
    }
    return told as unknown as Tokens;
  }
}

export class SaffuiError extends Error {
  error: string;
  constructor(error: string, description: string) {
    super(description);
    this.error = error;
  }
}

/// The claims of a token, read without verification: a client displays them,
/// it never trusts them. Verification is the server's job.
export function peek(token: string): Record<string, unknown> {
  const body = token.split(".")[1] ?? "";
  const text = atob(body.replace(/-/g, "+").replace(/_/g, "/"));
  return JSON.parse(text) as Record<string, unknown>;
}

function base64url(bytes: Uint8Array): string {
  let held = "";
  for (const byte of bytes) held += String.fromCharCode(byte);
  return btoa(held).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function pkce(): Promise<{ verifier: string; challenge: string }> {
  const drawn = crypto.getRandomValues(new Uint8Array(32));
  const verifier = base64url(drawn);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return { verifier, challenge: base64url(new Uint8Array(digest)) };
}
