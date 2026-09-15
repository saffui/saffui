import { isFreshlyAdopted, loseSignIn, readBearer } from "./session";

/// A refusal in the server's own words, with the catalogue's slug when it named one.
export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, message: string, code = "") {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/// One door to the account API: bearer attached, JSON both ways. A token the
/// server no longer takes loses the sign-in, which the console then mends or
/// explains; any other refusal is thrown in the server's words.
export async function api<T>(path: string, init?: RequestInit & { json?: unknown }): Promise<T> {
  const bearer = await readBearer();
  const headers = new Headers(init?.headers);
  headers.set("authorization", `Bearer ${bearer}`);
  let body = init?.body;
  if (init?.json !== undefined) {
    headers.set("content-type", "application/json");
    body = JSON.stringify(init.json);
  }
  const answer = await fetch(path, { ...init, headers, body });
  if (answer.status === 401) {
    loseSignIn(isFreshlyAdopted() ? "refused" : "ended");
    throw new ApiError(401, "signed out", "unauthorized");
  }
  if (!answer.ok) {
    const told = (await answer.json().catch(() => ({}))) as Record<string, unknown>;
    throw new ApiError(
      answer.status,
      String(told.message ?? answer.statusText),
      typeof told.error_code === "string" ? told.error_code : "",
    );
  }
  if (answer.status === 204) return undefined as T;
  return (await answer.json()) as T;
}
