import { useSession } from "@/stores/session";

/// One door to the admin API: bearer attached, JSON both ways, a refusal
/// thrown with the server's own words so pages can show them.
export async function api<T>(path: string, init?: RequestInit & { json?: unknown }): Promise<T> {
  const session = useSession();
  const bearer = await session.bearer();
  if (import.meta.env.DEV && bearer === "preview") {
    const { previewAnswer } = await import("@/services/preview");
    return previewAnswer<T>(path);
  }
  const headers = new Headers(init?.headers);
  headers.set("authorization", `Bearer ${bearer}`);
  let body = init?.body;
  if (init?.json !== undefined) {
    headers.set("content-type", "application/json");
    body = JSON.stringify(init.json);
  }
  const answer = await fetch(path, { ...init, headers, body });
  if (answer.status === 401) {
    session.signOut();
    throw new ApiError(401, "signed out");
  }
  if (!answer.ok) {
    const told = await answer.json().catch(() => ({}));
    throw new ApiError(answer.status, String(told.detail ?? told.error ?? answer.statusText));
  }
  if (answer.status === 204) return undefined as T;
  return (await answer.json()) as T;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function adminPath(realm: string, leaf: string): string {
  return `/admin/realms/${encodeURIComponent(realm)}/${leaf}`;
}
