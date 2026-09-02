import { useSession } from "@/stores/session";
import { say } from "@/i18n";
import { toastRefused } from "@/services/toasts";

/// Console-side hints for refusals whose server message states what happened
/// but not what to do about it. Keyed by the catalogue's error_code slug.
const HINTS: Record<string, string> = {
  forbidden: "toast-hint-forbidden",
  unauthorized: "toast-hint-unauthorized",
};

/// One door to the admin API: bearer attached, JSON both ways. A refusal is
/// thrown with the server's own words, and every failed write also lands on
/// the toast rail so the person is told even when a page swallows the throw.
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
    const message = String(told.message ?? told.detail ?? told.error ?? answer.statusText);
    const code = typeof told.error_code === "string" ? told.error_code : "";
    const refusal = new ApiError(answer.status, message, code);
    const method = (init?.method ?? "GET").toUpperCase();
    if (method !== "GET") {
      toastRefused(
        say("toast-refused", { status: answer.status }),
        message,
        code && HINTS[code] ? say(HINTS[code]) : undefined,
      );
    }
    throw refusal;
  }
  if (answer.status === 204) return undefined as T;
  return (await answer.json()) as T;
}

export class ApiError extends Error {
  status: number;
  /// The catalogue slug the server named, "" when it named none.
  code: string;
  constructor(status: number, message: string, code = "") {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function adminPath(realm: string, leaf: string): string {
  return `/admin/realms/${encodeURIComponent(realm)}/${leaf}`;
}
