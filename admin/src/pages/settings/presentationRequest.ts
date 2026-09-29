import type { PresentationStanding } from "@/models/presentations";

export type PresentationFormat = "dc+sd-jwt" | "ldp_vc";

/// What the page asks a wallet for: one credential of one format, its types
/// and its claims as they were typed.
export interface PresentationDraft {
  format: PresentationFormat;
  /// One type per line: SD-JWT VC types, or JSON-LD types expanded.
  types: string;
  /// One claim per line, its members joined by dots.
  claims: string;
}

/// Where a request stands: what its answer came to, or `expired` for one no
/// answer reached within its window.
export type PresentationStatus = PresentationStanding["status"] | "expired";

/// The lines typed, trimmed, blank ones let go.
export function readLines(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

/// The DCQL query for the one credential a draft names. A JSON-LD credential
/// must hold every type listed; an SD-JWT VC may be of any of them.
export function buildPresentationQuery(draft: PresentationDraft): Record<string, unknown> {
  const types = readLines(draft.types);
  const claims = readLines(draft.claims).map((line) => ({
    path: line.split(".").map((member) => member.trim()),
  }));
  return {
    credentials: [
      {
        id: "credential",
        format: draft.format,
        meta: draft.format === "ldp_vc" ? { type_values: [types] } : { vct_values: types },
        ...(claims.length ? { claims } : {}),
      },
    ],
  };
}

export function readStatus(standing: PresentationStanding, now: Date): PresentationStatus {
  const lapsed = new Date(standing.expires_at).getTime() <= now.getTime();
  return standing.status === "pending" && lapsed ? "expired" : standing.status;
}
