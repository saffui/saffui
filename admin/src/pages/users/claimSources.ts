import type { ClaimSource, ClaimSourceChange } from "@/models/user";

export interface ClaimSourceDraft {
  kind: "jwt" | "endpoint";
  claims: string;
  jwt: string;
  endpoint: string;
  endpointToken: string;
}

export function emptyClaimSourceDraft(): ClaimSourceDraft {
  return { kind: "jwt", claims: "", jwt: "", endpoint: "", endpointToken: "" };
}

/// Claim names as they are typed: apart by spaces or commas, each kept once.
export function readClaimNames(typed: string): string[] {
  return [...new Set(typed.split(/[\s,]+/).filter(Boolean))];
}

/// The source as it is written: the document of its kind, and nothing of the other.
export function composeClaimSource(draft: ClaimSourceDraft): ClaimSourceChange {
  const claims = readClaimNames(draft.claims);
  if (draft.kind === "jwt") return { claims, kind: "jwt", jwt: draft.jwt.trim() };
  const token = draft.endpointToken.trim();
  return {
    claims,
    kind: "endpoint",
    endpoint: draft.endpoint.trim(),
    ...(token ? { endpoint_token: token } : {}),
  };
}

/// The typed names another source of this person already answers for. The realm
/// refuses them, since only the first source would ever speak for a name.
export function findAnsweredClaims(names: string[], standing: ClaimSource[]): string[] {
  return names.filter((name) => standing.some((source) => source.claims.includes(name)));
}

/// A source a sign-in through an identity provider keeps, replaced at each sign-in there.
export function isKeptBySignIn(source: ClaimSource): boolean {
  return source.source_id.startsWith("idp-");
}

/// What a signed document says of itself, read without checking its signature: the
/// application that receives it checks that, not the console.
export function readSignedDocument(
  jwt: string,
): { issuer: string | null; expiresAt: number | null } | null {
  const payload = jwt.split(".")[1];
  if (!payload) return null;
  try {
    const base64 = payload.replaceAll("-", "+").replaceAll("_", "/");
    const bytes = Uint8Array.from(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "=")), (held) =>
      held.charCodeAt(0),
    );
    const said = JSON.parse(new TextDecoder().decode(bytes));
    return {
      issuer: typeof said.iss === "string" ? said.iss : null,
      expiresAt: typeof said.exp === "number" ? said.exp : null,
    };
  } catch {
    return null;
  }
}
