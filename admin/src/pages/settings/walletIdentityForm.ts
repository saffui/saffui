import type { WalletIdentity, WalletIdentityWrite } from "@/models/walletIdentity";
import { buildPresentationQuery, readLines } from "./presentationRequest";
import type { PresentationDraft } from "./presentationRequest";

/// What the page says of how the realm knows people: the credential as a
/// presentation is drawn, the issuer that vouches, and the claim that
/// identifies, its members joined by dots.
export interface WalletIdentityDraft extends PresentationDraft {
  issuer: string;
  identifier: string;
}

/// The claims a draft asks for, each as it was typed.
export function listDraftClaims(draft: WalletIdentityDraft): string[] {
  return readLines(draft.claims);
}

/// The profile a draft says, its one credential asked for as a presentation
/// asks for it.
export function buildWalletIdentity(draft: WalletIdentityDraft): WalletIdentityWrite {
  const query = buildPresentationQuery(draft);
  const [credential] = query.credentials as Record<string, unknown>[];
  return {
    credential_query: { ...credential, id: "identity" },
    issuer: draft.issuer.trim(),
    identifier_path: draft.identifier
      .split(".")
      .map((member) => member.trim())
      .filter((member) => member !== ""),
  };
}

/// The draft a kept profile reads back as, so the form opens on what holds.
export function readWalletIdentityDraft(held: WalletIdentity): WalletIdentityDraft {
  const query = held.credential_query;
  const format = query.format === "dc+sd-jwt" ? "dc+sd-jwt" : "ldp_vc";
  const meta = (query.meta ?? {}) as { type_values?: string[][]; vct_values?: string[] };
  const types = format === "ldp_vc" ? (meta.type_values?.[0] ?? []) : (meta.vct_values ?? []);
  const claims = ((query.claims ?? []) as { path?: string[] }[])
    .map((claim) => (claim.path ?? []).join("."))
    .filter((claim) => claim !== "");
  return {
    format,
    types: types.join("\n"),
    claims: claims.join("\n"),
    issuer: held.issuer,
    identifier: held.identifier_path.join("."),
  };
}
