import type {
  CredentialIssuerBrief,
  CredentialIssuerTrustWrite,
  CredentialIssuerWrite,
  IssuerTrustedBy,
} from "@/models/credentialIssuers";
import type { TrustAnchorBrief } from "@/models/trustAnchors";
import { readLines } from "./presentationRequest";

/// The authorities an issuer is trusted through and the types it issues, as
/// typed: the authorities by identifier, one type per line.
export interface TrustDraft {
  anchors: string[];
  types: string;
}

/// An issuer as it is being named.
export interface IssuerDraft extends TrustDraft {
  name: string;
  issuer: string;
  trusted_by: IssuerTrustedBy;
}

export function emptyIssuerDraft(): IssuerDraft {
  return { name: "", issuer: "", trusted_by: "metadata", anchors: [], types: "" };
}

/// What a trust draft says: each authority and each type once.
export function buildTrustWrite(draft: TrustDraft): CredentialIssuerTrustWrite {
  return {
    anchors: [...new Set(draft.anchors)],
    credential_types: [...new Set(readLines(draft.types))],
  };
}

/// Whether a trust draft names an authority and a type, which the server
/// asks of every issuer trusted by certificate.
export function isTrustReady(draft: TrustDraft): boolean {
  const write = buildTrustWrite(draft);
  return write.anchors.length > 0 && write.credential_types.length > 0;
}

/// The issuer a draft names. One trusted by its metadata says nothing of
/// authorities or types, which the server would refuse.
export function buildIssuerWrite(draft: IssuerDraft): CredentialIssuerWrite {
  const named = { name: draft.name.trim(), issuer: draft.issuer.trim() };
  return draft.trusted_by === "certificate"
    ? { ...named, trusted_by: "certificate", ...buildTrustWrite(draft) }
    : named;
}

export function isIssuerReady(draft: IssuerDraft): boolean {
  return (
    draft.name.trim() !== "" &&
    draft.issuer.trim() !== "" &&
    (draft.trusted_by === "metadata" || isTrustReady(draft))
  );
}

/// The draft an issuer trusted by certificate reads back as, so its trust is
/// changed from what holds.
export function readTrustDraft(named: CredentialIssuerBrief): TrustDraft {
  return { anchors: [...named.anchors], types: named.credential_types.join("\n") };
}

/// The authorities an issuer is trusted through, each by its subject, or by
/// its identifier when the realm no longer lists it.
export function nameAuthorities(named: CredentialIssuerBrief, anchors: TrustAnchorBrief[]): string[] {
  return named.anchors.map(
    (id) => anchors.find((anchor) => anchor.id === id)?.subject ?? id,
  );
}
