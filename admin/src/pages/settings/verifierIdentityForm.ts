import type {
  Verifier,
  VerifierCertificate,
  VerifierIdentity,
  VerifierKey,
  VerifierKeyState,
  VerifierSubject,
  VerifierWrite,
} from "@/models/verifier";

/// What the page says of how the realm presents itself: the identity, and
/// the registrar's dataset and the registration certificate as typed.
export interface VerifierDraft {
  identity: VerifierIdentity;
  dataset: string;
  registration: string;
}

/// The subject of a certificate request as typed, every name a line.
export interface SubjectDraft {
  common_name: string;
  organization: string;
  organization_identifier: string;
  country: string;
}

/// The draft the realm's settings read back as, so the form opens on what
/// holds.
export function readVerifierDraft(held: Verifier): VerifierDraft {
  return {
    identity: held.identity,
    dataset: held.registrar_dataset ? JSON.stringify(held.registrar_dataset, null, 2) : "",
    registration: held.registration_certificate ?? "",
  };
}

/// The dataset as typed: null when left empty, undefined when it is not a
/// JSON object.
export function readDataset(text: string): Record<string, unknown> | null | undefined {
  if (text.trim() === "") return null;
  try {
    const read: unknown = JSON.parse(text);
    return read !== null && typeof read === "object" && !Array.isArray(read)
      ? (read as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

/// The settings a draft says, or undefined while its dataset is not a JSON
/// object.
export function buildVerifierWrite(draft: VerifierDraft): VerifierWrite | undefined {
  const dataset = readDataset(draft.dataset);
  if (dataset === undefined) return undefined;
  const registration = draft.registration.trim();
  return {
    identity: draft.identity,
    registrar_dataset: dataset,
    registration_certificate: registration === "" ? null : registration,
  };
}

/// The subject a draft names: each name trimmed, an empty one left out, the
/// country in capitals.
export function buildSubject(draft: SubjectDraft): VerifierSubject {
  const optional = (written: string) => {
    const trimmed = written.trim();
    return trimmed === "" ? null : trimmed;
  };
  return {
    common_name: draft.common_name.trim(),
    organization: optional(draft.organization),
    organization_identifier: optional(draft.organization_identifier),
    country: optional(draft.country)?.toUpperCase() ?? null,
  };
}

/// The key of a state the realm holds, one at most.
export function findKey(keys: VerifierKey[], state: VerifierKeyState): VerifierKey | undefined {
  return keys.find((key) => key.state === state);
}

/// Whether a certificate is valid at `now`, as the server reads it: from its
/// first instant, until its last one excluded.
export function isCertificateValid(certificate: VerifierCertificate, now: Date): boolean {
  return (
    new Date(certificate.not_before).getTime() <= now.getTime() &&
    now.getTime() < new Date(certificate.not_after).getTime()
  );
}
