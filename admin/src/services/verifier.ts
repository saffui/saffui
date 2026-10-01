import { say } from "@/i18n";
import { adminPath, api } from "@/services/http";
import type {
  Verifier,
  VerifierKey,
  VerifierSubject,
  VerifierWrite,
} from "@/models/verifier";

/// How the realm presents itself to wallets, and the keys it holds to present
/// itself by a certificate.
export async function readVerifier(realm: string): Promise<Verifier> {
  return api<Verifier>(adminPath(realm, "verifier"));
}

/// By its certificate only while the realm holds one valid now.
export async function keepVerifierSettings(realm: string, asked: VerifierWrite): Promise<Verifier> {
  return api<Verifier>(adminPath(realm, "verifier"), {
    method: "PUT",
    json: asked,
    subject: say("verifier-identity-title"),
  });
}

/// Draws a key and the request an authority certifies it from.
export async function requestVerifierCertificate(
  realm: string,
  subject: VerifierSubject,
): Promise<VerifierKey> {
  return api<VerifierKey>(adminPath(realm, "verifier/keys"), {
    method: "POST",
    json: subject,
    subject: say("verifier-identity-title"),
  });
}

/// The chain an authority issued for the key awaiting it, PEM encoded.
export async function takeVerifierCertificate(realm: string, chain: string): Promise<VerifierKey> {
  return api<VerifierKey>(adminPath(realm, "verifier/certificate"), {
    method: "POST",
    json: { chain },
    subject: say("verifier-identity-title"),
  });
}

export async function withdrawVerifierKey(realm: string, kid: string): Promise<void> {
  await api<void>(adminPath(realm, `verifier/keys/${encodeURIComponent(kid)}`), {
    method: "DELETE",
    subject: say("verifier-identity-title"),
  });
}
