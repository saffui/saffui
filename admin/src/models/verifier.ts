/// How a realm presents itself to the wallets it asks for presentations: by
/// its did:web, or by the certificate an authority issued for its key.
export type VerifierIdentity = "did-web" | "x509-hash";

/// Where a key stands: awaiting the certificate its request asks for, or
/// serving under it.
export type VerifierKeyState = "awaiting" | "serving";

/// The subject a certificate request names, as an access certificate does.
export interface VerifierSubject {
  common_name: string;
  organization?: string | null;
  /// As EN 319 412-1 writes it.
  organization_identifier?: string | null;
  /// ISO 3166-1 alpha-2.
  country?: string | null;
}

/// Mirrors `server::api::rest::endpoints::admin::verifier::CertificateBrief`.
export interface VerifierCertificate {
  /// What the realm's requests are asked under while it serves.
  client_id: string;
  /// The subject of each certificate of the chain, leaf first.
  subjects: string[];
  /// The chain, DER, base64, leaf first, the anchor left out.
  chain: string[];
  not_before: string;
  not_after: string;
  certified_at: string;
}

/// Mirrors `VerifierKeyBrief`. The private half never leaves the server.
export interface VerifierKey {
  kid: string;
  state: VerifierKeyState;
  subject: VerifierSubject;
  /// The PKCS#10 request an authority certifies the key from, PEM.
  request: string;
  public_jwk: Record<string, unknown>;
  certificate: VerifierCertificate | null;
  created_by: string;
  created_at: string;
}

/// Mirrors `VerifierBrief`.
export interface Verifier {
  identity: VerifierIdentity;
  /// What the realm's registrar holds of it, as ETSI TS 119 472-2 sends it.
  registrar_dataset: Record<string, unknown> | null;
  /// A JWT in compact serialization.
  registration_certificate: string | null;
  updated_by: string | null;
  updated_at: string | null;
  keys: VerifierKey[];
  /// Whether the verifier these say how to present runs for the realm.
  running: boolean;
}

/// Mirrors `VerifierWrite`.
export type VerifierWrite = Pick<
  Verifier,
  "identity" | "registrar_dataset" | "registration_certificate"
>;
