/// What an authority is trusted for. Credential issuers are the only purpose
/// today.
export type TrustAnchorRole = "credential-issuer";

/// Mirrors `server::api::rest::endpoints::admin::trust_anchors::AnchorBrief`.
export interface TrustAnchorBrief {
  id: string;
  role: TrustAnchorRole;
  subject: string;
  key_identifier: string | null;
  /// SHA-256 of the certificate, lowercase hex.
  fingerprint: string;
  not_after: string;
  created_by: string;
  created_at: string;
  /// The DER, base64.
  certificate: string;
}

export interface TrustAnchorList {
  /// Experimental: the authorities do nothing until the process runs the
  /// verifier.
  running: boolean;
  items: TrustAnchorBrief[];
}

/// Mirrors `AnchorWrite`: one certificate, PEM encoded.
export interface TrustAnchorWrite {
  role: TrustAnchorRole;
  certificate: string;
}
