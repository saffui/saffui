/// How a realm trusts an issuer: by the keys its metadata publishes, or by
/// the certificate chain its credentials carry.
export type IssuerTrustedBy = "metadata" | "certificate";

/// Mirrors `server::api::rest::endpoints::admin::credential_issuers::IssuerBrief`.
export interface CredentialIssuerBrief {
  id: string;
  name: string;
  /// An https address or a did:web, as the issuer's credentials name it.
  issuer: string;
  trusted_by: IssuerTrustedBy;
  /// Public keys as JWKs, each with the `kid` a credential names it by; none
  /// for an issuer trusted by certificate.
  keys: Record<string, unknown>[];
  /// Where the keys were read, and when; null by certificate.
  read_from: string | null;
  read_at: string | null;
  /// The trust anchors it is trusted through, by identifier, and the types
  /// it issues, when trusted by certificate.
  anchors: string[];
  credential_types: string[];
  created_by: string;
  created_at: string;
}

export interface CredentialIssuerList {
  /// Experimental: the issuers do nothing until the process runs the verifier.
  running: boolean;
  items: CredentialIssuerBrief[];
}

/// Mirrors `IssuerWrite`: by its metadata unless said otherwise, the
/// authorities and the types for an issuer trusted by certificate alone.
export interface CredentialIssuerWrite {
  name: string;
  issuer: string;
  trusted_by?: IssuerTrustedBy;
  anchors?: string[];
  credential_types?: string[];
}

/// Mirrors `TrustWrite`.
export interface CredentialIssuerTrustWrite {
  anchors: string[];
  credential_types: string[];
}
