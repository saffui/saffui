/// Mirrors `server::api::rest::endpoints::admin::credential_issuers::IssuerBrief`.
export interface CredentialIssuerBrief {
  id: string;
  name: string;
  /// An https address or a did:web, as the issuer's credentials name it.
  issuer: string;
  /// Public keys as JWKs, each with the `kid` a credential names it by.
  keys: Record<string, unknown>[];
  /// Where the keys were read, and when.
  read_from: string;
  read_at: string;
  created_by: string;
  created_at: string;
}

export interface CredentialIssuerList {
  /// Experimental: the issuers do nothing until the process runs the verifier.
  running: boolean;
  items: CredentialIssuerBrief[];
}

/// Mirrors `IssuerWrite`.
export interface CredentialIssuerWrite {
  name: string;
  issuer: string;
}
