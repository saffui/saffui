/// How the realm knows people by a credential their wallet presents: mirrors
/// the answer of `server::api::rest::endpoints::admin::wallet_identity::read`.
/// The key identities are digested under never leaves the server.
export interface WalletIdentity {
  /// The one credential a login asks for, as a DCQL credential query.
  credential_query: Record<string, unknown>;
  /// The issuer that vouches for identities, one the realm names.
  issuer: string;
  /// The claim that identifies somebody, as a path of member names.
  identifier_path: string[];
  updated_by: string;
  updated_at: string;
}

export type WalletIdentityWrite = Pick<
  WalletIdentity,
  "credential_query" | "issuer" | "identifier_path"
>;
