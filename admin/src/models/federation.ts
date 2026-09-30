/// Partial mirror of `models::entities::authz::IdentityProviderModel`.
export interface IdpRow {
  internal_id: string;
  provider_id: string;
  name: string;
  display_name: string;
  description: string;
  enabled: boolean | null;
  trust_email: boolean | null;
  configs: Record<string, { Str?: string } | string> | null;
}

/// What a provider write carries, `models::entities::authz::IdentityProviderMutationModel`.
export interface IdpMutation {
  provider_id: string;
  name: string;
  display_name: string;
  description: string;
  enabled: boolean;
  trust_email: boolean;
  configs: Record<string, { Str: string }>;
}

export interface IdpMapperRow {
  mapper_id: string;
  realm_id: string;
  provider_alias: string;
  name: string;
  mapper_type: IdpMapperType;
  configs: Record<string, { Str?: string } | string> | null;
}

export type IdpMapperType =
  | "oidc-user-attribute-idp-mapper"
  | "oidc-hardcoded-role-idp-mapper"
  | "saml-user-attribute-idp-mapper"
  | "saml-role-idp-mapper";

export interface IdpMapperMutation {
  name: string;
  mapper_type: IdpMapperType;
  configs: Record<string, { Str: string }>;
}

/// What a provider does not announce that a setting here may need.
export type DiscoveryGap =
  | "no-private-key-jwt"
  | "no-assertion-algorithm"
  | "no-userinfo-encryption"
  | "no-claims-parameter"
  | "no-pkce-s256";

/// What `POST .../provider-discovery` read from an issuer's discovery document.
export interface DiscoveredProvider {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint: string | null;
  id_token_algs: string[];
  acr_values: string[];
  iss_parameter: boolean;
  /// What the provider's own key would sign assertions with: PS256, or RS256
  /// for a provider that verifies nothing else; none when it takes neither.
  assertion_alg: "PS256" | "RS256" | null;
  gaps: DiscoveryGap[];
}

/// What `POST .../identity-providers/{alias}/prove` answers: whether the
/// pipe held, how it was exercised, and the far side's words.
export interface DeliveryProof {
  proven: boolean;
  how: string;
  status: number | null;
  said: string;
}

/// Partial mirror of `models::entities::brokering::UserFederationModel`.
export interface DirectoryRow {
  alias: string;
  enabled: boolean | null;
  priority: number;
  configs: Record<string, { Str?: string } | string> | null;
}

export interface DirectoryMutation {
  enabled: boolean;
  priority: number;
  configs: Record<string, { Str: string }>;
}

export interface DirectoryImportReport {
  imported: number;
  refreshed: number;
  walked: number;
}

/// One birthright rule, as `GET .../iga/rules` says it.
export interface IgaRule {
  rule_id: string;
  when_attribute: string | null;
  when_value: string | null;
  when_expr: string | null;
  roles: string[];
  priority: number;
  enabled: boolean;
}

/// One row of a user's grant ledger, `GET .../iga/grants/{user}`.
export interface IgaGrant {
  role_id: string;
  rule_id: string | null;
  expires_at: string | null;
}
