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
