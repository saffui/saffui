import type {
  IdpMapperMutation,
  IdpMapperRow,
  IdpMapperType,
  IdpMutation,
  IdpRow,
} from "@/models/federation";

export const ATTRIBUTE_MAPPER: IdpMapperType = "oidc-user-attribute-idp-mapper";
export const ROLE_MAPPER: IdpMapperType = "oidc-hardcoded-role-idp-mapper";

export interface OidcDraft {
  alias: string;
  displayName: string;
  description: string;
  enabled: boolean;
  trustEmail: boolean;
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  clientId: string;
  clientSecret: string;
  scope: string;
  algorithms: string;
}

export interface MapperDraft {
  name: string;
  type: IdpMapperType;
  syncMode: "import" | "force";
  claim: string;
  userAttribute: string;
  role: string;
}

export function configText(
  row: { configs: Record<string, { Str?: string } | string> | null },
  key: string,
): string {
  const held = row.configs?.[key];
  if (typeof held === "string") return held;
  return held?.Str ?? "";
}

export function emptyOidcDraft(): OidcDraft {
  return {
    alias: "",
    displayName: "",
    description: "",
    enabled: true,
    trustEmail: false,
    issuer: "",
    authorizationEndpoint: "",
    tokenEndpoint: "",
    jwksUri: "",
    clientId: "",
    clientSecret: "",
    scope: "openid profile email",
    algorithms: "RS256 ES256",
  };
}

export function oidcDraft(row: IdpRow): OidcDraft {
  return {
    alias: row.provider_id,
    displayName: row.display_name,
    description: row.description,
    enabled: row.enabled !== false,
    trustEmail: row.trust_email === true,
    issuer: configText(row, "issuer"),
    authorizationEndpoint: configText(row, "authorization_endpoint"),
    tokenEndpoint: configText(row, "token_endpoint"),
    jwksUri: configText(row, "jwks_uri"),
    clientId: configText(row, "client_id"),
    clientSecret: "",
    scope: configText(row, "scope") || "openid",
    algorithms: configText(row, "allowed_algs"),
  };
}

export function oidcMutation(draft: OidcDraft): IdpMutation {
  const alias = draft.alias.trim();
  const configs: IdpMutation["configs"] = {
    issuer: { Str: draft.issuer.trim() },
    authorization_endpoint: { Str: draft.authorizationEndpoint.trim() },
    token_endpoint: { Str: draft.tokenEndpoint.trim() },
    jwks_uri: { Str: draft.jwksUri.trim() },
    client_id: { Str: draft.clientId.trim() },
    scope: { Str: draft.scope.trim() || "openid" },
  };
  if (draft.clientSecret) configs.client_secret = { Str: draft.clientSecret };
  if (draft.algorithms.trim()) configs.allowed_algs = { Str: draft.algorithms.trim() };
  return {
    provider_id: alias,
    name: alias,
    display_name: draft.displayName.trim(),
    description: draft.description.trim(),
    enabled: draft.enabled,
    trust_email: draft.trustEmail,
    configs,
  };
}

export function emptyMapperDraft(): MapperDraft {
  return {
    name: "",
    type: ATTRIBUTE_MAPPER,
    syncMode: "import",
    claim: "",
    userAttribute: "",
    role: "",
  };
}

export function mapperDraft(row: IdpMapperRow): MapperDraft {
  return {
    name: row.name,
    type: row.mapper_type,
    syncMode: configText(row, "syncMode") === "force" ? "force" : "import",
    claim: configText(row, "claim"),
    userAttribute: configText(row, "user.attribute"),
    role: configText(row, "role"),
  };
}

export function mapperMutation(draft: MapperDraft): IdpMapperMutation {
  const configs: IdpMapperMutation["configs"] = {
    syncMode: { Str: draft.syncMode },
  };
  if (draft.type === ATTRIBUTE_MAPPER) {
    configs.claim = { Str: draft.claim.trim() };
    configs["user.attribute"] = { Str: draft.userAttribute.trim() };
  } else {
    configs.role = { Str: draft.role };
  }
  return { name: draft.name.trim(), mapper_type: draft.type, configs };
}
