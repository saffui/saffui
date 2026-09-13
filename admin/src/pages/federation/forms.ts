import type {
  IdpMapperMutation,
  IdpMapperRow,
  IdpMapperType,
  IdpMutation,
  IdpRow,
} from "@/models/federation";

export const ATTRIBUTE_MAPPER: IdpMapperType = "oidc-user-attribute-idp-mapper";
export const ROLE_MAPPER: IdpMapperType = "oidc-hardcoded-role-idp-mapper";

export type BrokerProtocol = "oidc" | "oauth2";
export type TokenAuth = "client_secret_basic" | "client_secret_post";

export interface ProviderDraft {
  alias: string;
  displayName: string;
  description: string;
  enabled: boolean;
  trustEmail: boolean;
  protocol: BrokerProtocol;
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  userinfoEndpoint: string;
  clientId: string;
  clientSecret: string;
  scope: string;
  algorithms: string;
  tokenAuth: TokenAuth;
  pkce: boolean;
  subjectPointer: string;
  usernamePointer: string;
  emailPointer: string;
  emailVerifiedPointer: string;
  emailsEndpoint: string;
  emailsListPointer: string;
  emailsAddressPointer: string;
  emailsVerifiedPointer: string;
  emailsPrimaryPointer: string;
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

export function emptyProviderDraft(): ProviderDraft {
  return {
    alias: "",
    displayName: "",
    description: "",
    enabled: true,
    trustEmail: false,
    protocol: "oidc",
    issuer: "",
    authorizationEndpoint: "",
    tokenEndpoint: "",
    jwksUri: "",
    userinfoEndpoint: "",
    clientId: "",
    clientSecret: "",
    scope: "openid profile email",
    algorithms: "RS256 ES256",
    tokenAuth: "client_secret_basic",
    pkce: true,
    subjectPointer: "",
    usernamePointer: "",
    emailPointer: "",
    emailVerifiedPointer: "",
    emailsEndpoint: "",
    emailsListPointer: "",
    emailsAddressPointer: "/email",
    emailsVerifiedPointer: "/verified",
    emailsPrimaryPointer: "/primary",
  };
}

export function providerDraft(row: IdpRow): ProviderDraft {
  const empty = emptyProviderDraft();
  const protocol: BrokerProtocol = configText(row, "protocol") === "oauth2" ? "oauth2" : "oidc";
  return {
    alias: row.provider_id,
    displayName: row.display_name,
    description: row.description,
    enabled: row.enabled !== false,
    trustEmail: row.trust_email === true,
    protocol,
    issuer: configText(row, "issuer"),
    authorizationEndpoint: configText(row, "authorization_endpoint"),
    tokenEndpoint: configText(row, "token_endpoint"),
    jwksUri: configText(row, "jwks_uri"),
    userinfoEndpoint: configText(row, "userinfo_endpoint"),
    clientId: configText(row, "client_id"),
    clientSecret: "",
    scope: configText(row, "scope") || (protocol === "oidc" ? "openid" : ""),
    algorithms: configText(row, "allowed_algs"),
    tokenAuth:
      configText(row, "token_auth") === "client_secret_post"
        ? "client_secret_post"
        : "client_secret_basic",
    pkce: configText(row, "pkce") !== "false",
    subjectPointer: configText(row, "subject_pointer"),
    usernamePointer: configText(row, "username_pointer"),
    emailPointer: configText(row, "email_pointer"),
    emailVerifiedPointer: configText(row, "email_verified_pointer"),
    emailsEndpoint: configText(row, "emails_endpoint"),
    emailsListPointer: configText(row, "emails_list_pointer"),
    emailsAddressPointer: configText(row, "emails_address_pointer") || empty.emailsAddressPointer,
    emailsVerifiedPointer:
      configText(row, "emails_verified_pointer") || empty.emailsVerifiedPointer,
    emailsPrimaryPointer: configText(row, "emails_primary_pointer") || empty.emailsPrimaryPointer,
  };
}

export function providerMutation(draft: ProviderDraft): IdpMutation {
  const alias = draft.alias.trim();
  const configs: IdpMutation["configs"] = {
    protocol: { Str: draft.protocol },
    authorization_endpoint: { Str: draft.authorizationEndpoint.trim() },
    token_endpoint: { Str: draft.tokenEndpoint.trim() },
    client_id: { Str: draft.clientId.trim() },
    token_auth: { Str: draft.tokenAuth },
  };
  const written = (key: string, value: string) => {
    if (value.trim()) configs[key] = { Str: value.trim() };
  };
  if (draft.protocol === "oidc") {
    configs.issuer = { Str: draft.issuer.trim() };
    configs.jwks_uri = { Str: draft.jwksUri.trim() };
    configs.scope = { Str: draft.scope.trim() || "openid" };
    written("allowed_algs", draft.algorithms);
  } else {
    configs.userinfo_endpoint = { Str: draft.userinfoEndpoint.trim() };
    configs.subject_pointer = { Str: draft.subjectPointer.trim() };
    written("scope", draft.scope);
    written("username_pointer", draft.usernamePointer);
    written("email_pointer", draft.emailPointer);
    written("email_verified_pointer", draft.emailVerifiedPointer);
    if (draft.emailsEndpoint.trim()) {
      written("emails_endpoint", draft.emailsEndpoint);
      written("emails_list_pointer", draft.emailsListPointer);
      written("emails_address_pointer", draft.emailsAddressPointer);
      written("emails_verified_pointer", draft.emailsVerifiedPointer);
      written("emails_primary_pointer", draft.emailsPrimaryPointer);
    }
  }
  if (!draft.pkce) configs.pkce = { Str: "false" };
  if (draft.clientSecret) configs.client_secret = { Str: draft.clientSecret };
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
