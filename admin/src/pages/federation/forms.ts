import type {
  IdpMapperMutation,
  IdpMapperRow,
  IdpMapperType,
  IdpMutation,
  IdpRow,
} from "@/models/federation";

export const ATTRIBUTE_MAPPER: IdpMapperType = "oidc-user-attribute-idp-mapper";
export const ROLE_MAPPER: IdpMapperType = "oidc-hardcoded-role-idp-mapper";
export const SAML_ATTRIBUTE_MAPPER: IdpMapperType = "saml-user-attribute-idp-mapper";
export const SAML_ROLE_MAPPER: IdpMapperType = "saml-role-idp-mapper";

export type BrokerProtocol = "oidc" | "oauth2" | "saml";
export type TokenAuth = "client_secret_basic" | "client_secret_post";

export const PERSISTENT_NAME_ID = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

/// The name identifier formats a SAML provider can be asked for, with their labels.
export const NAME_ID_FORMATS = [
  [PERSISTENT_NAME_ID, "idp-name-id-persistent"],
  ["urn:oasis:names:tc:SAML:2.0:nameid-format:transient", "idp-name-id-transient"],
  ["urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "idp-name-id-email"],
  ["urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", "idp-name-id-unspecified"],
] as const;

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
  idpMetadata: string;
  nameIdFormat: string;
  principalAttribute: string;
  usernameAttribute: string;
  emailAttribute: string;
  spEntityId: string;
}

export interface MapperDraft {
  name: string;
  type: IdpMapperType;
  syncMode: "import" | "force";
  claim: string;
  userAttribute: string;
  role: string;
  attributeName: string;
  attributeValue: string;
  multivalued: boolean;
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
    idpMetadata: "",
    nameIdFormat: PERSISTENT_NAME_ID,
    principalAttribute: "",
    usernameAttribute: "",
    emailAttribute: "",
    spEntityId: "",
  };
}

/// The protocol a stored provider speaks, as the server reads it: OpenID Connect
/// unless the bag names another.
export function readProtocol(row: IdpRow): BrokerProtocol {
  const said = configText(row, "protocol");
  return said === "oauth2" || said === "saml" ? said : "oidc";
}

export function providerDraft(row: IdpRow): ProviderDraft {
  const empty = emptyProviderDraft();
  const protocol = readProtocol(row);
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
    idpMetadata: configText(row, "idp_metadata"),
    nameIdFormat: configText(row, "name_id_format") || empty.nameIdFormat,
    principalAttribute: configText(row, "principal_attribute"),
    usernameAttribute: configText(row, "username_attribute"),
    emailAttribute: configText(row, "email_attribute"),
    spEntityId: configText(row, "sp_entity_id"),
  };
}

export function providerMutation(draft: ProviderDraft): IdpMutation {
  const alias = draft.alias.trim();
  return {
    provider_id: alias,
    name: alias,
    display_name: draft.displayName.trim(),
    description: draft.description.trim(),
    enabled: draft.enabled,
    trust_email: draft.trustEmail,
    configs: draft.protocol === "saml" ? samlConfigs(draft) : brokerConfigs(draft),
  };
}

function brokerConfigs(draft: ProviderDraft): IdpMutation["configs"] {
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
  return configs;
}

/// A SAML provider's bag, whole: a save replaces every key, so each one it holds is
/// sent, and a blank optional one is left out rather than sent empty.
function samlConfigs(draft: ProviderDraft): IdpMutation["configs"] {
  const configs: IdpMutation["configs"] = {
    protocol: { Str: "saml" },
    idp_metadata: { Str: draft.idpMetadata.trim() },
    name_id_format: { Str: draft.nameIdFormat },
  };
  for (const [key, value] of [
    ["principal_attribute", draft.principalAttribute],
    ["username_attribute", draft.usernameAttribute],
    ["email_attribute", draft.emailAttribute],
    ["sp_entity_id", draft.spEntityId],
  ] as const) {
    if (value.trim()) configs[key] = { Str: value.trim() };
  }
  return configs;
}

/// What keeps a provider from being saved as it stands, as a message key, or
/// nothing: only what the page can tell by itself, the server checking the rest.
export function findProviderBlocker(draft: ProviderDraft): string | null {
  if (draft.protocol !== "saml") return null;
  if (!draft.idpMetadata.trim()) return "idp-saml-metadata-needed";
  const principal = draft.principalAttribute.trim();
  if (!principal && draft.nameIdFormat !== PERSISTENT_NAME_ID) return "idp-saml-principal-needed";
  if (principal && principal === draft.emailAttribute.trim()) return "idp-saml-principal-is-email";
  return null;
}

/// Where the realm describes itself to a SAML provider, for the provider to import.
export function samlMetadataAddress(origin: string, realm: string, alias: string): string {
  return `${origin}/realms/${encodeURIComponent(realm)}/broker/${encodeURIComponent(alias)}/saml/metadata`;
}

const MAPPER_LABELS: Record<IdpMapperType, string> = {
  "oidc-user-attribute-idp-mapper": "idp-mapper-attribute",
  "oidc-hardcoded-role-idp-mapper": "idp-mapper-role",
  "saml-user-attribute-idp-mapper": "idp-mapper-saml-attribute",
  "saml-role-idp-mapper": "idp-mapper-saml-role",
};

/// The message key naming a mapper type.
export function mapperTypeLabel(type: IdpMapperType): string {
  return MAPPER_LABELS[type];
}

/// The mapper types that read what a provider of this protocol sends, as the server
/// holds them: claims for OpenID Connect and OAuth 2.0, attributes for SAML, and a
/// granted role, which reads nothing, for either.
export function mapperTypesFor(protocol: BrokerProtocol): IdpMapperType[] {
  return protocol === "saml"
    ? [SAML_ATTRIBUTE_MAPPER, SAML_ROLE_MAPPER, ROLE_MAPPER]
    : [ATTRIBUTE_MAPPER, ROLE_MAPPER];
}

export function emptyMapperDraft(protocol: BrokerProtocol = "oidc"): MapperDraft {
  return {
    name: "",
    type: protocol === "saml" ? SAML_ATTRIBUTE_MAPPER : ATTRIBUTE_MAPPER,
    syncMode: "import",
    claim: "",
    userAttribute: "",
    role: "",
    attributeName: "",
    attributeValue: "",
    multivalued: false,
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
    attributeName: configText(row, "attribute.name"),
    attributeValue: configText(row, "attribute.value"),
    multivalued: ["true", "1"].includes(configText(row, "multivalued").trim().toLowerCase()),
  };
}

export function mapperMutation(draft: MapperDraft): IdpMapperMutation {
  const configs: IdpMapperMutation["configs"] = {
    syncMode: { Str: draft.syncMode },
  };
  if (draft.type === ATTRIBUTE_MAPPER) {
    configs.claim = { Str: draft.claim.trim() };
    configs["user.attribute"] = { Str: draft.userAttribute.trim() };
  } else if (draft.type === SAML_ATTRIBUTE_MAPPER) {
    configs["attribute.name"] = { Str: draft.attributeName.trim() };
    configs["user.attribute"] = { Str: draft.userAttribute.trim() };
    if (draft.multivalued) configs.multivalued = { Str: "true" };
  } else {
    if (draft.type === SAML_ROLE_MAPPER) {
      configs["attribute.name"] = { Str: draft.attributeName.trim() };
      configs["attribute.value"] = { Str: draft.attributeValue.trim() };
    }
    configs.role = { Str: draft.role };
  }
  return { name: draft.name.trim(), mapper_type: draft.type, configs };
}
