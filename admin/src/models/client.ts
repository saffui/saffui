/// Mirrors `server::api::rest::endpoints::admin::dto::ClientBrief`.
export interface ClientBrief {
  client_id: string;
  name: string;
  enabled: boolean;
  confidential: boolean;
  root_url: string | null;
  web_origins: string[];
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  backchannel_logout_uri: string | null;
  frontchannel_logout_uri: string | null;
  description: string;
  client_uri: string | null;
  /// The grants this client holds by an operator's say-so, read back off the
  /// same keys the engines read.
  device_grant: boolean;
  token_exchange: boolean;
  ciba_delivery: string;
  ciba_notification_endpoint: string | null;
  /// The client-wide cut: tokens minted before this instant are refused.
  not_before: number | null;
  /// RFC 8705's one name, in whichever of the three forms holds it. At
  /// most one is ever set: the verifier refuses a plural bag.
  tls_san_dns: string | null;
  tls_san_uri: string | null;
  tls_subject_dn: string | null;
  key_configuration?: ClientKeyConfiguration;
  key_capabilities?: ClientKeyCapabilities;
}

export interface ClientDetail extends ClientBrief {
  key_configuration: ClientKeyConfiguration;
  key_capabilities: ClientKeyCapabilities;
}

export interface ClientEncryptionRegistration {
  alg: string;
  enc: string;
}

export interface ClientKeyConfiguration {
  authentication_method: string;
  jwks: Record<string, unknown> | null;
  jwks_uri: string | null;
  id_token_signed_response_alg: string | null;
  userinfo_signed_response_alg: string | null;
  request_object_signing_alg: string | null;
  token_endpoint_auth_signing_alg: string | null;
  id_token_encryption: ClientEncryptionRegistration | null;
  userinfo_encryption: ClientEncryptionRegistration | null;
  request_object_encryption: ClientEncryptionRegistration | null;
}

export interface ClientKeyCapabilities {
  signing_algorithms: string[];
  encryption_algorithms: string[];
  encryption_methods: string[];
}

/// Mirrors `models::entities::client::ClientScopeModel`, plus the
/// `optional` flag the attachment listing injects.
export interface ClientScope {
  client_scope_id: string;
  name: string;
  description: string;
  protocol: string;
  default_scope: boolean | null;
  optional?: boolean;
}

/// Mirrors `models::entities::client::ProtocolMapperModel`.
export interface ProtocolMapper {
  mapper_id: string;
  name: string;
  protocol: string;
  mapper_type: string;
  configs?: Record<string, unknown> | null;
}
