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
  description: string;
  client_uri: string | null;
  /// The grants this client holds by an operator's say-so, read back off the
  /// same keys the engines read.
  device_grant: boolean;
  token_exchange: boolean;
  ciba_delivery: string;
  ciba_notification_endpoint: string | null;
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
}
