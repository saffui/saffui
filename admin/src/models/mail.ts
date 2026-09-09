/// Mirrors `server::api::rest::endpoints::admin::mail::MailBrief`.
export interface MailBrief {
  host: string;
  port: number;
  from_address: string;
  from_name: string | null;
  reply_to: string | null;
  implicit_tls: boolean;
  has_password: boolean;
  username: string | null;
}

/// Mirrors `admin::mail::MailWrite`. An absent password keeps the held one.
export interface MailWrite {
  host: string;
  port: number;
  from_address: string;
  from_name: string;
  reply_to: string | null;
  implicit_tls: boolean;
  username: string | null;
  password: string | null;
}

/// What the probe saw, and only that. Every field is absent where the relay
/// did not answer it, so the screen leaves a row out rather than printing a
/// reading nobody took.
export interface RelayReport {
  reached_in_millis: number | null;
  tls_version: string | null;
  cipher: string | null;
  certificate_until: string | null;
  certificate_issuer: string | null;
  max_message_bytes: number | null;
  auth_offered: string[];
  /// The dialogue as it happened. An AUTH line carries the command and the
  /// username, never the credential.
  transcript: string[];
  refused: string | null;
}

/// One message this realm could not deliver.
export interface MailRefusal {
  recipient: string;
  purpose: string;
  attempted_at: string;
  detail: string | null;
}
