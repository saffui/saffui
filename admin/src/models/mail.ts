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
