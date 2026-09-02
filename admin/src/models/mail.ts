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
