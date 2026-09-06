/// Mirrors `server::api::rest::endpoints::admin::sms::SmsBrief`.
export interface SmsBrief {
  url: string;
  sender: string;
  has_token: boolean;
}

/// Mirrors `admin::sms::SmsWrite`. An absent token keeps the held one; an
/// empty one forgets it.
export interface SmsWrite {
  url: string;
  sender: string;
  token: string | null;
}
