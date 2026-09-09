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

/// What this realm spent on texts today, and what its brakes held back.
///
/// `cap` is absent where the realm names none: the engine carries its own,
/// and printing that here would read as this realm's setting.
export interface SmsToday {
  sent: number;
  cap: number | null;
  blocked_prefix: number;
  number_velocity: number;
  day_budget: number;
}
