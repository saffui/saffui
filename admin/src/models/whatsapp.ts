/// Mirrors `server::api::rest::endpoints::admin::whatsapp::WhatsAppBrief`. There
/// is always a token held, and it is never in here.
export interface WhatsAppBrief {
  phone_number_id: string;
  template: string;
  languages: string[];
}

/// Mirrors `admin::whatsapp::WhatsAppWrite`. An absent token keeps the held one.
export interface WhatsAppWrite {
  phone_number_id: string;
  template: string;
  languages: string[];
  token: string | null;
}
