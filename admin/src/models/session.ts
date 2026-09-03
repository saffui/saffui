/// Mirrors `server::api::rest::endpoints::admin::dto::RealmSessionBrief`.
///
/// No grants: a realm-wide listing does not pay a query per row to decorate
/// rows nobody has narrowed down yet. One login's grants are on its own page.
export interface RealmSessionBrief {
  session_id: string;
  user_id: string;
  login_username: string;
  auth_method: string | null;
  ip_address: string | null;
  browser: string | null;
  system: string | null;
  started_at: number;
  auth_time: number | null;
  expiration: number | null;
}
