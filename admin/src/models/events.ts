/// Mirrors what `GET /admin/realms/{realm}/sign-in-events` answers per row:
/// `store::providers::login_events::LoginEvent`, minus the detail bag.
export interface SignInEvent {
  id: number;
  recorded_at: number;
  kind: string;
  user_id: string | null;
  client_id: string | null;
  session_id: string | null;
  ip: string | null;
  user_agent: string | null;
}
