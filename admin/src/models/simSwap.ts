/// Mirrors `server::api::rest::endpoints::admin::sim_swap::SimSwapBrief`. The
/// private half of the realm's key is never in here, only the public half the
/// carrier is given.
export interface SimSwapBrief {
  client_id: string;
  authorize_url: string;
  token_url: string;
  check_url: string;
  max_age_hours: number;
  when_unanswered: "send" | "hold";
  kid: string;
  public_jwk: Record<string, unknown>;
  /// Experimental: stored settings do nothing until the process runs the
  /// guard.
  running: boolean;
}

/// Mirrors `admin::sim_swap::SimSwapWrite`. The key is drawn by the server.
export interface SimSwapWrite {
  client_id: string;
  authorize_url: string;
  token_url: string;
  check_url: string;
  max_age_hours: number | null;
  when_unanswered: "send" | "hold";
}
