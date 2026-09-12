import { describe, expect, test } from "vitest";
import { sessionSettingsChanges, tokenSettingsChanges } from "./realmSettingsChanges";

describe("realm settings boards", () => {
  test("keeps remember-me with the session settings", () => {
    expect(
      sessionSettingsChanges({
        session_max_lifespan: "28800",
        offline_session_lifespan: "2592000",
        offline_session_max_lifespan: 0,
        max_offline_grants: 5,
        access_code_lifespan_login: "900",
        access_code_lifespan_user_action: "300",
        remember_me: true,
      }),
    ).toEqual({
      session_max_lifespan: 28800,
      offline_session_lifespan: 2592000,
      offline_session_max_lifespan: 0,
      max_offline_grants: 5,
      access_code_lifespan_login: 900,
      access_code_lifespan_user_action: 300,
      remember_me: true,
    });
  });

  test("keeps refresh rotation and PAR with the token settings", () => {
    expect(
      tokenSettingsChanges({
        access_token_lifespan: "300",
        refresh_token_lifespan: "1800",
        refresh_token_max_reuse: 0,
        access_code_lifespan: 60,
        action_tokens_lifespan: "",
        device_code_lifespan: 600,
        device_poll_interval: 5,
        ciba_expiry: 300,
        ciba_interval: 5,
        revoke_refresh_token: true,
        require_pushed_authorization_requests: true,
      }),
    ).toEqual({
      access_token_lifespan: 300,
      refresh_token_lifespan: 1800,
      refresh_token_max_reuse: 0,
      access_code_lifespan: 60,
      action_tokens_lifespan: undefined,
      device_code_lifespan: 600,
      device_poll_interval: 5,
      ciba_expiry: 300,
      ciba_interval: 5,
      revoke_refresh_token: true,
      require_pushed_authorization_requests: true,
    });
  });
});
