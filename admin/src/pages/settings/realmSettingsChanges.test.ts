import { describe, expect, test } from "vitest";
import {
  passwordlessFlowCompatible,
  sessionSettingsChanges,
  tokenSettingsChanges,
} from "./realmSettingsChanges";
import type { ExecutionRow } from "@/models/flows";

describe("realm settings boards", () => {
  const step = (
    authenticator: string,
    requirement: ExecutionRow["requirement"],
  ): ExecutionRow => ({
    execution_id: `${authenticator}-${requirement}`,
    alias: authenticator,
    flow_id: "browser",
    priority: 10,
    step: { kind: "authenticator", authenticator, config_id: null },
    requirement,
  });

  test("only offers passwordless where WebAuthn can admit by itself", () => {
    const compatible = (...executions: ExecutionRow[]) =>
      passwordlessFlowCompatible("browser", new Map([["browser", executions]]));
    expect(compatible(step("password", "required"))).toBe(false);
    expect(
      compatible(
        step("password", "alternative"),
        step("webauthn", "alternative"),
      ),
    ).toBe(true);
    expect(compatible(step("password", "required"), step("webauthn", "required"))).toBe(false);
    expect(compatible(step("webauthn", "disabled"))).toBe(false);
  });

  test("reads a nested WebAuthn path without following a flow cycle", () => {
    const nested: ExecutionRow = {
      ...step("nested", "alternative"),
      step: { kind: "sub_flow", flow_id: "passkeys" },
    };
    expect(
      passwordlessFlowCompatible(
        "browser",
        new Map([
          ["browser", [step("password", "alternative"), nested]],
          ["passkeys", [{ ...step("webauthn", "required"), flow_id: "passkeys" }]],
        ]),
      ),
    ).toBe(true);
    expect(
      passwordlessFlowCompatible(
        "browser",
        new Map([
          ["browser", [nested]],
          ["passkeys", [{ ...nested, flow_id: "passkeys", step: { kind: "sub_flow", flow_id: "browser" } }]],
        ]),
      ),
    ).toBe(false);
  });

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
