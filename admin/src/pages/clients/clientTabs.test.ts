import { describe, expect, test } from "vitest";
import { CLIENT_TABS, clientTabPath } from "./clientTabs";

describe("client tabs", () => {
  test("keeps agents inside the client area", () => {
    expect(CLIENT_TABS).toEqual(["clients", "agents"]);
  });

  test("escapes the realm in tab links", () => {
    expect(clientTabPath("north/east", "agents")).toBe("/north%2Feast/agents");
  });
});
