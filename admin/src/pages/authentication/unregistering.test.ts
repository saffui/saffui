import { describe, expect, test } from "vitest";
import type { RequiredActionRow } from "@/models/flows";
import { countUnregistering, warnsOfUnregistering } from "./unregistering";

const TOTP: RequiredActionRow = {
  action_id: "ra-1",
  provider_id: "totp",
  action: "configure-totp",
  name: "configure-totp",
  display_name: "Configure authenticator app",
  description: "",
  enabled: true,
  default_action: false,
  on_time_action: null,
  priority: 10,
};
const words = (key: string) => `<${key}>`;

describe("unregistering a realm's required action", () => {
  test("counts what goes with its row: offered, on at birth, and its priority", () => {
    expect(countUnregistering(TOTP, words)).toEqual([
      { value: "<actions-fact-on>", label: "<actions-col-enabled>" },
      { value: "<actions-fact-off>", label: "<actions-col-birth>" },
      { value: "10", label: "<flow-priority>" },
    ]);
    expect(countUnregistering({ ...TOTP, priority: null }, words)[2]?.value).toBe("0");
  });

  test("warns only where the realm had turned the action off", () => {
    expect(warnsOfUnregistering({ ...TOTP, enabled: false })).toBe(true);
    expect(warnsOfUnregistering(TOTP)).toBe(false);
    expect(warnsOfUnregistering({ ...TOTP, enabled: null })).toBe(false);
  });
});
