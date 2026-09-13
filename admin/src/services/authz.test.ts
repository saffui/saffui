import { describe, expect, test } from "vitest";
import type { PolicyRow } from "@/models/authz";
import { splitPolicyRows } from "./authz";

const editors: PolicyRow = {
  policy_id: "p-editors",
  name: "editors",
  description: "",
  policy_type: "role",
  policies: [],
  resources: [],
  scopes: [],
  decision: "unanimous",
  logic: "positive",
  policy_owner: "web-dashboard",
  roles: ["editor"],
};
const gate: PolicyRow = {
  ...editors,
  policy_id: "p-gate",
  name: "edit archive",
  policy_type: "aggregated",
  policies: ["p-editors", "p-risk"],
  roles: undefined,
};

describe("the policy listing", () => {
  test("keeps each readable row whole and names each unreadable one by its id", () => {
    const listing = splitPolicyRows([
      editors,
      { policy_id: "p-risk", unreadable: true },
      gate,
      { policy_id: "p-geo", unreadable: true },
    ]);

    expect(listing).toEqual({ readable: [editors, gate], unreadable: ["p-risk", "p-geo"] });
    expect(listing.readable[1]).toBe(gate);
  });

  test("holds no unreadable id when this build reads every rule", () => {
    expect(splitPolicyRows([editors])).toEqual({ readable: [editors], unreadable: [] });
  });

  test("holds no readable row when this build reads none", () => {
    expect(splitPolicyRows([{ policy_id: "p-risk", unreadable: true }])).toEqual({
      readable: [],
      unreadable: ["p-risk"],
    });
  });
});
