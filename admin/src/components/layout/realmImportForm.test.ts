import { describe, expect, test } from "vitest";
import { realmNameFromImportDocument } from "./realmImportForm";

describe("realm import form", () => {
  test("reads names from complete and partial export shapes", () => {
    expect(realmNameFromImportDocument({ realm_id: "main" })).toBe("main");
    expect(realmNameFromImportDocument({ realm: { name: "north" } })).toBe("north");
    expect(realmNameFromImportDocument({ realm: { realm_id: "east" } })).toBe("east");
  });

  test("leaves malformed documents unnamed", () => {
    expect(realmNameFromImportDocument(null)).toBe("");
    expect(realmNameFromImportDocument({ realm: "main" })).toBe("");
  });
});
