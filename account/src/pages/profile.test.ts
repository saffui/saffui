import { describe, expect, test } from "vitest";
import { composeAddressLines, formatUpdated, listOtherFacts } from "./profile";

describe("the profile's other facts", () => {
  test("lists only what the realm holds, in reading order", () => {
    const facts = listOtherFacts({
      preferred_username: "ada",
      website: "https://ada.example",
      zoneinfo: "Africa/Lome",
      nickname: "Ada",
      address: { locality: "Lomé", country: "Togo" },
    });
    expect(facts.map((fact) => fact.value)).toEqual([
      "Ada",
      "Africa/Lome",
      "https://ada.example",
      "Lomé\nTogo",
    ]);
  });

  test("lists nothing for a person the realm knows by username alone", () => {
    expect(listOtherFacts({ preferred_username: "ada" })).toEqual([]);
  });
});

describe("an address", () => {
  test("keeps the realm's own formatting when it holds one", () => {
    expect(
      composeAddressLines({ formatted: "12 rue du Port\nLomé", locality: "ignored" }),
    ).toEqual(["12 rue du Port", "Lomé"]);
  });

  test("is composed from its parts otherwise", () => {
    expect(
      composeAddressLines({
        street_address: "12 rue du Port",
        postal_code: "01 BP 1",
        locality: "Lomé",
        country: "Togo",
      }),
    ).toEqual(["12 rue du Port", "01 BP 1 Lomé", "Togo"]);
  });

  test("is no line at all when the realm holds none", () => {
    expect(composeAddressLines()).toEqual([]);
    expect(composeAddressLines({})).toEqual([]);
  });
});

describe("the last change", () => {
  test("reads as a date in the console's tongue", () => {
    const noon = Date.UTC(2026, 8, 15, 12) / 1000;
    expect(formatUpdated(noon, "en")).toBe("September 15, 2026");
    expect(formatUpdated(noon, "fr")).toBe("15 septembre 2026");
  });
});
