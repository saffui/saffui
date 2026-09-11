import { describe, expect, test } from "vitest";
import { localeMutation, localeSelection, toggleLocale } from "./localizationForm";

const available = ["en", "fr", "de"] as const;

describe("localization form", () => {
  test("an empty backend list means every language carried by the build", () => {
    expect(localeSelection([], "fr", available)).toEqual({
      offered: ["en", "fr", "de"],
      fallback: "fr",
    });
  });

  test("removing the fallback lets negotiation use the first offered language", () => {
    const selection = toggleLocale(
      { offered: ["en", "fr", "de"], fallback: "fr" },
      "fr",
      false,
      available,
    );

    expect(selection).toEqual({ offered: ["en", "de"], fallback: "" });
  });

  test("the unrestricted selection keeps the compact backend representation", () => {
    expect(
      localeMutation({ offered: ["en", "fr", "de"], fallback: "de" }, available),
    ).toEqual({ supported_locales: [], default_locale: "de" });
  });

  test("unknown languages never reach the backend", () => {
    expect(
      localeMutation({ offered: ["en", "xx"], fallback: "xx" }, available),
    ).toEqual({ supported_locales: ["en"], default_locale: "" });
  });
});
