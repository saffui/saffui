import { describe, expect, test } from "vitest";
import {
  composeApiPath,
  composeConsoleBase,
  composeReturnUri,
  composeThemePath,
  readRealm,
} from "./place";

describe("where the console is", () => {
  test("reads the realm off a console address at any depth", () => {
    expect(readRealm("/realms/main/account")).toBe("main");
    expect(readRealm("/realms/main/account/")).toBe("main");
    expect(readRealm("/realms/main/account/login/return")).toBe("main");
    expect(readRealm("/realms/a%20b/account/profile")).toBe("a b");
  });

  test("reads no realm off an address that is not a console's", () => {
    for (const elsewhere of [
      "/",
      "/account/",
      "/realms/main",
      "/realms/main/account-api/v1/me",
      "/realms/main/accounts",
      "/console/main/profile",
      "/realms/%E0%A4%A/account/",
    ]) {
      expect(readRealm(elsewhere), elsewhere).toBeNull();
    }
  });

  test("composes the realm's console, its return, its API and its look", () => {
    expect(composeConsoleBase("a b")).toBe("/realms/a%20b/account/");
    expect(composeReturnUri("https://id.example", "main")).toBe(
      "https://id.example/realms/main/account/login/return",
    );
    expect(composeApiPath("main", "me")).toBe("/realms/main/account-api/v1/me");
    expect(composeThemePath("main")).toBe("/realms/main/protocol/openid-connect/theme.css");
  });
});
