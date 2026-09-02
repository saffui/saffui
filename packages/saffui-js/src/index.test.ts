import { describe, expect, it } from "vitest";
import { peek, SaffuiError, Saffui } from "./index";

describe("peek", () => {
  it("reads claims without verifying, and only displays them", () => {
    const claims = { sub: "ada", preferred_username: "ada" };
    const body = Buffer.from(JSON.stringify(claims)).toString("base64url");
    expect(peek(`h.${body}.s`)).toEqual(claims);
  });
  it("throws on a token with no body to read", () => {
    expect(() => peek("not-a-token")).toThrow();
  });
});

describe("endpoints", () => {
  it("speaks the realm's own protocol paths", () => {
    const held = new Saffui({ realm: "main", clientId: "saffui-console" });
    expect(held.endpoint("token")).toBe("/realms/main/protocol/openid-connect/token");
    const away = new Saffui({ url: "https://id.example", realm: "a b", clientId: "c" });
    expect(away.endpoint("auth")).toBe(
      "https://id.example/realms/a%20b/protocol/openid-connect/auth",
    );
  });
});

describe("SaffuiError", () => {
  it("carries the protocol word beside the prose", () => {
    const refused = new SaffuiError("access_denied", "the login was refused");
    expect(refused.error).toBe("access_denied");
    expect(refused.message).toBe("the login was refused");
  });
});
