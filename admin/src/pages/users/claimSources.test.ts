import { describe, expect, test } from "vitest";
import type { ClaimSource } from "@/models/user";
import {
  composeClaimSource,
  emptyClaimSourceDraft,
  findAnsweredClaims,
  isKeptBySignIn,
  readClaimNames,
  readSignedDocument,
} from "./claimSources";

const KEPT: ClaimSource = {
  source_id: "idp-4f1c-ada",
  claims: ["email", "given_name"],
  kind: "jwt",
  jwt: "a.b.c",
  metadata: { created_by: "broker:4f1c", created_at: "2026-09-01T10:00:00Z" },
};

describe("a person's claim sources", () => {
  test("reads claim names apart by spaces or commas, each once", () => {
    expect(readClaimNames(" badge, level  badge,,rank ")).toEqual(["badge", "level", "rank"]);
    expect(readClaimNames("  ")).toEqual([]);
  });

  test("writes a signed document without an address, and an address without a document", () => {
    const draft = {
      ...emptyClaimSourceDraft(),
      claims: "badge",
      jwt: " a.b.c ",
      endpoint: " https://claims.example/ada ",
      endpointToken: " fetch-token ",
    };
    expect(composeClaimSource(draft)).toEqual({ claims: ["badge"], kind: "jwt", jwt: "a.b.c" });
    expect(composeClaimSource({ ...draft, kind: "endpoint" })).toEqual({
      claims: ["badge"],
      kind: "endpoint",
      endpoint: "https://claims.example/ada",
      endpoint_token: "fetch-token",
    });
    expect(composeClaimSource({ ...draft, kind: "endpoint", endpointToken: "  " })).toEqual({
      claims: ["badge"],
      kind: "endpoint",
      endpoint: "https://claims.example/ada",
    });
  });

  test("names the typed claims another source already answers for", () => {
    expect(findAnsweredClaims(["email", "badge"], [KEPT])).toEqual(["email"]);
    expect(findAnsweredClaims(["badge"], [KEPT])).toEqual([]);
  });

  test("tells a source a sign-in keeps from one written here", () => {
    expect(isKeptBySignIn(KEPT)).toBe(true);
    expect(isKeptBySignIn({ ...KEPT, source_id: "src-9Qm" })).toBe(false);
  });

  test("reads what a signed document says of itself, and nothing from what is not one", () => {
    expect(readSignedDocument("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlL8OpcXVpcGUiLCJleHAiOjE3OTAwMDAwMDB9.c2lnbmF0dXJl")).toEqual({
      issuer: "https://idp.example/équipe",
      expiresAt: 1790000000,
    });
    expect(readSignedDocument("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZGEifQ.c2lnbmF0dXJl")).toEqual({ issuer: null, expiresAt: null });
    expect(readSignedDocument("not-a-document")).toBeNull();
    expect(readSignedDocument("a.%%%.c")).toBeNull();
  });
});
