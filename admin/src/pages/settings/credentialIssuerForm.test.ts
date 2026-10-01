import { describe, expect, test } from "vitest";
import type { CredentialIssuerBrief } from "@/models/credentialIssuers";
import type { TrustAnchorBrief } from "@/models/trustAnchors";
import {
  buildIssuerWrite,
  buildTrustWrite,
  emptyIssuerDraft,
  isIssuerReady,
  isTrustReady,
  nameAuthorities,
  readTrustDraft,
} from "./credentialIssuerForm";

const CERTIFIED: CredentialIssuerBrief = {
  id: "i1",
  name: "PID provider",
  issuer: "https://pid.example",
  trusted_by: "certificate",
  keys: [],
  read_from: null,
  read_at: null,
  anchors: ["a2", "gone"],
  credential_types: ["urn:eudi:mdl:1", "urn:eudi:pid:1"],
  created_by: "ada",
  created_at: "2026-10-01T09:00:00Z",
};

function anchor(id: string, subject: string): TrustAnchorBrief {
  return {
    id,
    role: "credential-issuer",
    subject,
    key_identifier: null,
    fingerprint: "",
    not_after: "2031-06-30T23:59:59Z",
    created_by: "ada",
    created_at: "2026-09-26T10:12:00Z",
    certificate: "",
  };
}

describe("the credential issuer form", () => {
  test("names an issuer by its metadata without a word of authorities", () => {
    const draft = {
      ...emptyIssuerDraft(),
      name: " Registre civil ",
      issuer: " https://certify.registre.example ",
      anchors: ["a1"],
      types: "urn:eudi:pid:1",
    };
    expect(buildIssuerWrite(draft)).toEqual({
      name: "Registre civil",
      issuer: "https://certify.registre.example",
    });
    expect(isIssuerReady(draft)).toBe(true);
    expect(isIssuerReady({ ...draft, name: " " })).toBe(false);
    expect(isIssuerReady({ ...draft, issuer: "" })).toBe(false);
  });

  test("names an issuer by certificate through authorities and for types, each once", () => {
    const draft = {
      name: "PID provider",
      issuer: "https://pid.example",
      trusted_by: "certificate" as const,
      anchors: ["a1", "a2", "a1"],
      types: "urn:eudi:pid:1\n\n urn:eudi:mdl:1 \nurn:eudi:pid:1\n",
    };
    expect(buildIssuerWrite(draft)).toEqual({
      name: "PID provider",
      issuer: "https://pid.example",
      trusted_by: "certificate",
      anchors: ["a1", "a2"],
      credential_types: ["urn:eudi:pid:1", "urn:eudi:mdl:1"],
    });
    expect(isIssuerReady(draft)).toBe(true);
    expect(isIssuerReady({ ...draft, anchors: [] })).toBe(false);
    expect(isIssuerReady({ ...draft, types: " \n" })).toBe(false);
  });

  test("changes an issuer's trust from what holds", () => {
    const draft = readTrustDraft(CERTIFIED);
    expect(draft).toEqual({ anchors: ["a2", "gone"], types: "urn:eudi:mdl:1\nurn:eudi:pid:1" });
    expect(buildTrustWrite(draft)).toEqual({
      anchors: CERTIFIED.anchors,
      credential_types: CERTIFIED.credential_types,
    });
    draft.anchors.push("a1");
    expect(CERTIFIED.anchors).toEqual(["a2", "gone"]);
    expect(isTrustReady(draft)).toBe(true);
    expect(isTrustReady({ anchors: [], types: draft.types })).toBe(false);
    expect(isTrustReady({ anchors: draft.anchors, types: "" })).toBe(false);
  });

  test("names the authorities an issuer is trusted through by their subject", () => {
    const anchors = [anchor("a1", "CN=Other Root"), anchor("a2", "CN=PID Issuer CA")];
    expect(nameAuthorities(CERTIFIED, anchors)).toEqual(["CN=PID Issuer CA", "gone"]);
    expect(nameAuthorities({ ...CERTIFIED, anchors: [] }, anchors)).toEqual([]);
  });
});
