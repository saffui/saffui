import { describe, expect, test } from "vitest";
import { buildWalletIdentity, listDraftClaims, readWalletIdentityDraft } from "./walletIdentityForm";

const DRAFT = {
  format: "ldp_vc" as const,
  types:
    "https://www.w3.org/2018/credentials#VerifiableCredential\nhttps://mosip.io/vocab#MOSIPVerifiableCredential",
  claims: "credentialSubject.UIN\n credentialSubject.fullName \n",
  issuer: " did:web:mosip.github.io:inji-config:collab:mock ",
  identifier: "credentialSubject.UIN",
};

describe("the wallet identity form", () => {
  test("says the credential as a presentation asks for it, and the claim that identifies", () => {
    expect(buildWalletIdentity(DRAFT)).toEqual({
      credential_query: {
        id: "identity",
        format: "ldp_vc",
        meta: {
          type_values: [
            [
              "https://www.w3.org/2018/credentials#VerifiableCredential",
              "https://mosip.io/vocab#MOSIPVerifiableCredential",
            ],
          ],
        },
        claims: [
          { path: ["credentialSubject", "UIN"] },
          { path: ["credentialSubject", "fullName"] },
        ],
      },
      issuer: "did:web:mosip.github.io:inji-config:collab:mock",
      identifier_path: ["credentialSubject", "UIN"],
    });
    expect(listDraftClaims(DRAFT)).toEqual(["credentialSubject.UIN", "credentialSubject.fullName"]);
  });

  test("reads a kept profile back as the draft that wrote it", () => {
    for (const draft of [
      DRAFT,
      {
        format: "dc+sd-jwt" as const,
        types: "urn:eudi:pid:1\nurn:eudi:pid:tg:1",
        claims: "personal_administrative_number",
        issuer: "https://issuer.example/pid",
        identifier: "personal_administrative_number",
      },
    ]) {
      const kept = {
        ...buildWalletIdentity(draft),
        updated_by: "ada",
        updated_at: "2026-09-30T10:00:00Z",
      };
      expect(buildWalletIdentity(readWalletIdentityDraft(kept))).toEqual(
        buildWalletIdentity(draft),
      );
    }
  });
});
