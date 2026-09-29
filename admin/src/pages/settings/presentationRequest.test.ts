import { describe, expect, test } from "vitest";
import type { PresentationStanding } from "@/models/presentations";
import { buildPresentationQuery, readStatus } from "./presentationRequest";

describe("a presentation request", () => {
  test("asks for a JSON-LD credential holding every type listed, and its claims", () => {
    const query = buildPresentationQuery({
      format: "ldp_vc",
      types:
        " https://www.w3.org/2018/credentials#VerifiableCredential \n\nhttps://issuer.example/vocab#IdentityCredential\n",
      claims: "credentialSubject.fullName\n credentialSubject . dateOfBirth \n",
    });
    expect(query).toEqual({
      credentials: [
        {
          id: "credential",
          format: "ldp_vc",
          meta: {
            type_values: [
              [
                "https://www.w3.org/2018/credentials#VerifiableCredential",
                "https://issuer.example/vocab#IdentityCredential",
              ],
            ],
          },
          claims: [
            { path: ["credentialSubject", "fullName"] },
            { path: ["credentialSubject", "dateOfBirth"] },
          ],
        },
      ],
    });
  });

  test("asks for an SD-JWT VC of any type listed, with no claims when none are typed", () => {
    expect(
      buildPresentationQuery({
        format: "dc+sd-jwt",
        types: "urn:eudi:pid:1\nurn:eudi:pid:de:1",
        claims: "\n  \n",
      }),
    ).toEqual({
      credentials: [
        {
          id: "credential",
          format: "dc+sd-jwt",
          meta: { vct_values: ["urn:eudi:pid:1", "urn:eudi:pid:de:1"] },
        },
      ],
    });
  });

  test("stands as its answer left it, or expired once its window closed unanswered", () => {
    const standing: PresentationStanding = {
      id: "0f0e",
      status: "pending",
      outcome: null,
      expires_at: "2026-09-29T12:05:00Z",
      answered_at: null,
      created_by: "ada",
      created_at: "2026-09-29T12:00:00Z",
    };
    const before = new Date("2026-09-29T12:04:59Z");
    const at = new Date("2026-09-29T12:05:00Z");
    expect(readStatus(standing, before)).toBe("pending");
    expect(readStatus(standing, at)).toBe("expired");
    expect(readStatus({ ...standing, status: "verified" }, at)).toBe("verified");
  });
});
