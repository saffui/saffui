import { describe, expect, test } from "vitest";
import type { Verifier, VerifierKey } from "@/models/verifier";
import {
  buildSubject,
  buildVerifierWrite,
  findKey,
  isCertificateValid,
  readDataset,
  readVerifierDraft,
} from "./verifierIdentityForm";

const DATASET = {
  identifier: [{ type: "http://data.europa.eu/eudi/id/VATIN", identifier: "FR12345678901" }],
  intendedUseIdentifier: "account-opening",
};

const CERTIFICATE = {
  client_id: "x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk",
  subjects: ["CN=Acme verifier", "CN=Access CA"],
  chain: ["bGVhZg==", "YWNjZXNzIGNh"],
  not_before: "2026-10-01T00:00:00Z",
  not_after: "2027-01-01T00:00:00Z",
  certified_at: "2026-10-01T08:00:00Z",
};

function key(state: VerifierKey["state"], kid: string): VerifierKey {
  return {
    kid,
    state,
    subject: { common_name: "Acme verifier" },
    request: "-----BEGIN CERTIFICATE REQUEST-----",
    public_jwk: { kty: "EC", crv: "P-256", kid },
    certificate: state === "serving" ? CERTIFICATE : null,
    created_by: "ada",
    created_at: "2026-10-01T08:00:00Z",
  };
}

describe("the verifier identity form", () => {
  test("reads the realm's settings back as the draft that wrote them", () => {
    const held: Verifier = {
      identity: "x509-hash",
      registrar_dataset: DATASET,
      registration_certificate: "h.p.s",
      updated_by: "ada",
      updated_at: "2026-10-01T08:00:00Z",
      keys: [],
      running: true,
    };
    const draft = readVerifierDraft(held);
    expect(draft).toEqual({
      identity: "x509-hash",
      dataset: JSON.stringify(DATASET, null, 2),
      registration: "h.p.s",
    });
    expect(buildVerifierWrite(draft)).toEqual({
      identity: "x509-hash",
      registrar_dataset: DATASET,
      registration_certificate: "h.p.s",
    });
    expect(
      readVerifierDraft({ ...held, identity: "did-web", registrar_dataset: null, registration_certificate: null }),
    ).toEqual({ identity: "did-web", dataset: "", registration: "" });
  });

  test("sends nothing for what was left empty, and nothing at all for a dataset that is not an object", () => {
    expect(buildVerifierWrite({ identity: "did-web", dataset: "  ", registration: " \n" })).toEqual({
      identity: "did-web",
      registrar_dataset: null,
      registration_certificate: null,
    });
    for (const written of ["[1]", "\"text\"", "{ unclosed", "null"]) {
      expect(readDataset(written), written).toBeUndefined();
      expect(buildVerifierWrite({ identity: "x509-hash", dataset: written, registration: "" }), written).toBeUndefined();
    }
  });

  test("names the subject as typed, its empty names left out and the country in capitals", () => {
    expect(
      buildSubject({
        common_name: " Acme verifier ",
        organization: "",
        organization_identifier: " VATFR-12345678901 ",
        country: "fr",
      }),
    ).toEqual({
      common_name: "Acme verifier",
      organization: null,
      organization_identifier: "VATFR-12345678901",
      country: "FR",
    });
  });

  test("finds the key serving and the one awaiting its certificate", () => {
    const keys = [key("serving", "first"), key("awaiting", "second")];
    expect(findKey(keys, "serving")?.kid).toBe("first");
    expect(findKey(keys, "awaiting")?.kid).toBe("second");
    expect(findKey([key("serving", "first")], "awaiting")).toBeUndefined();
  });

  test("holds a certificate valid from its first instant until its last one excluded", () => {
    expect(isCertificateValid(CERTIFICATE, new Date("2026-10-01T00:00:00Z"))).toBe(true);
    expect(isCertificateValid(CERTIFICATE, new Date("2026-12-31T23:59:59Z"))).toBe(true);
    expect(isCertificateValid(CERTIFICATE, new Date("2027-01-01T00:00:00Z"))).toBe(false);
    expect(isCertificateValid(CERTIFICATE, new Date("2026-09-30T23:59:59Z"))).toBe(false);
  });
});
