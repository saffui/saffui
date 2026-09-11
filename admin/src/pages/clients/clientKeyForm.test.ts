import { describe, expect, test } from "vitest";
import { clientKeyConfiguration, clientKeyDraft, responseSigningChoices } from "./clientKeyForm";
import type { ClientKeyConfiguration } from "@/models/client";

const current: ClientKeyConfiguration = {
  authentication_method: "private-key-jwt",
  jwks: null,
  jwks_uri: "https://app.example/jwks",
  id_token_signed_response_alg: "ES256",
  userinfo_signed_response_alg: null,
  request_object_signing_alg: "ES256",
  token_endpoint_auth_signing_alg: "ES256",
  id_token_encryption: { alg: "ECDH-ES", enc: "A256GCM" },
  userinfo_encryption: null,
  request_object_encryption: null,
};

describe("client key form", () => {
  test("round-trips a complete key registration", () => {
    const result = clientKeyConfiguration(clientKeyDraft(current), "private-key-jwt");

    expect(result).toEqual({ configuration: current, error: null });
  });

  test("rejects malformed inline key sets", () => {
    const draft = clientKeyDraft({ ...current, jwks_uri: null });
    draft.source = "inline";
    draft.inlineJwks = "not json";

    expect(clientKeyConfiguration(draft, "private-key-jwt").error).toBe("jwks");
  });

  test("refuses encryption without a complete pair", () => {
    const draft = clientKeyDraft(current);
    draft.userinfoEncryptionAlgorithm = "RSA-OAEP-256";

    expect(clientKeyConfiguration(draft, "private-key-jwt").error).toBe("pair");
  });

  test("clears every optional registration atomically", () => {
    const draft = clientKeyDraft(current);
    draft.source = "none";
    draft.jwksUri = "";
    draft.idTokenSigning = "";
    draft.requestObjectSigning = "";
    draft.clientAssertionSigning = "";
    draft.idTokenEncryptionAlgorithm = "";
    draft.idTokenEncryptionMethod = "";

    const result = clientKeyConfiguration(draft, "client-secret");

    expect(result.configuration).toMatchObject({
      authentication_method: "client-secret",
      jwks: null,
      jwks_uri: null,
      id_token_signed_response_alg: null,
      request_object_signing_alg: null,
      id_token_encryption: null,
    });
  });
});

describe("the algorithms a response can be signed with", () => {
  test("are the realm's own, nothing from the build's catalogue", () => {
    expect(responseSigningChoices(["ES256", "RS256"], "")).toEqual([
      { algorithm: "ES256", held: true },
      { algorithm: "RS256", held: true },
    ]);
  });

  test("keep a choice the realm no longer holds a key for, flagged", () => {
    expect(responseSigningChoices(["ES256"], "EdDSA")).toEqual([
      { algorithm: "ES256", held: true },
      { algorithm: "EdDSA", held: false },
    ]);
  });

  test("list a held choice once", () => {
    expect(responseSigningChoices(["ES256"], "ES256")).toEqual([{ algorithm: "ES256", held: true }]);
  });
});
