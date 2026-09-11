import type {
  ClientEncryptionRegistration,
  ClientKeyConfiguration,
} from "@/models/client";

export type ClientKeySource = "none" | "uri" | "inline";

export interface ClientKeyDraft {
  source: ClientKeySource;
  jwksUri: string;
  inlineJwks: string;
  idTokenSigning: string;
  userinfoSigning: string;
  requestObjectSigning: string;
  clientAssertionSigning: string;
  idTokenEncryptionAlgorithm: string;
  idTokenEncryptionMethod: string;
  userinfoEncryptionAlgorithm: string;
  userinfoEncryptionMethod: string;
  requestObjectEncryptionAlgorithm: string;
  requestObjectEncryptionMethod: string;
}

/// What a response to this client can be signed with: the realm's own active
/// algorithms, plus the one already asked for when the realm no longer holds a
/// key for it, flagged, so a choice that cannot work shows instead of vanishing.
export function responseSigningChoices(
  held: string[],
  current: string,
): { algorithm: string; held: boolean }[] {
  const choices = held.map((algorithm) => ({ algorithm, held: true }));
  return current && !held.includes(current)
    ? [...choices, { algorithm: current, held: false }]
    : choices;
}

export type ClientKeyFormResult =
  | { configuration: ClientKeyConfiguration; error: null }
  | { configuration: null; error: "jwks" | "pair" | "request-signature" | "source" };

export function clientKeyDraft(configuration: ClientKeyConfiguration): ClientKeyDraft {
  return {
    source: configuration.jwks_uri ? "uri" : configuration.jwks ? "inline" : "none",
    jwksUri: configuration.jwks_uri ?? "",
    inlineJwks: configuration.jwks ? JSON.stringify(configuration.jwks, null, 2) : "",
    idTokenSigning: configuration.id_token_signed_response_alg ?? "",
    userinfoSigning: configuration.userinfo_signed_response_alg ?? "",
    requestObjectSigning: configuration.request_object_signing_alg ?? "",
    clientAssertionSigning: configuration.token_endpoint_auth_signing_alg ?? "",
    idTokenEncryptionAlgorithm: configuration.id_token_encryption?.alg ?? "",
    idTokenEncryptionMethod: configuration.id_token_encryption?.enc ?? "",
    userinfoEncryptionAlgorithm: configuration.userinfo_encryption?.alg ?? "",
    userinfoEncryptionMethod: configuration.userinfo_encryption?.enc ?? "",
    requestObjectEncryptionAlgorithm: configuration.request_object_encryption?.alg ?? "",
    requestObjectEncryptionMethod: configuration.request_object_encryption?.enc ?? "",
  };
}

function encryption(
  algorithm: string,
  method: string,
): ClientEncryptionRegistration | null | undefined {
  if (!algorithm && !method) return null;
  if (!algorithm || !method) return undefined;
  return { alg: algorithm, enc: method };
}

export function clientKeyConfiguration(
  draft: ClientKeyDraft,
  authenticationMethod: string,
): ClientKeyFormResult {
  let jwks: Record<string, unknown> | null = null;
  const jwksUri = draft.source === "uri" ? draft.jwksUri.trim() : null;
  if (draft.source === "inline") {
    try {
      const parsed: unknown = JSON.parse(draft.inlineJwks);
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
        return { configuration: null, error: "jwks" };
      }
      jwks = parsed as Record<string, unknown>;
    } catch {
      return { configuration: null, error: "jwks" };
    }
  }

  const idTokenEncryption = encryption(
    draft.idTokenEncryptionAlgorithm,
    draft.idTokenEncryptionMethod,
  );
  const userinfoEncryption = encryption(
    draft.userinfoEncryptionAlgorithm,
    draft.userinfoEncryptionMethod,
  );
  const requestObjectEncryption = encryption(
    draft.requestObjectEncryptionAlgorithm,
    draft.requestObjectEncryptionMethod,
  );
  if (
    idTokenEncryption === undefined ||
    userinfoEncryption === undefined ||
    requestObjectEncryption === undefined
  ) {
    return { configuration: null, error: "pair" };
  }
  if (requestObjectEncryption && !draft.requestObjectSigning) {
    return { configuration: null, error: "request-signature" };
  }
  const usesClientKeys =
    authenticationMethod === "private-key-jwt" ||
    Boolean(draft.requestObjectSigning || idTokenEncryption || userinfoEncryption);
  if (usesClientKeys && !jwks && !jwksUri) {
    return { configuration: null, error: "source" };
  }

  return {
    error: null,
    configuration: {
      authentication_method: authenticationMethod,
      jwks,
      jwks_uri: jwksUri,
      id_token_signed_response_alg: draft.idTokenSigning || null,
      userinfo_signed_response_alg: draft.userinfoSigning || null,
      request_object_signing_alg: draft.requestObjectSigning || null,
      token_endpoint_auth_signing_alg: draft.clientAssertionSigning || null,
      id_token_encryption: idTokenEncryption,
      userinfo_encryption: userinfoEncryption,
      request_object_encryption: requestObjectEncryption,
    },
  };
}
