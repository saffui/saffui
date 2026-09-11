import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { updateClient } = await import("@/services/clients");

afterEach(() => vi.unstubAllGlobals());

describe("client key configuration transport", () => {
  test("writes the complete configuration to the escaped client resource", async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);
    const key_configuration = {
      authentication_method: "private-key-jwt",
      jwks: null,
      jwks_uri: "https://app.example/jwks",
      id_token_signed_response_alg: "ES256",
      userinfo_signed_response_alg: null,
      request_object_signing_alg: "ES256",
      token_endpoint_auth_signing_alg: "ES256",
      id_token_encryption: null,
      userinfo_encryption: null,
      request_object_encryption: null,
    };

    await updateClient("north/east", "app/mobile", { key_configuration });

    expect(fetch).toHaveBeenCalledWith(
      "/admin/realms/north%2Feast/clients/app%2Fmobile",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({ key_configuration }),
      }),
    );
  });
});
