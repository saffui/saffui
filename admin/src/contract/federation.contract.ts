import { describe, expect, test } from "vitest";
import { redeliverToConnector } from "@/services/events";
import {
  createIdp,
  createIdpMapper,
  deleteIdp,
  deleteIdpMapper,
  listDirectories,
  listIdpMappers,
  listIdps,
  updateIdp,
  updateIdpMapper,
} from "@/services/federation";
import { deleteSpnego, getSpnego, putSpnego } from "@/services/negotiation";
import { keepAnswer, REALM } from "./answers";

const PROVIDER = "contract-oidc";
const HOOK = "contract-hook";

describe("federation", () => {
  test("keeps an OpenID provider with a mapper, and removes both", async () => {
    const provider = {
      provider_id: PROVIDER,
      name: PROVIDER,
      display_name: "Contract upstream",
      description: "",
      enabled: false,
      trust_email: false,
      configs: {
        issuer: { Str: "https://upstream.example.test" },
        authorization_endpoint: { Str: "https://upstream.example.test/authorize" },
        token_endpoint: { Str: "https://upstream.example.test/token" },
        jwks_uri: { Str: "https://upstream.example.test/jwks" },
        client_id: { Str: "saffui" },
        client_secret: { Str: "an-upstream-secret" },
        scope: { Str: "openid" },
      },
    };
    await keepAnswer(createIdp, REALM, provider);
    await keepAnswer(updateIdp, REALM, PROVIDER, { ...provider, display_name: "Upstream" });
    const providers = await keepAnswer(listIdps, REALM);
    expect(providers.some((held) => held.provider_id === PROVIDER)).toBe(true);

    const mapper = await keepAnswer(createIdpMapper, REALM, PROVIDER, {
      name: "department",
      mapper_type: "oidc-user-attribute-idp-mapper",
      configs: {
        syncMode: { Str: "import" },
        claim: { Str: "department" },
        "user.attribute": { Str: "department" },
      },
    });
    await keepAnswer(updateIdpMapper, REALM, PROVIDER, mapper.mapper_id, {
      name: "department",
      mapper_type: "oidc-user-attribute-idp-mapper",
      configs: {
        syncMode: { Str: "force" },
        claim: { Str: "department" },
        "user.attribute": { Str: "department" },
      },
    });
    const mappers = await keepAnswer(listIdpMappers, REALM, PROVIDER);
    expect(mappers.some((held) => held.mapper_id === mapper.mapper_id)).toBe(true);
    await deleteIdpMapper(REALM, PROVIDER, mapper.mapper_id);
    await deleteIdp(REALM, PROVIDER);
  });

  test("keeps a webhook connector and simulates a redelivery to it", async () => {
    await createIdp(REALM, {
      provider_id: HOOK,
      name: HOOK,
      display_name: "",
      description: "",
      enabled: true,
      trust_email: false,
      configs: {
        kind: { Str: "webhook" },
        url: { Str: "https://hooks.example.test/saffui" },
        filter: { Str: "user.*" },
        secret: { Str: "a-webhook-secret-of-decent-length" },
      },
    });
    const simulated = await keepAnswer(
      redeliverToConnector,
      REALM,
      HOOK,
      { fromEventId: 0 },
      { dryRun: true },
    );
    expect(simulated.dry_run).toBe(true);
    await deleteIdp(REALM, HOOK);
  });

  test("keeps a negotiation principal and forgets it, and lists directories", async () => {
    await keepAnswer(putSpnego, REALM, {
      enabled: false,
      configs: { service_principal: { Str: "HTTP/id.test@SAFFUI.TEST" } },
    });
    await keepAnswer(getSpnego, REALM);
    await deleteSpnego(REALM);
    await keepAnswer(listDirectories, REALM);
  });
});
