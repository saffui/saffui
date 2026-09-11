import { describe, expect, test } from "vitest";
import type { IdpRow } from "@/models/federation";
import {
  ATTRIBUTE_MAPPER,
  ROLE_MAPPER,
  mapperDraft,
  mapperMutation,
  oidcDraft,
  oidcMutation,
} from "./forms";

describe("identity provider forms", () => {
  test("round-trips the exact OIDC fields without echoing a sealed secret", () => {
    const row: IdpRow = {
      internal_id: "idp-1",
      provider_id: "corp",
      name: "corp",
      display_name: "Corporate login",
      description: "Employees",
      enabled: true,
      trust_email: true,
      configs: {
        issuer: { Str: "https://id.example" },
        authorization_endpoint: { Str: "https://id.example/auth" },
        token_endpoint: { Str: "https://id.example/token" },
        jwks_uri: { Str: "https://id.example/keys" },
        client_id: { Str: "console" },
        client_secret: { Str: "**********" },
      },
    };

    const draft = oidcDraft(row);
    expect(draft.clientSecret).toBe("");
    expect(oidcMutation(draft)).toEqual(
      expect.objectContaining({
        provider_id: "corp",
        trust_email: true,
        configs: expect.not.objectContaining({ client_secret: expect.anything() }),
      }),
    );
  });

  test("sends a new secret only when the operator typed one", () => {
    const draft = oidcDraft({
      internal_id: "idp-1",
      provider_id: "corp",
      name: "corp",
      display_name: "Corp",
      description: "",
      enabled: true,
      trust_email: false,
      configs: {
        issuer: "https://id.example",
        authorization_endpoint: "https://id.example/auth",
        token_endpoint: "https://id.example/token",
        jwks_uri: "https://id.example/keys",
        client_id: "console",
      },
    });
    draft.clientSecret = "new-secret";
    expect(oidcMutation(draft).configs.client_secret).toEqual({ Str: "new-secret" });
  });
});

describe("identity provider mapper forms", () => {
  test("keeps only claim mapping fields", () => {
    const body = mapperMutation({
      name: " Department ",
      type: ATTRIBUTE_MAPPER,
      syncMode: "force",
      claim: " department ",
      userAttribute: " upstream.department ",
      role: "ignored",
    });
    expect(body).toEqual({
      name: "Department",
      mapper_type: ATTRIBUTE_MAPPER,
      configs: {
        syncMode: { Str: "force" },
        claim: { Str: "department" },
        "user.attribute": { Str: "upstream.department" },
      },
    });
  });

  test("reads and writes role mappings by stable role id", () => {
    const draft = mapperDraft({
      mapper_id: "map-1",
      realm_id: "main",
      provider_alias: "corp",
      name: "operators",
      mapper_type: ROLE_MAPPER,
      configs: { role: { Str: "role-id" }, syncMode: { Str: "import" } },
    });
    expect(mapperMutation(draft)).toEqual({
      name: "operators",
      mapper_type: ROLE_MAPPER,
      configs: { syncMode: { Str: "import" }, role: { Str: "role-id" } },
    });
  });
});
