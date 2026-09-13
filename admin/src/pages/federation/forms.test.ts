import { describe, expect, test } from "vitest";
import type { IdpRow } from "@/models/federation";
import {
  ATTRIBUTE_MAPPER,
  ROLE_MAPPER,
  mapperDraft,
  emptyProviderDraft,
  mapperMutation,
  providerDraft,
  providerMutation,
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

    const draft = providerDraft(row);
    expect(draft.clientSecret).toBe("");
    expect(providerMutation(draft)).toEqual(
      expect.objectContaining({
        provider_id: "corp",
        trust_email: true,
        configs: expect.not.objectContaining({ client_secret: expect.anything() }),
      }),
    );
  });

  test("sends a new secret only when the operator typed one", () => {
    const draft = providerDraft({
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
    expect(providerMutation(draft).configs.client_secret).toEqual({ Str: "new-secret" });
  });
});

describe("plain OAuth 2.0 provider forms", () => {
  test("round-trips a plain OAuth 2.0 provider and sends only its own fields", () => {
    const row: IdpRow = {
      internal_id: "idp-2",
      provider_id: "github",
      name: "github",
      display_name: "GitHub",
      description: "",
      enabled: true,
      trust_email: true,
      configs: {
        protocol: { Str: "oauth2" },
        authorization_endpoint: { Str: "https://github.com/login/oauth/authorize" },
        token_endpoint: { Str: "https://github.com/login/oauth/access_token" },
        userinfo_endpoint: { Str: "https://api.github.com/user" },
        client_id: { Str: "console" },
        client_secret: { Str: "**********" },
        scope: { Str: "read:user user:email" },
        token_auth: { Str: "client_secret_post" },
        pkce: { Str: "false" },
        subject_pointer: { Str: "/id" },
        username_pointer: { Str: "/login" },
        emails_endpoint: { Str: "https://api.github.com/user/emails" },
      },
    };

    const draft = providerDraft(row);
    expect(draft.protocol).toBe("oauth2");
    expect(draft.tokenAuth).toBe("client_secret_post");
    expect(draft.pkce).toBe(false);
    expect(draft.emailsVerifiedPointer).toBe("/verified");
    expect(providerMutation(draft).configs).toEqual({
      protocol: { Str: "oauth2" },
      authorization_endpoint: { Str: "https://github.com/login/oauth/authorize" },
      token_endpoint: { Str: "https://github.com/login/oauth/access_token" },
      client_id: { Str: "console" },
      token_auth: { Str: "client_secret_post" },
      userinfo_endpoint: { Str: "https://api.github.com/user" },
      subject_pointer: { Str: "/id" },
      scope: { Str: "read:user user:email" },
      username_pointer: { Str: "/login" },
      emails_endpoint: { Str: "https://api.github.com/user/emails" },
      emails_address_pointer: { Str: "/email" },
      emails_verified_pointer: { Str: "/verified" },
      emails_primary_pointer: { Str: "/primary" },
      pkce: { Str: "false" },
    });
  });

  test("sends no address list and no OpenID Connect field for an account API alone", () => {
    const draft = {
      ...emptyProviderDraft(),
      alias: "x",
      protocol: "oauth2" as const,
      issuer: "https://left.over",
      jwksUri: "https://left.over/keys",
      authorizationEndpoint: "https://x.com/i/oauth2/authorize",
      tokenEndpoint: "https://api.x.com/2/oauth2/token",
      userinfoEndpoint: "https://api.x.com/2/users/me",
      clientId: "console",
      scope: "users.read",
      subjectPointer: "/data/id",
    };
    const configs = providerMutation(draft).configs;
    expect(Object.keys(configs).sort()).toEqual([
      "authorization_endpoint",
      "client_id",
      "protocol",
      "scope",
      "subject_pointer",
      "token_auth",
      "token_endpoint",
      "userinfo_endpoint",
    ]);
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
