import { describe, expect, test } from "vitest";
import type { IdpRow } from "@/models/federation";
import {
  ATTRIBUTE_MAPPER,
  applyDiscoveredProvider,
  PERSISTENT_NAME_ID,
  ROLE_MAPPER,
  SAML_ATTRIBUTE_MAPPER,
  SAML_ROLE_MAPPER,
  emptyMapperDraft,
  emptyProviderDraft,
  findProviderBlocker,
  listNeededProviderKeys,
  mapperDraft,
  mapperMutation,
  mapperTypeLabel,
  mapperTypesFor,
  providerDraft,
  providerMutation,
  readHeldAssertionAlgorithm,
  readProviderPublicKey,
  samlMetadataAddress,
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

describe("national sign-in provider forms", () => {
  const assertionJwk = '{"kty":"RSA","kid":"k-1","alg":"PS256","use":"sig","n":"AQAB","e":"AQAB"}';
  const row: IdpRow = {
    internal_id: "idp-4",
    provider_id: "national",
    name: "national",
    display_name: "National ID",
    description: "",
    enabled: true,
    trust_email: false,
    configs: {
      issuer: { Str: "https://esignet.example" },
      authorization_endpoint: { Str: "https://esignet.example/authorize" },
      token_endpoint: { Str: "https://esignet.example/oauth2/token" },
      jwks_uri: { Str: "https://esignet.example/oauth2/jwks" },
      userinfo_endpoint: { Str: "https://esignet.example/oauth2/userinfo" },
      client_id: { Str: "saffui" },
      scope: { Str: "openid profile" },
      allowed_algs: { Str: "PS256" },
      token_auth: { Str: "private_key_jwt" },
      userinfo_response: { Str: "jwe" },
      userinfo_algs: { Str: "RS256 PS256" },
      claims: { Str: '{"userinfo":{"name":{"essential":true}}}' },
      accepted_acrs: { Str: "mosip:idp:acr:biometrics=mfa" },
      assertion_jwk: { Str: assertionJwk },
      encryption_jwk: { Str: '{"kty":"RSA","kid":"k-2","alg":"RSA-OAEP-256","use":"enc","n":"AQAB","e":"AQAB"}' },
    },
  };

  test("round-trips what the provider is asked and answers, and never sends a key back", () => {
    const draft = providerDraft(row);
    expect(draft.tokenAuth).toBe("private_key_jwt");
    expect(draft.userinfoForm).toBe("jwe");
    expect(draft.claimsRequest).toBe('{\n  "userinfo": {\n    "name": {\n      "essential": true\n    }\n  }\n}');
    draft.clientSecret = "typed-by-mistake";
    const configs = providerMutation(draft).configs;
    expect(configs).toEqual({
      protocol: { Str: "oidc" },
      issuer: { Str: "https://esignet.example" },
      authorization_endpoint: { Str: "https://esignet.example/authorize" },
      token_endpoint: { Str: "https://esignet.example/oauth2/token" },
      jwks_uri: { Str: "https://esignet.example/oauth2/jwks" },
      client_id: { Str: "saffui" },
      scope: { Str: "openid profile" },
      allowed_algs: { Str: "PS256" },
      token_auth: { Str: "private_key_jwt" },
      assertion_alg: { Str: "PS256" },
      assertion_audience: { Str: "issuer" },
      userinfo_response: { Str: "jwe" },
      userinfo_endpoint: { Str: "https://esignet.example/oauth2/userinfo" },
      userinfo_algs: { Str: "RS256 PS256" },
      claims: { Str: draft.claimsRequest },
      accepted_acrs: { Str: "mosip:idp:acr:biometrics=mfa" },
    });
  });

  test("round-trips an assertion signed RS256 to the token endpoint, and sends none without one", () => {
    const older = providerDraft({
      ...row,
      configs: { ...row.configs, assertion_alg: { Str: "RS256" }, assertion_audience: { Str: "token_endpoint" } },
    });
    expect([older.assertionAlgorithm, older.assertionAudience]).toEqual(["RS256", "token_endpoint"]);
    const configs = providerMutation(older).configs;
    expect([configs.assertion_alg, configs.assertion_audience]).toEqual([{ Str: "RS256" }, { Str: "token_endpoint" }]);
    const plain = providerMutation({ ...older, protocol: "oauth2" }).configs;
    expect([plain.assertion_alg, plain.assertion_audience]).toEqual([{ Str: "RS256" }, undefined]);
    const secret = providerMutation({ ...older, tokenAuth: "client_secret_basic" }).configs;
    expect([secret.assertion_alg, secret.assertion_audience]).toEqual([undefined, undefined]);
  });

  test("reads the algorithm a drawn key holds, and a saved provider's from its key when unsaid", () => {
    const keyed = (alg: string) => ({
      ...row,
      configs: { ...row.configs, assertion_jwk: { Str: JSON.stringify({ ...JSON.parse(assertionJwk), alg }) } },
    });
    expect(readHeldAssertionAlgorithm(row)).toBe("PS256");
    expect(readHeldAssertionAlgorithm(keyed("RS256"))).toBe("RS256");
    expect(readHeldAssertionAlgorithm(keyed("ES256"))).toBeNull();
    expect(readHeldAssertionAlgorithm({ ...row, configs: { ...row.configs, assertion_jwk: { Str: "not json" } } })).toBeNull();
    expect(readHeldAssertionAlgorithm(undefined)).toBeNull();
    expect(providerDraft(keyed("RS256")).assertionAlgorithm).toBe("RS256");
    expect(providerDraft({ ...row, configs: { ...row.configs, assertion_jwk: { Str: "" } } }).assertionAlgorithm).toBe("PS256");
  });

  test("reads a plain JSON userinfo with no algorithm of its own", () => {
    const draft = { ...providerDraft(row), userinfoForm: "json" as const };
    const configs = providerMutation(draft).configs;
    expect(configs.userinfo_response).toEqual({ Str: "json" });
    expect(configs.userinfo_algs).toBeUndefined();
    const unread = providerMutation({ ...draft, userinfoForm: "" }).configs;
    expect(unread.userinfo_response).toBeUndefined();
    expect(unread.userinfo_endpoint).toBeUndefined();
  });

  test("names the keys a provider needs and shows those already drawn", () => {
    const draft = providerDraft(row);
    expect(listNeededProviderKeys(draft)).toEqual(["assertion_jwk", "encryption_jwk"]);
    expect(listNeededProviderKeys({ ...draft, tokenAuth: "client_secret_basic", userinfoForm: "jws" })).toEqual([]);
    expect(listNeededProviderKeys({ ...draft, protocol: "oauth2", userinfoForm: "jwe" })).toEqual(["assertion_jwk"]);
    expect(JSON.parse(readProviderPublicKey(row, "assertion_jwk"))).toEqual(JSON.parse(assertionJwk));
    expect(readProviderPublicKey(undefined, "assertion_jwk")).toBe("");
  });

  test("round-trips a way back held to name its issuer", () => {
    const held = providerDraft({ ...row, configs: { ...row.configs, iss_parameter: { Str: "required" } } });
    expect(held.issuerRequiredOnReturn).toBe(true);
    expect(providerMutation(held).configs.iss_parameter).toEqual({ Str: "required" });
    const loose = { ...held, issuerRequiredOnReturn: false };
    expect(providerMutation(loose).configs.iss_parameter).toBeUndefined();
    expect(providerMutation({ ...held, protocol: "oauth2" }).configs.iss_parameter).toBeUndefined();
  });

  test("takes what the issuer publishes, keeping the userinfo algorithms as set", () => {
    const draft = { ...providerDraft(row), issuerRequiredOnReturn: false };
    const found = {
      issuer: "https://esignet.example",
      authorization_endpoint: "https://esignet.example/v1/authorize",
      token_endpoint: "https://esignet.example/v1/token",
      jwks_uri: "https://esignet.example/v1/jwks",
      userinfo_endpoint: null,
      id_token_algs: ["PS256", "ES256"],
      acr_values: ["mosip:idp:acr:biometrics"],
      iss_parameter: true,
      assertion_alg: "RS256" as const,
      gaps: [],
    };
    const applied = applyDiscoveredProvider(draft, found);
    expect(applied.assertionAlgorithm).toBe("RS256");
    expect(applyDiscoveredProvider(draft, found, "PS256").assertionAlgorithm).toBe("PS256");
    expect(applyDiscoveredProvider(draft, { ...found, assertion_alg: null }).assertionAlgorithm).toBe(
      draft.assertionAlgorithm,
    );
    expect(applied.authorizationEndpoint).toBe("https://esignet.example/v1/authorize");
    expect(applied.tokenEndpoint).toBe("https://esignet.example/v1/token");
    expect(applied.jwksUri).toBe("https://esignet.example/v1/jwks");
    expect(applied.userinfoEndpoint).toBe("https://esignet.example/oauth2/userinfo");
    expect(applied.algorithms).toBe("PS256 ES256");
    expect(applied.userinfoAlgorithms).toBe("RS256 PS256");
    expect(applied.issuerRequiredOnReturn).toBe(true);
    expect(applied.clientId).toBe(draft.clientId);
  });

  test("keeps a claims request that is not a JSON object from being saved", () => {
    const draft = providerDraft(row);
    expect(findProviderBlocker(draft)).toBeNull();
    for (const written of ["not json", "[]", "null", '"name"']) {
      expect(findProviderBlocker({ ...draft, claimsRequest: written })).toBe("idp-claims-not-an-object");
    }
    expect(findProviderBlocker({ ...draft, claimsRequest: " " })).toBeNull();
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
      ...emptyMapperDraft(),
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

describe("SAML provider forms", () => {
  const row: IdpRow = {
    internal_id: "idp-3",
    provider_id: "partner",
    name: "partner",
    display_name: "Partner SSO",
    description: "",
    enabled: true,
    trust_email: false,
    configs: {
      protocol: { Str: "saml" },
      idp_metadata: { Str: "<md:EntityDescriptor/>" },
      name_id_format: { Str: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" },
      principal_attribute: { Str: "uid" },
      email_attribute: { Str: "mail" },
    },
  };

  test("reads a SAML provider as SAML and saves every key it holds, none of the other protocols", () => {
    const draft = providerDraft(row);
    expect(draft.protocol).toBe("saml");
    expect(providerMutation(draft).configs).toEqual({
      protocol: { Str: "saml" },
      idp_metadata: { Str: "<md:EntityDescriptor/>" },
      name_id_format: { Str: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" },
      principal_attribute: { Str: "uid" },
      email_attribute: { Str: "mail" },
    });
  });

  test("starts on the persistent format and leaves a blank optional key out", () => {
    const draft = {
      ...emptyProviderDraft(),
      alias: "partner",
      protocol: "saml" as const,
      idpMetadata: " <md:EntityDescriptor/> ",
      spEntityId: " ",
    };
    expect(draft.nameIdFormat).toBe(PERSISTENT_NAME_ID);
    expect(providerMutation(draft).configs).toEqual({
      protocol: { Str: "saml" },
      idp_metadata: { Str: "<md:EntityDescriptor/>" },
      name_id_format: { Str: PERSISTENT_NAME_ID },
    });
  });

  test("names what keeps a SAML provider from being saved", () => {
    const ready = { ...emptyProviderDraft(), protocol: "saml" as const, idpMetadata: "<md:EntityDescriptor/>" };
    expect(findProviderBlocker(ready)).toBeNull();
    expect(findProviderBlocker({ ...ready, idpMetadata: " " })).toBe("idp-saml-metadata-needed");
    expect(
      findProviderBlocker({ ...ready, nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" }),
    ).toBe("idp-saml-principal-needed");
    expect(findProviderBlocker({ ...ready, principalAttribute: "mail", emailAttribute: " mail " })).toBe(
      "idp-saml-principal-is-email",
    );
    expect(findProviderBlocker(emptyProviderDraft())).toBeNull();
  });

  test("gives the realm's metadata address for a provider", () => {
    expect(samlMetadataAddress("https://id.example", "main realm", "partner")).toBe(
      "https://id.example/realms/main%20realm/broker/partner/saml/metadata",
    );
  });
});

describe("SAML mapper forms", () => {
  test("offers the rules that read what each protocol sends", () => {
    expect(mapperTypesFor("saml")).toEqual([SAML_ATTRIBUTE_MAPPER, SAML_ROLE_MAPPER, ROLE_MAPPER]);
    expect(mapperTypesFor("oidc")).toEqual([ATTRIBUTE_MAPPER, ROLE_MAPPER]);
    expect(mapperTypesFor("oauth2")).toEqual([ATTRIBUTE_MAPPER, ROLE_MAPPER]);
    expect(emptyMapperDraft("saml").type).toBe(SAML_ATTRIBUTE_MAPPER);
    expect(emptyMapperDraft().type).toBe(ATTRIBUTE_MAPPER);
    expect([ATTRIBUTE_MAPPER, ROLE_MAPPER, SAML_ATTRIBUTE_MAPPER, SAML_ROLE_MAPPER].map(mapperTypeLabel)).toEqual([
      "idp-mapper-attribute",
      "idp-mapper-role",
      "idp-mapper-saml-attribute",
      "idp-mapper-saml-role",
    ]);
  });

  test("round-trips a SAML attribute rule, keeping a list only when asked", () => {
    const draft = mapperDraft({
      mapper_id: "m-3",
      realm_id: "main",
      provider_alias: "partner",
      name: "groups",
      mapper_type: SAML_ATTRIBUTE_MAPPER,
      configs: {
        "attribute.name": { Str: "memberOf" },
        "user.attribute": { Str: "groups" },
        multivalued: { Str: "true" },
        syncMode: { Str: "force" },
      },
    });
    expect(draft.multivalued).toBe(true);
    expect(mapperMutation(draft)).toEqual({
      name: "groups",
      mapper_type: SAML_ATTRIBUTE_MAPPER,
      configs: {
        syncMode: { Str: "force" },
        "attribute.name": { Str: "memberOf" },
        "user.attribute": { Str: "groups" },
        multivalued: { Str: "true" },
      },
    });
    expect(mapperMutation({ ...draft, multivalued: false }).configs.multivalued).toBeUndefined();
  });

  test("round-trips a SAML role rule by its attribute, its value and a stable role id", () => {
    const draft = mapperDraft({
      mapper_id: "m-4",
      realm_id: "main",
      provider_alias: "partner",
      name: "staff",
      mapper_type: SAML_ROLE_MAPPER,
      configs: {
        "attribute.name": { Str: "memberOf" },
        "attribute.value": { Str: "staff" },
        role: { Str: "role-staff" },
        syncMode: { Str: "import" },
      },
    });
    expect(mapperMutation(draft)).toEqual({
      name: "staff",
      mapper_type: SAML_ROLE_MAPPER,
      configs: {
        syncMode: { Str: "import" },
        "attribute.name": { Str: "memberOf" },
        "attribute.value": { Str: "staff" },
        role: { Str: "role-staff" },
      },
    });
  });
});
