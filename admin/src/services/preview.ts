// Answers for the dev-only preview session, so the shell can be reviewed
// with no server behind it. Shapes mirror the real endpoints; the module is
// only ever reached in dev builds and only under the "preview" bearer.
import { ApiError } from "@/services/http";
import type { UserBrief } from "@/models/user";

const NOW = Math.floor(Date.now() / 1000);

const PEOPLE: UserBrief[] = [
  {
    user_id: "ada",
    user_name: "ada",
    enabled: true,
    email: "ada@example.test",
    email_verified: true,
    given_name: "Ada",
    family_name: "Lovelace",
    phone_number: null,
    required_actions: [],
  },
  {
    user_id: "grace",
    user_name: "grace",
    enabled: true,
    email: "grace@acme.example",
    email_verified: true,
    given_name: "Grace",
    family_name: "Hopper",
    phone_number: "+228 90 00 00 00",
    required_actions: ["update-password"],
  },
  {
    user_id: "linus",
    user_name: "linus",
    enabled: true,
    email: "linus@beta.example",
    email_verified: false,
    given_name: "Linus",
    family_name: "Ekwueme",
    phone_number: null,
    required_actions: [],
  },
  {
    user_id: "margaret",
    user_name: "margaret",
    enabled: false,
    email: "margaret@acme.example",
    email_verified: true,
    given_name: "Margaret",
    family_name: "Mensah",
    phone_number: null,
    required_actions: [],
  },
];

const CLIENTS = [
  { client_id: "web-dashboard", name: "Web dashboard", enabled: true, confidential: true,
    redirect_uris: ["https://app.acme.example/callback"], post_logout_redirect_uris: ["https://app.acme.example/"] },
  { client_id: "kiosk-tv", name: "Lobby kiosk", enabled: true, confidential: false,
    redirect_uris: [], post_logout_redirect_uris: [] },
  { client_id: "payments-api", name: "Payments API", enabled: true, confidential: true,
    redirect_uris: ["https://payments.acme.example/oauth/return"], post_logout_redirect_uris: [] },
  { client_id: "counter-desk", name: "Counter desk", enabled: false, confidential: true,
    redirect_uris: ["https://counter.beta.example/back"], post_logout_redirect_uris: [] },
];

function person(path: string): UserBrief | null {
  const found = /\/users\/([^/?]+)/.exec(path);
  return found ? (PEOPLE.find((held) => held.user_id === found[1]) ?? null) : null;
}

export function previewAnswer<T>(path: string): T {
  const answer = (held: unknown) => held as T;

  if (path.endsWith("/mail")) throw new ApiError(404, "nothing is configured");
  if (path.includes("/journal/verify")) {
    return answer({ holds: true, entries: 42, broken_at: null });
  }
  if (path.includes("/journal?")) {
    const write = (seq: number, actor: string, method: string, pattern: string, status: number, ago: number) => ({
      seq,
      recorded_at: NOW - ago,
      entry: {
        kind: "admin.write",
        occurred_at: NOW - ago,
        actor,
        party: "saffui-console",
        method,
        pattern,
        path: pattern.replace("{realm}", "main").replace("{user}", "grace"),
        status,
      },
    });
    return answer({
      items: [
        write(42, "ada", "PUT", "/admin/realms/{realm}/theme", 204, 320),
        write(41, "ada", "DELETE", "/admin/realms/{realm}/users/{user}/lockout", 204, 1500),
        write(40, "linus", "PUT", "/admin/realms/{realm}/theme", 422, 4100),
        write(39, "ada", "POST", "/admin/realms/{realm}/organizations", 201, 7300),
        write(38, "ada", "POST", "/admin/realms/{realm}/journal/anchors", 201, 86_000),
      ],
      first: 0,
      max: 5,
      total: 42,
    });
  }
  if (/\/users\/[^/]+\/roles$/.test(path)) {
    return answer({
      roles: [
        { role_id: "r-1", name: "auditor", display_name: "Auditor", description: "", client_id: null },
        { role_id: "r-2", name: "reader", display_name: "Reader", description: "held through Finance", client_id: "web-dashboard" },
      ],
    });
  }
  if (/\/users\/[^/]+\/groups$/.test(path)) {
    return answer({
      groups: [{ group_id: "g-1", name: "finance", display_name: "Finance", description: "" }],
    });
  }
  if (/\/users\/[^/]+\/organizations$/.test(path)) {
    return answer({
      organizations: [{ org_id: "o-1", name: "acme", display_name: "Acme Corp", enabled: true }],
    });
  }
  if (path.endsWith("/lockout")) {
    const who = person(path);
    if (who?.user_id === "grace") {
      return answer({
        failures: 5,
        locked: true,
        until: NOW + 700,
        last_failure: NOW - 60,
        last_address: "203.0.113.9",
      });
    }
    return answer({ failures: 0, locked: false, until: 0 });
  }
  if (/\/users\/[^/]+\/keys$/.test(path)) {
    return answer([
      {
        credential_id: "q5Zl2m4",
        label: "Work laptop",
        enrolled_at: NOW - 86_400 * 40,
        last_used_at: NOW - 3600,
      },
    ]);
  }
  if (/\/users\/[^/]+\/sessions$/.test(path)) {
    return answer([
      {
        session_id: "s-1",
        auth_method: "password",
        ip_address: "198.51.100.7",
        browser: "Firefox",
        system: "macOS",
        mobile: false,
        user_agent: "Mozilla/5.0",
        started_at: NOW - 5400,
        auth_time: NOW - 5400,
        expiration: NOW + 30_000,
        grants: [
          { client_id: "web-dashboard", offline: false, expiration: NOW + 1800 },
          { client_id: "kiosk-tv", offline: true, expiration: NOW + 86_400 * 20 },
        ],
      },
    ]);
  }
  if (/\/users\/[^/]+\/consents$/.test(path)) {
    return answer({
      consents: [
        {
          client_id: "web-dashboard",
          scopes: ["openid", "profile", "email"],
          granted_at: NOW - 86_400 * 12,
        },
      ],
    });
  }
  const who = person(path);
  if (who) return answer(who);
  if (path.includes("/users?")) {
    return answer({ items: PEOPLE, first: 0, max: 25, total: 1284 });
  }
  if (/\/clients\/[^/]+\/scopes$/.test(path)) {
    return answer([
      { client_scope_id: "cs-1", name: "openid", description: "", protocol: "openid-connect", default_scope: true, optional: false },
      { client_scope_id: "cs-2", name: "profile", description: "Name and picture", protocol: "openid-connect", default_scope: true, optional: false },
      { client_scope_id: "cs-3", name: "payments:write", description: "Move money", protocol: "openid-connect", default_scope: false, optional: true },
    ]);
  }
  if (/\/clients\/[^/]+\/mappers$/.test(path)) {
    return answer([
      { mapper_id: "m-1", name: "audience for payments", protocol: "openid-connect", mapper_type: "audience" },
      { mapper_id: "m-2", name: "department claim", protocol: "openid-connect", mapper_type: "user-attribute" },
    ]);
  }
  if (/\/clients\/[^/?]+$/.test(path)) {
    const found = CLIENTS.find((held) => path.endsWith(`/${held.client_id}`));
    if (found) return answer(found);
  }
  if (path.includes("/clients?")) {
    return answer({ items: CLIENTS, first: 0, max: 25, total: 12 });
  }
  if (/\/client-scopes\/[^/]+\/mappers$/.test(path)) {
    return answer([
      { mapper_id: "m-3", name: "email claims", protocol: "openid-connect", mapper_type: "user-property" },
    ]);
  }
  if (path.endsWith("/client-scopes")) {
    return answer([
      { client_scope_id: "cs-1", name: "openid", description: "The protocol's own word", protocol: "openid-connect", default_scope: true },
      { client_scope_id: "cs-2", name: "profile", description: "Name and picture", protocol: "openid-connect", default_scope: true },
      { client_scope_id: "cs-4", name: "email", description: "Email address", protocol: "openid-connect", default_scope: true },
      { client_scope_id: "cs-5", name: "offline_access", description: "Access while away", protocol: "openid-connect", default_scope: false },
      { client_scope_id: "cs-3", name: "payments:write", description: "Move money", protocol: "openid-connect", default_scope: false },
    ]);
  }
  if (/\/roles\/[^/]+\/holders$/.test(path)) {
    return answer({ users: ["ada", "grace"], groups: ["finance"] });
  }
  if (path.includes("/roles?")) {
    return answer({
      items: [
        { role_id: "r-1", name: "auditor", display_name: "Auditor", description: "Reads the journal", client_id: null },
        { role_id: "r-2", name: "reader", display_name: "Reader", description: "", client_id: "web-dashboard" },
        { role_id: "r-3", name: "payments-officer", display_name: "Payments officer", description: "May move money", client_id: "payments-api" },
      ],
      first: 0,
      max: 50,
      total: 3,
    });
  }
  if (/\/groups\/[^/]+\/membership$/.test(path)) {
    return answer({ users: ["ada", "grace", "linus"], roles: ["reader"] });
  }
  if (path.includes("/groups?")) {
    return answer({
      items: [
        { group_id: "g-1", name: "finance", display_name: "Finance", description: "Money people" },
        { group_id: "g-2", name: "platform", display_name: "Platform", description: "" },
      ],
      first: 0,
      max: 50,
      total: 2,
    });
  }
  if (/\/organizations\/[^/]+\/members$/.test(path)) {
    return answer([
      { user_id: "ada", membership_type: "unmanaged", roles: [], joined_at: "2026-07-02T09:00:00Z" },
      { user_id: "grace", membership_type: "managed", roles: ["org-admin"], joined_at: "2026-08-11T14:00:00Z" },
    ]);
  }
  if (/\/organizations\/[^/?]+$/.test(path) && !path.endsWith("/theme")) {
    return answer({
      org_id: "o-1",
      name: "acme",
      display_name: "Acme Corp",
      description: "The anchor customer",
      enabled: true,
      domains: [
        { name: "acme.example", verified: true },
        { name: "acme-labs.example", verified: false },
      ],
      redirect_url: "https://app.acme.example/",
    });
  }
  if (path.includes("/organizations?")) {
    return answer({
      items: [
        { org_id: "o-1", name: "acme", display_name: "Acme Corp", description: "The anchor customer", enabled: true, domains: [], redirect_url: null },
        { org_id: "o-2", name: "beta", display_name: "Beta LLC", description: "", enabled: false, domains: [], redirect_url: null },
      ],
      first: 0,
      max: 50,
      total: 2,
    });
  }
  if (path.endsWith("/keys")) {
    return answer({
      signing: [
        { kid: "sf-es256-2026-08", algorithm: "ES256", status: "active" },
        { kid: "sf-rs256-2026-02", algorithm: "RS256", status: "retiring" },
      ],
      encryption: [],
    });
  }
  if (path.endsWith("/theme")) {
    return answer(null);
  }
  if (/\/admin\/realms\/[^/]+$/.test(path)) {
    return answer({
      realm_id: "main",
      name: "main",
      display_name: "Main",
      enabled: true,
      client_registration: "open",
      registration_bounds: { max_clients: null, requires_consent: false, trusted_hosts: [] },
      require_pushed_authorization_requests: false,
      registration_allowed: false,
      register_email_as_username: null,
      verify_email: true,
      login_with_email_allowed: true,
      duplicated_email_allowed: false,
      edit_user_name_allowed: null,
      reset_password_allowed: true,
      remember_me: true,
      revoke_refresh_token: true,
      refresh_token_max_reuse: 0,
      access_token_lifespan: 300,
      offline_session_lifespan: 2592000,
      offline_session_max_lifespan: 0,
      max_offline_grants: 5,
      action_tokens_lifespan: null,
      access_code_lifespan: 60,
      access_code_lifespan_login: 900,
      not_before: 0,
      ssl_enforcement: "external",
      password_policy: { length: 12, digits: 1 },
      brute_force: { max_failures: 5, wait_seconds: 900 },
    });
  }
  throw new ApiError(404, "the preview world does not hold this");
}
