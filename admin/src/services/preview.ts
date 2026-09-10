// Answers for the dev-only preview session, so the shell can be reviewed
// with no server behind it. Shapes mirror the real endpoints; the module is
// only ever reached in dev builds and only under the "preview" bearer.
import { ApiError } from "@/services/http";
import type { UserBrief } from "@/models/user";

const NOW = Math.floor(Date.now() / 1000);

/// Revoking in the preview has to show, or the button would look broken here
/// and nowhere else.
const TAKEN_AWAY = new Set<string>();

const PEOPLE: UserBrief[] = [
  {
    user_id: "0f8a4c31-6b2e-4d59-9c11-2a7f5e8d3b40",
    user_name: "ada",
    enabled: true,
    email: "ada@example.test",
    email_verified: true,
    given_name: "Ada",
    family_name: "Lovelace",
    phone_number: null,
    required_actions: [],
    created_at: "2026-08-16T09:00:00Z",
    origin: "local",
  },
  {
    user_id: "3d1e7a86-9f04-42bb-8e57-c6b2d09fa715",
    user_name: "grace",
    enabled: true,
    email: "grace@acme.example",
    email_verified: true,
    given_name: "Grace",
    family_name: "Hopper",
    phone_number: "+228 90 00 00 00",
    required_actions: ["update-password"],
    created_at: "2026-08-16T09:00:00Z",
    origin: "local",
  },
  {
    user_id: "b74c2f90-15da-4e83-a6d1-8f30c5b91e2a",
    user_name: "linus",
    enabled: true,
    email: "linus@beta.example",
    email_verified: false,
    given_name: "Linus",
    family_name: "Ekwueme",
    phone_number: null,
    required_actions: [],
    created_at: "2026-08-16T09:00:00Z",
    origin: "local",
  },
  {
    user_id: "9e05b3c7-42af-4610-b8d2-7c1e6f4a83d5",
    user_name: "margaret",
    enabled: false,
    email: "margaret@acme.example",
    email_verified: true,
    given_name: "Margaret",
    family_name: "Mensah",
    phone_number: null,
    required_actions: [],
    created_at: "2026-08-16T09:00:00Z",
    origin: "local",
  },
];

const CLIENTS = [
  { client_id: "web-dashboard", name: "Web dashboard", enabled: true, confidential: true, root_url: null, web_origins: [],
    redirect_uris: ["https://app.acme.example/callback"], post_logout_redirect_uris: ["https://app.acme.example/"] },
  { client_id: "kiosk-tv", name: "Lobby kiosk", enabled: true, confidential: false, root_url: null, web_origins: [],
    redirect_uris: [], post_logout_redirect_uris: [] },
  { client_id: "payments-api", name: "Payments API", enabled: true, confidential: true, root_url: null, web_origins: [],
    redirect_uris: ["https://payments.acme.example/oauth/return"], post_logout_redirect_uris: [] },
  { client_id: "counter-desk", name: "Counter desk", enabled: false, confidential: true, root_url: null, web_origins: [],
    redirect_uris: ["https://counter.beta.example/back"], post_logout_redirect_uris: [] },
];

function person(path: string): UserBrief | null {
  const found = /\/users\/([^/?]+)/.exec(path);
  return found
    ? (PEOPLE.find((held) => held.user_id === found[1] || held.user_name === found[1]) ??
      null)
    : null;
}

/// One decision as the log keeps it, for the fixtures below.
function decided(
  id: string,
  who: string,
  action: string,
  kind: string,
  ref: string | null,
  reported: string,
  computed: string,
  agoSeconds: number,
) {
  return {
    decision_id: id,
    subject_type: "user",
    subject_id: who,
    resource_kind: kind,
    resource_ref: ref,
    action,
    reported,
    computed,
    duration_us: 400 + agoSeconds,
    trace_id: null,
    occurred_at_millis: (NOW - agoSeconds) * 1000,
  };
}

export function previewAnswer<T>(path: string, method = "GET"): T {
  const answer = (held: unknown) => held as T;

  if (path.endsWith("/mail")) {
    if (method === "DELETE") return answer(undefined);
    return answer({
      host: "smtp.saffui.tg",
      port: 587,
      from_address: "no-reply@saffui.tg",
      from_name: "saffui",
      reply_to: "support@saffui.tg",
      implicit_tls: false,
      username: "no-reply@saffui.tg",
      has_password: true,
    });
  }
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
  if (path.endsWith("/sms/today")) {
    return answer({
      sent: 3218, cap: 5000,
      blocked_prefix: 19, number_velocity: 7, day_budget: 0,
    });
  }
  if (path.endsWith("/mail/probe")) {
    return answer({
      reached_in_millis: 412,
      tls_version: "TLSv1.3",
      cipher: "TLS_AES_256_GCM_SHA384",
      certificate_until: "Aug  2 09:14:00 2026 GMT",
      certificate_issuer: "R11",
      max_message_bytes: 20_480_000,
      auth_offered: ["LOGIN", "PLAIN"],
      transcript: [
        "< 220 smtp.saffui.tg ESMTP ready",
        "> EHLO smtp.saffui.tg",
        "< 250-smtp.saffui.tg",
        "< 250-STARTTLS",
        "< 250-AUTH LOGIN PLAIN",
        "< 250 SIZE 20480000",
        "> STARTTLS",
        "< 220 2.0.0 Ready to start TLS",
        "--- TLS ---",
        "> EHLO smtp.saffui.tg",
        "< 250 smtp.saffui.tg",
        "> AUTH LOGIN (no-reply@saffui.tg)",
        "< 235 2.7.0 Authentication succeeded",
        "> QUIT",
        "< 221 2.0.0 Bye",
      ],
      refused: null,
    });
  }
  if (path.endsWith("/mail/refusals")) {
    const ago = (hours: number) => new Date((NOW - hours * 3600) * 1000).toISOString();
    return answer({
      hours: 24,
      items: [
        { recipient: "kwame.b@old.tg", purpose: "reset-password", attempted_at: ago(3), detail: "550 5.1.1 mailbox unknown" },
        { recipient: "batch@acme.example", purpose: "verify-email", attempted_at: ago(6), detail: "421 4.7.0 too many connections" },
        { recipient: "probe@beta.example", purpose: "magic-link", attempted_at: ago(9), detail: "read timed out after 20 s" },
      ],
    });
  }
  if (/\/features\/[^/]+$/.test(path) && method === "PUT") {
    return answer(null);
  }
  if (/\/realms\/[^/]+\/features$/.test(path)) {
    const held = (
      slug: string, lifecycle: string, reach: string, closing: string, doc: string, on: boolean,
    ) => ({
      slug, lifecycle, reach, closing, doc,
      compiled: true, in_process: on, enabled: on,
      asked: null, changed_by: null, changed_at: null,
    });
    return answer({
      items: [
        held("token-exchange", "stable", "realm", "narrows", "Trade a token for another audience, or for a subject being acted for.", true),
        held("scim", "stable", "realm", "narrows", "A SCIM 2.0 root for an external directory to provision accounts through.", true),
        held("ussd-bridge", "stable", "realm", "narrows", "Answer USSD sessions opened on an operator short code.", true),
        held("authorization", "stable", "realm", "narrows", "Resources, scopes and policies served to this realm's resource servers.", true),
        held("phone-first-login", "stable", "realm", "narrows", "Accept a proven phone number anywhere a username is expected.", true),
        held("web-authn", "stable", "realm", "weakens", "Passkeys and roaming authenticators as a factor.", true),
        held("sms-otp", "stable", "realm", "weakens", "A code delivered by the SMS gateway, as a first or second factor.", true),
        held("metrics", "stable", "process", "narrows", "Request metrics on the operations port, in the Prometheus text form.", true),
        held("organization", "preview", "realm", "narrows", "Group accounts under an organization carrying its own brokers and domains.", true),
        held("pq-hybrid", "preview", "process", "weakens", "ML-DSA signatures and ML-KEM encapsulation.", false),
        held("rebac-store", "experimental", "realm", "narrows", "Relation tuples backing the ReBAC side of the authorization engine.", false),
      ],
    });
  }
  if (/\/users\/[^/]+\/(credentials|keys)\/[^/]+$/.test(path) && method === "DELETE") {
    TAKEN_AWAY.add(path.split("/").pop() ?? "");
    return answer(null);
  }
  if (/\/users\/[^/]+\/credentials$/.test(path)) {
    const iso = (days: number) => new Date((NOW - 86_400 * days) * 1000).toISOString();
    return answer({
      items: [
        { id: null, kind: "password", label: null, detail: "argon2id", created_at: iso(12) },
        { id: "cred-totp", kind: "totp", label: "Authenticator app", detail: "SHA1 · 6 digits · 30 s", created_at: iso(240) },
        { id: "a2V5LTE", kind: "webauthn", label: "Work laptop", detail: null, created_at: iso(401) },
        { id: "cred-codes", kind: "recovery-code", label: "Printed set", detail: "8 still unused", created_at: iso(401) },
      ].filter((held) => !held.id || !TAKEN_AWAY.has(held.id)),
    });
  }
  if (/\/users\/[^/]+\/password\/history$/.test(path)) {
    return answer({
      items: [12, 97, 168, 240, 401, 520, 733].map((days, at) => ({
        replaced_at: new Date((NOW - 86_400 * days) * 1000).toISOString(),
        by: ["ada", "root", "ada", "linus", "root", "ada", "root"][at],
      })),
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
  if (who) {
    return answer({
      ...who,
      attributes: { department: { Str: "engineering" }, cost_center: { Str: "cc-7" } },
      identity_providers: who.user_id === "grace" ? ["corp-okta"] : [],
    });
  }
  if (path.includes("/users?")) {
    const asked = new URLSearchParams(path.split("?")[1]);
    const typed = (asked.get("search") ?? "").toLowerCase();
    const enabled = asked.get("enabled");
    const rows = PEOPLE.filter(
      (row) =>
        !typed ||
        row.user_name.toLowerCase().startsWith(typed) ||
        (row.email ?? "").toLowerCase().startsWith(typed),
    )
      .filter((row) => !enabled || String(row.enabled) === enabled)
      .filter(
        (row) => asked.get("pending") !== "true" || (row.required_actions ?? []).length > 0,
      );
    return answer({ items: rows, first: 0, max: 25, total: rows.length });
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
    return answer({
      users: ["u-ada", "u-grace"],
      groups: ["g-finance"],
      user_details: [
        { id: "u-ada", name: "ada" },
        { id: "u-grace", name: "grace" },
      ],
      group_details: [{ id: "g-finance", name: "finance" }],
    });
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
        {
          group_id: "g-1",
          name: "finance",
          display_name: "Finance",
          description: "Money people",
          parent_id: null,
        },
        { group_id: "g-2", name: "platform", display_name: "Platform", description: "", parent_id: null },
        {
          group_id: "g-3",
          name: "payments",
          display_name: "Payments",
          description: "Cards and ledgers",
          parent_id: "g-1",
        },
      ],
      first: 0,
      max: 50,
      total: 2,
    });
  }
  if (/\/organizations\/[^/]+\/members$/.test(path)) {
    return answer([
      { user_id: "0f8a4c31-6b2e-4d59-9c11-2a7f5e8d3b40", membership_type: "unmanaged", roles: [], joined_at: "2026-07-02T09:00:00Z" },
      { user_id: "3d1e7a86-9f04-42bb-8e57-c6b2d09fa715", membership_type: "managed", roles: ["org-admin"], joined_at: "2026-08-11T14:00:00Z" },
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
  if (/\/federations\/[^/]+\/import$/.test(path)) {
    return answer({ imported: 14, refreshed: 82, walked: 96 });
  }
  if (path.includes("/import/preview") || path.endsWith("/import")) {
    return answer({
      realm_id: "main",
      new: { roles: 2, groups: 1, clients: 1 },
      overwritten: {},
      skipped: {},
      collisions: [],
      collision_count: 0,
      collisions_truncated: false,
    });
  }
  if (path.includes("/export")) {
    return answer({
      format_version: 1,
      exported_at: NOW,
      sections: ["realm", "users"],
      realm: { realm_id: "main" },
      users: PEOPLE,
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
  if (/\/identity-providers\/[^/]+\/prove$/.test(path)) {
    return answer({
      proven: true,
      how: "answered",
      status: 200,
      said: "the SCIM root answered as itself",
    });
  }
  if (path.endsWith("/subject-requests")) {
    return answer([
      { request_id: "d-1", user_id: "0f8a4c31-6b2e-4d59-9c11-2a7f5e8d3b40", subject_identifier: "ada", kind: "erasure", stage: "received",
        jurisdiction: "ke", received_at: 1788700000, due_at: 1788700000 - 86400, verified_at: null, closed_at: null,
        deadline_source: "Data Protection (General) Regulations 2021, reg. 9(4), seven days." },
      { request_id: "d-2", user_id: null, subject_identifier: "gone@example.test", kind: "access", stage: "verified",
        jurisdiction: "eu", received_at: 1788700000, due_at: 1788700000 + 2000000, verified_at: 1788700000, closed_at: null,
        deadline_source: "GDPR art. 12(3), one month, extendable by two" },
      { request_id: "d-3", user_id: "b74c2f90-15da-4e83-a6d1-8f30c5b91e2a", subject_identifier: "linus", kind: "objection", stage: "refused",
        reason: "duplicate of d-1", jurisdiction: "eu", received_at: 1788700000, due_at: 1788700000 + 2000000,
        verified_at: null, closed_at: 1788700000, deadline_source: "GDPR art. 12(3), one month, extendable by two" },
    ]);
  }
  if (/\/identity-providers\/[^/]+\/mappers\/[^/]+$/.test(path)) {
    return answer(null);
  }
  if (/\/identity-providers\/[^/]+\/mappers$/.test(path)) {
    if (method !== "GET") return answer(null);
    return answer([
      {
        mapper_id: "m-1", realm_id: "main", provider_alias: "corp-okta",
        name: "department", mapper_type: "oidc-user-attribute-idp-mapper",
        configs: { claim: { Str: "department" }, "user.attribute": { Str: "department" }, syncMode: { Str: "import" } },
      },
      {
        mapper_id: "m-2", realm_id: "main", provider_alias: "corp-okta",
        name: "staff", mapper_type: "oidc-hardcoded-role-idp-mapper",
        configs: { role: { Str: "role-staff" }, syncMode: { Str: "import" } },
      },
    ]);
  }
  if (path.endsWith("/identity-providers")) {
    return answer([
      { internal_id: "i-1", provider_id: "corp-okta", name: "corp-okta", display_name: "Corp Okta", description: "", enabled: true, trust_email: true, configs: null },
      { internal_id: "i-2", provider_id: "the-collector", name: "the-collector", display_name: "SOC collector", description: "", enabled: true, trust_email: false,
        configs: { kind: { Str: "caep-push" }, delivery: { Str: "poll" }, audience: { Str: "https://soc.example" } } },
      { internal_id: "i-3", provider_id: "crm-webhook", name: "crm-webhook", display_name: "CRM provisioning", description: "", enabled: true, trust_email: false,
        configs: { kind: { Str: "scim-outbound" }, base_url: { Str: "https://crm.example/scim/v2" } } },
      { internal_id: "i-4", provider_id: "github-actions", name: "github-actions", display_name: "GitHub Actions", description: "", enabled: true, trust_email: false,
        configs: { kind: { Str: "workload" }, issuer: { Str: "https://token.actions.githubusercontent.com" },
          jwks_uri: { Str: "https://token.actions.githubusercontent.com/.well-known/jwks" },
          audience: { Str: "https://id.acme.example" }, subject_patterns: { Str: "repo:acme/deploy:* repo:acme/api:ref:refs/heads/main" },
          client_id: { Str: "ci-deployer" } } },
    ]);
  }
  if (/\/federations\/[^/]+$/.test(path) && method !== "GET") {
    return answer(null);
  }
  if (path.endsWith("/federations")) {
    return answer([
      { alias: "corp-ldap", enabled: true, priority: 10, configs: {
        url: { Str: "ldaps://directory.example:636" }, bind_dn: { Str: "cn=reader,dc=example,dc=test" },
        users_dn: { Str: "ou=people,dc=example,dc=test" }, user_filter: { Str: "(uid={username})" },
        username_attribute: { Str: "uid" }, email_attribute: { Str: "mail" },
        first_name_attribute: { Str: "givenName" }, last_name_attribute: { Str: "sn" },
      } },
      { alias: "legacy-ad", enabled: false, priority: 20, configs: {
        url: { Str: "ldaps://legacy.example:636" }, bind_dn: { Str: "cn=sync,dc=legacy,dc=test" },
        users_dn: { Str: "ou=users,dc=legacy,dc=test" }, user_filter: { Str: "(sAMAccountName={username})" },
        username_attribute: { Str: "sAMAccountName" }, email_attribute: { Str: "mail" },
        first_name_attribute: { Str: "givenName" }, last_name_attribute: { Str: "sn" },
      } },
    ]);
  }
  if (/\/agents\/[^/]+$/.test(path) && method !== "GET") {
    return answer({
      client_id: "deploy-bot", name: "deploy-bot", enabled: true,
      capabilities: ["deploy:read", "audit:read"], session_seconds: 900,
      keyed: false, not_before: null,
    });
  }
  if (path.endsWith("/agents") && method !== "GET") {
    return answer({
      client_id: "deploy-bot", name: "deploy-bot", enabled: true,
      capabilities: ["deploy:read"], session_seconds: 900,
      keyed: false, not_before: null,
    });
  }
  if (path.endsWith("/agents")) {
    return answer([
      {
        client_id: "deploy-bot", name: "deploy-bot", enabled: true,
        capabilities: ["deploy:read", "audit:read"], session_seconds: 900,
        keyed: false, not_before: null,
      },
    ]);
  }
  if (path.endsWith("/spnego") && method === "DELETE") return answer(undefined);
  if (path.endsWith("/spnego") && method !== "GET") {
    return answer({ realm_id: "main", enabled: true, configs: { service_principal: { Str: "HTTP/id.example@EXAMPLE.ORG" } } });
  }
  if (path.endsWith("/spnego")) {
    return answer({ realm_id: "main", enabled: true, configs: { service_principal: { Str: "HTTP/id.example@EXAMPLE.ORG" } } });
  }
  if (path.endsWith("/iga/rules")) {
    return answer([
      { rule_id: "ru-1", when_attribute: "department", when_value: "finance", when_expr: null, roles: ["r-1"], priority: 10, enabled: true },
      { rule_id: "ru-2", when_attribute: null, when_value: null, when_expr: "department=eng && clearance!=none", roles: ["r-2", "r-3"], priority: 20, enabled: true },
    ]);
  }
  if (/\/iga\/grants\/[^/]+$/.test(path)) {
    return answer([
      { role_id: "auditor", rule_id: "ru-1", expires_at: null },
      { role_id: "contractor-access", rule_id: null, expires_at: new Date(Date.now() + 86_400_000 * 9).toISOString() },
    ]);
  }
  if (path.endsWith("/journal/anchors")) {
    return answer({ anchors: [
      { seq: 38, head_hash: "ab12", witness: "https://witness.example/log", receipt: "r-2026-09-01", anchored_at: NOW - 86_000 },
    ] });
  }
  if (path.endsWith("/rebac/schema") && method === "PUT") {
    return answer(null);
  }
  if (path.endsWith("/rebac/schema")) {
    return answer({
      revision: 4,
      format: 1,
      source:
        "definition user {}\n\ndefinition group {\n    relation member: user | group#member\n}\n\n" +
        "definition folder {\n    relation viewer: user | group#member\n    permission view = viewer\n}\n\n" +
        "definition document {\n    relation parent: folder\n    relation owner: user\n" +
        "    relation viewer: user | group#member\n    permission view = viewer + owner + view from parent\n}\n",
    });
  }
  if (path.includes("/rebac/relations?")) {
    return answer([
      { subject_type: "user", subject_id: "ada", subject_relation: "" },
      { subject_type: "group", subject_id: "editors", subject_relation: "member" },
    ]);
  }
  if (path.endsWith("/authz/evaluate")) {
    return answer({
      decision_id: "d-sim-1",
      reported: "deny",
      computed: "deny",
      // The engine tags a reason inside the record, kebab-cased, and names
      // the policy it is about beside it. A fixture in another shape is a
      // page that renders here and not against the server.
      detail: {
        reasons: [
          { reason: "empty-binding", policy_id: "p-editors", kind: "role" },
          { reason: "dangling-condition", policy_id: "p-hours", condition: "office-hours" },
        ],
      },
      // A relationship question also carries where the walk went, which is
      // what the resolution tree renders.
      walk: {
        reached: true,
        stopped: null,
        cut: 0,
        steps: [
          { depth: 0, asked: "document:minutes#view", rule: "any: one part is enough", answered: true, note: null },
          { depth: 1, asked: "document:minutes#viewer", rule: "direct: the edges stored against this relation", answered: false, note: null },
          { depth: 1, asked: "document:minutes#owner", rule: "direct: the edges stored against this relation", answered: false, note: null },
          { depth: 1, asked: "document:minutes#parent", rule: "arrow: follow a relation, then ask there", answered: true, note: null },
          { depth: 2, asked: "folder:archive#view", rule: "computed: another member of the same object", answered: true, note: null },
          { depth: 3, asked: "folder:archive#viewer", rule: "direct: the edges stored against this relation", answered: true, note: null },
          { depth: 4, asked: "group:editors#member", rule: "direct: the edges stored against this relation", answered: true, note: null },
        ],
      },
    });
  }
  if (path.includes("/events/dead")) {
    return answer([
      { event_id: 812, kind: "user.updated", user_id: "mira", attempts: 8,
        occurred_at: new Date((NOW - 5400) * 1000).toISOString() },
    ]);
  }
  if (path.includes("/authz/decisions/disagreements")) {
    return answer([
      decided("d-9", "ada", "export", "invoice", "2026-08", "permit", "deny", 8),
      decided("d-7", "marchetti", "read", "invoice", "2026-07", "permit", "deny", 240),
    ]);
  }
  if (path.includes("/authz/decisions")) {
    return answer([
      decided("d-9", "ada", "export", "invoice", "2026-08", "permit", "deny", 8),
      decided("d-8", "ada", "read", "doc archive", null, "permit", "permit", 61),
      decided("d-7", "marchetti", "read", "invoice", "2026-07", "permit", "deny", 240),
      decided("d-6", "ledger", "viewer", "document", "2026-08", "deny", "deny", 900),
    ]);
  }
  if (/\/authz\/servers\/[^/]+\/(policies|resources|scopes)\/[^/]+$/.test(path)) {
    return answer(null);
  }
  if (/\/authz\/servers\/[^/]+\/policies$/.test(path)) {
    return answer([
      { policy_id: "p-editors", name: "editors", description: "Holds the editor role", policy_type: "role", policies: [], resources: [], scopes: [], decision: "unanimous", logic: "positive", policy_owner: "web-dashboard", roles: ["editor"] },
      { policy_id: "p-hours", name: "office hours", description: "Mon to Fri, 08:00 to 19:00", policy_type: "time", policies: [], resources: [], scopes: [], decision: "unanimous", logic: "positive", policy_owner: "web-dashboard" },
      { policy_id: "p-org", name: "acting for acme", description: "", policy_type: "organization", policies: [], resources: [], scopes: [] },
      { policy_id: "p-gate", name: "edit archive", description: "All of the above, against the archive", policy_type: "aggregated", policies: ["p-editors", "p-hours", "p-org"], resources: ["res-1"], scopes: ["sc-1"] },
    ]);
  }
  if (/\/authz\/servers\/[^/]+\/resources$/.test(path)) {
    return answer([{ resource_id: "res-1", name: "doc archive", user_managed_access: true }]);
  }
  if (/\/authz\/servers\/[^/]+\/scopes$/.test(path)) {
    return answer([{ scope_id: "sc-1", name: "edit" }]);
  }
  if (path.endsWith("/auth/flows/f-stepup")) {
    return answer({
      flow: { flow_id: "f-stepup", alias: "step-up", description: "Second factor on demand", top_level: false, built_in: false },
      executions: [
        { execution_id: "y-1", alias: "Authenticator app", flow_id: "f-stepup", priority: 10,
          step: { kind: "authenticator", authenticator: "totp", config_id: null }, requirement: "alternative" },
        { execution_id: "y-2", alias: "Texted code", flow_id: "f-stepup", priority: 20,
          step: { kind: "authenticator", authenticator: "sms-otp", config_id: null }, requirement: "alternative" },
        { execution_id: "y-3", alias: "Recovery code", flow_id: "f-stepup", priority: 30,
          step: { kind: "authenticator", authenticator: "recovery-code", config_id: null }, requirement: "alternative" },
      ],
    });
  }
  if (/\/auth\/flows\/[^/]+$/.test(path)) {
    return answer({
      flow: { flow_id: "f-browser", alias: "browser", description: "The realm's own sign-in", top_level: true, built_in: true },
      executions: [
        { execution_id: "x-1", alias: "Password", flow_id: "f-browser", priority: 10,
          step: { kind: "authenticator", authenticator: "password", config_id: null }, requirement: "required" },
        { execution_id: "x-2", alias: "Authenticator app", flow_id: "f-browser", priority: 20,
          step: { kind: "authenticator", authenticator: "totp", config_id: null }, requirement: "alternative" },
        { execution_id: "x-3", alias: "Security key", flow_id: "f-browser", priority: 30,
          step: { kind: "authenticator", authenticator: "webauthn", config_id: null }, requirement: "alternative" },
        { execution_id: "x-4", alias: "Mailed link", flow_id: "f-browser", priority: 40,
          step: { kind: "authenticator", authenticator: "magic-link", config_id: null }, requirement: "disabled" },
        { execution_id: "x-5", alias: "Step up", flow_id: "f-browser", priority: 50,
          step: { kind: "sub_flow", flow_id: "f-stepup" }, requirement: "required" },
      ],
    });
  }
  if (path.endsWith("/page-keys")) {
    return answer({
      keys: [
        { name: "login-title", en: "Sign in", fr: "Connexion" },
        { name: "login-username", en: "Username", fr: "Identifiant" },
        { name: "signup-invite", en: "New here?", fr: "Premiere visite ?" },
      ],
    });
  }
  if (path.endsWith("/preview-token")) {
    return answer({
      scope: "openid profile",
      claims: [
        { claim: "department", value: "engineering", origin: "department", lands_in: "both" },
        { claim: "name", value: "Ada Lovelace", origin: "full name", lands_in: "identity" },
      ],
    });
  }
  if (path.endsWith("/auth/required-actions")) {
    return answer([
      {
        action_id: "ra-1",
        provider_id: "totp",
        action: "configure-totp",
        name: "configure-totp",
        display_name: "Configure authenticator app",
        description: "",
        enabled: true,
        default_action: false,
        on_time_action: null,
        priority: 10,
      },
    ]);
  }
  if (path.endsWith("/auth/flows") && method === "POST") {
    return answer({ flow_id: "f-new", alias: "made", description: "", top_level: true, built_in: false });
  }
  if (/\/auth\/flows\/[^/]+$/.test(path) && method === "DELETE") {
    return answer(null);
  }
  if (path.endsWith("/auth/flows")) {
    return answer([
      { flow_id: "f-browser", alias: "browser", description: "The realm's own sign-in", top_level: true, built_in: true },
      { flow_id: "f-stepup", alias: "step-up", description: "Second factor on demand", top_level: false, built_in: false },
    ]);
  }
  if (path.includes("/sign-in-events")) {
    const row = (id: number, kind: string, user: string, ip: string, ago: number) => ({
      id, recorded_at: NOW - ago, kind, user_id: user, client_id: "web-dashboard",
      session_id: "s-" + id, ip, user_agent: "Mozilla/5.0", detail: null,
    });
    return answer({
      items: [
        row(3, "signed_in", "ada", "203.0.113.9", 120),
        row(2, "sign_in_failed", "grace", "198.51.100.7", 300),
        row(1, "signed_out", "linus", "203.0.113.9", 900),
      ],
      first: 0, max: 25, total: 3,
    });
  }
  if (path.endsWith("/ussd")) {
    return answer({ has_secret: true });
  }
  if (path.endsWith("/sms")) {
    return answer({ url: "https://api.orange.tg/v1/sms", sender: "SAFFUI", has_token: false });
  }
  if (path.endsWith("/overview")) {
    return answer({
      users: 1284,
      clients: 12,
      sessions: 217,
      pending_requests: 3,
      queue: 0,
      slow_tail_millis: 42,
    });
  }
  if (path === "/admin/features") {
    return answer([
      { slug: "kerberos", lifecycle: "stable", compiled: false, enabled: false, doc: "SPNEGO desktop tickets at the LDAP front; links the system Kerberos libraries." },
      { slug: "embedded-admin", lifecycle: "stable", compiled: true, enabled: true, doc: "This console, served from inside the binary under /console." },
      { slug: "fapi2", lifecycle: "preview", compiled: true, enabled: false, doc: "The FAPI 2.0 security profile gates, per client." },
    ]);
  }
  if (path.endsWith("/registration-secret")) {
    return answer({ registration_secret: "preview-secret-drawn-once" });
  }
  if (path === "/admin/realms" && method === "POST") {
    // A birth, answered the way the plane answers one: the realm, and the
    // credential that opens it, readable here and nowhere afterwards.
    return answer({
      realm_id: "annex",
      name: "annex",
      display_name: "Annex",
      enabled: true,
      administrator: {
        user_name: "root",
        password: "8Qm2vXpLd0RhTsYb_cN4jWkE6zAuFgH1iOoP3-eSrVc",
      },
    });
  }
  if (path === "/admin/realms" || path.startsWith("/admin/realms?")) {
    const rows = [
      { realm_id: "main", name: "main", display_name: "Main", enabled: true },
      { realm_id: "staging", name: "staging", display_name: "Staging", enabled: true },
      { realm_id: "sunset", name: "sunset", display_name: "Legacy", enabled: false },
    ];
    return answer({ items: rows, first: 0, max: rows.length, total: rows.length });
  }
  if (/\/admin\/realms\/[^/?]+(\?.*)?$/.test(path)) {
    // GET and PUT both land here in preview: the same settings document,
    // which is exactly what the real PUT answers back.
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
      acr_loa_map: { mfa: 2 },
      events_enabled: true,
      admin_events_enabled: false,
      otp_policy: null,
      webauthn_policy: null,
      mail_templates: null,
      device_code_lifespan: null,
      device_poll_interval: null,
      browser_flow: null,
      supported_locales: null,
      default_locale: null,
      attributes: { support: "it@acme.example" },
      refresh_token_lifespan: null,
      session_max_lifespan: 0,
      access_code_lifespan_user_action: null,
      password_policy: {
        min_length: 12,
        max_length: null,
        min_digits: 1,
        min_upper_case: 1,
        min_lower_case: null,
        min_special_chars: null,
        not_email: true,
        not_username: true,
        not_birthdate: false,
        blacklisted: ["acme", "saffui"],
        regex_pattern: null,
        expires_after_days: null,
        history_look_back: 3,
        hashing: { m_cost: 19456, t_cost: 2, p_cost: 1, output_len: 32 },
      },
      brute_force: {
        protected: true,
        max_failures: 5,
        lockout_seconds: 60,
        max_lockout_seconds: 900,
        reset_seconds: 900,
      },
    });
  }
  throw new ApiError(404, "the preview world does not hold this");
}
