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
  if (path.includes("/clients?")) {
    return answer({ items: [{}], first: 0, max: 1, total: 12 });
  }
  if (path.includes("/organizations?")) {
    return answer({ items: [{}], first: 0, max: 1, total: 2 });
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
  if (/\/admin\/realms\/[^/]+$/.test(path)) {
    return answer({
      realm_id: "main",
      name: "main",
      display_name: "Main",
      enabled: true,
      client_registration: "open",
      registration_bounds: { max_clients: null, requires_consent: false, trusted_hosts: [] },
      require_pushed_authorization_requests: false,
    });
  }
  throw new ApiError(404, "the preview world does not hold this");
}
