import { afterEach, describe, expect, test, vi } from "vitest";

const asked: string[] = [];
let metricsFeatureEnabled = true;

vi.mock("@/services/http", () => ({
  adminPath: (realm: string, leaf: string) => `/admin/realms/${realm}/${leaf}`,
  api: async (path: string) => {
    asked.push(path);
    if (path.endsWith("/keys")) return { signing: [] };
    if (path.endsWith("/mail")) return { host: "", port: 0, has_password: false, implicit_tls: true };
    if (path.endsWith("/sms")) return { url: null, has_token: false };
    if (path.endsWith("/ussd")) return { has_secret: false };
    if (path.includes("/sign-in-events")) return { items: [], first: 0, max: 7, total: 0 };
    if (path.endsWith("/features")) return { items: [{ slug: "metrics", enabled: metricsFeatureEnabled }] };
    if (path.endsWith("/metrics")) {
      return {
        window_seconds: 86400,
        since: "2026-09-11T00:00:00Z",
        decisions: {
          total: 2,
          permits: 1,
          denials: 1,
          indeterminate: 1,
          disagreements: 1,
          average_duration_us: 200,
          p95_duration_us: 290,
        },
        logins: {
          total: 1,
          signed_in: 1,
          sign_in_failed: 0,
          signed_out: 0,
          sms_throttled: 0,
        },
      };
    }
    throw new Error(`unexpected path: ${path}`);
  },
}));

vi.mock("@/services/journal", () => ({
  listJournal: async () => ({ items: [] }),
  verifyChain: async () => ({ holds: true, entries: 0, broken_at: null }),
}));

const { readOverview } = await import("./overview");

afterEach(() => {
  asked.length = 0;
  metricsFeatureEnabled = true;
  vi.restoreAllMocks();
});

describe("overview business metrics", () => {
  test("reads the realm metrics endpoint with the other overview data", async () => {
    const told = await readOverview("main", {
      strip: { users: 1, clients: 1, sessions: 1, pending_requests: 0 },
      settings: {
        client_registration: "closed",
        registration_bounds: { trusted_hosts: [] },
        verify_email: false,
        reset_password_allowed: false,
      } as never,
    });

    expect(asked).toContain("/admin/realms/main/metrics");
    expect(told.businessMetrics?.decisions.p95_duration_us).toBe(290);
  });

  test("does not ask for metrics while the realm feature is off", async () => {
    metricsFeatureEnabled = false;

    const told = await readOverview("main", {
      strip: { users: 1, clients: 1, sessions: 1, pending_requests: 0 },
      settings: {
        client_registration: "closed",
        registration_bounds: { trusted_hosts: [] },
        verify_email: false,
        reset_password_allowed: false,
      } as never,
    });

    expect(asked).not.toContain("/admin/realms/main/metrics");
    expect(told.businessMetrics).toBeNull();
  });
});
