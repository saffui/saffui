import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { evaluate } = await import("@/services/authz");

afterEach(() => vi.unstubAllGlobals());

describe("authorization evaluator transport", () => {
  test("keeps RBAC, ABAC and ReBAC questions in the backend contract", async () => {
    const fetch = vi.fn().mockImplementation(
      () => new Response(
        JSON.stringify({
          decision_id: "d-1",
          reported: "deny",
          computed: "deny",
          detail: { reasons: [] },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetch);

    await evaluate("north/east", "user-1", {
      kind: "policy",
      server_id: "client/1",
      policy_id: "policy-rbac",
    });
    await evaluate("north/east", "user-1", {
      kind: "policy",
      server_id: "client/1",
      policy_id: "policy-abac",
    });
    await evaluate("north/east", "user-1", {
      kind: "relationship",
      object_type: "document",
      object_id: "doc/1",
      relation: "viewer",
    });

    expect(fetch).toHaveBeenCalledTimes(3);
    expect(fetch).toHaveBeenNthCalledWith(
      1,
      "/admin/realms/north%2Feast/authz/evaluate",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          subject: "user-1",
          question: { kind: "policy", server_id: "client/1", policy_id: "policy-rbac" },
        }),
      }),
    );
    expect(fetch).toHaveBeenNthCalledWith(
      3,
      "/admin/realms/north%2Feast/authz/evaluate",
      expect.objectContaining({
        body: JSON.stringify({
          subject: "user-1",
          question: {
            kind: "relationship",
            object_type: "document",
            object_id: "doc/1",
            relation: "viewer",
          },
        }),
      }),
    );
  });
});
