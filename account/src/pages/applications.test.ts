import { beforeEach, describe, expect, test, vi } from "vitest";

const calls = vi.hoisted(() => ({
  withdrawConsent: vi.fn(async (_realm: string, _client: string) => {}),
  takeBackAccess: vi.fn(async (_realm: string, _client: string) => ({ ended_grants: 2 })),
}));

vi.mock("@/services/applications", () => ({
  withdrawConsent: calls.withdrawConsent,
  takeBackAccess: calls.takeBackAccess,
}));

import type { HeldApplication } from "@/services/applications";
import { ApiError } from "@/services/http";
import { carryOutGesture, composeConfirmation, describeScope } from "./applications";

const GRAFANA: HeldApplication = {
  client_id: "grafana",
  name: "Grafana",
  home: "https://grafana.example",
  consent: { scopes: ["openid", "email"], granted_at: "2026-09-01T10:00:00Z", asks_consent: true },
  access: { logins: 2, offline: true, expiration: null },
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("a scope", () => {
  test("is said by what it lets an application have, or by its name when unknown", () => {
    expect(describeScope("email")).toBe("Your email address");
    expect(describeScope("offline_access")).toBe("Access while you are away");
    expect(describeScope("reports:read")).toBe("reports:read");
  });
});

describe("the words before a gesture", () => {
  test("say that a withdrawn consent is asked for again where the application asks", () => {
    const asked = composeConfirmation({ kind: "withdraw-consent", application: GRAFANA });
    expect(asked.title).toBe("Withdraw your consent to Grafana?");
    expect(asked.body).toMatch(/asks for your agreement again/);
    const unasked = composeConfirmation({
      kind: "withdraw-consent",
      application: { ...GRAFANA, consent: { ...GRAFANA.consent!, asks_consent: false } },
    });
    expect(unasked.body).toMatch(/does not ask for agreement/);
  });

  test("say what taking back access leaves standing", () => {
    const words = composeConfirmation({ kind: "take-back-access", application: GRAFANA });
    expect(words.title).toBe("Take back Grafana's access?");
    expect(words.body).toMatch(/from all your sign-ins, offline access included/);
    expect(words.body).toMatch(/Your consent stays/);
  });
});

describe("a gesture on an application", () => {
  test("withdraws only the consent", async () => {
    await expect(
      carryOutGesture("main", { kind: "withdraw-consent", application: GRAFANA }),
    ).resolves.toEqual({ tone: "ok", text: "Your consent to Grafana is withdrawn." });
    expect(calls.withdrawConsent).toHaveBeenCalledWith("main", "grafana");
    expect(calls.takeBackAccess).not.toHaveBeenCalled();
  });

  test("takes back only the access, and says from how many sign-ins", async () => {
    await expect(
      carryOutGesture("main", { kind: "take-back-access", application: GRAFANA }),
    ).resolves.toEqual({
      tone: "ok",
      text: "Grafana no longer holds access through 2 of your sign-ins.",
    });
    expect(calls.takeBackAccess).toHaveBeenCalledWith("main", "grafana");
    expect(calls.withdrawConsent).not.toHaveBeenCalled();
  });

  test("something already gone is said calmly, and a failure is said plainly", async () => {
    calls.withdrawConsent.mockRejectedValueOnce(new ApiError(404, "gone", "auth.consent.not_found"));
    await expect(
      carryOutGesture("main", { kind: "withdraw-consent", application: GRAFANA }),
    ).resolves.toEqual({ tone: "ok", text: "That was already done. The list is up to date." });
    calls.takeBackAccess.mockRejectedValueOnce(new ApiError(500, "broken", "internal_error"));
    await expect(
      carryOutGesture("main", { kind: "take-back-access", application: GRAFANA }),
    ).resolves.toMatchObject({ tone: "danger" });
  });
});
