import { describe, expect, test } from "vitest";
import {
  advanceBreach,
  assembleEvidencePack,
  breachNotificationDraft,
  discoverBreach,
  fulfilSubjectRequest,
  listBreaches,
  listSubjectRequests,
  lodgeSubjectRequest,
  refuseSubjectRequest,
  verifySubjectRequest,
} from "@/services/compliance";
import { keepAnswer, REALM } from "./answers";

// Planted by the server's contract test.
const ADA = "ada";

describe("privacy", () => {
  test("proves and fulfils an access request, and refuses an objection", async () => {
    const access = await keepAnswer(lodgeSubjectRequest, REALM, {
      subject_identifier: ADA,
      kind: "access",
      jurisdiction: "eu",
    });
    await keepAnswer(verifySubjectRequest, REALM, access.request_id);
    const fulfilled = await keepAnswer(fulfilSubjectRequest, REALM, access.request_id, {});
    expect(fulfilled.bundle).toBeDefined();

    const objection = await lodgeSubjectRequest(REALM, {
      subject_identifier: ADA,
      kind: "objection",
      jurisdiction: "eu",
    });
    await keepAnswer(refuseSubjectRequest, REALM, objection.request_id, "Held under contract");
    const requests = await keepAnswer(listSubjectRequests, REALM);
    expect(requests.length).toBeGreaterThan(1);
  });

  test("takes a breach from discovery through filing to its close", async () => {
    const breach = await keepAnswer(discoverBreach, REALM, {
      description: "A contract breach",
      data_categories: ["email"],
      severity: "medium",
      jurisdiction: "eu",
    });
    await keepAnswer(advanceBreach, REALM, breach.breach_id, "assess", {
      severity: "high",
      subjects_affected: 1,
    });
    await keepAnswer(breachNotificationDraft, REALM, breach.breach_id);
    await keepAnswer(advanceBreach, REALM, breach.breach_id, "filing", {
      notified_to: "the supervisory authority",
      filed_by: ADA,
    });
    await keepAnswer(advanceBreach, REALM, breach.breach_id, "close");
    const breaches = await keepAnswer(listBreaches, REALM);
    expect(breaches.some((held) => held.breach_id === breach.breach_id)).toBe(true);
  });

  test("assembles the evidence pack of a day", async () => {
    const now = Math.floor(Date.now() / 1000);
    await keepAnswer(assembleEvidencePack, REALM, now - 86_400, now);
  });
});
