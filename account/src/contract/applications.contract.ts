import { describe, expect, test } from "vitest";
import { listApplications, takeBackAccess, withdrawConsent } from "@/services/applications";
import { keepAnswer, REALM } from "./answers";

describe("the applications that hold something of the person", () => {
  test("lists what the person agreed to and what applications hold, and no console", async () => {
    const applications = await keepAnswer(listApplications, REALM);
    expect(applications.map((application) => application.client_id)).not.toContain(
      "account-console",
    );
    expect(applications.some((application) => application.consent !== null)).toBe(true);
    expect(applications.some((application) => application.access !== null)).toBe(true);
  });

  test("withdraws a consent once", async () => {
    const agreed = (await listApplications(REALM)).find((application) => application.consent);
    if (!agreed) throw new Error("the world holds no consent");
    await withdrawConsent(REALM, agreed.client_id);
    await expect(withdrawConsent(REALM, agreed.client_id)).rejects.toMatchObject({
      status: 404,
      code: "auth.consent.not_found",
    });
  });

  test("takes back what an application got, and says how many grants went", async () => {
    const online = (await listApplications(REALM)).find(
      (application) => application.access && !application.access.offline,
    );
    if (!online) throw new Error("the world holds no online grant");
    const ended = await keepAnswer(takeBackAccess, REALM, online.client_id);
    expect(ended.ended_grants).toBe(1);
    await expect(takeBackAccess(REALM, online.client_id)).rejects.toMatchObject({
      status: 404,
      code: "auth.grant.not_found",
    });
  });
});
