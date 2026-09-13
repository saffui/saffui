import { describe, expect, test } from "vitest";
import { createRole, deleteRole } from "@/services/directory";
import { listIgaGrants, listIgaRules } from "@/services/federation";
import {
  activateCampaign,
  approveRequest,
  closeCampaign,
  convergeRules,
  createRule,
  decideItem,
  deleteRule,
  deleteSodException,
  deleteSodRule,
  denyRequest,
  handGrant,
  listCampaignItems,
  listCampaigns,
  listRequests,
  listSodExceptions,
  listSodRules,
  listSodViolations,
  lodgeRequest,
  openCampaign,
  putSodException,
  putSodRule,
  readReport,
  revokeGrant,
  updateRule,
  withdrawRequest,
} from "@/services/governance";
import { createUser, deleteUser, grantRoleToUser, revokeRoleFromUser } from "@/services/users";
import { keepAnswer, REALM } from "./answers";

// Planted by the server's contract test.
const ADA = "ada";
const SOD_RULE = "contract-sod";

function aDayFromNow(): string {
  return new Date(Date.now() + 86_400_000).toISOString();
}

async function makeRole(name: string) {
  return createRole(REALM, { name, display_name: name, description: "" });
}

async function makePerson(name: string) {
  return createUser(REALM, { user_name: name, email: `${name}@example.test`, enabled: true });
}

describe("governance", () => {
  test("keeps an attribute rule, converges, and removes it", async () => {
    const role = await makeRole("contract-finance");
    const rule = {
      when_attribute: "department",
      when_value: "finance",
      roles: [role.role_id],
      enabled: true,
    };
    await createRule(REALM, rule);
    const kept = (await keepAnswer(listIgaRules, REALM)).find(
      (held) => held.when_value === "finance",
    );
    if (!kept) throw new Error("the rule did not read back");
    await updateRule(REALM, kept.rule_id, { ...rule, enabled: false });
    await convergeRules(REALM);
    await deleteRule(REALM, kept.rule_id);
    await deleteRole(REALM, role.role_id);
  });

  test("hands a grant with an end and revokes it", async () => {
    const role = await makeRole("contract-temporary");
    await handGrant(REALM, { user_id: ADA, role_id: role.role_id, expires_at: aDayFromNow() });
    const grants = await keepAnswer(listIgaGrants, REALM, ADA);
    expect(grants.some((grant) => grant.role_id === role.role_id)).toBe(true);
    await revokeGrant(REALM, ADA, role.role_id);
    await deleteRole(REALM, role.role_id);
  });

  test("finds a separation of duties broken, excuses it, and removes the rule", async () => {
    const left = await makeRole("contract-maker");
    const right = await makeRole("contract-checker");
    const person = await makePerson("contract-both");
    await grantRoleToUser(REALM, left.role_id, person.user_id);
    await grantRoleToUser(REALM, right.role_id, person.user_id);
    await putSodRule(REALM, SOD_RULE, {
      roles: [left.role_id, right.role_id],
      min_conflicting: 2,
      enabled: true,
    });
    await keepAnswer(listSodRules, REALM);
    const violations = await keepAnswer(listSodViolations, REALM);
    expect(violations.some((violation) => violation.user_id === person.user_id)).toBe(true);

    await putSodException(REALM, SOD_RULE, person.user_id, {
      covered_roles: [left.role_id, right.role_id],
      justification: "Held under contract",
      valid_until: aDayFromNow(),
    });
    const exceptions = await keepAnswer(listSodExceptions, REALM);
    expect(exceptions.some((exception) => exception.user_id === person.user_id)).toBe(true);
    await deleteSodException(REALM, SOD_RULE, person.user_id);

    await revokeRoleFromUser(REALM, left.role_id, person.user_id);
    await revokeRoleFromUser(REALM, right.role_id, person.user_id);
    await deleteSodRule(REALM, SOD_RULE);
    await deleteUser(REALM, person.user_id);
    await deleteRole(REALM, left.role_id);
    await deleteRole(REALM, right.role_id);
  });

  test("lodges access requests, is refused deciding its own, and withdraws them", async () => {
    const role = await makeRole("contract-requested");
    const person = await makePerson("contract-requester");
    const lodge = async () => {
      const before = new Set((await listRequests(REALM)).map((held) => held.request_id));
      await lodgeRequest(REALM, {
        user_id: person.user_id,
        role_id: role.role_id,
        reason: "Needed under contract",
      });
      const lodged = (await keepAnswer(listRequests, REALM)).find(
        (held) => !before.has(held.request_id),
      );
      if (!lodged) throw new Error("the request did not read back");
      return lodged.request_id;
    };
    // One administrator holds the token, and four eyes need two: the refusal
    // still proves each door took its path and its body.
    const own = await lodge();
    await expect(approveRequest(REALM, own)).rejects.toMatchObject({ status: 422 });
    await expect(denyRequest(REALM, own, "Not needed")).rejects.toMatchObject({ status: 422 });
    await withdrawRequest(REALM, own);

    await deleteUser(REALM, person.user_id);
    await deleteRole(REALM, role.role_id);
  });

  test("runs a certification campaign over one role to its report", async () => {
    const role = await makeRole("contract-reviewed");
    const person = await makePerson("contract-reviewee");
    await grantRoleToUser(REALM, role.role_id, person.user_id);
    await openCampaign(REALM, {
      name: "contract-review",
      scope_kind: "role",
      scope_ref: role.role_id,
      reviewer_id: ADA,
    });
    const campaign = (await keepAnswer(listCampaigns, REALM)).find(
      (held) => held.name === "contract-review",
    );
    if (!campaign) throw new Error("the campaign did not read back");
    await activateCampaign(REALM, campaign.campaign_id);
    const items = await keepAnswer(listCampaignItems, REALM, campaign.campaign_id);
    expect(items.length).toBeGreaterThan(0);
    for (const item of items) {
      await decideItem(REALM, campaign.campaign_id, item.item_id, { decision: "certify" });
    }
    await closeCampaign(REALM, campaign.campaign_id);
    const report = await keepAnswer(readReport, REALM, campaign.campaign_id);
    expect(report.length).toBeGreaterThan(0);

    await revokeRoleFromUser(REALM, role.role_id, person.user_id);
    await deleteUser(REALM, person.user_id);
    await deleteRole(REALM, role.role_id);
  });
});
