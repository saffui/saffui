import { beforeAll, describe, expect, test } from "vitest";
import type { JournalEntry } from "@/models/journal";
import { createRole, deleteRole } from "@/services/directory";
import { listDeadLetters } from "@/services/events";
import {
  activateCampaign,
  closeCampaign,
  listCampaigns,
  openCampaign,
} from "@/services/governance";
import { listJournal, verifyChain } from "@/services/journal";
import { countOf, readBusinessMetrics, readOverview } from "@/services/overview";
import { listRealms } from "@/services/realms";
import { listRealmSessions } from "@/services/sessions";
import { getRealmSettings, reshapeRealm } from "@/services/settings";
import { keepAnswer, REALM } from "./answers";

const JOURNALLED = "contract-journalled";

/// Closes a campaign over a role nobody holds, so the newest entries of the
/// chain are a closing and the requests around it, whatever file ran before.
async function closeAnEmptyCampaign() {
  const role = await createRole(REALM, { name: JOURNALLED, display_name: JOURNALLED, description: "" });
  await openCampaign(REALM, {
    name: JOURNALLED,
    scope_kind: "role",
    scope_ref: role.role_id,
    reviewer_id: "ada",
  });
  const campaign = (await listCampaigns(REALM)).find((held) => held.name === JOURNALLED);
  if (!campaign) throw new Error("the campaign did not read back");
  await activateCampaign(REALM, campaign.campaign_id);
  await closeCampaign(REALM, campaign.campaign_id);
  await deleteRole(REALM, role.role_id);
}

function kindsOf(entries: JournalEntry[]): string[] {
  return entries.map((held) => held.entry.kind);
}

describe("overview", () => {
  beforeAll(closeAnEmptyCampaign);

  test("reads the realm's overview, counts and metrics", async () => {
    const settings = await getRealmSettings(REALM);
    const users = await keepAnswer(countOf, REALM, "users");
    expect(users).toBeGreaterThan(0);
    const overview = await keepAnswer(readOverview, REALM, {
      strip: { users: users ?? 0, clients: 0, sessions: 0, pending_requests: 0 },
      settings,
    });
    expect(kindsOf(overview.journal)).toEqual(
      expect.arrayContaining(["admin.write", "governance.campaign.closed"]),
    );
    await keepAnswer(readBusinessMetrics, REALM, 3600);
  });

  test("lists realms, the journal and its chain, logins and dead letters", async () => {
    const realms = await keepAnswer(listRealms);
    expect(realms.some((realm) => realm.realm_id === REALM)).toBe(true);

    await reshapeRealm(REALM, { display_name: "Main, journalled" }, "realm");
    const journal = await keepAnswer(listJournal, REALM, 0, 20);
    expect(kindsOf(journal.items)).toEqual(
      expect.arrayContaining(["admin.write", "governance.campaign.closed"]),
    );
    const chain = await keepAnswer(verifyChain, REALM);
    expect(chain.holds).toBe(true);

    const sessions = await keepAnswer(listRealmSessions, REALM, 0, 20);
    expect(sessions.items.length).toBeGreaterThan(0);
    await keepAnswer(listDeadLetters, REALM);
  });
});
