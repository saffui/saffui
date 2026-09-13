import { describe, expect, test } from "vitest";
import { listDeadLetters } from "@/services/events";
import { listJournal, verifyChain } from "@/services/journal";
import { countOf, readBusinessMetrics, readOverview } from "@/services/overview";
import { listRealms } from "@/services/realms";
import { listRealmSessions } from "@/services/sessions";
import { getRealmSettings, reshapeRealm } from "@/services/settings";
import { keepAnswer, REALM } from "./answers";

describe("overview", () => {
  test("reads the realm's overview, counts and metrics", async () => {
    const settings = await getRealmSettings(REALM);
    const users = await keepAnswer(countOf, REALM, "users");
    expect(users).toBeGreaterThan(0);
    await keepAnswer(readOverview, REALM, {
      strip: { users: users ?? 0, clients: 0, sessions: 0, pending_requests: 0 },
      settings,
    });
    await keepAnswer(readBusinessMetrics, REALM, 3600);
  });

  test("lists realms, the journal and its chain, logins and dead letters", async () => {
    const realms = await keepAnswer(listRealms);
    expect(realms.some((realm) => realm.realm_id === REALM)).toBe(true);

    await reshapeRealm(REALM, { display_name: "Main, journalled" }, "realm");
    const journal = await keepAnswer(listJournal, REALM, 0, 20);
    expect(journal.items.length).toBeGreaterThan(0);
    const chain = await keepAnswer(verifyChain, REALM);
    expect(chain.holds).toBe(true);

    const sessions = await keepAnswer(listRealmSessions, REALM, 0, 20);
    expect(sessions.items.length).toBeGreaterThan(0);
    await keepAnswer(listDeadLetters, REALM);
  });
});
