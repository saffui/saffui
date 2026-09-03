import { adminPath, api } from "@/services/http";
import { say } from "@/i18n";
import type { Page } from "@/models/paging";
import type { RealmSessionBrief } from "@/models/session";

/// Every login open in this realm, newest first, one page at a time.
export async function listRealmSessions(
  realm: string,
  first: number,
  max: number,
): Promise<Page<RealmSessionBrief>> {
  return api<Page<RealmSessionBrief>>(
    adminPath(realm, `sessions?first=${first}&max=${max}`),
  );
}

/// End every login in this realm. Half of a revocation: the tokens already
/// handed out live out their span until the realm's cut is struck too.
export async function endRealmSessions(realm: string): Promise<number> {
  const told = await api<{ ended: number }>(adminPath(realm, "sessions"), {
    method: "DELETE",
    subject: say("subject-realm-sessions", { realm }),
  });
  return told.ended;
}
