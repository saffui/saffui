import { adminPath, api } from "@/services/http";
import type { ChainVerified, JournalPage } from "@/models/journal";

export async function listJournal(
  realm: string,
  first: number,
  max: number,
): Promise<JournalPage> {
  return api<JournalPage>(`${adminPath(realm, "journal")}?first=${first}&max=${max}`);
}

export async function verifyChain(realm: string): Promise<ChainVerified> {
  return api<ChainVerified>(adminPath(realm, "journal/verify"));
}
