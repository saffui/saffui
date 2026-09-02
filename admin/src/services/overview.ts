import { adminPath, api, ApiError } from "@/services/http";
import { listJournal, verifyChain } from "@/services/journal";
import type { ChainVerified, JournalEntry } from "@/models/journal";
import type { Page } from "@/models/paging";
import type { RealmKeys } from "@/models/keys";
import type { MailBrief } from "@/models/mail";
import type { RealmSettings } from "@/models/realm";

/// One row of a collection plus the paid-for count: the cheapest honest way
/// to say "how many" over a paged listing.
async function countOf(realm: string, leaf: string): Promise<number | null> {
  const page = await api<Page<unknown>>(`${adminPath(realm, leaf)}?max=1&count=true`);
  return page.total;
}

export interface OverviewNumbers {
  users: number | null;
  clients: number | null;
  organizations: number | null;
  signingKeys: number;
}

export interface Attention {
  /// A short, factual sentence; the message key is the page's business.
  what: "no-signing-key" | "no-mail" | "open-registration";
  /// Where fixing it lives, as a console path under the realm.
  where: string;
}

export interface OverviewTold {
  numbers: OverviewNumbers;
  attention: Attention[];
  /// The newest journal entries, and whether the chain verifies whole.
  journal: JournalEntry[];
  chain: ChainVerified | null;
}

export async function readOverview(realm: string): Promise<OverviewTold> {
  // The journal needs its own capability; an operator without it still gets
  // the rest of the page rather than an error.
  const quietly = <T>(asked: Promise<T>): Promise<T | null> =>
    asked.catch((refused: unknown) => {
      if (refused instanceof ApiError && refused.status < 500) return null;
      throw refused;
    });
  const [users, clients, organizations, keys, mail, settings, journal, chain] =
    await Promise.all([
      countOf(realm, "users"),
      countOf(realm, "clients"),
      countOf(realm, "organizations"),
      api<RealmKeys>(adminPath(realm, "keys")),
      quietly(api<MailBrief>(adminPath(realm, "mail"))),
      api<RealmSettings>(`/admin/realms/${encodeURIComponent(realm)}`),
      quietly(listJournal(realm, 0, 5)),
      quietly(verifyChain(realm)),
    ]);

  const attention: Attention[] = [];
  if (keys.signing.length === 0) {
    attention.push({ what: "no-signing-key", where: "keys" });
  }
  if (mail === null || !mail.host) {
    attention.push({ what: "no-mail", where: "settings" });
  }
  if (
    settings.client_registration === "open" &&
    settings.registration_bounds.trusted_hosts.length === 0
  ) {
    attention.push({ what: "open-registration", where: "settings" });
  }

  return {
    numbers: {
      users,
      clients,
      organizations,
      signingKeys: keys.signing.length,
    },
    attention,
    journal: journal?.items ?? [],
    chain,
  };
}
