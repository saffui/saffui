import { adminPath, api, ApiError } from "@/services/http";
import { listRealmFeatures, listSignInEvents } from "@/services/settings";
import { listJournal, verifyChain } from "@/services/journal";
import type { ChainVerified, JournalEntry } from "@/models/journal";
import type { SignInEvent } from "@/models/events";
import type { Page } from "@/models/paging";
import type { RealmKeys } from "@/models/keys";
import type { MailBrief } from "@/models/mail";
import type { SmsBrief } from "@/models/sms";
import type { RealmSettings } from "@/models/realm";

/// One row of a collection plus the paid-for count: the cheapest honest way
/// to say "how many" over a paged listing.
/// How many rows a listing holds, paid for by the count rather than by the
/// page: `max=1` so the answer is the number and not the rows.
export async function countOf(realm: string, leaf: string): Promise<number | null> {
  const page = await api<Page<unknown>>(`${adminPath(realm, leaf)}?max=1&count=true`);
  return page.total;
}

/// What the strip shows, as the server answers it in one reading.
///
/// `slowTailMillis` is absent where the build carries no histogram, and the
/// strip then leaves the box out rather than printing a placeholder for a
/// reading that never comes.
export interface OverviewNumbers {
  users: number;
  clients: number;
  sessions: number;
  pendingRequests: number;
  slowTailMillis?: number;
}

/// One message gateway, as the console can honestly describe it.
///
/// The deck reads `up` and `degraded` on these. Nothing here probes them, so
/// nothing here claims a liveness: what is known is whether the realm has
/// configured the gateway, and what it points at.
export interface Gateway {
  which: "email" | "sms" | "ussd";
  /// Where it goes, in the gateway's own terms. Absent when unconfigured.
  at: string | null;
  /// Three states, not two. A gateway named without its credential is the
  /// quiet failure: it looks configured and fails at the first send, which
  /// nobody sees until somebody asks for a reset link.
  state: "unset" | "incomplete" | "set";
  /// What in this realm stops working while it is unset, read off settings
  /// already in hand. Empty means nothing switched on depends on it.
  needed_by: string[];
  /// Mail only: whether the connection to the server is encrypted. A password
  /// crossing in the clear belongs on the overview, not buried in settings.
  clear_text?: boolean;
}

export interface Attention {
  /// A short, factual sentence; the message key is the page's business.
  what: "no-signing-key" | "no-mail" | "open-registration";
  /// Where fixing it lives, as a console path under the realm.
  where: string;
}

export interface OverviewTold {
  numbers: OverviewNumbers;
  gateways: Gateway[];
  attention: Attention[];
  /// The newest journal entries, and whether the chain verifies whole.
  journal: JournalEntry[];
  chain: ChainVerified | null;
  signIns: Page<SignInEvent> | null;
  businessMetrics: BusinessMetrics | null;
}

export interface BusinessMetrics {
  window_seconds: number;
  since: string;
  decisions: {
    total: number;
    permits: number;
    denials: number;
    indeterminate: number;
    disagreements: number;
    average_duration_us: number | null;
    p95_duration_us: number | null;
  };
  logins: {
    total: number;
    signed_in: number;
    sign_in_failed: number;
    signed_out: number;
    sms_throttled: number;
  };
}

export async function readBusinessMetrics(realm: string, windowSeconds?: number): Promise<BusinessMetrics> {
  const query = windowSeconds === undefined ? "" : `?window_seconds=${windowSeconds}`;
  return api<BusinessMetrics>(adminPath(realm, `metrics${query}`));
}

/// The counts and the settings the strip needs, which the standing store has
/// already read for the status bar. Passing them in rather than asking again
/// is the whole point of that store: one reading per realm, not one per page
/// that happens to show the same four numbers.
export interface AlreadyRead {
  strip: {
    users: number;
    clients: number;
    sessions: number;
    pending_requests: number;
    slow_tail_millis?: number;
  };
  settings: RealmSettings;
}

export async function readOverview(
  realm: string,
  held: AlreadyRead,
): Promise<OverviewTold> {
  const { strip, settings } = held;
  // The journal needs its own capability; an operator without it still gets
  // the rest of the page rather than an error.
  const quietly = <T>(asked: Promise<T>): Promise<T | null> =>
    asked.catch((refused: unknown) => {
      if (refused instanceof ApiError && refused.status < 500) return null;
      throw refused;
    });
  const [keys, mail, sms, ussd, journal, chain, signIns, features] = await Promise.all([
    api<RealmKeys>(adminPath(realm, "keys")),
    quietly(api<MailBrief>(adminPath(realm, "mail"))),
    quietly(api<SmsBrief>(adminPath(realm, "sms"))),
    quietly(api<{ has_secret: boolean }>(adminPath(realm, "ussd"))),
    quietly(listJournal(realm, 0, 5)),
    quietly(verifyChain(realm)),
    settings.events_enabled ? quietly(listSignInEvents(realm, 0, 7)) : Promise.resolve(null),
    quietly(listRealmFeatures(realm)),
  ]);
  const businessMetrics =
    features?.some((feature) => feature.slug === "metrics" && feature.enabled)
      ? await quietly(readBusinessMetrics(realm))
      : null;

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

  // What each gateway points at, said in its own terms. A refusal reads as
  // unconfigured, which is what a realm with no such settings answers.
  const stateOf = (named: boolean, credentialled: boolean): Gateway["state"] =>
    !named ? "unset" : credentialled ? "set" : "incomplete";

  // What breaks while a gateway is missing, from settings already read. Only
  // what the realm has switched on counts: a realm that never verifies an
  // address does not need mail to do it.
  const mailNeeds = [
    settings.verify_email ? "verify-email" : null,
    settings.reset_password_allowed ? "reset-password" : null,
  ].filter((held): held is string => held !== null);

  const gateways: Gateway[] = [
    {
      which: "email",
      at: mail?.host ? `${mail.host}:${mail.port}` : null,
      state: stateOf(Boolean(mail?.host), Boolean(mail?.has_password)),
      needed_by: mailNeeds,
      clear_text: mail?.host ? !mail.implicit_tls : undefined,
    },
    {
      which: "sms",
      at: sms?.url ?? null,
      state: stateOf(Boolean(sms?.url), Boolean(sms?.has_token)),
      needed_by: [],
    },
    {
      which: "ussd",
      at: null,
      state: ussd?.has_secret ? "set" : "unset",
      needed_by: [],
    },
  ];

  return {
    numbers: {
      users: strip.users,
      clients: strip.clients,
      sessions: strip.sessions,
      pendingRequests: strip.pending_requests,
      slowTailMillis: strip.slow_tail_millis,
    },
    gateways,
    attention,
    journal: journal?.items ?? [],
    chain,
    signIns,
    businessMetrics,
  };
}
