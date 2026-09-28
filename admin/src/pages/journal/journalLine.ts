import { say } from "@/i18n";
import type { JournalEnvelope } from "@/models/journal";

/// One journal entry as a row shows it, whatever kind wrote it.
export interface JournalLine {
  /// Who acted, when the entry names anyone.
  actor: string | null;
  /// The request line, or what the entry says in words.
  what: string;
  /// Hover text: the route a request matched, or the digest a report sealed.
  detail: string;
  /// The answer a request got. An entry no request wrote has none.
  status: number | null;
  trace: string | null;
}

export function readJournalLine(entry: JournalEnvelope): JournalLine {
  switch (entry.kind) {
    case "admin.write":
    case "admin.read":
      return {
        actor: entry.actor,
        what: `${entry.method} ${entry.path || (entry.pattern ?? "")}`,
        detail: entry.pattern ?? "",
        status: entry.status,
        trace: entry.trace_id ?? null,
      };
    case "governance.campaign.closed":
      return {
        actor: null,
        what: say("journal-campaign-closed", { campaign: entry.campaign, items: entry.items }),
        detail: entry.report_digest,
        status: null,
        trace: null,
      };
  }
  // Only a newer server writes a kind this build does not know; its name still says what it is.
  const { kind }: { kind: string } = entry;
  return { actor: null, what: kind, detail: "", status: null, trace: null };
}
