import type { LiveEventSummary } from "@/services/events";

/// The number to read after, as it is typed: nothing reads from the oldest kept, and
/// anything that is not a whole number is refused rather than read as one.
export function readHistoryCursor(typed: string): number | null {
  const held = typed.trim();
  if (!held) return 0;
  if (!/^\d+$/.test(held)) return null;
  const cursor = Number(held);
  return Number.isSafeInteger(cursor) ? cursor : null;
}

/// A page laid after what is already shown, oldest first. An event already there stays
/// where it stands: reading a page twice is not two happenings.
export function appendHistoryPage(
  held: LiveEventSummary[],
  page: LiveEventSummary[],
): LiveEventSummary[] {
  const shown = new Set(held.map((row) => row.event_id));
  return [...held, ...page.filter((row) => !shown.has(row.event_id))];
}
