import { say } from "@/i18n";
import { adminPath, api } from "@/services/http";
import { useSession } from "@/stores/session";

/// One telling given up on, as the dead-letter list shows it.
export interface DeadLetter {
  event_id: number;
  kind: string;
  user_id: string;
  attempts: number;
  occurred_at: string;
}

export async function listDeadLetters(realm: string): Promise<DeadLetter[]> {
  return api<DeadLetter[]>(adminPath(realm, "events/dead"));
}

export async function requeueDead(realm: string, eventId: number): Promise<void> {
  await api<void>(adminPath(realm, `events/dead/${eventId}/requeue`), {
    method: "POST",
    subject: say("events-dead-subject", { id: String(eventId) }),
  });
}

/// One committed happening, as the live feed speaks it.
export interface LiveTold {
  event_id: number;
  kind: string;
  user_id: string;
  occurred_at: string;
}

export function parseLiveFrame(frame: string): LiveTold | null {
  const id = frame
    .split("\n")
    .find((line) => line.startsWith("id: "))
    ?.slice(4)
    .trim();
  const data = frame
    .split("\n")
    .filter((line) => line.startsWith("data: "))
    .map((line) => line.slice(6))
    .join("\n");
  if (!data) return null;
  try {
    const told = JSON.parse(data) as LiveTold;
    if (typeof told.event_id !== "number" && id) told.event_id = Number(id);
    return typeof told.event_id === "number" ? told : null;
  } catch {
    return null;
  }
}

/// Drink the realm's live feed until the signal aborts. EventSource cannot
/// carry a bearer, so this reads the stream by hand: fetch, then frames
/// split on the blank line, `data:` lines parsed, comments dropped.
export async function drinkEvents(
  realm: string,
  onTold: (told: LiveTold) => void,
  signal: AbortSignal,
  lastEventId?: number,
): Promise<void> {
  const session = useSession();
  const bearer = await session.bearer();
  const answer = await fetch(adminPath(realm, "events/stream"), {
    headers: {
      authorization: `Bearer ${bearer}`,
      ...(lastEventId === undefined ? {} : { "last-event-id": String(lastEventId) }),
    },
    signal,
  });
  if (!answer.ok || !answer.body) {
    throw new Error(`the feed refused: ${answer.status}`);
  }
  const reader = answer.body.getReader();
  const decoder = new TextDecoder();
  let held = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return;
    held += decoder.decode(value, { stream: true });
    let at = held.indexOf("\n\n");
    while (at !== -1) {
      const frame = held.slice(0, at);
      held = held.slice(at + 2);
      const told = parseLiveFrame(frame);
      if (told) onTold(told);
      at = held.indexOf("\n\n");
    }
  }
}
