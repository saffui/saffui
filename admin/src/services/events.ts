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

/// Drink the realm's live feed until the signal aborts. EventSource cannot
/// carry a bearer, so this reads the stream by hand: fetch, then frames
/// split on the blank line, `data:` lines parsed, comments dropped.
export async function drinkEvents(
  realm: string,
  onTold: (told: LiveTold) => void,
  signal: AbortSignal,
): Promise<void> {
  const session = useSession();
  const bearer = await session.bearer();
  const answer = await fetch(adminPath(realm, "events/stream"), {
    headers: { authorization: `Bearer ${bearer}` },
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
      for (const line of frame.split("\n")) {
        if (line.startsWith("data: ")) {
          try {
            onTold(JSON.parse(line.slice(6)) as LiveTold);
          } catch {
            // A frame that does not parse is dropped; the log below is
            // the place to ask what happened.
          }
        }
      }
      at = held.indexOf("\n\n");
    }
  }
}
