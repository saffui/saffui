import { defineStore } from "pinia";
import { adminPath, api } from "@/services/http";
import type { RealmSettings } from "@/models/realm";

/// What the realm looks like right now, read once and shared.
///
/// The status bar sits on every screen and the overview opens with the same
/// numbers and the same settings, so fetching them per page would pay twice
/// for one answer. Both read from here.
interface Standing {
  users: number;
  clients: number;
  sessions: number;
  pending_requests: number;
  queue: number;
  /// Absent where the build carries no histogram. The bar leaves the reading
  /// out rather than printing a placeholder for one that never comes.
  slow_tail_millis?: number;
}

/// The reading in flight, shared rather than dropped. Two callers on the same
/// navigation are the normal case, and the second one needs the answer as
/// much as the first.
let inFlight: { realm: string; asked: Promise<void> } | null = null;

export const useStanding = defineStore("standing", {
  state: () => ({
    realm: "",
    held: null as Standing | null,
    settings: null as RealmSettings | null,
    /// Whether the realm's doors answered the last time this asked. Null
    /// until they have been asked at all, so nothing claims a state it has
    /// not yet observed.
    answering: null as boolean | null,
  }),
  actions: {
    /// Read the realm's numbers and its settings in one go.
    async read(realm: string, again = false) {
      if (!again && this.realm === realm && this.held) return;
      if (inFlight?.realm === realm) return inFlight.asked;
      const asked = this.ask(realm).finally(() => {
        if (inFlight?.asked === asked) inFlight = null;
      });
      inFlight = { realm, asked };
      return asked;
    },
    async ask(realm: string) {
      try {
        const [held, settings] = await Promise.all([
          api<Standing>(adminPath(realm, "overview")),
          api<RealmSettings>(`/admin/realms/${encodeURIComponent(realm)}`),
        ]);
        this.held = held;
        this.settings = settings;
        this.realm = realm;
        this.answering = true;
      } catch {
        // The bar shows what it can; a refusal here is not the page's error,
        // but it is not a healthy realm either, and the bar says so.
        this.held = null;
        this.settings = null;
        this.answering = false;
      }
    },
  },
});
