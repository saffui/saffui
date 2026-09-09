import { defineStore } from "pinia";
import { adminPath, api } from "@/services/http";

/// What the realm looks like right now, read once and shared.
///
/// The status bar sits on every screen and the overview opens with the same
/// numbers, so fetching them per page would pay for the same four counts on
/// every navigation. One reading per realm, refreshed when something is
/// written, is what both read from.
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

export const useStanding = defineStore("standing", {
  state: () => ({
    realm: "",
    held: null as Standing | null,
    reading: false,
  }),
  actions: {
    /// Read the realm's numbers. A second call for the same realm while one is
    /// in flight is dropped rather than queued: the bar and the page both ask
    /// on the same navigation.
    async read(realm: string, again = false) {
      if (this.reading) return;
      if (!again && this.realm === realm && this.held) return;
      this.reading = true;
      try {
        this.held = await api<Standing>(adminPath(realm, "overview"));
        this.realm = realm;
      } catch {
        // The bar shows what it can; a refusal here is not the page's error.
        this.held = null;
      } finally {
        this.reading = false;
      }
    },
  },
});
