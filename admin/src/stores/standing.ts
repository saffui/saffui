import { defineStore } from "pinia";
import { adminPath, api } from "@/services/http";
import type { PasswordPolicy } from "@/models/realm";

/// What the realm looks like right now, read once and shared.
///
/// The status bar sits on every screen and the overview opens with the same
/// numbers, so fetching them per page would pay for the same four counts on
/// every navigation. One reading per realm, refreshed when something is
/// written, is what both read from.
/// The realm's own switches, as far as the shell needs them. Read beside the
/// numbers because both are wanted on the first screen and neither changes
/// between two clicks.
interface Switches {
  edit_user_name_allowed: boolean | null;
  duplicated_email_allowed: boolean | null;
  register_email_as_username: boolean | null;
  password_policy: PasswordPolicy | null;
}

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
    switches: null as Switches | null,
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
        const [held, switches] = await Promise.all([
          api<Standing>(adminPath(realm, "overview")),
          api<Switches>(`/admin/realms/${encodeURIComponent(realm)}`),
        ]);
        this.held = held;
        this.switches = switches;
        this.realm = realm;
      } catch {
        // The bar shows what it can; a refusal here is not the page's error.
        this.held = null;
        this.switches = null;
      } finally {
        this.reading = false;
      }
    },
  },
});
