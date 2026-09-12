import { defineStore } from "pinia";
import { peek, type Tokens } from "saffui-js";
import { clientFor, rememberRealm, rememberedRealm, returnUri } from "@/services/auth";
import { getUser } from "@/services/users";

let renewal: Promise<string> | null = null;

/// Who is signed in, into which realm, holding what. Tokens live in memory
/// only: a reload signs in again through the server's own session cookie,
/// which is the durable thing.
export const useSession = defineStore("session", {
  state: () => ({
    realm: "",
    accessToken: "",
    refreshToken: "",
    idToken: "",
    expiresAt: 0,
    displayName: "",
    userId: "",
  }),
  getters: {
    signedIn: (state) => state.accessToken !== "" && Date.now() < state.expiresAt,
  },
  actions: {
    async login(realm: string) {
      rememberRealm(realm);
      await clientFor(realm).login({
        redirectUri: returnUri(),
        scope: "openid profile admin",
        extra: {
          claims: JSON.stringify({
            id_token: { preferred_username: { essential: true } },
          }),
        },
      });
    },
    adopt(realm: string, tokens: Tokens) {
      this.realm = realm;
      this.accessToken = tokens.access_token;
      this.refreshToken = tokens.refresh_token ?? "";
      this.idToken = tokens.id_token ?? this.idToken;
      this.expiresAt = Date.now() + (tokens.expires_in - 15) * 1000;
      const identity = identityOf(this.idToken || tokens.access_token);
      this.userId = identity.id;
      this.displayName = identity.name;
      if (identity.id && !identity.name) void this.loadName(realm, identity.id);
    },
    async loadName(realm: string, userId: string) {
      try {
        const user = await getUser(realm, userId);
        if (this.realm === realm && this.userId === userId) this.displayName = user.user_name;
      } catch {
        // The account menu remains anonymous if this realm denies the read.
      }
    },
    async returned(query: URLSearchParams) {
      const realm = rememberedRealm();
      if (!realm) throw new Error("no login is in progress here");
      const tokens = await clientFor(realm).handleRedirect(query);
      this.adopt(realm, tokens);
    },
    /// A live token, renewed under the caller when the held one is stale.
    async bearer(): Promise<string> {
      if (this.accessToken && Date.now() < this.expiresAt) return this.accessToken;
      if (this.refreshToken) {
        const realm = this.realm;
        const held = this.refreshToken;
        if (!renewal) {
          renewal = clientFor(realm)
            .renew(held)
            .then((renewed) => {
              if (this.refreshToken === held) this.adopt(realm, renewed);
              return this.accessToken;
            })
            .finally(() => {
              renewal = null;
            });
        }
        try {
          return await renewal;
        } catch {
          if (this.refreshToken === held) this.signOut();
          throw new Error("signed out");
        }
      }
      this.signOut();
      throw new Error("signed out");
    },
    signOut() {
      this.$reset();
    },
    async logout() {
      const realm = this.realm;
      const idToken = this.idToken;
      this.$reset();
      if (!realm) return;
      try {
        await clientFor(realm).logout(idToken || undefined);
      } catch {
        // Local sign-out still stands when the server cannot be reached.
      }
    },
    /// Dev-only stand-in so the shell can be reviewed with no server behind
    /// it. Refused outright in production builds.
    preview() {
      if (!import.meta.env.DEV) return;
      this.realm = "main";
      this.accessToken = "preview";
      this.expiresAt = Date.now() + 3_600_000;
      this.displayName = "ada";
      this.userId = "ada";
    },
  },
});

function identityOf(token: string): { id: string; name: string } {
  try {
    const claims = peek(token);
    return {
      id: typeof claims.sub === "string" ? claims.sub : "",
      name: typeof claims.preferred_username === "string" ? claims.preferred_username : "",
    };
  } catch {
    return { id: "", name: "" };
  }
}
