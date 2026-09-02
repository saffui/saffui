import { defineStore } from "pinia";
import { peek, type Tokens } from "saffui-js";
import { clientFor, rememberRealm, rememberedRealm, returnUri } from "@/services/auth";

/// Who is signed in, into which realm, holding what. Tokens live in memory
/// only: a reload signs in again through the server's own session cookie,
/// which is the durable thing.
export const useSession = defineStore("session", {
  state: () => ({
    realm: "",
    accessToken: "",
    refreshToken: "",
    expiresAt: 0,
    displayName: "",
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
      });
    },
    adopt(realm: string, tokens: Tokens) {
      this.realm = realm;
      this.accessToken = tokens.access_token;
      this.refreshToken = tokens.refresh_token ?? "";
      this.expiresAt = Date.now() + (tokens.expires_in - 15) * 1000;
      this.displayName = subjectOf(tokens.access_token);
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
        try {
          const renewed = await clientFor(this.realm).renew(this.refreshToken);
          this.adopt(this.realm, renewed);
          return this.accessToken;
        } catch {
          // A refusal here is a session that ended; fall through to sign-out.
        }
      }
      this.signOut();
      throw new Error("signed out");
    },
    signOut() {
      this.$reset();
    },
    /// Dev-only stand-in so the shell can be reviewed with no server behind
    /// it. Refused outright in production builds.
    preview() {
      if (!import.meta.env.DEV) return;
      this.realm = "main";
      this.accessToken = "preview";
      this.expiresAt = Date.now() + 3_600_000;
      this.displayName = "ada";
    },
  },
});

function subjectOf(token: string): string {
  try {
    const claims = peek(token);
    return String(claims.preferred_username ?? claims.sub ?? "");
  } catch {
    return "";
  }
}
