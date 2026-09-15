import { reactive } from "vue";
import { Saffui, type Tokens } from "saffui-js";
import { readTongue } from "@/i18n";
import { composeReturnUri } from "./place";

/// The client the console signs in as, provisioned with every realm.
export const ACCOUNT_CONSOLE = "account-console";
const RETURN_KEY = "sf-account-return-to";
const HOME = "/profile";
/// How soon after a sign-in a refused token means the realm refuses this sign-in,
/// rather than that the login has ended since.
const FRESH_MS = 30_000;

/// Who is signed in and holding what. Tokens live in memory only: a reload signs
/// in again through the server's own session cookie, which is the durable thing.
export const session = reactive({
  realm: "",
  accessToken: "",
  refreshToken: "",
  idToken: "",
  expiresAt: 0,
  adoptedAt: 0,
  /// Why the sign-in was lost: "ended" is mended by signing in again, "refused"
  /// is not, since the realm would refuse the next one the same way.
  lost: "" as "" | "ended" | "refused",
});

let renewal: Promise<string> | null = null;

function openClient(realm: string): Saffui {
  return new Saffui({ realm, clientId: ACCOUNT_CONSOLE });
}

export function holdRealm(realm: string): void {
  session.realm = realm;
}

export function isSignedIn(now = Date.now()): boolean {
  return session.accessToken !== "" && now < session.expiresAt;
}

export function isFreshlyAdopted(now = Date.now()): boolean {
  return session.adoptedAt !== 0 && now - session.adoptedAt < FRESH_MS;
}

/// Send the person to sign in, remembering the page to land back on. The sign-in
/// pages speak the console's tongue.
export async function signIn(path: string): Promise<void> {
  rememberPath(path);
  await openClient(session.realm).login({
    redirectUri: composeReturnUri(location.origin, session.realm),
    scope: "openid account",
    extra: { ui_locales: readTongue() },
  });
}

/// Redeem the answer the sign-in came back with, and name the page to land on.
export async function finishSignIn(query: URLSearchParams): Promise<string> {
  adoptTokens(await openClient(session.realm).handleRedirect(query));
  return takeRememberedPath();
}

export function adoptTokens(tokens: Tokens, now = Date.now()): void {
  session.accessToken = tokens.access_token;
  session.refreshToken = tokens.refresh_token ?? "";
  session.idToken = tokens.id_token ?? session.idToken;
  // A little early, so a token is never sent in its last seconds.
  session.expiresAt = now + (tokens.expires_in - 15) * 1000;
  session.adoptedAt = now;
  session.lost = "";
}

/// A live token, renewed under the caller when the held one is stale. When none
/// is to be had, the sign-in is lost as ended and the call throws.
export async function readBearer(now = Date.now()): Promise<string> {
  if (isSignedIn(now)) return session.accessToken;
  const held = session.refreshToken;
  if (held) {
    renewal ??= openClient(session.realm)
      .renew(held)
      .then((renewed) => {
        if (session.refreshToken === held) adoptTokens(renewed);
        return session.accessToken;
      })
      .finally(() => {
        renewal = null;
      });
    try {
      return await renewal;
    } catch {
      // A refused renewal is an ended sign-in, told below like a missing one.
    }
  }
  loseSignIn("ended");
  throw new Error("signed out");
}

export function loseSignIn(why: "ended" | "refused"): void {
  forgetSignIn();
  session.lost = why;
}

/// End the sign-in on the server and here. Forgotten here first, so a server that
/// cannot be reached still leaves nothing usable behind in the page.
export async function signOut(): Promise<void> {
  const { realm, idToken } = session;
  forgetSignIn();
  try {
    await openClient(realm).logout(idToken || undefined);
  } catch {
    // Signed out of this page all the same.
  }
}

/// Forget the sign-in here only: what signing out does in this page, and all that is
/// left to do once the server has ended the login itself.
export function forgetSignIn(): void {
  session.accessToken = "";
  session.refreshToken = "";
  session.idToken = "";
  session.expiresAt = 0;
  session.adoptedAt = 0;
}

/// The page a sign-in interrupted. A path is not a secret: keeping it in
/// sessionStorage lets the sign-in land back where the person was, while the
/// tokens stay in memory.
export function rememberPath(path: string): void {
  try {
    sessionStorage.setItem(RETURN_KEY, path);
  } catch {
    // Nothing kept; the profile answers instead.
  }
}

/// Only a page of this console comes back, once; anything else lands on the profile.
export function takeRememberedPath(): string {
  let held = "";
  try {
    held = sessionStorage.getItem(RETURN_KEY) ?? "";
    sessionStorage.removeItem(RETURN_KEY);
  } catch {
    // Nothing kept; the profile answers instead.
  }
  const inside =
    held.startsWith("/") &&
    !held.startsWith("//") &&
    !held.startsWith("/\\") &&
    !held.startsWith("/login/");
  return inside ? held : HOME;
}
