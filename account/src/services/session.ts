import { reactive } from "vue";
import { Saffui, SaffuiError, type Challenge, type Tokens } from "saffui-js";
import { readTongue } from "@/i18n";
import { composeReturnUri } from "./place";

/// The client the console signs in as, provisioned with every realm.
export const ACCOUNT_CONSOLE = "account-console";
/// The ceremonies the console may ask the sign-in pages to run, each adding one way
/// to sign in. The server refuses any other name, and one the realm turned off.
export const CEREMONIES = ["configure-totp", "configure-webauthn", "configure-recovery-codes"] as const;
export type Ceremony = (typeof CEREMONIES)[number];
/// What a sign-in the console started was for.
export type Attempt = "sign-in" | "step-up" | "enrol";

const SCOPE = "openid account";
const RETURN_KEY = "sf-account-return-to";
const ATTEMPT_KEY = "sf-account-attempt";
const HOME = "/profile";
/// How soon after a sign-in a refused token means the realm refuses this sign-in,
/// rather than that the login has ended since.
const FRESH_MS = 30_000;
/// How soon after a step-up a demand for another means the new sign-in was not
/// enough, rather than that it has grown old.
const STEP_UP_MS = 120_000;

/// Who is signed in and holding what. Tokens live in memory only: a reload signs
/// in again through the server's own session cookie, which is the durable thing.
export const session = reactive({
  realm: "",
  accessToken: "",
  refreshToken: "",
  idToken: "",
  expiresAt: 0,
  adoptedAt: 0,
  /// When a step-up the console asked for came back, 0 when none did.
  steppedUpAt: 0,
  /// Why the sign-in was lost: "ended" is mended by signing in again, "refused"
  /// is not, since the realm would refuse the next one the same way.
  lost: "" as "" | "ended" | "refused",
});

/// Where a sign-in was meant to land, and what it was for.
export interface Landing {
  path: string;
  attempt: Attempt;
}

/// A sign-in that came back refused, with where it was meant to land.
export class SignInRefused extends Error {
  landing: Landing;
  constructor(landing: Landing, cause: unknown) {
    super("the sign-in was refused", { cause });
    this.landing = landing;
  }
}

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

export function isStepUpRecent(now = Date.now()): boolean {
  return session.steppedUpAt !== 0 && now - session.steppedUpAt < STEP_UP_MS;
}

/// Send the person to sign in, remembering the page to land back on. The sign-in
/// pages speak the console's tongue.
export async function signIn(path: string): Promise<void> {
  await startSignIn(path, "sign-in", {});
}

/// Send the person to sign in again as the server's challenge asks, landing back on
/// the page that met it.
export async function stepUp(challenge: Challenge, path: string): Promise<void> {
  rememberPath(path);
  rememberAttempt("step-up");
  await openClient(session.realm).stepUp({
    redirectUri: composeReturnUri(location.origin, session.realm),
    scope: SCOPE,
    extra: { ui_locales: readTongue() },
    challenge,
  });
}

/// Send the person to add a way to sign in. The ceremony runs on the sign-in pages
/// after a fresh sign-in, where it can also be declined.
export async function enrolFactor(ceremony: Ceremony, path: string): Promise<void> {
  await startSignIn(path, "enrol", { enrol: ceremony });
}

async function startSignIn(path: string, attempt: Attempt, extra: Record<string, string>) {
  rememberPath(path);
  rememberAttempt(attempt);
  await openClient(session.realm).login({
    redirectUri: composeReturnUri(location.origin, session.realm),
    scope: SCOPE,
    extra: { ui_locales: readTongue(), ...extra },
  });
}

/// Redeem the answer the sign-in came back with. A step-up that came back is noted,
/// so a page asked for another at once can say the new sign-in was not enough.
export async function finishSignIn(query: URLSearchParams, now = Date.now()): Promise<Landing> {
  const landing: Landing = { path: takeRememberedPath(), attempt: takeAttempt() };
  try {
    adoptTokens(await openClient(session.realm).handleRedirect(query), now);
  } catch (refused) {
    throw new SignInRefused(landing, refused);
  }
  if (landing.attempt === "step-up") session.steppedUpAt = now;
  return landing;
}

/// The page a refused step-up or ceremony lands back on, told which was refused.
export function composeRefusedPath(landing: Landing): string {
  const joined = landing.path.includes("?") ? "&" : "?";
  return `${landing.path}${joined}refused=${landing.attempt}`;
}

/// Where a refused sign-in sends the person: afresh into the console when there was
/// nothing left to redeem, back to its page when a step-up or a ceremony was refused,
/// and to the explanation otherwise.
export function chooseRefusedRoute(refused: unknown): string {
  const landing = refused instanceof SignInRefused ? refused.landing : null;
  const cause = refused instanceof SignInRefused ? refused.cause : refused;
  if (cause instanceof SaffuiError && cause.error === "no_login") return HOME;
  if (landing && landing.attempt !== "sign-in") return composeRefusedPath(landing);
  return "/trouble";
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
  session.steppedUpAt = 0;
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

function rememberAttempt(attempt: Attempt): void {
  try {
    sessionStorage.setItem(ATTEMPT_KEY, attempt);
  } catch {
    // A plain sign-in is assumed on the way back.
  }
}

function takeAttempt(): Attempt {
  let held = "";
  try {
    held = sessionStorage.getItem(ATTEMPT_KEY) ?? "";
    sessionStorage.removeItem(ATTEMPT_KEY);
  } catch {
    // A plain sign-in is assumed.
  }
  return held === "step-up" || held === "enrol" ? held : "sign-in";
}
