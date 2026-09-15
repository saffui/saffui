import type { Challenge } from "saffui-js";
import { say } from "@/i18n";
import {
  changePassword,
  removeApp,
  removeKey,
  removeRecoveryCodes,
  type OwnApp,
  type OwnKey,
} from "@/services/factors";
import { ApiError, StepUpNeeded } from "@/services/http";

export interface PasswordForm {
  current: string;
  replacement: string;
  again: string;
}

/// A way to sign in the person asked to remove, held while they confirm it.
export type Removal =
  | { kind: "app"; app: OwnApp }
  | { kind: "key"; key: OwnKey }
  | { kind: "recovery-codes"; count: number };

export interface Confirmation {
  title: string;
  body: string;
  confirm: string;
}

export interface Outcome {
  tone: "ok" | "danger";
  text: string;
  /// The sign-in the server asks for first, when it refused for want of one.
  stepUp: Challenge | null;
}

/// The realm's password rules and the missing fields, by the words the server says
/// them in, so the console can say them in its own tongue.
const PASSWORD_REFUSALS: Record<string, string> = {
  "the password is too short": "security-rule-too-short",
  "the password is too long": "security-rule-too-long",
  "the password needs more digits": "security-rule-digits",
  "the password needs more capitals": "security-rule-capitals",
  "the password needs more small letters": "security-rule-small-letters",
  "the password needs more punctuation": "security-rule-punctuation",
  "the password is something about you": "security-rule-about-you",
  "the password is one this realm refuses": "security-rule-refused",
  "the password does not match the shape this realm requires": "security-rule-shape",
  "the password is one this account used before": "security-rule-used-before",
  "the current password is required": "security-password-missing",
  "a new password is required": "security-password-missing",
};

/// Why a way to sign in has to stay, by the server's words for it.
const KEPT_BECAUSE: Record<string, string> = {
  "this is the last second factor: add another before removing it":
    "security-kept-last-second-factor",
  "this key is the only way this account signs in": "security-kept-only-way-in",
};

/// Whether the password form can be sent. The server judges the current password and
/// the realm's rules; only the repeat, which it never sees, is judged here.
export function checkPasswordForm(form: PasswordForm): "missing" | "mismatch" | "ready" {
  if (!form.current || !form.replacement) return "missing";
  if (form.replacement !== form.again) return "mismatch";
  return "ready";
}

/// Why a password change was refused: in the console's tongue where the console knows
/// the words, in the server's otherwise.
export function describePasswordRefusal(refused: ApiError): string {
  if (refused.code === "user.password.current_mismatch") return say("security-password-wrong");
  if (refused.code === "user.locked_out") return say("security-password-locked");
  if (refused.code === "user.password.not_held_here") return say("security-password-not-here");
  const named = PASSWORD_REFUSALS[refused.message];
  return named ? say(named) : refused.message;
}

export function describeKeptBecause(said: string): string {
  const named = KEPT_BECAUSE[said];
  return named ? say(named) : said;
}

export function nameApp(app: OwnApp): string {
  return app.label || say("security-app-unnamed");
}

/// A day, in the console's tongue, or nothing for a stamp that names no day.
export function formatDay(stamp: string | null, tongue: string): string {
  const day = new Date(stamp ?? "");
  if (!stamp || Number.isNaN(day.getTime())) return "";
  return new Intl.DateTimeFormat(tongue, { dateStyle: "medium" }).format(day);
}

/// What a removal takes away, said before it happens.
export function composeRemovalConfirmation(removal: Removal): Confirmation {
  if (removal.kind === "app") {
    return {
      title: say("confirm-remove-app-title", { name: nameApp(removal.app) }),
      body: say("confirm-remove-app-body"),
      confirm: say("confirm-remove"),
    };
  }
  if (removal.kind === "key") {
    return {
      title: say("confirm-remove-key-title", { name: removal.key.label }),
      body: say("confirm-remove-key-body"),
      confirm: say("confirm-remove"),
    };
  }
  return {
    title: say("confirm-remove-codes-title"),
    body: say("confirm-remove-codes-body", { count: removal.count }),
    confirm: say("confirm-remove"),
  };
}

export async function submitPasswordChange(realm: string, form: PasswordForm): Promise<Outcome> {
  try {
    const { ended_sessions } = await changePassword(realm, form.current, form.replacement);
    return {
      tone: "ok",
      text: say("security-password-changed", { count: ended_sessions }),
      stepUp: null,
    };
  } catch (refused) {
    if (refused instanceof StepUpNeeded) return askForStepUp(refused);
    if (refused instanceof ApiError) {
      return { tone: "danger", text: describePasswordRefusal(refused), stepUp: null };
    }
    return sayFailed();
  }
}

/// Remove what the person confirmed. The last way in stays, in the console's words,
/// and a way already gone is said calmly.
export async function carryOutRemoval(realm: string, removal: Removal): Promise<Outcome> {
  try {
    if (removal.kind === "app") await removeApp(realm, removal.app.id);
    else if (removal.kind === "key") await removeKey(realm, removal.key.id);
    else await removeRecoveryCodes(realm);
    return { tone: "ok", text: say("security-removed"), stepUp: null };
  } catch (refused) {
    if (refused instanceof StepUpNeeded) return askForStepUp(refused);
    if (refused instanceof ApiError && refused.code === "account.last_factor") {
      return { tone: "danger", text: describeKeptBecause(refused.message), stepUp: null };
    }
    if (refused instanceof ApiError && refused.status === 404) {
      return { tone: "ok", text: say("security-gone"), stepUp: null };
    }
    return sayFailed();
  }
}

function askForStepUp(refused: StepUpNeeded): Outcome {
  return { tone: "danger", text: say("security-step-up-needed"), stepUp: refused.challenge };
}

function sayFailed(): Outcome {
  return { tone: "danger", text: say("security-failed"), stepUp: null };
}
