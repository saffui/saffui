import { say } from "@/i18n";
import {
  takeBackAccess,
  withdrawConsent,
  type HeldApplication,
} from "@/services/applications";
import { ApiError } from "@/services/http";

/// A gesture on one application, held while the person confirms it.
export type Gesture =
  | { kind: "withdraw-consent"; application: HeldApplication }
  | { kind: "take-back-access"; application: HeldApplication };

export interface Confirmation {
  title: string;
  body: string;
  confirm: string;
}

export interface Outcome {
  tone: "ok" | "danger";
  text: string;
}

/// The scopes a person may agree to, by what each lets an application read.
const SCOPE_WORDS: Record<string, string> = {
  openid: "applications-scope-openid",
  profile: "applications-scope-profile",
  email: "applications-scope-email",
  phone: "applications-scope-phone",
  address: "applications-scope-address",
  offline_access: "applications-scope-offline-access",
};

/// What a scope lets an application have, in the console's tongue where the console
/// knows the scope, and by its name otherwise.
export function describeScope(scope: string): string {
  const named = SCOPE_WORDS[scope];
  return named ? say(named) : scope;
}

/// What a gesture does, said before it happens: withdrawing a consent and taking back
/// access are two gestures with two consequences.
export function composeConfirmation(gesture: Gesture): Confirmation {
  const application = gesture.application.name;
  if (gesture.kind === "take-back-access") {
    return {
      title: say("confirm-take-back-access-title", { application }),
      body: say("confirm-take-back-access-body", { application }),
      confirm: say("confirm-take-back-access"),
    };
  }
  const asksAgain = gesture.application.consent?.asks_consent === true;
  return {
    title: say("confirm-withdraw-consent-title", { application }),
    body: asksAgain
      ? say("confirm-withdraw-consent-body", { application })
      : say("confirm-withdraw-consent-body-unasked", { application }),
    confirm: say("confirm-withdraw-consent"),
  };
}

/// Carry out a confirmed gesture and say how it went; something already gone is said
/// calmly.
export async function carryOutGesture(realm: string, gesture: Gesture): Promise<Outcome> {
  const application = gesture.application.name;
  try {
    if (gesture.kind === "withdraw-consent") {
      await withdrawConsent(realm, gesture.application.client_id);
      return { tone: "ok", text: say("applications-consent-withdrawn", { application }) };
    }
    const { ended_grants } = await takeBackAccess(realm, gesture.application.client_id);
    return {
      tone: "ok",
      text: say("applications-access-taken-back", { application, count: ended_grants }),
    };
  } catch (refused) {
    if (refused instanceof ApiError && refused.status === 404) {
      return { tone: "ok", text: say("applications-gone") };
    }
    return { tone: "danger", text: say("applications-failed") };
  }
}
