import { say } from "@/i18n";
import { ApiError } from "@/services/http";
import { forgetSignIn } from "@/services/session";
import {
  endLogin,
  endOtherLogins,
  revokeGrant,
  type HeldGrant,
  type HeldLogin,
} from "@/services/sessions";

/// A gesture on the person's logins, held while they confirm it.
export type Gesture =
  | { kind: "end"; login: HeldLogin }
  | { kind: "end-others" }
  | { kind: "take-back"; login: HeldLogin; grant: HeldGrant };

export interface Confirmation {
  title: string;
  body: string;
  confirm: string;
}

export interface Outcome {
  tone: "ok" | "danger";
  text: string;
  /// Whether the gesture ended the login this page rides.
  signedOut: boolean;
}

/// The logins in the order a person looks for them: this browser's first, then the
/// newest.
export function orderLogins(logins: HeldLogin[]): HeldLogin[] {
  return [...logins].sort(
    (one, other) => Number(other.current) - Number(one.current) || other.started_at - one.started_at,
  );
}

/// Every login but this browser's, closed ones holding offline access included: what
/// signing out everywhere else ends.
export function countOtherLogins(logins: HeldLogin[]): number {
  return logins.filter((login) => !login.current).length;
}

/// A login's device as its person would name it, from what the browser said of itself.
export function describeDevice(login: HeldLogin): string {
  if (login.browser && login.system) {
    return say("sessions-device", { browser: login.browser, system: login.system });
  }
  return login.browser ?? login.system ?? say("sessions-device-unknown");
}

/// A moment, as a date and a time in the console's tongue.
export function formatMoment(seconds: number, tongue: string): string {
  return new Intl.DateTimeFormat(tongue, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(seconds * 1000),
  );
}

/// What a gesture does, said before it happens: ending a login and taking back what
/// one application got are two gestures with two consequences.
export function composeConfirmation(gesture: Gesture): Confirmation {
  if (gesture.kind === "end" && gesture.login.current) {
    return {
      title: say("confirm-end-current-title"),
      body: say("confirm-end-current-body"),
      confirm: say("confirm-end-current"),
    };
  }
  if (gesture.kind === "end") {
    return {
      title: say("confirm-end-title"),
      body: say("confirm-end-body", { device: describeDevice(gesture.login) }),
      confirm: say("confirm-end"),
    };
  }
  if (gesture.kind === "end-others") {
    return {
      title: say("confirm-end-others-title"),
      body: say("confirm-end-others-body"),
      confirm: say("confirm-end-others"),
    };
  }
  return {
    title: say("confirm-take-back-title", { application: gesture.grant.name }),
    body: say("confirm-take-back-body", { application: gesture.grant.name }),
    confirm: say("confirm-take-back"),
  };
}

/// Carry out a confirmed gesture and say how it went. Ending the login this page
/// rides forgets the sign-in here too, since the server has just ended it.
export async function carryOutGesture(realm: string, gesture: Gesture): Promise<Outcome> {
  try {
    if (gesture.kind === "end") {
      await endLogin(realm, gesture.login.session_id);
      if (gesture.login.current) forgetSignIn();
      return { tone: "ok", text: say("sessions-ended"), signedOut: gesture.login.current };
    }
    if (gesture.kind === "end-others") {
      const { ended_sessions } = await endOtherLogins(realm);
      return {
        tone: "ok",
        text: say("sessions-ended-others", { count: ended_sessions }),
        signedOut: false,
      };
    }
    await revokeGrant(realm, gesture.login.session_id, gesture.grant.client_id);
    return {
      tone: "ok",
      text: say("sessions-taken-back", { application: gesture.grant.name }),
      signedOut: false,
    };
  } catch (refused) {
    if (refused instanceof ApiError && refused.status === 404) {
      return { tone: "ok", text: say("sessions-gone"), signedOut: false };
    }
    return { tone: "danger", text: say("sessions-failed"), signedOut: false };
  }
}
