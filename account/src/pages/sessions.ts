import { say } from "@/i18n";
import type { HeldLogin } from "@/services/sessions";

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
