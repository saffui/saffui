import type { UserFull } from "@/models/user";

export interface OwnPasswordForm {
  current: string;
  replacement: string;
  again: string;
}

/// Whether the form can be sent. The server judges the current password and
/// the realm's policy; only what it never sees, the confirmation, is judged here.
export function ownPasswordReady(form: OwnPasswordForm): "missing" | "mismatch" | "ready" {
  if (!form.current || !form.replacement) return "missing";
  if (form.replacement !== form.again) return "mismatch";
  return "ready";
}

/// A directory keeps its own passwords, so the console offers no change there.
export function passwordKeptHere(user: Pick<UserFull, "origin">): boolean {
  return user.origin !== "ldap";
}
