import type { OwnFactors } from "@/services/account";

/// The factors a person may add to their own account from the console, named
/// as the server's required actions. Each runs on the sign-in page after a
/// fresh sign-in, and the server refuses any other name.
export const OWN_FACTORS = [
  "configure-totp",
  "configure-webauthn",
  "configure-recovery-codes",
] as const;

export type OwnFactor = (typeof OWN_FACTORS)[number];

/// Whether the sign-in behind a page may still remove a factor, against the
/// moment the server gave. A page left open past it asks for a new sign-in
/// first, rather than sending a removal the server will refuse.
export function freshEnough(freshUntil: number | null, nowSeconds: number): boolean {
  return freshUntil !== null && freshUntil >= nowSeconds;
}

/// What a removal needs first: a sign-in with a stronger factor, a recent
/// sign-in, or nothing, from what the server said and the moment it is now.
export function signInNeededBeforeRemoval(
  factors: Pick<OwnFactors, "fresh_until" | "stronger_sign_in_needed">,
  nowSeconds: number,
): "stronger" | "recent" | null {
  if (factors.stronger_sign_in_needed) return "stronger";
  if (!freshEnough(factors.fresh_until, nowSeconds)) return "recent";
  return null;
}
