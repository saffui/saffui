/// The factors a person may add to their own account from the console, named
/// as the server's required actions. Each runs on the sign-in page after a
/// fresh sign-in, and the server refuses any other name.
export const OWN_FACTORS = [
  "configure-totp",
  "configure-webauthn",
  "configure-recovery-codes",
] as const;

export type OwnFactor = (typeof OWN_FACTORS)[number];
