// The console signs in through the very server it administers, using the
// product's own browser library. One public client, per-realm instances.
import { Saffui } from "saffui-js";

export const CONSOLE_CLIENT = "saffui-console";
const REALM_KEY = "sf-console-realm";

export function clientFor(realm: string): Saffui {
  return new Saffui({ realm, clientId: CONSOLE_CLIENT });
}

export function returnUri(): string {
  return `${location.origin}/login/return`;
}

/// The realm a login was started against, remembered across the redirect.
export function rememberRealm(realm: string): void {
  sessionStorage.setItem(REALM_KEY, realm);
}
export function rememberedRealm(): string {
  return sessionStorage.getItem(REALM_KEY) ?? "";
}
