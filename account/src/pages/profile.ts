import { say } from "@/i18n";
import type { Address, Me } from "@/services/me";

export interface Fact {
  label: string;
  value: string;
}

/// The details beyond name and contact, in the order a person reads them, and only
/// those the realm holds. Addresses of pages stay text: the console never follows
/// a link somebody else may have typed.
export function listOtherFacts(me: Me): Fact[] {
  const facts: Fact[] = [];
  for (const [value, label] of [
    [me.nickname, say("profile-nickname")],
    [me.middle_name, say("profile-middle-name")],
    [me.birthdate, say("profile-birthdate")],
    [me.gender, say("profile-gender")],
    [me.locale, say("profile-locale")],
    [me.zoneinfo, say("profile-zoneinfo")],
    [me.website, say("profile-website")],
    [me.profile, say("profile-page")],
  ] as const) {
    if (value) facts.push({ label, value });
  }
  const address = composeAddressLines(me.address);
  if (address.length) facts.push({ label: say("profile-address"), value: address.join("\n") });
  return facts;
}

/// An address as lines: the realm's own formatting when it holds one, else its parts.
export function composeAddressLines(address?: Address): string[] {
  if (!address) return [];
  if (address.formatted) return address.formatted.split(/\r?\n/).filter(Boolean);
  return [
    address.street_address,
    [address.postal_code, address.locality].filter(Boolean).join(" "),
    address.region,
    address.country,
  ].filter((line): line is string => Boolean(line));
}

/// When the profile last changed, as a date in the console's tongue.
export function formatUpdated(seconds: number, tongue: string): string {
  return new Intl.DateTimeFormat(tongue, { dateStyle: "long" }).format(new Date(seconds * 1000));
}
