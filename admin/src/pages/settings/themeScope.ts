import type { OrganizationRow } from "@/models/directory";
import type { RealmTheme } from "@/models/realm";
import {
  forgetOrganizationTheme,
  getOrganizationTheme,
  writeOrganizationTheme,
} from "@/services/directory";
import { forgetRealmTheme, getRealmTheme, writeRealmTheme } from "@/services/settings";

export interface ThemeChoice {
  id: string;
  label: string;
}

/// The organization whose theme the page edits, as its address names it; blank for
/// the realm's own.
export function readThemeOrganization(asked: unknown): string {
  return typeof asked === "string" ? asked.trim() : "";
}

/// The organizations offered beside the realm, keeping the one the address names even
/// when it is not among those listed.
export function listThemeChoices(organizations: OrganizationRow[], chosen: string): ThemeChoice[] {
  const listed = organizations.map((org) => ({ id: org.org_id, label: org.display_name || org.name }));
  if (!chosen || listed.some((choice) => choice.id === chosen)) return listed;
  return [...listed, { id: chosen, label: chosen }];
}

export function readScopedTheme(realm: string, organization: string): Promise<RealmTheme> {
  return organization ? getOrganizationTheme(realm, organization) : getRealmTheme(realm);
}

export function writeScopedTheme(
  realm: string,
  organization: string,
  theme: NonNullable<RealmTheme>,
): Promise<void> {
  return organization
    ? writeOrganizationTheme(realm, organization, theme)
    : writeRealmTheme(realm, theme);
}

export function forgetScopedTheme(realm: string, organization: string): Promise<void> {
  return organization ? forgetOrganizationTheme(realm, organization) : forgetRealmTheme(realm);
}
