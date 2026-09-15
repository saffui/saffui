import type { OrganizationChange, OrganizationRow } from "@/models/directory";

export interface OrganizationDraft {
  name: string;
  display_name: string;
  description: string;
}

/// The whole organization as it is to be written: what the drawer edits, over
/// everything it does not. The plane replaces an organization whole, so a field left
/// out would be reset: its landing address and attributes cleared, and a switched-off
/// organization switched back on.
export function composeOrganizationChange(
  opened: OrganizationRow,
  draft: OrganizationDraft,
): OrganizationChange {
  return {
    name: draft.name.trim() || opened.name,
    display_name: draft.display_name.trim(),
    description: draft.description.trim(),
    enabled: opened.enabled,
    redirect_url: opened.redirect_url,
    attributes: opened.attributes,
  };
}
