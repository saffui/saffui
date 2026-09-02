import { say } from "@/i18n";
import { adminPath, api } from "@/services/http";
import type { Page } from "@/models/paging";
import type {
  GroupMembership,
  GroupRow,
  OrganizationRow,
  OrgMember,
  RoleHolders,
  RoleRow,
} from "@/models/directory";

function paged(leaf: string, first: number, max: number): string {
  return `${leaf}?first=${first}&max=${max}&count=true`;
}

export async function listRoles(
  realm: string,
  first: number,
  max: number,
): Promise<Page<RoleRow>> {
  return api<Page<RoleRow>>(adminPath(realm, paged("roles", first, max)));
}

export async function listRoleHolders(realm: string, roleId: string): Promise<RoleHolders> {
  return api<RoleHolders>(adminPath(realm, `roles/${encodeURIComponent(roleId)}/holders`));
}

export async function listGroups(
  realm: string,
  first: number,
  max: number,
): Promise<Page<GroupRow>> {
  return api<Page<GroupRow>>(adminPath(realm, paged("groups", first, max)));
}

/// Mark or unmark a group as one every new account joins at creation.
export async function markGroupDefault(
  realm: string,
  group: GroupRow,
  isDefault: boolean,
): Promise<void> {
  await api<unknown>(adminPath(realm, `groups/${encodeURIComponent(group.group_id)}`), {
    method: "PUT",
    json: {
      name: group.name,
      display_name: group.display_name,
      description: group.description,
      is_default: isDefault,
    },
    subject: say("subject-group", { group: group.name }),
  });
}

export async function listGroupMembership(
  realm: string,
  groupId: string,
): Promise<GroupMembership> {
  return api<GroupMembership>(
    adminPath(realm, `groups/${encodeURIComponent(groupId)}/membership`),
  );
}

export async function listOrganizations(
  realm: string,
  first: number,
  max: number,
): Promise<Page<OrganizationRow>> {
  return api<Page<OrganizationRow>>(adminPath(realm, paged("organizations", first, max)));
}

export async function getOrganization(
  realm: string,
  orgId: string,
): Promise<OrganizationRow> {
  return api<OrganizationRow>(adminPath(realm, `organizations/${encodeURIComponent(orgId)}`));
}

export async function listOrganizationMembers(
  realm: string,
  orgId: string,
): Promise<OrgMember[]> {
  return api<OrgMember[]>(
    adminPath(realm, `organizations/${encodeURIComponent(orgId)}/members`),
  );
}
