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

export async function createGroup(
  realm: string,
  name: string,
  description: string,
  parentId: string | null = null,
) {
  return api<GroupRow>(adminPath(realm, "groups"), {
    method: "POST",
    json: { name, description, parent_id: parentId },
    subject: say("subject-group", { group: name }),
  });
}

export async function updateGroup(realm: string, group: GroupRow): Promise<void> {
  await api<unknown>(adminPath(realm, `groups/${encodeURIComponent(group.group_id)}`), {
    method: "PUT",
    json: {
      name: group.name,
      display_name: group.display_name,
      description: group.description,
      is_default: group.is_default,
      parent_id: group.parent_id ?? null,
    },
    subject: say("subject-group", { group: group.name }),
  });
}

export async function deleteGroup(realm: string, groupId: string): Promise<void> {
  await api<void>(adminPath(realm, `groups/${encodeURIComponent(groupId)}`), {
    method: "DELETE",
    quiet: true,
  });
}

export async function grantRoleToGroup(realm: string, groupId: string, roleId: string) {
  await api<unknown>(
    adminPath(realm, `groups/${encodeURIComponent(groupId)}/roles/${encodeURIComponent(roleId)}`),
    { method: "PUT", subject: say("subject-group-role", { group: groupId, role: roleId }) },
  );
}

export async function revokeRoleFromGroup(realm: string, groupId: string, roleId: string) {
  await api<unknown>(
    adminPath(realm, `groups/${encodeURIComponent(groupId)}/roles/${encodeURIComponent(roleId)}`),
    { method: "DELETE", subject: say("subject-group-role", { group: groupId, role: roleId }) },
  );
}

export async function createRole(
  realm: string,
  spec: { name: string; description?: string; display_name?: string; client_id?: string },
) {
  return api<{ role_id: string; name: string }>(adminPath(realm, "roles"), {
    method: "POST",
    json: spec,
    subject: say("subject-role", { role: spec.name }),
  });
}

export async function updateRole(
  realm: string,
  roleId: string,
  spec: { name: string; description?: string; display_name?: string; client_id?: string },
): Promise<void> {
  await api<unknown>(adminPath(realm, `roles/${encodeURIComponent(roleId)}`), {
    method: "PUT",
    json: spec,
    subject: say("subject-role", { role: spec.name }),
  });
}

export async function deleteRole(realm: string, roleId: string): Promise<void> {
  await api<void>(adminPath(realm, `roles/${encodeURIComponent(roleId)}`), {
    method: "DELETE",
    quiet: true,
  });
}

export async function createOrganization(
  realm: string,
  spec: { name: string; display_name?: string; description?: string },
) {
  return api<{ org_id: string; name: string }>(adminPath(realm, "organizations"), {
    method: "POST",
    json: spec,
    subject: say("subject-org", { org: spec.name }),
  });
}

export async function updateOrganization(
  realm: string,
  orgId: string,
  spec: { name: string; display_name?: string; description?: string },
): Promise<void> {
  await api<unknown>(adminPath(realm, `organizations/${encodeURIComponent(orgId)}`), {
    method: "PUT",
    json: spec,
    subject: say("subject-org", { org: spec.name }),
  });
}

export async function deleteOrganization(realm: string, orgId: string): Promise<void> {
  await api<void>(adminPath(realm, `organizations/${encodeURIComponent(orgId)}`), {
    method: "DELETE",
    quiet: true,
  });
}

/// Claim a domain; the answer carries the TXT challenge to publish.
export async function claimDomain(realm: string, orgId: string, domain: string) {
  return api<{ domain: string; challenge: string }>(
    adminPath(realm, `organizations/${encodeURIComponent(orgId)}/domains`),
    {
      method: "POST",
      json: { domain },
      subject: say("subject-domain", { domain }),
    },
  );
}

/// The operator attests the record is published; no probe runs server side.
export async function verifyDomain(realm: string, orgId: string, domain: string): Promise<void> {
  await api<unknown>(
    adminPath(
      realm,
      `organizations/${encodeURIComponent(orgId)}/domains/${encodeURIComponent(domain)}/verify`,
    ),
    { method: "POST", subject: say("subject-domain", { domain }) },
  );
}

export async function dropDomain(realm: string, orgId: string, domain: string): Promise<void> {
  await api<void>(
    adminPath(
      realm,
      `organizations/${encodeURIComponent(orgId)}/domains/${encodeURIComponent(domain)}`,
    ),
    { method: "DELETE", subject: say("subject-domain", { domain }) },
  );
}
