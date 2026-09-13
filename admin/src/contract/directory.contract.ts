import { describe, expect, test } from "vitest";
import {
  addCompositeRole,
  addOrganizationMember,
  claimDomain,
  createGroup,
  createOrganization,
  createRole,
  deleteGroup,
  deleteOrganization,
  deleteRole,
  dropDomain,
  forgetOrganizationTheme,
  getOrganization,
  getOrganizationTheme,
  grantRoleToGroup,
  listCompositeRoles,
  listGroupMembership,
  listGroups,
  listOrganizationMembers,
  listOrganizations,
  listRoleHolders,
  listRoles,
  markGroupDefault,
  removeCompositeRole,
  removeOrganizationMember,
  revokeRoleFromGroup,
  updateGroup,
  updateOrganization,
  updateRole,
  writeOrganizationTheme,
} from "@/services/directory";
import {
  grantRoleToUser,
  joinGroup,
  leaveGroup,
  listMemberGroups,
  listMemberOrganizations,
  revokeRoleFromUser,
} from "@/services/users";
import { keepAnswer, REALM } from "./answers";

// Planted by the server's contract test.
const ADA = "ada";
const DOMAIN = "contract.example.test";

describe("roles", () => {
  test("creates roles, composes them, grants one, and removes them", async () => {
    const parent = await keepAnswer(createRole, REALM, {
      name: "contract-auditor",
      display_name: "Auditor",
      description: "",
    });
    const child = await keepAnswer(createRole, REALM, {
      name: "contract-reader",
      display_name: "Reader",
      description: "",
    });
    await updateRole(REALM, parent.role_id, {
      name: "contract-auditor",
      display_name: "Auditor",
      description: "Reads the journal",
    });
    const page = await keepAnswer(listRoles, REALM, 0, 50);
    expect(page.items.some((role) => role.role_id === parent.role_id)).toBe(true);

    await addCompositeRole(REALM, parent.role_id, child.role_id);
    const composites = await keepAnswer(listCompositeRoles, REALM, parent.role_id);
    expect(composites.some((role) => role.role_id === child.role_id)).toBe(true);
    await grantRoleToUser(REALM, parent.role_id, ADA);
    const holders = await keepAnswer(listRoleHolders, REALM, parent.role_id);
    expect(holders.users).toContain(ADA);

    await revokeRoleFromUser(REALM, parent.role_id, ADA);
    await removeCompositeRole(REALM, parent.role_id, child.role_id);
    await deleteRole(REALM, child.role_id);
    await deleteRole(REALM, parent.role_id);
  });
});

describe("groups", () => {
  test("creates a group, fills it, and removes it", async () => {
    const group = await keepAnswer(createGroup, REALM, "contract-team", "Under contract");
    await updateGroup(REALM, { ...group, display_name: "Contract team" });
    await markGroupDefault(REALM, group, true);
    await markGroupDefault(REALM, group, false);
    const page = await keepAnswer(listGroups, REALM, 0, 50);
    expect(page.items.some((held) => held.group_id === group.group_id)).toBe(true);

    const role = await createRole(REALM, {
      name: "contract-team-role",
      display_name: "Team role",
      description: "",
    });
    await joinGroup(REALM, group.group_id, ADA);
    await grantRoleToGroup(REALM, group.group_id, role.role_id);
    const membership = await keepAnswer(listGroupMembership, REALM, group.group_id);
    expect(membership.users).toContain(ADA);
    expect(membership.roles.length).toBeGreaterThan(0);
    const groups = await keepAnswer(listMemberGroups, REALM, ADA);
    expect(groups.length).toBeGreaterThan(0);

    await revokeRoleFromGroup(REALM, group.group_id, role.role_id);
    await leaveGroup(REALM, group.group_id, ADA);
    await deleteRole(REALM, role.role_id);
    await deleteGroup(REALM, group.group_id);
  });
});

describe("organizations", () => {
  test("creates an organization with a member, a domain and a theme, and removes it", async () => {
    const born = await keepAnswer(createOrganization, REALM, {
      name: "contract-org",
      display_name: "Contract org",
      description: "",
    });
    await updateOrganization(REALM, born.org_id, {
      name: "contract-org",
      display_name: "Contract organization",
      description: "Under contract",
    });
    const page = await keepAnswer(listOrganizations, REALM, 0, 50);
    expect(page.items.some((held) => held.org_id === born.org_id)).toBe(true);

    await addOrganizationMember(REALM, born.org_id, ADA);
    const members = await keepAnswer(listOrganizationMembers, REALM, born.org_id);
    expect(members.some((member) => member.user_id === ADA)).toBe(true);
    const organizations = await keepAnswer(listMemberOrganizations, REALM, ADA);
    expect(organizations.length).toBeGreaterThan(0);

    const claimed = await keepAnswer(claimDomain, REALM, born.org_id, DOMAIN);
    expect(claimed.challenge.length).toBeGreaterThan(0);
    const organization = await keepAnswer(getOrganization, REALM, born.org_id);
    expect(organization.domains.some((domain) => domain.name === DOMAIN)).toBe(true);
    await dropDomain(REALM, born.org_id, DOMAIN);

    await writeOrganizationTheme(REALM, born.org_id, { light: { bg: "#ffffff" } });
    const theme = await keepAnswer(getOrganizationTheme, REALM, born.org_id);
    expect(theme?.light?.bg).toBe("#ffffff");
    await forgetOrganizationTheme(REALM, born.org_id);

    await removeOrganizationMember(REALM, born.org_id, ADA);
    await deleteOrganization(REALM, born.org_id);
  });
});
