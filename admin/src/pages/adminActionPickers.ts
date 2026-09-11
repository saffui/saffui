import type { ProtocolMapper } from "@/models/client";
import type { OrgMember, RoleRow } from "@/models/directory";
import type { UserBrief } from "@/models/user";

export type ActionPickerRow = { id: string; label: string; held: boolean };

export function organizationMemberPickerRows(
  users: Pick<UserBrief, "user_id" | "user_name">[],
  members: Pick<OrgMember, "user_id">[],
): ActionPickerRow[] {
  const held = new Set(members.map((member) => member.user_id));
  return users.map((user) => ({
    id: user.user_id,
    label: user.user_name,
    held: held.has(user.user_id),
  }));
}

export function compositeRolePickerRows(
  roles: Pick<RoleRow, "role_id" | "name" | "display_name">[],
  parentRoleId: string,
  children: Pick<RoleRow, "role_id">[],
): ActionPickerRow[] {
  const held = new Set(children.map((role) => role.role_id));
  return roles
    .filter((role) => role.role_id !== parentRoleId && !held.has(role.role_id))
    .map((role) => ({
      id: role.role_id,
      label: role.display_name || role.name,
      held: false,
    }));
}

export function clientMapperPickerRows(
  catalogue: Pick<ProtocolMapper, "mapper_id" | "name">[],
  attached: Pick<ProtocolMapper, "mapper_id">[],
): ActionPickerRow[] {
  const held = new Set(attached.map((mapper) => mapper.mapper_id));
  return catalogue
    .filter((mapper) => !held.has(mapper.mapper_id))
    .map((mapper) => ({ id: mapper.mapper_id, label: mapper.name, held: false }));
}
