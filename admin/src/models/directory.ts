/// Partial mirror of `models::entities::authz::RoleModel`: the fields the
/// console reads.
export interface RoleRow {
  role_id: string;
  name: string;
  display_name: string;
  description: string;
  client_id: string | null;
}

/// Partial mirror of `models::entities::authz::GroupModel`.
export interface GroupRow {
  group_id: string;
  name: string;
  display_name: string;
  description: string;
}

/// Partial mirror of `models::entities::organization::OrganizationModel`.
export interface OrganizationRow {
  org_id: string;
  name: string;
  display_name: string;
  description: string;
  enabled: boolean;
  domains: { name: string; verified: boolean }[];
  redirect_url: string | null;
}

/// Mirrors `GET .../roles/{role}/holders`.
export interface RoleHolders {
  users: string[];
  groups: string[];
}

/// Mirrors `GET .../groups/{group}/membership`.
export interface GroupMembership {
  users: string[];
  roles: string[];
}

/// Partial mirror of `models::entities::organization::OrganizationMemberModel`.
export interface OrgMember {
  user_id: string;
  membership_type: string;
  roles: string[];
  joined_at: string | null;
}
