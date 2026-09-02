import { adminPath, api } from "@/services/http";
import type { Page } from "@/models/paging";
import type {
  ConsentBrief,
  GroupBrief,
  KeyBrief,
  Lockout,
  OrgBrief,
  RoleBrief,
  SessionBrief,
  UserBrief,
} from "@/models/user";

export async function listUsers(
  realm: string,
  first: number,
  max: number,
): Promise<Page<UserBrief>> {
  return api<Page<UserBrief>>(`${adminPath(realm, "users")}?first=${first}&max=${max}&count=true`);
}

export async function getUser(realm: string, userId: string): Promise<UserBrief> {
  return api<UserBrief>(adminPath(realm, `users/${encodeURIComponent(userId)}`));
}

export async function getLockout(realm: string, userId: string): Promise<Lockout> {
  return api<Lockout>(adminPath(realm, `users/${encodeURIComponent(userId)}/lockout`));
}

export async function liftLockout(realm: string, userId: string): Promise<void> {
  await api<void>(adminPath(realm, `users/${encodeURIComponent(userId)}/lockout`), {
    method: "DELETE",
  });
}

export async function listWebAuthnKeys(realm: string, userId: string): Promise<KeyBrief[]> {
  return api<KeyBrief[]>(adminPath(realm, `users/${encodeURIComponent(userId)}/keys`));
}

export async function revokeWebAuthnKey(
  realm: string,
  userId: string,
  credentialId: string,
): Promise<void> {
  await api<void>(
    adminPath(
      realm,
      `users/${encodeURIComponent(userId)}/keys/${encodeURIComponent(credentialId)}`,
    ),
    { method: "DELETE" },
  );
}

export async function listSessions(realm: string, userId: string): Promise<SessionBrief[]> {
  return api<SessionBrief[]>(adminPath(realm, `users/${encodeURIComponent(userId)}/sessions`));
}

export async function closeSession(
  realm: string,
  userId: string,
  sessionId: string,
): Promise<void> {
  await api<void>(
    adminPath(
      realm,
      `users/${encodeURIComponent(userId)}/sessions/${encodeURIComponent(sessionId)}`,
    ),
    { method: "DELETE" },
  );
}

export async function listConsents(realm: string, userId: string): Promise<ConsentBrief[]> {
  const told = await api<{ consents: ConsentBrief[] }>(
    adminPath(realm, `users/${encodeURIComponent(userId)}/consents`),
  );
  return told.consents;
}

export async function listEffectiveRoles(realm: string, userId: string): Promise<RoleBrief[]> {
  const told = await api<{ roles: RoleBrief[] }>(
    adminPath(realm, `users/${encodeURIComponent(userId)}/roles`),
  );
  return told.roles;
}

export async function listMemberGroups(realm: string, userId: string): Promise<GroupBrief[]> {
  const told = await api<{ groups: GroupBrief[] }>(
    adminPath(realm, `users/${encodeURIComponent(userId)}/groups`),
  );
  return told.groups;
}

export async function listMemberOrganizations(
  realm: string,
  userId: string,
): Promise<OrgBrief[]> {
  const told = await api<{ organizations: OrgBrief[] }>(
    adminPath(realm, `users/${encodeURIComponent(userId)}/organizations`),
  );
  return told.organizations;
}
