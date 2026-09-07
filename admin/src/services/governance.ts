import { say } from "@/i18n";
import { adminPath, api } from "@/services/http";

/// The plane only answers PUT at a named rule, so a new rule draws its
/// own identifier here.
export async function createRule(realm: string, body: Record<string, unknown>) {
  return api<unknown>(adminPath(realm, `iga/rules/${crypto.randomUUID()}`), {
    method: "PUT",
    json: body,
    subject: say("subject-rule"),
  });
}

export async function updateRule(
  realm: string,
  ruleId: string,
  body: Record<string, unknown>,
): Promise<void> {
  await api<unknown>(adminPath(realm, `iga/rules/${encodeURIComponent(ruleId)}`), {
    method: "PUT",
    json: body,
    subject: say("subject-rule"),
  });
}

export async function deleteRule(realm: string, ruleId: string): Promise<void> {
  await api<void>(adminPath(realm, `iga/rules/${encodeURIComponent(ruleId)}`), {
    method: "DELETE",
    subject: say("subject-rule"),
  });
}

/// Re-walk every rule now rather than at the sweeper's next pass.
export async function convergeRules(realm: string): Promise<void> {
  await api<unknown>(adminPath(realm, "iga/converge"), {
    method: "POST",
    subject: say("subject-converge"),
  });
}

export async function handGrant(
  realm: string,
  body: { user_id: string; role_id: string; expires_at?: string },
): Promise<void> {
  await api<unknown>(adminPath(realm, "iga/grants"), {
    method: "POST",
    json: body,
    subject: say("subject-hand-grant", { role: body.role_id, user: body.user_id }),
  });
}

export async function revokeGrant(realm: string, userId: string, roleId: string): Promise<void> {
  await api<void>(
    adminPath(realm, `iga/grants/${encodeURIComponent(userId)}/${encodeURIComponent(roleId)}`),
    { method: "DELETE", subject: say("subject-hand-grant", { role: roleId, user: userId }) },
  );
}

export interface SodRule {
  rule_id: string;
  roles: string[];
  min_conflicting: number;
  enabled: boolean;
}

export interface SodViolation {
  user_id: string;
  user_name: string;
  rule_id: string;
  roles: string[];
  excused: boolean;
}

export interface SodException {
  rule_id: string;
  user_id: string;
  covered_roles: string[];
  justification: string;
  granted_by: string;
  valid_until: string;
}

export async function listSodRules(realm: string): Promise<SodRule[]> {
  return api<SodRule[]>(adminPath(realm, "iga/sod/rules"));
}

export async function putSodRule(
  realm: string,
  ruleId: string,
  body: { roles: string[]; min_conflicting?: number; enabled?: boolean },
): Promise<void> {
  await api<unknown>(adminPath(realm, `iga/sod/rules/${encodeURIComponent(ruleId)}`), {
    method: "PUT",
    json: body,
    subject: say("subject-sod"),
  });
}

export async function deleteSodRule(realm: string, ruleId: string): Promise<void> {
  await api<void>(adminPath(realm, `iga/sod/rules/${encodeURIComponent(ruleId)}`), {
    method: "DELETE",
    subject: say("subject-sod"),
  });
}

/// Weighed where it is read: nothing stored, nothing stale.
export async function listSodViolations(realm: string): Promise<SodViolation[]> {
  return api<SodViolation[]>(adminPath(realm, "iga/sod/violations"));
}

export async function listSodExceptions(realm: string): Promise<SodException[]> {
  return api<SodException[]>(adminPath(realm, "iga/sod/exceptions"));
}

export async function putSodException(
  realm: string,
  ruleId: string,
  userId: string,
  body: { covered_roles: string[]; justification: string; valid_until: string },
): Promise<void> {
  await api<unknown>(
    adminPath(
      realm,
      `iga/sod/rules/${encodeURIComponent(ruleId)}/exceptions/${encodeURIComponent(userId)}`,
    ),
    { method: "PUT", json: body, subject: say("subject-sod-exception") },
  );
}

export async function deleteSodException(
  realm: string,
  ruleId: string,
  userId: string,
): Promise<void> {
  await api<void>(
    adminPath(
      realm,
      `iga/sod/rules/${encodeURIComponent(ruleId)}/exceptions/${encodeURIComponent(userId)}`,
    ),
    { method: "DELETE", subject: say("subject-sod-exception") },
  );
}
