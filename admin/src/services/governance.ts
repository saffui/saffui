import { say } from "@/i18n";
import { adminPath, api } from "@/services/http";

export async function createRule(realm: string, body: Record<string, unknown>) {
  return api<unknown>(adminPath(realm, "iga/rules"), {
    method: "POST",
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
