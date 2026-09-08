import { say } from "@/i18n";
import { adminPath, api } from "@/services/http";
import { useSession } from "@/stores/session";

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

export interface AccessRequest {
  request_id: string;
  user_id: string;
  role_id: string;
  reason: string;
  expires_at: string | null;
  state: string;
  asked_by: string;
  decided_by: string | null;
  decided_at: string | null;
  decided_reason: string | null;
  created_at: string;
}

export async function listRequests(realm: string): Promise<AccessRequest[]> {
  return api<AccessRequest[]>(adminPath(realm, "iga/requests"));
}

export async function lodgeRequest(
  realm: string,
  body: { user_id: string; role_id: string; reason: string; expires_at?: string },
): Promise<void> {
  await api<unknown>(adminPath(realm, "iga/requests"), {
    method: "POST",
    json: body,
    subject: say("subject-request"),
  });
}

export async function approveRequest(realm: string, requestId: string): Promise<void> {
  await api<unknown>(adminPath(realm, `iga/requests/${encodeURIComponent(requestId)}/approve`), {
    method: "POST",
    subject: say("subject-request"),
  });
}

export async function denyRequest(realm: string, requestId: string, reason: string): Promise<void> {
  await api<unknown>(adminPath(realm, `iga/requests/${encodeURIComponent(requestId)}/deny`), {
    method: "POST",
    json: { reason },
    subject: say("subject-request"),
  });
}

export async function withdrawRequest(realm: string, requestId: string): Promise<void> {
  await api<unknown>(adminPath(realm, `iga/requests/${encodeURIComponent(requestId)}/withdraw`), {
    method: "POST",
    subject: say("subject-request"),
  });
}

export interface Campaign {
  campaign_id: string;
  name: string;
  scope_kind: string;
  scope_ref: string | null;
  reviewer_id: string;
  state: string;
  snapshot_at: string | null;
  closed_at: string | null;
  excluded: number;
  report_seq: number | null;
  created_at: string;
}

export interface CampaignItem {
  item_id: string;
  subject_id: string;
  edge_kind: string;
  edge_ref: string;
  frozen: Record<string, unknown>;
  state: string;
  resolution: string | null;
}

export async function listCampaigns(realm: string): Promise<Campaign[]> {
  return api<Campaign[]>(adminPath(realm, "iga/campaigns"));
}

export async function openCampaign(
  realm: string,
  body: { name: string; scope_kind: string; scope_ref?: string; reviewer_id: string },
): Promise<void> {
  await api<unknown>(adminPath(realm, "iga/campaigns"), {
    method: "POST",
    json: body,
    subject: say("subject-campaign"),
  });
}

export async function activateCampaign(realm: string, campaignId: string): Promise<void> {
  await api<unknown>(
    adminPath(realm, `iga/campaigns/${encodeURIComponent(campaignId)}/activate`),
    { method: "POST", subject: say("subject-campaign") },
  );
}

export async function listCampaignItems(
  realm: string,
  campaignId: string,
): Promise<CampaignItem[]> {
  return api<CampaignItem[]>(adminPath(realm, `iga/campaigns/${encodeURIComponent(campaignId)}/items`));
}

export async function decideItem(
  realm: string,
  campaignId: string,
  itemId: string,
  body: { decision: string; justification?: string },
): Promise<void> {
  await api<unknown>(
    adminPath(
      realm,
      `iga/campaigns/${encodeURIComponent(campaignId)}/items/${encodeURIComponent(itemId)}/decide`,
    ),
    { method: "POST", json: body, subject: say("subject-decision") },
  );
}

export async function closeCampaign(realm: string, campaignId: string): Promise<void> {
  await api<unknown>(adminPath(realm, `iga/campaigns/${encodeURIComponent(campaignId)}/close`), {
    method: "POST",
    subject: say("subject-campaign"),
  });
}

/// The report as it was hashed, read as the text it is. Parsing and
/// re-printing it would hand the operator a second rendering, and a second
/// rendering is a second digest.
export async function readReport(realm: string, campaignId: string): Promise<string> {
  const session = useSession();
  const bearer = await session.bearer();
  const answer = await fetch(
    adminPath(realm, `iga/campaigns/${encodeURIComponent(campaignId)}/report`),
    { headers: { authorization: `Bearer ${bearer}` } },
  );
  if (!answer.ok) throw new Error(String(answer.status));
  return answer.text();
}
