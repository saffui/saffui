import { adminPath, api } from "@/services/http";
import { say } from "@/i18n";

/// Mirrors the plane's subject-request answer.
export interface SubjectRequest {
  request_id: string;
  user_id: string | null;
  subject_identifier: string;
  kind: string;
  stage: string;
  outcome?: string;
  reason?: string;
  jurisdiction: string;
  received_at: number;
  due_at: number;
  verified_at: number | null;
  closed_at: number | null;
  deadline_source: string;
}

export interface LodgeSpec {
  subject_identifier: string;
  kind: string;
  jurisdiction: string;
  due_at?: number;
}

export async function listSubjectRequests(realm: string): Promise<SubjectRequest[]> {
  return api<SubjectRequest[]>(adminPath(realm, "subject-requests"));
}

export async function lodgeSubjectRequest(
  realm: string,
  spec: LodgeSpec,
): Promise<SubjectRequest> {
  return api<SubjectRequest>(adminPath(realm, "subject-requests"), {
    method: "POST",
    json: spec,
    subject: say("subject-dsar"),
  });
}

export async function verifySubjectRequest(
  realm: string,
  requestId: string,
): Promise<SubjectRequest> {
  return api<SubjectRequest>(
    adminPath(realm, `subject-requests/${encodeURIComponent(requestId)}/verify`),
    { method: "POST", json: {}, subject: say("subject-dsar") },
  );
}

export async function refuseSubjectRequest(
  realm: string,
  requestId: string,
  reason: string,
): Promise<SubjectRequest> {
  return api<SubjectRequest>(
    adminPath(realm, `subject-requests/${encodeURIComponent(requestId)}/refuse`),
    { method: "POST", json: { reason }, subject: say("subject-dsar") },
  );
}

/// Execute a verified erasure and close it. Only erasure has an execution
/// today; the plane says so for the other kinds.
export interface FulfilSpec {
  email?: string;
  given_name?: string;
  family_name?: string;
  phone_number?: string;
  client_id?: string;
}

export async function fulfilSubjectRequest(
  realm: string,
  requestId: string,
  spec: FulfilSpec = {},
): Promise<SubjectRequest & { bundle?: unknown }> {
  return api<SubjectRequest & { bundle?: unknown }>(
    adminPath(realm, `subject-requests/${encodeURIComponent(requestId)}/fulfil`),
    { method: "POST", json: spec, subject: say("subject-dsar") },
  );
}

/// Mirrors the plane's breach answer.
export interface BreachRecord {
  breach_id: string;
  description: string;
  data_categories: string[];
  subjects_affected: number | null;
  severity: string;
  status: string;
  jurisdiction: string;
  occurred_at: number | null;
  discovered_at: number;
  notify_by: number | null;
  notified_at: number | null;
  notified_to: string | null;
  filed_by: string | null;
}

export interface DiscoverSpec {
  description: string;
  data_categories: string[];
  severity: string;
  jurisdiction: string;
  occurred_at?: number;
}

export async function listBreaches(realm: string): Promise<BreachRecord[]> {
  return api<BreachRecord[]>(adminPath(realm, "breaches"));
}

export async function discoverBreach(realm: string, spec: DiscoverSpec): Promise<BreachRecord> {
  return api<BreachRecord>(adminPath(realm, "breaches"), {
    method: "POST",
    json: spec,
    subject: say("subject-breach"),
  });
}

export async function advanceBreach(
  realm: string,
  breachId: string,
  step: "assess" | "filing" | "not-notifiable" | "close",
  body: Record<string, unknown> = {},
): Promise<BreachRecord> {
  return api<BreachRecord>(
    adminPath(realm, `breaches/${encodeURIComponent(breachId)}/${step}`),
    { method: "POST", json: body, subject: say("subject-breach") },
  );
}

export async function breachNotificationDraft(
  realm: string,
  breachId: string,
): Promise<Record<string, unknown>> {
  return api<Record<string, unknown>>(
    adminPath(realm, `breaches/${encodeURIComponent(breachId)}/notification-draft`),
  );
}

/// Assemble the period's evidence pack; drawn fresh, never stored.
export async function assembleEvidencePack(
  realm: string,
  from: number,
  to: number,
): Promise<Record<string, unknown>> {
  return api<Record<string, unknown>>(
    adminPath(realm, `evidence-pack?from=${from}&to=${to}`),
  );
}
