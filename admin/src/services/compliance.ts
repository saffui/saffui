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
