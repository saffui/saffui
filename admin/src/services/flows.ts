import { adminPath, api } from "@/services/http";
import { say } from "@/i18n";
import type { FlowDetail, FlowRow, Requirement } from "@/models/flows";

export async function listFlows(realm: string): Promise<FlowRow[]> {
  return api<FlowRow[]>(adminPath(realm, "auth/flows"));
}

export async function getFlow(realm: string, flowId: string): Promise<FlowDetail> {
  return api<FlowDetail>(adminPath(realm, `auth/flows/${encodeURIComponent(flowId)}`));
}

export async function setRequirement(
  realm: string,
  executionId: string,
  requirement: Requirement,
): Promise<void> {
  await api<unknown>(
    adminPath(realm, `auth/executions/${encodeURIComponent(executionId)}/requirement`),
    { method: "PUT", json: { requirement }, subject: say("subject-requirement") },
  );
}

/// Add one step to a flow, an authenticator from the build catalogue or a
/// sub flow, at the given priority.
export async function addExecution(
  realm: string,
  flowId: string,
  body: {
    alias: string;
    flow_id: string;
    priority: number;
    step: { kind: "authenticator"; authenticator: string } | { kind: "sub_flow"; flow_id: string };
    requirement: string;
  },
): Promise<void> {
  await api<unknown>(adminPath(realm, `auth/flows/${encodeURIComponent(flowId)}/executions`), {
    method: "POST",
    json: body,
    subject: say("subject-execution", { step: body.alias }),
  });
}

export async function removeExecution(realm: string, executionId: string): Promise<void> {
  await api<void>(adminPath(realm, `auth/executions/${encodeURIComponent(executionId)}`), {
    method: "DELETE",
    subject: say("subject-execution", { step: executionId }),
  });
}
