import { adminPath, api } from "@/services/http";
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
    { method: "PUT", json: { requirement } },
  );
}
