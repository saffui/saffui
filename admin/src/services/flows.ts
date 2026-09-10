import { adminPath, api } from "@/services/http";
import { say } from "@/i18n";
import type { FlowDetail, FlowRow, Requirement, RequiredActionRow } from "@/models/flows";

export async function listFlows(realm: string): Promise<FlowRow[]> {
  return api<FlowRow[]>(adminPath(realm, "auth/flows"));
}

/// Make a flow. A realm is born with one, `browser`, and everything else is
/// built here: a second factor before the client sees a session, a flow bound
/// to one client, a copy to try a change on.
export async function createFlow(
  realm: string,
  flow: { alias: string; description: string; top_level: boolean },
): Promise<FlowRow> {
  return api<FlowRow>(adminPath(realm, "auth/flows"), {
    method: "POST",
    json: {
      alias: flow.alias,
      // The only kind this build runs. A flow's provider decides how its
      // steps are read, and nothing reads another.
      provider_id: "basic-flow",
      description: flow.description,
      top_level: flow.top_level,
      // What the realm was born with is built in; what somebody adds is not,
      // and saying otherwise would let a deletion look refusable when it is
      // not, or the reverse.
      built_in: false,
    },
    subject: say("flows-subject", { flow: flow.alias }),
  });
}

/// Take a flow away. The realm's own binding is checked by the server, which
/// refuses to leave a realm with no flow to run.
export async function deleteFlow(realm: string, flowId: string): Promise<void> {
  await api<void>(adminPath(realm, `auth/flows/${encodeURIComponent(flowId)}`), {
    method: "DELETE",
    subject: say("flows-subject", { flow: flowId }),
  });
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

/// Rewrite the whole running order in one breath, the way a drag ends.
export async function reorderFlow(
  realm: string,
  flowId: string,
  order: { execution_id: string; priority: number }[],
): Promise<void> {
  await api<unknown>(adminPath(realm, `auth/flows/${encodeURIComponent(flowId)}/order`), {
    method: "PUT",
    json: { order },
    subject: say("subject-flow-order"),
  });
}

export async function removeExecution(realm: string, executionId: string): Promise<void> {
  await api<void>(adminPath(realm, `auth/executions/${encodeURIComponent(executionId)}`), {
    method: "DELETE",
    subject: say("subject-execution", { step: executionId }),
  });
}

export async function listActions(realm: string): Promise<RequiredActionRow[]> {
  return api<RequiredActionRow[]>(adminPath(realm, "auth/required-actions"));
}

export async function registerAction(
  realm: string,
  body: Omit<RequiredActionRow, "action_id">,
): Promise<RequiredActionRow> {
  return api<RequiredActionRow>(adminPath(realm, "auth/required-actions"), {
    method: "POST",
    json: body,
    subject: say("subject-action", { action: body.action }),
  });
}

export async function reworkAction(
  realm: string,
  action: string,
  body: Omit<RequiredActionRow, "action_id">,
): Promise<void> {
  await api<unknown>(adminPath(realm, `auth/required-actions/${encodeURIComponent(action)}`), {
    method: "PUT",
    json: body,
    subject: say("subject-action", { action }),
  });
}
