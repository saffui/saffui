import type { AgentBrief } from "@/services/clients";

export interface AgentDraft {
  clientId: string;
  capabilities: string;
  sessionSeconds: number | "";
}

export function emptyAgentDraft(): AgentDraft {
  return { clientId: "", capabilities: "", sessionSeconds: "" };
}

export function agentDraft(agent: AgentBrief): AgentDraft {
  return {
    clientId: agent.client_id,
    capabilities: agent.capabilities.join("\n"),
    sessionSeconds: agent.session_seconds ?? "",
  };
}

export function capabilityList(value: string): string[] {
  return [...new Set(value.split(/[\s,]+/).map((held) => held.trim()).filter(Boolean))];
}

export function agentRegistration(draft: AgentDraft) {
  const body: { client_id: string; capabilities: string[]; session_seconds?: number } = {
    client_id: draft.clientId.trim(),
    capabilities: capabilityList(draft.capabilities),
  };
  if (draft.sessionSeconds !== "") body.session_seconds = Number(draft.sessionSeconds);
  return body;
}

export function agentReshape(agent: AgentBrief, draft: AgentDraft) {
  const next = capabilityList(draft.capabilities);
  return {
    add: next.filter((held) => !agent.capabilities.includes(held)),
    remove: agent.capabilities.filter((held) => !next.includes(held)),
    session_seconds: draft.sessionSeconds === "" ? undefined : Number(draft.sessionSeconds),
  };
}

export function agentDraftIsWritable(draft: AgentDraft): boolean {
  const seconds = draft.sessionSeconds === "" ? 0 : Number(draft.sessionSeconds);
  return Boolean(draft.clientId.trim()) && capabilityList(draft.capabilities).length > 0 &&
    (draft.sessionSeconds === "" || Number.isInteger(seconds) && seconds > 0 && seconds <= 86_400);
}
