import { describe, expect, test } from "vitest";
import type { AgentBrief } from "@/services/clients";
import {
  agentDraft,
  agentDraftIsWritable,
  agentRegistration,
  agentReshape,
  capabilityList,
  emptyAgentDraft,
} from "./agentForms";

const agent: AgentBrief = {
  client_id: "deploy-bot",
  name: "deploy-bot",
  enabled: true,
  capabilities: ["deploy:read", "deploy:write"],
  session_seconds: 900,
  keyed: false,
  not_before: null,
};

describe("agent forms", () => {
  test("deduplicates the capability root without changing its words", () => {
    expect(capabilityList("deploy:read deploy:read\ndeploy:write")).toEqual([
      "deploy:read",
      "deploy:write",
    ]);
  });

  test("registers a keyless agent with an optional ceiling", () => {
    const draft = emptyAgentDraft();
    draft.clientId = " deploy-bot ";
    draft.capabilities = "deploy:read\ndeploy:write";
    draft.sessionSeconds = 900;
    expect(agentDraftIsWritable(draft)).toBe(true);
    expect(agentRegistration(draft)).toEqual({
      client_id: "deploy-bot",
      capabilities: ["deploy:read", "deploy:write"],
      session_seconds: 900,
    });
  });

  test("sends only capability deltas when an agent is reshaped", () => {
    const draft = agentDraft(agent);
    draft.capabilities = "deploy:read audit:read";
    expect(agentReshape(agent, draft)).toEqual({
      add: ["audit:read"],
      remove: ["deploy:write"],
      session_seconds: 900,
    });
  });
});
