import { describe, expect, test } from "vitest";
import {
  addExecution,
  createFlow,
  deleteFlow,
  getFlow,
  listActions,
  listFlows,
  registerAction,
  removeExecution,
  reorderFlow,
  reworkAction,
  setRequirement,
  unregisterAction,
} from "@/services/flows";
import { keepAnswer, REALM } from "./answers";

const ACTIONS = [
  { action: "verify-email", provider: "mail", title: "Verify email" },
  { action: "configure-totp", provider: "totp", title: "Configure authenticator app" },
  { action: "update-password", provider: "password", title: "Update password" },
  { action: "configure-recovery-codes", provider: "recovery-code", title: "Draw recovery codes" },
  { action: "configure-webauthn", provider: "webauthn", title: "Configure passkey" },
];

describe("authentication flows", () => {
  test("builds a flow step by step and removes it", async () => {
    const flows = await keepAnswer(listFlows, REALM);
    expect(flows.some((flow) => flow.alias === "browser")).toBe(true);

    const flow = await keepAnswer(createFlow, REALM, {
      alias: "contract-flow",
      description: "Under contract",
      top_level: true,
    });
    await addExecution(REALM, flow.flow_id, {
      alias: "contract-password",
      flow_id: flow.flow_id,
      priority: 10,
      step: { kind: "authenticator", authenticator: "password" },
      requirement: "required",
    });
    const built = await keepAnswer(getFlow, REALM, flow.flow_id);
    const [step] = built.executions;
    if (!step) throw new Error("the step did not read back");
    await setRequirement(REALM, step.execution_id, "alternative");
    await reorderFlow(REALM, flow.flow_id, [{ execution_id: step.execution_id, priority: 20 }]);
    await removeExecution(REALM, step.execution_id);
    await deleteFlow(REALM, flow.flow_id);
  });

  test("registers a required action, reworks it and unregisters it", async () => {
    const registered = await keepAnswer(listActions, REALM);
    const fresh = ACTIONS.find((held) => !registered.some((row) => row.action === held.action));
    expect(fresh).toBeDefined();
    const row = fresh
      ? await keepAnswer(registerAction, REALM, {
          provider_id: fresh.provider,
          action: fresh.action,
          name: fresh.action,
          display_name: fresh.title,
          description: "",
          enabled: true,
          default_action: false,
          on_time_action: null,
          priority: 100,
        })
      : registered[0];
    await reworkAction(REALM, row.action, {
      provider_id: row.provider_id,
      action: row.action,
      name: row.name,
      display_name: row.display_name,
      description: "Reworked under contract",
      enabled: row.enabled,
      default_action: row.default_action,
      on_time_action: row.on_time_action,
      priority: row.priority,
    });
    await unregisterAction(REALM, row.action);
    const left = await keepAnswer(listActions, REALM);
    expect(left.some((held) => held.action === row.action)).toBe(false);
  });
});
