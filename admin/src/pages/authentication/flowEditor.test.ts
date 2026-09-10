import { describe, expect, test } from "vitest";
import { flowIssues } from "./flowEditor";

describe("flow editor validation", () => {
  test("flags duplicate priorities and self-containing subflows", () => {
    const issues = flowIssues({
      flow: { flow_id: "f-1", alias: "browser", description: "", top_level: true, built_in: false },
      executions: [
        { execution_id: "e-1", alias: "password", flow_id: "f-1", priority: 10, requirement: "required", step: { kind: "authenticator", authenticator: "password", config_id: null } },
        { execution_id: "e-2", alias: "self", flow_id: "f-1", priority: 10, requirement: "alternative", step: { kind: "sub_flow", flow_id: "f-1" } },
      ],
    });
    expect(issues.map((issue) => issue.executionId)).toEqual(["e-2", "e-2"]);
  });
});
