import type { FlowDetail } from "@/models/flows";

export interface FlowIssue {
  executionId: string;
  message: string;
}

export function flowIssues(flow: FlowDetail): FlowIssue[] {
  const issues: FlowIssue[] = [];
  const priorities = new Map<number, string>();
  for (const row of flow.executions) {
    const previous = priorities.get(row.priority);
    if (previous) {
      issues.push({ executionId: row.execution_id, message: `duplicate priority ${row.priority}` });
    }
    priorities.set(row.priority, row.execution_id);
    if (row.step.kind === "sub_flow" && row.step.flow_id === flow.flow.flow_id) {
      issues.push({ executionId: row.execution_id, message: "flow cannot contain itself" });
    }
  }
  return issues;
}
