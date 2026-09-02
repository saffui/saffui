/// Partial mirror of `models::entities::auth::AuthenticationFlowModel`.
export interface FlowRow {
  flow_id: string;
  alias: string;
  description: string;
  top_level: boolean | null;
  built_in: boolean | null;
}

export type Requirement = "required" | "alternative" | "disabled";

/// Mirrors `models::entities::auth::ExecutionStep` (internally tagged).
export type ExecutionStepShape =
  | { kind: "authenticator"; authenticator: string; config_id: string | null }
  | { kind: "sub_flow"; flow_id: string };

/// Partial mirror of `models::entities::auth::AuthenticationExecutionModel`.
export interface ExecutionRow {
  execution_id: string;
  alias: string;
  flow_id: string;
  priority: number;
  step: ExecutionStepShape;
  requirement: Requirement;
}

/// Mirrors `GET .../auth/flows/{flow}`.
export interface FlowDetail {
  flow: FlowRow;
  executions: ExecutionRow[];
}
