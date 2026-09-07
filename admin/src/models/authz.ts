/// Partial mirror of `models::entities::authz::PolicyModel` (terms
/// flattened): the fields the console draws.
export interface PolicyRow {
  policy_id: string;
  name: string;
  description: string;
  policy_type: string;
  /// Child policies a composite is built from, by id.
  policies: string[];
  /// Resource ids this policy binds, making it a permission.
  resources: string[];
  scopes: string[];
}

/// Partial mirror of a stored resource row.
export interface ResourceRow {
  resource_id: string;
  name: string;
}

export interface ScopeRow {
  scope_id: string;
  name: string;
}

/// One decision the engine reached, as the log keeps it. `reported` is what
/// the caller was told and `computed` what the evaluation reached: a
/// permissive server is where the two part company.
export interface DecisionRow {
  decision_id: string;
  subject_type: string;
  subject_id: string;
  resource_kind: string;
  resource_ref: string | null;
  action: string;
  reported: string;
  computed: "permit" | "deny" | "indeterminate";
  duration_us: number;
  trace_id: string | null;
  occurred_at_millis: number | null;
}

/// Mirrors `POST .../authz/evaluate`.
export interface EvaluateAnswer {
  decision_id: string;
  reported: string;
  computed: "permit" | "deny" | "indeterminate";
  detail: { reasons?: unknown[] };
}

export type EvaluateQuestion =
  | { kind: "policy"; server_id: string; policy_id: string }
  | { kind: "permission"; server_id: string; resource: string; scope: string }
  | { kind: "relationship"; object_type: string; object_id: string; relation: string };
