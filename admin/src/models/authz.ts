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
  /// The rest of what a policy carries, sent back whole so an edit replaces
  /// the terms rather than dropping the ones the screen does not show.
  decision: string;
  logic: string;
  policy_owner: string;
  /// The rule's own list, under the name its kind uses. Absent for a kind
  /// that carries nothing of its own, and for the kinds this console does not
  /// author yet.
  roles?: string[];
  groups?: string[];
  users?: string[];
  clients?: string[];
  client_scopes?: string[];
}

/// Partial mirror of a stored resource row.
export interface ResourceRow {
  resource_id: string;
  name: string;
  /// Whether this resource may be shared as a relation on it. The server it
  /// belongs to is the ceiling; this cannot open what that has closed.
  user_managed_access?: boolean;
}

export interface ScopeRow {
  scope_id: string;
  name: string;
}

export interface AuthzRoute {
  route_id: string;
  method: string;
  path: string;
  server_id: string;
  resource: string;
  scope: string;
  action: string;
  priority: number;
  enabled: boolean;
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
  /// Where the walk went, for a relationship question. Absent for the others,
  /// which are decided by policies rather than walked.
  walk?: RelationWalk;
}

/// One step the engine took, in the order it took it.
export interface WalkStep {
  depth: number;
  /// `object_type:object_id#member`, the way a tuple is written.
  asked: string;
  /// What the graph told it to do there, absent where the graph said nothing.
  rule: string | null;
  /// How it came out, absent where the walk stopped before answering.
  answered: boolean | null;
  note: string | null;
}

export interface RelationWalk {
  /// Absent where the walk stopped rather than answering.
  reached: boolean | null;
  /// Why it stopped, in the engine's own words.
  stopped: string | null;
  steps: WalkStep[];
  /// Steps beyond what the trace keeps. Nonzero means the tail is missing.
  cut: number;
}

export type EvaluateQuestion =
  | { kind: "policy"; server_id: string; policy_id: string }
  | { kind: "permission"; server_id: string; resource: string; scope: string }
  | { kind: "relationship"; object_type: string; object_id: string; relation: string };
