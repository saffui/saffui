import type { RealmUpdate } from "@/models/realm";
import type { ExecutionRow } from "@/models/flows";

type NumericField = string | number;

export interface SessionSettingsValues {
  session_max_lifespan: NumericField;
  offline_session_lifespan: NumericField;
  offline_session_max_lifespan: NumericField;
  max_offline_grants: NumericField;
  access_code_lifespan_login: NumericField;
  access_code_lifespan_user_action: NumericField;
  remember_me: boolean;
}

export interface TokenSettingsValues {
  access_token_lifespan: NumericField;
  refresh_token_lifespan: NumericField;
  refresh_token_max_reuse: NumericField;
  access_code_lifespan: NumericField;
  action_tokens_lifespan: NumericField;
  device_code_lifespan: NumericField;
  device_poll_interval: NumericField;
  ciba_expiry: NumericField;
  ciba_interval: NumericField;
  revoke_refresh_token: boolean;
  require_pushed_authorization_requests: boolean;
}

function whole(value: NumericField): number | undefined {
  if (value === "") return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : undefined;
}

export function sessionSettingsChanges(values: SessionSettingsValues): RealmUpdate {
  return {
    session_max_lifespan: whole(values.session_max_lifespan) ?? 0,
    offline_session_lifespan: whole(values.offline_session_lifespan),
    offline_session_max_lifespan: whole(values.offline_session_max_lifespan) ?? 0,
    max_offline_grants: whole(values.max_offline_grants) ?? 0,
    access_code_lifespan_login: whole(values.access_code_lifespan_login),
    access_code_lifespan_user_action: whole(values.access_code_lifespan_user_action),
    remember_me: values.remember_me,
  };
}

export function tokenSettingsChanges(values: TokenSettingsValues): RealmUpdate {
  return {
    access_token_lifespan: whole(values.access_token_lifespan),
    refresh_token_lifespan: whole(values.refresh_token_lifespan),
    refresh_token_max_reuse: whole(values.refresh_token_max_reuse),
    access_code_lifespan: whole(values.access_code_lifespan),
    action_tokens_lifespan: whole(values.action_tokens_lifespan),
    device_code_lifespan: whole(values.device_code_lifespan),
    device_poll_interval: whole(values.device_poll_interval),
    ciba_expiry: whole(values.ciba_expiry),
    ciba_interval: whole(values.ciba_interval),
    revoke_refresh_token: values.revoke_refresh_token,
    require_pushed_authorization_requests: values.require_pushed_authorization_requests,
  };
}

export function passwordlessFlowCompatible(
  flowId: string,
  flows: ReadonlyMap<string, ExecutionRow[]>,
  visited = new Set<string>(),
): boolean {
  if (visited.has(flowId)) return false;
  const nextVisited = new Set(visited).add(flowId);
  const executions = flows.get(flowId) ?? [];
  const active = executions.filter((row) => row.requirement !== "disabled");
  const supports = (row: ExecutionRow) =>
    row.step.kind === "authenticator"
      ? row.step.authenticator === "webauthn"
      : passwordlessFlowCompatible(row.step.flow_id, flows, nextVisited);
  return active.some(supports) && active.filter((row) => row.requirement === "required").every(supports);
}
