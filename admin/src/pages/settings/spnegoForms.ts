import type { SpnegoMutation, SpnegoRow } from "@/services/negotiation";
import { servicePrincipal } from "@/services/negotiation";

export interface SpnegoDraft {
  enabled: boolean;
  servicePrincipal: string;
}

export function spnegoDraft(row: SpnegoRow | null): SpnegoDraft {
  return {
    enabled: row?.enabled !== false,
    servicePrincipal: row ? servicePrincipal(row) : "",
  };
}

export function spnegoMutation(draft: SpnegoDraft): SpnegoMutation {
  return {
    enabled: draft.enabled,
    configs: { service_principal: { Str: draft.servicePrincipal.trim() } },
  };
}

export function spnegoIsWritable(draft: SpnegoDraft): boolean {
  const principal = draft.servicePrincipal.trim();
  return principal.includes("/") && principal.includes("@");
}
