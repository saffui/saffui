import type { RequiredActionRow } from "@/models/flows";

export interface UnregisterFact {
  value: string;
  label: string;
}

/// What goes with a realm's row for an action, as the dialog counts it: whether it is
/// offered, whether new accounts are born owing it, and its priority.
export function countUnregistering(
  row: RequiredActionRow,
  say: (key: string) => string,
): UnregisterFact[] {
  const state = (on: boolean | null) => say(on ? "actions-fact-on" : "actions-fact-off");
  return [
    { value: state(row.enabled), label: say("actions-col-enabled") },
    { value: state(row.default_action), label: say("actions-col-birth") },
    { value: String(row.priority ?? 0), label: say("flow-priority") },
  ];
}

/// An action the realm turned off is refused when someone asks it of a person; once its
/// row is gone nothing refuses it, which the dialog warns of.
export function warnsOfUnregistering(row: RequiredActionRow): boolean {
  return row.enabled === false;
}
