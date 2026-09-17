import type { AttributeValue } from "@/models/client";

/// A key a rule reads as a switch, with what its absence means. The resting
/// value comes from the server because it is not the same for every switch.
export interface Switch {
  key: string;
  resting: boolean;
}

/// What one rule reads, as the server says it.
export interface RuleKeys {
  mapper_type: string;
  allowed: string[];
  required: string[];
  one_of: string[];
  booleans: Switch[];
}

/// The answer of `mapper-kinds`: every rule this build runs, and the flags
/// they all read.
export interface Kinds {
  kinds: RuleKeys[];
  target_flags: Switch[];
}

export interface Field {
  key: string;
  required: boolean;
  /// One of several spellings, of which the rule needs one.
  alternative: boolean;
}

/// The fields a rule offers, its own keys only: the flags every rule reads are
/// answered apart, because a form that mixes them makes the common look like
/// the particular. A key the rule reads as a switch is answered apart too,
/// since a toggle says the same thing without anybody typing `true`.
export function fieldsOf(kinds: Kinds, mapperType: string): Field[] {
  const rule = kinds.kinds.find((held) => held.mapper_type === mapperType);
  if (!rule) return [];
  const switches = rule.booleans.map((held) => held.key);
  return rule.allowed
    .filter((key) => !switches.includes(key))
    .map((key) => ({
      key,
      required: rule.required.includes(key),
      alternative: rule.one_of.includes(key),
    }));
}

/// The switches a rule carries of its own, beside the three every rule reads.
export function switchesOf(kinds: Kinds, mapperType: string): Switch[] {
  return kinds.kinds.find((held) => held.mapper_type === mapperType)?.booleans ?? [];
}

/// A flag as the server reads one: stored as a boolean, or as the string a
/// JSON bag carries. A rule written either way has to show the same switch.
///
/// `resting` is what an absent value means, and it is not the same everywhere:
/// a target flag absent means the claim rides everywhere, while `multivalued`
/// absent means a single value. One hardcoded default would show a rule as
/// multivalued when it is not.
export function readFlag(value: AttributeValue | undefined, resting: boolean): boolean {
  if (!value) return resting;
  if ("Bool" in value) return value.Bool;
  if ("Str" in value) return ["true", "1"].includes(value.Str.trim().toLowerCase());
  return resting;
}

/// The text of a value, for the fields that carry one.
export function readText(value: AttributeValue | undefined): string {
  if (!value) return "";
  if ("Str" in value) return value.Str;
  if ("Int" in value) return String(value.Int);
  if ("Bool" in value) return String(value.Bool);
  return value.ListStr.join(", ");
}

/// Written back as a string, which is what every key this build reads expects;
/// the server narrows where a rule says to.
export function writeText(text: string): AttributeValue {
  return { Str: text };
}

export function writeFlag(on: boolean): AttributeValue {
  return { Bool: on };
}

/// What the door would refuse, said here first so an operator hears it without
/// a round trip. The door stays the authority: this only spares the trip.
export function missing(
  kinds: Kinds,
  mapperType: string,
  configs: Record<string, AttributeValue>,
): string[] {
  const rule = kinds.kinds.find((held) => held.mapper_type === mapperType);
  if (!rule) return [];
  const held = Object.keys(configs);
  const said: string[] = [];
  for (const key of held) {
    if (!rule.allowed.includes(key) && !kinds.target_flags.some((flag) => flag.key === key)) {
      said.push(key);
    }
  }
  const absent = rule.required.filter((key) => !held.includes(key));
  const oneOf =
    rule.one_of.length > 0 && !rule.one_of.some((key) => held.includes(key)) ? rule.one_of : [];
  return [
    ...said.map((key) => `unknown:${key}`),
    ...absent.map((key) => `missing:${key}`),
    ...(oneOf.length ? [`one-of:${oneOf.join(",")}`] : []),
  ];
}

/// The escape hatch, both ways. The fields and the text are two readings of
/// one bag rather than two states to keep in step, so switching loses nothing.
export function asJson(configs: Record<string, AttributeValue>): string {
  return JSON.stringify(configs, null, 2);
}

export function fromJson(text: string): Record<string, AttributeValue> | null {
  try {
    const read = JSON.parse(text) as unknown;
    if (!read || typeof read !== "object" || Array.isArray(read)) return null;
    return read as Record<string, AttributeValue>;
  } catch {
    return null;
  }
}
