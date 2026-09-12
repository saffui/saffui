import type { RealmKeyView } from "@/models/keys";

export interface KeyGroup {
  algorithm: string;
  keys: RealmKeyView[];
}

export function groupKeys(keys: RealmKeyView[]): KeyGroup[] {
  const groups = new Map<string, RealmKeyView[]>();
  for (const key of keys) {
    const group = groups.get(key.algorithm) ?? [];
    group.push(key);
    groups.set(key.algorithm, group);
  }
  return [...groups].map(([algorithm, held]) => ({
    algorithm,
    keys: [...held].sort((left, right) => (right.priority ?? 0) - (left.priority ?? 0)),
  }));
}

export function publishedKeyCount(keys: RealmKeyView[]): number {
  return keys.filter((key) => key.status !== "disabled").length;
}

export function keyCanBeRemoved(key: RealmKeyView): boolean {
  return key.status !== "active" && key.status !== "disabled";
}

export function keyCreatedAt(key: RealmKeyView): Date | null {
  if (key.created_at === undefined || !Number.isFinite(key.created_at)) return null;
  const date = new Date(key.created_at * 1000);
  return Number.isNaN(date.getTime()) ? null : date;
}
