export function realmNameFromImportDocument(document: unknown): string {
  if (!document || typeof document !== "object") return "";
  const held = document as Record<string, unknown>;
  if (typeof held.realm_id === "string") return held.realm_id;
  if (!held.realm || typeof held.realm !== "object") return "";
  const realm = held.realm as Record<string, unknown>;
  if (typeof realm.name === "string") return realm.name;
  return typeof realm.realm_id === "string" ? realm.realm_id : "";
}
