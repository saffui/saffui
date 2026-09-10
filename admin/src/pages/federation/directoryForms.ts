import type { DirectoryMutation, DirectoryRow } from "@/models/federation";
import { configText } from "./forms";

export interface DirectoryDraft {
  alias: string;
  enabled: boolean;
  priority: number;
  url: string;
  bindDn: string;
  bindPassword: string;
  usersDn: string;
  userFilter: string;
  usernameAttribute: string;
  emailAttribute: string;
  firstNameAttribute: string;
  lastNameAttribute: string;
  dangerPlaintext: boolean;
}

export function emptyDirectoryDraft(): DirectoryDraft {
  return {
    alias: "",
    enabled: true,
    priority: 0,
    url: "ldaps://",
    bindDn: "",
    bindPassword: "",
    usersDn: "",
    userFilter: "(uid={username})",
    usernameAttribute: "uid",
    emailAttribute: "mail",
    firstNameAttribute: "givenName",
    lastNameAttribute: "sn",
    dangerPlaintext: false,
  };
}

export function directoryDraft(row: DirectoryRow): DirectoryDraft {
  return {
    alias: row.alias,
    enabled: row.enabled !== false,
    priority: row.priority,
    url: configText(row, "url"),
    bindDn: configText(row, "bind_dn"),
    bindPassword: "",
    usersDn: configText(row, "users_dn"),
    userFilter: configText(row, "user_filter") || "(uid={username})",
    usernameAttribute: configText(row, "username_attribute") || "uid",
    emailAttribute: configText(row, "email_attribute") || "mail",
    firstNameAttribute: configText(row, "first_name_attribute") || "givenName",
    lastNameAttribute: configText(row, "last_name_attribute") || "sn",
    dangerPlaintext: configText(row, "danger_plaintext") === "true",
  };
}

export function directoryMutation(draft: DirectoryDraft): DirectoryMutation {
  const configs: DirectoryMutation["configs"] = {
    url: { Str: draft.url.trim() },
    bind_dn: { Str: draft.bindDn.trim() },
    users_dn: { Str: draft.usersDn.trim() },
    user_filter: { Str: draft.userFilter.trim() },
    username_attribute: { Str: draft.usernameAttribute.trim() },
    email_attribute: { Str: draft.emailAttribute.trim() },
    first_name_attribute: { Str: draft.firstNameAttribute.trim() },
    last_name_attribute: { Str: draft.lastNameAttribute.trim() },
  };
  if (draft.bindPassword) configs.bind_password = { Str: draft.bindPassword };
  if (draft.url.trim().startsWith("ldap://") && draft.dangerPlaintext) {
    configs.danger_plaintext = { Str: "true" };
  }
  return { enabled: draft.enabled, priority: draft.priority, configs };
}

export function directoryIsWritable(draft: DirectoryDraft): boolean {
  const url = draft.url.trim();
  return (
    (url.startsWith("ldaps://") || (url.startsWith("ldap://") && draft.dangerPlaintext)) &&
    draft.userFilter.includes("{username}")
  );
}
