/// Mirrors what `GET /admin/features` answers per row: the registry entry of
/// `commons::feature`, resolved against this build.
export interface FeatureBrief {
  slug: string;
  lifecycle: string;
  compiled: boolean;
  enabled: boolean;
  doc: string;
}

/// One capability as the realm sees it.
///
/// `enabled` is what this realm runs, which is the process's answer narrowed
/// by what the realm asked for. `asked` is the realm's own wish, null where it
/// has never spoken, so "off because we closed it" reads apart from "off
/// because this node was not started with it".
export interface RealmFeature {
  slug: string;
  lifecycle: "stable" | "preview" | "experimental" | "deprecated";
  /// Whose switch it is. A process capability is read-only here.
  reach: "process" | "realm";
  /// What goes away with it. "weakens" means closing it takes a protection
  /// that was in force, which an administrator hardening a realm would not
  /// expect, so the console asks before it does that.
  closing: "narrows" | "weakens";
  doc: string;
  compiled: boolean;
  in_process: boolean;
  enabled: boolean;
  asked: boolean | null;
  changed_by: string | null;
  changed_at: string | null;
}
