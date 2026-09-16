import type { ProtectedServer, ResourceRow, ResourceShare } from "@/models/authz";

export interface ShareDraft {
  relation: string;
  subject_type: string;
  subject_id: string;
  subject_relation: string;
}

export function emptyShareDraft(): ShareDraft {
  return { relation: "", subject_type: "user", subject_id: "", subject_relation: "" };
}

/// The share as it is written: a named subject, or everybody standing in a relation to
/// one. A blank subject relation is left out rather than sent as an empty name.
export function composeShare(draft: ShareDraft): ResourceShare {
  return {
    relation: draft.relation.trim(),
    subject_type: draft.subject_type.trim(),
    subject_id: draft.subject_id.trim(),
    subject_relation: draft.subject_relation.trim(),
  };
}

/// Whether a share can be written at all, said before anything is sent: the server is the
/// ceiling, then the resource. The words are keys, so the page says it in its own tongue.
export function whyShareClosed(
  server: ProtectedServer | null,
  resource: ResourceRow,
): string | null {
  if (!server?.user_managed_access) return "authz-share-server-closed";
  if (!resource.user_managed_access) return "authz-share-resource-closed";
  return null;
}

/// A share is ready when it names a relation and a subject. The subject relation is the
/// one part that may stay empty.
export function shareIsReady(draft: ShareDraft): boolean {
  const share = composeShare(draft);
  return Boolean(share.relation && share.subject_type && share.subject_id);
}
