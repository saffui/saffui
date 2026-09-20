/// The picture formats the door keeps, as a file dialog states them.
///
/// SVG is absent on purpose and not by oversight: served from the server's own
/// origin it is a document that runs its own script, so the door refuses it
/// whatever a dialog would have allowed. Naming the four here only spares
/// somebody choosing a file that is going to be refused.
export const ACCEPTED = "image/png,image/jpeg,image/gif,image/webp";

/// What the door will keep, in bytes. Stated by the server; repeated here only
/// to say so before a file crosses the wire.
export const LARGEST = 64 * 1024;

/// Where a realm's mark is drawn from.
///
/// The address never changes, so a counter rides along: without it a browser
/// redraws the copy it already holds and an operator who just replaced their
/// logo sees the old one and doubts the upload.
export function markPath(realm: string, drawn: number): string {
  const at = `/realms/${encodeURIComponent(realm)}/protocol/openid-connect/logo`;
  return drawn > 0 ? `${at}?drawn=${drawn}` : at;
}

/// What is wrong with a chosen file, before any of it is sent.
///
/// The door weighs the bytes and stays the authority; this only spares a
/// round trip and says the same two things it would have said.
export function refuses(picture: { size: number; type: string }): "too-big" | "not-a-picture" | "" {
  if (picture.size > LARGEST) return "too-big";
  if (!ACCEPTED.split(",").includes(picture.type)) return "not-a-picture";
  return "";
}
