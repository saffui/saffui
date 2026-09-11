/// What the server accepts as a user name, said here so a person learns it
/// while typing rather than after a round trip.
///
/// Mirrors `services::admin::users::check_name`. Kept as one function beside
/// its own test, because a rule copied into two screens is a rule that drifts
/// in one of them: the create form and the rename field both ask this.
export const NAME_LIMIT = 255;

export type NameRefusal = "empty" | "long" | "spaced" | "control";

/// Absent where the name is one the server will take.
export function refusalOf(userName: string): NameRefusal | null {
  if (!userName) return "empty";
  if (userName.length > NAME_LIMIT) return "long";
  // Every character, not only the ends: the server refuses a space inside a
  // name too, and trimming here would send one that looked accepted.
  if (/\s/u.test(userName)) return "spaced";
  // eslint-disable-next-line no-control-regex -- these are exactly the rule
  if (/[\u0000-\u001f\u007f]/u.test(userName)) return "control";
  return null;
}
