import type { Foreseen, ShownToken } from "@/services/clients";

/// One line of a token's body, as a reader sees it: the claim, its value
/// rendered as JSON, and what is worth knowing about where it came from.
export interface Line {
  key: string;
  value: string;
  /// The mapper that wrote it, absent for the claims the assembly writes
  /// itself. This is the whole point of reading a token here rather than in a
  /// decoder: a decoder cannot say who put a claim there.
  author: string;
  /// Its value only exists once there is a login and a minting, so what is
  /// shown stands in for one rather than being one.
  drawn: boolean;
}

/// One claim a registered rule wrote, for the screens that ask about the
/// rules rather than about the token.
export interface Authored {
  claim: string;
  value: string;
  origin: string;
}

/// What the registered rules wrote, and nothing the assembly writes itself: a
/// policy is weighed against the claims somebody chose to add.
export function authoredRows(foreseen: Foreseen): Authored[] {
  return Object.entries(foreseen.authors).map(([claim, origin]) => ({
    claim,
    value: render(foreseen.access.body[claim] ?? foreseen.identity?.body[claim]),
    origin,
  }));
}

/// The lines of one token's body.
export function linesOf(shown: ShownToken, foreseen: Foreseen): Line[] {
  return Object.entries(shown.body).map(([key, value]) => ({
    key,
    value: render(value),
    author: foreseen.authors[key] ?? "",
    drawn: foreseen.drawn_at_issuance.includes(key),
  }));
}

/// The lines of a header, which nobody writes but the key.
export function headerLines(shown: ShownToken): Line[] {
  return Object.entries(shown.header).map(([key, value]) => ({
    key,
    value: render(value),
    author: "",
    drawn: false,
  }));
}

/// A value as JSON, which is how a token carries it. A string stays quoted,
/// because a reader has to tell "1" from 1 to know what a client will get.
export function render(value: unknown): string {
  return JSON.stringify(value ?? null);
}

/// Seconds since the epoch read as a moment, for the three claims that bound a
/// token. Anything else is left as it is: guessing that a number is a time
/// because it looks like one would relabel a claim somebody wrote.
const MOMENTS = ["iat", "nbf", "exp", "auth_time"];

export function asMoment(key: string, value: unknown): string {
  if (!MOMENTS.includes(key) || typeof value !== "number") return "";
  return new Date(value * 1000).toISOString().replace("T", " ").replace(".000Z", "Z");
}

/// How long the window lasts, in seconds, or nothing when the token states no
/// pair to measure between.
export function windowOf(shown: ShownToken): number | null {
  const opened = shown.body.iat;
  const closes = shown.body.exp;
  if (typeof opened !== "number" || typeof closes !== "number") return null;
  return closes - opened;
}
