/// tongue -> key -> the realm's wording, as both saving and previewing want it.
export type Spoken = Record<string, Record<string, string>>;

/// The pages a realm can be shown, in the order the screen offers them.
export const LOOKABLE = ["login", "device", "requests", "reset"] as const;
export type Lookable = (typeof LOOKABLE)[number];

/// What is worth keeping out of what was typed: a field left empty says
/// nothing rather than saying the empty string.
///
/// One packer for both doors. A draft packed any other way would preview a
/// page that saving would not produce, which is the one thing a preview must
/// not do.
export function packed(spoken: Spoken): Record<string, Record<string, string>> {
  const held: Record<string, Record<string, string>> = {};
  for (const tongue of Object.keys(spoken)) {
    const words: Record<string, string> = {};
    for (const [name, value] of Object.entries(spoken[tongue] ?? {})) {
      if (value.trim()) words[name] = value.trim();
    }
    if (Object.keys(words).length) held[tongue] = words;
  }
  return held;
}

/// Whether anything was typed that is not saved: with nothing said, a draft
/// would show exactly what the saved page already shows.
export function saysAnything(spoken: Spoken): boolean {
  return Object.keys(packed(spoken)).length > 0;
}

/// Where a page is shown. The realm and the page name ride in the path, so
/// both are escaped; a draft is named in the query or left out entirely.
export function previewPath(realm: string, which: Lookable, draft?: string): string {
  const at = `/realms/${encodeURIComponent(realm)}/protocol/openid-connect/page-preview/${encodeURIComponent(which)}`;
  return draft ? `${at}?draft=${encodeURIComponent(draft)}` : at;
}
