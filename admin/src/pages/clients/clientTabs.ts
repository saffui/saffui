export const CLIENT_TABS = ["clients", "agents"] as const;

export type ClientTab = (typeof CLIENT_TABS)[number];

export function clientTabPath(realm: string, tab: ClientTab): string {
  return `/${encodeURIComponent(realm)}/${tab}`;
}
