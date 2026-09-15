/// The realm a console address serves, or null for an address that is not a
/// console's: the server mounts one console per realm, at /realms/{realm}/account/.
export function readRealm(pathname: string): string | null {
  const matched = /^\/realms\/([^/]+)\/account(?:\/|$)/.exec(pathname);
  if (!matched) return null;
  try {
    return decodeURIComponent(matched[1]);
  } catch {
    return null;
  }
}

/// Where a realm's console lives, which is its router's base.
export function composeConsoleBase(realm: string): string {
  return `/realms/${encodeURIComponent(realm)}/account/`;
}

/// Where a sign-in comes back to: the address the realm registered for its console.
export function composeReturnUri(origin: string, realm: string): string {
  return `${origin}${composeConsoleBase(realm)}login/return`;
}

export function composeApiPath(realm: string, leaf: string): string {
  return `/realms/${encodeURIComponent(realm)}/account-api/v1/${leaf}`;
}

/// The sheet of what the realm overrides of the look its sign-in pages share.
export function composeThemePath(realm: string): string {
  return `/realms/${encodeURIComponent(realm)}/protocol/openid-connect/theme.css`;
}
