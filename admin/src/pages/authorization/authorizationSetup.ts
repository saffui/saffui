export function canWriteAuthorization(clientId: string, loading: boolean, unprotected: boolean): boolean {
  return Boolean(clientId) && !loading && !unprotected;
}
