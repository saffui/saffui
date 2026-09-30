import { say } from "@/i18n";
import { adminPath, api, ApiError } from "@/services/http";
import type { WalletIdentity, WalletIdentityWrite } from "@/models/walletIdentity";

/// How the realm knows people by a wallet credential, or null for a realm
/// that does not yet.
export async function readWalletIdentity(realm: string): Promise<WalletIdentity | null> {
  try {
    return await api<WalletIdentity>(adminPath(realm, "wallet-identity"));
  } catch (refused) {
    if (refused instanceof ApiError && refused.status === 404) return null;
    throw refused;
  }
}

/// The first write draws the key identities are digested under; a rewrite
/// keeps it.
export async function keepWalletIdentity(
  realm: string,
  asked: WalletIdentityWrite,
): Promise<WalletIdentity> {
  return api<WalletIdentity>(adminPath(realm, "wallet-identity"), {
    method: "PUT",
    json: asked,
    subject: say("wallet-identity-title"),
  });
}
