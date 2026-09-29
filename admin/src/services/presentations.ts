import { adminPath, api } from "@/services/http";
import type { PresentationMade, PresentationStanding } from "@/models/presentations";

/// Ask a wallet for the presentation a DCQL query names. Quiet when taken: the
/// link and its QR code are the answer the page shows.
export async function askPresentation(
  realm: string,
  dcqlQuery: Record<string, unknown>,
): Promise<PresentationMade> {
  return api<PresentationMade>(adminPath(realm, "presentations"), {
    method: "POST",
    json: { dcql_query: dcqlQuery },
    quiet: true,
  });
}

export async function readPresentation(realm: string, id: string): Promise<PresentationStanding> {
  return api<PresentationStanding>(adminPath(realm, `presentations/${encodeURIComponent(id)}`));
}
