/// Mirrors one item of `GET /admin/realms/{realm}/journal`: the chain
/// position, the write instant, and the hashed envelope itself.
export interface JournalEntry {
  seq: number;
  recorded_at: number;
  entry: JournalEnvelope;
}

/// Every kind the server writes into the chain, told apart by `kind`.
export type JournalEnvelope = RequestEnvelope | CampaignClosedEnvelope;

/// Mirrors what `server::middleware::admin_audit` writes for an admin
/// request: every write, and every read while forensic mode stands.
export interface RequestEnvelope {
  kind: "admin.write" | "admin.read";
  occurred_at: number;
  actor: string;
  party: string | null;
  method: string;
  pattern: string | null;
  path: string;
  status: number;
  /// The trace the write ran in, when one was open.
  trace_id?: string | null;
}

/// Mirrors what `services::admin::recert::close` anchors: the campaign's
/// report joins the chain as its digest, not as its lines.
export interface CampaignClosedEnvelope {
  kind: "governance.campaign.closed";
  occurred_at: number;
  campaign: string;
  report_digest: string;
  /// How many frozen items the report resolved.
  items: number;
}

export interface JournalPage {
  items: JournalEntry[];
  first: number;
  max: number;
  total: number | null;
}

/// Mirrors `GET .../journal/verify`.
export interface ChainVerified {
  holds: boolean;
  entries: number;
  broken_at: number | null;
}
