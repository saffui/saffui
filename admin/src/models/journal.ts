/// Mirrors one item of `GET /admin/realms/{realm}/journal`: the chain
/// position, the write instant, and the hashed envelope itself.
export interface JournalEntry {
  seq: number;
  recorded_at: number;
  entry: {
    kind: string;
    occurred_at: number;
    actor: string;
    party: string | null;
    method: string;
    pattern: string | null;
    path: string;
    status: number;
  };
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
