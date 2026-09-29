/// What asking for a presentation hands back: mirrors the answer of
/// `server::api::rest::endpoints::admin::presentations::ask`.
export interface PresentationMade {
  id: string;
  /// The link drawn as a QR code, SVG with its own light ground.
  qr: string | null;
  /// The `openid4vp://authorize` link a wallet opens.
  uri: string;
  expires_at: string;
}

/// One credential a verified presentation held: names, never a claim's value.
export interface PresentedCredential {
  id: string;
  issuer: string;
  /// An SD-JWT VC's type.
  vct?: string;
  /// A JSON-LD credential's types, expanded.
  types?: string[];
  /// The claims asked for, each a path joined with dots.
  claims: string[];
}

/// What an answer came to: the credentials verified, the wallet's refusal, or
/// why the realm refused the answer.
export interface PresentationOutcome {
  credentials?: PresentedCredential[];
  error?: string;
  reason?: string;
}

/// Mirrors the answer of `presentations::read`.
export interface PresentationStanding {
  id: string;
  status: "pending" | "verified" | "refused" | "failed";
  outcome: PresentationOutcome | null;
  expires_at: string;
  answered_at: string | null;
  created_by: string;
  created_at: string;
}
