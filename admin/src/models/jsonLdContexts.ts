/// Mirrors `server::api::rest::endpoints::admin::jsonld_contexts::ContextBrief`.
export interface JsonLdContextBrief {
  id: string;
  /// The context as credentials name it in their `@context`.
  url: string;
  /// The SHA-256 of the document kept, in lowercase hex.
  digest: string;
  octets: number;
  read_at: string;
  created_by: string;
  created_at: string;
}

export interface JsonLdContextList {
  /// Experimental: the contexts do nothing until the process runs the verifier.
  running: boolean;
  /// The contexts every realm holds, built into the server.
  built_in: string[];
  items: JsonLdContextBrief[];
}

/// Mirrors `ContextWrite`.
export interface JsonLdContextWrite {
  url: string;
}
