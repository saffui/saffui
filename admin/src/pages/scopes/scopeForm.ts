import type { AttributeValue, ClientScope } from "@/models/client";

export interface ScopeDraft {
  name: string;
  description: string;
  defaultScope: boolean;
}

export interface ScopeWrite {
  name: string;
  description: string;
  default_scope: boolean;
  protocol?: string;
  configs?: Record<string, AttributeValue> | null;
}

/// An edit sends the scope back whole. The server replaces it and gives what
/// is left out its resting value, so a scope saved without its protocol and
/// settings would become an OpenID Connect scope with none.
export function scopeWrite(draft: ScopeDraft, held: ClientScope | null): ScopeWrite {
  const body: ScopeWrite = {
    name: draft.name.trim(),
    description: draft.description.trim(),
    default_scope: draft.defaultScope,
  };
  if (held) {
    body.protocol = held.protocol;
    body.configs = held.configs ?? null;
  }
  return body;
}
