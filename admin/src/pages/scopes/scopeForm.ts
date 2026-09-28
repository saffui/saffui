export interface ScopeDraft {
  name: string;
  description: string;
  defaultScope: boolean;
}

export function scopeWrite(draft: ScopeDraft) {
  return {
    name: draft.name.trim(),
    description: draft.description.trim(),
    default_scope: draft.defaultScope,
  };
}
