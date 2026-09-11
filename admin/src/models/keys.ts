/// Mirrors what `GET /admin/realms/{realm}/keys` answers: the signing ring
/// and the encryption keys, each key said by its public face only.
export interface RealmKeyView {
  kid: string;
  algorithm: string;
  status: string;
  realm_id?: string;
  key_type?: string;
  key_use?: "sig" | "enc";
  priority?: number;
  public_jwk?: Record<string, unknown>;
  created_at?: number;
}

export interface RealmKeys {
  signing: RealmKeyView[];
  encryption: RealmKeyView[];
}
