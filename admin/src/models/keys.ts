/// Mirrors what `GET /admin/realms/{realm}/keys` answers: the signing ring
/// and the encryption keys, each key said by its public face only.
export interface RealmKeyView {
  kid: string;
  algorithm: string;
  status: string;
}

export interface RealmKeys {
  signing: RealmKeyView[];
  encryption: RealmKeyView[];
}
