//! Security keys, behind the port of the core. The ceremonies are those of
//! the `webauthn-rs` library, which is not modified: this file names the relying
//! party, carries what a ceremony keeps between its two halves, and compares
//! a counter to the one that is kept now.

use saffui_core::ports::crypto::{
    CryptoFailure, EnrolledKey, KeyCeremony, KeyProof, KeyRefusal, SecurityKeys,
};
use serde_json::Value;
use uuid::Uuid;
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::{
    Credential, PublicKeyCredential, RegisterPublicKeyCredential, SecurityKey,
    SecurityKeyAuthentication, SecurityKeyRegistration, WebauthnError,
};

pub struct WebauthnSecurityKeys {
    /// Absent when the public origin is named by an address, for which a
    /// browser lets no key sign, and in a build held to the validated module.
    party: Option<Webauthn>,
}

/// The relying party of an origin named by its host.
#[cfg(not(feature = "fips-strict"))]
fn build_party(origin: &str) -> Option<Webauthn> {
    let url = webauthn_rs::prelude::Url::parse(origin).ok()?;
    let host = url.domain()?.to_owned();
    webauthn_rs::WebauthnBuilder::new(&host, &url)
        .ok()?
        .build()
        .ok()
}

/// None: the library draws its challenges from `rand`, and this build draws
/// from the validated module alone.
#[cfg(feature = "fips-strict")]
fn build_party(_origin: &str) -> Option<Webauthn> {
    None
}

impl WebauthnSecurityKeys {
    /// Names the relying party after the host of the public origin: a key
    /// enrolled here answers on this origin, and on no other.
    #[must_use]
    pub fn for_origin(origin: &str) -> Self {
        Self {
            party: build_party(origin),
        }
    }

    /// Whether a key can be enrolled and asked on this origin.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.party.is_some()
    }
}

/// Reads the keys a person holds. A record this library does not read is
/// the record of no key.
fn read_held(held: &[Vec<u8>]) -> Vec<SecurityKey> {
    held.iter()
        .filter_map(|record| serde_json::from_slice(record).ok())
        .collect()
}

impl SecurityKeys for WebauthnSecurityKeys {
    fn start_enrollment(
        &self,
        person: Uuid,
        username: &str,
        held: &[Vec<u8>],
    ) -> Result<KeyCeremony, CryptoFailure> {
        let party = self.party.as_ref().ok_or(CryptoFailure)?;
        let excluded = read_held(held)
            .iter()
            .map(|key| key.cred_id().clone())
            .collect();
        let (options, state) = party
            .start_securitykey_registration(person, username, username, Some(excluded), None, None)
            .map_err(|_| CryptoFailure)?;
        Ok(KeyCeremony {
            options: serde_json::to_value(&options).map_err(|_| CryptoFailure)?,
            state: serde_json::to_vec(&state).map_err(|_| CryptoFailure)?,
        })
    }

    fn finish_enrollment(&self, state: &[u8], answer: &Value) -> Result<EnrolledKey, KeyRefusal> {
        let party = self.party.as_ref().ok_or(KeyRefusal::Failed)?;
        let state: SecurityKeyRegistration =
            serde_json::from_slice(state).map_err(|_| KeyRefusal::Failed)?;
        let answer: RegisterPublicKeyCredential =
            serde_json::from_value(answer.clone()).map_err(|_| KeyRefusal::Refused)?;
        let key = party
            .finish_securitykey_registration(&answer, &state)
            .map_err(|_| KeyRefusal::Refused)?;
        Ok(EnrolledKey {
            credential_id: key.cred_id().to_vec(),
            record: serde_json::to_vec(&key).map_err(|_| KeyRefusal::Failed)?,
        })
    }

    fn start_proof(&self, held: &[Vec<u8>]) -> Result<KeyCeremony, CryptoFailure> {
        let party = self.party.as_ref().ok_or(CryptoFailure)?;
        let (options, state) = party
            .start_securitykey_authentication(&read_held(held))
            .map_err(|_| CryptoFailure)?;
        Ok(KeyCeremony {
            options: serde_json::to_value(&options).map_err(|_| CryptoFailure)?,
            state: serde_json::to_vec(&state).map_err(|_| CryptoFailure)?,
        })
    }

    fn finish_proof(
        &self,
        state: &[u8],
        answer: &Value,
        held: &[Vec<u8>],
    ) -> Result<KeyProof, KeyRefusal> {
        let party = self.party.as_ref().ok_or(KeyRefusal::Failed)?;
        let state: SecurityKeyAuthentication =
            serde_json::from_slice(state).map_err(|_| KeyRefusal::Failed)?;
        let answer: PublicKeyCredential =
            serde_json::from_value(answer.clone()).map_err(|_| KeyRefusal::Refused)?;
        // The library tells a counter that went back from the one the
        // challenge was made with apart from every other refusal.
        let proven = party
            .finish_securitykey_authentication(&answer, &state)
            .map_err(|error| match error {
                WebauthnError::CredentialPossibleCompromise => KeyRefusal::CopySuspected,
                _ => KeyRefusal::Refused,
            })?;
        let mut key = read_held(held)
            .into_iter()
            .find(|key| key.cred_id() == proven.cred_id())
            .ok_or(KeyRefusal::Refused)?;
        // The library compared the counter to the one the challenge was
        // made with. The key may have been used since: the counter that is
        // kept now decides. A key that counts nothing answers zero forever.
        let kept = Credential::from(key.clone()).counter;
        if (proven.counter() > 0 || kept > 0) && proven.counter() <= kept {
            return Err(KeyRefusal::CopySuspected);
        }
        let moved = key.update_credential(&proven) == Some(true);
        let record = if moved {
            Some(serde_json::to_vec(&key).map_err(|_| KeyRefusal::Failed)?)
        } else {
            None
        };
        Ok(KeyProof {
            credential_id: proven.cred_id().to_vec(),
            record,
        })
    }
}

// Every ceremony below needs a relying party, which `fips-strict` builds none of.
#[cfg(all(test, not(feature = "fips-strict")))]
mod tests {
    use saffui_core::ports::crypto::{KeyCeremony, KeyRefusal, SecurityKeys};
    use serde_json::json;
    use uuid::Uuid;

    use super::WebauthnSecurityKeys;
    use crate::adapters::soft_key::SoftKey;

    const ORIGIN: &str = "https://id.example.test";

    fn open() -> WebauthnSecurityKeys {
        let keys = WebauthnSecurityKeys::for_origin(ORIGIN);
        assert!(keys.is_available());
        keys
    }

    /// Enrolls `key` for a person who holds `held`, and returns its record.
    fn enroll(keys: &WebauthnSecurityKeys, key: &SoftKey, held: &[Vec<u8>]) -> Vec<u8> {
        let asked = keys
            .start_enrollment(Uuid::from_u128(7), "ada", held)
            .expect("a started enrollment");
        let enrolled = keys
            .finish_enrollment(&asked.state, &key.attest(&asked.options, ORIGIN))
            .expect("an enrolled key");
        assert_eq!(enrolled.credential_id, key.credential_id);
        enrolled.record
    }

    fn ask(keys: &WebauthnSecurityKeys, held: &[Vec<u8>]) -> KeyCeremony {
        keys.start_proof(held).expect("a started proof")
    }

    #[test]
    fn a_key_enrolls_then_proves_itself_and_its_record_moves_with_its_counter() {
        let keys = open();
        let mut key = SoftKey::make();
        let record = enroll(&keys, &key, &[]);

        let asked = ask(&keys, std::slice::from_ref(&record));
        let proof = keys
            .finish_proof(
                &asked.state,
                &key.answer(&asked.options, ORIGIN),
                std::slice::from_ref(&record),
            )
            .expect("a proof");

        assert_eq!(proof.credential_id, key.credential_id);
        let moved = proof.record.expect("a record that moved");
        assert_ne!(moved, record);
        let asked = ask(&keys, std::slice::from_ref(&moved));
        let again = keys.finish_proof(
            &asked.state,
            &key.answer(&asked.options, ORIGIN),
            std::slice::from_ref(&moved),
        );
        assert!(again.is_ok(), "{again:?}");
    }

    #[test]
    fn an_answer_to_another_challenge_or_given_on_another_origin_is_refused() {
        let keys = open();
        let mut key = SoftKey::make();
        let held = [enroll(&keys, &key, &[])];
        let asked = ask(&keys, &held);
        let asked_later = ask(&keys, &held);

        let to_another = key.answer(&asked_later.options, ORIGIN);
        assert_eq!(
            keys.finish_proof(&asked.state, &to_another, &held),
            Err(KeyRefusal::Refused)
        );
        let elsewhere = key.answer(&asked.options, "https://id.example.test.evil.example");
        assert_eq!(
            keys.finish_proof(&asked.state, &elsewhere, &held),
            Err(KeyRefusal::Refused),
            "a page that looks like ours gets an answer that serves nowhere"
        );
        assert_eq!(
            keys.finish_proof(&asked.state, &json!({ "id": "x" }), &held),
            Err(KeyRefusal::Refused)
        );
        assert!(
            keys.finish_proof(&asked.state, &key.answer(&asked.options, ORIGIN), &held)
                .is_ok()
        );
    }

    #[test]
    fn an_enrollment_answered_for_another_challenge_or_origin_is_refused() {
        let keys = open();
        let key = SoftKey::make();
        let person = Uuid::from_u128(7);
        let asked = keys
            .start_enrollment(person, "ada", &[])
            .expect("a started enrollment");
        let asked_later = keys
            .start_enrollment(person, "ada", &[])
            .expect("a started enrollment");

        assert_eq!(
            keys.finish_enrollment(&asked.state, &key.attest(&asked_later.options, ORIGIN)),
            Err(KeyRefusal::Refused)
        );
        assert_eq!(
            keys.finish_enrollment(
                &asked.state,
                &key.attest(&asked.options, "https://elsewhere.example")
            ),
            Err(KeyRefusal::Refused)
        );
        assert_eq!(
            keys.finish_enrollment(b"not a state", &key.attest(&asked.options, ORIGIN)),
            Err(KeyRefusal::Failed)
        );
    }

    #[test]
    fn a_key_the_person_does_not_hold_proves_nothing() {
        let keys = open();
        let held = [enroll(&keys, &SoftKey::make(), &[])];
        let mut of_another = SoftKey::make();
        enroll(&keys, &of_another, &[]);
        let asked = ask(&keys, &held);

        assert_eq!(
            keys.finish_proof(
                &asked.state,
                &of_another.answer(&asked.options, ORIGIN),
                &held
            ),
            Err(KeyRefusal::Refused)
        );
    }

    #[test]
    fn a_key_taken_away_after_the_challenge_was_made_proves_nothing() {
        let keys = open();
        let mut key = SoftKey::make();
        let held = [enroll(&keys, &key, &[])];
        let asked = ask(&keys, &held);

        // The challenge still names the key. What decides is what is held
        // when the answer comes.
        assert_eq!(
            keys.finish_proof(&asked.state, &key.answer(&asked.options, ORIGIN), &[]),
            Err(KeyRefusal::Refused)
        );
    }

    #[test]
    fn a_counter_that_does_not_move_forward_is_refused() {
        let keys = open();
        let mut key = SoftKey::make();
        let record = enroll(&keys, &key, &[]);
        key.counter = 4;
        let asked = ask(&keys, std::slice::from_ref(&record));
        let moved = keys
            .finish_proof(
                &asked.state,
                &key.answer(&asked.options, ORIGIN),
                std::slice::from_ref(&record),
            )
            .expect("a proof")
            .record
            .expect("a record that moved");
        let held = [moved];

        // A copy made before the key was last used answers with less.
        key.counter = 2;
        let asked = ask(&keys, &held);
        assert_eq!(
            keys.finish_proof(&asked.state, &key.answer(&asked.options, ORIGIN), &held),
            Err(KeyRefusal::CopySuspected)
        );
    }

    #[test]
    fn a_proof_is_compared_to_the_counter_kept_now_and_not_to_the_one_it_was_asked_with() {
        let keys = open();
        let mut key = SoftKey::make();
        let record = enroll(&keys, &key, &[]);
        // Asked while the record still says zero.
        let asked_early = ask(&keys, std::slice::from_ref(&record));
        let early_answer = key.answer(&asked_early.options, ORIGIN);
        key.counter = 6;
        let asked = ask(&keys, std::slice::from_ref(&record));
        let moved = keys
            .finish_proof(
                &asked.state,
                &key.answer(&asked.options, ORIGIN),
                std::slice::from_ref(&record),
            )
            .expect("a proof")
            .record
            .expect("a record that moved");

        assert_eq!(
            keys.finish_proof(&asked_early.state, &early_answer, &[moved]),
            Err(KeyRefusal::CopySuspected),
            "the counter of the early answer is behind the one that is kept"
        );
    }

    #[test]
    fn a_person_is_not_offered_a_key_they_hold_already() {
        let keys = open();
        let key = SoftKey::make();
        let held = [enroll(&keys, &key, &[])];

        let asked = keys
            .start_enrollment(Uuid::from_u128(7), "ada", &held)
            .expect("a started enrollment");

        let excluded = &asked.options["publicKey"]["excludeCredentials"];
        assert_eq!(excluded.as_array().map(Vec::len), Some(1), "{excluded}");
        assert_eq!(excluded[0]["id"], key.name_credential());
    }

    #[test]
    fn an_origin_named_by_an_address_has_no_security_keys() {
        let keys = WebauthnSecurityKeys::for_origin("http://127.0.0.1:8080");

        assert!(!keys.is_available());
        assert!(
            keys.start_enrollment(Uuid::from_u128(7), "ada", &[])
                .is_err()
        );
        assert!(keys.start_proof(&[]).is_err());
        assert_eq!(
            keys.finish_proof(b"", &json!({}), &[]),
            Err(KeyRefusal::Failed)
        );
    }
}

#[cfg(all(test, feature = "fips-strict"))]
mod fips_strict_tests {
    use saffui_core::ports::crypto::{KeyRefusal, SecurityKeys};
    use serde_json::json;
    use uuid::Uuid;

    use super::WebauthnSecurityKeys;

    #[test]
    fn a_build_held_to_the_validated_module_serves_no_security_key_on_any_origin() {
        let keys = WebauthnSecurityKeys::for_origin("https://id.example.test");

        assert!(!keys.is_available());
        assert!(
            keys.start_enrollment(Uuid::from_u128(7), "ada", &[])
                .is_err()
        );
        assert!(keys.start_proof(&[]).is_err());
        assert_eq!(
            keys.finish_enrollment(b"", &json!({})),
            Err(KeyRefusal::Failed)
        );
        assert_eq!(
            keys.finish_proof(b"", &json!({}), &[]),
            Err(KeyRefusal::Failed)
        );
    }
}
