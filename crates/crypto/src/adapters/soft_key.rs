//! A security key in software, for tests: it answers the two ceremonies of
//! a relying party the way a browser and its key do, and nothing checks who
//! holds it.

use data_encoding::BASE64URL_NOPAD;
use serde_cbor_2::Value as Cbor;
use serde_json::{Value, json};

use super::{SharedProvider, open_provider};
use crate::jose::jwk::alg::ec::EcKeyPair;
use crate::jose::jwk::{KeyPair, P_256};
use crate::provider::{HashAlg, PrivateKey, SignAlg};

/// Bit 0: a person is present. Bit 6: the data of a new credential follows.
const PRESENT: u8 = 0b0000_0001;
const PRESENT_WITH_CREDENTIAL: u8 = 0b0100_0001;

/// The model a soft key names when it enrolls.
pub const AAGUID: [u8; 16] = *b"saffui-soft-key!";

/// One credential, its private half included.
pub struct SoftKey {
    provider: SharedProvider,
    signing: PrivateKey,
    /// The public half as a key writes it once, at enrollment (COSE).
    cose: Vec<u8>,
    pub credential_id: Vec<u8>,
    /// The signature counter. A test winds it back to play a copy of the key.
    pub counter: u32,
}

impl SoftKey {
    /// Makes a key with a fresh pair on P-256.
    ///
    /// # Panics
    ///
    /// Panics when the provider of this machine makes no key: a test has
    /// nothing to go on with.
    #[must_use]
    pub fn make() -> Self {
        let provider = open_provider().expect("a provider");
        let pair = EcKeyPair::generate(P_256).expect("a key pair");
        let jwk = pair.to_jwk_key_pair();
        let read_coordinate = |named: &str| -> Vec<u8> {
            let value = jwk.parameter(named).and_then(Value::as_str).expect(named);
            BASE64URL_NOPAD.decode(value.as_bytes()).expect(named)
        };
        let cose = write_cose_key(&read_coordinate("x"), &read_coordinate("y"));
        let credential_id = provider
            .digest()
            .hash(HashAlg::Sha256, &pair.to_der_public_key())
            .expect("a digest");
        Self {
            provider,
            signing: PrivateKey::from_der(pair.to_der_private_key()),
            cose,
            credential_id,
            counter: 0,
        }
    }

    /// The name of the credential as a browser writes it.
    #[must_use]
    pub fn name_credential(&self) -> String {
        BASE64URL_NOPAD.encode(&self.credential_id)
    }

    /// Answers an enrollment as a browser standing on `origin` hands it
    /// back, with no attestation.
    ///
    /// # Panics
    ///
    /// Panics when `options` are not those of an enrollment.
    #[must_use]
    pub fn attest(&self, options: &Value, origin: &str) -> Value {
        let asked = &options["publicKey"];
        let challenge = asked["challenge"].as_str().expect("a challenge");
        let relying_party = asked["rp"]["id"].as_str().expect("a relying party");
        let client_data = write_client_data("webauthn.create", challenge, origin);

        let named = u16::try_from(self.credential_id.len()).expect("a short identifier");
        let mut authenticator_data = self.digest(relying_party.as_bytes());
        authenticator_data.push(PRESENT_WITH_CREDENTIAL);
        authenticator_data.extend_from_slice(&0_u32.to_be_bytes());
        authenticator_data.extend_from_slice(&AAGUID);
        authenticator_data.extend_from_slice(&named.to_be_bytes());
        authenticator_data.extend_from_slice(&self.credential_id);
        authenticator_data.extend_from_slice(&self.cose);

        let attestation = serde_cbor_2::to_vec(&Cbor::Map(
            [
                (write_text("fmt"), write_text("none")),
                (
                    write_text("attStmt"),
                    Cbor::Map(std::collections::BTreeMap::new()),
                ),
                (write_text("authData"), Cbor::Bytes(authenticator_data)),
            ]
            .into_iter()
            .collect(),
        ))
        .expect("an attestation");

        json!({
            "id": self.name_credential(),
            "rawId": self.name_credential(),
            "type": "public-key",
            "extensions": {},
            "response": {
                "attestationObject": BASE64URL_NOPAD.encode(&attestation),
                "clientDataJSON": BASE64URL_NOPAD.encode(&client_data),
            },
        })
    }

    /// Answers a challenge as a browser standing on `origin` hands it back,
    /// and moves the counter, as a key does.
    ///
    /// # Panics
    ///
    /// Panics when `options` are not those of a proof.
    pub fn answer(&mut self, options: &Value, origin: &str) -> Value {
        let asked = &options["publicKey"];
        let challenge = asked["challenge"].as_str().expect("a challenge");
        let relying_party = asked["rpId"].as_str().expect("a relying party");
        let client_data = write_client_data("webauthn.get", challenge, origin);

        self.counter += 1;
        let mut authenticator_data = self.digest(relying_party.as_bytes());
        authenticator_data.push(PRESENT);
        authenticator_data.extend_from_slice(&self.counter.to_be_bytes());

        // Signed with the digest of what the browser collected behind it:
        // neither half is swapped under the signature.
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&self.digest(&client_data));
        let signature = self
            .provider
            .signer()
            .sign(SignAlg::Es256, &self.signing, &signed)
            .expect("a signature");

        json!({
            "id": self.name_credential(),
            "rawId": self.name_credential(),
            "type": "public-key",
            "extensions": {},
            "response": {
                "authenticatorData": BASE64URL_NOPAD.encode(&authenticator_data),
                "clientDataJSON": BASE64URL_NOPAD.encode(&client_data),
                "signature": BASE64URL_NOPAD.encode(&signature),
                "userHandle": null,
            },
        })
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        self.provider
            .digest()
            .hash(HashAlg::Sha256, data)
            .expect("a digest")
    }
}

/// What a browser collects: the ceremony, the challenge as it was given,
/// and where the page stands.
fn write_client_data(ceremony: &str, challenge: &str, origin: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "type": ceremony,
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    }))
    .expect("client data")
}

/// An EC2 key on P-256 for ES256, under its integer labels (RFC 9052, 7).
fn write_cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    let entries = [
        (1, Cbor::Integer(2)),
        (3, Cbor::Integer(-7)),
        (-1, Cbor::Integer(1)),
        (-2, Cbor::Bytes(x.to_vec())),
        (-3, Cbor::Bytes(y.to_vec())),
    ];
    serde_cbor_2::to_vec(&Cbor::Map(
        entries
            .into_iter()
            .map(|(label, value)| (Cbor::Integer(label), value))
            .collect(),
    ))
    .expect("a public key")
}

fn write_text(value: &str) -> Cbor {
    Cbor::Text(value.to_owned())
}
