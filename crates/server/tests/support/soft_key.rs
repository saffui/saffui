use crypto::jose::jwk::alg::ec::EcKeyPair;
use crypto::jose::jwk::{KeyPair, P_256};
use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, CryptoProvider, HashAlg, PrivateKey, SignAlg};
use data_encoding::BASE64URL_NOPAD;
use serde_cbor_2::Value as Cbor;
use serde_json::{Value, json};

/// Bit 0: user present. Bit 2: user verified. Bit 6: credential data attached.
const UP_UV: u8 = 0b0000_0101;
const UP_UV_AT: u8 = 0b0100_0101;

/// One credential, private half included.
pub struct SoftKey {
    provider: OpenSslProvider,
    signing: PrivateKey,
    /// The COSE encoding of the public half, written once at creation the way
    /// an authenticator burns it into the attestation.
    cose: Vec<u8>,
    pub credential_id: Vec<u8>,
    /// The signature counter. Public so a test can wind it back, which is how
    /// a cloned authenticator announces itself.
    pub counter: u32,
}

impl SoftKey {
    pub fn new() -> Self {
        let provider = OpenSslProvider::new(&CryptoConfig {
            fips_required: false,
            pkcs11: None,
        })
        .expect("a software provider");
        let pair = EcKeyPair::generate(P_256).expect("a key pair");
        let jwk = pair.to_jwk_key_pair();
        let coordinate = |named: &str| -> Vec<u8> {
            let value = jwk.parameter(named).and_then(Value::as_str).expect(named);
            BASE64URL_NOPAD.decode(value.as_bytes()).expect(named)
        };
        let cose = cose_p256(&coordinate("x"), &coordinate("y"));
        // Derived rather than random so the tests are replayable; a real
        // authenticator's identifier is opaque either way.
        let credential_id = provider
            .digest()
            .hash(HashAlg::Sha256, &pair.to_der_public_key())
            .expect("a digest");
        SoftKey {
            provider,
            signing: PrivateKey::from_der(pair.to_der_private_key()),
            cose,
            credential_id,
            counter: 0,
        }
    }

    /// Answer a registration ceremony: the attestation a browser would return
    /// from `navigator.credentials.create`, attestation format `none`.
    pub fn attest(&self, creation: &Value, origin: &str) -> Value {
        let asked = &creation["publicKey"];
        let challenge = asked["challenge"].as_str().expect("a challenge");
        let rp_id = asked["rp"]["id"].as_str().expect("a relying party");
        let client_data = self.client_data("webauthn.create", challenge, origin);

        // rpIdHash || flags || counter || aaguid || len || id || COSE key.
        let mut auth_data = self.sha256(rp_id.as_bytes());
        auth_data.push(UP_UV_AT);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]);
        auth_data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.credential_id);
        auth_data.extend_from_slice(&self.cose);

        let attestation = serde_cbor_2::to_vec(&Cbor::Map(
            [
                (text("fmt"), text("none")),
                (text("attStmt"), Cbor::Map(Default::default())),
                (text("authData"), Cbor::Bytes(auth_data)),
            ]
            .into_iter()
            .collect(),
        ))
        .expect("an attestation object");

        json!({
            "id": BASE64URL_NOPAD.encode(&self.credential_id),
            "rawId": BASE64URL_NOPAD.encode(&self.credential_id),
            "type": "public-key",
            "extensions": {},
            "response": {
                "attestationObject": BASE64URL_NOPAD.encode(&attestation),
                "clientDataJSON": BASE64URL_NOPAD.encode(&client_data),
            },
        })
    }

    /// Answer an authentication challenge: the assertion a browser would return
    /// from `navigator.credentials.get`. Advances the counter, as a device
    /// does.
    pub fn answer(&mut self, asks: &Value, origin: &str) -> String {
        let asked = &asks["publicKey"];
        let challenge = asked["challenge"].as_str().expect("a challenge");
        let rp_id = asked["rpId"].as_str().expect("a relying party");
        let client_data = self.client_data("webauthn.get", challenge, origin);

        self.counter += 1;
        let mut auth_data = self.sha256(rp_id.as_bytes());
        auth_data.push(UP_UV);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());

        // What is signed is authData with the *hash* of the client data behind
        // it, so neither half can be swapped out under the signature.
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&self.sha256(&client_data));
        let signature = self
            .provider
            .signer()
            .sign(SignAlg::Es256, &self.signing, &signed)
            .expect("a signature");

        json!({
            "id": BASE64URL_NOPAD.encode(&self.credential_id),
            "rawId": BASE64URL_NOPAD.encode(&self.credential_id),
            "type": "public-key",
            "extensions": {},
            "response": {
                "authenticatorData": BASE64URL_NOPAD.encode(&auth_data),
                "clientDataJSON": BASE64URL_NOPAD.encode(&client_data),
                "signature": BASE64URL_NOPAD.encode(&signature),
                "userHandle": null,
            },
        })
        .to_string()
    }

    /// What the browser collected: the ceremony, the challenge as issued, and
    /// where it was standing when it ran.
    fn client_data(&self, ceremony: &str, challenge: &str, origin: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": ceremony,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        }))
        .expect("client data")
    }

    fn sha256(&self, data: &[u8]) -> Vec<u8> {
        self.provider
            .digest()
            .hash(HashAlg::Sha256, data)
            .expect("a digest")
    }
}

/// RFC 9052 §7: an EC2 key on P-256 for ES256, integer-labelled.
fn cose_p256(x: &[u8], y: &[u8]) -> Vec<u8> {
    let entries = [
        (1, Cbor::Integer(2)),  // kty: EC2
        (3, Cbor::Integer(-7)), // alg: ES256
        (-1, Cbor::Integer(1)), // crv: P-256
        (-2, Cbor::Bytes(x.to_vec())),
        (-3, Cbor::Bytes(y.to_vec())),
    ];
    serde_cbor_2::to_vec(&Cbor::Map(
        entries
            .into_iter()
            .map(|(label, value)| (Cbor::Integer(label), value))
            .collect(),
    ))
    .expect("a COSE key")
}

fn text(value: &str) -> Cbor {
    Cbor::Text(value.to_owned())
}
