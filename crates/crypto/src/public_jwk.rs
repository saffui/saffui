use data_encoding::BASE64URL_NOPAD;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey};
use serde_json::{Map, Value};

use crate::provider::PublicKey;

/// The public key a JWK writes, as the SubjectPublicKeyInfo the signer
/// verifies with, for the two kinds a wallet signs a presentation with:
/// Ed25519, and ECDSA over P-256. Nothing for any other kind, for a coordinate
/// of another length than its curve's, or for a point off the curve, which
/// OpenSSL refuses as it decodes it.
pub fn public_key_from_jwk(jwk: &Map<String, Value>) -> Option<PublicKey> {
    let text = |name: &str| jwk.get(name).and_then(Value::as_str);
    let coordinate = |name: &str| {
        text(name)
            .and_then(|written| BASE64URL_NOPAD.decode(written.as_bytes()).ok())
            .filter(|decoded| decoded.len() == 32)
    };
    let key = match (text("kty")?, text("crv")?) {
        ("OKP", "Ed25519") => {
            PKey::public_key_from_raw_bytes(&coordinate("x")?, Id::ED25519).ok()?
        }
        ("EC", "P-256") => {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).ok()?;
            let uncompressed = [&[0x04][..], &coordinate("x")?, &coordinate("y")?].concat();
            let mut context = BigNumContext::new().ok()?;
            let point = EcPoint::from_bytes(&group, &uncompressed, &mut context).ok()?;
            PKey::from_ec_key(EcKey::from_public_key(&group, &point).ok()?).ok()?
        }
        _ => return None,
    };
    key.public_key_to_der().ok().map(PublicKey::from_der)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::jose::jwk::{Ed25519, KeyPair};
    use crate::jose::jws::{ES256, EdDSA};

    fn public_members(pair: &dyn KeyPair) -> Map<String, Value> {
        pair.to_jwk_public_key().as_ref().clone()
    }

    fn read_der(jwk: &Map<String, Value>) -> Option<Vec<u8>> {
        public_key_from_jwk(jwk).map(|key| key.der().to_vec())
    }

    #[test]
    fn an_ed25519_or_p256_key_is_read_as_its_pair_writes_it() {
        let ed25519 = EdDSA.generate_key_pair(Ed25519).expect("a key pair");
        assert_eq!(
            read_der(&public_members(&ed25519)),
            Some(ed25519.to_der_public_key())
        );
        let p256 = ES256.generate_key_pair().expect("a key pair");
        assert_eq!(
            read_der(&public_members(&p256)),
            Some(p256.to_der_public_key())
        );
    }

    #[test]
    fn another_kind_a_short_coordinate_or_a_point_off_the_curve_is_no_key() {
        let p256 = public_members(&ES256.generate_key_pair().expect("a key pair"));
        let mut off_curve = p256.clone();
        let mut y = BASE64URL_NOPAD
            .decode(p256["y"].as_str().expect("y").as_bytes())
            .expect("base64url");
        y[31] ^= 1;
        off_curve.insert("y".to_owned(), json!(BASE64URL_NOPAD.encode(&y)));
        assert_eq!(read_der(&off_curve), None);

        let mut short = p256.clone();
        short.insert("x".to_owned(), json!(BASE64URL_NOPAD.encode(&[7; 31])));
        assert_eq!(read_der(&short), None);

        // Coordinates of the wrong lengths that, end to end, write a point on
        // the curve: each is read at its curve's length or not at all.
        let decoded = |name: &str| {
            BASE64URL_NOPAD
                .decode(p256[name].as_str().expect("a coordinate").as_bytes())
                .expect("base64url")
        };
        let (x, y) = (decoded("x"), decoded("y"));
        let mut shifted = p256.clone();
        shifted.insert("x".to_owned(), json!(BASE64URL_NOPAD.encode(&x[..31])));
        shifted.insert(
            "y".to_owned(),
            json!(BASE64URL_NOPAD.encode(&[&x[31..], &y[..]].concat())),
        );
        assert_eq!(read_der(&shifted), None);

        let mut p384 = p256.clone();
        p384.insert("crv".to_owned(), json!("P-384"));
        assert_eq!(read_der(&p384), None);

        let ed25519 = public_members(&EdDSA.generate_key_pair(Ed25519).expect("a key pair"));
        let mut exchange = ed25519.clone();
        exchange.insert("crv".to_owned(), json!("X25519"));
        assert_eq!(read_der(&exchange), None);
        let mut mislabelled = ed25519.clone();
        mislabelled.insert("kty".to_owned(), json!("EC"));
        assert_eq!(read_der(&mislabelled), None);
        let mut unlabelled = ed25519;
        unlabelled.remove("crv");
        assert_eq!(read_der(&unlabelled), None);
    }
}
