use crate::jose::Value;
use crate::jose::jwk::Jwk;
use crate::provider::{CryptoError, CryptoProvider, HashAlg, Result};

/// Compute a JWK thumbprint, base64url-encoded without padding.
///
/// SHA-1 is refused. A thumbprint names a key, and two keys sharing a name is
/// exactly what every use of this value — binding a token, matching a
/// certificate — exists to rule out. SHA-1 collisions are within reach, so the
/// hash that would produce them is not offered.
pub fn jwk_thumbprint(provider: &dyn CryptoProvider, jwk: &Jwk, alg: HashAlg) -> Result<String> {
    if alg == HashAlg::Sha1 {
        return Err(CryptoError::UnsupportedAlgorithm);
    }

    let digest = provider
        .digest()
        .hash(alg, canonical_json(jwk)?.as_bytes())?;

    Ok(data_encoding::BASE64URL_NOPAD.encode(&digest))
}

/// The SHA-256 thumbprint, which is what RFC 7638 §3.4 makes the default and
/// what every other specification means by "the thumbprint".
pub fn jwk_sha256_thumbprint(provider: &dyn CryptoProvider, jwk: &Jwk) -> Result<String> {
    jwk_thumbprint(provider, jwk, HashAlg::Sha256)
}

/// The RFC 9278 thumbprint URI:
/// `urn:ietf:params:oauth:jwk-thumbprint:<hash-name>:<thumbprint>`.
pub fn jwk_thumbprint_uri(
    provider: &dyn CryptoProvider,
    jwk: &Jwk,
    alg: HashAlg,
) -> Result<String> {
    let name = hash_name(alg).ok_or(CryptoError::UnsupportedAlgorithm)?;
    let thumbprint = jwk_thumbprint(provider, jwk, alg)?;

    Ok(format!(
        "urn:ietf:params:oauth:jwk-thumbprint:{name}:{thumbprint}"
    ))
}

/// The hash's name in the IANA Named Information registry, which is where
/// RFC 9278 takes the identifier from.
///
/// Only the three this crate is sure of. A URI naming a hash under a spelling
/// nobody registered parses cleanly and resolves to nothing, which is worse
/// than refusing to build it.
fn hash_name(alg: HashAlg) -> Option<&'static str> {
    match alg {
        HashAlg::Sha256 => Some("sha-256"),
        HashAlg::Sha384 => Some("sha-384"),
        HashAlg::Sha512 => Some("sha-512"),
        _ => None,
    }
}

/// The canonical JSON of RFC 7638 §3.2: the required members, in lexicographic
/// order, with no whitespace.
///
/// Built here rather than serialised from the `Jwk`. A serialiser emits members
/// in whatever order it holds them, and this crate deliberately configures one
/// that preserves insertion order — so the same key read from two documents
/// would hash differently, and the thumbprint would agree with nobody.
fn canonical_json(jwk: &Jwk) -> Result<String> {
    let kty = jwk.key_type();

    // Already in lexicographic order by name, per key type.
    let members: Vec<(&str, &str)> = match kty {
        "RSA" => vec![
            ("e", required(jwk, "e")?),
            ("kty", kty),
            ("n", required(jwk, "n")?),
        ],
        "EC" => vec![
            ("crv", required(jwk, "crv")?),
            ("kty", kty),
            ("x", required(jwk, "x")?),
            ("y", required(jwk, "y")?),
        ],
        "OKP" => vec![
            ("crv", required(jwk, "crv")?),
            ("kty", kty),
            ("x", required(jwk, "x")?),
        ],
        "oct" => vec![("k", required(jwk, "k")?), ("kty", kty)],
        _ => return Err(CryptoError::UnsupportedAlgorithm),
    };

    let mut json = String::from("{");
    for (index, (name, value)) in members.iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        // Names are fixed ASCII from the list above and need no escaping.
        json.push('"');
        json.push_str(name);
        json.push_str("\":");
        json.push_str(&json_string(value)?);
    }
    json.push('}');

    Ok(json)
}

/// A required member, which must be present and must be a string.
fn required<'a>(jwk: &'a Jwk, name: &str) -> Result<&'a str> {
    match jwk.parameter(name) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(CryptoError::InvalidParams),
    }
}

/// A value as a JSON string literal.
///
/// These are base64url or fixed names, so escaping should never change them.
/// It is applied anyway, and a failure is reported rather than replaced with an
/// empty string: a thumbprint computed over a substituted value is a wrong
/// answer that looks exactly like a right one.
fn json_string(value: &str) -> Result<String> {
    serde_json::to_string(value).map_err(|_| CryptoError::OperationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::provider::CryptoConfig;
    use crate::provider::openssl::OpenSslProvider;

    fn provider() -> OpenSslProvider {
        OpenSslProvider::new(&CryptoConfig::default()).unwrap()
    }

    fn jwk(kty: &str, members: &[(&str, &str)]) -> Jwk {
        let mut jwk = Jwk::new(kty);
        for (name, value) in members {
            jwk.set_parameter(name, Some(Value::String((*value).to_string())))
                .unwrap();
        }
        jwk
    }

    /// The RSA public key of RFC 7638 §3.1.
    const RFC7638_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4\
                             cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6\
                             4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY\
                             368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNL\
                             yrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44\
                             -csFCur-kEgU8awapJzKnqDKgw";

    fn rfc7638_key() -> Jwk {
        jwk(
            "RSA",
            &[
                ("n", RFC7638_N),
                ("e", "AQAB"),
                // Members the thumbprint must ignore.
                ("alg", "RS256"),
                ("kid", "2011-04-29"),
            ],
        )
    }

    /// RFC 7638 §3.1 fixes the thumbprint of its example key.
    ///
    /// The whole point of the module in one assertion: this value is what other
    /// implementations produce, and an implementation that agrees only with
    /// itself identifies nothing.
    #[test]
    fn the_rfc7638_reference_vector() {
        assert_eq!(
            jwk_sha256_thumbprint(&provider(), &rfc7638_key()).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    /// The canonical JSON is exactly what the RFC prints: required members,
    /// lexicographic, no whitespace.
    #[test]
    fn the_canonical_json_is_the_one_the_rfc_prints() {
        let json = canonical_json(&rfc7638_key()).unwrap();

        assert_eq!(
            json,
            format!("{{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"{RFC7638_N}\"}}")
        );
        assert!(!json.contains(' '));
        assert!(!json.contains("alg"));
        assert!(!json.contains("kid"));
    }

    /// Optional members do not reach the thumbprint, whichever order they
    /// arrive in.
    ///
    /// This is what makes it name the key rather than the document: the same
    /// key read from two places has to hash the same.
    #[test]
    fn only_the_required_members_reach_it() {
        let canonical = jwk_sha256_thumbprint(&provider(), &rfc7638_key()).unwrap();

        let minimal = jwk("RSA", &[("e", "AQAB"), ("n", RFC7638_N)]);
        let reordered = jwk("RSA", &[("n", RFC7638_N), ("e", "AQAB")]);
        let decorated = jwk(
            "RSA",
            &[
                ("use", "sig"),
                ("n", RFC7638_N),
                ("kid", "another"),
                ("e", "AQAB"),
                ("x5t", "whatever"),
            ],
        );

        for (what, key) in [
            ("minimal", minimal),
            ("reordered", reordered),
            ("decorated", decorated),
        ] {
            assert_eq!(
                jwk_sha256_thumbprint(&provider(), &key).unwrap(),
                canonical,
                "{what} hashed differently"
            );
        }
    }

    /// Every key type names its own required members, and changing any of them
    /// changes the thumbprint.
    #[test]
    fn every_key_type_hashes_its_required_members() {
        let provider = provider();
        /// A key type, its required members, and one of them to change.
        type Case = (
            &'static str,
            Vec<(&'static str, &'static str)>,
            &'static str,
        );

        let cases: [Case; 4] = [
            ("RSA", vec![("e", "AQAB"), ("n", RFC7638_N)], "n"),
            (
                "EC",
                vec![
                    ("crv", "P-256"),
                    ("x", "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"),
                    ("y", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"),
                ],
                "y",
            ),
            (
                "OKP",
                vec![
                    ("crv", "Ed25519"),
                    ("x", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
                ],
                "x",
            ),
            ("oct", vec![("k", "GawgguFyGrWKav7AX4VKUg")], "k"),
        ];

        for (kty, members, changed) in cases {
            let key = jwk(kty, &members);
            let base = jwk_sha256_thumbprint(&provider, &key).unwrap();

            // Every required member is missed if it is absent.
            for (name, _) in &members {
                let without: Vec<(&str, &str)> =
                    members.iter().filter(|(n, _)| n != name).copied().collect();
                assert!(
                    jwk_sha256_thumbprint(&provider, &jwk(kty, &without)).is_err(),
                    "{kty} hashed without {name}"
                );
            }

            // And a different value gives a different thumbprint.
            let moved: Vec<(&str, &str)> = members
                .iter()
                .map(|(n, v)| {
                    if *n == changed {
                        (*n, "AAAA")
                    } else {
                        (*n, *v)
                    }
                })
                .collect();
            assert_ne!(
                jwk_sha256_thumbprint(&provider, &jwk(kty, &moved)).unwrap(),
                base,
                "{kty} ignored a change to {changed}"
            );
        }
    }

    /// Two key types are never confused for one another.
    #[test]
    fn the_key_type_is_part_of_the_hash() {
        let provider = provider();
        let secret = "GawgguFyGrWKav7AX4VKUg";

        let symmetric = jwk("oct", &[("k", secret)]);
        let mut mislabelled = Jwk::new("OKP");
        mislabelled
            .set_parameter("crv", Some(Value::String("Ed25519".to_string())))
            .unwrap();
        mislabelled
            .set_parameter("x", Some(Value::String(secret.to_string())))
            .unwrap();

        assert_ne!(
            jwk_sha256_thumbprint(&provider, &symmetric).unwrap(),
            jwk_sha256_thumbprint(&provider, &mislabelled).unwrap()
        );
    }

    /// A key type nothing here can canonicalise is refused rather than hashed
    /// under a guess.
    #[test]
    fn an_unknown_key_type_is_refused() {
        for kty in ["", "rsa", "RSA1", "AKP", "unknown"] {
            assert!(
                matches!(
                    jwk_sha256_thumbprint(&provider(), &jwk(kty, &[("n", "x"), ("e", "AQAB")])),
                    Err(CryptoError::UnsupportedAlgorithm)
                ),
                "{kty:?} was hashed"
            );
        }
    }

    /// A required member that is not a string is refused, not coerced.
    #[test]
    fn a_member_of_the_wrong_shape_is_refused() {
        let mut key = Jwk::new("RSA");
        key.set_parameter("n", Some(Value::String(RFC7638_N.to_string())))
            .unwrap();
        key.set_parameter("e", Some(Value::Number(65537.into())))
            .unwrap();

        assert!(matches!(
            jwk_sha256_thumbprint(&provider(), &key),
            Err(CryptoError::InvalidParams)
        ));
    }

    /// SHA-1 is refused: two keys under one name is what every use of this
    /// value exists to rule out.
    #[test]
    fn sha1_is_refused() {
        let provider = provider();

        assert!(matches!(
            jwk_thumbprint(&provider, &rfc7638_key(), HashAlg::Sha1),
            Err(CryptoError::UnsupportedAlgorithm)
        ));

        for alg in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
            let thumbprint = jwk_thumbprint(&provider, &rfc7638_key(), alg).unwrap();
            assert_eq!(
                data_encoding::BASE64URL_NOPAD
                    .decode(thumbprint.as_bytes())
                    .unwrap()
                    .len(),
                alg.output_len(),
                "{alg:?}"
            );
            assert!(!thumbprint.contains('='), "{alg:?} was padded");
        }
    }

    /// The URI carries the registered hash name and the thumbprint, and is not
    /// built for a hash whose name this crate does not know.
    #[test]
    fn the_uri_names_a_registered_hash() {
        let provider = provider();

        for (alg, name) in [
            (HashAlg::Sha256, "sha-256"),
            (HashAlg::Sha384, "sha-384"),
            (HashAlg::Sha512, "sha-512"),
        ] {
            let uri = jwk_thumbprint_uri(&provider, &rfc7638_key(), alg).unwrap();
            let thumbprint = jwk_thumbprint(&provider, &rfc7638_key(), alg).unwrap();

            assert_eq!(
                uri,
                format!("urn:ietf:params:oauth:jwk-thumbprint:{name}:{thumbprint}")
            );
        }

        for alg in [
            HashAlg::Sha1,
            HashAlg::Sha3_256,
            HashAlg::Sha3_384,
            HashAlg::Sha3_512,
        ] {
            assert!(
                matches!(
                    jwk_thumbprint_uri(&provider, &rfc7638_key(), alg),
                    Err(CryptoError::UnsupportedAlgorithm)
                ),
                "{alg:?} produced a URI"
            );
        }
    }
}
