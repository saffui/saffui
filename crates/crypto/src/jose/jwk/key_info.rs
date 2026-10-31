// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

use crate::jose::jwk::Jwk;
use crate::jose::jwk::alg::ec::EcCurve;
use crate::jose::jwk::alg::ecx::EcxCurve;
use crate::jose::jwk::alg::ed::EdCurve;
use crate::jose::util;
use crate::jose::util::HashAlgorithm;
use crate::jose::util::der::{DerClass, DerError, DerReader, DerType};
use crate::jose::util::oid::{
    OID_ED448, OID_ED25519, OID_ID_EC_PUBLIC_KEY, OID_MGF1, OID_PRIME256V1, OID_RSA_ENCRYPTION,
    OID_RSASSA_PSS, OID_SECP256K1, OID_SECP384R1, OID_SECP521R1, OID_SHA1, OID_SHA256, OID_SHA384,
    OID_SHA512, OID_X448, OID_X25519,
};

/// The RSASSA-PSS parameters read off an `AlgorithmIdentifier`: message digest,
/// MGF1 digest, and salt length (RFC 4055 §3.1).
type RsaPssParams = (Option<HashAlgorithm>, Option<HashAlgorithm>, Option<u8>);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeyAlg {
    Rsa,
    RsaPss {
        hash: Option<HashAlgorithm>,
        mgf1_hash: Option<HashAlgorithm>,
        salt_len: Option<u8>,
    },
    Ec {
        curve: Option<EcCurve>,
    },
    Ed {
        curve: Option<EdCurve>,
    },
    Ecx {
        curve: Option<EcxCurve>,
    },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeyFormat {
    Der { raw: bool },
    Pem { traditional: bool },
    Jwk,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeyInfo {
    format: KeyFormat,
    alg: Option<KeyAlg>,
    is_public_key: bool,
}

impl KeyInfo {
    pub fn format(&self) -> KeyFormat {
        self.format
    }

    pub fn alg(&self) -> Option<KeyAlg> {
        self.alg
    }

    pub fn is_public_key(&self) -> bool {
        self.is_public_key
    }

    pub fn detect(input: &impl AsRef<[u8]>) -> Option<KeyInfo> {
        let input = input.as_ref();
        if input.is_empty() {
            return None;
        }

        let key_info = match input[0] {
            // DER
            b'\x30' => Self::detect_from_der(input)?,
            // PEM
            b'-' => {
                let (alg, data) = util::parse_pem(input).ok()?;
                match alg.as_str() {
                    "PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key() {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: false },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "RSA PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key() || !matches!(key_info.alg(), Some(KeyAlg::Rsa))
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "RSA-PSS PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key()
                            || !matches!(
                                key_info.alg(),
                                Some(KeyAlg::RsaPss {
                                    hash: _,
                                    mgf1_hash: _,
                                    salt_len: _,
                                })
                            )
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "EC PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key()
                            || !matches!(key_info.alg(), Some(KeyAlg::Ec { curve: _ }))
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "ED25519 PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key()
                            || !matches!(
                                key_info.alg(),
                                Some(KeyAlg::Ed {
                                    curve: Some(EdCurve::Ed25519)
                                })
                            )
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "ED448 PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key()
                            || !matches!(
                                key_info.alg(),
                                Some(KeyAlg::Ed {
                                    curve: Some(EdCurve::Ed448)
                                })
                            )
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "X25519 PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key()
                            || !matches!(
                                key_info.alg(),
                                Some(KeyAlg::Ecx {
                                    curve: Some(EcxCurve::X25519)
                                })
                            )
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "X448 PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key()
                            || !matches!(
                                key_info.alg(),
                                Some(KeyAlg::Ecx {
                                    curve: Some(EcxCurve::X448)
                                })
                            )
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "PUBLIC KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if !key_info.is_public_key() {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: false },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "RSA PUBLIC KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if !key_info.is_public_key() || !matches!(key_info.alg(), Some(KeyAlg::Rsa))
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    _ => return None,
                }
            }
            // JWK
            _ => {
                let jwk = Jwk::from_bytes(input).ok()?;
                match jwk.key_type() {
                    "oct" => KeyInfo {
                        format: KeyFormat::Jwk,
                        alg: None,
                        is_public_key: false,
                    },
                    "RSA" => {
                        let is_public_key = jwk.parameter("d").is_none();

                        KeyInfo {
                            format: KeyFormat::Jwk,
                            alg: Some(KeyAlg::Rsa),
                            is_public_key,
                        }
                    }
                    "EC" => {
                        let alg = match jwk.curve() {
                            Some("P-256") => Some(KeyAlg::Ec {
                                curve: Some(EcCurve::P256),
                            }),
                            Some("P-384") => Some(KeyAlg::Ec {
                                curve: Some(EcCurve::P384),
                            }),
                            Some("P-521") => Some(KeyAlg::Ec {
                                curve: Some(EcCurve::P521),
                            }),
                            Some("secp256k1") => Some(KeyAlg::Ec {
                                curve: Some(EcCurve::Secp256k1),
                            }),
                            Some(_) => Some(KeyAlg::Ec { curve: None }),
                            None => return None,
                        };
                        let is_public_key = jwk.parameter("d").is_none();

                        KeyInfo {
                            format: KeyFormat::Jwk,
                            alg,
                            is_public_key,
                        }
                    }
                    "OKP" => {
                        let alg = match jwk.curve() {
                            Some("Ed25519") => Some(KeyAlg::Ed {
                                curve: Some(EdCurve::Ed25519),
                            }),
                            Some("Ed448") => Some(KeyAlg::Ed {
                                curve: Some(EdCurve::Ed448),
                            }),
                            Some("X25519") => Some(KeyAlg::Ecx {
                                curve: Some(EcxCurve::X25519),
                            }),
                            Some("X448") => Some(KeyAlg::Ecx {
                                curve: Some(EcxCurve::X448),
                            }),
                            Some(_) => None,
                            None => return None,
                        };
                        let is_public_key = jwk.parameter("d").is_none();

                        KeyInfo {
                            format: KeyFormat::Jwk,
                            alg,
                            is_public_key,
                        }
                    }
                    _ => KeyInfo {
                        format: KeyFormat::Jwk,
                        alg: None,
                        is_public_key: false,
                    },
                }
            }
        };

        Some(key_info)
    }

    fn detect_from_der(input: &[u8]) -> Option<KeyInfo> {
        let mut reader = DerReader::from_reader(input);

        match reader.next().ok()? {
            Some(DerType::Sequence) => {}
            _ => return None,
        }

        let key_info = match reader.next().ok()? {
            Some(DerType::Sequence) => match reader.next().ok()? {
                Some(DerType::ObjectIdentifier) => match reader.to_object_identifier().ok()? {
                    val if val == *OID_RSA_ENCRYPTION => KeyInfo {
                        format: KeyFormat::Der { raw: false },
                        alg: Some(KeyAlg::Rsa),
                        is_public_key: true,
                    },
                    val if val == *OID_RSASSA_PSS => {
                        let (hash, mgf1_hash, salt_len) =
                            Self::parse_rsa_pss_params(&mut reader).ok()?;

                        KeyInfo {
                            format: KeyFormat::Der { raw: false },
                            alg: Some(KeyAlg::RsaPss {
                                hash,
                                mgf1_hash,
                                salt_len,
                            }),
                            is_public_key: true,
                        }
                    }
                    val if val == *OID_ID_EC_PUBLIC_KEY => {
                        let curve = match reader.next().ok()? {
                            Some(DerType::ObjectIdentifier) => {
                                match reader.to_object_identifier().ok()? {
                                    val if val == *OID_PRIME256V1 => Some(EcCurve::P256),
                                    val if val == *OID_SECP384R1 => Some(EcCurve::P384),
                                    val if val == *OID_SECP521R1 => Some(EcCurve::P521),
                                    val if val == *OID_SECP256K1 => Some(EcCurve::Secp256k1),
                                    _ => None,
                                }
                            }
                            _ => None,
                        };

                        KeyInfo {
                            format: KeyFormat::Der { raw: false },
                            alg: Some(KeyAlg::Ec { curve }),
                            is_public_key: true,
                        }
                    }
                    val if val == *OID_ED25519 => KeyInfo {
                        format: KeyFormat::Der { raw: false },
                        alg: Some(KeyAlg::Ed {
                            curve: Some(EdCurve::Ed25519),
                        }),
                        is_public_key: true,
                    },
                    val if val == *OID_ED448 => KeyInfo {
                        format: KeyFormat::Der { raw: false },
                        alg: Some(KeyAlg::Ed {
                            curve: Some(EdCurve::Ed448),
                        }),
                        is_public_key: true,
                    },
                    val if val == *OID_X25519 => KeyInfo {
                        format: KeyFormat::Der { raw: false },
                        alg: Some(KeyAlg::Ecx {
                            curve: Some(EcxCurve::X25519),
                        }),
                        is_public_key: true,
                    },
                    val if val == *OID_X448 => KeyInfo {
                        format: KeyFormat::Der { raw: false },
                        alg: Some(KeyAlg::Ecx {
                            curve: Some(EcxCurve::X448),
                        }),
                        is_public_key: true,
                    },
                    _ => KeyInfo {
                        format: KeyFormat::Der { raw: false },
                        alg: None,
                        is_public_key: true,
                    },
                },
                _ => return None,
            },
            Some(DerType::Integer) => match reader.next().ok()? {
                Some(DerType::Sequence) => match reader.next().ok()? {
                    Some(DerType::ObjectIdentifier) => match reader.to_object_identifier().ok()? {
                        val if val == *OID_RSA_ENCRYPTION => KeyInfo {
                            format: KeyFormat::Der { raw: false },
                            alg: Some(KeyAlg::Rsa),
                            is_public_key: false,
                        },
                        val if val == *OID_RSASSA_PSS => {
                            let (hash, mgf1_hash, salt_len) =
                                Self::parse_rsa_pss_params(&mut reader).ok()?;

                            KeyInfo {
                                format: KeyFormat::Der { raw: false },
                                alg: Some(KeyAlg::RsaPss {
                                    hash,
                                    mgf1_hash,
                                    salt_len,
                                }),
                                is_public_key: false,
                            }
                        }
                        val if val == *OID_ID_EC_PUBLIC_KEY => {
                            let curve = match reader.next().ok()? {
                                Some(DerType::ObjectIdentifier) => {
                                    match reader.to_object_identifier().ok()? {
                                        val if val == *OID_PRIME256V1 => Some(EcCurve::P256),
                                        val if val == *OID_SECP384R1 => Some(EcCurve::P384),
                                        val if val == *OID_SECP521R1 => Some(EcCurve::P521),
                                        val if val == *OID_SECP256K1 => Some(EcCurve::Secp256k1),
                                        _ => None,
                                    }
                                }
                                _ => None,
                            };

                            KeyInfo {
                                format: KeyFormat::Der { raw: false },
                                alg: Some(KeyAlg::Ec { curve }),
                                is_public_key: false,
                            }
                        }
                        val if val == *OID_ED25519 => KeyInfo {
                            format: KeyFormat::Der { raw: false },
                            alg: Some(KeyAlg::Ed {
                                curve: Some(EdCurve::Ed25519),
                            }),
                            is_public_key: false,
                        },
                        val if val == *OID_ED448 => KeyInfo {
                            format: KeyFormat::Der { raw: false },
                            alg: Some(KeyAlg::Ed {
                                curve: Some(EdCurve::Ed448),
                            }),
                            is_public_key: false,
                        },
                        val if val == *OID_X25519 => KeyInfo {
                            format: KeyFormat::Der { raw: false },
                            alg: Some(KeyAlg::Ecx {
                                curve: Some(EcxCurve::X25519),
                            }),
                            is_public_key: false,
                        },
                        val if val == *OID_X448 => KeyInfo {
                            format: KeyFormat::Der { raw: false },
                            alg: Some(KeyAlg::Ecx {
                                curve: Some(EcxCurve::X448),
                            }),
                            is_public_key: false,
                        },
                        _ => return None,
                    },
                    _ => return None,
                },
                Some(DerType::Integer) => {
                    if let Some(DerType::EndOfContents) = reader.next().ok()? {
                        KeyInfo {
                            format: KeyFormat::Der { raw: true },
                            alg: Some(KeyAlg::Rsa),
                            is_public_key: true,
                        }
                    } else {
                        KeyInfo {
                            format: KeyFormat::Der { raw: true },
                            alg: Some(KeyAlg::Rsa),
                            is_public_key: false,
                        }
                    }
                }
                Some(DerType::OctetString) => {
                    let curve = match reader.next().ok()? {
                        Some(DerType::Other(DerClass::ContextSpecific, 0)) => {
                            match reader.next().ok()? {
                                Some(DerType::ObjectIdentifier) => {
                                    match reader.to_object_identifier().ok()? {
                                        val if val == *OID_PRIME256V1 => Some(EcCurve::P256),
                                        val if val == *OID_SECP384R1 => Some(EcCurve::P384),
                                        val if val == *OID_SECP521R1 => Some(EcCurve::P521),
                                        val if val == *OID_SECP256K1 => Some(EcCurve::Secp256k1),
                                        _ => None,
                                    }
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };

                    KeyInfo {
                        format: KeyFormat::Der { raw: true },
                        alg: Some(KeyAlg::Ec { curve }),
                        is_public_key: false,
                    }
                }
                _ => return None,
            },
            _ => return None,
        };

        Some(key_info)
    }

    fn parse_rsa_pss_params(reader: &mut DerReader<&[u8]>) -> Result<RsaPssParams, DerError> {
        let mut hash = Some(HashAlgorithm::Sha1);
        let mut mgf1_hash = Some(HashAlgorithm::Sha1);
        let mut salt_len = Some(20);

        if let Some(DerType::Sequence) = reader.next()? {
            while let Some(DerType::Other(DerClass::ContextSpecific, i)) = reader.next()? {
                if i == 0 {
                    match reader.next()? {
                        Some(DerType::Sequence) => {}
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::ObjectIdentifier) => match reader.to_object_identifier()? {
                            val if val == *OID_SHA1 => hash = Some(HashAlgorithm::Sha1),
                            val if val == *OID_SHA256 => hash = Some(HashAlgorithm::Sha256),
                            val if val == *OID_SHA384 => hash = Some(HashAlgorithm::Sha384),
                            val if val == *OID_SHA512 => hash = Some(HashAlgorithm::Sha512),
                            _ => hash = None,
                        },
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::EndOfContents) => {}
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::EndOfContents) => {}
                        _ => break,
                    }
                } else if i == 1 {
                    match reader.next()? {
                        Some(DerType::Sequence) => {}
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::ObjectIdentifier) => match reader.to_object_identifier()? {
                            val if val == *OID_MGF1 => {}
                            _ => break,
                        },
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::Sequence) => {}
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::ObjectIdentifier) => match reader.to_object_identifier()? {
                            val if val == *OID_SHA1 => mgf1_hash = Some(HashAlgorithm::Sha1),
                            val if val == *OID_SHA256 => mgf1_hash = Some(HashAlgorithm::Sha256),
                            val if val == *OID_SHA384 => mgf1_hash = Some(HashAlgorithm::Sha384),
                            val if val == *OID_SHA512 => mgf1_hash = Some(HashAlgorithm::Sha512),
                            _ => mgf1_hash = None,
                        },
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::EndOfContents) => {}
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::EndOfContents) => {}
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::EndOfContents) => {}
                        _ => break,
                    }
                } else if i == 2 {
                    match reader.next()? {
                        Some(DerType::Integer) => salt_len = Some(reader.to_u8()?),
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::EndOfContents) => {}
                        _ => break,
                    }
                } else {
                    reader.skip_contents()?;
                }
            }
        }

        Ok((hash, mgf1_hash, salt_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::jose::jwk::KeyPair;
    use crate::jose::jwk::alg::ec::EcKeyPair;
    use crate::jose::jwk::alg::ecx::EcxKeyPair;
    use crate::jose::jwk::alg::ed::EdKeyPair;
    use crate::jose::jwk::alg::rsa::RsaKeyPair;
    use crate::jose::jwk::alg::rsapss::RsaPssKeyPair;
    use crate::jose::jwk::{Ed448, Ed25519, P_256, P_384, P_521, Secp256k1, X448, X25519};

    /// Detection has to agree with the encoder on all four of DER and PEM,
    /// private and public, for every key type this crate can generate.
    ///
    /// It reads raw bytes and decides format, algorithm and whether the key is
    /// public. Getting the last one wrong is the interesting failure: a caller
    /// that hands a private key where a public one was expected, and is told it
    /// is public, has just been cleared to publish it.
    fn check(pair: &dyn KeyPair, expected: KeyAlg) {
        check_with(pair, expected, false)
    }

    /// `private_der_raw` because the encoders disagree by key type: OpenSSL
    /// writes an EC private key to DER in the traditional SEC1 form, while the
    /// same key to PEM goes out as PKCS#8. Detection reports what it is handed,
    /// so the expectation follows the encoder rather than the other way round.
    fn check_with(pair: &dyn KeyPair, expected: KeyAlg, private_der_raw: bool) {
        let cases: [(Vec<u8>, KeyFormat, bool); 4] = [
            (
                pair.to_der_private_key(),
                KeyFormat::Der {
                    raw: private_der_raw,
                },
                false,
            ),
            (
                pair.to_der_public_key(),
                KeyFormat::Der { raw: false },
                true,
            ),
            (
                pair.to_pem_private_key(),
                KeyFormat::Pem { traditional: false },
                false,
            ),
            (
                pair.to_pem_public_key(),
                KeyFormat::Pem { traditional: false },
                true,
            ),
        ];

        for (bytes, format, is_public) in cases {
            let info = KeyInfo::detect(&bytes)
                .unwrap_or_else(|| panic!("{expected:?} in {format:?} was not recognised"));
            assert_eq!(info.format(), format, "{expected:?}");
            assert_eq!(
                info.is_public_key(),
                is_public,
                "{expected:?} in {format:?}"
            );
            assert_eq!(info.alg(), Some(expected), "{expected:?} in {format:?}");
        }
    }

    #[test]
    fn rsa_keys_are_recognised_in_every_encoding() {
        check(&RsaKeyPair::generate(2048).unwrap(), KeyAlg::Rsa);
    }

    /// A PSS key carries its digest, MGF1 digest and salt length in the
    /// algorithm identifier, so detection reports them rather than a bare Rsa.
    #[test]
    fn rsa_pss_keys_carry_their_parameters() {
        let pair = RsaPssKeyPair::generate(2048, HashAlgorithm::Sha256, HashAlgorithm::Sha256, 32)
            .unwrap();
        check(
            &pair,
            KeyAlg::RsaPss {
                hash: Some(HashAlgorithm::Sha256),
                mgf1_hash: Some(HashAlgorithm::Sha256),
                salt_len: Some(32),
            },
        );
    }

    #[test]
    fn ec_keys_are_recognised_on_every_curve() {
        for curve in [P_256, P_384, P_521, Secp256k1] {
            check_with(
                &EcKeyPair::generate(curve).unwrap(),
                KeyAlg::Ec { curve: Some(curve) },
                true,
            );
        }
    }

    #[test]
    fn edwards_keys_are_recognised_on_both_curves() {
        for curve in [Ed25519, Ed448] {
            check(
                &EdKeyPair::generate(curve).unwrap(),
                KeyAlg::Ed { curve: Some(curve) },
            );
        }
    }

    #[test]
    fn montgomery_keys_are_recognised_on_both_curves() {
        for curve in [X25519, X448] {
            check(
                &EcxKeyPair::generate(curve).unwrap(),
                KeyAlg::Ecx { curve: Some(curve) },
            );
        }
    }

    /// The traditional PEM encoding is a different envelope for the same key,
    /// and detection has to say so rather than fall back to the modern one.
    #[test]
    fn traditional_pem_is_reported_as_traditional() {
        let pair = EcKeyPair::generate(P_256).unwrap();
        let info = KeyInfo::detect(&pair.to_traditional_pem_private_key()).unwrap();

        assert_eq!(info.format(), KeyFormat::Pem { traditional: true });
        assert!(!info.is_public_key());
    }

    /// Nothing that is not a key returns something that looks like one.
    #[test]
    fn input_that_is_not_a_key_is_refused() {
        assert!(KeyInfo::detect(&Vec::<u8>::new()).is_none());
        assert!(KeyInfo::detect(&b"not a key at all".to_vec()).is_none());
        assert!(KeyInfo::detect(&b"-----BEGIN NOTHING-----".to_vec()).is_none());

        // A DER sequence header with nothing behind it.
        assert!(KeyInfo::detect(&vec![0x30u8, 0x82, 0xff, 0xff]).is_none());
    }

    /// Detection classifies, it does not validate.
    ///
    /// A key truncated after its algorithm identifier is still reported, and
    /// that is the contract: `detect` answers "what is this shaped like" so a
    /// caller can pick a parser. The parser is what rejects it. Written down
    /// because the name invites the other reading, and a caller that treats a
    /// `Some` here as "this key is usable" is wrong.
    #[test]
    fn detection_is_not_validation() {
        let der = RsaKeyPair::generate(2048).unwrap().to_der_private_key();
        let truncated = der[..der.len() / 2].to_vec();

        let info = KeyInfo::detect(&truncated).expect("still classified");
        assert_eq!(info.alg(), Some(KeyAlg::Rsa));
        assert!(RsaKeyPair::from_der(&truncated).is_err());
    }
}
