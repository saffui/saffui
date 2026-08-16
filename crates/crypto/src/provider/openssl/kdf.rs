//! Key derivation over OpenSSL.

use openssl::hash::Hasher;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use crate::provider::openssl::digest::message_digest;
use crate::provider::{ConcatKdfInfo, CryptoError, HashAlg, KdfProvider, Result};

pub struct OpenSslKdf;

/// HMAC over raw bytes, for the inner rounds of HKDF.
///
/// Separate from the HMAC provider because that one takes a `SecretBox` key,
/// and here the key is a pseudorandom block this module already owns.
fn hmac(hash: HashAlg, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let pkey = PKey::hmac(key).map_err(|_| CryptoError::OperationFailed)?;
    let mut signer =
        Signer::new(message_digest(hash), &pkey).map_err(|_| CryptoError::OperationFailed)?;
    signer
        .update(data)
        .map_err(|_| CryptoError::OperationFailed)?;
    signer
        .sign_to_vec()
        .map_err(|_| CryptoError::OperationFailed)
}

impl KdfProvider for OpenSslKdf {
    fn hkdf(
        &self,
        hash: HashAlg,
        ikm: &SecretBox<Vec<u8>>,
        salt: Option<&[u8]>,
        info: &[u8],
        len: usize,
    ) -> Result<SecretBox<Vec<u8>>> {
        let hash_len = hash.output_len();
        // RFC 5869 2.3: the counter is one byte, so the expand stage cannot
        // produce more than 255 blocks.
        if len > 255 * hash_len {
            return Err(CryptoError::InvalidParams);
        }

        // Extract. RFC 5869 2.2: an absent salt is a string of zeros as long
        // as the digest. An explicitly empty salt is treated the same, because
        // it carries no entropy either and because OpenSSL refuses an HMAC key
        // of zero length outright — a legal-looking input would otherwise come
        // back as an opaque operation failure.
        let default_salt = vec![0u8; hash_len];
        let salt = match salt {
            Some(val) if !val.is_empty() => val,
            _ => &default_salt,
        };
        let prk = Zeroizing::new(hmac(hash, salt, ikm.expose_secret())?);

        // Expand. The running output and each block are as sensitive as the key
        // being derived, so they are scrubbed on drop: `previous` is reassigned
        // every round and would otherwise leave a copy of each intermediate
        // block behind in freed memory.
        //
        // The capacity is the block-aligned length, not the requested one. The
        // loop appends whole digest blocks, so a buffer sized to `len` would
        // grow on the last one whenever `len` is not a multiple of the digest
        // size — and a reallocation copies the derived bytes to a new block and
        // frees the old one without scrubbing it, which is precisely what
        // `Zeroizing` is here to prevent. Fitting every block up front means no
        // reallocation happens at all.
        let mut okm = Zeroizing::new(Vec::with_capacity(len.div_ceil(hash_len) * hash_len));
        let mut previous: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        let mut counter: u8 = 1;
        while okm.len() < len {
            let mut input = Zeroizing::new(Vec::with_capacity(previous.len() + info.len() + 1));
            input.extend_from_slice(&previous);
            input.extend_from_slice(info);
            input.push(counter);
            previous = Zeroizing::new(hmac(hash, &prk, &input)?);
            okm.extend_from_slice(&previous);
            counter = counter.wrapping_add(1);
        }
        okm.truncate(len);
        Ok(SecretBox::new(Box::new(okm.to_vec())))
    }

    fn concat_kdf(
        &self,
        hash: HashAlg,
        z: &SecretBox<Vec<u8>>,
        info: ConcatKdfInfo<'_>,
        len: usize,
    ) -> Result<SecretBox<Vec<u8>>> {
        // `OtherInfo` is the four fields end to end, each already formatted by
        // the caller.
        let mut other_info = Vec::with_capacity(
            info.alg_id.len() + info.party_u.len() + info.party_v.len() + info.supp_pub.len(),
        );
        other_info.extend_from_slice(info.alg_id);
        other_info.extend_from_slice(info.party_u);
        other_info.extend_from_slice(info.party_v);
        other_info.extend_from_slice(info.supp_pub);

        // Block-aligned for the same reason as `hkdf`: whole digest blocks are
        // appended, and a reallocation would strand derived key material in a
        // freed buffer that nothing scrubs.
        let hash_len = hash.output_len();
        let mut out = Zeroizing::new(Vec::with_capacity(len.div_ceil(hash_len) * hash_len));
        let mut counter: u32 = 1;
        while out.len() < len {
            let mut hasher =
                Hasher::new(message_digest(hash)).map_err(|_| CryptoError::OperationFailed)?;
            hasher
                .update(&counter.to_be_bytes())
                .map_err(|_| CryptoError::OperationFailed)?;
            hasher
                .update(z.expose_secret())
                .map_err(|_| CryptoError::OperationFailed)?;
            hasher
                .update(&other_info)
                .map_err(|_| CryptoError::OperationFailed)?;

            let digest = Zeroizing::new(
                hasher
                    .finish()
                    .map_err(|_| CryptoError::OperationFailed)?
                    .to_vec(),
            );
            out.extend_from_slice(&digest);
            counter = counter.checked_add(1).ok_or(CryptoError::InvalidParams)?;
        }
        out.truncate(len);
        Ok(SecretBox::new(Box::new(out.to_vec())))
    }

    fn pbkdf2_hmac(
        &self,
        hash: HashAlg,
        passphrase: &SecretBox<String>,
        salt: &[u8],
        iterations: u32,
        len: usize,
    ) -> Result<SecretBox<Vec<u8>>> {
        // Zero rounds is not a weak derivation, it is none at all.
        if iterations == 0 {
            return Err(CryptoError::InvalidParams);
        }

        let mut out = Zeroizing::new(vec![0u8; len]);
        openssl::pkcs5::pbkdf2_hmac(
            passphrase.expose_secret().as_bytes(),
            salt,
            iterations as usize,
            message_digest(hash),
            &mut out,
        )
        .map_err(|_| CryptoError::OperationFailed)?;

        Ok(SecretBox::new(Box::new(out.to_vec())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(bytes: &[u8]) -> SecretBox<Vec<u8>> {
        SecretBox::new(Box::new(bytes.to_vec()))
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 5869 test case 1: SHA-256, with a salt and info.
    #[test]
    fn rfc5869_case_1() {
        let okm = OpenSslKdf
            .hkdf(
                HashAlg::Sha256,
                &secret(&unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")),
                Some(&unhex("000102030405060708090a0b0c")),
                &unhex("f0f1f2f3f4f5f6f7f8f9"),
                42,
            )
            .unwrap();

        assert_eq!(
            hex(okm.expose_secret()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        );
    }

    /// RFC 5869 test case 3: no salt and no info, which is the branch where
    /// the default salt of zeros is used.
    #[test]
    fn rfc5869_case_3() {
        let okm = OpenSslKdf
            .hkdf(
                HashAlg::Sha256,
                &secret(&unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")),
                None,
                b"",
                42,
            )
            .unwrap();

        assert_eq!(
            hex(okm.expose_secret()),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
        );
    }

    /// An absent salt, a salt of zeros, and an empty salt are one derivation.
    ///
    /// RFC 5869 2.2 defines the first two as the same. The third is treated the
    /// same here as well: it carries no entropy either, and OpenSSL refuses an
    /// HMAC key of zero length, so without the normalisation a legal-looking
    /// call comes back as an opaque operation failure.
    ///
    /// A salt with content is a different derivation, which is the part that
    /// has to hold.
    #[test]
    fn an_absent_a_zero_and_an_empty_salt_are_the_same_derivation() {
        let ikm = secret(b"input key material");

        let absent = OpenSslKdf
            .hkdf(HashAlg::Sha256, &ikm, None, b"", 32)
            .unwrap();
        let zeros = OpenSslKdf
            .hkdf(HashAlg::Sha256, &ikm, Some(&[0u8; 32]), b"", 32)
            .unwrap();
        let empty = OpenSslKdf
            .hkdf(HashAlg::Sha256, &ikm, Some(b""), b"", 32)
            .unwrap();

        assert_eq!(absent.expose_secret(), zeros.expose_secret());
        assert_eq!(absent.expose_secret(), empty.expose_secret());

        let salted = OpenSslKdf
            .hkdf(HashAlg::Sha256, &ikm, Some(b"salt"), b"", 32)
            .unwrap();
        assert_ne!(absent.expose_secret(), salted.expose_secret());
    }

    /// More than 255 blocks cannot be produced: the counter is one byte, and
    /// wrapping it would repeat output rather than extend it.
    #[test]
    fn hkdf_refuses_more_than_the_counter_can_address() {
        let ikm = secret(b"input key material");

        for hash in [HashAlg::Sha256, HashAlg::Sha512] {
            let most = 255 * hash.output_len();
            assert!(
                OpenSslKdf.hkdf(hash, &ikm, None, b"", most).is_ok(),
                "{hash:?} refused its own maximum"
            );
            assert!(
                matches!(
                    OpenSslKdf.hkdf(hash, &ikm, None, b"", most + 1),
                    Err(CryptoError::InvalidParams)
                ),
                "{hash:?} accepted one block too many"
            );
        }
    }

    /// Every input is bound into the output: changing any one of them changes
    /// what comes out, and none is silently ignored.
    #[test]
    fn every_hkdf_input_changes_the_output() {
        let ikm = secret(b"input key material");
        let base = OpenSslKdf
            .hkdf(HashAlg::Sha256, &ikm, Some(b"salt"), b"info", 32)
            .unwrap();

        let variants = [
            OpenSslKdf
                .hkdf(
                    HashAlg::Sha256,
                    &secret(b"other ikm"),
                    Some(b"salt"),
                    b"info",
                    32,
                )
                .unwrap(),
            OpenSslKdf
                .hkdf(HashAlg::Sha256, &ikm, Some(b"other salt"), b"info", 32)
                .unwrap(),
            OpenSslKdf
                .hkdf(HashAlg::Sha256, &ikm, Some(b"salt"), b"other info", 32)
                .unwrap(),
            OpenSslKdf
                .hkdf(HashAlg::Sha384, &ikm, Some(b"salt"), b"info", 32)
                .unwrap(),
        ];

        for other in variants {
            assert_ne!(base.expose_secret(), other.expose_secret());
        }
    }

    /// The concatenation KDF is deterministic, gives the length asked for, and
    /// binds each `OtherInfo` field.
    ///
    /// The four fields are concatenated, so a field that is not bound would be
    /// one an attacker can move between positions without changing the key.
    #[test]
    fn concat_kdf_binds_each_field_of_other_info() {
        let z = secret(b"shared secret");
        let info = ConcatKdfInfo {
            alg_id: b"alg",
            party_u: b"u",
            party_v: b"v",
            supp_pub: b"pub",
        };

        let base = OpenSslKdf
            .concat_kdf(HashAlg::Sha256, &z, info.clone(), 32)
            .unwrap();
        assert_eq!(base.expose_secret().len(), 32);

        let again = OpenSslKdf
            .concat_kdf(HashAlg::Sha256, &z, info.clone(), 32)
            .unwrap();
        assert_eq!(base.expose_secret(), again.expose_secret());

        let variants = [
            ConcatKdfInfo {
                alg_id: b"other",
                ..info.clone()
            },
            ConcatKdfInfo {
                party_u: b"other",
                ..info.clone()
            },
            ConcatKdfInfo {
                party_v: b"other",
                ..info.clone()
            },
            ConcatKdfInfo {
                supp_pub: b"other",
                ..info.clone()
            },
        ];
        for variant in variants {
            let other = OpenSslKdf
                .concat_kdf(HashAlg::Sha256, &z, variant, 32)
                .unwrap();
            assert_ne!(base.expose_secret(), other.expose_secret());
        }

        let other_z = OpenSslKdf
            .concat_kdf(HashAlg::Sha256, &secret(b"other secret"), info, 32)
            .unwrap();
        assert_ne!(base.expose_secret(), other_z.expose_secret());
    }

    /// Output longer than one digest is produced by running the counter, and
    /// the first block stays the same.
    #[test]
    fn concat_kdf_extends_past_one_digest() {
        let z = secret(b"shared secret");
        let info = ConcatKdfInfo::default();

        let short = OpenSslKdf
            .concat_kdf(HashAlg::Sha256, &z, info.clone(), 32)
            .unwrap();
        let long = OpenSslKdf
            .concat_kdf(HashAlg::Sha256, &z, info, 80)
            .unwrap();

        assert_eq!(long.expose_secret().len(), 80);
        assert_eq!(
            &long.expose_secret()[..32],
            short.expose_secret().as_slice()
        );
    }

    /// RFC 6070 test case 1, which is PBKDF2 over HMAC-SHA-1.
    #[test]
    fn rfc6070_case_1() {
        let out = OpenSslKdf
            .pbkdf2_hmac(
                HashAlg::Sha1,
                &SecretBox::new(Box::new("password".to_string())),
                b"salt",
                1,
                20,
            )
            .unwrap();

        assert_eq!(
            hex(out.expose_secret()),
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        );
    }

    /// RFC 6070 test case 2: the same inputs at 4096 rounds, so the iteration
    /// count is shown to reach the derivation rather than be carried along.
    #[test]
    fn rfc6070_case_2() {
        let out = OpenSslKdf
            .pbkdf2_hmac(
                HashAlg::Sha1,
                &SecretBox::new(Box::new("password".to_string())),
                b"salt",
                4096,
                20,
            )
            .unwrap();

        assert_eq!(
            hex(out.expose_secret()),
            "4b007901b765489abead49d926f721d065a429c1"
        );
    }

    /// Zero rounds is not a weak derivation, it is none at all.
    #[test]
    fn pbkdf2_refuses_zero_iterations() {
        assert!(matches!(
            OpenSslKdf.pbkdf2_hmac(
                HashAlg::Sha256,
                &SecretBox::new(Box::new("password".to_string())),
                b"salt",
                0,
                32
            ),
            Err(CryptoError::InvalidParams)
        ));
    }
}
