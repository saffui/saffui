//! AEAD over OpenSSL.
//!
//! The cipher table lives here rather than beside the digest one: this is its
//! only consumer, and hoisting it would put a mapping in a shared place that
//! nothing else shares.

use openssl::symm::Cipher;
use secrecy::{ExposeSecret, SecretBox};

use crate::provider::{AeadAlg, AeadProvider, CryptoError, Result};

fn cipher(alg: AeadAlg) -> Cipher {
    match alg {
        AeadAlg::A128Gcm => Cipher::aes_128_gcm(),
        AeadAlg::A192Gcm => Cipher::aes_192_gcm(),
        AeadAlg::A256Gcm => Cipher::aes_256_gcm(),
        #[cfg(feature = "chacha20")]
        AeadAlg::ChaCha20Poly1305 => Cipher::chacha20_poly1305(),
    }
}

pub struct OpenSslAead;

impl OpenSslAead {
    /// Both lengths are checked before the cipher is reached.
    ///
    /// OpenSSL accepts a nonce of any length for GCM and derives one by
    /// hashing when it is not 12 bytes, which is legal and almost never
    /// intended: two callers who disagree on the length produce ciphertext
    /// neither can read, and the failure surfaces as a bad tag much later.
    fn check(alg: AeadAlg, key: &SecretBox<Vec<u8>>, nonce: &[u8]) -> Result<()> {
        if key.expose_secret().len() != alg.key_len() {
            return Err(CryptoError::InvalidKey);
        }
        if nonce.len() != alg.nonce_len() {
            return Err(CryptoError::InvalidParams);
        }
        Ok(())
    }
}

impl AeadProvider for OpenSslAead {
    fn encrypt(
        &self,
        alg: AeadAlg,
        key: &SecretBox<Vec<u8>>,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        Self::check(alg, key, nonce)?;

        let mut tag = vec![0u8; alg.tag_len()];
        let mut out = openssl::symm::encrypt_aead(
            cipher(alg),
            key.expose_secret(),
            Some(nonce),
            aad,
            plaintext,
            &mut tag,
        )
        .map_err(|_| CryptoError::OperationFailed)?;

        // Ciphertext followed by the tag, which is what `decrypt` expects and
        // what the JOSE layer above serialises.
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn decrypt(
        &self,
        alg: AeadAlg,
        key: &SecretBox<Vec<u8>>,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        Self::check(alg, key, nonce)?;

        let tag_len = alg.tag_len();
        if ciphertext.len() < tag_len {
            return Err(CryptoError::InvalidParams);
        }
        let (body, tag) = ciphertext.split_at(ciphertext.len() - tag_len);

        openssl::symm::decrypt_aead(
            cipher(alg),
            key.expose_secret(),
            Some(nonce),
            aad,
            body,
            tag,
        )
        .map_err(|_| CryptoError::OperationFailed)
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

    /// Test case 4 of the GCM specification, which is where the AES-GCM vectors
    /// everyone quotes come from.
    ///
    /// A known answer rather than a round trip: an implementation that pairs
    /// the wrong cipher with a key length, or that treats the nonce as a
    /// counter, agrees with itself and interoperates with nothing.
    #[test]
    fn gcm_specification_case_4() {
        let key = secret(&unhex("feffe9928665731c6d6a8f9467308308"));
        let nonce = unhex("cafebabefacedbaddecaf888");
        let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = unhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let expected = unhex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
             5bc94fbc3221a5db94fae95ae7121a47",
        );

        let out = OpenSslAead
            .encrypt(AeadAlg::A128Gcm, &key, &nonce, &aad, &plaintext)
            .unwrap();
        assert_eq!(out, expected);

        let back = OpenSslAead
            .decrypt(AeadAlg::A128Gcm, &key, &nonce, &aad, &out)
            .unwrap();
        assert_eq!(back, plaintext);
    }

    /// Every algorithm round-trips, with and without additional data.
    #[test]
    fn every_algorithm_round_trips() {
        let algs = [
            AeadAlg::A128Gcm,
            AeadAlg::A192Gcm,
            AeadAlg::A256Gcm,
            #[cfg(feature = "chacha20")]
            AeadAlg::ChaCha20Poly1305,
        ];

        for alg in algs {
            let key = secret(&vec![0x5a; alg.key_len()]);
            let nonce = vec![0x2b; alg.nonce_len()];

            for aad in [&b""[..], &b"bound data"[..]] {
                let out = OpenSslAead
                    .encrypt(alg, &key, &nonce, aad, b"payload")
                    .unwrap();
                assert_eq!(out.len(), b"payload".len() + alg.tag_len(), "{alg:?}");

                let back = OpenSslAead.decrypt(alg, &key, &nonce, aad, &out).unwrap();
                assert_eq!(back, b"payload", "{alg:?}");
            }
        }
    }

    /// Decryption fails on any change to what the tag covers.
    ///
    /// This is the whole of what AEAD offers over a cipher, so each part is
    /// moved separately: the ciphertext, the tag, the additional data, the
    /// nonce and the key.
    #[test]
    fn decryption_refuses_anything_that_moved() {
        let key = secret(&[0x5a; 32]);
        let nonce = [0x2b; 12];
        let aad = b"bound data";
        let out = OpenSslAead
            .encrypt(AeadAlg::A256Gcm, &key, &nonce, aad, b"payload")
            .unwrap();

        let mut body = out.clone();
        body[0] ^= 1;
        assert!(
            OpenSslAead
                .decrypt(AeadAlg::A256Gcm, &key, &nonce, aad, &body)
                .is_err()
        );

        let mut tag = out.clone();
        let last = tag.len() - 1;
        tag[last] ^= 1;
        assert!(
            OpenSslAead
                .decrypt(AeadAlg::A256Gcm, &key, &nonce, aad, &tag)
                .is_err()
        );

        assert!(
            OpenSslAead
                .decrypt(AeadAlg::A256Gcm, &key, &nonce, b"other data", &out)
                .is_err()
        );

        let mut other_nonce = nonce;
        other_nonce[0] ^= 1;
        assert!(
            OpenSslAead
                .decrypt(AeadAlg::A256Gcm, &key, &other_nonce, aad, &out)
                .is_err()
        );

        let other_key = secret(&[0x5b; 32]);
        assert!(
            OpenSslAead
                .decrypt(AeadAlg::A256Gcm, &other_key, &nonce, aad, &out)
                .is_err()
        );
    }

    /// A key or nonce of the wrong length is refused before the cipher is
    /// reached, on both paths.
    #[test]
    fn a_key_or_nonce_of_the_wrong_length_is_refused() {
        let nonce = [0x2b; 12];

        for len in [15usize, 17, 24, 32] {
            let key = secret(&vec![0x5a; len]);
            assert!(
                OpenSslAead
                    .encrypt(AeadAlg::A128Gcm, &key, &nonce, b"", b"payload")
                    .is_err(),
                "a {len}-byte key was accepted for A128GCM"
            );
        }

        let key = secret(&[0x5a; 16]);
        for len in [0usize, 8, 11, 13, 16] {
            let nonce = vec![0x2b; len];
            assert!(
                OpenSslAead
                    .encrypt(AeadAlg::A128Gcm, &key, &nonce, b"", b"payload")
                    .is_err(),
                "a {len}-byte nonce was accepted"
            );
            assert!(
                OpenSslAead
                    .decrypt(AeadAlg::A128Gcm, &key, &nonce, b"", &[0; 32])
                    .is_err()
            );
        }
    }

    /// Input too short to hold a tag is refused rather than indexed into.
    #[test]
    fn a_ciphertext_shorter_than_its_tag_is_refused() {
        let key = secret(&[0x5a; 16]);
        let nonce = [0x2b; 12];

        for len in 0..AeadAlg::A128Gcm.tag_len() {
            assert!(
                OpenSslAead
                    .decrypt(AeadAlg::A128Gcm, &key, &nonce, b"", &vec![0; len])
                    .is_err(),
                "a {len}-byte input was accepted"
            );
        }
    }

    /// An empty plaintext still produces a tag, and reads back as empty.
    #[test]
    fn an_empty_plaintext_is_still_authenticated() {
        let key = secret(&[0x5a; 16]);
        let nonce = [0x2b; 12];

        let out = OpenSslAead
            .encrypt(AeadAlg::A128Gcm, &key, &nonce, b"aad", b"")
            .unwrap();
        assert_eq!(out.len(), AeadAlg::A128Gcm.tag_len());

        let back = OpenSslAead
            .decrypt(AeadAlg::A128Gcm, &key, &nonce, b"aad", &out)
            .unwrap();
        assert!(back.is_empty());

        let mut moved = out.clone();
        moved[0] ^= 1;
        assert!(
            OpenSslAead
                .decrypt(AeadAlg::A128Gcm, &key, &nonce, b"aad", &moved)
                .is_err()
        );
    }
}
