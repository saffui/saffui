use openssl::symm::{Cipher, Crypter, Mode};
use secrecy::{ExposeSecret, SecretBox};

use crate::provider::{CbcAlg, CbcProvider, CryptoError, Result};

pub struct OpenSslCbc;

fn cipher(alg: CbcAlg) -> Cipher {
    match alg {
        CbcAlg::A128Cbc => Cipher::aes_128_cbc(),
        CbcAlg::A192Cbc => Cipher::aes_192_cbc(),
        CbcAlg::A256Cbc => Cipher::aes_256_cbc(),
    }
}

impl CbcProvider for OpenSslCbc {
    fn decrypt_without_padding(
        &self,
        alg: CbcAlg,
        key: &SecretBox<Vec<u8>>,
        iv: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if key.expose_secret().len() != alg.key_len()
            || iv.len() != alg.block_len()
            || ciphertext.is_empty()
            || !ciphertext.len().is_multiple_of(alg.block_len())
        {
            return Err(CryptoError::InvalidParams);
        }
        let mut crypter = Crypter::new(cipher(alg), Mode::Decrypt, key.expose_secret(), Some(iv))
            .map_err(|_| CryptoError::OperationFailed)?;
        crypter.pad(false);
        let mut plain = vec![0; ciphertext.len() + alg.block_len()];
        let written = crypter
            .update(ciphertext, &mut plain)
            .map_err(|_| CryptoError::OperationFailed)?;
        let finished = crypter
            .finalize(&mut plain[written..])
            .map_err(|_| CryptoError::OperationFailed)?;
        plain.truncate(written + finished);
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::OpenSslCbc;
    use crate::provider::{CbcAlg, CbcProvider, CryptoError};
    use openssl::symm::{Cipher, Crypter, Mode};
    use secrecy::SecretBox;

    fn encrypted(key: &[u8], iv: &[u8], plain: &[u8]) -> Vec<u8> {
        let mut crypter =
            Crypter::new(Cipher::aes_256_cbc(), Mode::Encrypt, key, Some(iv)).expect("a crypter");
        crypter.pad(false);
        let mut out = vec![0; plain.len() + 16];
        let written = crypter.update(plain, &mut out).expect("encrypted");
        let finished = crypter.finalize(&mut out[written..]).expect("finished");
        out.truncate(written + finished);
        out
    }

    /// Whole blocks come back exactly, their padding left for the caller, and a
    /// key, a vector or a length that does not fit the cipher is refused.
    #[test]
    fn whole_blocks_decrypt_with_their_padding_left_on() {
        let raw_key = [0x42; 32];
        let key = SecretBox::new(Box::new(raw_key.to_vec()));
        let iv = [0x24; 16];
        let plain = b"an assertion, then its padding\x7f\x02";
        let ciphertext = encrypted(&raw_key, &iv, plain);

        let decrypted = OpenSslCbc
            .decrypt_without_padding(CbcAlg::A256Cbc, &key, &iv, &ciphertext)
            .expect("decrypted");
        assert_eq!(decrypted, plain.to_vec());
        for (alg, iv, ciphertext) in [
            (CbcAlg::A128Cbc, &iv[..], &ciphertext[..]),
            (CbcAlg::A256Cbc, &iv[..12], &ciphertext[..]),
            (CbcAlg::A256Cbc, &iv[..], &ciphertext[..31]),
            (CbcAlg::A256Cbc, &iv[..], &ciphertext[..0]),
        ] {
            assert!(matches!(
                OpenSslCbc.decrypt_without_padding(alg, &key, iv, ciphertext),
                Err(CryptoError::InvalidParams)
            ));
        }
    }
}
