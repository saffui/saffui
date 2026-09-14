use crypto::provider::{AeadAlg, CbcAlg, CryptoProvider, HashAlg, PrivateKey};
use crypto::secrecy::ExposeSecret;
use roxmltree::Node;

use crate::xml::{base64_content_of, children_named, element_children, is_named};

const XMLENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const XMLENC11: &str = "http://www.w3.org/2009/xmlenc11#";
const XMLDSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const ELEMENT_TYPE: &str = "http://www.w3.org/2001/04/xmlenc#Element";

/// Why an encrypted element was not read.
///
/// The cryptographic failures share one variant on purpose: telling a wrong key
/// from a broken ciphertext or a bad padding apart is how an oracle starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Undecrypted {
    #[error("the encrypted element is not shaped as XML Encryption for SAML")]
    Misshapen,
    #[error("the encrypted element names an algorithm this service does not accept")]
    UnacceptedAlgorithm,
    #[error("the encrypted element could not be decrypted")]
    Undecryptable,
}

/// The cipher an encrypted element's content is under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentCipher {
    Cbc(CbcAlg),
    Gcm(AeadAlg),
}

impl ContentCipher {
    /// Whether the cipher authenticates what it decrypts. CBC does not, so a
    /// caller decrypts it only under a signature it has already verified.
    pub fn is_authenticated(self) -> bool {
        matches!(self, Self::Gcm(_))
    }

    fn key_len(self) -> usize {
        match self {
            Self::Cbc(alg) => alg.key_len(),
            Self::Gcm(alg) => alg.key_len(),
        }
    }
}

/// The cipher a SAML encrypted element names for its content, read before
/// anything is decrypted.
pub fn content_cipher_of(sealed: Node<'_, '_>) -> Result<ContentCipher, Undecrypted> {
    let data = encrypted_data_of(sealed)?;
    let method = element_children(data)
        .next()
        .filter(|part| is_named(*part, XMLENC, "EncryptionMethod"))
        .ok_or(Undecrypted::Misshapen)?;
    content_cipher_named(method.attribute("Algorithm").unwrap_or_default())
}

/// The plaintext a SAML encrypted element holds, its content key unwrapped with
/// the first of `keys` that opens it.
///
/// The profile is narrow: one `EncryptedData` of type element under AES-GCM or
/// AES-CBC, and exactly one `EncryptedKey` under RSA-OAEP, inside the data's key
/// info or beside the data. OAEP parameters, content held elsewhere and RSA 1.5
/// are refused.
pub fn decrypt_element(
    provider: &dyn CryptoProvider,
    sealed: Node<'_, '_>,
    keys: &[PrivateKey],
) -> Result<Vec<u8>, Undecrypted> {
    let data = encrypted_data_of(sealed)?;
    if data
        .attribute("Type")
        .is_some_and(|kind| kind != ELEMENT_TYPE)
    {
        return Err(Undecrypted::Misshapen);
    }
    let mut parts = element_children(data);
    let method = parts
        .next()
        .filter(|part| is_named(*part, XMLENC, "EncryptionMethod"))
        .ok_or(Undecrypted::Misshapen)?;
    let cipher = content_cipher_named(method.attribute("Algorithm").unwrap_or_default())?;
    let mut part = parts.next();
    let key_info = part.filter(|found| is_named(*found, XMLDSIG, "KeyInfo"));
    if key_info.is_some() {
        part = parts.next();
    }
    let cipher_data = part
        .filter(|found| is_named(*found, XMLENC, "CipherData"))
        .ok_or(Undecrypted::Misshapen)?;
    if parts.next().is_some() || element_children(method).next().is_some() {
        return Err(Undecrypted::Misshapen);
    }

    let mut encrypted_keys = key_info
        .into_iter()
        .flat_map(|info| children_named(info, XMLENC, "EncryptedKey"))
        .chain(children_named(sealed, XMLENC, "EncryptedKey"));
    let encrypted_key = encrypted_keys.next().ok_or(Undecrypted::Misshapen)?;
    if encrypted_keys.next().is_some() {
        return Err(Undecrypted::Misshapen);
    }
    let (oaep_digest, mgf1_digest, wrapped) = read_encrypted_key(encrypted_key)?;
    let body = cipher_value_of(cipher_data)?;

    let content_key = keys
        .iter()
        .find_map(|key| {
            provider
                .key_transport()
                .unwrap_rsa_oaep(key, oaep_digest, mgf1_digest, &wrapped)
                .ok()
        })
        .ok_or(Undecrypted::Undecryptable)?;
    if content_key.expose_secret().len() != cipher.key_len() {
        return Err(Undecrypted::Undecryptable);
    }
    match cipher {
        ContentCipher::Cbc(alg) => {
            let block = alg.block_len();
            if body.len() < 2 * block {
                return Err(Undecrypted::Undecryptable);
            }
            let (iv, ciphertext) = body.split_at(block);
            let mut plain = provider
                .cbc()
                .decrypt_without_padding(alg, &content_key, iv, ciphertext)
                .map_err(|_| Undecrypted::Undecryptable)?;
            // XML Encryption pads with arbitrary bytes and states the count last.
            let padding = plain.last().map_or(0, |last| usize::from(*last));
            if padding == 0 || padding > block {
                return Err(Undecrypted::Undecryptable);
            }
            plain.truncate(plain.len() - padding);
            Ok(plain)
        }
        ContentCipher::Gcm(alg) => {
            if body.len() < alg.nonce_len() + alg.tag_len() {
                return Err(Undecrypted::Undecryptable);
            }
            let (nonce, authenticated) = body.split_at(alg.nonce_len());
            provider
                .aead()
                .decrypt(alg, &content_key, nonce, &[], authenticated)
                .map_err(|_| Undecrypted::Undecryptable)
        }
    }
}

/// The one `EncryptedData` a SAML encrypted element holds, beside nothing but
/// encrypted keys.
fn encrypted_data_of<'a, 'input>(
    sealed: Node<'a, 'input>,
) -> Result<Node<'a, 'input>, Undecrypted> {
    if element_children(sealed).any(|part| {
        !is_named(part, XMLENC, "EncryptedData") && !is_named(part, XMLENC, "EncryptedKey")
    }) {
        return Err(Undecrypted::Misshapen);
    }
    let mut data = children_named(sealed, XMLENC, "EncryptedData");
    match (data.next(), data.next()) {
        (Some(found), None) => Ok(found),
        _ => Err(Undecrypted::Misshapen),
    }
}

/// The OAEP digests an encrypted key names, and the key it wraps.
fn read_encrypted_key(
    encrypted_key: Node<'_, '_>,
) -> Result<(HashAlg, HashAlg, Vec<u8>), Undecrypted> {
    let (mut method, mut cipher_data) = (None, None);
    for part in element_children(encrypted_key) {
        match (part.tag_name().namespace(), part.tag_name().name()) {
            (Some(XMLENC), "EncryptionMethod") if method.is_none() => method = Some(part),
            (Some(XMLENC), "CipherData") if cipher_data.is_none() => cipher_data = Some(part),
            (Some(XMLDSIG), "KeyInfo") | (Some(XMLENC), "ReferenceList" | "CarriedKeyName") => {}
            _ => return Err(Undecrypted::Misshapen),
        }
    }
    let (oaep_digest, mgf1_digest) = key_transport_named(method.ok_or(Undecrypted::Misshapen)?)?;
    let wrapped = cipher_value_of(cipher_data.ok_or(Undecrypted::Misshapen)?)?;
    Ok((oaep_digest, mgf1_digest, wrapped))
}

/// RSA-OAEP as XML Encryption names it: the 2001 form fixes MGF1 to SHA-1, the
/// 2009 form lets it be named; both default the OAEP digest to SHA-1.
fn key_transport_named(method: Node<'_, '_>) -> Result<(HashAlg, HashAlg), Undecrypted> {
    let (mut digest, mut mgf) = (None, None);
    for parameter in element_children(method) {
        let named = parameter.attribute("Algorithm").unwrap_or_default();
        match (
            parameter.tag_name().namespace(),
            parameter.tag_name().name(),
        ) {
            (Some(XMLDSIG), "DigestMethod") if digest.is_none() => {
                digest = Some(digest_named(named)?)
            }
            (Some(XMLENC11), "MGF") if mgf.is_none() => mgf = Some(mgf_named(named)?),
            _ => return Err(Undecrypted::Misshapen),
        }
    }
    match method.attribute("Algorithm").unwrap_or_default() {
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" if mgf.is_none() => {
            Ok((digest.unwrap_or(HashAlg::Sha1), HashAlg::Sha1))
        }
        "http://www.w3.org/2009/xmlenc11#rsa-oaep" => Ok((
            digest.unwrap_or(HashAlg::Sha1),
            mgf.unwrap_or(HashAlg::Sha1),
        )),
        _ => Err(Undecrypted::UnacceptedAlgorithm),
    }
}

fn content_cipher_named(uri: &str) -> Result<ContentCipher, Undecrypted> {
    match uri {
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc" => Ok(ContentCipher::Cbc(CbcAlg::A128Cbc)),
        "http://www.w3.org/2001/04/xmlenc#aes192-cbc" => Ok(ContentCipher::Cbc(CbcAlg::A192Cbc)),
        "http://www.w3.org/2001/04/xmlenc#aes256-cbc" => Ok(ContentCipher::Cbc(CbcAlg::A256Cbc)),
        "http://www.w3.org/2009/xmlenc11#aes128-gcm" => Ok(ContentCipher::Gcm(AeadAlg::A128Gcm)),
        "http://www.w3.org/2009/xmlenc11#aes192-gcm" => Ok(ContentCipher::Gcm(AeadAlg::A192Gcm)),
        "http://www.w3.org/2009/xmlenc11#aes256-gcm" => Ok(ContentCipher::Gcm(AeadAlg::A256Gcm)),
        _ => Err(Undecrypted::UnacceptedAlgorithm),
    }
}

fn digest_named(uri: &str) -> Result<HashAlg, Undecrypted> {
    match uri {
        "http://www.w3.org/2000/09/xmldsig#sha1" => Ok(HashAlg::Sha1),
        "http://www.w3.org/2001/04/xmlenc#sha256" => Ok(HashAlg::Sha256),
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => Ok(HashAlg::Sha384),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Ok(HashAlg::Sha512),
        _ => Err(Undecrypted::UnacceptedAlgorithm),
    }
}

fn mgf_named(uri: &str) -> Result<HashAlg, Undecrypted> {
    match uri {
        "http://www.w3.org/2009/xmlenc11#mgf1sha1" => Ok(HashAlg::Sha1),
        "http://www.w3.org/2009/xmlenc11#mgf1sha256" => Ok(HashAlg::Sha256),
        "http://www.w3.org/2009/xmlenc11#mgf1sha384" => Ok(HashAlg::Sha384),
        "http://www.w3.org/2009/xmlenc11#mgf1sha512" => Ok(HashAlg::Sha512),
        _ => Err(Undecrypted::UnacceptedAlgorithm),
    }
}

fn cipher_value_of(cipher_data: Node<'_, '_>) -> Result<Vec<u8>, Undecrypted> {
    let mut inside = element_children(cipher_data);
    match (inside.next(), inside.next()) {
        (Some(value), None) if is_named(value, XMLENC, "CipherValue") => {
            base64_content_of(value).ok_or(Undecrypted::Misshapen)
        }
        _ => Err(Undecrypted::Misshapen),
    }
}
