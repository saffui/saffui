// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

use std::any::Any;
use std::fmt::{Debug, Display};
use std::ops::Deref;

use crate::jose::jwk::Jwk;
use crate::jose::jws::JwsHeader;
use crate::jose::util::{self, decode_base64_urlsafe_no_pad};
use crate::jose::{JoseError, JoseHeader, Map, Value};

/// Represent JWS protected and unprotected header claims
#[derive(Debug, Eq, PartialEq, Clone, Default)]
pub struct JwsHeaderSet {
    protected: Map<String, Value>,
    unprotected: Map<String, Value>,
}

impl JwsHeaderSet {
    /// Return a JwsHeader instance.
    pub fn new() -> Self {
        Self {
            protected: Map::new(),
            unprotected: Map::new(),
        }
    }

    /// Set a value for algorithm header claim (alg).
    ///
    /// # Arguments
    ///
    /// * `value` - a algorithm
    /// * `protection` - If it dosen't need protection, set false.
    pub fn set_algorithm(&mut self, value: impl Into<String>, protection: bool) {
        let key = "alg";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for algorithm header claim (alg).
    pub fn algorithm(&self) -> Option<&str> {
        match self.claim("alg") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for JWK set URL header claim (jku).
    ///
    /// # Arguments
    ///
    /// * `value` - a JWK set URL
    pub fn set_jwk_set_url(&mut self, value: impl Into<String>, protection: bool) {
        let key = "jku";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for JWK set URL header claim (jku).
    pub fn jwk_set_url(&self) -> Option<&str> {
        match self.claim("jku") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for JWK header claim (jwk).
    ///
    /// # Arguments
    ///
    /// * `value` - a JWK
    pub fn set_jwk(&mut self, value: Jwk, protection: bool) {
        let key = "jwk";
        let value: Map<String, Value> = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::Object(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::Object(value));
        }
    }

    /// Return the value for JWK header claim (jwk).
    pub fn jwk(&self) -> Option<Jwk> {
        match self.claim("jwk") {
            Some(Value::Object(vals)) => Jwk::from_map(vals.clone()).ok(),
            _ => None,
        }
    }

    /// Set a value for X.509 URL header claim (x5u).
    ///
    /// # Arguments
    ///
    /// * `value` - a X.509 URL
    pub fn set_x509_url(&mut self, value: impl Into<String>, protection: bool) {
        let key = "x5u";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return a value for a X.509 URL header claim (x5u).
    pub fn x509_url(&self) -> Option<&str> {
        match self.claim("x5u") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set values for X.509 certificate chain header claim (x5c).
    ///
    /// # Arguments
    ///
    /// * `values` - X.509 certificate chain
    pub fn set_x509_certificate_chain(&mut self, values: &[impl AsRef<[u8]>], protection: bool) {
        let key = "x5c";
        let vec = values
            .iter()
            .map(|v| Value::String(util::encode_base64_standard(v)))
            .collect();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::Array(vec));
        } else {
            self.protected.remove(key);
            self.unprotected.insert(key.to_string(), Value::Array(vec));
        }
    }

    /// Return values for a X.509 certificate chain header claim (x5c).
    pub fn x509_certificate_chain(&self) -> Option<Vec<Vec<u8>>> {
        match self.claim("x5c") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val2) => match util::decode_base64_standard(val2) {
                            Ok(val3) => vec.push(val3.clone()),
                            Err(_) => return None,
                        },
                        _ => return None,
                    }
                }
                Some(vec)
            }
            _ => None,
        }
    }

    /// Set a value for X.509 certificate SHA-1 thumbprint header claim (x5t).
    ///
    /// # Arguments
    ///
    /// * `value` - A X.509 certificate SHA-1 thumbprint
    pub fn set_x509_certificate_sha1_thumbprint(
        &mut self,
        value: impl AsRef<[u8]>,
        protection: bool,
    ) {
        let key = "x5t";
        let value = util::encode_base64_urlsafe_nopad(value);
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for X.509 certificate SHA-1 thumbprint header claim (x5t).
    pub fn x509_certificate_sha1_thumbprint(&self) -> Option<Vec<u8>> {
        match self.claim("x5t") {
            Some(Value::String(val)) => decode_base64_urlsafe_no_pad(val).ok(),
            _ => None,
        }
    }

    /// Set a value for a x509 certificate SHA-256 thumbprint header claim (x5t#S256).
    ///
    /// # Arguments
    ///
    /// * `value` - A x509 certificate SHA-256 thumbprint
    pub fn set_x509_certificate_sha256_thumbprint(
        &mut self,
        value: impl AsRef<[u8]>,
        protection: bool,
    ) {
        let key = "x5t#S256";
        let value = util::encode_base64_urlsafe_nopad(value);
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for X.509 certificate SHA-256 thumbprint header claim (x5t#S256).
    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<Vec<u8>> {
        match self.claim("x5t#S256") {
            Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val).ok(),
            _ => None,
        }
    }

    /// Set a value for key ID header claim (kid).
    ///
    /// # Arguments
    ///
    /// * `value` - a key ID
    pub fn set_key_id(&mut self, value: impl Into<String>, protection: bool) {
        let key = "kid";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for key ID header claim (kid).
    pub fn key_id(&self) -> Option<&str> {
        match self.claim("kid") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for token type header claim (typ).
    ///
    /// # Arguments
    ///
    /// * `value` - a token type (e.g. "JWT")
    pub fn set_token_type(&mut self, value: impl Into<String>, protection: bool) {
        let key = "typ";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for token type header claim (typ).
    pub fn token_type(&self) -> Option<&str> {
        match self.claim("typ") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for content type header claim (cty).
    ///
    /// # Arguments
    ///
    /// * `value` - a content type (e.g. "JWT")
    pub fn set_content_type(&mut self, value: impl Into<String>, protection: bool) {
        let key = "cty";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for content type header claim (cty).
    pub fn content_type(&self) -> Option<&str> {
        match self.claim("cty") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set values for critical header claim (crit).
    ///
    /// # Arguments
    ///
    /// * `values` - critical claim names
    pub fn set_critical(&mut self, values: &[impl AsRef<str>]) {
        let key = "crit";
        let vec = values
            .iter()
            .map(|v| Value::String(v.as_ref().to_string()))
            .collect();
        self.unprotected.remove(key);
        self.protected.insert(key.to_string(), Value::Array(vec));
    }

    /// Return values for critical header claim (crit).
    pub fn critical(&self) -> Option<Vec<&str>> {
        match self.claim("crit") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val2) => vec.push(val2.as_str()),
                        _ => return None,
                    }
                }
                Some(vec)
            }
            _ => None,
        }
    }

    /// Set a value for base64url-encode payload header claim (b64).
    ///
    /// # Arguments
    ///
    /// * `value` - is base64url-encode payload
    pub fn set_base64url_encode_payload(&mut self, value: bool) {
        let key = "b64";
        self.unprotected.remove(key);
        self.protected.insert(key.to_string(), Value::Bool(value));
    }

    /// Return the value for base64url-encode payload header claim (b64).
    pub fn base64url_encode_payload(&self) -> Option<bool> {
        match self.claim("b64") {
            Some(Value::Bool(val)) => Some(*val),
            _ => None,
        }
    }

    /// Set a value for url header claim (url).
    ///
    /// # Arguments
    ///
    /// * `value` - a url
    pub fn set_url(&mut self, value: impl Into<String>, protection: bool) {
        let key = "url";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for url header claim (url).
    pub fn url(&self) -> Option<&str> {
        match self.claim("url") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for a nonce header claim (nonce).
    ///
    /// # Arguments
    ///
    /// * `value` - A nonce
    pub fn set_nonce(&mut self, value: impl AsRef<[u8]>, protection: bool) {
        let key = "nonce";
        let value = util::encode_base64_urlsafe_nopad(value);
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for nonce header claim (nonce).
    pub fn nonce(&self) -> Option<Vec<u8>> {
        match self.claim("nonce") {
            Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val).ok(),
            _ => None,
        }
    }

    pub fn set_claim(
        &mut self,
        key: &str,
        value: Option<Value>,
        protection: bool,
    ) -> Result<(), JoseError> {
        match value {
            Some(val) => {
                JwsHeader::check_claim(key, &val)?;
                if protection {
                    self.unprotected.remove(key);
                    self.protected.insert(key.to_string(), val);
                } else {
                    self.protected.remove(key);
                    self.unprotected.insert(key.to_string(), val);
                }
            }
            None => {
                self.protected.remove(key);
                self.unprotected.remove(key);
            }
        }

        Ok(())
    }

    /// Return values for header claims set
    pub fn claims_set(&self, protection: bool) -> &Map<String, Value> {
        if protection {
            &self.protected
        } else {
            &self.unprotected
        }
    }

    pub fn to_map(&self) -> Map<String, Value> {
        let mut map = self.protected.clone();
        for (key, value) in &self.unprotected {
            map.insert(key.clone(), value.clone());
        }
        map
    }
}

impl JoseHeader for JwsHeaderSet {
    fn len(&self) -> usize {
        self.protected.len() + self.unprotected.len()
    }

    fn claim(&self, key: &str) -> Option<&Value> {
        if let Some(val) = self.protected.get(key) {
            Some(val)
        } else {
            self.unprotected.get(key)
        }
    }

    fn box_clone(&self) -> Box<dyn JoseHeader> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl Display for JwsHeaderSet {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let protected = serde_json::to_string(&self.protected).map_err(|_e| std::fmt::Error {})?;
        let unprotected =
            serde_json::to_string(&self.unprotected).map_err(|_e| std::fmt::Error {})?;
        fmt.write_str("{\"protected\":")?;
        fmt.write_str(&protected)?;
        fmt.write_str(",\"unprotected\":")?;
        fmt.write_str(&unprotected)?;
        fmt.write_str("}")?;
        Ok(())
    }
}

impl Deref for JwsHeaderSet {
    type Target = dyn JoseHeader;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::json;

    use crate::jose::Value;
    use crate::jose::jwk::Jwk;
    use crate::jose::jws::JwsHeaderSet;

    #[test]
    fn test_new_jws_header() -> Result<()> {
        let mut header = JwsHeaderSet::new();
        let jwk = Jwk::new("oct");
        header.set_jwk_set_url("jku", true);
        header.set_jwk(jwk.clone(), true);
        header.set_x509_url("x5u", true);
        header.set_x509_certificate_chain(
            &[
                b"x5c0".to_vec(),
                b"x5c1".to_vec(),
                "@@~".as_bytes().to_vec(),
            ],
            true,
        );
        header.set_x509_certificate_sha1_thumbprint(b"x5t@@~", true);
        header.set_x509_certificate_sha256_thumbprint(b"x5t#S256 @@~", true);
        header.set_key_id("kid", true);
        header.set_token_type("typ", true);
        header.set_content_type("cty", true);
        header.set_critical(&["crit0", "crit1"]);
        header.set_url("url", true);
        header.set_nonce(b"nonce", true);
        header.set_claim("header_claim", Some(json!("header_claim")), true)?;

        assert_eq!(header.jwk_set_url(), Some("jku"));
        assert_eq!(header.jwk(), Some(jwk));
        assert_eq!(header.x509_url(), Some("x5u"));
        assert_eq!(
            header.x509_certificate_chain(),
            Some(vec![
                b"x5c0".to_vec(),
                b"x5c1".to_vec(),
                "@@~".as_bytes().to_vec()
            ])
        );
        assert_eq!(
            header.claim("x5c"),
            Some(&Value::Array(vec![
                Value::String("eDVjMA==".to_string()),
                Value::String("eDVjMQ==".to_string()),
                Value::String("QEB+".to_string()),
            ]))
        );
        assert_eq!(
            header.x509_certificate_sha1_thumbprint(),
            Some(b"x5t@@~".to_vec())
        );
        assert_eq!(
            header.claim("x5t"),
            Some(&Value::String("eDV0QEB-".to_string()))
        );
        assert_eq!(
            header.x509_certificate_sha256_thumbprint(),
            Some(b"x5t#S256 @@~".to_vec())
        );
        assert_eq!(
            header.claim("x5t#S256"),
            Some(&Value::String("eDV0I1MyNTYgQEB-".to_string()))
        );
        assert_eq!(header.key_id(), Some("kid"));
        assert_eq!(header.token_type(), Some("typ"));
        assert_eq!(header.content_type(), Some("cty"));
        assert_eq!(header.url(), Some("url"));
        assert_eq!(header.nonce(), Some(b"nonce".to_vec()));
        assert_eq!(header.critical(), Some(vec!["crit0", "crit1"]));
        assert_eq!(header.claim("header_claim"), Some(&json!("header_claim")));
        Ok(())
    }

    /// A claim lands in exactly one half, and moving it takes it out of the
    /// other.
    ///
    /// The two halves are not decoration: only the protected one is covered by
    /// the signature. A claim that stayed in both after being moved would be
    /// readable as protected while an unsigned copy sat beside it, and a reader
    /// picking the wrong copy would trust a value nobody signed.
    #[test]
    fn a_claim_lives_in_one_half_and_moving_it_empties_the_other() {
        let mut set = JwsHeaderSet::new();

        set.set_key_id("kid-1", true);
        assert_eq!(set.claims_set(true).get("kid"), Some(&json!("kid-1")));
        assert_eq!(set.claims_set(false).get("kid"), None);

        set.set_key_id("kid-2", false);
        assert_eq!(set.claims_set(true).get("kid"), None);
        assert_eq!(set.claims_set(false).get("kid"), Some(&json!("kid-2")));
        assert_eq!(set.key_id(), Some("kid-2"));
    }

    /// Every claim, in each half, read back through the merged view.
    #[test]
    fn every_claim_reads_back_from_either_half() -> Result<()> {
        for protection in [true, false] {
            let mut set = JwsHeaderSet::new();
            set.set_algorithm("ES256", protection);
            set.set_jwk_set_url("https://example.test/jwks", protection);
            set.set_x509_url("https://example.test/x5u", protection);
            set.set_x509_certificate_chain(&[b"first".to_vec()], protection);
            set.set_x509_certificate_sha1_thumbprint(b"sha1-thumb", protection);
            set.set_x509_certificate_sha256_thumbprint(b"sha256-thumb", protection);
            set.set_key_id("kid-1", protection);
            set.set_token_type("JWT", protection);
            set.set_content_type("application/json", protection);
            set.set_url("https://example.test/url", protection);
            set.set_nonce(b"nonce-bytes", protection);

            let mut jwk = Jwk::new("oct");
            jwk.set_key_id("jwk-kid");
            set.set_jwk(jwk, protection);

            set.set_claim("custom", Some(json!("value")), protection)?;

            assert_eq!(set.algorithm(), Some("ES256"));
            assert_eq!(set.claims_set(protection).get("alg"), Some(&json!("ES256")));
            assert_eq!(set.jwk_set_url(), Some("https://example.test/jwks"));
            assert_eq!(set.x509_url(), Some("https://example.test/x5u"));
            assert_eq!(set.x509_certificate_chain(), Some(vec![b"first".to_vec()]));
            assert_eq!(
                set.x509_certificate_sha1_thumbprint(),
                Some(b"sha1-thumb".to_vec())
            );
            assert_eq!(
                set.x509_certificate_sha256_thumbprint(),
                Some(b"sha256-thumb".to_vec())
            );
            assert_eq!(set.key_id(), Some("kid-1"));
            assert_eq!(set.token_type(), Some("JWT"));
            assert_eq!(set.content_type(), Some("application/json"));
            assert_eq!(set.url(), Some("https://example.test/url"));
            assert_eq!(set.nonce(), Some(b"nonce-bytes".to_vec()));
            assert_eq!(
                set.jwk().and_then(|j| j.key_id().map(str::to_owned)),
                Some("jwk-kid".to_string())
            );

            // The merged view is what a signer hands to the header, so every
            // claim has to be in it whichever half it was put in.
            let merged = set.to_map();
            assert_eq!(merged.get("kid"), Some(&json!("kid-1")));
            assert_eq!(merged.get("custom"), Some(&json!("value")));
        }

        Ok(())
    }

    /// `alg` and the payload-encoding flag are signed or they are worthless, so
    /// they go in the protected half whatever a caller asks for.
    #[test]
    fn the_signed_claims_stay_protected() {
        let mut set = JwsHeaderSet::new();
        set.set_algorithm("ES256", true);
        set.set_critical(&["b64"]);
        set.set_base64url_encode_payload(false);

        assert_eq!(set.claims_set(true).get("alg"), Some(&json!("ES256")));
        assert_eq!(set.claims_set(false).get("alg"), None);
        assert_eq!(set.claims_set(true).get("crit"), Some(&json!(["b64"])));
        assert_eq!(set.claims_set(false).get("crit"), None);
        assert_eq!(set.claims_set(true).get("b64"), Some(&json!(false)));
        assert_eq!(set.claims_set(false).get("b64"), None);

        assert_eq!(set.critical(), Some(vec!["b64"]));
        assert_eq!(set.base64url_encode_payload(), Some(false));
    }

    #[test]
    fn a_claim_of_the_wrong_type_is_refused() {
        let mut set = JwsHeaderSet::new();

        assert!(set.set_claim("alg", Some(json!(1)), true).is_err());
        assert!(set.set_claim("kid", Some(json!(true)), false).is_err());
        assert!(set.set_claim("crit", Some(json!("b64")), true).is_err());
        assert!(set.set_claim("b64", Some(json!("false")), true).is_err());
    }

    #[test]
    fn setting_a_claim_to_none_removes_it_from_both_halves() -> Result<()> {
        let mut set = JwsHeaderSet::new();
        set.set_key_id("kid-1", true);
        set.set_claim("kid", None, true)?;

        assert_eq!(set.key_id(), None);
        assert!(!set.claims_set(true).contains_key("kid"));
        assert!(!set.claims_set(false).contains_key("kid"));

        Ok(())
    }
}
