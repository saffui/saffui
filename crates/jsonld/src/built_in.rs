//! The contexts this server holds from the start, compiled in: the W3C
//! credentials contexts of VCDM 1.1 and 2.0, and the two suite contexts
//! MOSIP's issuers and Inji's wallets sign under. A realm pins any other, and
//! none of these.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::Value;

use crate::context::Contexts;
use crate::json::parse_strict;

pub const CREDENTIALS_V1: &str = "https://www.w3.org/2018/credentials/v1";
pub const CREDENTIALS_V2: &str = "https://www.w3.org/ns/credentials/v2";
pub const ED25519_2020_V1: &str = "https://w3id.org/security/suites/ed25519-2020/v1";
pub const JWS_2020_V1: &str = "https://w3id.org/security/suites/jws-2020/v1";

const WRITTEN: [(&str, &str); 4] = [
    (
        CREDENTIALS_V1,
        include_str!("../contexts/w3c/credentials-v1.jsonld"),
    ),
    (
        CREDENTIALS_V2,
        include_str!("../contexts/w3c/credentials-v2.jsonld"),
    ),
    (
        ED25519_2020_V1,
        include_str!("../contexts/digitalbazaar/ed25519-signature-2020-v1.jsonld"),
    ),
    (
        JWS_2020_V1,
        include_str!("../contexts/w3c/jws-2020-v1.jsonld"),
    ),
];

/// The built-in contexts by the URL documents name them with, read once.
pub fn built_in_contexts() -> &'static HashMap<String, Value> {
    static READ: OnceLock<HashMap<String, Value>> = OnceLock::new();
    READ.get_or_init(|| {
        WRITTEN
            .iter()
            .filter_map(|(url, text)| {
                Some(((*url).to_owned(), parse_strict(text.as_bytes()).ok()?))
            })
            .collect()
    })
}

/// The built-in contexts, then the ones a realm pinned.
pub struct HeldContexts<'p> {
    pinned: &'p HashMap<String, Value>,
}

impl<'p> HeldContexts<'p> {
    pub fn new(pinned: &'p HashMap<String, Value>) -> Self {
        Self { pinned }
    }
}

impl Contexts for HeldContexts<'_> {
    fn document(&self, url: &str) -> Option<&Value> {
        built_in_contexts()
            .get(url)
            .or_else(|| self.pinned.get(url))
    }
}
