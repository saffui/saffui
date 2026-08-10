// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::io::Read;
use std::ops::Bound::Included;
use std::string::ToString;
use std::sync::Arc;

use anyhow::bail;

use crate::jose::jwk::Jwk;
use crate::jose::{JoseError, Map, Value};

/// Represents JWK set.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct JwkSet {
    keys: Vec<Arc<Jwk>>,
    params: Map<String, Value>,
    kid_map: BTreeMap<(String, usize), Arc<Jwk>>,
}

impl Default for JwkSet {
    fn default() -> Self {
        Self::new()
    }
}

impl JwkSet {
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            params: {
                let mut map = Map::new();
                map.insert("keys".to_string(), Value::Array(Vec::new()));
                map
            },
            kid_map: BTreeMap::new(),
        }
    }

    pub fn from_map(map: Map<String, Value>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let mut kid_map = BTreeMap::new();
            let keys = match map.get("keys") {
                Some(Value::Array(vals)) => {
                    let mut vec = Vec::new();
                    for (i, val) in vals.iter().enumerate() {
                        match val {
                            Value::Object(val) => {
                                let jwk = Arc::new(Jwk::from_map(val.clone())?);
                                if let Some(kid) = jwk.key_id() {
                                    kid_map.insert((kid.to_string(), i), Arc::clone(&jwk));
                                }
                                vec.push(jwk);
                            }
                            _ => {
                                bail!("An element of the JWK set keys parameter must be a object.")
                            }
                        }
                    }
                    vec
                }
                Some(_) => bail!("The JWT keys parameter must be a array."),
                None => bail!("The JWK set must have a keys parameter."),
            };

            Ok(Self {
                keys,
                params: map,
                kid_map,
            })
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwkFormat(err),
        })
    }

    pub fn from_reader(input: &mut dyn Read) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let keys: Map<String, Value> = serde_json::from_reader(input)?;
            Ok(Self::from_map(keys)?)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwkFormat(err),
        })
    }

    pub fn from_bytes(input: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let keys: Map<String, Value> = serde_json::from_slice(input.as_ref())?;
            Ok(Self::from_map(keys)?)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwkFormat(err),
        })
    }

    pub fn get(&self, key_id: &str) -> Vec<&Jwk> {
        let mut vec = Vec::new();
        for (_, val) in self.kid_map.range((
            Included((key_id.to_string(), 0)),
            Included((key_id.to_string(), usize::MAX)),
        )) {
            let jwk: &Jwk = val;
            vec.push(jwk);
        }
        vec
    }

    pub fn keys(&self) -> Vec<&Jwk> {
        self.keys.iter().map(|e| e.as_ref()).collect()
    }

    pub fn push_key(&mut self, jwk: Jwk) {
        match self.params.get_mut("keys") {
            Some(Value::Array(keys)) => {
                keys.push(Value::Object(jwk.as_ref().clone()));
            }
            _ => unreachable!(),
        }

        let jwk = Arc::new(jwk);
        if let Some(kid) = jwk.key_id() {
            self.kid_map
                .insert((kid.to_string(), self.keys.len()), Arc::clone(&jwk));
        }
        self.keys.push(jwk);
    }

    pub fn remove_key(&mut self, jwk: &Jwk) {
        let index = self.keys.iter().position(|e| e.as_ref() == jwk);
        if let Some(index) = index {
            match self.params.get_mut("keys") {
                Some(Value::Array(keys)) => {
                    keys.remove(index);
                }
                _ => unreachable!(),
            }
            self.keys.remove(index);
            // The lookup index has to follow, or `get(kid)` keeps handing out a
            // key this set no longer holds — a revoked key that still verifies.
            // Rebuilt rather than pruned by entry: the second half of the map's
            // own key is the position in `keys`, so removing one element shifts
            // every entry after it.
            self.reindex();
        }
    }

    /// Rebuild the key-id index from `keys`, whose order it mirrors.
    fn reindex(&mut self) {
        self.kid_map = self
            .keys
            .iter()
            .enumerate()
            .filter_map(|(i, jwk)| {
                jwk.key_id()
                    .map(|kid| ((kid.to_string(), i), Arc::clone(jwk)))
            })
            .collect();
    }
}

impl AsRef<Map<String, Value>> for JwkSet {
    fn as_ref(&self) -> &Map<String, Value> {
        &self.params
    }
}

impl From<JwkSet> for Map<String, Value> {
    fn from(val: JwkSet) -> Self {
        val.params
    }
}

impl Display for JwkSet {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str("{\"keys\":[")?;

        for (i, jwk) in self.keys.iter().enumerate() {
            if i > 0 {
                fmt.write_str(",")?;
            }

            let map: &Map<String, Value> = jwk.as_ref().as_ref();
            let val = serde_json::to_string(map).map_err(|_e| std::fmt::Error {})?;
            fmt.write_str(&val)?;
        }

        fmt.write_str("]}")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oct_key(kid: &str) -> Jwk {
        let mut jwk = Jwk::new("oct");
        jwk.set_key_id(kid);
        jwk
    }

    /// Removing a key has to remove it from the lookup index too.
    ///
    /// `remove_key` dropped the key from `keys` and from the `keys` parameter
    /// and left `kid_map` alone, so `get(kid)` kept returning a key the set no
    /// longer held. For a JWK set that is revocation: the key is gone from
    /// every listing and still resolves for verification.
    ///
    /// The third key is the other half. `kid_map` is keyed by `(kid, position
    /// in keys)`, so removing an element shifts every entry after it — pruning
    /// the one entry would have left the survivors pointing at the wrong
    /// positions. The index is rebuilt instead, and `"c"` is here to prove it.
    #[test]
    fn a_removed_key_stops_resolving_by_its_id() {
        let mut set = JwkSet::new();
        set.push_key(oct_key("a"));
        set.push_key(oct_key("b"));
        set.push_key(oct_key("c"));
        assert_eq!(set.get("b").len(), 1);

        set.remove_key(&oct_key("b"));

        assert!(
            set.get("b").is_empty(),
            "a removed key still resolves by its key id"
        );
        assert_eq!(
            set.get("c").len(),
            1,
            "removing a key lost the key that followed it in the index"
        );
        assert_eq!(set.get("a").len(), 1);
        assert_eq!(set.keys().len(), 2);
    }
}
