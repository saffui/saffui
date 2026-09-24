//! What a browser that signed in before carries back, so that its attempts
//! under that name are counted against it rather than against its address.
//!
//! Sealed rather than signed, by the realm's keyring and under the digest of
//! the name it was minted for: it opens under that name in that realm and as
//! nothing anywhere else, and it says nothing to whoever reads it. Nothing is
//! stored. It is minted only once a login admits, so holding one proves no
//! more than its holder already proved, and it is read before the name is
//! looked up, at the same cost whatever the name.

use chrono::{DateTime, Utc};
use crypto::envelope::Envelope;
use crypto::provider::CryptoProvider;
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use models::entities::realm::RealmModel;
use secrecy::ExposeSecret;
use store::keyring::RealmKeyring;

/// What a token is sealed for, and never what anything else is.
const PURPOSE: &str = "device";

/// How long a token stands once minted. Every admission mints another, so a
/// browser in use keeps one.
pub const LIFETIME: i64 = 90 * 86_400;

/// How far ahead a node whose clock runs fast may have minted one.
const AHEAD: i64 = 60;

const ID_LEN: usize = 16;

/// A browser that proved it signed in under the name being weighed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub(crate) id: String,
}

impl Device {
    /// What its failures are counted under, drawn afresh at every admission.
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Seal a token for the browser just admitted under this name, or nothing
/// when none can be sealed: that browser then stays on its address's rules,
/// which is where it was.
pub async fn mint(
    provider: &dyn CryptoProvider,
    ring: &RealmKeyring,
    envelope: &Envelope,
    counted_name: &str,
    now: DateTime<Utc>,
) -> Option<String> {
    let mut id = [0_u8; ID_LEN];
    provider.rand().fill(&mut id).ok()?;
    let sealed = ring
        .seal(
            envelope,
            PURPOSE,
            counted_name,
            &payload(&id, now.timestamp()),
        )
        .await
        .ok()?;
    Some(BASE64URL_NOPAD.encode(&sealed))
}

/// The device a presented token proves for this name, or nothing.
///
/// Only where the realm counts failures by where they come from: a device
/// that no count weighs would escape both its own and its address's. A token
/// that does not open under this name, or has outlived its lifetime, is no
/// token at all.
pub async fn recognize(
    realm: &RealmModel,
    ring: &RealmKeyring,
    envelope: &Envelope,
    counted_name: Option<&str>,
    presented: Option<&str>,
    now: DateTime<Utc>,
) -> Option<Device> {
    let counted_name = counted_name.filter(|_| realm.source_throttle.throttled)?;
    let sealed = BASE64URL_NOPAD.decode(presented?.as_bytes()).ok()?;
    let opened = ring
        .open(envelope, PURPOSE, counted_name, &sealed)
        .await
        .ok()?;
    let (id, issued_at) = read_payload(opened.expose_secret())?;
    standing(issued_at, now.timestamp()).then(|| Device {
        id: HEXLOWER.encode(&id),
    })
}

fn payload(id: &[u8; ID_LEN], issued_at: i64) -> Vec<u8> {
    let mut held = Vec::with_capacity(ID_LEN + 8);
    held.extend_from_slice(id);
    held.extend_from_slice(&issued_at.to_be_bytes());
    held
}

fn read_payload(held: &[u8]) -> Option<([u8; ID_LEN], i64)> {
    if held.len() != ID_LEN + 8 {
        return None;
    }
    let (id, issued_at) = held.split_at(ID_LEN);
    Some((
        id.try_into().ok()?,
        i64::from_be_bytes(issued_at.try_into().ok()?),
    ))
}

fn standing(issued_at: i64, now: i64) -> bool {
    (-AHEAD..LIFETIME).contains(&now.saturating_sub(issued_at))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_payload_reads_back_as_it_was_written() {
        let id = [7_u8; ID_LEN];
        assert_eq!(
            read_payload(&payload(&id, 1_790_000_000)),
            Some((id, 1_790_000_000))
        );
        let mut longer = payload(&id, 1);
        longer.push(0);
        assert_eq!(read_payload(&longer), None);
        assert_eq!(read_payload(&longer[..ID_LEN]), None);
    }

    #[test]
    fn a_token_stands_for_its_lifetime_and_no_longer() {
        let minted = 1_790_000_000;
        assert!(standing(minted, minted));
        assert!(standing(minted, minted + LIFETIME - 1));
        assert!(
            !standing(minted, minted + LIFETIME),
            "outlived its lifetime"
        );
        assert!(standing(minted + AHEAD, minted), "a clock a little ahead");
        assert!(
            !standing(minted + AHEAD + 1, minted),
            "minted further ahead than any clock may run"
        );
        assert!(!standing(i64::MIN, i64::MAX));
    }
}
