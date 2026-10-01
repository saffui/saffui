//! The revocation of the certificates a credential's chain or a status list's
//! chain runs through, read off the revocation lists (RFC 5280 §5) a
//! scheduled pass keeps. A presentation never sends the server out to ask: a
//! list nobody has read yet is written down by the first certificate naming
//! it, and that certificate is refused until the pass has read the list.

use chrono::{DateTime, Duration, Utc};
use crypto::provider::{CryptoProvider, HashAlg};
use crypto::revocation::{ReadRevocations, UnreadRevocations, read_revocation_list};
use data_encoding::HEXLOWER;
use store::providers::realms::revocation_lists::{
    self, DueRevocationList, KeptRevocations, ListPlace,
};
use store::tenancy::UnitOfWork;

use super::certificates::ChainLink;
use super::presentation::{LEEWAY_SECONDS, Unanswerable};

/// The most lists a realm keeps.
const MOST_LISTS: i64 = 1_000;
/// How many lists of one realm one pass reads.
const MOST_LISTS_PER_PASS: i64 = 20;
/// The most serials one list revokes that this verifier keeps.
pub const MOST_REVOKED: usize = 200_000;
/// The longest address a list is read from.
const MOST_ADDRESS_CHARS: usize = 2048;
/// The longest serial a certificate carries (RFC 5280 §4.1.2.2), in octets.
const MOST_SERIAL_OCTETS: usize = 20;
/// How long a list may be relied on when its authority says nothing of the
/// next, and the longest whatever it says.
const RELIED_ON_UNSAID: Duration = Duration::hours(24);
const RELIED_ON_AT_MOST: Duration = Duration::days(7);
/// The bounds a list is read again within: half way to the time it may no
/// longer be relied on.
const REFRESH_AT_LEAST: Duration = Duration::minutes(15);
const REFRESH_AT_MOST: Duration = Duration::hours(24);
/// When a list that could not be read is tried again.
const READ_AGAIN_AFTER_FAILURE: Duration = Duration::minutes(5);
/// How often a certificate naming a list is written down, so the sweep knows
/// a list in use.
const CITED_NOTED_EVERY: Duration = Duration::days(1);

pub const REVOCATION_ELSEWHERE: &str =
    "a certificate of the chain publishes its revocation where this verifier does not read";
pub const REVOCATION_NOT_READ_YET: &str =
    "the revocation list of a certificate of the chain has not been read yet: it will be shortly";
pub const REVOCATION_LISTS_FULL: &str =
    "the realm already follows as many revocation lists as it keeps";
pub const REVOCATION_NEVER_READ: &str =
    "the revocation list of a certificate of the chain could not be read";
pub const REVOCATION_STALE: &str =
    "the revocation list of a certificate of the chain may no longer be relied on";
pub const CERTIFICATE_REVOKED: &str = "a certificate of the chain has been revoked";

pub const REVOCATION_UNFETCHED: &str = "nothing could be read at the revocation list's address";
pub const REVOCATION_UNREADABLE: &str = "the revocation list could not be read";
pub const REVOCATION_OF_ANOTHER_AUTHORITY: &str =
    "the revocation list is issued by another authority than the certificates naming it";
pub const REVOCATION_UNSIGNED: &str = "the revocation list is not signed by its authority";
pub const REVOCATION_NOT_FOR_LISTS: &str =
    "the revocation list's authority does not sign revocation lists";
pub const REVOCATION_CRITICAL: &str =
    "the revocation list says something critical this verifier does not read";
pub const REVOCATION_NOT_YET: &str = "the revocation list is not issued yet";
pub const REVOCATION_PAST_ITS_NEXT: &str = "the revocation list is past its next update";
pub const TOO_MANY_REVOKED: &str =
    "the revocation list revokes more certificates than this verifier keeps";
pub const REVOKED_SERIAL_TOO_LONG: &str =
    "the revocation list revokes a serial longer than a certificate carries";
pub const REVOCATION_OLDER: &str = "the revocation list served is older than the one kept";

/// What the lists kept say of the certificates of the chains of one answer,
/// each list under the issuer whose credential named it: a revocation when
/// there is one, the first refusal otherwise, once every list not read yet
/// has been written down for the pass.
pub async fn check_chains(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    chains: &[(String, Vec<ChainLink>)],
    now: DateTime<Utc>,
) -> Result<Result<(), &'static str>, Unanswerable> {
    let mut refusal = None;
    for (issuer_id, links) in chains {
        for link in links {
            match check_link(transaction, provider, issuer_id, link, now).await? {
                Ok(()) => {}
                Err(CERTIFICATE_REVOKED) => refusal = Some(CERTIFICATE_REVOKED),
                Err(why) => {
                    refusal.get_or_insert(why);
                }
            }
        }
    }
    Ok(refusal.map_or(Ok(()), Err))
}

async fn check_link(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    issuer_id: &str,
    link: &ChainLink,
    now: DateTime<Utc>,
) -> Result<Result<(), &'static str>, Unanswerable> {
    let Some(uri) = link.revocation.addresses.first() else {
        // A certificate that publishes nothing is held to its validity alone.
        return Ok(if link.revocation.unreadable {
            Err(REVOCATION_ELSEWHERE)
        } else {
            Ok(())
        });
    };
    if uri.chars().count() > MOST_ADDRESS_CHARS {
        return Ok(Err(REVOCATION_ELSEWHERE));
    }
    let authority_digest = HEXLOWER.encode(
        &provider
            .digest()
            .hash(HashAlg::Sha256, &link.authority)
            .map_err(|_| Unanswerable::Unwritable)?,
    );
    let place = ListPlace {
        issuer_id,
        uri,
        authority_digest: &authority_digest,
    };
    let Some(named) = revocation_lists::read_named(transaction, &place, &link.serial)
        .await
        .map_err(|_| Unanswerable::Unwritable)?
    else {
        let written =
            revocation_lists::write_down(transaction, &place, &link.authority, &now, MOST_LISTS)
                .await
                .map_err(|_| Unanswerable::Unwritable)?;
        return Ok(Err(if written {
            REVOCATION_NOT_READ_YET
        } else {
            REVOCATION_LISTS_FULL
        }));
    };
    if now - named.cited_at >= CITED_NOTED_EVERY {
        revocation_lists::note_cited(transaction, &place, &now)
            .await
            .map_err(|_| Unanswerable::Unwritable)?;
    }
    let Some(usable_until) = named.usable_until else {
        return Ok(Err(if named.failed {
            REVOCATION_NEVER_READ
        } else {
            REVOCATION_NOT_READ_YET
        }));
    };
    if usable_until <= now {
        return Ok(Err(REVOCATION_STALE));
    }
    Ok(if named.revokes {
        Err(CERTIFICATE_REVOKED)
    } else {
        Ok(())
    })
}

/// Claim the revocation lists of the realm this transaction is scoped to that
/// are due: none where the realm does not run the verifier.
pub async fn claim_due_revocation_lists(
    transaction: &UnitOfWork,
    now: DateTime<Utc>,
) -> Result<Vec<DueRevocationList>, ()> {
    if !crate::realm::feature::runs_for_realm(
        transaction,
        commons::feature::Feature::WalletVerifier,
    )
    .await
    {
        return Ok(Vec::new());
    }
    revocation_lists::claim_due(
        transaction,
        &now,
        &(now + READ_AGAIN_AFTER_FAILURE),
        MOST_LISTS_PER_PASS,
    )
    .await
    .map_err(|_| ())
}

/// Read a due list from what its address served, under the authority it was
/// written down for, or say why it was not.
pub fn read_due_revocation_list(
    due: &DueRevocationList,
    served: Option<&[u8]>,
    now: DateTime<Utc>,
) -> Result<ReadRevocations, &'static str> {
    let served = served.ok_or(REVOCATION_UNFETCHED)?;
    let read = read_revocation_list(served, &due.authority).map_err(say_unread)?;
    check_reading(&read, now)?;
    Ok(read)
}

/// Why a list served was not read under its authority, in the realm's words.
fn say_unread(why: UnreadRevocations) -> &'static str {
    match why {
        UnreadRevocations::Unreadable => REVOCATION_UNREADABLE,
        UnreadRevocations::AnotherAuthority => REVOCATION_OF_ANOTHER_AUTHORITY,
        UnreadRevocations::Unsigned => REVOCATION_UNSIGNED,
        UnreadRevocations::NotForRevocations => REVOCATION_NOT_FOR_LISTS,
        UnreadRevocations::Critical => REVOCATION_CRITICAL,
    }
}

/// Whether a list read is the current one, within the leeway two clocks may
/// disagree by, and revokes no more than this verifier keeps, by serials no
/// longer than a certificate carries.
fn check_reading(read: &ReadRevocations, now: DateTime<Utc>) -> Result<(), &'static str> {
    let leeway = LEEWAY_SECONDS;
    if read.this_update > now.timestamp() + leeway {
        return Err(REVOCATION_NOT_YET);
    }
    if read
        .next_update
        .is_some_and(|next| next + leeway <= now.timestamp())
    {
        return Err(REVOCATION_PAST_ITS_NEXT);
    }
    if read.revoked.len() > MOST_REVOKED {
        return Err(TOO_MANY_REVOKED);
    }
    // The schema keeps no longer one, and a list kept in part revokes less
    // than it says.
    if read
        .revoked
        .iter()
        .any(|serial| serial.len() > MOST_SERIAL_OCTETS)
    {
        return Err(REVOKED_SERIAL_TOO_LONG);
    }
    Ok(())
}

/// Until when a reading made `now` may be relied on, and when its list is due
/// again: relied on until its authority's next update, a day when it says
/// none, a week at most; due half way there within the bounds this server
/// sets, a tenth later at most by `drawn` so lists read together are not read
/// again together.
fn plan_revocation_reading(
    read: &ReadRevocations,
    now: DateTime<Utc>,
    drawn: u32,
) -> (DateTime<Utc>, DateTime<Utc>) {
    let said = read
        .next_update
        .and_then(|next| DateTime::from_timestamp(next, 0))
        .unwrap_or(now + RELIED_ON_UNSAID);
    let usable_until = said.min(now + RELIED_ON_AT_MOST);
    let refresh = ((usable_until - now) / 2).clamp(REFRESH_AT_LEAST, REFRESH_AT_MOST);
    let spread = i64::from(drawn) % (refresh.num_seconds() / 10 + 1);
    (usable_until, now + refresh + Duration::seconds(spread))
}

/// Keep a reading made `now`, planned as `plan_revocation_reading` says.
/// False when the authority issued the reading kept later than this one.
pub async fn keep_revocation_list(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    due: &DueRevocationList,
    read: &ReadRevocations,
    now: DateTime<Utc>,
) -> Result<bool, ()> {
    let mut drawn = [0u8; 4];
    provider.rand().fill(&mut drawn).map_err(|_| ())?;
    let (usable_until, due_at) = plan_revocation_reading(read, now, u32::from_be_bytes(drawn));
    let issued_at = DateTime::from_timestamp(read.this_update, 0).ok_or(())?;
    revocation_lists::keep_reading(
        transaction,
        &KeptRevocations {
            place: due.place(),
            revoked: &read.revoked,
            issued_at,
            read_at: now,
            usable_until,
            due_at,
        },
    )
    .await
    .map_err(|_| ())
}

/// Say why a list was not kept. The reading kept before stays, until it may
/// no longer be relied on.
pub async fn note_unread_revocation_list(
    transaction: &UnitOfWork,
    due: &DueRevocationList,
    why: &str,
) -> Result<(), ()> {
    revocation_lists::note_unread(transaction, &due.place(), why)
        .await
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::super::certificates::testing::{Certified, Hierarchy, NOW};
    use super::*;
    use crypto::jose::jwk::KeyPair;
    use crypto::provider::PrivateKey;
    use crypto::revocation::{Revoking, issue_revocation_list};

    fn read(next_update: Option<i64>) -> ReadRevocations {
        ReadRevocations {
            revoked: Vec::new(),
            this_update: 1_790_000_000,
            next_update,
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(NOW, 0).expect("a time")
    }

    /// The list `authority` issues an hour before `NOW` for the day, revoking
    /// `serials`.
    fn issued_by(authority: &Certified, serials: &[u8]) -> Vec<u8> {
        let serials: Vec<[u8; 1]> = serials.iter().map(|serial| [*serial]).collect();
        let revoked: Vec<&[u8]> = serials.iter().map(|serial| serial.as_slice()).collect();
        issue_revocation_list(&Revoking {
            issuer_certificate: &authority.certificate,
            issuer_key: &PrivateKey::from_der(authority.key.to_der_private_key()),
            revoked: &revoked,
            this_update: NOW - 3_600,
            next_update: NOW + 82_800,
        })
        .expect("a list issued by the crypto crate")
    }

    fn due_under(authority: &Certified) -> DueRevocationList {
        DueRevocationList {
            issuer_id: "i1".to_owned(),
            uri: "http://ca.example/issuing.crl".to_owned(),
            authority_digest: "aa".repeat(32),
            authority: authority.certificate.clone(),
            issued_at: None,
        }
    }

    /// A due list is read under the authority it was written down for, and
    /// under no other: what its address served is said not to be it in the
    /// realm's words.
    #[test]
    fn a_due_revocation_list_is_read_under_the_authority_it_was_written_down_for() {
        let held = Hierarchy::new();
        let stranger = Hierarchy::new();
        let due = due_under(&held.issuing);
        assert_eq!(
            read_due_revocation_list(&due, Some(&issued_by(&held.issuing, &[0x21, 0x22])), now()),
            Ok(ReadRevocations {
                revoked: vec![vec![0x21], vec![0x22]],
                this_update: NOW - 3_600,
                next_update: Some(NOW + 82_800),
            })
        );
        for (served, why) in [
            (None, REVOCATION_UNFETCHED),
            (Some(b"no list".to_vec()), REVOCATION_UNREADABLE),
            (
                Some(issued_by(&held.root, &[])),
                REVOCATION_OF_ANOTHER_AUTHORITY,
            ),
            (Some(issued_by(&stranger.issuing, &[])), REVOCATION_UNSIGNED),
        ] {
            assert_eq!(
                read_due_revocation_list(&due, served.as_deref(), now()),
                Err(why)
            );
        }
        assert_eq!(
            read_due_revocation_list(
                &due_under(&held.signer),
                Some(&issued_by(&held.signer, &[])),
                now()
            ),
            Err(REVOCATION_NOT_FOR_LISTS)
        );
    }

    #[test]
    fn why_a_list_was_not_read_is_said_in_the_realms_words() {
        for (why, said) in [
            (UnreadRevocations::Unreadable, REVOCATION_UNREADABLE),
            (
                UnreadRevocations::AnotherAuthority,
                REVOCATION_OF_ANOTHER_AUTHORITY,
            ),
            (UnreadRevocations::Unsigned, REVOCATION_UNSIGNED),
            (
                UnreadRevocations::NotForRevocations,
                REVOCATION_NOT_FOR_LISTS,
            ),
            (UnreadRevocations::Critical, REVOCATION_CRITICAL),
        ] {
            assert_eq!(say_unread(why), said);
        }
    }

    /// A list is the current one from its issue to its next update, within
    /// the leeway, and revokes no more than this verifier keeps.
    #[test]
    fn a_list_read_is_current_and_within_what_is_kept() {
        let reading = |this_update: i64, next_update: Option<i64>, revoked: usize| {
            check_reading(
                &ReadRevocations {
                    revoked: vec![vec![0x01]; revoked],
                    this_update: NOW + this_update,
                    next_update: next_update.map(|next| NOW + next),
                },
                now(),
            )
        };
        assert_eq!(reading(-3_600, Some(3_600), 0), Ok(()));
        assert_eq!(reading(LEEWAY_SECONDS, None, 0), Ok(()));
        assert_eq!(
            reading(LEEWAY_SECONDS + 1, None, 0),
            Err(REVOCATION_NOT_YET)
        );
        assert_eq!(reading(-3_600, Some(1 - LEEWAY_SECONDS), 0), Ok(()));
        assert_eq!(
            reading(-3_600, Some(-LEEWAY_SECONDS), 0),
            Err(REVOCATION_PAST_ITS_NEXT)
        );
        assert_eq!(reading(-3_600, None, MOST_REVOKED), Ok(()));
        assert_eq!(
            reading(-3_600, None, MOST_REVOKED + 1),
            Err(TOO_MANY_REVOKED)
        );
        for (octets, held) in [
            (MOST_SERIAL_OCTETS, Ok(())),
            (MOST_SERIAL_OCTETS + 1, Err(REVOKED_SERIAL_TOO_LONG)),
        ] {
            let read = ReadRevocations {
                revoked: vec![vec![0x01], vec![0x7f; octets]],
                this_update: NOW - 3_600,
                next_update: None,
            };
            assert_eq!(check_reading(&read, now()), held, "{octets}");
        }
    }

    /// A list is relied on until its authority's next update, a day when it
    /// says none, a week at most, and read again half way there within the
    /// bounds, a tenth later at most.
    #[test]
    fn a_list_is_relied_on_until_its_next_update_and_read_again_half_way() {
        let now = DateTime::from_timestamp(1_790_000_000, 0).expect("a time");
        for (next, usable, refresh) in [
            (
                Some(Duration::hours(10)),
                Duration::hours(10),
                Duration::hours(5),
            ),
            (None, Duration::hours(24), Duration::hours(12)),
            (
                Some(Duration::days(30)),
                Duration::days(7),
                Duration::hours(24),
            ),
            (
                Some(Duration::minutes(10)),
                Duration::minutes(10),
                Duration::minutes(15),
            ),
        ] {
            let said = next.map(|next| (now + next).timestamp());
            let (usable_until, due_at) = plan_revocation_reading(&read(said), now, 0);
            assert_eq!(
                (usable_until, due_at),
                (now + usable, now + refresh),
                "{next:?}"
            );
            let (_, spread) = plan_revocation_reading(&read(said), now, u32::MAX);
            assert!(
                spread >= due_at && spread <= due_at + refresh / 10,
                "{next:?}: {spread}"
            );
            assert_eq!(
                plan_revocation_reading(&read(said), now, 7).1,
                due_at + Duration::seconds(7),
                "{next:?}"
            );
        }
    }
}
