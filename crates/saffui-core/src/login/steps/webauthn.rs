//! The second step of signing in, for a person who holds a security key:
//! the key signs a challenge of the realm.

use std::net::IpAddr;

use serde_json::json;
use uuid::Uuid;

use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::directory::Person;
use crate::error::{ErrorCode, Failure};
use crate::login::device::{DeviceMark, find_known_browser, prove_device_marks};
use crate::login::steps::totp::MAX_CODE_FAILURES;
use crate::login::throttle::Brake;
use crate::ports::crypto::{KeyCeremony, KeyRefusal};
use crate::ports::storage::UnitOfWork;
use crate::tenancy::RealmScope;

fn fail_ceremony(detail: &str) -> Failure {
    Failure::with_detail(ErrorCode::CryptoUnavailable, detail)
}

/// What the keys of a person can be asked after their password.
pub(crate) enum KeyProofStart {
    NoKeyHeld,
    /// They hold keys, and keys are not served here.
    NotServed,
    Started(KeyCeremony),
}

/// Starts a proof by one of the keys of a person. Nothing is started for a
/// person who holds none, nor where keys are not served.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when the ceremony cannot start,
/// or the storage failure.
pub(crate) async fn start_key_proof(
    app: &App,
    work: &mut dyn UnitOfWork,
    person: Uuid,
) -> Result<KeyProofStart, Failure> {
    let held: Vec<Vec<u8>> = work
        .list_security_keys(person)
        .await?
        .into_iter()
        .map(|key| key.record)
        .collect();
    if held.is_empty() {
        return Ok(KeyProofStart::NoKeyHeld);
    }
    if !app.security_keys.are_served() {
        return Ok(KeyProofStart::NotServed);
    }
    app.security_keys
        .start_proof(&held)
        .map(KeyProofStart::Started)
        .map_err(|_| fail_ceremony("a proof by a security key cannot be started"))
}

/// Proves that a person holds one of their security keys, with the answer
/// of the key to the challenge kept in `state`, and gives back the brake the
/// answer was counted under, for the flow to clear.
///
/// The key is believed only if it is held when its answer comes. Its
/// counter is kept at once, in place of the record the proof was judged
/// against and of no other. An answer that proves nothing, a key whose
/// counter went back and a locked name are one refusal; a counter that went
/// back is also written in the chain; a refused answer is counted under the name, with the
/// guesses of the other steps, and not against its address: nothing is
/// hashed here. A proven key forgets the codes the person got wrong short of
/// a suspension, never a suspension: that one an administrator resumes.
///
/// # Errors
///
/// Returns [`ErrorCode::KeyRejected`] for every refusal above, or the
/// storage failure.
pub(crate) async fn verify_key(
    app: &App,
    scope: RealmScope,
    person: &Person,
    state: &[u8],
    answer: &serde_json::Value,
    caller: Option<IpAddr>,
    known_browsers: &[DeviceMark],
) -> Result<Brake, Failure> {
    let typed = person.username.as_str();
    let mut brake = Brake::of(app, scope, typed, caller)?;
    let now = app.now();
    let proven = prove_device_marks(app, scope, known_browsers, typed, now)?;

    let mut work = app.storage.begin(scope).await?;
    if let Some(device) = find_known_browser(work.as_mut(), &proven, Some(person), now).await? {
        brake.count_browser_apart(app, scope, typed, device)?;
    }
    if brake.is_name_locked(work.as_mut(), now).await? {
        work.commit().await?;
        return Err(Failure::new(ErrorCode::KeyRejected));
    }
    let keys = work.list_security_keys(person.id).await?;
    let held: Vec<Vec<u8>> = keys.iter().map(|key| key.record.clone()).collect();
    let refusal = match app.security_keys.finish_proof(state, answer, &held) {
        // The counter the key moved is kept in place of the one this proof
        // was compared to and of no other: a copy of the key is told by a
        // counter that goes back, and two proofs compared to one counter are
        // not both believed.
        Ok(proof) => {
            let judged = keys
                .iter()
                .find(|key| key.credential_id == proof.credential_id);
            let recorded = match judged {
                Some(judged) => {
                    work.record_key_use(judged, proof.record.as_deref(), now)
                        .await?
                }
                None => false,
            };
            (!recorded).then_some(KeyRefusal::Refused)
        }
        Err(KeyRefusal::Failed) => {
            return Err(fail_ceremony(
                "a proof by a security key cannot be finished",
            ));
        }
        Err(refusal) => Some(refusal),
    };
    if refusal.is_none() {
        work.clear_code_attempts_below(person.id, MAX_CODE_FAILURES)
            .await?;
    } else {
        brake.record_failure(work.as_mut(), now).await?;
    }
    // Refused as any other answer, and said after the counters, as a
    // suspension of codes is: the key may have been copied, and whoever
    // holds the realm should look.
    if refusal == Some(KeyRefusal::CopySuspected) {
        let suspected = json!({ "person_id": person.id.to_string() });
        record_event(app, work.as_mut(), EventKind::KeyCopySuspected, suspected).await?;
    }
    work.commit().await?;
    match refusal {
        None => Ok(brake),
        Some(_) => Err(Failure::new(ErrorCode::KeyRejected)),
    }
}
