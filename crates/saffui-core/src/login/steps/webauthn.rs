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
use crate::login::throttle::Brake;
use crate::ports::crypto::{KeyCeremony, KeyRefusal};
use crate::ports::storage::UnitOfWork;
use crate::tenancy::RealmScope;

fn fail(detail: &str) -> Failure {
    Failure::with_detail(ErrorCode::CryptoUnavailable, detail)
}

/// Starts a proof by one of the keys of a person. Nothing is started for a
/// person who holds none.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when the ceremony cannot start,
/// or the storage failure.
pub(crate) async fn start_key_proof(
    app: &App,
    work: &mut dyn UnitOfWork,
    person: Uuid,
) -> Result<Option<KeyCeremony>, Failure> {
    let held: Vec<Vec<u8>> = work
        .list_security_keys(person)
        .await?
        .into_iter()
        .map(|key| key.record)
        .collect();
    if held.is_empty() {
        return Ok(None);
    }
    app.security_keys
        .start_proof(&held)
        .map(Some)
        .map_err(|_| fail("a proof by a security key cannot be started"))
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
/// guesses of the other steps. A proven key forgets the codes the person got
/// wrong.
///
/// # Errors
///
/// Returns [`ErrorCode::KeyRejected`] for every refusal above,
/// [`ErrorCode::HashingBusy`] when the address spent its attempts, or the
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
    brake.admit(work.as_mut(), now).await?;
    if brake.is_name_locked(work.as_mut(), now).await? {
        work.commit().await?;
        return Err(Failure::new(ErrorCode::KeyRejected));
    }
    let keys = work.list_security_keys(person.id).await?;
    let held: Vec<Vec<u8>> = keys.iter().map(|key| key.record.clone()).collect();
    let mut accepted = false;
    match app.security_keys.finish_proof(state, answer, &held) {
        // The counter the key moved is kept in place of the one this proof
        // was compared to and of no other: a copy of the key is told by a
        // counter that goes back, and two proofs compared to one counter are
        // not both believed.
        Ok(proof) => {
            if let Some(judged) = keys
                .iter()
                .find(|key| key.credential_id == proof.credential_id)
            {
                accepted = work
                    .record_key_use(judged, proof.record.as_deref(), now)
                    .await?;
            }
        }
        Err(KeyRefusal::Refused) => {}
        // Refused as any other answer, and said: the key may have been
        // copied, and whoever holds the realm should look.
        Err(KeyRefusal::CopySuspected) => {
            let suspected = json!({ "person_id": person.id.to_string() });
            record_event(app, work.as_mut(), EventKind::KeyCopySuspected, suspected).await?;
        }
        Err(KeyRefusal::Failed) => {
            return Err(fail("a proof by a security key cannot be finished"));
        }
    }
    if accepted {
        work.clear_code_attempts(person.id).await?;
    } else {
        brake.record_failure(work.as_mut(), now).await?;
    }
    work.commit().await?;
    if accepted {
        Ok(brake)
    } else {
        Err(Failure::new(ErrorCode::KeyRejected))
    }
}
