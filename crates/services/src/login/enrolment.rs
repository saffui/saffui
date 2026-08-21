//! Enrolling a credential the realm told this user to set up.
//!
//! Not an authenticator. A step proves who is answering; this adds something
//! for a later login to prove against, and it runs only once a flow has
//! admitted, so the credential is planted by its owner and never by whoever is
//! still guessing at a password.

use config::serving::PublicOrigin;
use deadpool_postgres::Transaction;
use models::entities::user::{RequiredAction, UserModel};
use serde_json::Value;
use store::providers::{users, webauthn};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CredentialID, PasskeyRegistration, RegisterPublicKeyCredential, Webauthn,
};

use crate::login::authenticator::{Challenge, relying_party};

/// The name the ceremony's state and answer travel under. Not an
/// authenticator's name, so the flow's own steps can never collide with it.
pub const CONFIGURE_WEBAUTHN: &str = "webauthn-register";

/// Where an enrolment stands after one round.
#[derive(Debug)]
pub enum Enrolment {
    /// Nothing was pending, or what was pending is now done.
    Settled,
    /// The caller is shown the creation options and answers next round.
    Asked(Challenge),
    /// The answer did not verify. The login fails with it: an admitted login
    /// that shrugged off its realm's instruction would admit the very state
    /// the realm said may not log in any more.
    Refused,
}

/// Run one round of whatever enrolment the realm requires of this user.
///
/// Actions this build has no ceremony for are left standing rather than
/// refused: a realm that asks for what a build cannot do keeps the debt
/// recorded, and blocking every login on it would lock the realm out of
/// fixing its own configuration.
pub async fn required(
    transaction: &Transaction<'_>,
    origin: &PublicOrigin,
    subject: &UserModel,
    attestation: Option<&str>,
    remembered: &Value,
) -> Enrolment {
    let pending = subject
        .required_actions
        .as_deref()
        .unwrap_or_default()
        .contains(&RequiredAction::ConfigureWebauthn);
    if !pending {
        return Enrolment::Settled;
    }
    let Ok(party) = relying_party(origin) else {
        return Enrolment::Refused;
    };
    match (attestation, remembered.get(CONFIGURE_WEBAUTHN)) {
        // Both halves in hand: verify, keep, and strike the instruction.
        (Some(answered), Some(state)) => {
            finish(transaction, &party, subject, answered, state).await
        }
        // No state yet, so nothing to verify against: issue the challenge.
        _ => start(transaction, &party, subject).await,
    }
}

/// The start leg: creation options out, registration state remembered.
async fn start(transaction: &Transaction<'_>, party: &Webauthn, subject: &UserModel) -> Enrolment {
    // Everything already enrolled is excluded, so a browser offers the user
    // their unregistered keys rather than re-registering one it finds first.
    let Ok(held) = webauthn::of_user(transaction, &subject.user_id).await else {
        return Enrolment::Refused;
    };
    let exclude: Vec<CredentialID> = held
        .into_iter()
        .map(|credential| CredentialID::from(credential.credential_id))
        .collect();

    let started = party.start_passkey_registration(
        // A stable function of the user, because the handle is how a browser
        // recognises "this account already has a key on this device".
        Uuid::new_v5(&Uuid::NAMESPACE_OID, subject.user_id.as_bytes()),
        &subject.user_name,
        &subject.user_name,
        (!exclude.is_empty()).then_some(exclude),
    );
    let Ok((creation, state)) = started else {
        return Enrolment::Refused;
    };
    let (Ok(shown), Ok(remembered)) = (
        serde_json::to_value(&creation),
        serde_json::to_value(&state),
    ) else {
        return Enrolment::Refused;
    };
    Enrolment::Asked(Challenge { shown, remembered })
}

/// The finish leg: the attestation against the remembered state, the passkey
/// into the store, the instruction struck.
async fn finish(
    transaction: &Transaction<'_>,
    party: &Webauthn,
    subject: &UserModel,
    answered: &str,
    state: &Value,
) -> Enrolment {
    let Ok(state) = serde_json::from_value::<PasskeyRegistration>(state.clone()) else {
        return Enrolment::Refused;
    };
    let Ok(attested) = serde_json::from_str::<RegisterPublicKeyCredential>(answered) else {
        return Enrolment::Refused;
    };
    let Ok(passkey) = party.finish_passkey_registration(&attested, &state) else {
        return Enrolment::Refused;
    };

    let Ok(stored) = serde_json::to_value(&passkey) else {
        return Enrolment::Refused;
    };
    let enrolled = webauthn::enrol(
        transaction,
        &webauthn::EnrolledCredential {
            credential_id: passkey.cred_id().as_ref().to_vec(),
            user_id: subject.user_id.clone(),
            label: String::new(),
            passkey: stored,
            // Zero rather than the device's own first value. The store's
            // counter is the high-water mark of *use*, and this key has not
            // been used yet.
            sign_count: 0,
            enrolled_at: None,
            last_used_at: None,
        },
    )
    .await;
    if enrolled.is_err() {
        return Enrolment::Refused;
    }

    // Struck only once the credential is in. The other order leaves a user
    // whose instruction is gone and whose key was never kept.
    match users::clear_required_action(
        transaction,
        &subject.user_id,
        RequiredAction::ConfigureWebauthn,
    )
    .await
    {
        Ok(true) => Enrolment::Settled,
        _ => Enrolment::Refused,
    }
}
