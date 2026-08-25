use config::serving::PublicOrigin;
use crypto::otp::totp::{TotpParams, totp_verify_step};
use crypto::provider::{CryptoProvider, HashAlg};
use data_encoding::{BASE32_NOPAD, HEXLOWER};
use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::credentials::{
    CredentialModel, CredentialSecret, OtpAlgorithm, OtpParameters,
};
use models::entities::realm::RealmModel;
use models::entities::user::{RequiredAction, UserModel};
use secrecy::SecretBox;
use serde_json::{Value, json};
use store::providers::{credentials, one_time_tokens, users, webauthn};
use store::tenancy::TenantContext;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CredentialID, PasskeyRegistration, RegisterPublicKeyCredential, Webauthn,
};

use crate::login::authenticator::{Challenge, redacted, relying_party};

/// The names the ceremonies' state and answers travel under. Not an
/// authenticator's name, so the flow's own steps can never collide with them.
pub const CONFIGURE_WEBAUTHN: &str = "webauthn-register";
pub const CONFIGURE_TOTP: &str = "totp-register";
pub const VERIFY_EMAIL: &str = "verify-email";

/// How long a mailed verification link lasts, and how soon another may be
/// asked for. The same reasoning as the sign-in link: without a window a
/// caller loops the login and this server floods a mailbox on somebody's
/// behalf.
const VERIFY_LIFESPAN: i64 = 900;
const VERIFY_COOLDOWN: i64 = 60;

/// What a fresh authenticator app is enrolled with: RFC 6238's defaults, which
/// every app reads without being told.
const TOTP_DIGITS: u32 = 6;
const TOTP_PERIOD: u64 = 30;
const TOTP_SECRET_BYTES: usize = 20;
const TOTP_WINDOW: u32 = 1;

/// What the caller sent for whichever ceremony is running.
#[derive(Debug, Default, Clone, Copy)]
pub struct Answers<'a> {
    pub attestation: Option<&'a str>,
    pub code: Option<&'a str>,
    /// What a mailed address-verification link carried back.
    pub verified_address: Option<&'a str>,
}

/// Where an enrolment stands after one round.
#[derive(Debug)]
pub enum Enrolment {
    /// Nothing was pending, or what was pending is now done.
    Settled,
    /// The caller is shown what the named ceremony issued and answers next
    /// round.
    Asked {
        named: &'static str,
        challenge: Challenge,
        /// A message this round produced, sent once the caller has committed.
        sending: Option<Box<crate::messaging::Outgoing>>,
    },
    /// The answer did not verify. The login fails with it: an admitted login
    /// that shrugged off its realm's instruction would admit the very state
    /// the realm said may not log in any more.
    Refused,
}

/// Run one round of whatever enrolment the realm requires of this user, one
/// ceremony at a time: a key first, then an authenticator app.
///
/// Actions this build has no ceremony for are left standing rather than
/// refused: a realm that asks for what a build cannot do keeps the debt
/// recorded, and blocking every login on it would lock the realm out of
/// fixing its own configuration.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one round"
)]
pub async fn required(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &TenantContext,
    realm: &RealmModel,
    origin: &PublicOrigin,
    subject: &UserModel,
    answers: Answers<'_>,
    remembered: &Value,
    // What a mailed ceremony needs. Absent where the realm requires none.
    posting: Option<crate::login::authenticator::Posting<'_>>,
) -> Enrolment {
    let pending = |action: RequiredAction| {
        subject
            .required_actions
            .as_deref()
            .unwrap_or_default()
            .contains(&action)
    };
    if pending(RequiredAction::ConfigureWebauthn) {
        let Ok(party) = relying_party(origin) else {
            return Enrolment::Refused;
        };
        let round = match (answers.attestation, remembered.get(CONFIGURE_WEBAUTHN)) {
            // Both halves in hand: verify, keep, and strike the instruction.
            (Some(answered), Some(state)) => {
                finish(transaction, &party, subject, answered, state).await
            }
            // No state yet, so nothing to verify against: issue the challenge.
            _ => start(transaction, &party, subject).await,
        };
        if !matches!(round, Enrolment::Settled) {
            return round;
        }
    }
    if pending(RequiredAction::ConfigureTotp) {
        return match (answers.code, remembered.get(CONFIGURE_TOTP)) {
            (Some(typed), Some(state)) => {
                finish_totp(transaction, provider, tenant, subject, typed, state).await
            }
            _ => start_totp(provider, realm, subject),
        };
    }
    if pending(RequiredAction::VerifyEmail) {
        return match answers.verified_address {
            Some(followed) => {
                let Some(posting) = posting else {
                    return Enrolment::Refused;
                };
                finish_verify(
                    transaction,
                    provider,
                    subject,
                    posting.auth_session_id,
                    followed,
                )
                .await
            }
            None => start_verify(transaction, provider, origin, subject, posting).await,
        };
    }
    Enrolment::Settled
}

/// The start leg of an authenticator app: a fresh secret, shown once as the
/// URI an app scans and as text for the one that cannot, and remembered.
fn start_totp(provider: &dyn CryptoProvider, realm: &RealmModel, subject: &UserModel) -> Enrolment {
    let mut secret = vec![0u8; TOTP_SECRET_BYTES];
    if provider.rand().fill(&mut secret).is_err() {
        return Enrolment::Refused;
    }
    let encoded = BASE32_NOPAD.encode(&secret);
    let issuer = if realm.display_name.is_empty() {
        &realm.name
    } else {
        &realm.display_name
    };
    let otpauth = format!(
        "otpauth://totp/{issuer}:{account}?secret={encoded}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}",
        issuer = percent(issuer),
        account = percent(&subject.user_name),
    );
    Enrolment::Asked {
        named: CONFIGURE_TOTP,
        challenge: Challenge {
            shown: json!({ "secret": encoded, "otpauth": otpauth }),
            remembered: json!({ "secret": encoded }),
        },
        sending: None,
    }
}

/// The finish leg: the code against the remembered secret, the credential
/// into the store with that step spent, the instruction struck.
async fn finish_totp(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &TenantContext,
    subject: &UserModel,
    typed: &str,
    state: &Value,
) -> Enrolment {
    let Some(encoded) = state.get("secret").and_then(Value::as_str) else {
        return Enrolment::Refused;
    };
    let Ok(secret) = BASE32_NOPAD.decode(encoded.as_bytes()) else {
        return Enrolment::Refused;
    };
    let Ok(code) = typed.split_whitespace().collect::<String>().parse::<u32>() else {
        return Enrolment::Refused;
    };
    let params = TotpParams {
        period: TOTP_PERIOD,
        digits: TOTP_DIGITS,
        hash: HashAlg::Sha1,
    };
    let secret = SecretBox::new(Box::new(secret));
    let Ok(Some(step)) = totp_verify_step(provider.hmac(), &secret, code, params, TOTP_WINDOW)
    else {
        return Enrolment::Refused;
    };

    let Ok(parameters) = OtpParameters::totp(TOTP_DIGITS, TOTP_PERIOD) else {
        return Enrolment::Refused;
    };
    let mut drawn = [0u8; 16];
    if provider.rand().fill(&mut drawn).is_err() {
        return Enrolment::Refused;
    }
    let credential_id = HEXLOWER.encode(&drawn);
    let credential = CredentialModel::otp(
        credential_id.clone(),
        tenant.realm_id.clone(),
        subject.user_id.clone(),
        CredentialSecret::new(encoded.to_owned()),
        OtpAlgorithm::Sha1,
        parameters,
        AuditableModel::from_creator(tenant.tenant.clone(), subject.user_id.clone()),
    );
    if credentials::create(transaction, &credential).await.is_err() {
        return Enrolment::Refused;
    }
    // The code that proved the app is spent: a login must not accept it again.
    if !matches!(
        credentials::consume_otp_step(transaction, &credential_id, step as i64).await,
        Ok(true)
    ) {
        return Enrolment::Refused;
    }
    match users::clear_required_action(transaction, &subject.user_id, RequiredAction::ConfigureTotp)
        .await
    {
        Ok(true) => Enrolment::Settled,
        _ => Enrolment::Refused,
    }
}

/// RFC 3986 §2.3: the unreserved set kept, everything else escaped.
fn percent(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
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
    Enrolment::Asked {
        named: CONFIGURE_WEBAUTHN,
        challenge: Challenge { shown, remembered },
        sending: None,
    }
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

/// Mail a link, or say a recent one is still good for it.
async fn start_verify(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    origin: &PublicOrigin,
    subject: &UserModel,
    posting: Option<crate::login::authenticator::Posting<'_>>,
) -> Enrolment {
    // Nothing to send to, or nothing to send with, is a ceremony that cannot
    // run. Left standing like any other this build cannot perform: the debt
    // stays recorded, and refusing here would lock out every person in a realm
    // whose administrator asked for this and configured no mail.
    if subject.email.is_empty() {
        return Enrolment::Settled;
    }
    let Some(posting) = posting else {
        return Enrolment::Settled;
    };
    let Some(settings) = posting.mail.filter(|_| posting.can_send) else {
        return Enrolment::Settled;
    };

    let shown = json!({ "sent_to": redacted(&subject.email) });
    let Ok(recent) =
        one_time_tokens::minted_at(transaction, &subject.user_id, VERIFY_EMAIL, posting.now).await
    else {
        return Enrolment::Refused;
    };
    if recent.is_some_and(|sent| posting.now - sent < chrono::Duration::seconds(VERIFY_COOLDOWN)) {
        return Enrolment::Asked {
            named: VERIFY_EMAIL,
            challenge: Challenge {
                shown,
                remembered: Value::Null,
            },
            sending: None,
        };
    }

    let mut drawn = [0u8; 32];
    if provider.rand().fill(&mut drawn).is_err() {
        return Enrolment::Refused;
    }
    let token = data_encoding::BASE64URL_NOPAD.encode(&drawn);
    // Bound to this login, so a link mailed to a person cannot finish a login
    // somebody else started.
    if one_time_tokens::mint(
        transaction,
        provider.digest(),
        one_time_tokens::Owner {
            tenant: &subject.metadata.tenant,
            realm_id: &subject.realm_id,
            user_id: &subject.user_id,
            purpose: VERIFY_EMAIL,
        },
        &token,
        Some(posting.auth_session_id),
        posting.now + chrono::Duration::seconds(VERIFY_LIFESPAN),
        posting.now,
    )
    .await
    .is_err()
    {
        return Enrolment::Refused;
    }

    let link = format!(
        "{}/realms/{}/protocol/openid-connect/login?verify_email={token}",
        origin.as_str(),
        posting.realm_name,
    );
    Enrolment::Asked {
        named: VERIFY_EMAIL,
        challenge: Challenge {
            shown,
            remembered: Value::Null,
        },
        sending: Some(Box::new(crate::messaging::Outgoing {
            settings: settings.duplicate(),
            message: crate::messaging::Message {
                to: subject.email.clone(),
                subject: "Confirm your address".to_owned(),
                body: format!(
                    "Confirm this address to finish signing in. The link works once, and \
                     only in the browser you started from.\n\n{link}\n"
                ),
            },
            about: crate::messaging::About {
                user_id: subject.user_id.clone(),
                purpose: VERIFY_EMAIL.to_owned(),
            },
        })),
    }
}

/// Spend what came back, and take the instruction off.
async fn finish_verify(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    subject: &UserModel,
    auth_session_id: &str,
    followed: &str,
) -> Enrolment {
    // Bound to the login presenting it: a link mailed to a person does not
    // finish a login somebody else started.
    match one_time_tokens::spend(
        transaction,
        provider.digest(),
        &subject.user_id,
        VERIFY_EMAIL,
        followed,
        Some(auth_session_id),
        chrono::Utc::now(),
    )
    .await
    {
        Ok(one_time_tokens::Spent::Yes) => {}
        // Followed somewhere other than where the login began. The instruction
        // stands and the login waits, so the person can go back and follow it
        // in the browser that asked.
        Ok(one_time_tokens::Spent::ElsewhereBound) => {
            return Enrolment::Asked {
                named: VERIFY_EMAIL,
                challenge: Challenge {
                    shown: json!({ "wrong_browser": true }),
                    remembered: Value::Null,
                },
                sending: None,
            };
        }
        _ => return Enrolment::Refused,
    }
    if users::set_email_verified(transaction, &subject.user_id, true)
        .await
        .is_err()
    {
        return Enrolment::Refused;
    }
    match users::clear_required_action(transaction, &subject.user_id, RequiredAction::VerifyEmail)
        .await
    {
        Ok(_) => Enrolment::Settled,
        Err(_) => Enrolment::Refused,
    }
}
