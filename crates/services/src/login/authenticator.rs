use std::str::FromStr;

use chrono::{DateTime, Utc};
use config::serving::PublicOrigin;
use crypto::otp::totp::{TotpParams, totp_verify_step};
use crypto::password::StoredPassword;
use crypto::password::migration::{burn_verification_time, verify_and_plan};
use crypto::provider::CryptoProvider;
use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use deadpool_postgres::Transaction;
use models::entities::credentials::{CredentialType, OtpCredentialData, OtpParameters};
use models::entities::mail::MailSettings;
use models::entities::realm::RealmModel;
use models::entities::user::UserModel;
use secrecy::{ExposeSecret, SecretBox};
use store::providers::{credentials, one_time_tokens};

use crate::messaging::{Message, Outgoing};
use url::Url;
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PublicKeyCredential};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::login::step::Outcome;

/// What a step answered, and what it needs shown before it can answer again.
///
/// Two values rather than one, because the fold is pure and a challenge is not:
/// it is issued by a step, carries state that has to be kept between two
/// requests, and is the caller's to render. Folding it into [`Outcome`] would
/// put credential material into the part that decides who is let in.
#[derive(Debug)]
pub struct Answered {
    pub outcome: Outcome,
    /// What the caller must be shown, when the step issued one. A password step
    /// issues nothing: the form is the caller's and the server has no state in
    /// it. A step that must hand out a nonce and remember it does.
    pub asks: Option<Challenge>,
    /// A message the step produced, to be sent once the caller has committed.
    /// Never sent here: a transaction held open across a conversation with
    /// somebody else's mail server is a pooled connection taken from every
    /// other request.
    pub sending: Option<Outgoing>,
}

impl Answered {
    /// A step that needs nothing shown.
    pub fn plain(outcome: Outcome) -> Self {
        Answered {
            outcome,
            asks: None,
            sending: None,
        }
    }
}

/// Something the caller is shown, and what the server has to remember about it.
///
/// The two travel together because they are one act. A challenge handed out and
/// not remembered is one nothing can verify against, and remembering one that
/// was never handed out leaves state nobody will ever answer.
#[derive(Debug)]
pub struct Challenge {
    /// What the caller renders or hands to a device, as it goes on the wire.
    pub shown: serde_json::Value,
    /// What verifying the answer will need, kept in the login's notes under the
    /// authenticator's own name so two steps cannot overwrite each other.
    pub remembered: serde_json::Value,
}

/// The authenticators this build knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authenticator {
    /// A username and a password, against the credential the realm stores.
    Password,
    /// A time-based code, against the shared secret the realm stores.
    Totp,
    /// A key the user holds, answering a challenge this server issued.
    Webauthn,
    /// A link mailed to the address the realm holds, followed back here.
    MagicLink,
}

/// A name no build knows. Refused where a flow is read, so a realm cannot be
/// left with a step nothing runs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("no authenticator is named '{0}'")]
pub struct Unknown(pub String);

impl FromStr for Authenticator {
    type Err = Unknown;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "password" => Ok(Self::Password),
            "totp" => Ok(Self::Totp),
            "webauthn" => Ok(Self::Webauthn),
            "magic-link" => Ok(Self::MagicLink),
            other => Err(Unknown(other.to_owned())),
        }
    }
}

impl Authenticator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Webauthn => "webauthn",
            Self::MagicLink => "magic-link",
        }
    }

    /// The authentication context this one reaches.
    ///
    /// Not the same vocabulary as the name, and deliberately. A flow names an
    /// authenticator, an `acr` names a *class* of authentication, and a realm
    /// maps the class rather than the mechanism: a second factor is a second
    /// factor whether it arrives by code, by key or by push, and a client asking
    /// for one should not have to name which the realm happens to run.
    pub fn context(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Totp => "mfa",
            // A key is a second factor like a code is. What the realm maps is
            // the class, not which device the flow happened to run.
            Self::Webauthn => "mfa",
            // One factor, like a password. What the class names is how many
            // things were proved, not which of them was.
            Self::MagicLink => "password",
        }
    }
}

/// What a caller answered a challenge with.
///
/// Not cloneable, so an answer is moved to the one place that reads it rather
/// than left in a second copy nothing tracks.
#[derive(Debug)]
pub enum Answer {
    Password(SecretBox<String>),
    /// The digits typed, as typed. Parsed where it is verified, so a code with
    /// the spaces an app renders is the code the user read.
    Totp(String),
    /// The credential the browser handed back, as the JSON it produced.
    Webauthn(String),
    /// The value carried by a link that was followed back here.
    MagicLink(SecretBox<String>),
}

/// Say whether an answer satisfies one authenticator.
///
/// The subject is resolved before this: an authenticator says whether the
/// answer is right, not who is answering.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one step"
)]
pub async fn verify_answer(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm: &RealmModel,
    origin: &PublicOrigin,
    subject: Option<&UserModel>,
    authenticator: Authenticator,
    answers: &[Answer],
    // What the previous round of this same authenticator issued. A step that
    // hands out a challenge verifies against what it remembered, and one that
    // issues nothing never looks.
    remembered: Option<&serde_json::Value>,
    // Where a mailed link points back to, and how this realm sends. Absent
    // where no step needs them.
    posting: Option<Posting<'_>>,
) -> Answered {
    match authenticator {
        Authenticator::Password => {
            Answered::plain(password(transaction, provider, realm, subject, answers).await)
        }
        Authenticator::Totp => Answered::plain(totp(transaction, provider, subject, answers).await),
        Authenticator::Webauthn => {
            webauthn(transaction, origin, subject, answers, remembered).await
        }
        Authenticator::MagicLink => {
            magic_link(transaction, provider, origin, subject, answers, posting).await
        }
    }
}

/// What a mailed step needs beyond the answer: which login the link finishes,
/// and how this realm sends.
#[derive(Clone, Copy)]
pub struct Posting<'a> {
    pub auth_session_id: &'a str,
    pub realm_name: &'a str,
    pub mail: Option<&'a MailSettings>,
    /// Whether anything at all carries a message out of this deployment. Apart
    /// from the settings: a realm can name a server while the deployment has
    /// chosen no way to reach one.
    pub can_send: bool,
    pub now: DateTime<Utc>,
}

/// How long a mailed link stays good.
const LINK_LIFESPAN: i64 = 600;

/// How soon another may be asked for. Without it a caller loops the endpoint
/// and this server floods somebody else's mailbox on their behalf.
const LINK_COOLDOWN: i64 = 60;

const MAGIC_LINK: &str = "magic-link";

/// Issue a link, or spend one that was followed back.
///
/// The link is bound to this login, so one sent to a person cannot finish a
/// login somebody else started. It is never remembered in the notes: the token
/// row is the state, and a copy in a column a challenge is built from is a copy
/// that reaches whoever reads the challenge.
async fn magic_link(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    origin: &PublicOrigin,
    subject: Option<&UserModel>,
    answers: &[Answer],
    posting: Option<Posting<'_>>,
) -> Answered {
    let Some(posting) = posting else {
        return Answered::plain(Outcome::Failed);
    };
    // Resolved before this step, and a step that cannot name whose mailbox to
    // send to has nothing to do. Refused rather than skipped: a flow reaching
    // here with nobody is a flow that would otherwise admit nobody in.
    let Some(subject) = subject else {
        return Answered::plain(Outcome::Failed);
    };

    if let Some(Answer::MagicLink(presented)) =
        of_kind(answers, |answer| matches!(answer, Answer::MagicLink(_)))
    {
        let spent = one_time_tokens::spend(
            transaction,
            provider.digest(),
            &subject.user_id,
            MAGIC_LINK,
            presented.expose_secret(),
            Some(posting.auth_session_id),
            posting.now,
        )
        .await;
        return Answered::plain(match spent {
            Ok(true) => Outcome::Passed,
            Ok(false) => Outcome::Failed,
            Err(_) => Outcome::Failed,
        });
    }

    // Both halves, and before anything is minted. A realm that names no server
    // cannot be sent from, and neither can a deployment that chose no way to
    // reach one. Failed rather than pending either way: a login left waiting on
    // a message nothing will send is one that never ends, and a token minted
    // for it is a credential nobody will ever be told.
    let Some(settings) = posting.mail.filter(|_| posting.can_send) else {
        tracing::warn!("a login asked for a mailed link and nothing here can send one");
        return Answered::plain(Outcome::Failed);
    };
    if subject.email.trim().is_empty() {
        return Answered::plain(Outcome::Failed);
    }

    // One in flight is enough. Asking again inside the window is answered the
    // way the first was, so nothing is told apart by whether a mail went out.
    //
    // A store that cannot answer holds the message. A guard that treats "I do
    // not know" as "none was sent" is one a caller floods a mailbox through by
    // making the read fail.
    let Ok(recent) =
        one_time_tokens::minted_at(transaction, &subject.user_id, MAGIC_LINK, posting.now).await
    else {
        return Answered::plain(Outcome::Failed);
    };
    if let Some(sent) = recent
        && posting.now - sent < chrono::Duration::seconds(LINK_COOLDOWN)
    {
        return Answered {
            outcome: Outcome::Pending,
            asks: Some(Challenge {
                shown: serde_json::json!({ "sent_to": redacted(&subject.email) }),
                remembered: serde_json::Value::Null,
            }),
            sending: None,
        };
    }

    let mut drawn = [0u8; 32];
    if provider.rand().fill(&mut drawn).is_err() {
        return Answered::plain(Outcome::Failed);
    }
    let token = BASE64URL_NOPAD.encode(&drawn);
    let minted = one_time_tokens::mint(
        transaction,
        provider.digest(),
        one_time_tokens::Owner {
            tenant: &subject.metadata.tenant,
            realm_id: &subject.realm_id,
            user_id: &subject.user_id,
            purpose: MAGIC_LINK,
        },
        &token,
        Some(posting.auth_session_id),
        posting.now + chrono::Duration::seconds(LINK_LIFESPAN),
        posting.now,
    )
    .await;
    if minted.is_err() {
        return Answered::plain(Outcome::Failed);
    }

    let link = format!(
        "{}/realms/{}/protocol/openid-connect/login?magic_link={token}",
        origin.as_str(),
        posting.realm_name,
    );
    Answered {
        outcome: Outcome::Pending,
        // Nothing of the link. What is shown says a message went out, and the
        // link is in the message.
        asks: Some(Challenge {
            shown: serde_json::json!({ "sent_to": redacted(&subject.email) }),
            remembered: serde_json::Value::Null,
        }),
        sending: Some(Outgoing {
            settings: settings.duplicate(),
            message: Message {
                to: subject.email.clone(),
                subject: "Your sign-in link".to_owned(),
                body: format!(
                    "Follow this link to sign in. It works once, and only in the browser \
                     you started from.\n\n{link}\n"
                ),
            },
            about: crate::messaging::About {
                user_id: subject.user_id.clone(),
                purpose: MAGIC_LINK.to_owned(),
            },
        }),
    }
}

/// Enough of an address for the person to recognise their own, and not enough
/// for whoever else is looking at the screen to read it.
fn redacted(email: &str) -> String {
    match email.split_once('@') {
        Some((name, domain)) => {
            let kept: String = name.chars().take(2).collect();
            format!("{kept}\u{2026}@{domain}")
        }
        None => "\u{2026}".to_owned(),
    }
}

/// The one answer a step understands, of everything the caller sent.
///
/// A flow runs every step against what it was given, so a login resumed with a
/// second factor still has to satisfy the first. Handing each step the whole set
/// and letting it take its own kind is what makes that possible without the
/// runner remembering which steps already passed.
fn of_kind(answers: &[Answer], wanted: fn(&Answer) -> bool) -> Option<&Answer> {
    answers.iter().find(|answer| wanted(answer))
}

async fn password(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm: &RealmModel,
    subject: Option<&UserModel>,
    answers: &[Answer],
) -> Outcome {
    let Some(Answer::Password(offered)) =
        of_kind(answers, |answer| matches!(answer, Answer::Password(_)))
    else {
        // Nothing was answered, so the caller is asked. A step with no answer
        // has not failed; it has not run.
        return Outcome::Pending;
    };

    let cost = realm.password_policy.as_ref().map(|policy| policy.hashing);

    let Some(subject) = subject else {
        // No such user. The same work is done anyway, because a login that
        // answers faster for an unknown name than for a known one publishes
        // which names exist.
        burn(provider, offered, cost);
        return Outcome::Failed;
    };

    let held =
        credentials::load_for_user_of_type(transaction, &subject.user_id, CredentialType::Password)
            .await;
    let Ok(held) = held else {
        return Outcome::Failed;
    };
    let Some(credential) = held.into_iter().next() else {
        burn(provider, offered, cost);
        return Outcome::Failed;
    };

    // The column holds a PHC string. A credential in a shape this build does
    // not recognise is refused rather than read as the nearest thing it has.
    let Ok(stored) = StoredPassword::Argon2id {
        encoded: credential.secret.expose().to_owned(),
    }
    .to_legacy_hash() else {
        return Outcome::Failed;
    };

    match verify_and_plan(provider, offered, &stored) {
        Ok(plan) if plan.valid => Outcome::Passed,
        _ => Outcome::Failed,
    }
}

/// Spend what a verification would have spent.
fn burn(
    provider: &dyn CryptoProvider,
    offered: &SecretBox<String>,
    cost: Option<crypto::provider::Argon2Params>,
) {
    if let Some(cost) = cost {
        burn_verification_time(provider, offered, cost);
    }
}

/// How far either side of now a code is still accepted.
///
/// One step, which is thirty seconds at the usual period. It buys tolerance for
/// a clock that drifts and a user who types slowly, and it costs acceptance
/// width: a code stays good for `period * (2 * WINDOW + 1)`, ninety seconds
/// here, which is exactly why the step it was accepted at has to be spent.
const WINDOW: u32 = 1;

/// A time-based code, against what the realm stores.
async fn totp(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    subject: Option<&UserModel>,
    answers: &[Answer],
) -> Outcome {
    let Some(Answer::Totp(typed)) = of_kind(answers, |answer| matches!(answer, Answer::Totp(_)))
    else {
        // Nothing answered, so the caller is asked. A step with no answer has
        // not failed; it has not run.
        return Outcome::Pending;
    };
    // No decoy here. A second factor runs only once a first has said who this
    // is, so the name is already known to whoever is asking and the timing tells
    // them nothing they did not have.
    let Some(subject) = subject else {
        return Outcome::Failed;
    };
    let Some(code) = parse_code(typed) else {
        return Outcome::Failed;
    };

    let held =
        credentials::load_for_user_of_type(transaction, &subject.user_id, CredentialType::Totp)
            .await;
    let Ok(held) = held else {
        return Outcome::Failed;
    };
    let Some(credential) = held.into_iter().next() else {
        return Outcome::Failed;
    };
    let Some(OtpCredentialData {
        algorithm,
        parameters: OtpParameters::Totp { digits, period },
    }) = credential.otp
    else {
        // A row that says `totp` and holds a counter is one no verifier reads,
        // and reading it as the nearest thing it has is how a credential of one
        // kind gets checked as another.
        return Outcome::Failed;
    };

    let Ok(secret) = BASE32_NOPAD.decode(credential.secret.expose().as_bytes()) else {
        return Outcome::Failed;
    };
    let secret = SecretBox::new(Box::new(secret));

    let step = totp_verify_step(
        provider.hmac(),
        &secret,
        code,
        TotpParams {
            period,
            digits,
            hash: algorithm.hash(),
        },
        WINDOW,
    );
    let Ok(Some(step)) = step else {
        return Outcome::Failed;
    };

    // Spent before the step is called a success. RFC 6238 §5.2 refuses a code
    // presented twice, and a failure to record one hands out a login whose code
    // stays replayable for the rest of the window.
    match credentials::consume_otp_step(transaction, &credential.credential_id, step as i64).await {
        Ok(true) => Outcome::Passed,
        _ => Outcome::Failed,
    }
}

/// The digits, tolerating the spaces an authenticator app renders.
fn parse_code(typed: &str) -> Option<u32> {
    typed.split_whitespace().collect::<String>().parse().ok()
}

/// A key the user holds, answering a challenge this server issued.
///
/// Two rounds, and both are here. Nothing answered means the challenge is
/// issued and remembered; an answer is checked against what was remembered. A
/// challenge verified against anything else is one an attacker can supply both
/// halves of.
async fn webauthn(
    transaction: &Transaction<'_>,
    origin: &PublicOrigin,
    subject: Option<&UserModel>,
    answers: &[Answer],
    remembered: Option<&serde_json::Value>,
) -> Answered {
    // Where this deployment answers from, not anything a request carried. A
    // relying party a caller could name is one a caller could impersonate, and a
    // credential is scoped to the party it was enrolled against for exactly that
    // reason.
    let Ok(party) = relying_party(origin) else {
        return Answered::plain(Outcome::Failed);
    };
    let Some(subject) = subject else {
        return Answered::plain(Outcome::Failed);
    };

    let Ok(enrolled) = store::providers::webauthn::of_user(transaction, &subject.user_id).await
    else {
        return Answered::plain(Outcome::Failed);
    };
    let held: Vec<Passkey> = enrolled
        .iter()
        .filter_map(|credential| serde_json::from_value(credential.passkey.clone()).ok())
        .collect();
    if held.is_empty() {
        // Nothing enrolled. Refused rather than asked, because a challenge no
        // key can answer is a screen the user waits at forever.
        return Answered::plain(Outcome::Failed);
    }

    let Some(Answer::Webauthn(handed_back)) =
        of_kind(answers, |answer| matches!(answer, Answer::Webauthn(_)))
    else {
        let Ok((shown, state)) = party.start_passkey_authentication(&held) else {
            return Answered::plain(Outcome::Failed);
        };
        let (Ok(shown), Ok(remembered)) =
            (serde_json::to_value(shown), serde_json::to_value(&state))
        else {
            return Answered::plain(Outcome::Failed);
        };
        return Answered {
            sending: None,
            outcome: Outcome::Pending,
            asks: Some(Challenge { shown, remembered }),
        };
    };

    // No state, no answer. A round that verifies against a challenge it cannot
    // find is one where the caller supplied both halves.
    let Some(state) = remembered
        .and_then(|held| serde_json::from_value::<PasskeyAuthentication>(held.clone()).ok())
    else {
        return Answered::plain(Outcome::Failed);
    };
    let Ok(presented) = serde_json::from_str::<PublicKeyCredential>(handed_back) else {
        return Answered::plain(Outcome::Failed);
    };
    let Ok(result) = party.finish_passkey_authentication(&presented, &state) else {
        return Answered::plain(Outcome::Failed);
    };

    // The counter, which is what tells a cloned authenticator from the real one.
    // The library says the assertion checks out; the store says whether this
    // device has gone backwards, and one that has is refused rather than
    // recorded.
    let advanced = store::providers::webauthn::record_use(
        transaction,
        result.cred_id().as_ref(),
        i64::from(result.counter()),
    )
    .await;
    match advanced {
        Ok(true) => Answered::plain(Outcome::Passed),
        _ => Answered::plain(Outcome::Failed),
    }
}

/// The party a credential is scoped to.
pub(crate) fn relying_party(origin: &PublicOrigin) -> Result<Webauthn, ()> {
    let url = Url::parse(origin.as_str()).map_err(|_| ())?;
    WebauthnBuilder::new(origin.host(), &url)
        .and_then(WebauthnBuilder::build)
        .map_err(|_| ())
}
