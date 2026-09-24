use auth::messaging::{About, Message, Outgoing, Tongue, choose_tongue};
use chrono::{DateTime, Utc};
use models::entities::attributes;
use models::entities::credentials::{CredentialChange, CredentialType};
use models::entities::mail::MailSettings;
use models::entities::realm::RealmModel;
use models::entities::user::{UserModel, profile};
use serde_json::Value;
use store::providers::events::notices::{self, HeldNotice, Noted, Settled};
use store::providers::events::outbox::{self, OutboxEvent};
use store::providers::{brokering, credentials, users, webauthn};
use store::tenancy::UnitOfWork;

/// What a receipt for a security notice is recorded under.
pub const SECURITY_NOTICE: &str = "security-notice";

/// How many times a notice is offered to the mail server before it is given up on.
pub const NOTICE_ATTEMPTS: i32 = 5;

/// What a person is told happened to how they sign in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    PasswordSet,
    PasswordChanged,
    AppAdded,
    AppRemoved,
    /// Taken away by an administrator, where the other removals are the person's.
    AppRevoked,
    KeyAdded,
    KeyRemoved,
    KeyRevoked,
    RecoveryCodesIssued,
    RecoveryCodesRemoved,
    RecoveryCodesRevoked,
    /// A code spent to sign in: an account entered without its usual second factor.
    RecoveryCodeUsed,
    /// Told to the address the change moved away from.
    AddressChanged,
    /// An upstream account linked to an account that already existed.
    ProviderLinked,
}

impl NoticeKind {
    pub const ALL: [NoticeKind; 14] = [
        NoticeKind::PasswordSet,
        NoticeKind::PasswordChanged,
        NoticeKind::AppAdded,
        NoticeKind::AppRemoved,
        NoticeKind::AppRevoked,
        NoticeKind::KeyAdded,
        NoticeKind::KeyRemoved,
        NoticeKind::KeyRevoked,
        NoticeKind::RecoveryCodesIssued,
        NoticeKind::RecoveryCodesRemoved,
        NoticeKind::RecoveryCodesRevoked,
        NoticeKind::RecoveryCodeUsed,
        NoticeKind::AddressChanged,
        NoticeKind::ProviderLinked,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            NoticeKind::PasswordSet => "password-set",
            NoticeKind::PasswordChanged => "password-changed",
            NoticeKind::AppAdded => "app-added",
            NoticeKind::AppRemoved => "app-removed",
            NoticeKind::AppRevoked => "app-revoked",
            NoticeKind::KeyAdded => "key-added",
            NoticeKind::KeyRemoved => "key-removed",
            NoticeKind::KeyRevoked => "key-revoked",
            NoticeKind::RecoveryCodesIssued => "recovery-codes-issued",
            NoticeKind::RecoveryCodesRemoved => "recovery-codes-removed",
            NoticeKind::RecoveryCodesRevoked => "recovery-codes-revoked",
            NoticeKind::RecoveryCodeUsed => "recovery-code-used",
            NoticeKind::AddressChanged => "address-changed",
            NoticeKind::ProviderLinked => "provider-linked",
        }
    }

    pub fn parse(spelled: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == spelled)
    }
}

/// A notice a happening owes: where it goes when that is not the person's current
/// address, and the provider it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owed {
    pub kind: NoticeKind,
    pub recipient: Option<String>,
    pub provider_alias: Option<String>,
}

fn owe_to_person(kind: NoticeKind) -> Owed {
    Owed {
        kind,
        recipient: None,
        provider_alias: None,
    }
}

/// The notice a happening owes, if any: a change to a password or a factor, an
/// address moved away from a verified one, or an upstream account linked to an
/// account that already existed.
pub fn read_notice(kind: &str, payload: &Value) -> Option<Owed> {
    match kind {
        outbox::CREDENTIAL_CHANGED => read_credential_change(payload).map(owe_to_person),
        outbox::USER_UPDATED => {
            let previous = payload["previous_email"]
                .as_str()
                .filter(|held| !held.trim().is_empty())?;
            (payload["previous_email_verified"].as_bool() == Some(true)).then(|| Owed {
                kind: NoticeKind::AddressChanged,
                recipient: Some(previous.to_owned()),
                provider_alias: None,
            })
        }
        outbox::IDENTITY_LINKED => {
            let provider = payload["provider"].as_str()?;
            (payload["account_created"].as_bool() == Some(false)).then(|| Owed {
                kind: NoticeKind::ProviderLinked,
                recipient: None,
                provider_alias: Some(provider.to_owned()),
            })
        }
        _ => None,
    }
}

/// The notice a change to a password or a factor owes. A code spent to sign in is
/// told apart from a sheet given up.
fn read_credential_change(payload: &Value) -> Option<NoticeKind> {
    let change: CredentialChange = payload["change_type"].as_str()?.parse().ok()?;
    let credential = payload["credential_type"].as_str()?;
    if credential == webauthn::CREDENTIAL_TYPE {
        return match change {
            CredentialChange::Create => Some(NoticeKind::KeyAdded),
            CredentialChange::Delete => Some(NoticeKind::KeyRemoved),
            CredentialChange::Revoke => Some(NoticeKind::KeyRevoked),
            CredentialChange::Update => None,
        };
    }
    let spent = payload["spent"].as_bool() == Some(true);
    match (credential.parse::<CredentialType>().ok()?, change) {
        (CredentialType::Password, CredentialChange::Create) => Some(NoticeKind::PasswordSet),
        (CredentialType::Password, CredentialChange::Update) => Some(NoticeKind::PasswordChanged),
        (CredentialType::Totp | CredentialType::Hotp, CredentialChange::Create) => {
            Some(NoticeKind::AppAdded)
        }
        (CredentialType::Totp | CredentialType::Hotp, CredentialChange::Delete) => {
            Some(NoticeKind::AppRemoved)
        }
        (CredentialType::Totp | CredentialType::Hotp, CredentialChange::Revoke) => {
            Some(NoticeKind::AppRevoked)
        }
        (CredentialType::RecoveryCode, CredentialChange::Create | CredentialChange::Update) => {
            Some(NoticeKind::RecoveryCodesIssued)
        }
        (CredentialType::RecoveryCode, CredentialChange::Delete) if spent => {
            Some(NoticeKind::RecoveryCodeUsed)
        }
        (CredentialType::RecoveryCode, CredentialChange::Delete) => {
            Some(NoticeKind::RecoveryCodesRemoved)
        }
        (CredentialType::RecoveryCode, CredentialChange::Revoke) => {
            Some(NoticeKind::RecoveryCodesRevoked)
        }
        _ => None,
    }
}

/// A value spoken inside a mail, kept on one line: a name holding a line break
/// would otherwise start a header of its own.
fn flatten(value: &str) -> String {
    value
        .chars()
        .map(|held| if held.is_control() { ' ' } else { held })
        .collect()
}

/// An address shown only enough to be recognised: its first character and its
/// domain. The mailbox a change moved away from learns no more of the new one.
fn mask_address(address: &str) -> String {
    match address.split_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => {
            let first: String = local.chars().take(1).collect();
            format!("{first}***@{domain}")
        }
        _ => "***".to_owned(),
    }
}

fn describe(kind: NoticeKind, tongue: Tongue) -> &'static str {
    match tongue {
        Tongue::English => match kind {
            NoticeKind::PasswordSet => "A password was set for your account",
            NoticeKind::PasswordChanged => "Your password was changed",
            NoticeKind::AppAdded => "An authenticator app was added to your account",
            NoticeKind::AppRemoved => "An authenticator app was removed from your account",
            NoticeKind::AppRevoked => {
                "An administrator removed an authenticator app from your account"
            }
            NoticeKind::KeyAdded => "A security key was added to your account",
            NoticeKind::KeyRemoved => "A security key was removed from your account",
            NoticeKind::KeyRevoked => "An administrator removed a security key from your account",
            NoticeKind::RecoveryCodesIssued => "New recovery codes were issued for your account",
            NoticeKind::RecoveryCodesRemoved => "Your recovery codes were removed",
            NoticeKind::RecoveryCodesRevoked => "An administrator removed your recovery codes",
            NoticeKind::RecoveryCodeUsed => "A recovery code was used to sign in to your account",
            NoticeKind::AddressChanged => "The email address of your account was changed",
            NoticeKind::ProviderLinked => "An external account was linked to your account",
        },
        Tongue::French => match kind {
            NoticeKind::PasswordSet => "Un mot de passe a été défini pour votre compte",
            NoticeKind::PasswordChanged => "Votre mot de passe a été changé",
            NoticeKind::AppAdded => {
                "Une application d'authentification a été ajoutée à votre compte"
            }
            NoticeKind::AppRemoved => {
                "Une application d'authentification a été retirée de votre compte"
            }
            NoticeKind::AppRevoked => {
                "Un administrateur a retiré une application d'authentification de votre compte"
            }
            NoticeKind::KeyAdded => "Une clé de sécurité a été ajoutée à votre compte",
            NoticeKind::KeyRemoved => "Une clé de sécurité a été retirée de votre compte",
            NoticeKind::KeyRevoked => {
                "Un administrateur a retiré une clé de sécurité de votre compte"
            }
            NoticeKind::RecoveryCodesIssued => {
                "De nouveaux codes de secours ont été émis pour votre compte"
            }
            NoticeKind::RecoveryCodesRemoved => "Vos codes de secours ont été retirés",
            NoticeKind::RecoveryCodesRevoked => "Un administrateur a retiré vos codes de secours",
            NoticeKind::RecoveryCodeUsed => {
                "Un code de secours a servi à vous connecter à votre compte"
            }
            NoticeKind::AddressChanged => "L'adresse e-mail de votre compte a été changée",
            NoticeKind::ProviderLinked => "Un compte externe a été lié à votre compte",
        },
    }
}

/// The words that frame a notice, in one tongue.
struct Wording {
    subject_separator: &'static str,
    account: &'static str,
    when: &'static str,
    when_format: &'static str,
    new_address: &'static str,
    provider: &'static str,
    codes_left: &'static str,
    or_reset: &'static str,
    or_administrator: &'static str,
}

const ENGLISH: Wording = Wording {
    subject_separator: ": ",
    account: "Account: ",
    when: "When: ",
    when_format: "%Y-%m-%d at %H:%M",
    new_address: "New address: ",
    provider: "Provider: ",
    codes_left: "Recovery codes left: ",
    or_reset: "If this was you, there is nothing to do. If it was not, reset your password from \
               the sign-in page and tell your administrator.",
    or_administrator: "If this was you, there is nothing to do. If it was not, tell your \
                       administrator at once.",
};

const FRENCH: Wording = Wording {
    subject_separator: " : ",
    account: "Compte : ",
    when: "Quand : le ",
    when_format: "%d/%m/%Y à %H:%M",
    new_address: "Nouvelle adresse : ",
    provider: "Fournisseur : ",
    codes_left: "Codes de secours restants : ",
    or_reset: "Si c'était vous, vous n'avez rien à faire. Sinon, réinitialisez votre mot de passe \
               depuis la page de connexion et prévenez votre administrateur.",
    or_administrator: "Si c'était vous, vous n'avez rien à faire. Sinon, prévenez tout de suite \
                       votre administrateur.",
};

/// What a notice tells beyond its kind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Particulars {
    /// The recovery codes left, after one was used.
    pub codes_left: Option<i64>,
    /// The provider a link names, by the name the realm shows.
    pub provider: Option<String>,
}

/// What a notice says, as a subject and a body: what changed, on which account and
/// when, and what to do if it was not the person. No link: security mail that
/// teaches people to follow links teaches them to follow the forged ones too.
pub fn compose_notice(
    realm: &RealmModel,
    person: &UserModel,
    kind: NoticeKind,
    occurred_at: DateTime<Utc>,
    particulars: &Particulars,
) -> auth::messaging::Worded {
    let reader = person
        .attributes
        .as_ref()
        .and_then(|held| attributes::string_at(held, profile::LOCALE));
    let tongue = choose_tongue(reader, realm.default_locale.as_deref());
    let wording = match tongue {
        Tongue::English => &ENGLISH,
        Tongue::French => &FRENCH,
    };
    let realm_name = flatten(if realm.display_name.trim().is_empty() {
        &realm.name
    } else {
        &realm.display_name
    });
    let happened = describe(kind, tongue);
    let user_name = flatten(&person.user_name);
    let codes_left = particulars.codes_left.map(|left| left.to_string());
    let mut lines = vec![
        format!("{}{}", wording.account, user_name),
        format!(
            "{}{} UTC",
            wording.when,
            occurred_at.format(wording.when_format)
        ),
    ];
    let new_address =
        (kind == NoticeKind::AddressChanged).then(|| mask_address(&flatten(&person.email)));
    lines.extend(
        [
            (wording.new_address, new_address.clone()),
            (
                wording.provider,
                particulars.provider.as_deref().map(flatten),
            ),
            (wording.codes_left, codes_left.clone()),
        ]
        .into_iter()
        .filter_map(|(label, value)| value.map(|value| format!("{label}{value}"))),
    );
    // A reset link goes to the address the account holds now, and a provider stays
    // linked whatever the password: after these two, only the administrator helps.
    let resettable = realm.reset_password_allowed == Some(true)
        && !matches!(
            kind,
            NoticeKind::AddressChanged | NoticeKind::ProviderLinked
        );
    let advice = if resettable {
        wording.or_reset
    } else {
        wording.or_administrator
    };
    // Every name is supplied, empty where this kind carries none, so a realm
    // writing one its kind never fills reads as nothing rather than leaving
    // `{{provider}}` standing in somebody's mail.
    let when = format!("{} UTC", occurred_at.format(wording.when_format));
    let said = [
        ("realm", realm_name.as_str()),
        ("account", user_name.as_str()),
        ("when", when.as_str()),
        ("what", happened),
        ("advice", advice),
        ("new_address", new_address.as_deref().unwrap_or_default()),
        (
            "provider",
            particulars.provider.as_deref().unwrap_or_default(),
        ),
        ("codes_left", codes_left.as_deref().unwrap_or_default()),
    ];

    // The realm's words where it wrote any for this kind. A notice has no
    // fixed wording to fall back to, so the build's is composed here rather
    // than looked up, and it is what answers when the realm said nothing.
    match auth::messaging::reworded(realm, kind.as_str(), reader) {
        Some(template) => auth::messaging::put_in(
            kind.as_str(),
            tongue,
            &template.subject,
            &template.body,
            "",
            &said,
        ),
        None => auth::messaging::told(
            &format!("{realm_name}{}{happened}", wording.subject_separator),
            &format!("{happened}.\n\n{}\n\n{advice}\n", lines.join("\n")),
        ),
    }
}

/// Why a notice owed will never go out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsent {
    /// The realm switched its notices off.
    SwitchedOff,
    PersonGone,
    /// An unverified address could be a stranger's, who would learn what happens
    /// to the account.
    NoVerifiedAddress,
}

/// The address a notice goes to: the one it was owed at, verified when it was
/// noted, or else the person's own verified address, in a realm that has not
/// switched its notices off and for a person still held.
pub fn find_recipient(
    realm: &RealmModel,
    person: Option<&UserModel>,
    recipient: Option<&str>,
) -> Result<String, Unsent> {
    if realm.security_notices_enabled == Some(false) {
        return Err(Unsent::SwitchedOff);
    }
    let person = person.ok_or(Unsent::PersonGone)?;
    if let Some(recipient) = recipient {
        return Ok(recipient.to_owned());
    }
    if person.email_verified != Some(true) || person.email.trim().is_empty() {
        return Err(Unsent::NoVerifiedAddress);
    }
    Ok(person.email.clone())
}

/// How an attempt settles its notice: sent once it went out, given up on once the
/// last attempt allowed failed, still owed otherwise.
pub fn settle_attempt(went_out: bool, attempts: i32) -> Option<Settled> {
    if went_out {
        Some(Settled::Sent)
    } else if attempts >= NOTICE_ATTEMPTS {
        Some(Settled::Dead)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the security notices could not be read or settled")]
pub struct Unsettled;

/// Owe a person a notice for a happening that changed how they sign in. Noting it
/// again, as a retried telling does, adds nothing.
pub async fn note_owed_notice(
    transaction: &UnitOfWork,
    event: &OutboxEvent,
) -> Result<(), Unsettled> {
    let Some(owed) = read_notice(&event.kind, &event.payload) else {
        return Ok(());
    };
    notices::note(
        transaction,
        &Noted {
            event_id: event.event_id,
            user_id: &event.user_id,
            kind: owed.kind.as_str(),
            occurred_at: event.occurred_at,
            recipient: owed.recipient.as_deref(),
            provider_alias: owed.provider_alias.as_deref(),
        },
    )
    .await
    .map_err(|_| Unsettled)
}

/// The realm's notices due now, claimed for this pass.
pub async fn claim_due_notices(
    transaction: &UnitOfWork,
    ceiling: i64,
    backoff_seconds: i64,
) -> Result<Vec<HeldNotice>, Unsettled> {
    notices::claim_due(transaction, ceiling, backoff_seconds)
        .await
        .map_err(|_| Unsettled)
}

/// A notice claimed and composed, ready to go out once its transaction commits.
pub struct DueNotice {
    pub event_id: i64,
    pub attempts: i32,
    pub outgoing: Outgoing,
}

/// Compose each claimed notice for its person. One that can never go out is
/// settled as skipped here, in the claiming transaction.
///
/// `settings` is what the realm sends with, None where it names no mail server or
/// the deployment sends nothing.
pub async fn compose_due_notices(
    transaction: &UnitOfWork,
    realm: &RealmModel,
    settings: Option<&MailSettings>,
    claimed: Vec<HeldNotice>,
) -> Result<Vec<DueNotice>, Unsettled> {
    let mut due = Vec::new();
    for notice in claimed {
        let person = users::load(transaction, &notice.user_id)
            .await
            .map_err(|_| Unsettled)?;
        let address = find_recipient(realm, person.as_ref(), notice.recipient.as_deref());
        let (Some(kind), Some(settings), Some(person), Ok(address)) = (
            NoticeKind::parse(&notice.kind),
            settings,
            person.as_ref(),
            address,
        ) else {
            notices::settle(transaction, notice.event_id, Settled::Skipped)
                .await
                .map_err(|_| Unsettled)?;
            continue;
        };
        let codes_left = match kind {
            NoticeKind::RecoveryCodeUsed => Some(
                credentials::count_recovery_codes(transaction, &person.user_id)
                    .await
                    .map_err(|_| Unsettled)?,
            ),
            _ => None,
        };
        let provider = match notice.provider_alias.as_deref() {
            Some(alias) => Some(
                brokering::provider_by_alias(transaction, alias)
                    .await
                    .map_err(|_| Unsettled)?
                    .map(|held| held.display_name)
                    .filter(|shown| !shown.trim().is_empty())
                    .unwrap_or_else(|| alias.to_owned()),
            ),
            None => None,
        };
        let worded = compose_notice(
            realm,
            person,
            kind,
            notice.occurred_at,
            &Particulars {
                codes_left,
                provider,
            },
        );
        due.push(DueNotice {
            event_id: notice.event_id,
            attempts: notice.attempts,
            outgoing: Outgoing {
                settings: settings.duplicate(),
                message: Message::to(&address, worded),
                about: About {
                    user_id: person.user_id.clone(),
                    purpose: SECURITY_NOTICE.to_owned(),
                },
            },
        });
    }
    Ok(due)
}

/// What one notice's attempt came to.
pub struct Attempted {
    pub event_id: i64,
    pub attempts: i32,
    pub went_out: bool,
}

/// Settle every notice its attempt decided.
pub async fn settle_attempts(
    transaction: &UnitOfWork,
    attempted: &[Attempted],
) -> Result<(), Unsettled> {
    for attempt in attempted {
        if let Some(settled) = settle_attempt(attempt.went_out, attempt.attempts) {
            notices::settle(transaction, attempt.event_id, settled)
                .await
                .map_err(|_| Unsettled)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use models::auditable::AuditableModel;
    use models::entities::attributes::AttributeValue;
    use models::entities::realm::RealmCreateModel;
    use serde_json::json;

    fn changed(credential: &str, change: &str) -> Value {
        json!({ "credential_type": credential, "change_type": change })
    }

    /// Every change to a password or a factor owes its person the notice that names
    /// it, telling a code spent to sign in from a sheet given up, and a factor an
    /// administrator revoked from one the person removed.
    #[test]
    fn a_change_to_a_password_or_factor_owes_its_notice() {
        let spent =
            json!({ "credential_type": "recovery-code", "change_type": "delete", "spent": true });
        for (payload, owed) in [
            (changed("password", "create"), NoticeKind::PasswordSet),
            (changed("password", "update"), NoticeKind::PasswordChanged),
            (changed("totp", "create"), NoticeKind::AppAdded),
            (changed("hotp", "delete"), NoticeKind::AppRemoved),
            (changed("totp", "revoke"), NoticeKind::AppRevoked),
            (changed("webauthn", "create"), NoticeKind::KeyAdded),
            (changed("webauthn", "delete"), NoticeKind::KeyRemoved),
            (changed("webauthn", "revoke"), NoticeKind::KeyRevoked),
            (
                changed("recovery-code", "create"),
                NoticeKind::RecoveryCodesIssued,
            ),
            (
                changed("recovery-code", "update"),
                NoticeKind::RecoveryCodesIssued,
            ),
            (
                changed("recovery-code", "delete"),
                NoticeKind::RecoveryCodesRemoved,
            ),
            (
                changed("recovery-code", "revoke"),
                NoticeKind::RecoveryCodesRevoked,
            ),
            (spent, NoticeKind::RecoveryCodeUsed),
        ] {
            assert_eq!(
                read_notice(outbox::CREDENTIAL_CHANGED, &payload),
                Some(owe_to_person(owed)),
                "{payload}"
            );
            assert_eq!(NoticeKind::parse(owed.as_str()), Some(owed));
        }
    }

    /// A happening that changes no way into an account owes nothing: another kind,
    /// a service account's secret, a superseded password, a factor updated in place,
    /// or a payload that does not say what changed.
    #[test]
    fn a_happening_that_changes_no_way_in_owes_nothing() {
        assert_eq!(
            read_notice(outbox::SESSION_REVOKED, &changed("password", "update")),
            None
        );
        for payload in [
            changed("secret", "update"),
            changed("password-history", "create"),
            changed("webauthn", "update"),
            changed("totp", "update"),
            changed("password", "delete"),
            changed("password", "renamed"),
            json!({ "change_type": "create" }),
            json!({ "credential_type": "totp" }),
        ] {
            assert_eq!(
                read_notice(outbox::CREDENTIAL_CHANGED, &payload),
                None,
                "{payload}"
            );
        }
        assert_eq!(NoticeKind::parse("password-renamed"), None);
    }

    /// An address moved away from a verified one owes that old address its notice;
    /// one moved away from an address never verified, or an update that moved no
    /// address, owes nothing.
    #[test]
    fn an_address_moved_away_from_a_verified_one_owes_the_old_address() {
        let moved = |verified: bool| {
            json!({
                "user_name": "ada", "email": "ada@example.org", "enabled": true,
                "previous_email": "ada@example.test", "previous_email_verified": verified,
            })
        };
        assert_eq!(
            read_notice(outbox::USER_UPDATED, &moved(true)),
            Some(Owed {
                kind: NoticeKind::AddressChanged,
                recipient: Some("ada@example.test".to_owned()),
                provider_alias: None,
            })
        );
        assert_eq!(
            NoticeKind::parse("address-changed"),
            Some(NoticeKind::AddressChanged)
        );
        for payload in [
            moved(false),
            json!({ "user_name": "ada", "email": "ada@example.org", "enabled": true }),
            json!({ "previous_email": " ", "previous_email_verified": true }),
        ] {
            assert_eq!(
                read_notice(outbox::USER_UPDATED, &payload),
                None,
                "{payload}"
            );
        }
    }

    /// An upstream account linked to an account that already existed owes it a notice
    /// naming the provider; the link an account was made with owes nothing.
    #[test]
    fn a_provider_linked_to_an_existing_account_owes_a_notice() {
        assert_eq!(
            read_notice(
                outbox::IDENTITY_LINKED,
                &json!({ "provider": "acme", "account_created": false })
            ),
            Some(Owed {
                kind: NoticeKind::ProviderLinked,
                recipient: None,
                provider_alias: Some("acme".to_owned()),
            })
        );
        assert_eq!(
            NoticeKind::parse("provider-linked"),
            Some(NoticeKind::ProviderLinked)
        );
        for payload in [
            json!({ "provider": "acme", "account_created": true }),
            json!({ "provider": "acme" }),
            json!({ "account_created": false }),
        ] {
            assert_eq!(
                read_notice(outbox::IDENTITY_LINKED, &payload),
                None,
                "{payload}"
            );
        }
    }

    /// An address is shown by its first character and its domain, and one that is
    /// not an address shows nothing of itself.
    #[test]
    fn an_address_is_shown_only_enough_to_be_recognised() {
        assert_eq!(mask_address("grace@example.org"), "g***@example.org");
        assert_eq!(mask_address("é@exemple.fr"), "é***@exemple.fr");
        for unshaped in ["no-at-sign", "@example.org", "grace@"] {
            assert_eq!(mask_address(unshaped), "***", "{unshaped}");
        }
    }

    fn realm(display_name: &str, locale: Option<&str>, resettable: bool) -> RealmModel {
        let mut realm = RealmCreateModel {
            name: "acme".into(),
            display_name: display_name.into(),
            enabled: true,
        }
        .into_model(
            "realm-1".into(),
            AuditableModel::from_creator("acme".into(), "root".into()),
        );
        realm.default_locale = locale.map(str::to_owned);
        realm.reset_password_allowed = Some(resettable);
        realm
    }

    fn person(locale: Option<&str>, verified: Option<bool>) -> UserModel {
        UserModel {
            user_id: "user-1".into(),
            realm_id: "realm-1".into(),
            user_name: "ada".into(),
            enabled: true,
            email: "ada@example.test".into(),
            email_verified: verified,
            phone_number: None,
            phone_number_verified: None,
            required_actions: None,
            not_before: None,
            user_storage: None,
            attributes: locale.map(|tongue| {
                std::collections::HashMap::from([(
                    profile::LOCALE.to_owned(),
                    AttributeValue::Str(tongue.to_owned()),
                )])
            }),
            is_service_account: None,
            service_account_client_link: None,
            metadata: AuditableModel::from_creator("acme".into(), "root".into()),
        }
    }

    fn at_ten_forty_two() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 15, 10, 42, 0)
            .single()
            .expect("an instant")
    }

    /// The point of the whole thing. A realm that has reworded its letters had
    /// no way to reword the one message that reaches somebody after their
    /// account changed under them, which is the one they are most likely to
    /// read closely.
    #[test]
    fn a_realms_own_words_win_for_a_notice_as_they_do_for_a_letter() {
        let mut realm = realm("Acme", Some("en"), true);
        let mut tongues = std::collections::HashMap::new();
        tongues.insert(
            "en".to_owned(),
            models::entities::realm::MailTemplate {
                subject: "{{realm}}: something happened".to_owned(),
                body: "{{what}} on {{account}} at {{when}}.\n\nCall us.\n".to_owned(),
            },
        );
        let mut templates = std::collections::HashMap::new();
        templates.insert(NoticeKind::PasswordChanged.as_str().to_owned(), tongues);
        realm.mail_templates = Some(templates);

        let held = compose_notice(
            &realm,
            &person(None, Some(true)),
            NoticeKind::PasswordChanged,
            at_ten_forty_two(),
            &Particulars::default(),
        );
        assert_eq!(held.subject, "Acme: something happened");
        assert_eq!(
            held.text,
            "Your password was changed on ada at 2026-09-15 at 10:42 UTC.\n\nCall us.\n"
        );

        // A kind the realm said nothing about keeps the build's words, so
        // rewording one notice never silences the others.
        let other = compose_notice(
            &realm,
            &person(None, Some(true)),
            NoticeKind::KeyAdded,
            at_ten_forty_two(),
            &Particulars::default(),
        );
        assert!(other.subject.contains("Acme"), "{}", other.subject);
        assert!(other.text.contains("Account: ada"), "{}", other.text);
    }

    /// A name this kind never fills reads as nothing rather than leaving the
    /// marker standing in somebody's mail.
    #[test]
    fn a_name_this_kind_does_not_carry_is_left_empty_and_not_shown() {
        let mut realm = realm("Acme", Some("en"), true);
        let mut tongues = std::collections::HashMap::new();
        tongues.insert(
            "en".to_owned(),
            models::entities::realm::MailTemplate {
                subject: "Acme".to_owned(),
                body: "Provider: {{provider}}. Codes: {{codes_left}}.\n".to_owned(),
            },
        );
        let mut templates = std::collections::HashMap::new();
        templates.insert(NoticeKind::PasswordChanged.as_str().to_owned(), tongues);
        realm.mail_templates = Some(templates);

        let held = compose_notice(
            &realm,
            &person(None, Some(true)),
            NoticeKind::PasswordChanged,
            at_ten_forty_two(),
            &Particulars::default(),
        );
        assert!(
            !held.text.contains("{{"),
            "a marker was left standing: {}",
            held.text
        );
        assert_eq!(held.text, "Provider: . Codes: .\n");
    }

    /// A notice names what changed, the account and the minute, then what to do if
    /// it was not the person: reset the password where the realm lets them, tell
    /// the administrator in any case. It carries no link.
    #[test]
    fn a_notice_says_what_changed_on_which_account_and_when_without_a_link() {
        let held = compose_notice(
            &realm("Acme", None, true),
            &person(None, Some(true)),
            NoticeKind::PasswordChanged,
            at_ten_forty_two(),
            &Particulars::default(),
        );
        let (subject, body) = (held.subject, held.text);
        assert_eq!(subject, "Acme: Your password was changed");
        assert_eq!(
            body,
            "Your password was changed.\n\nAccount: ada\nWhen: 2026-09-15 at 10:42 UTC\n\nIf this \
             was you, there is nothing to do. If it was not, reset your password from the sign-in \
             page and tell your administrator.\n"
        );

        let held = compose_notice(
            &realm("", Some("en"), false),
            &person(Some("fr"), Some(true)),
            NoticeKind::RecoveryCodeUsed,
            at_ten_forty_two(),
            &Particulars {
                codes_left: Some(7),
                provider: None,
            },
        );
        let (subject, body) = (held.subject, held.text);
        assert_eq!(
            subject,
            "acme : Un code de secours a servi à vous connecter à votre compte"
        );
        assert_eq!(
            body,
            "Un code de secours a servi à vous connecter à votre compte.\n\nCompte : ada\nQuand : \
             le 15/09/2026 à 10:42 UTC\nCodes de secours restants : 7\n\nSi c'était vous, vous \
             n'avez rien à faire. Sinon, prévenez tout de suite votre administrateur.\n"
        );
    }

    /// A moved address is told with the new one masked, and a link with the provider
    /// named; neither advises a reset, whose link would go where the change went.
    #[test]
    fn a_moved_address_or_a_link_is_told_without_advising_a_reset() {
        let mut moved = person(None, Some(false));
        moved.email = "grace@example.org".into();
        let held = compose_notice(
            &realm("Acme", None, true),
            &moved,
            NoticeKind::AddressChanged,
            at_ten_forty_two(),
            &Particulars::default(),
        );
        let (subject, body) = (held.subject, held.text);
        assert_eq!(
            subject,
            "Acme: The email address of your account was changed"
        );
        assert_eq!(
            body,
            "The email address of your account was changed.\n\nAccount: ada\nWhen: 2026-09-15 at \
             10:42 UTC\nNew address: g***@example.org\n\nIf this was you, there is nothing to do. \
             If it was not, tell your administrator at once.\n"
        );

        let held = compose_notice(
            &realm("Acme", Some("fr"), true),
            &person(None, Some(true)),
            NoticeKind::ProviderLinked,
            at_ten_forty_two(),
            &Particulars {
                codes_left: None,
                provider: Some("Annuaire Acme".to_owned()),
            },
        );
        let (subject, body) = (held.subject, held.text);
        assert_eq!(subject, "Acme : Un compte externe a été lié à votre compte");
        assert_eq!(
            body,
            "Un compte externe a été lié à votre compte.\n\nCompte : ada\nQuand : le 15/09/2026 à \
             10:42 UTC\nFournisseur : Annuaire Acme\n\nSi c'était vous, vous n'avez rien à faire. \
             Sinon, prévenez tout de suite votre administrateur.\n"
        );
    }

    /// A name holding a line break stays on its line: a realm or an account named to
    /// carry a header of its own writes none.
    #[test]
    fn a_name_holding_a_line_break_stays_on_its_line() {
        let mut named = person(None, Some(true));
        named.user_name = "ada\r\nBcc: someone@example.test".into();
        let held = compose_notice(
            &realm("Acme\nBcc: someone@example.test", None, false),
            &named,
            NoticeKind::KeyAdded,
            at_ten_forty_two(),
            &Particulars::default(),
        );
        let (subject, body) = (held.subject, held.text);
        assert!(!subject.contains(['\r', '\n']), "{subject:?}");
        assert!(
            body.contains("Account: ada  Bcc: someone@example.test\n"),
            "{body:?}"
        );
    }

    /// A notice goes to the address it was owed at, or else to the person's verified
    /// address, only for a person still held and in a realm that has not switched its
    /// notices off.
    #[test]
    fn a_notice_goes_to_its_owed_or_verified_address_in_a_realm_that_tells() {
        let telling = realm("Acme", None, false);
        let verified = person(None, Some(true));
        assert_eq!(
            find_recipient(&telling, Some(&verified), None),
            Ok("ada@example.test".to_owned())
        );
        let mut switched_on = telling.clone();
        switched_on.security_notices_enabled = Some(true);
        assert!(find_recipient(&switched_on, Some(&verified), None).is_ok());
        let mut switched_off = telling.clone();
        switched_off.security_notices_enabled = Some(false);
        for owed in [None, Some("old@example.test")] {
            assert_eq!(
                find_recipient(&switched_off, Some(&verified), owed),
                Err(Unsent::SwitchedOff)
            );
            assert_eq!(
                find_recipient(&telling, None, owed),
                Err(Unsent::PersonGone)
            );
        }
        let mut addressless = person(None, Some(true));
        addressless.email = " ".into();
        for unverified in [person(None, Some(false)), person(None, None), addressless] {
            assert_eq!(
                find_recipient(&telling, Some(&unverified), None),
                Err(Unsent::NoVerifiedAddress)
            );
            assert_eq!(
                find_recipient(&telling, Some(&unverified), Some("old@example.test")),
                Ok("old@example.test".to_owned())
            );
        }
    }

    /// An attempt settles its notice once it went out or was the last allowed, and
    /// leaves it owed otherwise.
    #[test]
    fn an_attempt_settles_its_notice_once_it_went_out_or_was_the_last() {
        assert_eq!(settle_attempt(true, 1), Some(Settled::Sent));
        assert_eq!(settle_attempt(true, NOTICE_ATTEMPTS), Some(Settled::Sent));
        assert_eq!(settle_attempt(false, 1), None);
        assert_eq!(settle_attempt(false, NOTICE_ATTEMPTS - 1), None);
        assert_eq!(settle_attempt(false, NOTICE_ATTEMPTS), Some(Settled::Dead));
    }
}
