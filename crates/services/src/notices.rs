use auth::messaging::{About, Message, Outgoing};
use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::attributes;
use models::entities::credentials::{CredentialChange, CredentialType};
use models::entities::mail::MailSettings;
use models::entities::realm::RealmModel;
use models::entities::user::{UserModel, profile};
use serde_json::Value;
use store::providers::notices::{self, HeldNotice, Settled};
use store::providers::outbox::{self, OutboxEvent};
use store::providers::{credentials, users, webauthn};

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
}

impl NoticeKind {
    const ALL: [NoticeKind; 12] = [
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
        }
    }

    pub fn parse(spelled: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == spelled)
    }
}

/// The notice a happening owes its person, if any: a change to their password or
/// to a factor. A code spent to sign in is told apart from a sheet given up.
pub fn read_notice(kind: &str, payload: &Value) -> Option<NoticeKind> {
    if kind != outbox::CREDENTIAL_CHANGED {
        return None;
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tongue {
    English,
    French,
}

/// The tongue a notice is written in: the person's where it is one of the two the
/// notices speak, the realm's otherwise, English when neither says.
fn choose_tongue(person: Option<&str>, realm: Option<&str>) -> Tongue {
    [person, realm]
        .into_iter()
        .flatten()
        .find_map(|asked| {
            match asked
                .split(['-', '_'])
                .next()
                .map(str::to_ascii_lowercase)
                .as_deref()
            {
                Some("fr") => Some(Tongue::French),
                Some("en") => Some(Tongue::English),
                _ => None,
            }
        })
        .unwrap_or(Tongue::English)
}

/// A value spoken inside a mail, kept on one line: a name holding a line break
/// would otherwise start a header of its own.
fn flatten(value: &str) -> String {
    value
        .chars()
        .map(|held| if held.is_control() { ' ' } else { held })
        .collect()
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
        },
    }
}

/// What a notice says, as a subject and a body: what changed, on which account and
/// when, and what to do if it was not the person. No link: security mail that
/// teaches people to follow links teaches them to follow the forged ones too.
pub fn compose_notice(
    realm: &RealmModel,
    person: &UserModel,
    kind: NoticeKind,
    occurred_at: DateTime<Utc>,
    codes_left: Option<i64>,
) -> (String, String) {
    let tongue = choose_tongue(
        person
            .attributes
            .as_ref()
            .and_then(|held| attributes::string_at(held, profile::LOCALE)),
        realm.default_locale.as_deref(),
    );
    let realm_name = flatten(if realm.display_name.trim().is_empty() {
        &realm.name
    } else {
        &realm.display_name
    });
    let account = flatten(&person.user_name);
    let happened = describe(kind, tongue);
    let resettable = realm.reset_password_allowed == Some(true);
    let (subject, facts, left, advice) = match tongue {
        Tongue::English => (
            format!("{realm_name}: {happened}"),
            format!(
                "Account: {account}\nWhen: {} UTC\n",
                occurred_at.format("%Y-%m-%d at %H:%M")
            ),
            codes_left.map(|left| format!("Recovery codes left: {left}\n")),
            if resettable {
                "If this was you, there is nothing to do. If it was not, reset your password \
                 from the sign-in page and tell your administrator."
            } else {
                "If this was you, there is nothing to do. If it was not, tell your \
                 administrator at once."
            },
        ),
        Tongue::French => (
            format!("{realm_name} : {happened}"),
            format!(
                "Compte : {account}\nQuand : le {} UTC\n",
                occurred_at.format("%d/%m/%Y à %H:%M")
            ),
            codes_left.map(|left| format!("Codes de secours restants : {left}\n")),
            if resettable {
                "Si c'était vous, vous n'avez rien à faire. Sinon, réinitialisez votre mot de \
                 passe depuis la page de connexion et prévenez votre administrateur."
            } else {
                "Si c'était vous, vous n'avez rien à faire. Sinon, prévenez tout de suite votre \
                 administrateur."
            },
        ),
    };
    let body = format!(
        "{happened}.\n\n{facts}{}\n{advice}\n",
        left.unwrap_or_default()
    );
    (subject, body)
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

/// Who a notice goes to: a person still held, at a verified address, in a realm
/// that has not switched its notices off.
pub fn find_recipient<'p>(
    realm: &RealmModel,
    person: Option<&'p UserModel>,
) -> Result<&'p UserModel, Unsent> {
    if realm.security_notices_enabled == Some(false) {
        return Err(Unsent::SwitchedOff);
    }
    let person = person.ok_or(Unsent::PersonGone)?;
    if person.email_verified != Some(true) || person.email.trim().is_empty() {
        return Err(Unsent::NoVerifiedAddress);
    }
    Ok(person)
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
    transaction: &Transaction<'_>,
    event: &OutboxEvent,
) -> Result<(), Unsettled> {
    let Some(kind) = read_notice(&event.kind, &event.payload) else {
        return Ok(());
    };
    notices::note(
        transaction,
        event.event_id,
        &event.user_id,
        kind.as_str(),
        event.occurred_at,
    )
    .await
    .map_err(|_| Unsettled)
}

/// The realm's notices due now, claimed for this pass.
pub async fn claim_due_notices(
    transaction: &Transaction<'_>,
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
    transaction: &Transaction<'_>,
    realm: &RealmModel,
    settings: Option<&MailSettings>,
    claimed: Vec<HeldNotice>,
) -> Result<Vec<DueNotice>, Unsettled> {
    let mut due = Vec::new();
    for notice in claimed {
        let person = users::load(transaction, &notice.user_id)
            .await
            .map_err(|_| Unsettled)?;
        let (Some(kind), Some(settings), Ok(person)) = (
            NoticeKind::parse(&notice.kind),
            settings,
            find_recipient(realm, person.as_ref()),
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
        let (subject, body) = compose_notice(realm, person, kind, notice.occurred_at, codes_left);
        due.push(DueNotice {
            event_id: notice.event_id,
            attempts: notice.attempts,
            outgoing: Outgoing {
                settings: settings.duplicate(),
                message: Message {
                    to: person.email.clone(),
                    subject,
                    body,
                },
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
    transaction: &Transaction<'_>,
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
                Some(owed),
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
            read_notice(outbox::USER_UPDATED, &changed("password", "update")),
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

    /// A notice is written in the person's tongue where it is one of the two the
    /// notices speak, the realm's otherwise, English when neither says.
    #[test]
    fn a_notice_speaks_the_persons_tongue_then_the_realms() {
        assert_eq!(choose_tongue(Some("fr-FR"), Some("en")), Tongue::French);
        assert_eq!(choose_tongue(Some("EN_us"), Some("fr")), Tongue::English);
        assert_eq!(choose_tongue(Some("de"), Some("fr")), Tongue::French);
        assert_eq!(choose_tongue(None, Some("fr")), Tongue::French);
        assert_eq!(choose_tongue(Some("de"), None), Tongue::English);
        assert_eq!(choose_tongue(None, None), Tongue::English);
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

    /// A notice names what changed, the account and the minute, then what to do if
    /// it was not the person: reset the password where the realm lets them, tell
    /// the administrator in any case. It carries no link.
    #[test]
    fn a_notice_says_what_changed_on_which_account_and_when_without_a_link() {
        let (subject, body) = compose_notice(
            &realm("Acme", None, true),
            &person(None, Some(true)),
            NoticeKind::PasswordChanged,
            at_ten_forty_two(),
            None,
        );
        assert_eq!(subject, "Acme: Your password was changed");
        assert_eq!(
            body,
            "Your password was changed.\n\nAccount: ada\nWhen: 2026-09-15 at 10:42 UTC\n\nIf this \
             was you, there is nothing to do. If it was not, reset your password from the sign-in \
             page and tell your administrator.\n"
        );

        let (subject, body) = compose_notice(
            &realm("", Some("en"), false),
            &person(Some("fr"), Some(true)),
            NoticeKind::RecoveryCodeUsed,
            at_ten_forty_two(),
            Some(7),
        );
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

    /// A name holding a line break stays on its line: a realm or an account named to
    /// carry a header of its own writes none.
    #[test]
    fn a_name_holding_a_line_break_stays_on_its_line() {
        let mut named = person(None, Some(true));
        named.user_name = "ada\r\nBcc: someone@example.test".into();
        let (subject, body) = compose_notice(
            &realm("Acme\nBcc: someone@example.test", None, false),
            &named,
            NoticeKind::KeyAdded,
            at_ten_forty_two(),
            None,
        );
        assert!(!subject.contains(['\r', '\n']), "{subject:?}");
        assert!(
            body.contains("Account: ada  Bcc: someone@example.test\n"),
            "{body:?}"
        );
    }

    /// Only a verified address is written to, of a person still held, in a realm
    /// that has not switched its notices off.
    #[test]
    fn only_a_verified_address_in_a_realm_that_tells_is_written_to() {
        let telling = realm("Acme", None, false);
        let verified = person(None, Some(true));
        assert!(find_recipient(&telling, Some(&verified)).is_ok());
        let mut switched_on = telling.clone();
        switched_on.security_notices_enabled = Some(true);
        assert!(find_recipient(&switched_on, Some(&verified)).is_ok());
        let mut switched_off = telling.clone();
        switched_off.security_notices_enabled = Some(false);
        assert_eq!(
            find_recipient(&switched_off, Some(&verified)).err(),
            Some(Unsent::SwitchedOff)
        );
        assert_eq!(
            find_recipient(&telling, None).err(),
            Some(Unsent::PersonGone)
        );
        let mut addressless = person(None, Some(true));
        addressless.email = " ".into();
        for unverified in [person(None, Some(false)), person(None, None), addressless] {
            assert_eq!(
                find_recipient(&telling, Some(&unverified)).err(),
                Some(Unsent::NoVerifiedAddress)
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
