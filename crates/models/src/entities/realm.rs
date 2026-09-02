use serde::{Deserialize, Serialize};

use crypto::provider::Argon2Params;

use crate::auditable::AuditableModel;
use crate::entities::acr::AcrLoaMap;
use crate::entities::attributes::AttributesMap;
use crate::str_enum::str_enum;

str_enum! {
    #[postgres(name = "ssl_enforcement")]
    /// Where a realm insists on a secured connection.
    pub enum SslEnforcement {
        /// Nowhere. For a deployment behind something that already terminates
        /// it, and a mistake anywhere else.
        NotRequired => "none",
        /// Everywhere, including from inside the deployment.
        Always => "all",
        /// For requests that did not come from a private address.
        ExternalOnly => "external",
    }
}

/// When a count of failures becomes a refusal, and for how long.
///
/// Off by default. A lockout is a way to deny a person their own account, so a
/// deployment turns it on knowing that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BruteForce {
    pub protected: bool,
    pub max_failures: i32,
    pub lockout_seconds: i32,
    pub max_lockout_seconds: i32,
    /// A quiet spell of this long forgets the count.
    pub reset_seconds: i32,
}

impl Default for BruteForce {
    fn default() -> Self {
        BruteForce {
            protected: false,
            max_failures: 10,
            lockout_seconds: 60,
            max_lockout_seconds: 900,
            reset_seconds: 900,
        }
    }
}

impl BruteForce {
    /// How long a lockout lasts at this many failures.
    ///
    /// One more than the threshold earns the base window, and each further
    /// failure adds another, up to the ceiling. A wrong password twice is a
    /// person; a hundred times is not, and should not cost the same.
    pub fn lockout_for(self, failures: i64) -> i64 {
        let over = failures.saturating_sub(i64::from(self.max_failures)).max(0) + 1;
        (i64::from(self.lockout_seconds).saturating_mul(over))
            .min(i64::from(self.max_lockout_seconds))
    }
}

str_enum! {
    /// Whether a realm lets a client register itself, RFC 7591 §3.
    pub enum ClientRegistration {
        /// The endpoint is not there: it answers nothing and discovery does
        /// not name it. The default, because creating clients for whoever asks
        /// is not something a deployment should get by not deciding.
        Disabled => "disabled",
        /// Anyone may register. Valid per §1.2, and a deliberate choice.
        Open => "open",
        /// An initial access token is required, and the realm holds what it is
        /// checked against.
        Protected => "protected",
    }
}

/// A realm's rules for what a password may be, and what it costs to store one.
///
/// The cost is the hasher's own parameters rather than an algorithm named as
/// text with a count beside it. A count of iterations belongs to one algorithm,
/// and naming a different one describes a way of minting passwords that does not
/// exist here.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: Option<i64>,
    pub max_length: Option<i64>,
    pub min_digits: Option<u32>,
    pub min_upper_case: Option<u32>,
    pub min_lower_case: Option<u32>,
    pub min_special_chars: Option<u32>,
    /// Refuse a password that is the user's own address, username or birth
    /// date.
    pub not_email: Option<bool>,
    pub not_username: Option<bool>,
    pub not_birthdate: Option<bool>,
    pub blacklisted: Option<Vec<String>>,
    pub regex_pattern: Option<String>,
    pub expires_after_days: Option<i64>,
    /// How many previous passwords a new one is compared against.
    pub history_look_back: Option<u32>,
    /// What a stored password costs to compute.
    pub hashing: Argon2Params,
}

/// Who the password is for, of what the policy compares against.
#[derive(Debug, Clone, Copy, Default)]
pub struct About<'a> {
    pub username: Option<&'a str>,
    pub email: Option<&'a str>,
    pub birthdate: Option<&'a str>,
}

/// Why a password is refused. One reason, the first one found, because a list
/// of everything wrong with a password is a list of what to avoid guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PasswordRefused {
    #[error("the password is too short")]
    TooShort,
    #[error("the password is too long")]
    TooLong,
    #[error("the password needs more digits")]
    Digits,
    #[error("the password needs more capitals")]
    UpperCase,
    #[error("the password needs more small letters")]
    LowerCase,
    #[error("the password needs more punctuation")]
    SpecialChars,
    #[error("the password is something about you")]
    AboutYou,
    #[error("the password is one this realm refuses")]
    Blacklisted,
    #[error("the password does not match the shape this realm requires")]
    Shape,
}

/// A policy that cannot be satisfied by any password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PasswordPolicyConflict {
    #[error("the shortest password the policy allows is longer than the longest")]
    LengthRange,
    #[error("the character classes required add up to more than the longest password allowed")]
    ClassesExceedLength,
}

impl PasswordPolicy {
    /// Whether the policy can be satisfied at all.
    ///
    /// A range with its ends the wrong way round, or required character classes
    /// adding up past the longest password allowed, is a realm where no
    /// registration succeeds and the message says only that the password is
    /// invalid. Reading it back is what lets that be caught when the policy is
    /// written.
    /// Why this password is refused, or nothing when the policy admits it.
    ///
    /// Counted in characters and not in bytes: a password of eight accented
    /// letters is eight characters to whoever typed it, and calling it
    /// sixteen means the rule stated is not the rule applied.
    pub fn refuses(&self, password: &str, about: About<'_>) -> Option<PasswordRefused> {
        let length = i64::try_from(password.chars().count()).unwrap_or(i64::MAX);
        if self.min_length.is_some_and(|least| length < least) {
            return Some(PasswordRefused::TooShort);
        }
        if self.max_length.is_some_and(|most| length > most) {
            return Some(PasswordRefused::TooLong);
        }

        let count = |kept: fn(char) -> bool| {
            u32::try_from(password.chars().filter(|c| kept(*c)).count()).unwrap_or(u32::MAX)
        };
        for (least, held, why) in [
            (
                self.min_digits,
                count(|c| c.is_ascii_digit()),
                PasswordRefused::Digits,
            ),
            (
                self.min_upper_case,
                count(char::is_uppercase),
                PasswordRefused::UpperCase,
            ),
            (
                self.min_lower_case,
                count(char::is_lowercase),
                PasswordRefused::LowerCase,
            ),
            (
                self.min_special_chars,
                count(|c| !c.is_alphanumeric() && !c.is_whitespace()),
                PasswordRefused::SpecialChars,
            ),
        ] {
            if least.is_some_and(|least| held < least) {
                return Some(why);
            }
        }

        // Compared without case, because a password that is the username with
        // one capital is the username.
        let folded = password.to_lowercase();
        for (asked, value) in [
            (self.not_username, about.username),
            (self.not_email, about.email),
            (self.not_birthdate, about.birthdate),
        ] {
            if asked == Some(true)
                && value.is_some_and(|held| !held.is_empty() && held.to_lowercase() == folded)
            {
                return Some(PasswordRefused::AboutYou);
            }
        }

        if self
            .blacklisted
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|held| held.to_lowercase() == folded)
        {
            return Some(PasswordRefused::Blacklisted);
        }

        // A pattern that does not compile refuses everything rather than
        // admitting everything: a realm that wrote one meant to bound what a
        // password may be, and a typo must not quietly remove the bound.
        if let Some(pattern) = self.regex_pattern.as_deref() {
            let matches = regex::Regex::new(pattern)
                .ok()
                .map(|shape| shape.is_match(password));
            if matches != Some(true) {
                return Some(PasswordRefused::Shape);
            }
        }
        None
    }

    pub fn conflict(&self) -> Option<PasswordPolicyConflict> {
        if let (Some(min), Some(max)) = (self.min_length, self.max_length)
            && min > max
        {
            return Some(PasswordPolicyConflict::LengthRange);
        }

        if let Some(max) = self.max_length {
            let required = u64::from(self.min_digits.unwrap_or(0))
                + u64::from(self.min_upper_case.unwrap_or(0))
                + u64::from(self.min_lower_case.unwrap_or(0))
                + u64::from(self.min_special_chars.unwrap_or(0));
            if max < 0 || required > max.unsigned_abs() {
                return Some(PasswordPolicyConflict::ClassesExceedLength);
            }
        }

        None
    }
}

/// A realm.
/// What a realm allows a client that registered itself, as opposed to one an
/// administrator wrote down. Nothing here is read when registration is closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationBounds {
    /// How many clients registration may have created here, counted over the
    /// ones it created and not over the realm. An administrator keeps writing
    /// clients down after the endpoint has stopped answering, and a realm
    /// filled from outside never locks its owner out of it.
    pub max_clients: Option<i32>,
    /// Whether a client that registered itself has to be consented to. It was
    /// vetted by nobody, so the person is the one who decides.
    pub requires_consent: bool,
    /// Who may reach the endpoint, as addresses and prefixes. Empty is every
    /// caller: the policy above is what opened the endpoint at all.
    pub trusted_hosts: Vec<String>,
}

impl Default for RegistrationBounds {
    fn default() -> Self {
        RegistrationBounds {
            max_clients: None,
            requires_consent: true,
            trusted_hosts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmModel {
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub enabled: bool,

    pub registration_allowed: Option<bool>,
    /// Whether a client may register itself here, and on what terms. Not the
    /// line above: that one is about people.
    pub client_registration: ClientRegistration,
    /// What this realm does about a password being guessed at.
    pub brute_force: BruteForce,
    /// What an open registration is bounded by, which a closed one never
    /// reaches.
    pub registration_bounds: RegistrationBounds,
    /// Never serialised, like every other bearer credential. Hashed.
    #[serde(skip_serializing)]
    pub registration_secret: Option<String>,
    pub register_email_as_username: Option<bool>,
    pub verify_email: Option<bool>,
    pub login_with_email_allowed: Option<bool>,
    /// Whether two users may hold the same address. Off with
    /// `login_with_email_allowed`, or an address stops naming one account.
    pub duplicated_email_allowed: Option<bool>,
    pub edit_user_name_allowed: Option<bool>,
    pub reset_password_allowed: Option<bool>,
    pub remember_me: Option<bool>,

    pub ssl_enforcement: Option<SslEnforcement>,
    pub password_policy: Option<PasswordPolicy>,

    pub revoke_refresh_token: Option<bool>,
    pub refresh_token_max_reuse: Option<i32>,
    /// Lifespans, in seconds.
    pub access_token_lifespan: Option<i32>,
    /// How long a grant carrying `offline_access` may keep renewing.
    pub offline_session_lifespan: Option<i32>,
    /// The oldest an offline grant may get, however often it checks in. Zero
    /// is no bound, which is what a sliding window alone gives.
    pub offline_session_max_lifespan: i32,
    /// How many live offline grants one person may hold. Zero is no bound.
    pub max_offline_grants: i32,
    /// Whether every client here must push its request first, RFC 9126 §5.
    pub require_pushed_authorization_requests: bool,
    pub action_tokens_lifespan: Option<i32>,
    pub access_code_lifespan: Option<i32>,
    pub access_code_lifespan_user_action: Option<i32>,
    pub access_code_lifespan_login: Option<i32>,

    pub master_admin_client: Option<String>,
    pub events_enabled: Option<bool>,
    pub admin_events_enabled: Option<bool>,
    /// Tokens issued before this instant are refused.
    pub not_before: Option<i32>,
    pub attributes: Option<AttributesMap>,

    /// Maps context values to levels of assurance. None means the realm maps none,
    /// which is an omission and not level zero: a guess would be a false claim.
    pub acr_loa_map: Option<AcrLoaMap>,
    pub metadata: AuditableModel,
}

/// The create payload.
///
/// It names what a realm is and nothing about how it behaves. Every rule is set
/// afterwards by someone holding the capability for it, so creating a realm
/// cannot also decide that it allows registration or that it needs no secured
/// connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmCreateModel {
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
}

impl RealmCreateModel {
    pub fn into_model(self, realm_id: String, metadata: AuditableModel) -> RealmModel {
        RealmModel {
            realm_id,
            name: self.name,
            display_name: self.display_name,
            enabled: self.enabled,
            registration_allowed: None,
            client_registration: ClientRegistration::Disabled,
            registration_bounds: RegistrationBounds::default(),
            brute_force: BruteForce::default(),
            offline_session_max_lifespan: 0,
            max_offline_grants: 0,
            require_pushed_authorization_requests: false,
            registration_secret: None,
            register_email_as_username: None,
            verify_email: None,
            login_with_email_allowed: None,
            duplicated_email_allowed: None,
            edit_user_name_allowed: None,
            reset_password_allowed: None,
            remember_me: None,
            ssl_enforcement: None,
            password_policy: None,
            revoke_refresh_token: None,
            refresh_token_max_reuse: None,
            access_token_lifespan: None,
            offline_session_lifespan: None,
            action_tokens_lifespan: None,
            access_code_lifespan: None,
            access_code_lifespan_user_action: None,
            access_code_lifespan_login: None,
            master_admin_client: None,
            events_enabled: None,
            admin_events_enabled: None,
            not_before: None,
            attributes: None,
            acr_loa_map: None,
            metadata,
        }
    }
}

/// The update payload.
///
/// Applied to a loaded realm rather than converted into a fresh one, for the
/// reason a user update is: a conversion has to invent the fields the payload
/// does not carry, and the name is the one that matters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RealmUpdateModel {
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
    pub registration_allowed: Option<bool>,
    pub register_email_as_username: Option<bool>,
    pub verify_email: Option<bool>,
    pub login_with_email_allowed: Option<bool>,
    pub duplicated_email_allowed: Option<bool>,
    pub edit_user_name_allowed: Option<bool>,
    pub reset_password_allowed: Option<bool>,
    pub remember_me: Option<bool>,
    pub ssl_enforcement: Option<SslEnforcement>,
    pub password_policy: Option<PasswordPolicy>,
    pub revoke_refresh_token: Option<bool>,
    pub refresh_token_max_reuse: Option<i32>,
    pub access_token_lifespan: Option<i32>,
    /// How long a grant carrying `offline_access` may keep renewing.
    pub offline_session_lifespan: Option<i32>,
    pub action_tokens_lifespan: Option<i32>,
    pub access_code_lifespan: Option<i32>,
    pub access_code_lifespan_user_action: Option<i32>,
    pub access_code_lifespan_login: Option<i32>,
    pub master_admin_client: Option<String>,
    pub events_enabled: Option<bool>,
    pub admin_events_enabled: Option<bool>,
    pub not_before: Option<i32>,
    pub attributes: Option<AttributesMap>,
    pub acr_loa_map: Option<AcrLoaMap>,
    /// Whether a client may register itself here, and on what terms.
    pub client_registration: Option<ClientRegistration>,
    /// What this realm does about a password being guessed at.
    pub brute_force: Option<BruteForce>,
    /// What an open registration is bounded by.
    pub registration_bounds: Option<RegistrationBounds>,
    /// The oldest an offline grant may get. Zero is no bound.
    pub offline_session_max_lifespan: Option<i32>,
    /// How many live offline grants one person may hold. Zero is no bound.
    pub max_offline_grants: Option<i32>,
    /// Whether every client here must push its request first, RFC 9126 §5.
    pub require_pushed_authorization_requests: Option<bool>,
}

impl RealmUpdateModel {
    /// Write what the payload carries onto `realm`.
    ///
    /// Every field is optional and absent means unchanged, so an update that
    /// mentions one setting does not reset the others. The identifier and the
    /// name are left alone: a realm's name is what its issuer is built from, and
    /// renaming it through a settings edit would invalidate every token already
    /// issued.
    pub fn apply(self, realm: &mut RealmModel) {
        macro_rules! set {
            ($($field:ident),+ $(,)?) => {
                $(if let Some(value) = self.$field {
                    realm.$field = Some(value);
                })+
            };
        }

        if let Some(display_name) = self.display_name {
            realm.display_name = display_name;
        }
        if let Some(enabled) = self.enabled {
            realm.enabled = enabled;
        }
        if let Some(client_registration) = self.client_registration {
            realm.client_registration = client_registration;
        }
        if let Some(brute_force) = self.brute_force {
            realm.brute_force = brute_force;
        }
        if let Some(registration_bounds) = self.registration_bounds {
            realm.registration_bounds = registration_bounds;
        }
        if let Some(offline_session_max_lifespan) = self.offline_session_max_lifespan {
            realm.offline_session_max_lifespan = offline_session_max_lifespan;
        }
        if let Some(max_offline_grants) = self.max_offline_grants {
            realm.max_offline_grants = max_offline_grants;
        }
        if let Some(require_pushed) = self.require_pushed_authorization_requests {
            realm.require_pushed_authorization_requests = require_pushed;
        }

        set!(
            registration_allowed,
            register_email_as_username,
            verify_email,
            login_with_email_allowed,
            duplicated_email_allowed,
            edit_user_name_allowed,
            reset_password_allowed,
            remember_me,
            ssl_enforcement,
            password_policy,
            revoke_refresh_token,
            refresh_token_max_reuse,
            access_token_lifespan,
            offline_session_lifespan,
            action_tokens_lifespan,
            access_code_lifespan,
            access_code_lifespan_user_action,
            access_code_lifespan_login,
            master_admin_client,
            events_enabled,
            admin_events_enabled,
            not_before,
            attributes,
            acr_loa_map,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;

    fn realm() -> RealmModel {
        RealmCreateModel {
            name: "acme".into(),
            display_name: "Acme".into(),
            enabled: true,
        }
        .into_model(
            "realm-1".into(),
            AuditableModel::from_creator("acme".into(), "root".into()),
        )
    }

    #[test]
    fn a_policy_that_asks_for_nothing_admits_anything() {
        assert_eq!(
            PasswordPolicy::default().refuses("a", About::default()),
            None
        );
    }

    #[test]
    fn a_policy_refuses_for_the_first_reason_it_finds() {
        let policy = PasswordPolicy {
            min_length: Some(8),
            max_length: Some(20),
            min_digits: Some(1),
            min_upper_case: Some(1),
            min_special_chars: Some(1),
            ..PasswordPolicy::default()
        };
        assert_eq!(
            policy.refuses("Sh0rt!", About::default()),
            Some(PasswordRefused::TooShort)
        );
        assert_eq!(
            policy.refuses(&"A1!".repeat(9), About::default()),
            Some(PasswordRefused::TooLong)
        );
        assert_eq!(
            policy.refuses("nodigits!", About::default()),
            Some(PasswordRefused::Digits)
        );
        assert_eq!(
            policy.refuses("nocapital1!", About::default()),
            Some(PasswordRefused::UpperCase)
        );
        assert_eq!(
            policy.refuses("NoPunctuation1", About::default()),
            Some(PasswordRefused::SpecialChars)
        );
        assert_eq!(policy.refuses("GoodEnough1!", About::default()), None);
    }

    #[test]
    fn a_length_is_counted_in_characters_and_not_in_bytes() {
        let policy = PasswordPolicy {
            min_length: Some(8),
            ..PasswordPolicy::default()
        };
        // Eight characters to whoever typed them, sixteen bytes.
        assert_eq!(policy.refuses("ééééééét", About::default()), None);
        assert_eq!(
            policy.refuses("ééééé", About::default()),
            Some(PasswordRefused::TooShort)
        );
    }

    #[test]
    fn what_is_about_you_is_compared_without_case() {
        let policy = PasswordPolicy {
            not_username: Some(true),
            not_email: Some(true),
            ..PasswordPolicy::default()
        };
        let about = About {
            username: Some("ada"),
            email: Some("ada@example.test"),
            birthdate: None,
        };
        assert_eq!(
            policy.refuses("AdA", about),
            Some(PasswordRefused::AboutYou)
        );
        assert_eq!(
            policy.refuses("ADA@EXAMPLE.TEST", about),
            Some(PasswordRefused::AboutYou)
        );
        assert_eq!(policy.refuses("something-else", about), None);
        // Asked for nothing, compared against nothing.
        assert_eq!(PasswordPolicy::default().refuses("ada", about), None);
    }

    #[test]
    fn a_pattern_that_does_not_compile_refuses_everything() {
        let broken = PasswordPolicy {
            regex_pattern: Some("([unclosed".to_owned()),
            ..PasswordPolicy::default()
        };
        assert_eq!(
            broken.refuses("anything", About::default()),
            Some(PasswordRefused::Shape),
            "a typo in the pattern quietly removed the bound"
        );

        let shaped = PasswordPolicy {
            regex_pattern: Some("^[a-z]+$".to_owned()),
            ..PasswordPolicy::default()
        };
        assert_eq!(shaped.refuses("lowercase", About::default()), None);
        assert_eq!(
            shaped.refuses("Has Capitals", About::default()),
            Some(PasswordRefused::Shape)
        );
    }

    #[test]
    fn a_lockout_grows_with_the_count_and_stops_at_the_ceiling() {
        let policy = BruteForce {
            max_failures: 3,
            lockout_seconds: 60,
            max_lockout_seconds: 300,
            ..BruteForce::default()
        };
        // The failure that reaches the threshold earns the base window.
        assert_eq!(policy.lockout_for(3), 60);
        assert_eq!(policy.lockout_for(4), 120);
        assert_eq!(policy.lockout_for(7), 300, "the ceiling did not hold");
        assert_eq!(policy.lockout_for(700), 300);
        // Under the threshold nothing is locked, but the arithmetic still has
        // to hand back a window rather than a negative one.
        assert_eq!(policy.lockout_for(1), 60);
        assert_eq!(policy.lockout_for(0), 60);
    }

    #[test]
    fn a_realm_registers_no_client_until_it_says_so() {
        assert_eq!(realm().client_registration, ClientRegistration::Disabled);
        assert_eq!(ClientRegistration::ALL.len(), 3);
        assert_eq!(ClientRegistration::Disabled.as_str(), "disabled");
        assert_eq!(ClientRegistration::Open.as_str(), "open");
        assert_eq!(ClientRegistration::Protected.as_str(), "protected");
        assert_round_trips(ClientRegistration::ALL);
    }

    #[test]
    fn the_enforcement_levels_agree_with_their_own_spelling() {
        assert_eq!(SslEnforcement::ALL.len(), 3);
        assert_eq!(SslEnforcement::NotRequired.as_str(), "none");
        assert_eq!(SslEnforcement::Always.as_str(), "all");
        assert_eq!(SslEnforcement::ExternalOnly.as_str(), "external");
        assert_round_trips(SslEnforcement::ALL);
    }

    /// A created realm decides nothing about how it behaves. Every rule is set
    /// afterwards by someone holding the capability for it.
    #[test]
    fn a_created_realm_carries_no_rule_it_was_not_given() {
        let realm = realm();
        assert_eq!(realm.realm_id, "realm-1");
        assert_eq!(realm.name, "acme");
        assert!(realm.enabled);
        assert_eq!(realm.metadata.tenant, "acme");

        assert_eq!(realm.registration_allowed, None);
        assert_eq!(realm.ssl_enforcement, None, "not even that one is decided");
        assert_eq!(realm.password_policy, None);
        assert_eq!(realm.duplicated_email_allowed, None);
        assert_eq!(realm.acr_loa_map, None);
    }

    /// The cost a password is stored at is the hasher's own, so the policy
    /// cannot name a way of minting one that does not exist.
    #[test]
    fn the_policy_defaults_to_what_the_hasher_defaults_to() {
        let policy = PasswordPolicy::default();
        assert_eq!(policy.hashing, Argon2Params::default());
        assert_eq!(policy.min_length, None);
        assert_eq!(policy.conflict(), None, "requiring nothing is satisfiable");

        // And it survives the wire as the hasher's own numbers.
        let encoded = serde_json::to_string(&policy).unwrap();
        assert_eq!(
            serde_json::from_str::<PasswordPolicy>(&encoded).unwrap(),
            policy
        );
        assert!(encoded.contains("m_cost"), "{encoded}");
    }

    /// A range with its ends the wrong way round is a realm where no
    /// registration succeeds, and the message says only that the password is
    /// invalid.
    #[test]
    fn a_length_range_the_wrong_way_round_is_a_conflict() {
        let policy = PasswordPolicy {
            min_length: Some(12),
            max_length: Some(8),
            ..PasswordPolicy::default()
        };
        assert_eq!(policy.conflict(), Some(PasswordPolicyConflict::LengthRange));

        let equal = PasswordPolicy {
            min_length: Some(8),
            max_length: Some(8),
            ..PasswordPolicy::default()
        };
        assert_eq!(equal.conflict(), None, "a single allowed length is fine");
    }

    /// Character classes adding up past the longest allowed password is the
    /// same failure by another route, and the one nobody notices while writing
    /// each requirement on its own.
    #[test]
    fn required_classes_may_not_exceed_the_longest_password() {
        let policy = PasswordPolicy {
            max_length: Some(8),
            min_digits: Some(3),
            min_upper_case: Some(3),
            min_lower_case: Some(3),
            ..PasswordPolicy::default()
        };
        assert_eq!(
            policy.conflict(),
            Some(PasswordPolicyConflict::ClassesExceedLength)
        );

        let exact = PasswordPolicy {
            max_length: Some(9),
            min_digits: Some(3),
            min_upper_case: Some(3),
            min_lower_case: Some(3),
            ..PasswordPolicy::default()
        };
        assert_eq!(exact.conflict(), None, "adding up to the ceiling is fine");

        // Without a ceiling, no number of classes conflicts.
        let unbounded = PasswordPolicy {
            min_digits: Some(1_000),
            ..PasswordPolicy::default()
        };
        assert_eq!(unbounded.conflict(), None);
    }

    /// An update writes what it carries and leaves the rest alone, so setting
    /// one rule does not reset the others.
    #[test]
    fn an_update_touches_only_what_it_carries() {
        let mut realm = RealmModel {
            registration_allowed: Some(true),
            verify_email: Some(true),
            access_token_lifespan: Some(300),
            ..realm()
        };

        RealmUpdateModel {
            verify_email: Some(false),
            ssl_enforcement: Some(SslEnforcement::Always),
            ..RealmUpdateModel::default()
        }
        .apply(&mut realm);

        assert_eq!(realm.verify_email, Some(false));
        assert_eq!(realm.ssl_enforcement, Some(SslEnforcement::Always));
        assert_eq!(
            realm.registration_allowed,
            Some(true),
            "a rule the payload did not mention is untouched"
        );
        assert_eq!(realm.access_token_lifespan, Some(300));
    }

    /// The identifier and the name are never written. A realm's name is what its
    /// issuer is built from, so renaming it through a settings edit would
    /// invalidate every token already issued.
    #[test]
    fn an_update_cannot_rename_or_move_a_realm() {
        let mut realm = realm();
        RealmUpdateModel {
            display_name: Some("Acme Incorporated".into()),
            enabled: Some(false),
            ..RealmUpdateModel::default()
        }
        .apply(&mut realm);

        assert_eq!(realm.display_name, "Acme Incorporated");
        assert!(!realm.enabled);
        assert_eq!(realm.name, "acme", "the name is not settings");
        assert_eq!(realm.realm_id, "realm-1");
    }

    /// An empty update is a no-op rather than a reset. This is what the shape
    /// buys: a payload that mentions nothing changes nothing.
    #[test]
    fn an_empty_update_changes_nothing() {
        let before = RealmModel {
            registration_allowed: Some(true),
            ssl_enforcement: Some(SslEnforcement::ExternalOnly),
            password_policy: Some(PasswordPolicy::default()),
            ..realm()
        };
        let mut after = before.clone();
        RealmUpdateModel::default().apply(&mut after);

        assert_eq!(after.registration_allowed, before.registration_allowed);
        assert_eq!(after.ssl_enforcement, before.ssl_enforcement);
        assert_eq!(after.password_policy, before.password_policy);
        assert_eq!(after.display_name, before.display_name);
        assert!(after.enabled);
    }
}
