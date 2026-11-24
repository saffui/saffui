//! The settings of a realm: what it lets happen beyond the defaults, kept as
//! one document. They are read closed: a document that is absent, that does
//! not read, or that says what this version does not know or does not allow
//! reads as the defaults, and the defaults keep registration closed.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::authz::admin::{ADMIN_SCOPE, AdminCaller};
use crate::authz::roles::describe_actor;
use crate::claims::rules::check_scope_capabilities;
use crate::clients::check_scope_token;
use crate::error::{ErrorCode, Failure};

/// Who may register a client through the protocol (RFC 7591).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationPolicy {
    /// Nobody: the endpoint is not published.
    #[default]
    Closed,
    /// Whoever holds an initial access token an administrator made.
    InitialToken,
    /// Anyone who reaches the endpoint.
    Open,
}

impl RegistrationPolicy {
    pub const ALL: [Self; 3] = [Self::Closed, Self::InitialToken, Self::Open];

    /// The name the document and the administration plane give it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::InitialToken => "initial_token",
            Self::Open => "open",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|policy| policy.name() == name)
    }
}

/// The scopes a registered client may be allowed when the realm names
/// none: what a person is told of on the consent page, nothing kept while
/// they are away, and nothing that opens the administration.
pub const DEFAULT_REGISTRABLE_SCOPES: [&str; 3] = ["openid", "profile", "email"];
pub const MOST_REGISTRABLE_SCOPES: usize = 32;
pub const DEFAULT_MAX_REGISTERED_CLIENTS: u32 = 100;
pub const MOST_REGISTERED_CLIENTS: u32 = 10_000;
pub const DEFAULT_MAX_REDIRECT_URIS: u32 = 5;
pub const MOST_REDIRECT_URIS: u32 = 10;
pub const DEFAULT_MAX_DAILY_REGISTRATIONS: u32 = 100;
pub const MOST_DAILY_REGISTRATIONS: u32 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RealmSettings {
    pub registration: RegistrationPolicy,
    /// The scopes a registered client may be allowed, all of them when it
    /// names none.
    pub registrable_scopes: Vec<String>,
    /// How many clients registrations may have made in the realm, those
    /// whose registration ended counted until retention removes them.
    pub max_registered_clients: u32,
    /// How many addresses a registered client gives of each kind: where a
    /// person is sent back, and where after signing out.
    pub max_redirect_uris: u32,
    /// How many clients may register in the realm in a day, from wherever.
    pub max_daily_registrations: u32,
}

impl Default for RealmSettings {
    fn default() -> Self {
        Self {
            registration: RegistrationPolicy::Closed,
            registrable_scopes: DEFAULT_REGISTRABLE_SCOPES.map(str::to_owned).to_vec(),
            max_registered_clients: DEFAULT_MAX_REGISTERED_CLIENTS,
            max_redirect_uris: DEFAULT_MAX_REDIRECT_URIS,
            max_daily_registrations: DEFAULT_MAX_DAILY_REGISTRATIONS,
        }
    }
}

/// The settings an administrator writes: what is left out takes its default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WantedSettings {
    pub registration: RegistrationPolicy,
    pub registrable_scopes: Option<Vec<String>>,
    pub max_registered_clients: Option<u32>,
    pub max_redirect_uris: Option<u32>,
    pub max_daily_registrations: Option<u32>,
}

impl WantedSettings {
    /// The settings as they are written: each bound left out at its default.
    #[must_use]
    pub fn fill_defaults(self) -> RealmSettings {
        let defaults = RealmSettings::default();
        RealmSettings {
            registration: self.registration,
            registrable_scopes: self
                .registrable_scopes
                .unwrap_or(defaults.registrable_scopes),
            max_registered_clients: self
                .max_registered_clients
                .unwrap_or(defaults.max_registered_clients),
            max_redirect_uris: self.max_redirect_uris.unwrap_or(defaults.max_redirect_uris),
            max_daily_registrations: self
                .max_daily_registrations
                .unwrap_or(defaults.max_daily_registrations),
        }
    }
}

/// Checks settings against their bounds. A client nobody vetted is never
/// allowed the scope of the administration plane.
///
/// # Errors
///
/// Returns [`ErrorCode::RealmSettingsInvalid`].
pub fn check_realm_settings(settings: &RealmSettings) -> Result<(), Failure> {
    let scopes = &settings.registrable_scopes;
    let bounded = scopes.len() <= MOST_REGISTRABLE_SCOPES
        && (1..=MOST_REGISTERED_CLIENTS).contains(&settings.max_registered_clients)
        && (1..=MOST_REDIRECT_URIS).contains(&settings.max_redirect_uris)
        && (1..=MOST_DAILY_REGISTRATIONS).contains(&settings.max_daily_registrations);
    let allowed = scopes
        .iter()
        .all(|scope| check_scope_token(scope).is_ok() && scope != ADMIN_SCOPE);
    if bounded && allowed {
        Ok(())
    } else {
        Err(Failure::new(ErrorCode::RealmSettingsInvalid))
    }
}

/// Checks that a realm under `settings` takes one more registered client
/// while it holds `registered` of them.
///
/// # Errors
///
/// Returns [`ErrorCode::RegistrationQuotaReached`].
pub fn check_registration_quota(registered: u64, settings: &RealmSettings) -> Result<(), Failure> {
    if registered < u64::from(settings.max_registered_clients) {
        Ok(())
    } else {
        Err(Failure::new(ErrorCode::RegistrationQuotaReached))
    }
}

/// Checks that a realm under `settings` takes one more registration while
/// `registered` were made in it in the last day.
///
/// # Errors
///
/// Returns [`ErrorCode::RegistrationBudgetSpent`].
pub fn check_registration_budget(registered: u64, settings: &RealmSettings) -> Result<(), Failure> {
    if registered < u64::from(settings.max_daily_registrations) {
        Ok(())
    } else {
        Err(Failure::new(ErrorCode::RegistrationBudgetSpent))
    }
}

/// The scopes a change of the settings hands out that were not handed out
/// before: those of a realm that opens, all of them; those of a closed
/// realm, none. A closed realm hands out nothing.
#[must_use]
pub fn list_scopes_handed_out(before: &RealmSettings, after: &RealmSettings) -> Vec<String> {
    if after.registration == RegistrationPolicy::Closed {
        return Vec::new();
    }
    let held_before: &[String] = match before.registration {
        RegistrationPolicy::Closed => &[],
        RegistrationPolicy::InitialToken | RegistrationPolicy::Open => &before.registrable_scopes,
    };
    after
        .registrable_scopes
        .iter()
        .filter(|scope| !held_before.contains(scope))
        .cloned()
        .collect()
}

/// Reads the settings document of a realm, closed.
#[must_use]
pub fn read_settings_closed(document: Option<Value>) -> RealmSettings {
    document
        .and_then(|document| serde_json::from_value::<RealmSettings>(document).ok())
        .filter(|settings| check_realm_settings(settings).is_ok())
        .unwrap_or_default()
}

/// Reads the settings of the realm of the caller, as registration reads them.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn read_realm_settings(
    app: &App,
    caller: &AdminCaller,
) -> Result<RealmSettings, Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    Ok(read_settings_closed(work.read_realm_settings().await?))
}

/// Replaces the settings of the realm of the caller, whole, a bound left
/// out at its default. Nobody hands out more than they have: a registrable
/// scope the realm did not hand out yet, that makes tokens say what the
/// caller may not read, is refused, as at the creation of a client. Closing
/// hands out nothing.
///
/// # Errors
///
/// Returns [`ErrorCode::RealmSettingsInvalid`], [`ErrorCode::CapabilityMissing`],
/// or the storage failure.
pub async fn change_realm_settings(
    app: &App,
    caller: &AdminCaller,
    wanted: WantedSettings,
) -> Result<RealmSettings, Failure> {
    let wanted = wanted.fill_defaults();
    check_realm_settings(&wanted)?;
    let document = serde_json::to_value(&wanted)
        .map_err(|_| Failure::with_detail(ErrorCode::Internal, "settings that do not write"))?;
    let mut work = app.storage.begin(caller.scope).await?;
    // Taken: of two changes at once, the second judges what the first wrote.
    let before = read_settings_closed(work.read_realm_settings_for_update().await?);
    check_scope_capabilities(
        &list_scopes_handed_out(&before, &wanted),
        &caller.client.capabilities,
    )?;
    work.write_realm_settings(&document).await?;
    let told = json!({
        "actor": describe_actor(caller),
        "max_daily_registrations": wanted.max_daily_registrations,
        "max_redirect_uris": wanted.max_redirect_uris,
        "max_registered_clients": wanted.max_registered_clients,
        "registrable_scopes": wanted.registrable_scopes,
        "registration": wanted.registration.name(),
    });
    record_event(app, work.as_mut(), EventKind::RealmSettingsChanged, told).await?;
    work.commit().await?;
    Ok(wanted)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        RealmSettings, RegistrationPolicy, WantedSettings, change_realm_settings,
        check_realm_settings, check_registration_budget, check_registration_quota,
        list_scopes_handed_out, read_settings_closed,
    };
    use crate::authz::admin::authorize_admin_call;
    use crate::authz::capability::Capability;
    use crate::error::ErrorCode;
    use crate::oidc::scenario::Scenario;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::create_administrator;

    fn open() -> RealmSettings {
        RealmSettings {
            registration: RegistrationPolicy::Open,
            ..RealmSettings::default()
        }
    }

    /// What an administrator writes to have `settings`, every bound named.
    fn want(settings: RealmSettings) -> WantedSettings {
        WantedSettings {
            registration: settings.registration,
            registrable_scopes: Some(settings.registrable_scopes),
            max_registered_clients: Some(settings.max_registered_clients),
            max_redirect_uris: Some(settings.max_redirect_uris),
            max_daily_registrations: Some(settings.max_daily_registrations),
        }
    }

    #[test]
    fn the_defaults_keep_registration_closed_and_allow_nothing_kept_offline() {
        let defaults = RealmSettings::default();

        assert_eq!(defaults.registration, RegistrationPolicy::Closed);
        assert_eq!(defaults.registrable_scopes, ["openid", "profile", "email"]);
        assert_eq!(check_realm_settings(&defaults), Ok(()));
    }

    #[test]
    fn a_document_absent_unreadable_unknown_or_out_of_bounds_reads_closed() {
        let written = serde_json::to_value(open()).expect("a document");
        assert_eq!(read_settings_closed(Some(written.clone())), open());

        let mut unknown = written.clone();
        unknown["registraton"] = json!("open");
        let mut admin = written.clone();
        admin["registrable_scopes"] = json!(["openid", "admin"]);
        let mut unbounded = written.clone();
        unbounded["max_registered_clients"] = json!(0);
        for document in [
            None,
            Some(json!("open")),
            Some(json!({ "registration": "wide" })),
            Some(unknown),
            Some(admin),
            Some(unbounded),
        ] {
            assert_eq!(
                read_settings_closed(document.clone()),
                RealmSettings::default(),
                "{document:?}"
            );
        }
    }

    #[test]
    fn a_policy_is_written_in_the_document_by_the_name_the_plane_reads() {
        for policy in RegistrationPolicy::ALL {
            assert_eq!(
                serde_json::to_value(policy).expect("a name"),
                json!(policy.name())
            );
            assert_eq!(RegistrationPolicy::parse(policy.name()), Some(policy));
        }
        assert_eq!(RegistrationPolicy::parse("wide"), None);
    }

    #[test]
    fn a_realm_takes_registered_clients_up_to_its_bound_and_not_one_more() {
        let settings = RealmSettings {
            max_registered_clients: 2,
            ..open()
        };

        assert_eq!(check_registration_quota(1, &settings), Ok(()));
        assert_eq!(
            check_registration_quota(2, &settings).map_err(|failure| failure.code),
            Err(ErrorCode::RegistrationQuotaReached)
        );
    }

    #[test]
    fn a_realm_takes_as_many_registrations_a_day_as_its_budget_and_not_one_more() {
        let settings = RealmSettings {
            max_daily_registrations: 3,
            ..open()
        };

        assert_eq!(check_registration_budget(2, &settings), Ok(()));
        assert_eq!(
            check_registration_budget(3, &settings).map_err(|failure| failure.code),
            Err(ErrorCode::RegistrationBudgetSpent)
        );
    }

    #[test]
    fn a_bound_left_out_takes_its_default() {
        let wanted = WantedSettings {
            registration: RegistrationPolicy::Open,
            registrable_scopes: None,
            max_registered_clients: Some(7),
            max_redirect_uris: None,
            max_daily_registrations: None,
        };

        assert_eq!(
            wanted.fill_defaults(),
            RealmSettings {
                max_registered_clients: 7,
                ..open()
            }
        );
    }

    #[test]
    fn a_change_hands_out_the_scopes_a_closed_realm_did_not_and_closing_hands_out_none() {
        let scoped = |registration, scopes: &[&str]| RealmSettings {
            registration,
            registrable_scopes: scopes.iter().map(|&scope| scope.to_owned()).collect(),
            ..RealmSettings::default()
        };
        let open_with = |scopes| scoped(RegistrationPolicy::Open, scopes);

        assert_eq!(
            list_scopes_handed_out(&RealmSettings::default(), &open_with(&["openid", "email"])),
            ["openid", "email"],
            "a closed realm handed out none of its scopes"
        );
        assert_eq!(
            list_scopes_handed_out(&open_with(&["openid"]), &open_with(&["openid", "email"])),
            ["email"]
        );
        assert_eq!(
            list_scopes_handed_out(
                &open_with(&["openid", "email"]),
                &scoped(RegistrationPolicy::InitialToken, &["openid"])
            ),
            Vec::<String>::new()
        );
        assert_eq!(
            list_scopes_handed_out(
                &RealmSettings::default(),
                &scoped(RegistrationPolicy::Closed, &["openid", "email"])
            ),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_bound_past_its_ceiling_or_the_scope_of_the_administration_is_refused() {
        let many: Vec<String> = (0..33).map(|index| format!("scope-{index}")).collect();
        for refused in [
            RealmSettings {
                registrable_scopes: vec!["openid".to_owned(), "admin".to_owned()],
                ..open()
            },
            RealmSettings {
                registrable_scopes: vec!["a b".to_owned()],
                ..open()
            },
            RealmSettings {
                registrable_scopes: many,
                ..open()
            },
            RealmSettings {
                max_registered_clients: 0,
                ..open()
            },
            RealmSettings {
                max_registered_clients: 10_001,
                ..open()
            },
            RealmSettings {
                max_redirect_uris: 0,
                ..open()
            },
            RealmSettings {
                max_redirect_uris: 11,
                ..open()
            },
            RealmSettings {
                max_daily_registrations: 0,
                ..open()
            },
            RealmSettings {
                max_daily_registrations: 10_001,
                ..open()
            },
        ] {
            assert_eq!(
                check_realm_settings(&refused).map_err(|failure| failure.code),
                Err(ErrorCode::RealmSettingsInvalid),
                "{refused:?}"
            );
        }
        let widest = RealmSettings {
            registrable_scopes: (0..32).map(|index| format!("scope-{index}")).collect(),
            max_registered_clients: 10_000,
            max_redirect_uris: 10,
            max_daily_registrations: 10_000,
            ..open()
        };
        assert_eq!(check_realm_settings(&widest), Ok(()));
    }

    #[test]
    fn an_administrator_opens_only_what_they_may_read_and_the_chain_says_so() {
        let scenario = Scenario::start();
        let narrow = scenario.name_operator(&[Capability::RealmWrite]);
        let wide = RealmSettings {
            registrable_scopes: vec!["openid".to_owned(), "email".to_owned()],
            ..open()
        };

        let refused = complete(change_realm_settings(
            &scenario.app,
            &narrow,
            want(wide.clone()),
        ))
        .map_err(|failure| failure.code);
        assert_eq!(
            refused,
            Err(ErrorCode::CapabilityMissing),
            "the email of a person is for whoever reads people"
        );
        let written = complete(change_realm_settings(&scenario.app, &narrow, want(open())))
            .map_err(|failure| failure.code);
        assert_eq!(
            written,
            Err(ErrorCode::CapabilityMissing),
            "the defaults allow profile and email"
        );
        let opened = RealmSettings {
            registrable_scopes: vec!["openid".to_owned()],
            ..open()
        };
        assert_eq!(
            complete(change_realm_settings(
                &scenario.app,
                &narrow,
                want(opened.clone())
            )),
            Ok(opened.clone())
        );
        assert_eq!(
            complete(super::read_realm_settings(&scenario.app, &narrow)),
            Ok(opened)
        );
        let changed = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rfind(|event| event["kind"] == "realm.settings_changed")
            .expect("the change is in the chain");
        assert_eq!(
            changed["payload"],
            json!({
                "actor": { "client_id": "operator" },
                "max_daily_registrations": 100,
                "max_redirect_uris": 5,
                "max_registered_clients": 100,
                "registrable_scopes": ["openid"],
                "registration": "open",
            })
        );
    }

    #[test]
    fn an_operator_who_holds_only_the_right_to_write_the_realm_closes_registration() {
        let scenario = Scenario::start();
        let wide = scenario.name_operator(&[Capability::RealmWrite, Capability::UserRead]);
        complete(change_realm_settings(&scenario.app, &wide, want(open()))).expect("opened");
        let token = complete(create_administrator(
            &scenario.app,
            "acme",
            scenario.scope,
            "narrow",
            &[Capability::RealmWrite],
        ));
        let narrow = complete(authorize_admin_call(
            &scenario.app,
            "acme",
            Some(&token),
            Capability::RealmWrite,
        ))
        .expect("an administrator");

        assert_eq!(
            complete(change_realm_settings(
                &scenario.app,
                &narrow,
                want(RealmSettings::default())
            ))
            .map(|settings| settings.registration),
            Ok(RegistrationPolicy::Closed),
            "the scopes it keeps hand out nothing while it is closed"
        );
        assert_eq!(
            complete(change_realm_settings(&scenario.app, &narrow, want(open())))
                .map_err(|failure| failure.code),
            Err(ErrorCode::CapabilityMissing),
            "opened again, it hands out the email of a person"
        );
        complete(change_realm_settings(&scenario.app, &wide, want(open()))).expect("opened");
        assert_eq!(
            complete(change_realm_settings(
                &scenario.app,
                &narrow,
                want(RealmSettings {
                    max_redirect_uris: 2,
                    ..open()
                })
            ))
            .map(|settings| settings.max_redirect_uris),
            Ok(2),
            "what the realm hands out already is no scope added"
        );
    }
}
