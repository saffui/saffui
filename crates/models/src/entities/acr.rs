//! Authentication context: how strongly, and how recently.
//!
//! Four OIDC Core parameters that look separate and are one question. Is this
//! authentication good enough for what the client is about to do?
//!
//! - `acr_values` asks for a level of assurance.
//! - `max_age` asks for a recent one.
//! - `prompt=login` asks for a fresh one regardless.
//! - the `acr` claim reports what was actually achieved.
//!
//! # The failure this module exists to prevent
//!
//! Reporting an `acr` that was requested rather than reached. A relying party
//! reads that claim to decide whether to release money, and a server echoing
//! back whatever was asked for turns the whole mechanism into decoration.
//! Requested and achieved are separate types here so the two cannot be confused
//! by accident.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::str_enum::str_enum;

/// A realm's map from `acr` values to levels of assurance.
///
/// The `acr` strings are opaque and deployment defined, such as
/// `urn:mace:incommon:iap:silver` or `gold` or `2`, while the level is an
/// integer that orders them. The ordering is the point: a request for a level is
/// satisfied by any authentication at that level or above, and without a numeric
/// ordering "is this good enough" has no answer.
///
/// Serialised as the bare map, `{"password": 1, "mfa": 2}`. The wrapper exists to
/// hang behaviour on and is not part of the data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AcrLoaMap {
    /// A `BTreeMap` so iteration is stable. The highest matching value is what
    /// gets reported, and hashing order would make that depend on the build.
    entries: BTreeMap<String, i32>,
}

impl AcrLoaMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from pairs. Last wins on a duplicate.
    pub fn from_pairs<I, S>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (S, i32)>,
        S: Into<String>,
    {
        AcrLoaMap {
            entries: pairs.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        }
    }

    pub fn insert(&mut self, acr: impl Into<String>, loa: i32) {
        self.entries.insert(acr.into(), loa);
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every `acr` value this realm defines, weakest first.
    ///
    /// Ordered by level rather than by name because this is what discovery
    /// advertises. A client asking for the weakest acceptable reads the front of
    /// the list, and alphabetical order would make that meaningless.
    pub fn values_by_level(&self) -> Vec<&str> {
        let mut pairs: Vec<(&str, i32)> =
            self.entries.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        pairs.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(b.0)));
        pairs.into_iter().map(|(k, _)| k).collect()
    }

    /// The level an `acr` value denotes, if the realm maps it.
    ///
    /// `None` for an unmapped value, which is not level zero. A client asking for
    /// an `acr` this realm has never heard of is asking for something undefined,
    /// and reading that as "no requirement" grants what was meant to constrain.
    pub fn loa_of(&self, acr: &str) -> Option<i32> {
        self.entries.get(acr).copied()
    }

    /// The highest level `acr` value this realm maps at or below `loa`.
    ///
    /// This is what the `acr` claim reports: the strongest name the realm has for
    /// what was actually reached.
    pub fn acr_for_loa(&self, loa: i32) -> Option<&str> {
        self.entries
            .iter()
            .filter(|(_, l)| **l <= loa)
            .max_by_key(|(_, l)| **l)
            .map(|(acr, _)| acr.as_str())
    }
}

str_enum! {
    /// How hard a client is asking.
    ///
    /// OIDC Core distinguishes these and the distinction is load bearing.
    /// `acr_values` is voluntary, a hint the provider may ignore, while an `acr`
    /// claim marked essential in the `claims` parameter must be met or the
    /// request fails. Reading a voluntary request as essential breaks logins
    /// that would have succeeded. Reading an essential one as voluntary silently
    /// downgrades security, which is the direction that matters.
    pub enum AcrRequirement {
        /// From `acr_values`. Best effort: authenticate as strongly as possible,
        /// but do not fail for missing it.
        Voluntary => "voluntary",
        /// From `claims: {"id_token": {"acr": {"essential": true}}}`. Must be met.
        Essential => "essential",
    }
}

/// What a client asked for, before anything has been attempted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthContextRequest {
    /// Requested `acr` values in order of preference, as the client wrote them.
    pub acr_values: Vec<String>,
    pub requirement: AcrRequirement,
    /// How old the authentication may be, in seconds. A number rather than a
    /// flag because zero is a value and not an absence: it admits only an
    /// authentication in this very second, which `prompt=login` does not express.
    pub max_age: Option<i64>,
    /// `prompt=login` was requested.
    pub prompt_login: bool,
}

impl AuthContextRequest {
    /// Nothing requested: any live session satisfies it.
    pub fn none() -> Self {
        AuthContextRequest {
            acr_values: Vec::new(),
            requirement: AcrRequirement::Voluntary,
            max_age: None,
            prompt_login: false,
        }
    }

    /// Parse the space separated `acr_values` parameter.
    pub fn with_acr_values(mut self, raw: &str, requirement: AcrRequirement) -> Self {
        self.acr_values = raw.split_whitespace().map(str::to_string).collect();
        self.requirement = requirement;
        self
    }

    /// The minimum level that satisfies this request, under a realm's map.
    ///
    /// The lowest of the requested values, not the highest. `acr_values` is
    /// ordered by preference and any of them is acceptable to the client, so
    /// demanding the strongest would fail logins the client would have accepted.
    pub fn required_loa(&self, map: &AcrLoaMap) -> Option<i32> {
        self.acr_values
            .iter()
            .filter_map(|acr| map.loa_of(acr))
            .min()
    }

    /// Whether any requested `acr` is one this realm knows.
    pub fn names_a_known_acr(&self, map: &AcrLoaMap) -> bool {
        self.acr_values.iter().any(|a| map.loa_of(a).is_some())
    }
}

/// What was actually achieved, which is a different thing from what was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AchievedAuth {
    /// The level the authentication actually reached.
    pub loa: i32,
    /// When it happened, Unix epoch seconds. The `auth_time` claim.
    pub auth_time: i64,
}

/// Why a re-authentication is being asked for.
///
/// The two are not interchangeable, because only one of them is guaranteed to
/// terminate. Re-authenticating for freshness always converges: it moves
/// `auth_time` to now, so the next pass is satisfied. Re-authenticating for a
/// level converges only if the server can drive the flow to that level, and one
/// that cannot but redirects anyway sends the user around the login page forever.
///
/// `to_loa` alone cannot carry this. It holds the target level in every case,
/// including the freshness ones, so a caller matching on it would swallow
/// `prompt=login`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReauthReason {
    /// `prompt=login`, or `max_age` exceeded. Converges.
    Freshness,
    /// The session's level is below what was requested. Converges only if the
    /// caller can drive the authentication to `to_loa`.
    Level,
}

/// What the server must do about a request, given what it already has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    /// The existing session satisfies everything asked.
    Satisfied,
    /// Re-authenticate, at least to this level. `None` means any level: the
    /// session is merely too old, or `prompt=login` was asked.
    Reauthenticate {
        to_loa: Option<i32>,
        because: ReauthReason,
    },
    /// No authentication this realm offers can satisfy the request: an essential
    /// `acr` naming only values the realm does not map.
    ///
    /// Carries the values rather than a sentence built from them. They came off
    /// a request, and whether they are safe to show a client or to write to a log
    /// is not a decision a model gets to make on the caller's behalf.
    Unsatisfiable { requested: Vec<String> },
}

/// Decide what to do with an existing session, if any.
///
/// The order is deliberate and each step closes something.
///
/// 1. An essential request naming nothing this realm maps is unsatisfiable.
///    Failing now beats authenticating the user and failing afterwards.
/// 2. `prompt=login` re-authenticates unconditionally. It is the client saying
///    "prove it again", and honouring it only for an old session would make it
///    useless for the case it exists for.
/// 3. `max_age` compares against `auth_time`, not against session start. A
///    session refreshed for an hour is not a recent authentication, and
///    conflating them is how `max_age` silently stops working.
/// 4. The level check comes last, because it is the only one that can be met by
///    stepping up rather than starting over.
pub fn decide(
    request: &AuthContextRequest,
    map: &AcrLoaMap,
    session: Option<AchievedAuth>,
    now: i64,
) -> AuthDecision {
    if request.requirement == AcrRequirement::Essential
        && !request.acr_values.is_empty()
        && !request.names_a_known_acr(map)
    {
        return AuthDecision::Unsatisfiable {
            requested: request.acr_values.clone(),
        };
    }

    let required = request.required_loa(map);

    let Some(current) = session else {
        // No session at all. This is a first authentication, not a step up.
        return AuthDecision::Reauthenticate {
            to_loa: required,
            because: ReauthReason::Freshness,
        };
    };

    if request.prompt_login {
        return AuthDecision::Reauthenticate {
            to_loa: required,
            because: ReauthReason::Freshness,
        };
    }

    if let Some(max_age) = request.max_age {
        // Strictly greater, as OIDC Core §3.1.2.1 states it: an authentication
        // exactly `max_age` old still satisfies the request.
        if now - current.auth_time > max_age {
            return AuthDecision::Reauthenticate {
                to_loa: required,
                because: ReauthReason::Freshness,
            };
        }
    }

    match required {
        Some(needed) if current.loa < needed => AuthDecision::Reauthenticate {
            to_loa: Some(needed),
            because: ReauthReason::Level,
        },
        _ => AuthDecision::Satisfied,
    }
}

/// The `acr` claim to put in a token, for what was actually achieved.
///
/// The realm's strongest name at or below the achieved level, never the
/// requested value. `None` when the realm maps nothing at or below it, in which
/// case the claim is omitted rather than guessed: an absent `acr` is a claim
/// about nothing, while a wrong one is a false attestation.
pub fn acr_claim(map: &AcrLoaMap, achieved: AchievedAuth) -> Option<&str> {
    map.acr_for_loa(achieved.loa)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;

    fn realm_map() -> AcrLoaMap {
        AcrLoaMap::from_pairs([("password", 1), ("mfa", 2), ("hardware", 3)])
    }

    fn session(loa: i32, auth_time: i64) -> Option<AchievedAuth> {
        Some(AchievedAuth { loa, auth_time })
    }

    fn achieved(loa: i32) -> AchievedAuth {
        AchievedAuth { loa, auth_time: 0 }
    }

    #[test]
    fn the_requirement_agrees_with_its_own_spelling() {
        assert_eq!(AcrRequirement::ALL.len(), 2);
        assert_eq!(AcrRequirement::Voluntary.as_str(), "voluntary");
        assert_eq!(AcrRequirement::Essential.as_str(), "essential");
        assert_round_trips(AcrRequirement::ALL);
    }

    /// The claim reports what was reached, never what was asked. A relying party
    /// reads it to decide whether to release money.
    #[test]
    fn the_acr_claim_reports_what_was_achieved_not_what_was_requested() {
        let map = realm_map();

        assert_eq!(acr_claim(&map, achieved(1)), Some("password"));
        assert_eq!(acr_claim(&map, achieved(2)), Some("mfa"));
        assert_eq!(acr_claim(&map, achieved(3)), Some("hardware"));
        assert_eq!(
            acr_claim(&map, achieved(99)),
            Some("hardware"),
            "above every mapped level, still the strongest known name"
        );
        assert_eq!(
            acr_claim(&map, achieved(0)),
            None,
            "below every mapped level, omitted rather than guessed"
        );
    }

    /// `acr_values` is ordered by preference and any of them is acceptable, so
    /// the requirement is the lowest mapped level. Demanding the highest would
    /// fail logins the client would have accepted.
    #[test]
    fn the_requirement_is_the_weakest_acceptable_level() {
        let map = realm_map();

        let both =
            AuthContextRequest::none().with_acr_values("hardware mfa", AcrRequirement::Voluntary);
        assert_eq!(both.required_loa(&map), Some(2));

        let mixed = AuthContextRequest::none()
            .with_acr_values("unknown-scheme mfa", AcrRequirement::Voluntary);
        assert_eq!(
            mixed.required_loa(&map),
            Some(2),
            "an unmapped value does not lower the requirement"
        );

        let unknown = AuthContextRequest::none()
            .with_acr_values("unknown-a unknown-b", AcrRequirement::Voluntary);
        assert_eq!(unknown.required_loa(&map), None);
    }

    /// An essential request naming nothing the realm maps cannot be satisfied by
    /// any authentication, so it fails before the user is asked for anything.
    #[test]
    fn an_essential_unknown_acr_fails_before_authenticating() {
        let map = realm_map();
        let essential = AuthContextRequest::none()
            .with_acr_values("urn:example:nonexistent", AcrRequirement::Essential);

        assert_eq!(
            decide(&essential, &map, None, 1_000),
            AuthDecision::Unsatisfiable {
                requested: vec!["urn:example:nonexistent".to_owned()]
            },
            "the values are carried as data, not built into a sentence"
        );

        let voluntary = AuthContextRequest::none()
            .with_acr_values("urn:example:nonexistent", AcrRequirement::Voluntary);
        assert_eq!(
            decide(&voluntary, &map, session(1, 1_000), 1_000),
            AuthDecision::Satisfied,
            "a voluntary request must not fail a login that would have worked"
        );
    }

    /// `prompt=login` means prove it again, unconditionally. Honouring it only
    /// for an old session would make it useless for the case it exists for: a
    /// bank asking for a fresh proof seconds after login.
    #[test]
    fn prompt_login_reauthenticates_however_fresh_the_session() {
        let map = realm_map();

        let bare = AuthContextRequest {
            prompt_login: true,
            ..AuthContextRequest::none()
        };
        assert_eq!(
            decide(&bare, &map, session(3, 999), 1_000),
            AuthDecision::Reauthenticate {
                to_loa: None,
                because: ReauthReason::Freshness
            }
        );

        let levelled = AuthContextRequest {
            prompt_login: true,
            ..AuthContextRequest::none().with_acr_values("mfa", AcrRequirement::Voluntary)
        };
        assert_eq!(
            decide(&levelled, &map, session(3, 999), 1_000),
            AuthDecision::Reauthenticate {
                to_loa: Some(2),
                because: ReauthReason::Freshness
            },
            "the level is where to get back to, not why we are going"
        );
    }

    /// `max_age` measures the authentication, not the session. A session
    /// refreshed for an hour is not a recent authentication, and conflating the
    /// two is how it silently stops working.
    #[test]
    fn max_age_measures_the_authentication_not_the_session() {
        let map = realm_map();
        let request = AuthContextRequest {
            max_age: Some(300),
            ..AuthContextRequest::none()
        };

        assert_eq!(
            decide(&request, &map, session(1, 701), 1_000),
            AuthDecision::Satisfied
        );
        assert_eq!(
            decide(&request, &map, session(1, 700), 1_000),
            AuthDecision::Satisfied,
            "the boundary is no older than, so exactly at it is fresh"
        );
        assert_eq!(
            decide(&request, &map, session(1, 699), 1_000),
            AuthDecision::Reauthenticate {
                to_loa: None,
                because: ReauthReason::Freshness
            }
        );
    }

    /// `max_age=0` is a value a client sends, not an absent one, and it means
    /// always re-authenticate.
    #[test]
    fn max_age_zero_always_reauthenticates() {
        let map = realm_map();
        let zero = AuthContextRequest {
            max_age: Some(0),
            ..AuthContextRequest::none()
        };

        assert_eq!(
            decide(&zero, &map, session(3, 1_000), 1_000),
            AuthDecision::Satisfied,
            "authenticated this very second"
        );
        assert_eq!(
            decide(&zero, &map, session(3, 999), 1_000),
            AuthDecision::Reauthenticate {
                to_loa: None,
                because: ReauthReason::Freshness
            }
        );
        assert_eq!(
            decide(&AuthContextRequest::none(), &map, session(3, 0), 1_000),
            AuthDecision::Satisfied,
            "no max_age at all is not the same thing as zero"
        );
    }

    /// A session below the requested level steps up, at or above it passes. This
    /// is the only check that can be met by strengthening rather than starting
    /// over, which is why it runs last.
    #[test]
    fn a_weaker_session_steps_up_and_a_stronger_one_passes() {
        let map = realm_map();
        let request = AuthContextRequest::none().with_acr_values("mfa", AcrRequirement::Voluntary);

        assert_eq!(
            decide(&request, &map, session(1, 1_000), 1_000),
            AuthDecision::Reauthenticate {
                to_loa: Some(2),
                because: ReauthReason::Level
            }
        );
        assert_eq!(
            decide(&request, &map, session(2, 1_000), 1_000),
            AuthDecision::Satisfied,
            "exactly at the level"
        );
        assert_eq!(
            decide(&request, &map, session(3, 1_000), 1_000),
            AuthDecision::Satisfied,
            "a stronger authentication satisfies a weaker requirement"
        );
    }

    /// No session at all is a first authentication, not a step up, however high
    /// the requested level.
    #[test]
    fn no_session_authenticates_at_the_requested_level() {
        let map = realm_map();

        assert_eq!(
            decide(&AuthContextRequest::none(), &map, None, 1_000),
            AuthDecision::Reauthenticate {
                to_loa: None,
                because: ReauthReason::Freshness
            }
        );

        let high =
            AuthContextRequest::none().with_acr_values("hardware", AcrRequirement::Essential);
        assert_eq!(
            decide(&high, &map, None, 1_000),
            AuthDecision::Reauthenticate {
                to_loa: Some(3),
                because: ReauthReason::Freshness
            }
        );
    }

    /// An unmapped acr is not level zero. Reading it as no requirement would
    /// grant what was meant to constrain.
    #[test]
    fn an_unmapped_acr_is_not_a_zero_requirement() {
        let map = realm_map();
        assert_eq!(map.loa_of("mfa"), Some(2));
        assert_eq!(map.loa_of("nonexistent"), None);

        let empty = AcrLoaMap::new();
        assert!(empty.is_empty());
        let request = AuthContextRequest::none().with_acr_values("mfa", AcrRequirement::Essential);
        assert!(!request.names_a_known_acr(&empty));
        assert!(matches!(
            decide(&request, &empty, session(9, 1_000), 1_000),
            AuthDecision::Unsatisfiable { .. }
        ));
    }

    /// Discovery advertises the values weakest first, because a client picking
    /// the weakest acceptable reads the front of the list.
    #[test]
    fn discovery_lists_the_values_weakest_first() {
        assert_eq!(
            realm_map().values_by_level(),
            vec!["password", "mfa", "hardware"]
        );

        // Ties break by name, so the list does not depend on insertion order.
        let tied = AcrLoaMap::from_pairs([("zebra", 1), ("alpha", 1), ("top", 2)]);
        assert_eq!(tied.values_by_level(), vec!["alpha", "zebra", "top"]);
    }

    /// Parsing follows the parameter's own format: space separated, order kept.
    #[test]
    fn acr_values_parse_as_a_space_separated_preference_list() {
        let spaced = AuthContextRequest::none()
            .with_acr_values("  hardware   mfa password ", AcrRequirement::Voluntary);
        assert_eq!(spaced.acr_values, vec!["hardware", "mfa", "password"]);

        let blank = AuthContextRequest::none().with_acr_values("   ", AcrRequirement::Voluntary);
        assert!(blank.acr_values.is_empty());
    }

    /// Freshness and an unmet level must be distinguishable even when both carry
    /// the same target level.
    ///
    /// `decide` reports the target on every re-authentication, freshness ones
    /// included. A caller deciding by matching on `to_loa: Some(_)` would read
    /// `prompt=login` as an unmet level, and a caller that correctly declines to
    /// loop on unmet levels would then swallow it. That is why the reason is
    /// carried rather than inferred.
    #[test]
    fn the_reason_distinguishes_freshness_from_an_unmet_level() {
        let map = realm_map();
        let asked_for_mfa =
            AuthContextRequest::none().with_acr_values("mfa", AcrRequirement::Voluntary);

        let prompted = AuthContextRequest {
            prompt_login: true,
            ..asked_for_mfa.clone()
        };
        assert_eq!(
            decide(&prompted, &map, session(2, 1_000), 1_100),
            AuthDecision::Reauthenticate {
                to_loa: Some(2),
                because: ReauthReason::Freshness,
            },
            "prompt=login is freshness even when a level was also requested"
        );

        let stale = AuthContextRequest {
            max_age: Some(10),
            ..asked_for_mfa.clone()
        };
        assert_eq!(
            decide(&stale, &map, session(2, 1_000), 1_100),
            AuthDecision::Reauthenticate {
                to_loa: Some(2),
                because: ReauthReason::Freshness,
            }
        );

        assert_eq!(
            decide(&asked_for_mfa, &map, session(1, 1_000), 1_100),
            AuthDecision::Reauthenticate {
                to_loa: Some(2),
                because: ReauthReason::Level,
            },
            "only an actually insufficient level reports a level"
        );
    }
}
