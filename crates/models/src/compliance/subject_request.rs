//! Requests a data subject makes about their own data.
//!
//! Five kinds, and collapsing any two of them is the mistake that matters.
//! Objection is what someone who wants to keep their account but not be profiled
//! is asking for, and reading it as erasure turns "stop emailing me" into a
//! deleted account.

use serde::{Deserialize, Serialize};

use crate::str_enum::str_enum;

str_enum! {
    /// What a subject is asking for.
    pub enum DsarKind {
        /// What do you hold about me.
        Access => "access",
        /// This is wrong, fix it.
        Rectification => "rectification",
        /// Delete me.
        Erasure => "erasure",
        /// Stop doing this particular thing with my data, without deletion.
        Objection => "objection",
        /// Give it to me in a form I can hand to someone else.
        Portability => "portability",
    }
}

impl DsarKind {
    /// Whether fulfilling this changes what is stored.
    ///
    /// Two of them are reads. The other three write, which is why an identity
    /// has to be proven before one is executed: an unverified erasure is an
    /// account deletion anyone who can send a form could reach.
    pub fn is_mutating(self) -> bool {
        matches!(self, Self::Rectification | Self::Erasure | Self::Objection)
    }
}

str_enum! {
    /// Where a request stands, without what it produced.
    pub enum DsarStage {
        /// Lodged, and the subject not yet proven to be who they claim.
        Received => "received",
        /// Identity proven. Only now may a request that writes be executed.
        Verified => "verified",
        Fulfilled => "fulfilled",
        Refused => "refused",
    }
}

impl DsarStage {
    /// Whether a request in this stage is closed.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Fulfilled | Self::Refused)
    }
}

/// Where a request stands, with what closing it produced.
///
/// The outcome lives in the variant. Held in a field beside the stage, a refusal
/// with no reason is representable, and a subject is entitled to the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "lowercase")]
pub enum DsarStatus {
    Received,
    Verified,
    /// Closed, with a record of what was done.
    Fulfilled {
        outcome: String,
    },
    /// Closed, with the reason the subject is owed.
    Refused {
        reason: String,
    },
}

impl DsarStatus {
    pub fn stage(&self) -> DsarStage {
        match self {
            Self::Received => DsarStage::Received,
            Self::Verified => DsarStage::Verified,
            Self::Fulfilled { .. } => DsarStage::Fulfilled,
            Self::Refused { .. } => DsarStage::Refused,
        }
    }
}

/// Where a jurisdiction's response deadline comes from.
///
/// Recorded beside the number because the two are not equally trustworthy. A
/// value read from a statute can be cited in a filing; a value someone assumed
/// cannot, and the two look identical once they are an integer in a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineSource {
    /// Read from the primary text. The citation is what a filing quotes.
    Statute(&'static str),
    /// The law is known and fixes no window. A due date has to be supplied per
    /// request, usually from the controller's own policy, which is what a
    /// regulator will hold them to.
    Unspecified(&'static str),
    /// Not a jurisdiction this build knows.
    Unknown,
}

str_enum! {
    /// The jurisdictions whose law has been read.
    ///
    /// Only what was actually found is here. Several are listed with no deadline,
    /// not because they have none but because it could not be read from an
    /// accessible source, which is a different statement and the one an operator
    /// needs.
    ///
    /// The windows range from seven days to forty-five. A default drawn from the
    /// nearest neighbour would be wrong by a factor of six, which is why the
    /// number is optional and a caller has to handle its absence rather than
    /// fall back.
    pub enum Jurisdiction {
        Kenya => "ke",
        Nigeria => "ng",
        SouthAfrica => "za",
        Ghana => "gh",
        Togo => "tg",
        Benin => "bj",
        CoteDIvoire => "ci",
        BurkinaFaso => "bf",
        Gabon => "ga",
        Cameroon => "cm",
        Eu => "eu",
        /// Anything else. The deadline has to be supplied.
        Other => "other",
    }
}

impl Jurisdiction {
    /// The response window in days, where one was read from the law.
    pub fn response_days(self) -> Option<i64> {
        match self {
            Self::Kenya => Some(7),
            Self::Ghana => Some(21),
            Self::SouthAfrica => Some(30),
            // One month, taken as thirty days. The texts say a month, and a
            // month-accurate calculation belongs in a calendar rather than in a
            // constant that would be wrong in February either way.
            Self::Togo | Self::Eu => Some(30),
            Self::Benin => Some(45),
            Self::Nigeria
            | Self::CoteDIvoire
            | Self::BurkinaFaso
            | Self::Gabon
            | Self::Cameroon
            | Self::Other => None,
        }
    }

    /// Where that window comes from, cited.
    pub fn deadline_source(self) -> DeadlineSource {
        match self {
            Self::Kenya => DeadlineSource::Statute(
                "Data Protection (General) Regulations 2021, reg. 9(4), seven days. \
                 The deadline is in the Regulations rather than the 2019 Act.",
            ),
            Self::Ghana => {
                DeadlineSource::Statute("Data Protection Act 2012 (Act 843), s. 39(2), 21 days")
            }
            Self::SouthAfrica => DeadlineSource::Statute(
                "POPIA s. 23 routes access requests through PAIA, which fixes 30 days, \
                 extendable once by 30. A missed deadline is a deemed refusal.",
            ),
            Self::Togo => DeadlineSource::Statute(
                "Loi 2019-014, art. 46 and 47, one month, then the authority rules \
                 within three weeks",
            ),
            Self::Benin => {
                DeadlineSource::Statute("Code du numérique (loi 2017-20), art. 441, 45 days")
            }
            Self::Eu => DeadlineSource::Statute("GDPR art. 12(3), one month, extendable by two"),
            Self::Nigeria => DeadlineSource::Unspecified(
                "The NDPA 2023 and its implementation directive require a controller \
                 to be promptly responsive to requests and fix no number. Do not \
                 assume thirty days: promptly is the stricter obligation.",
            ),
            Self::CoteDIvoire => DeadlineSource::Unspecified(
                "Loi 2013-450 grants the rights and fixes no window in a source that \
                 could be read.",
            ),
            Self::BurkinaFaso => DeadlineSource::Unspecified(
                "Loi 001-2021 grants the rights and fixes no window in a source that \
                 could be read. The 2004 law it replaced is repealed.",
            ),
            Self::Gabon => DeadlineSource::Unspecified(
                "Loi 001/2011 grants the rights and fixes no window in a source that \
                 could be read.",
            ),
            Self::Cameroon => DeadlineSource::Unspecified(
                "Loi 2024/017 grants the rights and fixes no window in a source that \
                 could be read.",
            ),
            Self::Other => DeadlineSource::Unknown,
        }
    }
}

/// Why a request could not be lodged or advanced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DsarError {
    #[error("a subject request needs a {0}")]
    Missing(&'static str),
    #[error("{jurisdiction} fixes no window, so a due date has to be given")]
    DeadlineRequired { jurisdiction: Jurisdiction },
    #[error("a request cannot go from {from} to {to}")]
    InvalidTransition { from: DsarStage, to: DsarStage },
    #[error(
        "a {kind} request changes stored data and must not be executed before the \
         subject's identity is proven"
    )]
    NotVerified { kind: DsarKind },
}

/// What identifies a request when it is lodged.
#[derive(Debug, Clone)]
pub struct DsarLodgement {
    pub request_id: String,
    pub tenant: String,
    pub realm_id: String,
    /// What the requester gave to identify themselves.
    pub subject_identifier: String,
    pub kind: DsarKind,
    pub jurisdiction: Jurisdiction,
    /// Supplies the deadline where the jurisdiction fixes none, and shortens it
    /// where the controller's own policy is tighter than the law.
    pub due_override: Option<i64>,
}

/// A lodged request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsarRequest {
    pub request_id: String,
    pub tenant: String,
    pub realm_id: String,
    /// The subject, once resolved. A request may be lodged against an address
    /// before the account behind it is known.
    pub user_id: Option<String>,
    pub subject_identifier: String,
    pub kind: DsarKind,
    #[serde(flatten)]
    pub status: DsarStatus,
    pub jurisdiction: Jurisdiction,
    /// Unix epoch seconds.
    pub received_at: i64,
    /// When the clock runs out.
    pub due_at: i64,
    pub verified_at: Option<i64>,
    pub closed_at: Option<i64>,
}

impl DsarRequest {
    /// Lodge a request.
    pub fn lodge(lodgement: DsarLodgement, now: i64) -> Result<Self, DsarError> {
        let due_at = match (
            lodgement.due_override,
            lodgement.jurisdiction.response_days(),
        ) {
            (Some(explicit), _) => explicit,
            (None, Some(days)) => now + days * 86_400,
            (None, None) => {
                return Err(DsarError::DeadlineRequired {
                    jurisdiction: lodgement.jurisdiction,
                });
            }
        };

        Ok(DsarRequest {
            request_id: non_empty(lodgement.request_id, "request_id")?,
            tenant: non_empty(lodgement.tenant, "tenant")?,
            realm_id: non_empty(lodgement.realm_id, "realm_id")?,
            user_id: None,
            subject_identifier: non_empty(lodgement.subject_identifier, "subject_identifier")?,
            kind: lodgement.kind,
            status: DsarStatus::Received,
            jurisdiction: lodgement.jurisdiction,
            received_at: now,
            due_at,
            verified_at: None,
            closed_at: None,
        })
    }

    /// Whether the lifecycle allows moving to `next`.
    ///
    /// This table is what keeps an unverified request that writes from being
    /// executed. A read only request can be refused without proof of identity,
    /// and nothing can be fulfilled before it.
    pub fn can_transition_to(&self, next: DsarStage) -> bool {
        matches!(
            (self.status.stage(), next),
            (DsarStage::Received, DsarStage::Verified)
                | (
                    DsarStage::Received | DsarStage::Verified,
                    DsarStage::Refused
                )
                | (DsarStage::Verified, DsarStage::Fulfilled)
        )
    }

    /// Record that the subject proved who they are.
    pub fn verify(&mut self, now: i64) -> Result<(), DsarError> {
        self.check(DsarStage::Verified)?;
        self.status = DsarStatus::Verified;
        self.verified_at = Some(now);
        Ok(())
    }

    /// Close as fulfilled, recording what was done.
    pub fn fulfil(&mut self, outcome: impl Into<String>, now: i64) -> Result<(), DsarError> {
        // The transition table already refuses this, and a separate answer says
        // which rule was broken rather than that some rule was.
        if self.kind.is_mutating() && self.status.stage() != DsarStage::Verified {
            return Err(DsarError::NotVerified { kind: self.kind });
        }
        self.check(DsarStage::Fulfilled)?;
        self.status = DsarStatus::Fulfilled {
            outcome: non_empty(outcome, "outcome")?,
        };
        self.closed_at = Some(now);
        Ok(())
    }

    /// Close as refused, with the reason the subject is owed.
    pub fn refuse(&mut self, reason: impl Into<String>, now: i64) -> Result<(), DsarError> {
        self.check(DsarStage::Refused)?;
        self.status = DsarStatus::Refused {
            reason: non_empty(reason, "reason")?,
        };
        self.closed_at = Some(now);
        Ok(())
    }

    /// Whether the clock has run out at `now`, for a request still open.
    pub fn is_overdue(&self, now: i64) -> bool {
        !self.status.stage().is_terminal() && now > self.due_at
    }

    fn check(&self, next: DsarStage) -> Result<(), DsarError> {
        if self.can_transition_to(next) {
            Ok(())
        } else {
            Err(DsarError::InvalidTransition {
                from: self.status.stage(),
                to: next,
            })
        }
    }
}

fn non_empty(value: impl Into<String>, field: &'static str) -> Result<String, DsarError> {
    let value: String = value.into();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(DsarError::Missing(field));
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;

    fn lodgement(kind: DsarKind, jurisdiction: Jurisdiction) -> DsarLodgement {
        DsarLodgement {
            request_id: "dsar-1".into(),
            tenant: "acme".into(),
            realm_id: "realm-1".into(),
            subject_identifier: "ada@example.test".into(),
            kind,
            jurisdiction,
            due_override: None,
        }
    }

    fn lodged(kind: DsarKind) -> DsarRequest {
        DsarRequest::lodge(lodgement(kind, Jurisdiction::Kenya), 1_000).expect("a complete request")
    }

    #[test]
    fn the_catalogues_agree_with_their_own_spelling() {
        assert_eq!(DsarKind::ALL.len(), 5);
        assert_eq!(DsarStage::ALL.len(), 4);
        assert_eq!(Jurisdiction::ALL.len(), 12);
        assert_round_trips(DsarKind::ALL);
        assert_round_trips(DsarStage::ALL);
        assert_round_trips(Jurisdiction::ALL);
    }

    /// Objection is not erasure. Reading one as the other turns "stop emailing
    /// me" into a deleted account, which is the mistake this catalogue exists to
    /// prevent.
    #[test]
    fn no_two_kinds_share_a_spelling_and_objection_is_its_own() {
        let mut spellings: Vec<&str> = DsarKind::ALL.iter().map(|k| k.as_str()).collect();
        let count = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), count);
        assert_ne!(DsarKind::Objection, DsarKind::Erasure);
    }

    /// Exactly the three that write are the three that need proof of identity.
    #[test]
    fn exactly_the_writing_kinds_are_mutating() {
        let mutating: Vec<&DsarKind> = DsarKind::ALL.iter().filter(|k| k.is_mutating()).collect();
        assert_eq!(
            mutating,
            vec![
                &DsarKind::Rectification,
                &DsarKind::Erasure,
                &DsarKind::Objection
            ]
        );
        assert!(!DsarKind::Access.is_mutating(), "an export reads");
        assert!(!DsarKind::Portability.is_mutating());
    }

    /// A window that was read from a statute and a window nobody found are
    /// different answers, and only one of them can be cited.
    #[test]
    fn a_window_nobody_found_is_not_a_window_of_thirty_days() {
        assert_eq!(Jurisdiction::Kenya.response_days(), Some(7));
        assert_eq!(Jurisdiction::Benin.response_days(), Some(45));
        assert_eq!(
            Jurisdiction::Nigeria.response_days(),
            None,
            "promptly is stricter than any number, and assuming one is indefensible"
        );

        for jurisdiction in Jurisdiction::ALL {
            match (jurisdiction.response_days(), jurisdiction.deadline_source()) {
                (Some(_), DeadlineSource::Statute(citation)) => {
                    assert!(!citation.is_empty(), "{jurisdiction} cites nothing")
                }
                (None, DeadlineSource::Unspecified(note)) => {
                    assert!(!note.is_empty(), "{jurisdiction} says nothing")
                }
                (None, DeadlineSource::Unknown) => {
                    assert_eq!(*jurisdiction, Jurisdiction::Other)
                }
                (days, source) => panic!("{jurisdiction} has {days:?} from {source:?}"),
            }
        }
    }

    /// The windows are far enough apart that a default drawn from a neighbour
    /// would be wrong by a factor of six.
    #[test]
    fn no_window_can_stand_in_for_another() {
        let windows: Vec<i64> = Jurisdiction::ALL
            .iter()
            .filter_map(|j| j.response_days())
            .collect();
        let shortest = *windows.iter().min().unwrap();
        let longest = *windows.iter().max().unwrap();
        assert_eq!(shortest, 7);
        assert_eq!(longest, 45);
        assert!(longest > shortest * 6);
    }

    /// A jurisdiction that fixes no window refuses the request rather than
    /// inventing one, and an explicit date is accepted for it.
    #[test]
    fn a_jurisdiction_without_a_window_needs_an_explicit_date() {
        assert_eq!(
            DsarRequest::lodge(lodgement(DsarKind::Access, Jurisdiction::Nigeria), 1_000)
                .unwrap_err(),
            DsarError::DeadlineRequired {
                jurisdiction: Jurisdiction::Nigeria
            }
        );

        let supplied = DsarRequest::lodge(
            DsarLodgement {
                due_override: Some(5_000),
                ..lodgement(DsarKind::Access, Jurisdiction::Nigeria)
            },
            1_000,
        )
        .unwrap();
        assert_eq!(supplied.due_at, 5_000);

        // And a tighter policy shortens a statutory window rather than being
        // ignored in favour of it.
        let tightened = DsarRequest::lodge(
            DsarLodgement {
                due_override: Some(1_500),
                ..lodgement(DsarKind::Access, Jurisdiction::Kenya)
            },
            1_000,
        )
        .unwrap();
        assert_eq!(tightened.due_at, 1_500);
    }

    /// The statutory window is counted from when the request arrived.
    #[test]
    fn the_clock_runs_from_the_lodgement() {
        let request = lodged(DsarKind::Access);
        assert_eq!(request.received_at, 1_000);
        assert_eq!(request.due_at, 1_000 + 7 * 86_400);
        assert_eq!(request.status, DsarStatus::Received);

        assert!(!request.is_overdue(request.due_at));
        assert!(request.is_overdue(request.due_at + 1));
    }

    /// Nothing is fulfilled before the subject is proven. The table is what
    /// enforces it: an unverified erasure would be an account deletion anyone
    /// who can send a form could reach.
    #[test]
    fn nothing_is_fulfilled_before_the_subject_is_proven() {
        for kind in DsarKind::ALL {
            let mut request = lodged(*kind);
            let refused = request.fulfil("done", 2_000).unwrap_err();
            if kind.is_mutating() {
                assert_eq!(refused, DsarError::NotVerified { kind: *kind });
            } else {
                assert_eq!(
                    refused,
                    DsarError::InvalidTransition {
                        from: DsarStage::Received,
                        to: DsarStage::Fulfilled
                    },
                    "a read is refused too, by the table rather than the kind"
                );
            }
            assert_eq!(
                request.status,
                DsarStatus::Received,
                "{kind} was not closed"
            );
        }
    }

    /// The path a request may take, and the ones it may not.
    #[test]
    fn only_the_lifecycle_transitions_are_allowed() {
        let mut request = lodged(DsarKind::Erasure);
        assert!(request.verify(1_500).is_ok());
        assert_eq!(request.verified_at, Some(1_500));
        assert!(request.fulfil("tombstoned", 2_000).is_ok());
        assert_eq!(
            request.status,
            DsarStatus::Fulfilled {
                outcome: "tombstoned".into()
            }
        );
        assert_eq!(request.closed_at, Some(2_000));

        // A closed request stays closed.
        assert_eq!(
            request.verify(3_000).unwrap_err(),
            DsarError::InvalidTransition {
                from: DsarStage::Fulfilled,
                to: DsarStage::Verified
            }
        );
        assert_eq!(
            request.refuse("changed our mind", 3_000).unwrap_err(),
            DsarError::InvalidTransition {
                from: DsarStage::Fulfilled,
                to: DsarStage::Refused
            }
        );

        // Verifying twice is not a transition either.
        let mut once = lodged(DsarKind::Access);
        assert!(once.verify(1_500).is_ok());
        assert_eq!(
            once.verify(1_600).unwrap_err(),
            DsarError::InvalidTransition {
                from: DsarStage::Verified,
                to: DsarStage::Verified
            }
        );
    }

    /// A request can be refused before the subject is proven, which is how a
    /// request from someone who never comes back is closed.
    #[test]
    fn a_request_can_be_refused_from_either_open_stage() {
        let mut unproven = lodged(DsarKind::Erasure);
        assert!(unproven.refuse("identity never proven", 2_000).is_ok());
        assert_eq!(
            unproven.status,
            DsarStatus::Refused {
                reason: "identity never proven".into()
            }
        );

        let mut proven = lodged(DsarKind::Erasure);
        assert!(proven.verify(1_500).is_ok());
        assert!(proven.refuse("legal hold", 2_000).is_ok());
        assert_eq!(proven.status.stage(), DsarStage::Refused);
    }

    /// A refusal with no reason is not a refusal, and neither is a fulfilment
    /// with no record of what was done.
    #[test]
    fn closing_without_saying_what_happened_is_refused() {
        let mut request = lodged(DsarKind::Access);
        assert_eq!(
            request.refuse("   ", 2_000).unwrap_err(),
            DsarError::Missing("reason")
        );
        assert_eq!(
            request.status,
            DsarStatus::Received,
            "and the request is not closed by the attempt"
        );

        request.verify(1_500).unwrap();
        assert_eq!(
            request.fulfil("", 2_000).unwrap_err(),
            DsarError::Missing("outcome")
        );
        assert_eq!(request.status, DsarStatus::Verified);
    }

    /// A closed request stops being overdue. A clock that kept running would
    /// report every request ever refused as a breach of the window.
    #[test]
    fn a_closed_request_is_never_overdue() {
        let mut request = lodged(DsarKind::Access);
        let long_after = request.due_at + 1_000_000;
        assert!(request.is_overdue(long_after));

        request.refuse("out of scope", 2_000).unwrap();
        assert!(!request.is_overdue(long_after));

        // And the other way of closing one, which is the common way.
        let mut fulfilled = lodged(DsarKind::Access);
        assert!(fulfilled.is_overdue(long_after));
        fulfilled.verify(1_500).unwrap();
        assert!(
            fulfilled.is_overdue(long_after),
            "a verified request is still open and still on the clock"
        );
        fulfilled.fulfil("exported", 2_000).unwrap();
        assert!(!fulfilled.is_overdue(long_after));

        // Both stages that close a request are terminal, and neither open one
        // is: the clock stopping is what `is_terminal` decides.
        for stage in DsarStage::ALL {
            assert_eq!(
                stage.is_terminal(),
                matches!(stage, DsarStage::Fulfilled | DsarStage::Refused),
                "{stage}"
            );
        }
    }

    /// The status survives the wire as one value, so a stored row cannot come
    /// back refused with no reason.
    #[test]
    fn a_closed_status_cannot_decode_without_what_closed_it() {
        let mut request = lodged(DsarKind::Access);
        request.verify(1_500).unwrap();
        request.fulfil("exported", 2_000).unwrap();

        let encoded = serde_json::to_string(&request).unwrap();
        assert!(encoded.contains(r#""stage":"fulfilled""#), "{encoded}");
        assert_eq!(
            serde_json::from_str::<DsarRequest>(&encoded).unwrap(),
            request
        );

        let stripped = encoded.replace(r#""outcome":"exported","#, "");
        assert!(
            serde_json::from_str::<DsarRequest>(&stripped).is_err(),
            "a fulfilment with no record of what was done must not decode"
        );
    }

    /// Whitespace is not an identifier, and a request missing one names which.
    #[test]
    fn a_request_missing_what_identifies_it_is_refused() {
        for (field, broken) in [
            (
                "request_id",
                DsarLodgement {
                    request_id: "  ".into(),
                    ..lodgement(DsarKind::Access, Jurisdiction::Kenya)
                },
            ),
            (
                "tenant",
                DsarLodgement {
                    tenant: String::new(),
                    ..lodgement(DsarKind::Access, Jurisdiction::Kenya)
                },
            ),
            (
                "realm_id",
                DsarLodgement {
                    realm_id: " ".into(),
                    ..lodgement(DsarKind::Access, Jurisdiction::Kenya)
                },
            ),
            (
                "subject_identifier",
                DsarLodgement {
                    subject_identifier: String::new(),
                    ..lodgement(DsarKind::Access, Jurisdiction::Kenya)
                },
            ),
        ] {
            assert_eq!(
                DsarRequest::lodge(broken, 1_000).unwrap_err(),
                DsarError::Missing(field)
            );
        }
    }
}
