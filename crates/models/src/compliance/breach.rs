//! A personal data breach, from finding it to filing it.

use serde::{Deserialize, Serialize};

use crate::compliance::subject_request::Jurisdiction;
use crate::str_enum::str_enum;

str_enum! {
    /// How bad, in the controller's assessment.
    ///
    /// Drives whether the subjects are told as well as the authority, which most
    /// of these laws gate on risk rather than on a fixed rule.
    pub enum BreachSeverity {
        Low => "low",
        Medium => "medium",
        High => "high",
        Critical => "critical",
    }
}

impl BreachSeverity {
    /// Whether the affected subjects likely have to be told, and not only the
    /// authority.
    ///
    /// A starting point for the controller's judgement rather than a verdict.
    pub fn likely_requires_subject_notice(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

str_enum! {
    /// Where a breach is in its handling.
    pub enum BreachStatus {
        /// Found, not yet assessed.
        Discovered => "discovered",
        /// Scope and severity established.
        Assessed => "assessed",
        /// A person filed with the authority.
        Notified => "notified",
        /// Assessed as not meeting the threshold.
        ///
        /// A decision, recorded. "We decided not to notify, on this date, for
        /// this reason" is itself something a regulator asks for, and a breach
        /// that simply stopped moving says nothing.
        NotNotifiable => "not-notifiable",
        /// Handled and closed.
        Closed => "closed",
    }
}

impl BreachStatus {
    /// Whether the notification clock is still running.
    pub fn awaits_notification(self) -> bool {
        matches!(self, Self::Discovered | Self::Assessed)
    }
}

/// How long after discovery a breach has to be filed, where a source says.
///
/// The same discipline as the response windows: only what a source actually
/// says. Seventy-two hours is not universal, and at least one law here was read
/// in full and contains no notification duty at all. Assuming one would have a
/// controller reporting to an authority that is not expecting it, which is a
/// different mistake from reporting late.
///
/// Matched exhaustively rather than through a catch-all, so a jurisdiction added
/// later is a decision somebody makes instead of a silent absence.
pub fn notification_hours(jurisdiction: Jurisdiction) -> Option<i64> {
    match jurisdiction {
        // Without undue delay, and where feasible within seventy-two hours.
        Jurisdiction::Eu => Some(72),
        // Within seventy-two hours of becoming aware.
        Jurisdiction::Nigeria => Some(72),
        // No window read from a primary source. That includes one law read in
        // full that contains no notification duty, which is a different fact
        // from not having looked it up and one worth not overwriting.
        Jurisdiction::Kenya
        | Jurisdiction::SouthAfrica
        | Jurisdiction::Ghana
        | Jurisdiction::Togo
        | Jurisdiction::Benin
        | Jurisdiction::CoteDIvoire
        | Jurisdiction::BurkinaFaso
        | Jurisdiction::Gabon
        | Jurisdiction::Cameroon
        | Jurisdiction::Other => None,
    }
}

/// Why a breach could not be recorded or advanced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BreachError {
    #[error("a breach record needs a {0}")]
    Missing(&'static str),
    #[error("a breach cannot have been discovered before it happened")]
    ImpossibleChronology,
    #[error("a filing has to say who filed it and with whom")]
    IncompleteFiling,
    #[error("a breach cannot go from {from} to {to}")]
    InvalidTransition {
        from: BreachStatus,
        to: BreachStatus,
    },
}

/// What is known when a breach is found.
#[derive(Debug, Clone)]
pub struct BreachDiscovery {
    pub breach_id: String,
    pub tenant: String,
    pub realm_id: String,
    pub description: String,
    pub data_categories: Vec<String>,
    pub severity: BreachSeverity,
    pub jurisdiction: Jurisdiction,
    /// When it happened, if that is known yet.
    pub occurred_at: Option<i64>,
}

/// A recorded breach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreachRecord {
    pub breach_id: String,
    pub tenant: String,
    pub realm_id: String,
    pub description: String,
    pub data_categories: Vec<String>,
    /// Not yet established is a real state in the first hours, and it is not the
    /// same as none affected.
    pub subjects_affected: Option<i64>,
    pub severity: BreachSeverity,
    pub status: BreachStatus,
    pub occurred_at: Option<i64>,
    /// When the controller became aware. The clock hangs on this.
    pub discovered_at: i64,
    /// When a filing is due, settled at discovery.
    pub notify_by: Option<i64>,
    pub notified_at: Option<i64>,
    pub notified_to: Option<String>,
    /// The person who filed. Naming them is part of the record.
    pub filed_by: Option<String>,
}

impl BreachRecord {
    /// Record a breach that has been found.
    ///
    /// When it was discovered drives everything downstream, so it is required
    /// while when it happened is not: a controller usually knows when they found
    /// out long before they know when it started.
    pub fn discover(discovery: BreachDiscovery, discovered_at: i64) -> Result<Self, BreachError> {
        if discovery.occurred_at.is_some_and(|at| at > discovered_at) {
            return Err(BreachError::ImpossibleChronology);
        }

        Ok(BreachRecord {
            breach_id: non_empty(discovery.breach_id, "breach_id")?,
            tenant: non_empty(discovery.tenant, "tenant")?,
            realm_id: non_empty(discovery.realm_id, "realm_id")?,
            description: non_empty(discovery.description, "description")?,
            data_categories: discovery.data_categories,
            subjects_affected: None,
            severity: discovery.severity,
            status: BreachStatus::Discovered,
            occurred_at: discovery.occurred_at,
            discovered_at,
            // Settled now, under the law as it stands today. Absent where no
            // source fixes a window, which leaves the controller to set their
            // own rather than inherit a guess.
            notify_by: notification_hours(discovery.jurisdiction)
                .map(|hours| discovered_at + hours * 3_600),
            notified_at: None,
            notified_to: None,
            filed_by: None,
        })
    }

    /// Whether the handling allows moving to `next`.
    pub fn can_transition_to(&self, next: BreachStatus) -> bool {
        matches!(
            (self.status, next),
            (BreachStatus::Discovered, BreachStatus::Assessed)
                | (
                    BreachStatus::Assessed,
                    BreachStatus::Notified | BreachStatus::NotNotifiable
                )
                | (
                    BreachStatus::Notified | BreachStatus::NotNotifiable,
                    BreachStatus::Closed
                )
        )
    }

    /// Record the scope and the severity once they are established.
    pub fn assess(
        &mut self,
        severity: BreachSeverity,
        subjects_affected: Option<i64>,
    ) -> Result<(), BreachError> {
        self.check(BreachStatus::Assessed)?;
        self.severity = severity;
        self.subjects_affected = subjects_affected;
        self.status = BreachStatus::Assessed;
        Ok(())
    }

    /// Record that a person filed with an authority.
    ///
    /// All three facts together or none. A register saying a filing happened
    /// without saying to whom or by whom cannot evidence it, and from an
    /// auditor's seat that is the same as not having filed.
    pub fn record_filing(
        &mut self,
        notified_to: impl Into<String>,
        filed_by: impl Into<String>,
        now: i64,
    ) -> Result<(), BreachError> {
        self.check(BreachStatus::Notified)?;

        let notified_to: String = notified_to.into();
        let filed_by: String = filed_by.into();
        if notified_to.trim().is_empty() || filed_by.trim().is_empty() {
            return Err(BreachError::IncompleteFiling);
        }

        self.status = BreachStatus::Notified;
        self.notified_to = Some(notified_to.trim().to_owned());
        self.filed_by = Some(filed_by.trim().to_owned());
        self.notified_at = Some(now);
        Ok(())
    }

    /// Record the decision not to notify.
    pub fn record_not_notifiable(&mut self) -> Result<(), BreachError> {
        self.check(BreachStatus::NotNotifiable)?;
        self.status = BreachStatus::NotNotifiable;
        Ok(())
    }

    /// Close a breach that has been handled.
    pub fn close(&mut self) -> Result<(), BreachError> {
        self.check(BreachStatus::Closed)?;
        self.status = BreachStatus::Closed;
        Ok(())
    }

    /// Whether the clock has run out without a filing.
    pub fn is_overdue(&self, now: i64) -> bool {
        self.status.awaits_notification() && self.notify_by.is_some_and(|due| now > due)
    }

    /// A notification shaped for an authority's portal, addressed to nobody and
    /// filed by no one.
    ///
    /// What is outstanding is part of it. A draft that silently omits what it
    /// does not know invites someone to file it as it stands, and the two
    /// narrative fields are always missing at this point because no product can
    /// write them.
    pub fn draft_notification(&self, jurisdiction: Jurisdiction) -> DraftNotification {
        let mut outstanding = vec![
            "likely_consequences: the controller's assessment of the impact on the \
             subjects"
                .to_owned(),
            "measures_taken: what was done to contain the breach and limit its \
             effects"
                .to_owned(),
        ];
        if self.subjects_affected.is_none() {
            outstanding.push("approximate_subjects_affected: still being established".to_owned());
        }
        if self.data_categories.is_empty() {
            outstanding.push("categories_of_data: which categories were exposed".to_owned());
        }
        if notification_hours(jurisdiction).is_none() {
            outstanding.push(
                "notify_by: no window was read from this jurisdiction's law; confirm \
                 the deadline with the authority or the controller's own policy"
                    .to_owned(),
            );
        }

        DraftNotification {
            jurisdiction,
            breach_id: self.breach_id.clone(),
            nature_of_breach: self.description.clone(),
            categories_of_data: self.data_categories.clone(),
            approximate_subjects_affected: self.subjects_affected,
            became_aware_at: self.discovered_at,
            occurred_at: self.occurred_at,
            notify_by: self.notify_by,
            likely_consequences: String::new(),
            measures_taken: String::new(),
            subject_notice_likely_required: self.severity.likely_requires_subject_notice(),
            outstanding,
        }
    }

    fn check(&self, next: BreachStatus) -> Result<(), BreachError> {
        if self.can_transition_to(next) {
            Ok(())
        } else {
            Err(BreachError::InvalidTransition {
                from: self.status,
                to: next,
            })
        }
    }
}

/// A notification a person still has to finish and file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftNotification {
    pub jurisdiction: Jurisdiction,
    pub breach_id: String,
    pub nature_of_breach: String,
    pub categories_of_data: Vec<String>,
    pub approximate_subjects_affected: Option<i64>,
    pub became_aware_at: i64,
    pub occurred_at: Option<i64>,
    pub notify_by: Option<i64>,
    pub likely_consequences: String,
    pub measures_taken: String,
    pub subject_notice_likely_required: bool,
    /// What a person has to supply before this can be filed.
    pub outstanding: Vec<String>,
}

impl DraftNotification {
    /// Whether anything is still missing.
    ///
    /// A draft straight from a record is never ready. At the least the
    /// consequences and the measures are a person's account, which is why they
    /// start empty rather than filled with something plausible.
    pub fn is_ready_to_file(&self) -> bool {
        self.outstanding.is_empty()
    }
}

fn non_empty(value: impl Into<String>, field: &'static str) -> Result<String, BreachError> {
    let value: String = value.into();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(BreachError::Missing(field));
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;

    fn discovery(jurisdiction: Jurisdiction) -> BreachDiscovery {
        BreachDiscovery {
            breach_id: "breach-1".into(),
            tenant: "acme".into(),
            realm_id: "realm-1".into(),
            description: "an exposed backup".into(),
            data_categories: vec!["email".into()],
            severity: BreachSeverity::Medium,
            jurisdiction,
            occurred_at: Some(900),
        }
    }

    fn found(jurisdiction: Jurisdiction) -> BreachRecord {
        BreachRecord::discover(discovery(jurisdiction), 1_000).expect("a complete discovery")
    }

    #[test]
    fn the_catalogues_agree_with_their_own_spelling() {
        assert_eq!(BreachSeverity::ALL.len(), 4);
        assert_eq!(BreachStatus::ALL.len(), 5);
        assert_eq!(BreachStatus::NotNotifiable.as_str(), "not-notifiable");
        assert_round_trips(BreachSeverity::ALL);
        assert_round_trips(BreachStatus::ALL);
    }

    /// A window nobody read is not seventy-two hours. One of these laws was read
    /// in full and contains no notification duty at all, and assuming one has a
    /// controller reporting to an authority that is not expecting it.
    #[test]
    fn a_window_nobody_read_is_not_seventy_two_hours() {
        assert_eq!(notification_hours(Jurisdiction::Eu), Some(72));
        assert_eq!(notification_hours(Jurisdiction::Nigeria), Some(72));

        for silent in [
            Jurisdiction::Kenya,
            Jurisdiction::Togo,
            Jurisdiction::SouthAfrica,
            Jurisdiction::Ghana,
            Jurisdiction::Other,
        ] {
            assert_eq!(notification_hours(silent), None, "{silent}");
        }

        assert_eq!(
            Jurisdiction::ALL
                .iter()
                .filter(|j| notification_hours(**j).is_some())
                .count(),
            2,
            "only what a source actually says"
        );
    }

    /// The clock is settled at discovery, and only where a source fixes one.
    #[test]
    fn the_clock_is_settled_at_discovery() {
        let with_window = found(Jurisdiction::Nigeria);
        assert_eq!(with_window.discovered_at, 1_000);
        assert_eq!(with_window.notify_by, Some(1_000 + 72 * 3_600));
        assert_eq!(with_window.status, BreachStatus::Discovered);

        let without = found(Jurisdiction::Kenya);
        assert_eq!(
            without.notify_by, None,
            "the controller sets their own rather than inheriting a guess"
        );
        assert!(
            !without.is_overdue(i64::MAX),
            "and a breach with no window cannot run out of one"
        );
    }

    /// A breach cannot have been found before it happened.
    #[test]
    fn a_breach_cannot_predate_itself() {
        assert_eq!(
            BreachRecord::discover(
                BreachDiscovery {
                    occurred_at: Some(1_001),
                    ..discovery(Jurisdiction::Eu)
                },
                1_000
            )
            .unwrap_err(),
            BreachError::ImpossibleChronology
        );

        assert!(
            BreachRecord::discover(
                BreachDiscovery {
                    occurred_at: Some(1_000),
                    ..discovery(Jurisdiction::Eu)
                },
                1_000
            )
            .is_ok(),
            "finding it the instant it happened is possible"
        );
        assert!(
            BreachRecord::discover(
                BreachDiscovery {
                    occurred_at: None,
                    ..discovery(Jurisdiction::Eu)
                },
                1_000
            )
            .is_ok(),
            "and not knowing when it started is the usual case"
        );
    }

    /// Not yet established is not none affected, and the difference is what an
    /// authority is told in the first hours.
    #[test]
    fn an_unknown_count_is_not_a_count_of_none() {
        let mut record = found(Jurisdiction::Eu);
        assert_eq!(record.subjects_affected, None);

        record.assess(BreachSeverity::High, Some(0)).unwrap();
        assert_eq!(record.subjects_affected, Some(0));
        assert_ne!(record.subjects_affected, None);
    }

    /// A filing says who filed it and with whom, or it is not recorded at all. A
    /// register that cannot evidence a filing is, from an auditor's seat, the
    /// same as not having filed.
    #[test]
    fn a_filing_that_evidences_nothing_is_not_recorded() {
        let mut record = found(Jurisdiction::Eu);
        record.assess(BreachSeverity::High, Some(120)).unwrap();

        for (to, by) in [("", "the officer"), ("the authority", "  "), ("", "")] {
            assert_eq!(
                record.record_filing(to, by, 2_000).unwrap_err(),
                BreachError::IncompleteFiling
            );
            assert_eq!(
                record.status,
                BreachStatus::Assessed,
                "and the record is not advanced by the attempt"
            );
        }

        assert!(
            record
                .record_filing(" the authority ", "the officer", 2_000)
                .is_ok()
        );
        assert_eq!(record.notified_to.as_deref(), Some("the authority"));
        assert_eq!(record.filed_by.as_deref(), Some("the officer"));
        assert_eq!(record.notified_at, Some(2_000));
    }

    /// The handling has a shape, and filing is not something a closed breach can
    /// be made to do again.
    #[test]
    fn only_the_handling_transitions_are_allowed() {
        let mut record = found(Jurisdiction::Eu);

        assert_eq!(
            record
                .record_filing("the authority", "the officer", 2_000)
                .unwrap_err(),
            BreachError::InvalidTransition {
                from: BreachStatus::Discovered,
                to: BreachStatus::Notified
            },
            "nothing is filed before it is assessed"
        );

        record.assess(BreachSeverity::Critical, Some(10)).unwrap();
        assert_eq!(
            record.assess(BreachSeverity::Low, None).unwrap_err(),
            BreachError::InvalidTransition {
                from: BreachStatus::Assessed,
                to: BreachStatus::Assessed
            }
        );

        record
            .record_filing("the authority", "the officer", 2_000)
            .unwrap();
        record.close().unwrap();
        assert_eq!(
            record
                .record_filing("another authority", "someone else", 3_000)
                .unwrap_err(),
            BreachError::InvalidTransition {
                from: BreachStatus::Closed,
                to: BreachStatus::Notified
            },
            "a closed breach cannot be filed again"
        );
        assert_eq!(
            record.assess(BreachSeverity::Low, Some(0)).unwrap_err(),
            BreachError::InvalidTransition {
                from: BreachStatus::Closed,
                to: BreachStatus::Assessed
            },
            "nor re-assessed, which would put it back on the clock"
        );
        assert_eq!(
            record.close().unwrap_err(),
            BreachError::InvalidTransition {
                from: BreachStatus::Closed,
                to: BreachStatus::Closed
            }
        );

        // Every stage a closed breach could be pushed to is refused, rather than
        // the two anyone thought to try.
        for stage in BreachStatus::ALL {
            assert!(!record.can_transition_to(*stage), "closed to {stage}");
        }
    }

    /// Deciding not to notify is a decision that gets recorded, rather than a
    /// breach that stopped moving.
    #[test]
    fn deciding_not_to_notify_is_recorded() {
        let mut record = found(Jurisdiction::Eu);
        record.assess(BreachSeverity::Low, Some(1)).unwrap();
        record.record_not_notifiable().unwrap();

        assert_eq!(record.status, BreachStatus::NotNotifiable);
        assert!(
            !record.is_overdue(i64::MAX),
            "the clock stops on a recorded decision"
        );
        assert!(record.close().is_ok());
    }

    /// The clock runs while a breach is open and stops when it is answered,
    /// either way.
    #[test]
    fn the_clock_runs_only_while_the_breach_is_open() {
        let record = found(Jurisdiction::Eu);
        let due = record.notify_by.unwrap();
        assert!(!record.is_overdue(due));
        assert!(record.is_overdue(due + 1));

        let mut assessed = found(Jurisdiction::Eu);
        assessed.assess(BreachSeverity::High, Some(3)).unwrap();
        assert!(
            assessed.is_overdue(due + 1),
            "assessing it does not stop the clock"
        );

        let mut filed = assessed.clone();
        filed
            .record_filing("the authority", "the officer", 2_000)
            .unwrap();
        assert!(!filed.is_overdue(due + 1));
    }

    /// Only the two upper severities suggest telling the subjects, and it stays
    /// a starting point rather than a verdict.
    #[test]
    fn only_the_upper_severities_suggest_telling_the_subjects() {
        for severity in BreachSeverity::ALL {
            assert_eq!(
                severity.likely_requires_subject_notice(),
                matches!(severity, BreachSeverity::High | BreachSeverity::Critical),
                "{severity}"
            );
        }
    }

    /// A draft is never ready to file. The two narrative fields are a person's
    /// account, and a draft that omitted what it does not know invites someone
    /// to file it as it stands.
    #[test]
    fn a_draft_is_never_ready_to_file() {
        let complete = BreachRecord {
            subjects_affected: Some(120),
            ..found(Jurisdiction::Eu)
        };
        let draft = complete.draft_notification(Jurisdiction::Eu);

        assert!(!draft.is_ready_to_file());
        assert_eq!(draft.outstanding.len(), 2, "{:?}", draft.outstanding);
        assert!(draft.likely_consequences.is_empty());
        assert!(draft.measures_taken.is_empty());

        assert_eq!(draft.breach_id, "breach-1");
        assert_eq!(draft.nature_of_breach, "an exposed backup");
        assert_eq!(draft.became_aware_at, 1_000);
        assert_eq!(draft.notify_by, complete.notify_by);
    }

    /// What is unknown is listed rather than left out, including a deadline
    /// nobody could read from the law.
    #[test]
    fn a_draft_lists_what_it_does_not_know() {
        let bare = BreachRecord {
            data_categories: Vec::new(),
            ..found(Jurisdiction::Kenya)
        };
        let draft = bare.draft_notification(Jurisdiction::Kenya);

        assert_eq!(draft.outstanding.len(), 5);
        assert!(
            draft
                .outstanding
                .iter()
                .any(|item| item.starts_with("approximate_subjects_affected"))
        );
        assert!(
            draft
                .outstanding
                .iter()
                .any(|item| item.starts_with("categories_of_data"))
        );
        assert!(
            draft
                .outstanding
                .iter()
                .any(|item| item.starts_with("notify_by")),
            "a jurisdiction whose window nobody read says so"
        );

        // And a jurisdiction that fixes one does not.
        let known = found(Jurisdiction::Eu).draft_notification(Jurisdiction::Eu);
        assert!(!known.outstanding.iter().any(|i| i.starts_with("notify_by")));
    }
}
