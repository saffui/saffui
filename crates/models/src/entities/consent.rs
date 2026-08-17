//! Consent receipts.
//!
//! Not OAuth scope consent. That answers "may this client read your email
//! address": per client, revocable from a settings page, and meaningless to a
//! data protection authority. This answers "on what lawful basis, for what
//! purpose, under which version of which notice are you processing my personal
//! data", which is the question a regulatory filing has to answer and the one a
//! data subject exercises rights against.
//!
//! Two separate types on purpose. They share the word consent and nothing else,
//! and one model would end up missing the fields that make a receipt evidence:
//! the notice version, the lawful basis, the collection method.

use serde::{Deserialize, Serialize};

use crate::str_enum::str_enum;

str_enum! {
    /// The basis relied on for processing.
    ///
    /// A closed set, because it is the field a regulator reads first and an
    /// unrecognised value makes the receipt useless as evidence. These six are
    /// the set every law in scope mirrors, which is why one enum serves all of
    /// them.
    pub enum LawfulBasis {
        Consent => "consent",
        Contract => "contract",
        LegalObligation => "legal-obligation",
        VitalInterests => "vital-interests",
        PublicTask => "public-task",
        LegitimateInterests => "legitimate-interests",
    }
}

impl LawfulBasis {
    /// Whether the subject can withdraw processing on this basis.
    ///
    /// Only consent. Withdrawing "we process this because the law requires it"
    /// is not something a subject can do, and offering the button implies
    /// otherwise. The request is refused rather than quietly ignored, so the
    /// subject learns which basis actually applies, which is the substance of
    /// most complaints an authority receives.
    pub fn is_withdrawable(self) -> bool {
        matches!(self, Self::Consent)
    }
}

/// Whether a receipt records a grant or a withdrawal.
///
/// The withdrawal carries the receipt it withdraws. Holding that identifier in a
/// field beside the state lets both nonsensical rows be written: a withdrawal
/// naming nothing, and a grant naming a receipt it withdraws. Neither means
/// anything, and a constraint that lives in the schema is a constraint the type
/// does not have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum ConsentState {
    Granted,
    Withdrawn { withdraws: String },
}

impl ConsentState {
    /// The receipt this one withdraws, if it withdraws one.
    pub fn withdraws(&self) -> Option<&str> {
        match self {
            Self::Granted => None,
            Self::Withdrawn { withdraws } => Some(withdraws),
        }
    }
}

/// Why a receipt cannot be recorded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConsentError {
    /// A required field was empty. A receipt missing any of them is not
    /// evidence.
    #[error("a consent receipt needs a {0}")]
    Missing(&'static str),
    /// The basis is not one a subject can withdraw.
    #[error(
        "processing on the basis of {0} cannot be withdrawn by the subject; \
         object to it or ask for erasure instead"
    )]
    NotWithdrawable(LawfulBasis),
    /// The prior receipt is already a withdrawal.
    #[error("that consent has already been withdrawn")]
    AlreadyWithdrawn,
}

/// What the controller is recording, as opposed to who it is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentGrant {
    /// What the processing is for, in the controller's words.
    pub purpose: String,
    pub lawful_basis: LawfulBasis,
    /// Which version of which notice the subject was shown. Without it a receipt
    /// says someone consented to something, which is evidence of nothing.
    pub notice_version: String,
    pub notice_locale: Option<String>,
    /// How the consent was collected: a login form, a USSD session, an admin
    /// recording a paper form. Part of the "freely given, specific, informed"
    /// question.
    pub collection_method: Option<String>,
}

/// One entry in the ledger.
///
/// Append only. A withdrawal is a new receipt naming the one it withdraws, never
/// an edit: the record that consent was given on a date under a notice version
/// is exactly what a regulator asks for after it has been withdrawn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentReceipt {
    pub receipt_id: String,
    pub tenant: String,
    pub realm_id: String,
    pub user_id: String,
    pub purpose: String,
    pub lawful_basis: LawfulBasis,
    pub notice_version: String,
    pub notice_locale: Option<String>,
    #[serde(flatten)]
    pub state: ConsentState,
    pub collection_method: Option<String>,
    /// The audit chain sequence this receipt was attested at. The chain is the
    /// tamper evidence, and this is what lets an evidence pack prove the row and
    /// the chain agree.
    pub audit_seq: Option<i64>,
    /// Unix epoch seconds.
    pub created_at: i64,
}

impl ConsentReceipt {
    /// Record a grant.
    ///
    /// Every field checked here is one whose absence makes the receipt worthless
    /// to a regulator, which is a failure that surfaces years later during a
    /// filing rather than when the row is written.
    pub fn grant(
        receipt_id: impl Into<String>,
        tenant: impl Into<String>,
        realm_id: impl Into<String>,
        user_id: impl Into<String>,
        grant: ConsentGrant,
        now: i64,
    ) -> Result<Self, ConsentError> {
        Ok(ConsentReceipt {
            receipt_id: non_empty(receipt_id, "receipt_id")?,
            tenant: non_empty(tenant, "tenant")?,
            realm_id: non_empty(realm_id, "realm_id")?,
            user_id: non_empty(user_id, "user_id")?,
            purpose: non_empty(grant.purpose, "purpose")?,
            lawful_basis: grant.lawful_basis,
            notice_version: non_empty(grant.notice_version, "notice_version")?,
            notice_locale: grant.notice_locale,
            state: ConsentState::Granted,
            collection_method: grant.collection_method,
            audit_seq: None,
            created_at: now,
        })
    }

    /// Record the withdrawal of `prior`.
    ///
    /// The purpose, basis, notice version and locale are carried over so the
    /// withdrawal stands on its own in an export. A reader should not have to
    /// join back to learn what was withdrawn.
    pub fn withdraw(
        receipt_id: impl Into<String>,
        prior: &ConsentReceipt,
        collection_method: Option<String>,
        now: i64,
    ) -> Result<Self, ConsentError> {
        if !prior.lawful_basis.is_withdrawable() {
            return Err(ConsentError::NotWithdrawable(prior.lawful_basis));
        }
        if prior.state.withdraws().is_some() {
            return Err(ConsentError::AlreadyWithdrawn);
        }

        Ok(ConsentReceipt {
            receipt_id: non_empty(receipt_id, "receipt_id")?,
            tenant: prior.tenant.clone(),
            realm_id: prior.realm_id.clone(),
            user_id: prior.user_id.clone(),
            purpose: prior.purpose.clone(),
            lawful_basis: prior.lawful_basis,
            notice_version: prior.notice_version.clone(),
            notice_locale: prior.notice_locale.clone(),
            state: ConsentState::Withdrawn {
                withdraws: prior.receipt_id.clone(),
            },
            collection_method,
            audit_seq: None,
            created_at: now,
        })
    }
}

fn non_empty(value: impl Into<String>, field: &'static str) -> Result<String, ConsentError> {
    let value: String = value.into();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ConsentError::Missing(field));
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;

    fn grant_of(basis: LawfulBasis) -> ConsentGrant {
        ConsentGrant {
            purpose: "marketing email".into(),
            lawful_basis: basis,
            notice_version: "privacy-notice-v3".into(),
            notice_locale: Some("fr-FR".into()),
            collection_method: Some("login-form".into()),
        }
    }

    fn granted(basis: LawfulBasis) -> ConsentReceipt {
        ConsentReceipt::grant(
            "receipt-1",
            "acme",
            "realm-1",
            "ada",
            grant_of(basis),
            1_000,
        )
        .expect("a complete grant records")
    }

    #[test]
    fn the_bases_agree_with_their_own_spelling() {
        assert_eq!(LawfulBasis::ALL.len(), 6);
        assert_eq!(LawfulBasis::LegalObligation.as_str(), "legal-obligation");
        assert_eq!(
            LawfulBasis::LegitimateInterests.as_str(),
            "legitimate-interests"
        );
        assert_round_trips(LawfulBasis::ALL);
    }

    /// Exactly one basis is the subject's to withdraw. Offering the button for
    /// the others implies the processing would stop, which it would not.
    #[test]
    fn only_consent_is_the_subjects_to_withdraw() {
        for basis in LawfulBasis::ALL {
            assert_eq!(
                basis.is_withdrawable(),
                *basis == LawfulBasis::Consent,
                "{basis}"
            );
        }
    }

    /// A field whose absence makes the receipt worthless is refused when the row
    /// is written, not years later during a filing.
    #[test]
    fn a_receipt_missing_what_makes_it_evidence_is_refused() {
        let cases: [(&str, ConsentGrant, &str, &str); 3] = [
            ("", grant_of(LawfulBasis::Consent), "acme", "receipt_id"),
            (
                "receipt-1",
                ConsentGrant {
                    purpose: "   ".into(),
                    ..grant_of(LawfulBasis::Consent)
                },
                "acme",
                "purpose",
            ),
            (
                "receipt-1",
                ConsentGrant {
                    notice_version: String::new(),
                    ..grant_of(LawfulBasis::Consent)
                },
                "acme",
                "notice_version",
            ),
        ];

        for (receipt_id, grant, tenant, expected) in cases {
            assert_eq!(
                ConsentReceipt::grant(receipt_id, tenant, "realm-1", "ada", grant, 1_000),
                Err(ConsentError::Missing(expected))
            );
        }

        assert_eq!(
            ConsentReceipt::grant(
                "receipt-1",
                " ",
                "realm-1",
                "ada",
                grant_of(LawfulBasis::Consent),
                1_000
            ),
            Err(ConsentError::Missing("tenant"))
        );
    }

    /// Whitespace is not a value. A purpose of spaces is a purpose nobody wrote.
    #[test]
    fn a_recorded_value_is_trimmed_and_kept() {
        let receipt = ConsentReceipt::grant(
            "  receipt-1  ",
            "acme",
            "realm-1",
            "ada",
            ConsentGrant {
                purpose: "  marketing email  ".into(),
                ..grant_of(LawfulBasis::Consent)
            },
            1_000,
        )
        .unwrap();
        assert_eq!(receipt.receipt_id, "receipt-1");
        assert_eq!(receipt.purpose, "marketing email");
    }

    /// A withdrawal stands on its own. A reader should not have to join back to
    /// learn what was withdrawn.
    #[test]
    fn a_withdrawal_carries_what_it_withdraws() {
        let prior = granted(LawfulBasis::Consent);
        let withdrawal =
            ConsentReceipt::withdraw("receipt-2", &prior, Some("settings-page".into()), 2_000)
                .unwrap();

        assert_eq!(withdrawal.receipt_id, "receipt-2");
        assert_eq!(withdrawal.state.withdraws(), Some("receipt-1"));
        assert_eq!(withdrawal.purpose, prior.purpose);
        assert_eq!(withdrawal.lawful_basis, prior.lawful_basis);
        assert_eq!(withdrawal.notice_version, prior.notice_version);
        assert_eq!(withdrawal.notice_locale, prior.notice_locale);
        assert_eq!(withdrawal.created_at, 2_000);
        assert_eq!(
            withdrawal.collection_method.as_deref(),
            Some("settings-page"),
            "a withdrawal records how it was collected, not how the grant was"
        );

        assert_eq!(prior.state, ConsentState::Granted, "the grant is untouched");
    }

    /// Withdrawing a basis the subject does not control is refused, and the
    /// error names the basis so the subject learns which one applies.
    #[test]
    fn a_basis_the_subject_does_not_control_cannot_be_withdrawn() {
        for basis in LawfulBasis::ALL {
            let prior = granted(*basis);
            let result = ConsentReceipt::withdraw("receipt-2", &prior, None, 2_000);
            if *basis == LawfulBasis::Consent {
                assert!(result.is_ok(), "{basis} is withdrawable");
            } else {
                assert_eq!(result, Err(ConsentError::NotWithdrawable(*basis)));
            }
        }
    }

    /// Withdrawing twice is refused rather than recorded, so the ledger does not
    /// carry two withdrawals of one grant.
    #[test]
    fn a_withdrawal_cannot_itself_be_withdrawn() {
        let prior = granted(LawfulBasis::Consent);
        let withdrawal = ConsentReceipt::withdraw("receipt-2", &prior, None, 2_000).unwrap();
        assert_eq!(
            ConsentReceipt::withdraw("receipt-3", &withdrawal, None, 3_000),
            Err(ConsentError::AlreadyWithdrawn)
        );
    }

    /// The two nonsensical rows are unwritable rather than checked: a withdrawal
    /// naming nothing, and a grant naming a receipt it withdraws.
    #[test]
    fn neither_nonsensical_state_can_be_written_or_read() {
        let granted = granted(LawfulBasis::Consent);
        assert_eq!(granted.state.withdraws(), None);

        let encoded = serde_json::to_string(&granted).unwrap();
        assert!(encoded.contains(r#""state":"granted""#), "{encoded}");
        assert!(!encoded.contains("withdraws"));
        assert_eq!(
            serde_json::from_str::<ConsentReceipt>(&encoded).unwrap(),
            granted
        );

        let withdrawal = ConsentReceipt::withdraw("receipt-2", &granted, None, 2_000).unwrap();
        let encoded = serde_json::to_string(&withdrawal).unwrap();
        assert_eq!(
            serde_json::from_str::<ConsentReceipt>(&encoded).unwrap(),
            withdrawal
        );

        let orphaned = encoded.replace(r#""withdraws":"receipt-1","#, "");
        assert!(
            serde_json::from_str::<ConsentReceipt>(&orphaned).is_err(),
            "a withdrawal naming nothing must not decode"
        );
    }
}
