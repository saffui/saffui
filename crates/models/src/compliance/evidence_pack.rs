//! The evidence a controller assembles when there is no certificate to point at.
//!
//! A verifiable audit chain, the consent records, the request log, the breach
//! register and a current registration, in one artefact. It is what a tender asks
//! for when it cannot ask for a certificate.
//!
//! # Two properties make it worth anything
//!
//! **It is anchored.** The chain verification is not one section among several,
//! it is what makes the others credible. Consent records and a request log are
//! assertions by the controller; a verified chain is the reason to believe them.
//! A pack whose chain does not verify says so before anything else, and a reader
//! who sees that should discount everything below.
//!
//! **It never quietly truncates.** Every section that was capped, filtered or
//! failed to load says so. A pack that silently drops half a breach register
//! looks exactly like a pack from a controller who had no breaches, and telling
//! those apart is the entire point of producing one.

use serde::{Deserialize, Serialize};

/// What verifying a realm's audit chain found.
///
/// Where it broke lives in the variant that broke. Held in fields beside a flag,
/// a chain that verified and also names a break is representable, and so is one
/// that failed and says nothing about where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase")]
pub enum ChainVerification {
    Verified,
    Broken {
        /// The first sequence where verification failed, and the number a
        /// forensic reader starts from.
        at: i64,
        reason: String,
    },
}

impl ChainVerification {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }
}

/// The chain as the pack reports it.
///
/// Its own shape rather than the verifier's: this is what a regulator reads, and
/// the vocabulary does not depend on whatever produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainAttestation {
    pub realm_id: String,
    pub events: u64,
    #[serde(flatten)]
    pub verification: ChainVerification,
}

/// How complete one section is.
///
/// Separate from the data, because "there were no breaches" and "the register
/// could not be read" produce the same empty list and mean opposite things. A
/// reader of the first concludes a clean period; a reader of the second should
/// conclude nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "completeness", rename_all = "lowercase")]
pub enum SectionCompleteness {
    /// Everything in the period is here.
    Complete,
    /// Capped, and saying so rather than looking whole.
    Truncated { included: u64, total: u64 },
    /// Could not be assembled, with the reason.
    Unavailable { reason: String },
}

impl SectionCompleteness {
    /// Whether this section can be relied on as a full account.
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// One section: what it holds, and how much of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackSection<T> {
    pub items: Vec<T>,
    #[serde(flatten)]
    pub completeness: SectionCompleteness,
}

impl<T> PackSection<T> {
    pub fn complete(items: Vec<T>) -> Self {
        PackSection {
            items,
            completeness: SectionCompleteness::Complete,
        }
    }

    /// A section capped at a limit, where `total` is what existed.
    ///
    /// A cap that happened to fit everything is complete rather than truncated
    /// at its own size, since a reader told a section was cut wants to know that
    /// something is missing.
    pub fn capped(items: Vec<T>, total: u64) -> Self {
        let included = items.len() as u64;
        PackSection {
            completeness: if included >= total {
                SectionCompleteness::Complete
            } else {
                SectionCompleteness::Truncated { included, total }
            },
            items,
        }
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        PackSection {
            items: Vec::new(),
            completeness: SectionCompleteness::Unavailable {
                reason: reason.into(),
            },
        }
    }
}

/// What the pack says about itself, before any of its contents.
///
/// A reader decides how much weight to give the rest from this alone, which is
/// why it leads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackVerdict {
    /// Chain verified and every section whole. The only state that supports a
    /// full account of the period.
    Sound,
    /// The chain verified and at least one section is partial. Usable, with the
    /// gaps named.
    Partial,
    /// The chain did not verify. Everything below it is the controller's
    /// unverified assertion, and the pack says so rather than letting a reader
    /// assume otherwise.
    ChainUnverified,
}

/// The assembled pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePack<C, D, B, R> {
    pub tenant: String,
    pub realm_id: String,
    /// The period this accounts for. Without one a pack cannot be checked
    /// against anything, and a reader cannot tell what it leaves out.
    pub period_from: i64,
    pub period_to: i64,
    pub generated_at: i64,
    /// The anchor. Read first.
    pub chain: ChainAttestation,
    pub consent_receipts: PackSection<C>,
    pub dsar_requests: PackSection<D>,
    pub breaches: PackSection<B>,
    pub registrations: PackSection<R>,
    /// The retention configuration in force, as free key and value pairs. It is
    /// per deployment, and a fixed shape would omit whatever a given regulator
    /// asks about.
    pub retention: Vec<(String, String)>,
}

impl<C, D, B, R> EvidencePack<C, D, B, R> {
    /// What this pack supports being used for.
    ///
    /// The chain dominates. The sections are assertions by the controller and
    /// the chain is the reason to believe them, so an unverified chain makes the
    /// rest unverified too, however complete those sections are.
    pub fn verdict(&self) -> PackVerdict {
        if !self.chain.verification.is_verified() {
            return PackVerdict::ChainUnverified;
        }
        if self.gaps().is_empty() {
            PackVerdict::Sound
        } else {
            PackVerdict::Partial
        }
    }

    /// Every section that is not a full account, named.
    ///
    /// A pack that quietly dropped half a register looks exactly like a pack
    /// from a controller who had nothing to report, so what is missing is listed
    /// rather than left for a reader to notice.
    pub fn gaps(&self) -> Vec<&'static str> {
        let mut gaps = Vec::new();
        if !self.consent_receipts.completeness.is_complete() {
            gaps.push("consent_receipts");
        }
        if !self.dsar_requests.completeness.is_complete() {
            gaps.push("dsar_requests");
        }
        if !self.breaches.completeness.is_complete() {
            gaps.push("breaches");
        }
        if !self.registrations.completeness.is_complete() {
            gaps.push("registrations");
        }
        gaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Pack = EvidencePack<String, String, String, String>;

    fn pack(chain: ChainVerification) -> Pack {
        EvidencePack {
            tenant: "acme".into(),
            realm_id: "realm-1".into(),
            period_from: 0,
            period_to: 1_000,
            generated_at: 1_100,
            chain: ChainAttestation {
                realm_id: "realm-1".into(),
                events: 42,
                verification: chain,
            },
            consent_receipts: PackSection::complete(vec!["receipt".into()]),
            dsar_requests: PackSection::complete(Vec::new()),
            breaches: PackSection::complete(Vec::new()),
            registrations: PackSection::complete(vec!["registration".into()]),
            retention: vec![("sessions".into(), "30d".into())],
        }
    }

    /// The chain dominates. Sections are the controller's assertions and the
    /// chain is the reason to believe them, so a broken one makes the rest
    /// unverified however complete they are.
    #[test]
    fn an_unverified_chain_settles_the_verdict_whatever_else_is_whole() {
        let sound = pack(ChainVerification::Verified);
        assert_eq!(sound.verdict(), PackVerdict::Sound);
        assert!(sound.gaps().is_empty());

        let broken = pack(ChainVerification::Broken {
            at: 17,
            reason: "hash mismatch".into(),
        });
        assert_eq!(broken.verdict(), PackVerdict::ChainUnverified);
        assert!(
            broken.gaps().is_empty(),
            "every section is still whole, and it changes nothing"
        );
    }

    /// A section that is not a full account is named, and one gap is enough to
    /// stop the pack being a full account of the period.
    #[test]
    fn any_partial_section_is_named_and_lowers_the_verdict() {
        let truncated = Pack {
            breaches: PackSection::capped(vec!["one".into()], 9),
            ..pack(ChainVerification::Verified)
        };
        assert_eq!(truncated.verdict(), PackVerdict::Partial);
        assert_eq!(truncated.gaps(), vec!["breaches"]);

        let unavailable = Pack {
            dsar_requests: PackSection::unavailable("the log could not be read"),
            registrations: PackSection::unavailable("the registry timed out"),
            ..pack(ChainVerification::Verified)
        };
        assert_eq!(unavailable.verdict(), PackVerdict::Partial);
        assert_eq!(unavailable.gaps(), vec!["dsar_requests", "registrations"]);
    }

    /// Nothing to report and could not be read produce the same empty list and
    /// mean opposite things. Only the completeness tells them apart.
    #[test]
    fn an_empty_section_is_not_a_section_that_failed() {
        let nothing_to_report: PackSection<String> = PackSection::complete(Vec::new());
        let could_not_read: PackSection<String> = PackSection::unavailable("permission denied");

        assert_eq!(nothing_to_report.items, could_not_read.items);
        assert!(nothing_to_report.completeness.is_complete());
        assert!(!could_not_read.completeness.is_complete());
        assert_ne!(nothing_to_report.completeness, could_not_read.completeness);
    }

    /// A cap that happened to fit everything is whole. Reporting it as truncated
    /// at its own size tells a reader something is missing when nothing is.
    #[test]
    fn a_cap_that_fitted_everything_is_not_a_truncation() {
        let exact = PackSection::capped(vec!["a".to_owned(), "b".to_owned()], 2);
        assert!(exact.completeness.is_complete());

        let over = PackSection::capped(vec!["a".to_owned()], 5);
        assert_eq!(
            over.completeness,
            SectionCompleteness::Truncated {
                included: 1,
                total: 5
            }
        );

        let empty_of_nothing: PackSection<String> = PackSection::capped(Vec::new(), 0);
        assert!(empty_of_nothing.completeness.is_complete());
    }

    /// A chain that verified cannot also name a break, and one that failed
    /// cannot stay silent about where. A stored pack missing that is refused
    /// rather than read as verified.
    #[test]
    fn a_chain_cannot_both_verify_and_name_a_break() {
        let broken = pack(ChainVerification::Broken {
            at: 17,
            reason: "hash mismatch".into(),
        });

        // Checked on the structure rather than as a substring: nested one level
        // deeper the same text is still in there, and the shape is the contract.
        let structure = serde_json::to_value(&broken.chain).unwrap();
        assert_eq!(
            structure.get("result").and_then(|v| v.as_str()),
            Some("broken"),
            "the result sits beside the count: {structure}"
        );
        assert_eq!(structure.get("at").and_then(|v| v.as_i64()), Some(17));
        assert_eq!(structure.get("events").and_then(|v| v.as_u64()), Some(42));
        assert!(structure.get("verification").is_none(), "{structure}");

        let encoded = serde_json::to_string(&broken.chain).unwrap();
        assert_eq!(
            serde_json::from_str::<ChainAttestation>(&encoded).unwrap(),
            broken.chain
        );

        let silent = encoded.replace(r#""at":17,"#, "");
        assert!(
            serde_json::from_str::<ChainAttestation>(&silent).is_err(),
            "a failure that says nothing about where must not decode"
        );

        let verified = serde_json::to_string(&pack(ChainVerification::Verified).chain).unwrap();
        assert!(!verified.contains("reason"), "{verified}");
        assert!(!verified.contains("\"at\""), "{verified}");
    }

    /// The whole pack survives its own encoding, verdict and gaps included.
    #[test]
    fn a_pack_survives_its_own_encoding() {
        let original = Pack {
            breaches: PackSection::capped(vec!["one".into()], 9),
            ..pack(ChainVerification::Verified)
        };

        let structure = serde_json::to_value(&original).unwrap();
        let breaches = structure.get("breaches").expect("a breaches section");
        assert_eq!(
            breaches.get("completeness").and_then(|v| v.as_str()),
            Some("truncated"),
            "the completeness sits beside the items: {breaches}"
        );
        assert_eq!(breaches.get("total").and_then(|v| v.as_u64()), Some(9));
        assert!(breaches.get("items").is_some());

        let encoded = serde_json::to_string(&original).unwrap();
        let decoded: Pack = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.verdict(), PackVerdict::Partial);
        assert_eq!(decoded.gaps(), original.gaps());
    }
}
