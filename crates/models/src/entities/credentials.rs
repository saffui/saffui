//! Stored credentials: what a user authenticates with, and under what
//! parameters it was minted.

use crypto::provider::HashAlg;
use serde::{Deserialize, Serialize};

use crate::auditable::AuditableModel;
use crate::str_enum::str_enum;

str_enum! {
    #[postgres(name = "credential_type")]
    /// What a stored credential is.
    pub enum CredentialType {
        Password => "password",
        /// A superseded password, kept only so a policy can refuse its reuse.
        PasswordHistory => "password-history",
        /// A shared secret that is not a password — a service account's.
        Secret => "secret",
        Totp => "totp",
        Hotp => "hotp",
    }
}

str_enum! {
    #[postgres(name = "otp_algorithm")]
    /// The digest an OTP credential is computed with, spelled as an
    /// `otpauth://` URI spells it.
    ///
    /// Three, and not the seven the digest catalogue holds. An authenticator
    /// app enrols from that URI, and one naming a digest the app does not
    /// implement enrols cleanly and then produces codes that never match — a
    /// failure that surfaces at the user's next login rather than at
    /// enrolment. A digest no authenticator accepts is not storable here.
    pub enum OtpAlgorithm {
        Sha1 => "SHA1",
        Sha256 => "SHA256",
        Sha512 => "SHA512",
    }
}

impl OtpAlgorithm {
    /// The digest to hand the generator.
    pub fn hash(self) -> HashAlg {
        match self {
            Self::Sha1 => HashAlg::Sha1,
            Self::Sha256 => HashAlg::Sha256,
            Self::Sha512 => HashAlg::Sha512,
        }
    }
}

/// A credential whose parameters cannot be used to produce a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    #[error("a one-time password is 6 to 8 digits wide")]
    Digits,
    #[error("a time step of zero rotates every second")]
    Period,
}

/// What an OTP credential was minted under.
///
/// One arm per kind, because the parameters are disjoint: a counter belongs to
/// HOTP and a time step to TOTP. A shape carrying both gives every credential a
/// field that means nothing for it, and then the constructor for each kind has
/// to put something in the other's — a time step on a counter-based credential,
/// a counter on a time-based one, neither of which any verifier reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "sub_type", rename_all = "lowercase")]
pub enum OtpParameters {
    Hotp { digits: u32, counter: u64 },
    Totp { digits: u32, period: u64 },
}

impl OtpParameters {
    /// Counter-based, starting at `counter`.
    pub fn hotp(digits: u32, counter: u64) -> Result<Self, CredentialError> {
        check_digits(digits)?;
        Ok(Self::Hotp { digits, counter })
    }

    /// Time-based, stepping every `period` seconds.
    ///
    /// A zero step is refused rather than adjusted, for the same reason a zero
    /// width is: quietly making it one turns an uninitialised field into a
    /// working credential that rotates every second.
    pub fn totp(digits: u32, period: u64) -> Result<Self, CredentialError> {
        check_digits(digits)?;
        if period == 0 {
            return Err(CredentialError::Period);
        }
        Ok(Self::Totp { digits, period })
    }

    /// The thirty-second, six-digit configuration an authenticator assumes when
    /// a URI omits them.
    pub fn totp_default() -> Self {
        Self::Totp {
            digits: 6,
            period: 30,
        }
    }

    pub fn digits(self) -> u32 {
        match self {
            Self::Hotp { digits, .. } | Self::Totp { digits, .. } => digits,
        }
    }

    /// The credential type these parameters describe, so the row's type and its
    /// parameters cannot name different kinds.
    pub fn credential_type(self) -> CredentialType {
        match self {
            Self::Hotp { .. } => CredentialType::Hotp,
            Self::Totp { .. } => CredentialType::Totp,
        }
    }
}

fn check_digits(digits: u32) -> Result<(), CredentialError> {
    // The range the generator accepts. Storing anything else mints a credential
    // that is refused every time it is used.
    if (6..=8).contains(&digits) {
        Ok(())
    } else {
        Err(CredentialError::Digits)
    }
}

/// Material a credential is verified against: a password hash and its
/// parameters, or an OTP shared secret.
///
/// A newtype whose `Debug` renders nothing. An OTP shared secret in a log is a
/// second factor anyone reading that log can produce from then on, and it gets
/// there by a struct holding one being formatted rather than by anybody
/// printing the field.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSecret(String);

impl CredentialSecret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Read the material. Named so every place one is read is greppable.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for CredentialSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialSecret(<redacted>)")
    }
}

/// A stored credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialModel {
    pub credential_id: String,
    pub realm_id: String,
    pub user_id: String,
    pub credential_type: CredentialType,
    /// What the user calls it, when they were asked.
    pub user_label: Option<String>,
    /// Never serialised. The store binds it as a column; a credential rendered
    /// into a response must not carry what verifies it.
    #[serde(skip_serializing)]
    pub secret: CredentialSecret,
    /// The OTP parameters, for the two types that have them.
    pub otp: Option<OtpCredentialData>,
    /// Lower is tried first when a user holds several of one type.
    pub priority: i64,
    pub metadata: AuditableModel,
}

/// The parameters an OTP credential is verified under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtpCredentialData {
    pub algorithm: OtpAlgorithm,
    #[serde(flatten)]
    pub parameters: OtpParameters,
}

impl CredentialModel {
    /// A one-time password credential.
    ///
    /// The type is read from the parameters rather than passed alongside them,
    /// so a row cannot say `totp` while holding a counter.
    pub fn otp(
        credential_id: String,
        realm_id: String,
        user_id: String,
        secret: CredentialSecret,
        algorithm: OtpAlgorithm,
        parameters: OtpParameters,
        metadata: AuditableModel,
    ) -> Self {
        Self {
            credential_id,
            realm_id,
            user_id,
            credential_type: parameters.credential_type(),
            user_label: None,
            secret,
            otp: Some(OtpCredentialData {
                algorithm,
                parameters,
            }),
            priority: 0,
            metadata,
        }
    }

    /// Advance a counter-based credential. Does nothing to a time-based one,
    /// which has no counter to advance.
    pub fn advance_counter(&mut self, to: u64) -> bool {
        match self.otp.as_mut().map(|otp| &mut otp.parameters) {
            Some(OtpParameters::Hotp { counter, .. }) => {
                *counter = to;
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;

    fn credential(parameters: OtpParameters) -> CredentialModel {
        CredentialModel::otp(
            "cred-1".into(),
            "realm-1".into(),
            "ada".into(),
            CredentialSecret::new("JBSWY3DPEHPK3PXP".into()),
            OtpAlgorithm::Sha1,
            parameters,
            AuditableModel::from_creator("acme".into(), "ada".into()),
        )
    }

    #[test]
    fn the_catalogues_agree_with_their_own_spelling() {
        assert_eq!(CredentialType::ALL.len(), 5);
        assert_eq!(OtpAlgorithm::ALL.len(), 3);
        assert_eq!(CredentialType::PasswordHistory.as_str(), "password-history");
        assert_eq!(OtpAlgorithm::Sha256.as_str(), "SHA256");
        assert_round_trips(CredentialType::ALL);
        assert_round_trips(OtpAlgorithm::ALL);
    }

    /// Only the digests an authenticator implements can be stored, and each
    /// names the one the generator is given.
    #[test]
    fn only_an_enrollable_digest_can_be_stored() {
        assert_eq!(OtpAlgorithm::Sha1.hash(), HashAlg::Sha1);
        assert_eq!(OtpAlgorithm::Sha256.hash(), HashAlg::Sha256);
        assert_eq!(OtpAlgorithm::Sha512.hash(), HashAlg::Sha512);

        for refused in ["SHA384", "SHA3-256", "SHA3-512", "sha1", "MD5"] {
            assert!(
                refused.parse::<OtpAlgorithm>().is_err(),
                "{refused} enrols and then never matches"
            );
        }
    }

    /// Neither kind carries the other's parameter, which is what a single flat
    /// shape forces on both.
    #[test]
    fn each_kind_carries_only_its_own_parameters() {
        let hotp = OtpParameters::hotp(6, 0).unwrap();
        let totp = OtpParameters::totp(8, 60).unwrap();

        assert_eq!(hotp.credential_type(), CredentialType::Hotp);
        assert_eq!(totp.credential_type(), CredentialType::Totp);
        assert_eq!(hotp.digits(), 6);
        assert_eq!(totp.digits(), 8);

        assert!(matches!(hotp, OtpParameters::Hotp { counter: 0, .. }));
        assert!(matches!(totp, OtpParameters::Totp { period: 60, .. }));
    }

    /// A width the generator refuses mints a credential that fails every time
    /// it is used, so it is refused where it is written.
    #[test]
    fn a_width_no_generator_accepts_is_refused() {
        for digits in [0, 1, 5, 9, 10, u32::MAX] {
            assert_eq!(
                OtpParameters::hotp(digits, 0),
                Err(CredentialError::Digits),
                "{digits} digits"
            );
            assert_eq!(
                OtpParameters::totp(digits, 30),
                Err(CredentialError::Digits)
            );
        }
        for digits in [6, 7, 8] {
            assert!(OtpParameters::hotp(digits, 0).is_ok());
            assert!(OtpParameters::totp(digits, 30).is_ok());
        }
    }

    /// A zero step is refused rather than adjusted: making it one turns an
    /// uninitialised field into a credential that rotates every second.
    #[test]
    fn a_zero_time_step_is_refused_not_adjusted() {
        assert_eq!(OtpParameters::totp(6, 0), Err(CredentialError::Period));
        assert_eq!(
            OtpParameters::totp_default(),
            OtpParameters::Totp {
                digits: 6,
                period: 30
            }
        );
    }

    /// The row's type is read from its parameters, so the two cannot name
    /// different kinds.
    #[test]
    fn the_credential_type_follows_the_parameters() {
        assert_eq!(
            credential(OtpParameters::hotp(6, 3).unwrap()).credential_type,
            CredentialType::Hotp
        );
        assert_eq!(
            credential(OtpParameters::totp_default()).credential_type,
            CredentialType::Totp
        );
    }

    /// Only a counter-based credential has a counter to advance, and asking a
    /// time-based one says so rather than silently doing nothing.
    #[test]
    fn only_a_counter_based_credential_advances() {
        let mut hotp = credential(OtpParameters::hotp(6, 3).unwrap());
        assert!(hotp.advance_counter(4));
        assert!(matches!(
            hotp.otp.unwrap().parameters,
            OtpParameters::Hotp { counter: 4, .. }
        ));

        let mut totp = credential(OtpParameters::totp_default());
        assert!(!totp.advance_counter(4));
        assert_eq!(
            totp.otp.unwrap().parameters,
            OtpParameters::totp_default(),
            "a time-based credential is left alone"
        );
    }

    /// The parameters survive the wire as one value, so a stored row cannot
    /// come back holding a counter for a time-based credential.
    #[test]
    fn the_parameters_round_trip_as_one_value() {
        for parameters in [
            OtpParameters::hotp(8, 17).unwrap(),
            OtpParameters::totp(6, 60).unwrap(),
        ] {
            let data = OtpCredentialData {
                algorithm: OtpAlgorithm::Sha512,
                parameters,
            };
            let encoded = serde_json::to_string(&data).unwrap();
            assert_eq!(
                serde_json::from_str::<OtpCredentialData>(&encoded).unwrap(),
                data
            );
        }

        assert!(
            serde_json::from_str::<OtpParameters>(r#"{"sub_type":"totp","digits":6,"counter":1}"#)
                .is_err(),
            "a time-based credential has no counter"
        );
    }

    /// What verifies a credential never reaches a rendered one.
    #[test]
    fn a_rendered_credential_carries_no_secret() {
        let credential = credential(OtpParameters::totp_default());
        let json = serde_json::to_string(&credential).unwrap();
        assert!(
            !json.contains("JBSWY3DPEHPK3PXP"),
            "the shared secret was rendered: {json}"
        );
        assert!(json.contains("cred-1"), "the rest still renders");
    }

    /// And the log line, which is the one that happens by accident.
    #[test]
    fn debug_renders_no_secret() {
        let secret = CredentialSecret::new("JBSWY3DPEHPK3PXP".into());
        assert_eq!(format!("{secret:?}"), "CredentialSecret(<redacted>)");
        assert_eq!(secret.expose(), "JBSWY3DPEHPK3PXP");

        let rendered = format!("{:?}", credential(OtpParameters::totp_default()));
        assert!(!rendered.contains("JBSWY3DPEHPK3PXP"), "{rendered}");
        assert!(rendered.contains("cred-1"));
    }
}
