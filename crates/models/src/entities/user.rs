use serde::{Deserialize, Serialize};

use crate::auditable::AuditableModel;
use crate::entities::attributes::{AttributesMap, string_at};
use crate::str_enum::str_enum;

str_enum! {
    #[postgres(name = "user_storage")]
    /// Where the account itself lives.
    pub enum UserStorage {
        /// In this realm's own tables.
        Local => "local",
        /// In a directory this realm federates, with a local shadow record.
        Ldap => "ldap",
    }
}

str_enum! {
    #[postgres(name = "required_action")]
    /// Something a user must do before a session is considered complete.
    ///
    /// Named rather than free text because each one is a screen the login flow
    /// has to know how to show. An action nobody implements would leave a user
    /// with a session that can never be completed and no way to say why.
    pub enum RequiredAction {
        ResetPassword => "reset-password",
        UpdatePassword => "update-password",
        VerifyEmail => "verify-email",
        ConfigureTotp => "configure-totp",
        ConfigureWebauthn => "configure-webauthn",
        /// Draw a set of one-shot codes, the way back when the second
        /// factor is lost.
        ConfigureRecoveryCodes => "configure-recovery-codes",
    }
}

/// The attribute names a user profile is assembled from.
///
/// Constants because they are written by whoever stores a profile and read by
/// whoever renders a claim, and those are far apart. A literal in both places
/// agrees until one of them is edited.
pub mod profile {
    pub const FIRST_NAME: &str = "user.profile.first_name";
    pub const LAST_NAME: &str = "user.profile.last_name";
    pub const NICK_NAME: &str = "user.profile.nick_name";
    pub const GENDER: &str = "user.profile.gender";
    pub const BIRTH_DATE: &str = "user.profile.birthdate";
    pub const MIDDLE_NAME: &str = "user.profile.middle_name";
    pub const PROFILE_PAGE: &str = "user.profile.profile";
    pub const PICTURE: &str = "user.profile.picture";
    pub const WEBSITE: &str = "user.profile.website";
    pub const ZONEINFO: &str = "user.profile.zoneinfo";
    pub const LOCALE: &str = "user.profile.locale";
    pub const EMAIL: &str = "user.profile.email";
    pub const MOBILE: &str = "user.profile.mobile";
    pub const TELEPHONE: &str = "user.profile.telephone";

    /// What a realm asking for a basic profile requires.
    pub const BASIC: [&str; 2] = [FIRST_NAME, LAST_NAME];
}

/// Where a postal address is kept, one attribute per component OIDC Core
/// §5.1.1 names, plus the whole as a mailing label when the realm has it.
pub mod address {
    pub const FORMATTED: &str = "user.address.formatted";
    pub const STREET_ADDRESS: &str = "user.address.street_address";
    pub const LOCALITY: &str = "user.address.locality";
    pub const REGION: &str = "user.address.region";
    pub const POSTAL_CODE: &str = "user.address.postal_code";
    pub const COUNTRY: &str = "user.address.country";

    /// Every component, paired with the member it becomes in the claim.
    pub const COMPONENTS: [(&str, &str); 6] = [
        ("formatted", FORMATTED),
        ("street_address", STREET_ADDRESS),
        ("locality", LOCALITY),
        ("region", REGION),
        ("postal_code", POSTAL_CODE),
        ("country", COUNTRY),
    ];
}

/// A user of a realm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserModel {
    pub user_id: String,
    pub realm_id: String,
    pub user_name: String,
    pub enabled: bool,
    pub email: String,
    pub email_verified: Option<bool>,
    /// E.164, and first class rather than an attribute so it can be a login
    /// identifier: indexed, and unique within the realm.
    #[serde(default)]
    pub phone_number: Option<String>,
    #[serde(default)]
    pub phone_number_verified: Option<bool>,
    pub required_actions: Option<Vec<RequiredAction>>,
    pub not_before: Option<i64>,
    pub user_storage: Option<UserStorage>,
    pub attributes: Option<AttributesMap>,
    pub is_service_account: Option<bool>,
    pub service_account_client_link: Option<String>,
    pub metadata: AuditableModel,
}

impl UserModel {
    /// The profile attributes `required` names that this user does not have.
    ///
    /// Empty means nothing is missing. A user with no attribute map at all is
    /// missing every one of them, which is the case a check written as "the map
    /// is absent" answers correctly and a check written as "the map is present"
    /// gets backwards: an empty map is present and holds none of them.
    ///
    /// The realm decides what is required, so it is passed in rather than read
    /// here. A model that fetched its own policy would need the realm to answer
    /// a question about one user.
    pub fn missing_profile_attributes(&self, required: &[&str]) -> Vec<String> {
        let attributes = match &self.attributes {
            Some(attributes) => attributes,
            None => return required.iter().map(|name| (*name).to_owned()).collect(),
        };

        required
            .iter()
            .filter(|name| string_at(attributes, name).is_none_or(str::is_empty))
            .map(|name| (*name).to_owned())
            .collect()
    }
}

/// The create payload.
///
/// It names no credential. A password sent with a creation has nowhere to go:
/// the user record does not hold one, so the field would be read by nothing and
/// the caller would believe a credential was set. Setting one is its own
/// operation, against its own policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCreateModel {
    pub user_name: String,
    pub enabled: bool,
    pub email: String,
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub phone_number: Option<String>,
    #[serde(default)]
    pub phone_number_verified: Option<bool>,
    pub required_actions: Option<Vec<RequiredAction>>,
    pub not_before: Option<i64>,
    pub user_storage: Option<UserStorage>,
    pub attributes: Option<AttributesMap>,
    pub is_service_account: Option<bool>,
    pub service_account_client_link: Option<String>,
}

impl UserCreateModel {
    /// Build a user. The identifiers and the audit record come from the request
    /// context, not from the payload.
    pub fn into_model(
        self,
        user_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> UserModel {
        UserModel {
            user_id,
            realm_id,
            user_name: self.user_name,
            enabled: self.enabled,
            email: self.email,
            email_verified: self.email_verified,
            phone_number: self.phone_number,
            phone_number_verified: self.phone_number_verified,
            required_actions: self.required_actions,
            not_before: self.not_before,
            user_storage: self.user_storage,
            attributes: self.attributes,
            is_service_account: self.is_service_account,
            service_account_client_link: self.service_account_client_link,
            metadata,
        }
    }
}

/// The update payload.
///
/// Applied to a loaded user rather than converted into a fresh one. A
/// conversion has to invent the fields the payload does not carry, and the
/// username is the one that matters: an update that produced a user with an
/// empty name would rename whoever it was written over.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserUpdateModel {
    pub enabled: bool,
    pub email: String,
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub phone_number: Option<String>,
    #[serde(default)]
    pub phone_number_verified: Option<bool>,
    pub required_actions: Option<Vec<RequiredAction>>,
    pub not_before: Option<i64>,
    pub attributes: Option<AttributesMap>,
    pub is_service_account: Option<bool>,
    pub service_account_client_link: Option<String>,
}

impl UserUpdateModel {
    /// Write what the payload carries onto `user`.
    ///
    /// The identifiers, the username and the storage are left alone. None of
    /// them is in the payload, and a caller cannot move a user to another realm
    /// or another directory by editing its profile.
    pub fn apply(self, user: &mut UserModel) {
        user.enabled = self.enabled;
        user.email = self.email;
        user.email_verified = self.email_verified;
        user.phone_number = self.phone_number;
        user.phone_number_verified = self.phone_number_verified;
        user.required_actions = self.required_actions;
        user.not_before = self.not_before;
        user.attributes = self.attributes;
        user.is_service_account = self.is_service_account;
        user.service_account_client_link = self.service_account_client_link;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::attributes::AttributeValue;
    use crate::str_enum::assert_round_trips;

    fn create() -> UserCreateModel {
        UserCreateModel {
            user_name: "ada".into(),
            enabled: true,
            email: "ada@example.test".into(),
            email_verified: Some(true),
            phone_number: None,
            phone_number_verified: None,
            required_actions: None,
            not_before: None,
            user_storage: Some(UserStorage::Local),
            attributes: None,
            is_service_account: None,
            service_account_client_link: None,
        }
    }

    fn user() -> UserModel {
        create().into_model(
            "user-1".into(),
            "realm-1".into(),
            AuditableModel::from_creator("acme".into(), "root".into()),
        )
    }

    fn named(pairs: &[(&str, &str)]) -> UserModel {
        UserModel {
            attributes: Some(
                pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), AttributeValue::Str((*v).to_owned())))
                    .collect(),
            ),
            ..user()
        }
    }

    #[test]
    fn the_catalogues_agree_with_their_own_spelling() {
        assert_eq!(UserStorage::ALL.len(), 2);
        assert_eq!(RequiredAction::ALL.len(), 6);
        assert_round_trips(UserStorage::ALL);
        assert_round_trips(RequiredAction::ALL);
    }

    /// Every spelling written out, not one sample. A round trip only shows a
    /// value agrees with itself, and these are read by whoever renders the
    /// screen an action names, which is not this codebase.
    #[test]
    fn every_spelling_is_the_one_a_client_reads() {
        assert_eq!(UserStorage::Local.as_str(), "local");
        assert_eq!(UserStorage::Ldap.as_str(), "ldap");

        assert_eq!(RequiredAction::ResetPassword.as_str(), "reset-password");
        assert_eq!(RequiredAction::UpdatePassword.as_str(), "update-password");
        assert_eq!(RequiredAction::VerifyEmail.as_str(), "verify-email");
        assert_eq!(RequiredAction::ConfigureTotp.as_str(), "configure-totp");
        assert_eq!(
            RequiredAction::ConfigureRecoveryCodes.as_str(),
            "configure-recovery-codes"
        );
        assert_eq!(
            RequiredAction::ConfigureWebauthn.as_str(),
            "configure-webauthn"
        );
    }

    /// A user is built from the request context, not from what the payload
    /// claims about itself.
    #[test]
    fn a_created_user_takes_its_identifiers_from_the_caller() {
        let user = user();
        assert_eq!(user.user_id, "user-1");
        assert_eq!(user.realm_id, "realm-1");
        assert_eq!(user.user_name, "ada");
        assert_eq!(user.metadata.tenant, "acme");
    }

    /// A user with no attributes is missing every required name, rather than
    /// passing because there was nothing to look at.
    #[test]
    fn a_user_with_no_attributes_is_missing_all_of_them() {
        assert_eq!(
            user().missing_profile_attributes(&profile::BASIC),
            vec![profile::FIRST_NAME, profile::LAST_NAME]
        );
    }

    /// And an empty map is the same answer. It is present, and it holds none of
    /// them, which is the case a presence check gets backwards.
    #[test]
    fn an_empty_map_is_missing_all_of_them_too() {
        let user = UserModel {
            attributes: Some(AttributesMap::new()),
            ..user()
        };
        assert_eq!(
            user.missing_profile_attributes(&profile::BASIC),
            vec![profile::FIRST_NAME, profile::LAST_NAME]
        );
    }

    /// Each required name is answered on its own, so a map holding one of two
    /// is not a map that passes.
    #[test]
    fn a_partly_filled_profile_names_what_is_left() {
        let user = named(&[(profile::FIRST_NAME, "Ada")]);
        assert_eq!(
            user.missing_profile_attributes(&profile::BASIC),
            vec![profile::LAST_NAME]
        );

        let complete = named(&[
            (profile::FIRST_NAME, "Ada"),
            (profile::LAST_NAME, "Lovelace"),
        ]);
        assert!(
            complete
                .missing_profile_attributes(&profile::BASIC)
                .is_empty()
        );
    }

    /// A name stored empty is not a name that was given.
    #[test]
    fn an_empty_value_does_not_satisfy_a_requirement() {
        let user = named(&[(profile::FIRST_NAME, "Ada"), (profile::LAST_NAME, "")]);
        assert_eq!(
            user.missing_profile_attributes(&profile::BASIC),
            vec![profile::LAST_NAME]
        );
    }

    /// A value of the wrong shape is not a profile name either. A number stored
    /// under a name that must be text is a value nothing can render.
    #[test]
    fn a_value_of_the_wrong_shape_does_not_satisfy_a_requirement() {
        let user = UserModel {
            attributes: Some(AttributesMap::from([
                (profile::FIRST_NAME.to_owned(), AttributeValue::Int(7)),
                (
                    profile::LAST_NAME.to_owned(),
                    AttributeValue::Str("Lovelace".to_owned()),
                ),
            ])),
            ..user()
        };
        assert_eq!(
            user.missing_profile_attributes(&profile::BASIC),
            vec![profile::FIRST_NAME]
        );
    }

    /// Requiring nothing is satisfied by anything, including a user with no
    /// attributes at all.
    #[test]
    fn requiring_nothing_is_satisfied_by_everyone() {
        assert!(user().missing_profile_attributes(&[]).is_empty());
        assert!(
            named(&[(profile::FIRST_NAME, "Ada")])
                .missing_profile_attributes(&[])
                .is_empty()
        );
    }

    /// An update writes what it carries and leaves alone what it does not. The
    /// username is the one that matters: a shape that rebuilt the user would
    /// rename whoever it was written over.
    #[test]
    fn an_update_never_touches_what_it_does_not_carry() {
        let mut user = user();
        UserUpdateModel {
            enabled: false,
            email: "ada@other.test".into(),
            email_verified: Some(false),
            phone_number: Some("+33123456789".into()),
            phone_number_verified: None,
            required_actions: Some(vec![RequiredAction::VerifyEmail]),
            not_before: Some(7),
            attributes: None,
            is_service_account: None,
            service_account_client_link: None,
        }
        .apply(&mut user);

        assert!(!user.enabled);
        assert_eq!(user.email, "ada@other.test");
        assert_eq!(user.phone_number.as_deref(), Some("+33123456789"));
        assert_eq!(
            user.required_actions,
            Some(vec![RequiredAction::VerifyEmail])
        );

        assert_eq!(user.user_name, "ada", "an update does not rename a user");
        assert_eq!(user.user_id, "user-1");
        assert_eq!(user.realm_id, "realm-1", "nor move them to another realm");
        assert_eq!(
            user.user_storage,
            Some(UserStorage::Local),
            "nor move them to another directory"
        );
    }
}
