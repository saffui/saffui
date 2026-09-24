use crypto::provider::SignAlg;
use models::entities::client::ClientModel;

pub const PROFILE_KEY: &str = "profile";
pub const FAPI2: &str = "fapi2";

/// Whether this client wears the FAPI 2.0 Security Profile, by the operator's
/// hand on its bag. The profile is the registration's, never the request's: a
/// request cannot talk its way out of what the client signed up for.
pub fn is_fapi2(client: &ClientModel) -> bool {
    client
        .configs
        .as_ref()
        .and_then(|bag| bag.get(PROFILE_KEY))
        .and_then(models::entities::attributes::AttributeValue::as_str)
        == Some(FAPI2)
}

/// What the profile demands of the registration itself, checked where the
/// registration is used: there is no admin surface that writes the bag, so a
/// client provisioned against its own profile fails closed at the doors
/// rather than serving under it.
pub fn conformant(client: &ClientModel) -> Result<(), &'static str> {
    if !is_fapi2(client) {
        return Ok(());
    }
    if client.public_client == Some(true) {
        return Err("the profile names a confidential client");
    }
    if !matches!(
        client.client_authenticator_type.as_deref(),
        Some("private-key-jwt" | "tls-client-auth")
    ) {
        return Err("the profile authenticates by private_key_jwt or by TLS");
    }
    if !matches!(
        client.id_token_signed_response_alg,
        Some(SignAlg::Ps256 | SignAlg::Es256 | SignAlg::EdDsa)
    ) {
        return Err("the profile signs identity tokens with PS256, ES256 or EdDSA");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::auditable::AuditableModel;
    use models::entities::attributes::AttributeValue;
    use models::entities::client::ClientCreateModel;

    fn wearing(profile: Option<&str>) -> ClientModel {
        let mut client = ClientCreateModel {
            name: "app".into(),
            display_name: "app".into(),
            description: String::new(),
            enabled: Some(true),
        }
        .into_model(
            "app".into(),
            "main".into(),
            AuditableModel::from_creator("acme".into(), "root".into()),
        );
        client.public_client = Some(false);
        client.client_authenticator_type = Some("private-key-jwt".into());
        client.id_token_signed_response_alg = Some(SignAlg::Ps256);
        if let Some(profile) = profile {
            client.configs.get_or_insert_with(Default::default).insert(
                PROFILE_KEY.to_owned(),
                AttributeValue::Str(profile.to_owned()),
            );
        }
        client
    }

    #[test]
    fn the_profile_is_worn_or_it_binds_nothing() {
        assert!(!is_fapi2(&wearing(None)));
        assert!(!is_fapi2(&wearing(Some("other"))));
        assert!(is_fapi2(&wearing(Some(FAPI2))));

        let mut loose = wearing(None);
        loose.public_client = Some(true);
        loose.client_authenticator_type = None;
        loose.id_token_signed_response_alg = None;
        assert!(conformant(&loose).is_ok(), "an unworn profile constrained");
    }

    #[test]
    fn each_demand_of_the_profile_refuses_alone() {
        assert!(conformant(&wearing(Some(FAPI2))).is_ok());

        let mut public = wearing(Some(FAPI2));
        public.public_client = Some(true);
        assert!(conformant(&public).is_err());

        let mut secretive = wearing(Some(FAPI2));
        secretive.client_authenticator_type = Some("client-secret".into());
        assert!(conformant(&secretive).is_err());

        let mut rsa = wearing(Some(FAPI2));
        rsa.id_token_signed_response_alg = Some(SignAlg::Rs256);
        assert!(conformant(&rsa).is_err());
        let mut unsaid = wearing(Some(FAPI2));
        unsaid.id_token_signed_response_alg = None;
        assert!(conformant(&unsaid).is_err(), "the default is RS256");

        let mut ed = wearing(Some(FAPI2));
        ed.id_token_signed_response_alg = Some(SignAlg::EdDsa);
        assert!(conformant(&ed).is_ok());
    }
}
