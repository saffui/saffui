use crypto::envelope::Envelope;
use crypto::provider::CryptoProvider;
use data_encoding::BASE64;
use models::auditable::AuditableModel;
use models::entities::attributes::AttributeValue;
use models::entities::authz::{IdentityProviderModel, IdentityProviderMutationModel};
use models::entities::brokering::{IdpMapperModel, IdpMapperMutationModel};
use store::error::StoreError;
use store::keyring::RealmKeyring;
use store::providers::{brokering, roles};
use store::tenancy::UnitOfWork;

use crate::federation::brokering::{
    ATTRIBUTE_IDP_MAPPER, ATTRIBUTE_NAME, ATTRIBUTE_VALUE, CLAIM, KNOWN_IDP_MAPPERS, ROLE,
    ROLE_IDP_MAPPER, SAML_ATTRIBUTE_IDP_MAPPER, SAML_ROLE_IDP_MAPPER, SYNC_MODE, USER_ATTRIBUTE,
    Upstream, rule_fits_provider,
};

/// What the sealed upstream secret is scoped to.
const PURPOSE: &str = "identity-provider-secret";
/// Where the sealed half lives in the bag; the clear key never lands.
pub const SEALED_SECRET: &str = "client_secret_sealed";
const CLEAR_SECRET: &str = "client_secret";

#[derive(Debug, thiserror::Error)]
pub enum Unwritable {
    #[error("one with this alias already exists")]
    AlreadyExists,
    #[error("no such provider")]
    NotFound,
    #[error("no such mapper")]
    NoSuchMapper,
    /// Deletion refused while local accounts are linked through the alias:
    /// the links carry no key to the provider row, so deleting it would
    /// leave them naming a door that no longer exists.
    #[error("accounts are still linked through this provider")]
    StillLinked,
    #[error("{0}")]
    Invalid(String),
    #[error("the store could not be written")]
    Backend,
}

pub async fn providers(transaction: &UnitOfWork) -> Result<Vec<IdentityProviderModel>, Unwritable> {
    let mut listed = brokering::list_providers(transaction)
        .await
        .map_err(|_| Unwritable::Backend)?;
    for provider in &mut listed {
        conceal(provider);
    }
    Ok(listed)
}

pub async fn get_provider(
    transaction: &UnitOfWork,
    alias: &str,
) -> Result<IdentityProviderModel, Unwritable> {
    let mut found = brokering::provider_by_alias(transaction, alias)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)?;
    conceal(&mut found);
    Ok(found)
}

/// What an answer never carries: the sealed bytes are the deployment's, and
/// even sealed they are nobody's to read back over the plane.
fn conceal(provider: &mut IdentityProviderModel) {
    if let Some(bag) = provider.configs.as_mut() {
        for (clear_key, sealed_key) in [
            (CLEAR_SECRET, SEALED_SECRET),
            (
                crate::scim::outbound::CLEAR_BEARER,
                crate::scim::outbound::SEALED_BEARER,
            ),
            (
                crate::messaging::webhook::CLEAR_SECRET,
                crate::messaging::webhook::SEALED_SECRET,
            ),
        ] {
            bag.remove(clear_key);
            if bag.remove(sealed_key).is_some() {
                bag.insert(
                    clear_key.to_owned(),
                    AttributeValue::Str("**********".to_owned()),
                );
            }
        }
    }
}

/// Seal the upstream secret into the bag, so the clear value never lands.
async fn seal_secret(
    ring: &RealmKeyring,
    envelope: &Envelope,
    provider: &mut IdentityProviderModel,
) -> Result<(), Unwritable> {
    let Some(bag) = provider.configs.as_mut() else {
        return Ok(());
    };
    for (clear_key, sealed_key) in [
        (CLEAR_SECRET, SEALED_SECRET),
        (
            crate::scim::outbound::CLEAR_BEARER,
            crate::scim::outbound::SEALED_BEARER,
        ),
        (
            crate::messaging::webhook::CLEAR_SECRET,
            crate::messaging::webhook::SEALED_SECRET,
        ),
    ] {
        let Some(taken) = bag.remove(clear_key) else {
            continue;
        };
        let Some(clear) = taken.as_str().map(str::to_owned) else {
            return Err(Unwritable::Invalid("the secret is a string".to_owned()));
        };
        let sealed = ring
            .seal(envelope, PURPOSE, &provider.internal_id, clear.as_bytes())
            .await
            .map_err(|_| Unwritable::Backend)?;
        bag.insert(
            sealed_key.to_owned(),
            AttributeValue::Str(BASE64.encode(&sealed)),
        );
    }
    Ok(())
}

/// Register an upstream. The configuration is read the way a login will
/// read it, here at the door: a bag accepted unread defers every failure
/// to somebody's sign-in.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one registration"
)]
pub async fn create_provider(
    transaction: &UnitOfWork,
    crypto: &dyn CryptoProvider,
    ring: &RealmKeyring,
    envelope: &Envelope,
    tenant: &str,
    realm_id: &str,
    by: &str,
    asked: IdentityProviderMutationModel,
) -> Result<IdentityProviderModel, Unwritable> {
    if asked.provider_id.trim().is_empty()
        || asked.provider_id.contains('/')
        || asked.provider_id.contains(char::is_whitespace)
    {
        return Err(Unwritable::Invalid(
            "an alias rides a path segment: no spaces, no slashes".to_owned(),
        ));
    }
    let mut provider = asked.into_model(
        drawn(crypto)?,
        realm_id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    check_configuration(&provider)?;
    seal_secret(ring, envelope, &mut provider).await?;
    brokering::create_provider(transaction, &provider)
        .await
        .map_err(|why| match why {
            StoreError::AlreadyExists => Unwritable::AlreadyExists,
            _ => Unwritable::Backend,
        })?;
    conceal(&mut provider);
    Ok(provider)
}

pub async fn update_provider(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
    alias: &str,
    by: &str,
    asked: IdentityProviderMutationModel,
) -> Result<IdentityProviderModel, Unwritable> {
    let standing = brokering::provider_by_alias(transaction, alias)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)?;
    if asked.provider_id != standing.provider_id {
        return Err(Unwritable::Invalid(
            "a provider answers to one alias and does not change it".to_owned(),
        ));
    }

    let mut rewritten = asked.into_model(
        standing.internal_id.clone(),
        standing.realm_id.clone(),
        standing.metadata.clone(),
    );
    rewritten.metadata.updated_by = Some(by.to_owned());
    // A rewrite that says nothing about a sealed value keeps the standing
    // one, and the mask an answer wears means the same: it is this plane's
    // own word, echoed back, never something an operator typed.
    for (clear_key, sealed_key) in [
        (CLEAR_SECRET, SEALED_SECRET),
        (
            crate::scim::outbound::CLEAR_BEARER,
            crate::scim::outbound::SEALED_BEARER,
        ),
        (
            crate::messaging::webhook::CLEAR_SECRET,
            crate::messaging::webhook::SEALED_SECRET,
        ),
    ] {
        let echoed_mask = rewritten.configs.as_ref().is_some_and(|bag| {
            bag.get(clear_key).and_then(AttributeValue::as_str) == Some("**********")
        });
        if echoed_mask && let Some(bag) = rewritten.configs.as_mut() {
            bag.remove(clear_key);
        }
        let says_new = rewritten
            .configs
            .as_ref()
            .is_some_and(|bag| bag.contains_key(clear_key));
        if !says_new
            && let Some(kept) = standing
                .configs
                .as_ref()
                .and_then(|bag| bag.get(sealed_key))
        {
            rewritten
                .configs
                .get_or_insert_with(Default::default)
                .insert(sealed_key.to_owned(), kept.clone());
        }
    }
    check_configuration(&rewritten)?;
    seal_secret(ring, envelope, &mut rewritten).await?;
    if !brokering::update_provider(transaction, &rewritten)
        .await
        .map_err(|_| Unwritable::Backend)?
    {
        return Err(Unwritable::NotFound);
    }
    get_provider(transaction, alias).await
}

/// Read a provider's configuration the way its use will read it, by the kind of
/// provider it is: a bag that cannot be used is refused here rather than at
/// somebody's sign-in.
fn check_configuration(provider: &IdentityProviderModel) -> Result<(), Unwritable> {
    let refused = if crate::federation::workload::is_workload(provider) {
        crate::federation::workload::Trusted::parse(provider)
            .err()
            .map(|why| why.to_string())
    } else if crate::scim::outbound::is_outbound(provider) {
        crate::scim::outbound::Connector::parse(provider)
            .err()
            .map(|why| why.to_string())
    } else if crate::messaging::caep::is_receiver(provider) {
        crate::messaging::caep::Receiver::parse(provider)
            .err()
            .map(|why| why.to_string())
    } else if crate::messaging::webhook::is_webhook(provider) {
        crate::messaging::webhook::Webhook::parse(provider)
            .err()
            .map(|why| why.to_string())
    } else if crate::federation::saml_brokering::is_saml(provider) {
        crate::federation::saml_brokering::SamlUpstream::parse(provider)
            .err()
            .map(|why| why.to_string())
    } else {
        Upstream::parse(provider).err().map(|why| why.to_string())
    };
    refused.map_or(Ok(()), |why| Err(Unwritable::Invalid(why)))
}

pub async fn delete_provider(transaction: &UnitOfWork, alias: &str) -> Result<(), Unwritable> {
    let standing = brokering::provider_by_alias(transaction, alias)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)?;
    if brokering::alias_still_linked(transaction, alias)
        .await
        .map_err(|_| Unwritable::Backend)?
    {
        return Err(Unwritable::StillLinked);
    }
    brokering::delete_provider(transaction, &standing.internal_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}

fn drawn(crypto: &dyn CryptoProvider) -> Result<String, Unwritable> {
    draw(crypto)
}

fn draw(crypto: &dyn CryptoProvider) -> Result<String, Unwritable> {
    let mut bytes = [0_u8; 16];
    crypto
        .rand()
        .fill(&mut bytes)
        .map_err(|_| Unwritable::Backend)?;
    Ok(crypto::provider::uuid_from(bytes))
}

/// The rules of one provider.
pub async fn mappers_of(
    transaction: &UnitOfWork,
    alias: &str,
) -> Result<Vec<IdpMapperModel>, Unwritable> {
    provider_exists(transaction, alias).await?;
    brokering::mappers_of(transaction, alias)
        .await
        .map_err(|_| Unwritable::Backend)
}

async fn provider_exists(transaction: &UnitOfWork, alias: &str) -> Result<(), Unwritable> {
    brokering::provider_by_alias(transaction, alias)
        .await
        .map_err(|_| Unwritable::Backend)?
        .map(|_| ())
        .ok_or(Unwritable::NotFound)
}

/// Refuse what the arrival engine would not run: a type outside the
/// catalogue, a rule reading what its provider does not send, a sync mode
/// neither word, a rule missing what its type reads, and a role nobody made.
/// Checked here, at the plane, so a broken rule is the writer's problem and
/// never the person's at the door.
async fn check_rule(
    transaction: &UnitOfWork,
    provider: &IdentityProviderModel,
    asked: &IdpMapperMutationModel,
) -> Result<(), Unwritable> {
    check_rule_shape(provider, asked)?;
    let granted_role = match asked.mapper_type.as_str() {
        ROLE_IDP_MAPPER | SAML_ROLE_IDP_MAPPER => asked
            .configs
            .as_ref()
            .and_then(|bag| bag.get(ROLE))
            .and_then(AttributeValue::as_str),
        _ => None,
    };
    if let Some(role_id) = granted_role
        && roles::load(transaction, role_id)
            .await
            .map_err(|_| Unwritable::Backend)?
            .is_none()
    {
        return Err(Unwritable::Invalid(format!("no role answers to {role_id}")));
    }
    Ok(())
}

/// What a rule's check reads without the store.
fn check_rule_shape(
    provider: &IdentityProviderModel,
    asked: &IdpMapperMutationModel,
) -> Result<(), Unwritable> {
    let mapper_type = asked.mapper_type.as_str();
    if !KNOWN_IDP_MAPPERS.contains(&mapper_type) {
        return Err(Unwritable::Invalid(format!(
            "no rule of this name runs on arrival; one of: {}",
            KNOWN_IDP_MAPPERS.join(", ")
        )));
    }
    if !rule_fits_provider(mapper_type, provider) {
        return Err(Unwritable::Invalid(
            if crate::federation::saml_brokering::is_saml(provider) {
                format!(
                    "a SAML provider sends attributes, not claims; {SAML_ATTRIBUTE_IDP_MAPPER} reads them"
                )
            } else {
                format!(
                    "only a SAML provider sends attributes; {ATTRIBUTE_IDP_MAPPER} reads this provider's claims"
                )
            },
        ));
    }
    let named = |key: &str| {
        asked
            .configs
            .as_ref()
            .and_then(|bag| bag.get(key))
            .and_then(AttributeValue::as_str)
    };
    if let Some(mode) = named(SYNC_MODE)
        && !matches!(mode, "import" | "force")
    {
        return Err(Unwritable::Invalid(
            "syncMode is import or force".to_owned(),
        ));
    }
    let complete = |reads: &[&str], missing: &str| {
        if reads.iter().any(|key| named(key).is_none()) {
            Err(Unwritable::Invalid(missing.to_owned()))
        } else {
            Ok(())
        }
    };
    match mapper_type {
        ATTRIBUTE_IDP_MAPPER => complete(
            &[CLAIM, USER_ATTRIBUTE],
            "an attribute rule names a claim and a user.attribute",
        ),
        SAML_ATTRIBUTE_IDP_MAPPER => complete(
            &[ATTRIBUTE_NAME, USER_ATTRIBUTE],
            "a SAML attribute rule names an attribute.name and a user.attribute",
        ),
        SAML_ROLE_IDP_MAPPER => complete(
            &[ATTRIBUTE_NAME, ATTRIBUTE_VALUE, ROLE],
            "a SAML role rule names an attribute.name, an attribute.value and a role",
        ),
        _ => complete(&[ROLE], "a role rule names a role"),
    }
}

pub async fn add_mapper(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    alias: &str,
    asked: IdpMapperMutationModel,
) -> Result<IdpMapperModel, Unwritable> {
    let identity_provider = get_provider(transaction, alias).await?;
    check_rule(transaction, &identity_provider, &asked).await?;
    let mapper = asked.into_model(
        draw(provider)?,
        realm_id.to_owned(),
        alias.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    brokering::create_mapper(transaction, &mapper)
        .await
        .map_err(|_| Unwritable::Backend)?;
    Ok(mapper)
}

/// One rule of one provider: a mapper of another alias is not found here,
/// so a path cannot read across providers.
async fn mapper_of(
    transaction: &UnitOfWork,
    alias: &str,
    mapper_id: &str,
) -> Result<IdpMapperModel, Unwritable> {
    provider_exists(transaction, alias).await?;
    brokering::load_mapper(transaction, mapper_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .filter(|mapper| mapper.provider_alias == alias)
        .ok_or(Unwritable::NoSuchMapper)
}

pub async fn get_mapper(
    transaction: &UnitOfWork,
    alias: &str,
    mapper_id: &str,
) -> Result<IdpMapperModel, Unwritable> {
    mapper_of(transaction, alias, mapper_id).await
}

pub async fn rework_mapper(
    transaction: &UnitOfWork,
    alias: &str,
    mapper_id: &str,
    by: &str,
    asked: IdpMapperMutationModel,
) -> Result<IdpMapperModel, Unwritable> {
    let standing = mapper_of(transaction, alias, mapper_id).await?;
    let identity_provider = get_provider(transaction, alias).await?;
    check_rule(transaction, &identity_provider, &asked).await?;
    let mut mapper = asked.into_model(
        mapper_id.to_owned(),
        standing.realm_id.clone(),
        alias.to_owned(),
        standing.metadata.clone(),
    );
    mapper.metadata.updated_by = Some(by.to_owned());
    if !brokering::update_mapper(transaction, &mapper)
        .await
        .map_err(|_| Unwritable::Backend)?
    {
        return Err(Unwritable::NoSuchMapper);
    }
    mapper_of(transaction, alias, mapper_id).await
}

pub async fn remove_mapper(
    transaction: &UnitOfWork,
    alias: &str,
    mapper_id: &str,
) -> Result<(), Unwritable> {
    mapper_of(transaction, alias, mapper_id).await?;
    brokering::delete_mapper(transaction, mapper_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NoSuchMapper)
}

#[cfg(test)]
mod tests {
    use super::{Unwritable, check_configuration, check_rule_shape};
    use crypto::jose::jwk::KeyPair;
    use crypto::jose::jwk::alg::rsa::RsaKeyPair;
    use crypto::provider::{PrivateKey, PublicKey};
    use crypto::x509::{Issuance, issue_certificate};
    use models::auditable::AuditableModel;
    use models::entities::attributes::{AttributeValue, AttributesMap};
    use models::entities::authz::{IdentityProviderModel, IdentityProviderMutationModel};
    use models::entities::brokering::IdpMapperMutationModel;

    fn provider(said: &[(&str, &str)]) -> IdentityProviderModel {
        let configs: AttributesMap = said
            .iter()
            .map(|(key, value)| ((*key).to_owned(), AttributeValue::Str((*value).to_owned())))
            .collect();
        IdentityProviderMutationModel {
            provider_id: "upstream".into(),
            name: "upstream".into(),
            display_name: "Upstream".into(),
            description: String::new(),
            enabled: Some(true),
            trust_email: Some(false),
            configs: Some(configs),
        }
        .into_model(
            "idp-1".into(),
            "main".into(),
            AuditableModel::from_creator("local".into(), "root".into()),
        )
    }

    /// The door reads each provider by its kind: a SAML provider a login can use is
    /// let through and one it cannot is refused with its reason, while an OpenID
    /// provider is still read as one.
    #[test]
    fn the_door_reads_each_provider_by_its_kind() {
        let key = RsaKeyPair::generate(2048).expect("an RSA key");
        let certificate = issue_certificate(&Issuance {
            subject_key: &PublicKey::from_der(key.to_der_public_key()),
            subject_name: "idp.test",
            issuer_key: &PrivateKey::from_der(key.to_der_private_key()),
            issuer_name: "idp.test",
            serial: &[1],
            not_before: 1_789_372_800,
            not_after: 2_104_992_000,
        })
        .expect("a certificate issued by the crypto crate");
        let metadata = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.test/metadata"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#,
            data_encoding::BASE64.encode(&certificate)
        );
        assert!(
            check_configuration(&provider(&[
                ("protocol", "saml"),
                ("idp_metadata", &metadata)
            ]))
            .is_ok()
        );
        let refused = check_configuration(&provider(&[("protocol", "saml")]));
        assert!(
            matches!(&refused, Err(Unwritable::Invalid(why)) if why.contains("idp_metadata")),
            "{refused:?}"
        );

        let openid = [
            ("issuer", "https://idp.example"),
            ("client_id", "saffui"),
            ("authorization_endpoint", "https://idp.example/auth"),
            ("token_endpoint", "https://idp.example/token"),
            ("jwks_uri", "https://idp.example/certs"),
        ];
        assert!(check_configuration(&provider(&openid)).is_ok());
        let refused = check_configuration(&provider(&openid[..4]));
        assert!(
            matches!(&refused, Err(Unwritable::Invalid(why)) if why.contains("jwks_uri")),
            "{refused:?}"
        );
    }

    fn rule(mapper_type: &str, said: &[(&str, &str)]) -> IdpMapperMutationModel {
        IdpMapperMutationModel {
            name: "rule".into(),
            mapper_type: mapper_type.into(),
            configs: Some(
                said.iter()
                    .map(|(key, value)| {
                        ((*key).to_owned(), AttributeValue::Str((*value).to_owned()))
                    })
                    .collect(),
            ),
        }
    }

    /// A rule is checked against what its provider sends before the store is read:
    /// the SAML rules only for a SAML provider, the claim rule never for one, a
    /// granted role for either, and a rule missing what its type reads refused with
    /// its reason.
    #[test]
    fn a_rule_is_checked_against_what_its_provider_sends() {
        let saml = provider(&[("protocol", "saml")]);
        let openid = provider(&[]);
        let department = [("attribute.name", "department"), ("user.attribute", "unit")];
        let staff = [
            ("attribute.name", "memberOf"),
            ("attribute.value", "staff"),
            ("role", "role-staff"),
        ];
        let acr = [("claim", "acr"), ("user.attribute", "upstream.acr")];
        let held = [("role", "role-staff")];

        for (on, asked) in [
            (&saml, rule("saml-user-attribute-idp-mapper", &department)),
            (&saml, rule("saml-role-idp-mapper", &staff)),
            (&saml, rule("oidc-hardcoded-role-idp-mapper", &held)),
            (&openid, rule("oidc-hardcoded-role-idp-mapper", &held)),
            (&openid, rule("oidc-user-attribute-idp-mapper", &acr)),
        ] {
            assert!(
                check_rule_shape(on, &asked).is_ok(),
                "{}",
                asked.mapper_type
            );
        }
        let attribute_reads = "an attribute.name and a user.attribute";
        let role_reads = "an attribute.value and a role";
        for (on, asked, holds) in [
            (
                &saml,
                rule("oidc-user-attribute-idp-mapper", &acr),
                "not claims",
            ),
            (
                &openid,
                rule("saml-user-attribute-idp-mapper", &department),
                "only a SAML provider",
            ),
            (
                &openid,
                rule("saml-role-idp-mapper", &staff),
                "only a SAML provider",
            ),
            (
                &saml,
                rule("saml-user-attribute-idp-mapper", &department[..1]),
                attribute_reads,
            ),
            (
                &saml,
                rule("saml-user-attribute-idp-mapper", &department[1..]),
                attribute_reads,
            ),
            (&saml, rule("saml-role-idp-mapper", &staff[..2]), role_reads),
            (&saml, rule("saml-role-idp-mapper", &staff[1..]), role_reads),
            (
                &saml,
                rule("saml-role-idp-mapper", &[staff[0], staff[2]]),
                role_reads,
            ),
            (&saml, rule("saml-avatar-mapper", &department), "one of:"),
        ] {
            let refused = check_rule_shape(on, &asked);
            assert!(
                matches!(&refused, Err(Unwritable::Invalid(why)) if why.contains(holds)),
                "{refused:?}"
            );
        }
    }
}
