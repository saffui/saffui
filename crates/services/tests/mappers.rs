mod support;

use models::auditable::AuditableModel;
use models::entities::authz::GroupModel;
use models::entities::client::{Protocol, ProtocolMapperModel};
use services::mappers::{GROUP_MAPPER, PROPERTY_MAPPER, resolve};
use store::providers::{client_scopes, roles};
use store::tenancy::TenantContext;
use support::Fixture;

fn group(group_id: &str, name: &str, parent: Option<&str>) -> GroupModel {
    GroupModel {
        group_id: group_id.into(),
        realm_id: "main".into(),
        name: name.into(),
        display_name: name.into(),
        description: String::new(),
        is_default: false,
        parent_id: parent.map(str::to_owned),
        metadata: AuditableModel::from_creator("acme".into(), "root".into()),
    }
}

fn rule(mapper_id: &str, mapper_type: &str) -> ProtocolMapperModel {
    ProtocolMapperModel {
        mapper_id: mapper_id.into(),
        realm_id: "main".into(),
        name: mapper_id.into(),
        protocol: Protocol::OpenId,
        mapper_type: mapper_type.into(),
        configs: None,
        metadata: AuditableModel::from_creator("acme".into(), "root".into()),
    }
}

/// A group rule reads every group the person stands in, the ones above them
/// included, and reads nothing at all when no rule asks.
///
/// The unit tests hand `evaluate` a registry already filled, so they say what a
/// filled one becomes and nothing about whether anything fills it. This is the
/// link between the two: without it, a rule can be written, stored, and never
/// answer.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_group_rule_reads_every_group_the_person_stands_in() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    // Ada joins the child only. The parent is hers by standing in the child,
    // which is the whole reason the walk exists.
    roles::create_group(&transaction, &group("g-eng", "engineering", None))
        .await
        .unwrap();
    roles::create_group(&transaction, &group("g-back", "backend", Some("g-eng")))
        .await
        .unwrap();
    roles::add_to_group(&transaction, "ada", "g-back")
        .await
        .unwrap();

    // A rule of another kind first: the registry stays empty, because nothing
    // asked for it. That is the bargain the roles strike, and a grant with no
    // such rule must pay no query for one.
    let other = rule("m-name", PROPERTY_MAPPER);
    client_scopes::create_mapper(&transaction, &other)
        .await
        .unwrap();
    client_scopes::attach_mapper_to_client(&transaction, "app", "m-name")
        .await
        .unwrap();
    let resolved = resolve(&transaction, "app", "ada", "openid").await.unwrap();
    assert!(
        resolved.groups.is_empty(),
        "a grant carrying no group rule read the groups anyway: {:?}",
        resolved.groups
    );

    let asked = rule("m-groups", GROUP_MAPPER);
    client_scopes::create_mapper(&transaction, &asked)
        .await
        .unwrap();
    client_scopes::attach_mapper_to_client(&transaction, "app", "m-groups")
        .await
        .unwrap();
    let resolved = resolve(&transaction, "app", "ada", "openid").await.unwrap();
    assert_eq!(
        resolved.groups,
        vec!["backend".to_owned(), "engineering".to_owned()],
        "the walk up the parents did not answer"
    );
}
