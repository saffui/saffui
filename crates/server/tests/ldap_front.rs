//! The LDAP front, driven by a real directory client.
//!
//! The front is a second door to the same people: everything asserted here is
//! read back against what the HTTP world planted, and nothing here writes.

mod support;

use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};
use support::Plane;

const BASE: &str = "dc=id,dc=example";
const PEOPLE: &str = "ou=people,dc=id,dc=example";

/// Spawn the front for one plane on a loopback port, and hand back a URL a
/// directory client can dial.
async fn fronted(plane: &Plane) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(ldapfront::serve(
        listener,
        plane.pool(),
        plane.tenancy(),
        std::sync::Arc::new(support::provider()),
        ldapfront::Front {
            realm_id: support::REALM.into(),
            base_dn: BASE.into(),
        },
    ));
    format!("ldap://127.0.0.1:{port}")
}

async fn dialled(url: &str) -> Ldap {
    let (connection, ldap) = LdapConnAsync::new(url).await.expect("the front answers");
    ldap3::drive!(connection);
    ldap
}

fn subject_dn() -> String {
    format!("uid={},{PEOPLE}", support::SUBJECT)
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_legacy_client_binds_searches_and_asks_who_it_is() {
    let plane = Plane::with_actions(&[]).await;
    let url = fronted(&plane).await;
    let mut ldap = dialled(&url).await;

    let bound = ldap
        .simple_bind(&subject_dn(), support::PASSWORD)
        .await
        .expect("an answer");
    assert_eq!(bound.rc, 0, "the planted password binds: {bound:?}");

    // The person, read back by name with the attributes the profile and
    // email scopes would release.
    let (entries, done) = ldap
        .search(
            PEOPLE,
            Scope::Subtree,
            &format!("(uid={})", support::SUBJECT),
            vec!["*"],
        )
        .await
        .expect("an answer")
        .success()
        .expect("the search succeeds");
    assert_eq!(done.rc, 0);
    assert_eq!(entries.len(), 1, "one ada");
    let person = SearchEntry::construct(entries.into_iter().next().unwrap());
    assert_eq!(person.dn, subject_dn());
    let held = |attribute: &str| person.attrs.get(attribute).cloned().unwrap_or_default();
    assert_eq!(held("uid"), vec![support::SUBJECT.to_owned()]);
    assert_eq!(held("mail"), vec![support::SUBJECT_EMAIL.to_owned()]);
    assert_eq!(held("givenName"), vec![support::GIVEN_NAME.to_owned()]);
    assert_eq!(held("sn"), vec![support::FAMILY_NAME.to_owned()]);
    assert!(
        held("objectClass").contains(&"inetOrgPerson".to_owned()),
        "{person:?}"
    );

    // The same person by mail, and everyone by presence: the two other
    // shapes a directory consumer actually sends.
    let (by_mail, _) = ldap
        .search(
            PEOPLE,
            Scope::Subtree,
            &format!("(mail={})", support::SUBJECT_EMAIL),
            vec!["uid"],
        )
        .await
        .expect("an answer")
        .success()
        .expect("the search succeeds");
    assert_eq!(by_mail.len(), 1);
    let (everyone, _) = ldap
        .search(BASE, Scope::Subtree, "(objectClass=*)", vec!["uid"])
        .await
        .expect("an answer")
        .success()
        .expect("the search succeeds");
    assert!(!everyone.is_empty(), "presence lists the realm's people");

    let (exop, _) = ldap
        .extended(WhoAmI)
        .await
        .expect("an answer")
        .success()
        .expect("whoami succeeds");
    let named: WhoAmIResp = exop.parse();
    assert_eq!(named.authzid, format!("dn:{}", subject_dn()));

    ldap.unbind().await.expect("a clean goodbye");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_door_stays_shut_to_who_it_must() {
    let plane = Plane::with_actions(&[]).await;
    let url = fronted(&plane).await;

    // Reading before binding: which people exist is not an anonymous question.
    let mut fresh = dialled(&url).await;
    let unbound = fresh
        .search(PEOPLE, Scope::Subtree, "(objectClass=*)", vec!["uid"])
        .await
        .expect("an answer");
    assert_eq!(unbound.1.rc, 53, "unwilling before a bind: {unbound:?}");

    // The anonymous bind is refused outright, not admitted as a guest.
    let anonymous = fresh.simple_bind("", "").await.expect("an answer");
    assert_eq!(anonymous.rc, 53, "{anonymous:?}");

    // Wrong password, unknown name, foreign DN: one refusal, no telling
    // which of the three it was.
    let wrong = fresh
        .simple_bind(&subject_dn(), "not-the-password")
        .await
        .expect("an answer");
    assert_eq!(wrong.rc, 49, "{wrong:?}");
    let unknown = fresh
        .simple_bind(&format!("uid=nobody,{PEOPLE}"), support::PASSWORD)
        .await
        .expect("an answer");
    assert_eq!(unknown.rc, 49, "{unknown:?}");
    let foreign = fresh
        .simple_bind(&format!("cn=admin,{BASE}"), support::PASSWORD)
        .await
        .expect("an answer");
    assert_eq!(foreign.rc, 49, "{foreign:?}");

    // A filter the front does not fold is refused whole, never answered
    // approximately.
    let bound = fresh
        .simple_bind(&subject_dn(), support::PASSWORD)
        .await
        .expect("an answer");
    assert_eq!(bound.rc, 0);
    let vague = fresh
        .search(PEOPLE, Scope::Subtree, "(uid=ad*)", vec!["uid"])
        .await
        .expect("an answer");
    assert_eq!(vague.1.rc, 53, "substrings are refused: {vague:?}");

    // A disabled account stops binding, with the same face as a bad password.
    plane.disable_subject().await;
    let mut after = dialled(&url).await;
    let disabled = after
        .simple_bind(&subject_dn(), support::PASSWORD)
        .await
        .expect("an answer");
    assert_eq!(disabled.rc, 49, "{disabled:?}");

    // And the search side no longer lists them either.
    let (gone, _) = fresh
        .search(
            PEOPLE,
            Scope::Subtree,
            &format!("(uid={})", support::SUBJECT),
            vec!["uid"],
        )
        .await
        .expect("an answer")
        .success()
        .expect("the search still succeeds");
    assert!(gone.is_empty(), "a disabled person is not listed");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_mirrored_person_is_sent_to_their_own_directory() {
    let plane = Plane::with_actions(&[]).await;
    plane.plant_shadow("fedora", "wilderness").await;
    let url = fronted(&plane).await;
    let mut ldap = dialled(&url).await;

    // Even holding a local credential that would verify, a mirrored person
    // is refused: their password lives in the upstream directory, and this
    // front does not proxy binds there.
    let mirrored = ldap
        .simple_bind(&format!("uid=fedora,{PEOPLE}"), "wilderness")
        .await
        .expect("an answer");
    assert_eq!(mirrored.rc, 49, "{mirrored:?}");
}
