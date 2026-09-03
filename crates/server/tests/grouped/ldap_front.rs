//! The LDAP front, driven by a real directory client.
//!
//! The front is a second door to the same people: everything asserted here is
//! read back against what the HTTP world planted, and nothing here writes.


#[allow(unused_imports)]
use super::support;
use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};
use super::support::Plane;

const BASE: &str = "dc=id,dc=example";
const PEOPLE: &str = "ou=people,dc=id,dc=example";

/// Spawn the front for one plane on a loopback port, sealed when an
/// acceptor is handed in, and hand back the port.
async fn fronted(plane: &Plane, tls: Option<openssl::ssl::SslContext>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(ldapfront::serve(
        listener,
        tls,
        plane.pool(),
        plane.tenancy(),
        std::sync::Arc::new(support::provider()),
        ldapfront::Front {
            realm_id: support::REALM.into(),
            base_dn: BASE.into(),
        },
    ));
    port
}

async fn dialled(url: &str) -> Ldap {
    let (connection, ldap) = LdapConnAsync::new(url).await.expect("the front answers");
    ldap3::drive!(connection);
    ldap
}

/// An ephemeral self-signed pair, minted for one test's listener.
fn minted_acceptor() -> openssl::ssl::SslContext {
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::X509Builder;
    use openssl::x509::X509NameBuilder;

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut certificate = X509Builder::new().unwrap();
    certificate.set_version(2).unwrap();
    certificate.set_subject_name(&name).unwrap();
    certificate.set_issuer_name(&name).unwrap();
    certificate.set_pubkey(&key).unwrap();
    certificate
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    certificate
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    certificate.sign(&key, MessageDigest::sha256()).unwrap();
    let certificate = certificate.build();

    let mut acceptor =
        openssl::ssl::SslAcceptor::mozilla_intermediate_v5(openssl::ssl::SslMethod::tls_server())
            .unwrap();
    acceptor.set_certificate(&certificate).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.check_private_key().unwrap();
    acceptor.build().into_context()
}

fn subject_dn() -> String {
    format!("uid={},{PEOPLE}", support::SUBJECT)
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_legacy_client_binds_searches_and_asks_who_it_is() {
    let plane = Plane::with_actions(&[]).await;
    let port = fronted(&plane, None).await;
    let mut ldap = dialled(&format!("ldap://127.0.0.1:{port}")).await;

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

    // The shapes an address book types while somebody is still typing.
    for (typed, hits) in [
        ("(uid=ad*)", 1),
        ("(mail=ada@*)", 1),
        ("(uid=*race*)", 0),
        ("(&(objectClass=person)(uid=a*a))", 1),
    ] {
        let (found, _) = ldap
            .search(PEOPLE, Scope::Subtree, typed, vec!["uid"])
            .await
            .expect("an answer")
            .success()
            .expect("the search succeeds");
        assert_eq!(found.len(), hits, "{typed} answered wrong");
    }
    let (housed, _) = ldap
        .search(PEOPLE, Scope::Subtree, "(mail=*@example.test)", vec!["uid"])
        .await
        .expect("an answer")
        .success()
        .expect("the search succeeds");
    assert!(
        !housed.is_empty(),
        "a domain-wide substring found nobody at home"
    );

    // The four-way shape an address book actually types, and a couple of
    // reads the store serves through attributes.
    let (booked, _) = ldap
        .search(
            PEOPLE,
            Scope::Subtree,
            "(|(mail=ad*)(cn=ad*)(givenName=ad*)(sn=ad*))",
            vec!["uid"],
        )
        .await
        .expect("an answer")
        .success()
        .expect("the search succeeds");
    assert_eq!(booked.len(), 1, "the address-book shape missed ada");
    let (surnamed, _) = ldap
        .search(PEOPLE, Scope::Subtree, "(sn=Lovelace)", vec!["uid"])
        .await
        .expect("an answer")
        .success()
        .expect("the search succeeds");
    assert_eq!(surnamed.len(), 1, "an equality on sn missed ada");
    let stray = ldap
        .search(
            PEOPLE,
            Scope::Subtree,
            "(|(mail=ad*)(title=boss*))",
            vec!["uid"],
        )
        .await
        .expect("an answer");
    assert_eq!(
        stray.1.rc, 53,
        "a disjunction with a stray branch was answered narrowed: {stray:?}"
    );

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
    let port = fronted(&plane, None).await;
    let url = format!("ldap://127.0.0.1:{port}");

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
        .search(PEOPLE, Scope::Subtree, "(title=ad*)", vec!["uid"])
        .await
        .expect("an answer");
    assert_eq!(
        vague.1.rc, 53,
        "a substring on an attribute the store cannot sift was answered: {vague:?}"
    );

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
    let port = fronted(&plane, None).await;
    let mut ldap = dialled(&format!("ldap://127.0.0.1:{port}")).await;

    // Even holding a local credential that would verify, a mirrored person
    // is refused: their password lives in the upstream directory, and this
    // front does not proxy binds there.
    let mirrored = ldap
        .simple_bind(&format!("uid=fedora,{PEOPLE}"), "wilderness")
        .await
        .expect("an answer");
    assert_eq!(mirrored.rc, 49, "{mirrored:?}");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_hammered_password_locks_this_door_too() {
    let plane = Plane::with_actions(&[]).await;
    plane.count_logins(2).await;
    let port = fronted(&plane, None).await;
    let mut ldap = dialled(&format!("ldap://127.0.0.1:{port}")).await;

    for _ in 0..3 {
        let wrong = ldap
            .simple_bind(&subject_dn(), "not-the-password")
            .await
            .expect("an answer");
        assert_eq!(wrong.rc, 49, "{wrong:?}");
    }

    // The right password no longer helps, and wears the same refusal: a
    // locked account is not announced to whoever locked it.
    let locked = ldap
        .simple_bind(&subject_dn(), support::PASSWORD)
        .await
        .expect("an answer");
    assert_eq!(locked.rc, 49, "the lockout did not hold: {locked:?}");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_that_does_not_count_forgives_this_door_forever() {
    let plane = Plane::with_actions(&[]).await;
    let port = fronted(&plane, None).await;
    let mut ldap = dialled(&format!("ldap://127.0.0.1:{port}")).await;

    for _ in 0..6 {
        let wrong = ldap
            .simple_bind(&subject_dn(), "not-the-password")
            .await
            .expect("an answer");
        assert_eq!(wrong.rc, 49, "{wrong:?}");
    }
    let bound = ldap
        .simple_bind(&subject_dn(), support::PASSWORD)
        .await
        .expect("an answer");
    assert_eq!(bound.rc, 0, "an unarmed realm locked anyway: {bound:?}");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_sealed_listener_answers_a_real_handshake() {
    let plane = Plane::with_actions(&[]).await;
    let port = fronted(&plane, Some(minted_acceptor())).await;

    // The handshake is made with this test's own TLS client, wide open on
    // verification since the pair is self-signed and one minute old, and the
    // directory client then talks through the tunnel. The platform TLS the
    // ldap3 client would bring dawdles half a minute on unknown issuers.
    let tunnel = tunneled(port).await;
    let mut ldap = dialled(&format!("ldap://127.0.0.1:{tunnel}")).await;

    let bound = ldap
        .simple_bind(&subject_dn(), support::PASSWORD)
        .await
        .expect("an answer");
    assert_eq!(bound.rc, 0, "{bound:?}");
    let (entries, _) = ldap
        .search(
            PEOPLE,
            Scope::Subtree,
            &format!("(uid={})", support::SUBJECT),
            vec!["uid"],
        )
        .await
        .expect("an answer")
        .success()
        .expect("the search succeeds");
    assert_eq!(entries.len(), 1, "the sealed door serves the same people");
    ldap.unbind().await.expect("a clean goodbye");
}

/// A local plaintext port whose far side is a real TLS handshake with the
/// sealed listener.
async fn tunneled(sealed_port: u16) -> u16 {
    let doorstep = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = doorstep.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut plain, _) = doorstep.accept().await.unwrap();
        let mut connector =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client()).unwrap();
        connector.set_verify(openssl::ssl::SslVerifyMode::NONE);
        let ssl = connector
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();
        let raw = tokio::net::TcpStream::connect(("127.0.0.1", sealed_port))
            .await
            .unwrap();
        let mut sealed = tokio_openssl::SslStream::new(ssl, raw).unwrap();
        std::pin::Pin::new(&mut sealed)
            .connect()
            .await
            .expect("the handshake completes");
        let _ = tokio::io::copy_bidirectional(&mut plain, &mut sealed).await;
    });
    port
}

/// Mint a certificate signed by the given issuer, or self-signed when none.
fn minted_cert(
    name: &str,
    issuer: Option<(
        &openssl::x509::X509,
        &openssl::pkey::PKey<openssl::pkey::Private>,
    )>,
) -> (
    openssl::x509::X509,
    openssl::pkey::PKey<openssl::pkey::Private>,
) {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::x509::extension::BasicConstraints;
    use openssl::x509::{X509Builder, X509NameBuilder};

    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap();
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_text("CN", name).unwrap();
    let subject = subject.build();
    let mut certificate = X509Builder::new().unwrap();
    certificate.set_version(2).unwrap();
    certificate.set_subject_name(&subject).unwrap();
    certificate.set_pubkey(&key).unwrap();
    certificate
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    certificate
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    match issuer {
        Some((authority, signing)) => {
            certificate
                .set_issuer_name(authority.subject_name())
                .unwrap();
            certificate.sign(signing, MessageDigest::sha256()).unwrap();
        }
        None => {
            // The issuerless one is the authority, and chain verification
            // refuses an issuer that does not say it is one.
            certificate
                .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            certificate.set_issuer_name(&subject).unwrap();
            certificate.sign(&key, MessageDigest::sha256()).unwrap();
        }
    }
    (certificate.build(), key)
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_sealed_listener_can_demand_a_client_certificate() {
    let plane = Plane::with_actions(&[]).await;

    let (authority, authority_key) = minted_cert("bench-ca", None);
    let (server_cert, server_key) = minted_cert("localhost", Some((&authority, &authority_key)));
    let (client_cert, client_key) = minted_cert("legacy-app", Some((&authority, &authority_key)));

    let mut acceptor =
        openssl::ssl::SslAcceptor::mozilla_intermediate_v5(openssl::ssl::SslMethod::tls_server())
            .unwrap();
    acceptor.set_certificate(&server_cert).unwrap();
    acceptor.set_private_key(&server_key).unwrap();
    acceptor.check_private_key().unwrap();
    acceptor
        .cert_store_mut()
        .add_cert(authority.clone())
        .unwrap();
    acceptor.set_verify(
        openssl::ssl::SslVerifyMode::PEER | openssl::ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT,
    );
    let port = fronted(&plane, Some(acceptor.build().into_context())).await;

    // With the signed certificate, the tunnel opens and the bind holds.
    let with_cert = {
        let doorstep = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = doorstep.local_addr().unwrap().port();
        let (client_cert, client_key) = (client_cert.clone(), client_key.clone());
        tokio::spawn(async move {
            let (mut plain, _) = doorstep.accept().await.unwrap();
            let mut connector =
                openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client()).unwrap();
            connector.set_verify(openssl::ssl::SslVerifyMode::NONE);
            connector.set_certificate(&client_cert).unwrap();
            connector.set_private_key(&client_key).unwrap();
            let ssl = connector
                .build()
                .configure()
                .unwrap()
                .into_ssl("localhost")
                .unwrap();
            let raw = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let mut sealed = tokio_openssl::SslStream::new(ssl, raw).unwrap();
            std::pin::Pin::new(&mut sealed)
                .connect()
                .await
                .expect("the certified handshake completes");
            let _ = tokio::io::copy_bidirectional(&mut plain, &mut sealed).await;
        });
        local
    };
    let mut ldap = dialled(&format!("ldap://127.0.0.1:{with_cert}")).await;
    let bound = ldap
        .simple_bind(&subject_dn(), support::PASSWORD)
        .await
        .expect("an answer");
    assert_eq!(bound.rc, 0, "{bound:?}");

    // Without one, the handshake itself is refused: no certificate, no
    // conversation, before any bind is even spoken.
    let mut connector =
        openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client()).unwrap();
    connector.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let ssl = connector
        .build()
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap();
    let raw = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut bare = tokio_openssl::SslStream::new(ssl, raw).unwrap();
    // Under TLS 1.3 the server's refusal arrives after the client believes
    // the handshake done, so the proof is the first exchange: nothing is
    // readable but the alert, before any LDAP is spoken.
    let refused = match std::pin::Pin::new(&mut bare).connect().await {
        Err(_) => true,
        Ok(()) => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let _ = bare.write_all(b"0").await;
            let _ = bare.flush().await;
            let mut answer = [0u8; 8];
            match tokio::time::timeout(std::time::Duration::from_secs(5), bare.read(&mut answer))
                .await
            {
                Ok(Ok(0)) | Ok(Err(_)) => true,
                Ok(Ok(_)) => false,
                Err(_) => false,
            }
        }
    };
    assert!(refused, "a strangers conversation was answered");
}
