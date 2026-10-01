use super::credential_status::{compressed_statuses, settled};
#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use super::wallet::{
    ask_for, asked, client_id_and_nonce, mint_request_key, pid_query, plane_that_verifies,
};
use actix_web::http::{Method, StatusCode};
use crypto::jose::jwk::KeyPair;
use crypto::jose::jwk::alg::ec::{EcCurve, EcKeyPair};
use crypto::provider::{PrivateKey, PublicKey};
use crypto::revocation::{Revoking, issue_revocation_list};
use crypto::x509::{Certifying, certify_key, subject_key_identifier};
use data_encoding::BASE64URL_NOPAD;
use serde_json::{Value, json};
use services::verifier::certificates::{
    CREDENTIAL_CHAIN_OUT_OF_VALIDITY, CREDENTIAL_NOT_SIGNED_BY_A_SIGNER, CREDENTIAL_UNANCHORED,
    CREDENTIAL_UNCHAINED, LIST_UNANCHORED, LIST_UNCHAINED,
};
use services::verifier::revocation::{
    CERTIFICATE_REVOKED, REVOCATION_ELSEWHERE, REVOCATION_LISTS_FULL, REVOCATION_NEVER_READ,
    REVOCATION_NOT_READ_YET, REVOCATION_STALE, REVOCATION_UNFETCHED, REVOCATION_UNREADABLE,
};
use services::verifier::status::{LIST_NEVER_READ, LIST_NOT_READ_YET, REVOKED};
use store::tenancy::TenantContext;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const REALM: &str = support::REALM;
const PID: &str = "urn:eudi:pid:1";

/// What an issuer's host serves, by path: the media type and the body.
type Published = Arc<Mutex<HashMap<String, (&'static str, Vec<u8>)>>>;

/// A host serving whatever the test publishes on it, and nothing else.
fn serve_published() -> (String, Published) {
    use actix_web::{App, HttpRequest, HttpResponse, HttpServer, web};
    let published: Published = Arc::default();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let base = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    let served = published.clone();
    let server = HttpServer::new(move || {
        let served = served.clone();
        App::new().default_service(web::get().to(move |asked: HttpRequest| {
            let found = served.lock().expect("the host").get(asked.path()).cloned();
            async move {
                match found {
                    Some((media_type, body)) => {
                        HttpResponse::Ok().content_type(media_type).body(body)
                    }
                    None => HttpResponse::NotFound().finish(),
                }
            }
        }))
    })
    .listen(listener)
    .expect("a listener")
    .workers(1)
    .disable_signals()
    .run();
    tokio::spawn(server);
    (base, published)
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// A key and the certificate an authority issued for it.
struct Certified {
    key: EcKeyPair,
    certificate: Vec<u8>,
}

impl Certified {
    fn private(&self) -> PrivateKey {
        PrivateKey::from_der(self.key.to_der_private_key())
    }
}

/// What one certificate is issued as.
struct Issued<'a> {
    name: &'a str,
    /// Absent for a certificate that issues itself.
    issuer: Option<&'a Certified>,
    authority: bool,
    serial: u8,
    revocation_list: Option<&'a str>,
    /// Seconds from now.
    valid: (i64, i64),
}

fn certify(asked: Issued<'_>) -> Certified {
    let key = EcKeyPair::generate(EcCurve::P256).expect("a key");
    let own = PrivateKey::from_der(key.to_der_private_key());
    let certificate = certify_key(&Certifying {
        subject_key: &PublicKey::from_der(key.to_der_public_key()),
        subject_name: asked.name,
        issuer_certificate: asked.issuer.map(|issuer| issuer.certificate.as_slice()),
        issuer_key: &asked.issuer.map_or(own, Certified::private),
        serial: &[asked.serial],
        not_before: now() + asked.valid.0,
        not_after: now() + asked.valid.1,
        authority: asked.authority,
        revocation_list: asked.revocation_list,
    })
    .expect("a certificate issued by the crypto crate");
    Certified { key, certificate }
}

const YEAR: (i64, i64) = (-3_600, 365 * 86_400);
const SIGNER_SERIAL: u8 = 0x21;
const STATUS_SIGNER_SERIAL: u8 = 0x22;
const ISSUING_SERIAL: u8 = 0x11;

/// An issuer as HAIP has one: a root the realm trusts, the authority under it
/// that certifies its keys, the key its credentials are signed with and the
/// one its status lists are, and a host publishing its revocation lists and
/// its status list.
struct CertifiedIssuer {
    base: String,
    published: Published,
    root: Certified,
    issuing: Certified,
    signer: Certified,
    status_signer: Certified,
    holder: EcKeyPair,
}

impl CertifiedIssuer {
    fn new() -> Self {
        let (base, published) = serve_published();
        let root = certify(Issued {
            name: "PID Root",
            issuer: None,
            authority: true,
            serial: 0x01,
            revocation_list: None,
            valid: YEAR,
        });
        let issuing = certify(Issued {
            name: "PID Issuing CA",
            issuer: Some(&root),
            authority: true,
            serial: ISSUING_SERIAL,
            revocation_list: Some(&format!("{base}/crl/root.crl")),
            valid: YEAR,
        });
        let under_issuing = |name: &str, serial: u8| {
            certify(Issued {
                name,
                issuer: Some(&issuing),
                authority: false,
                serial,
                revocation_list: Some(&format!("{base}/crl/issuing.crl")),
                valid: YEAR,
            })
        };
        let signer = under_issuing("PID Provider", SIGNER_SERIAL);
        let status_signer = under_issuing("PID Status", STATUS_SIGNER_SERIAL);
        let issuer = Self {
            base,
            published,
            root,
            issuing,
            signer,
            status_signer,
            holder: EcKeyPair::generate(EcCurve::P256).expect("a holder key"),
        };
        issuer.revoke_under_root(&[], now() - 60);
        issuer.revoke_under_issuing(&[], now() - 60);
        issuer
    }

    fn iss(&self) -> String {
        format!("{}/pid", self.base)
    }

    fn status_list(&self) -> String {
        format!("{}/statuslists/1", self.base)
    }

    fn publish(&self, path: &str, media_type: &'static str, body: Vec<u8>) {
        self.published
            .lock()
            .expect("the host")
            .insert(path.to_owned(), (media_type, body));
    }

    fn revoke(&self, authority: &Certified, path: &str, serials: &[u8], issued_at: i64) {
        let serials: Vec<[u8; 1]> = serials.iter().map(|serial| [*serial]).collect();
        let revoked: Vec<&[u8]> = serials.iter().map(|serial| serial.as_slice()).collect();
        let list = issue_revocation_list(&Revoking {
            issuer_certificate: &authority.certificate,
            issuer_key: &authority.private(),
            revoked: &revoked,
            this_update: issued_at,
            next_update: issued_at + 86_400,
        })
        .expect("a list issued by the crypto crate");
        self.publish(path, "application/pkix-crl", list);
    }

    fn revoke_under_root(&self, serials: &[u8], issued_at: i64) {
        self.revoke(&self.root, "/crl/root.crl", serials, issued_at);
    }

    fn revoke_under_issuing(&self, serials: &[u8], issued_at: i64) {
        self.revoke(&self.issuing, "/crl/issuing.crl", serials, issued_at);
    }

    /// The chain a credential carries: its signer, then the authority that
    /// certified it, the root left out.
    fn chain(&self) -> Vec<Vec<u8>> {
        vec![
            self.signer.certificate.clone(),
            self.issuing.certificate.clone(),
        ]
    }

    /// Publish the status list its credentials cite, signed as `signed` says.
    fn publish_status_list(&self, statuses: &[u8], key: &EcKeyPair, chain: &[Vec<u8>]) {
        use crypto::jose::jws::{ES256, JwsHeader};
        let mut header = JwsHeader::new();
        header.set_token_type("statuslist+jwt");
        if !chain.is_empty() {
            header.set_x509_certificate_chain(chain);
        }
        let claims = json!({
            "sub": self.status_list(),
            "iss": self.iss(),
            "iat": now(),
            "exp": now() + 3_600,
            "ttl": 600,
            "status_list": { "bits": 1, "lst": compressed_statuses(statuses) },
        });
        let signer = ES256
            .signer_from_pem(key.to_pem_private_key())
            .expect("a signer");
        let token =
            crypto::jose::jws::serialize_compact(claims.to_string().as_bytes(), &header, &signer)
                .expect("signed");
        self.publish(
            "/statuslists/1",
            "application/statuslist+jwt",
            token.into_bytes(),
        );
    }
}

/// How one credential is issued and signed.
struct Signed<'a> {
    key: &'a EcKeyPair,
    chain: Vec<Vec<u8>>,
    vct: &'a str,
    /// The index it cites in the issuer's status list, when it cites one.
    status_index: Option<u64>,
}

impl CertifiedIssuer {
    fn signed(&self) -> Signed<'_> {
        Signed {
            key: &self.signer.key,
            chain: self.chain(),
            vct: PID,
            status_index: None,
        }
    }

    /// A presentation of the credential `how` describes, disclosing what the
    /// PID query asks for, bound to one request.
    fn presented(&self, how: &Signed<'_>, audience: &str, nonce: &str) -> String {
        use crypto::jose::jws::{ES256, JwsHeader};
        use crypto::sd_jwt::{Concealed, conceal_claims};
        let Value::Object(mut claims) = json!({
            "iss": self.iss(),
            "vct": how.vct,
            "iat": now(),
            "exp": now() + 3_600,
            "cnf": { "jwk": self.holder.to_jwk_public_key().as_ref() },
            "given_name": "Ada",
            "family_name": "Lovelace",
            "address": { "locality": "London" },
        }) else {
            unreachable!()
        };
        if let Some(index) = how.status_index {
            claims.insert(
                "status".to_owned(),
                json!({ "status_list": { "idx": index, "uri": self.status_list() } }),
            );
        }
        let concealment = conceal_claims(
            &support::provider(),
            claims,
            &[
                Concealed::Property(&["given_name"]),
                Concealed::Property(&["family_name"]),
                Concealed::Property(&["address", "locality"]),
            ],
            2,
        )
        .expect("concealed");
        let mut header = JwsHeader::new();
        header.set_token_type("dc+sd-jwt");
        if !how.chain.is_empty() {
            header.set_x509_certificate_chain(&how.chain);
        }
        let signer = ES256
            .signer_from_pem(how.key.to_pem_private_key())
            .expect("an issuer signer");
        let signed = crypto::jose::jws::serialize_compact(
            Value::Object(concealment.payload.clone())
                .to_string()
                .as_bytes(),
            &header,
            &signer,
        )
        .expect("signed");
        let presentation =
            crypto::sd_jwt::select_disclosures(&concealment.issued(&signed), |_| true)
                .expect("selected");
        let holder = ES256
            .signer_from_pem(self.holder.to_pem_private_key())
            .expect("a holder signer");
        crypto::sd_jwt::bind_presentation(
            &support::provider(),
            &presentation,
            &holder,
            audience,
            nonce,
            now(),
        )
        .expect("bound")
    }
}

/// Trust `certificate` as an authority for credential issuers, and hand back
/// the identifier the realm gives it.
async fn deposit(plane: &Plane, bearer: &str, certificate: &[u8]) -> String {
    let (status, anchor) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/trust-anchors"),
        bearer,
        Some(json!({
            "role": "credential-issuer",
            "certificate": support::pem_certificate(certificate),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{anchor}");
    anchor["id"].as_str().expect("an id").to_owned()
}

async fn name_by_certificate(
    plane: &Plane,
    bearer: &str,
    issuer: &str,
    anchors: &[&str],
    types: &[&str],
) -> (StatusCode, Value) {
    asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/credential-issuers"),
        bearer,
        Some(json!({
            "name": "PID provider",
            "issuer": issuer,
            "trusted_by": "certificate",
            "anchors": anchors,
            "credential_types": types,
        })),
    )
    .await
}

/// A realm that verifies, asking under its did:web, trusting `issuer` by
/// certificate through its root for PIDs. Hands back the anchor's identifier
/// and the issuer's.
async fn realm_trusting(plane: &Plane, bearer: &str, issuer: &CertifiedIssuer) -> (String, String) {
    super::wallet::verifier_running();
    mint_request_key(plane, bearer).await;
    let anchor = deposit(plane, bearer, &issuer.root.certificate).await;
    let (status, named) =
        name_by_certificate(plane, bearer, &issuer.iss(), &[&anchor], &[PID]).await;
    assert_eq!(status, StatusCode::CREATED, "{named}");
    let id = named["id"].as_str().expect("an id").to_owned();
    (anchor, id)
}

/// One pass of the scheduled reading of revocation lists, then of status
/// lists, as a node runs them.
async fn read_lists(plane: &Plane) -> (u64, u64) {
    let revocations =
        scheduler::revocation_lists::refresh_every_realm(&plane.tenancy(), &support::sealing())
            .await
            .expect("the realms listed");
    let statuses =
        scheduler::status_lists::refresh_every_realm(&plane.tenancy(), &support::sealing())
            .await
            .expect("the realms listed");
    (revocations.kept, statuses.kept)
}

async fn rewrite(plane: &Plane, statement: &str) {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    transaction
        .execute(statement, &[])
        .await
        .expect("the rows rewritten");
    transaction.commit().await.expect("committed");
}

/// Present the credential `how` describes for what `query` asks, and say what
/// the request came to: verified, or the reason it failed.
async fn present(
    plane: &Plane,
    bearer: &str,
    issuer: &CertifiedIssuer,
    how: &Signed<'_>,
    query: &Value,
) -> String {
    let (asked_for, request) = ask_for(plane, bearer, query).await;
    let (client_id, nonce) = client_id_and_nonce(&request);
    let answer = json!({
        "vp_token": { "pid": [issuer.presented(how, client_id, nonce)] },
        "state": request["state"],
    });
    settled(plane, bearer, &asked_for, &request, &answer).await
}

/// Present the issuer's PID as it signs it, citing no status, or the status
/// at `index` of its list.
async fn present_pid(
    plane: &Plane,
    bearer: &str,
    issuer: &CertifiedIssuer,
    index: Option<u64>,
) -> String {
    let how = Signed {
        status_index: index,
        ..issuer.signed()
    };
    present(plane, bearer, issuer, &how, &pid_query()).await
}

/// A credential of an issuer trusted by certificate is verified by the chain
/// it carries, once the revocation lists its certificates name and the status
/// list it cites have been read: nothing is fetched while a person presents,
/// and each list is refused until the pass has read it, the status list
/// itself under a certificate of the same authorities.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_credential_is_verified_by_the_chain_its_issuer_is_trusted_through() {
    let (plane, bearer) = plane_that_verifies().await;
    let issuer = CertifiedIssuer::new();
    realm_trusting(&plane, &bearer, &issuer).await;
    issuer.publish_status_list(
        &[0b0000_0100],
        &issuer.status_signer.key,
        &[
            issuer.status_signer.certificate.clone(),
            issuer.issuing.certificate.clone(),
        ],
    );
    let citing = Signed {
        status_index: Some(1),
        ..issuer.signed()
    };

    assert_eq!(
        present(&plane, &bearer, &issuer, &citing, &pid_query()).await,
        REVOCATION_NOT_READ_YET
    );
    assert_eq!(
        read_lists(&plane).await,
        (2, 1),
        "the lists of the signer's and of its authority's revocation, and the status list \
         written down beside them"
    );
    assert_eq!(
        present(&plane, &bearer, &issuer, &citing, &pid_query()).await,
        "verified"
    );
    let revoked = Signed {
        status_index: Some(2),
        ..issuer.signed()
    };
    assert_eq!(
        present(&plane, &bearer, &issuer, &revoked, &pid_query()).await,
        REVOKED
    );

    // What the query trusts is matched on the chain presented: the authority
    // that issued the signer, or the one that issued it, and no other.
    let trusting = |authority: &Certified| {
        let mut query = pid_query();
        let identifier = subject_key_identifier(&authority.certificate).expect("an identifier");
        query["credentials"][0]["trusted_authorities"] =
            json!([{ "type": "aki", "values": [BASE64URL_NOPAD.encode(&identifier)] }]);
        query
    };
    for authority in [&issuer.issuing, &issuer.root] {
        assert_eq!(
            present(&plane, &bearer, &issuer, &citing, &trusting(authority)).await,
            "verified"
        );
    }
    assert_eq!(
        present(&plane, &bearer, &issuer, &citing, &trusting(&issuer.signer)).await,
        "a credential's chain names none of the authorities the query trusts"
    );
    // A certificate carried beside the path verified says nothing of who
    // issued the credential.
    let stranger = CertifiedIssuer::new();
    let mut beside = Signed {
        status_index: Some(1),
        ..issuer.signed()
    };
    beside.chain.push(stranger.signer.certificate.clone());
    assert_eq!(
        present(&plane, &bearer, &issuer, &beside, &trusting(&issuer.root)).await,
        "verified"
    );
    assert_eq!(
        present(
            &plane,
            &bearer,
            &issuer,
            &beside,
            &trusting(&stranger.issuing)
        )
        .await,
        "a credential's chain names none of the authorities the query trusts"
    );
}

/// A credential that does not hold to the authorities its issuer is trusted
/// through, or to the types it is trusted to issue, fails its request in the
/// realm's words.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_credential_not_held_by_its_issuers_authorities_is_refused_in_words() {
    let (plane, bearer) = plane_that_verifies().await;
    let issuer = CertifiedIssuer::new();
    realm_trusting(&plane, &bearer, &issuer).await;
    assert_eq!(
        present(&plane, &bearer, &issuer, &issuer.signed(), &pid_query()).await,
        REVOCATION_NOT_READ_YET
    );
    assert_eq!(read_lists(&plane).await, (2, 0));
    assert_eq!(
        present(&plane, &bearer, &issuer, &issuer.signed(), &pid_query()).await,
        "verified"
    );

    let stranger = CertifiedIssuer::new();
    let alone = certify(Issued {
        name: "PID Provider",
        issuer: None,
        authority: false,
        serial: 0x31,
        revocation_list: None,
        valid: YEAR,
    });
    let lapsed = certify(Issued {
        name: "PID Provider",
        issuer: Some(&issuer.issuing),
        authority: false,
        serial: 0x32,
        revocation_list: None,
        valid: (-7_200, -3_600),
    });
    let mut both_types = pid_query();
    both_types["credentials"][0]["meta"]["vct_values"] = json!([PID, "urn:eudi:mdl:1"]);
    let cases: Vec<(Signed<'_>, &Value, &str)> = vec![
        (
            Signed {
                chain: Vec::new(),
                ..issuer.signed()
            },
            &both_types,
            CREDENTIAL_UNCHAINED,
        ),
        (
            Signed {
                key: &stranger.signer.key,
                chain: stranger.chain(),
                ..issuer.signed()
            },
            &both_types,
            CREDENTIAL_UNANCHORED,
        ),
        (
            Signed {
                key: &alone.key,
                chain: vec![alone.certificate.clone()],
                ..issuer.signed()
            },
            &both_types,
            CREDENTIAL_NOT_SIGNED_BY_A_SIGNER,
        ),
        (
            Signed {
                key: &lapsed.key,
                chain: vec![
                    lapsed.certificate.clone(),
                    issuer.issuing.certificate.clone(),
                ],
                ..issuer.signed()
            },
            &both_types,
            CREDENTIAL_CHAIN_OUT_OF_VALIDITY,
        ),
        (
            Signed {
                key: &stranger.signer.key,
                ..issuer.signed()
            },
            &both_types,
            "a credential's signature is not its issuer's",
        ),
        (
            Signed {
                vct: "urn:eudi:mdl:1",
                ..issuer.signed()
            },
            &both_types,
            "a credential is of a type its issuer is not trusted to issue",
        ),
    ];
    for (how, query, reason) in cases {
        assert_eq!(present(&plane, &bearer, &issuer, &how, query).await, reason);
    }

    // A certificate publishing its revocation where this verifier does not
    // read, or at an address longer than it keeps, refuses its credentials;
    // one at the longest address kept is written down for the pass.
    let presents_under = |serial: u8, address: String| {
        let signer = certify(Issued {
            name: "PID Provider",
            issuer: Some(&issuer.issuing),
            authority: false,
            serial,
            revocation_list: Some(&address),
            valid: YEAR,
        });
        let chain = vec![
            signer.certificate.clone(),
            issuer.issuing.certificate.clone(),
        ];
        let (plane, bearer, issuer) = (&plane, &bearer, &issuer);
        async move {
            let how = Signed {
                key: &signer.key,
                chain,
                ..issuer.signed()
            };
            present(plane, bearer, issuer, &how, &pid_query()).await
        }
    };
    let longest = format!(
        "{}/crl/{}",
        issuer.base,
        "a".repeat(2048 - issuer.base.len() - 5)
    );
    assert_eq!(longest.len(), 2048);
    for (serial, address, reason) in [
        (
            0x33,
            "ldap://ca.example/cn=issuing?certificateRevocationList".to_owned(),
            REVOCATION_ELSEWHERE,
        ),
        (0x34, format!("{longest}a"), REVOCATION_ELSEWHERE),
        (0x35, longest, REVOCATION_NOT_READ_YET),
    ] {
        assert_eq!(
            presents_under(serial, address).await,
            reason,
            "{serial:#04x}"
        );
    }

    // A realm follows a thousand revocation lists at most: a certificate
    // naming one more refuses its credentials.
    rewrite(
        &plane,
        "INSERT INTO certificate_revocation_lists \
             (tenant, realm_id, issuer_id, uri, authority_digest, authority, due_at, cited_at) \
         SELECT tenant, realm_id, issuer_id, 'http://filler.example/' || n, authority_digest, \
                authority, now() + interval '1 day', now() \
         FROM (SELECT * FROM certificate_revocation_lists LIMIT 1) AS one, \
              generate_series(1, 999 - (SELECT count(*) FROM certificate_revocation_lists)::int) n",
    )
    .await;
    for (serial, list, reason) in [
        (0x36, "thousandth", REVOCATION_NOT_READ_YET),
        (0x37, "one-more", REVOCATION_LISTS_FULL),
    ] {
        let address = format!("{}/crl/{list}.crl", issuer.base);
        assert_eq!(presents_under(serial, address).await, reason, "{list}");
    }
}

/// A certificate its authority revoked, or whose revocation can no longer be
/// established, refuses the credentials signed under it: the signer's, the
/// authority's that certified it, a list no longer relied on, and one that
/// could not be read. A revocation is said before a list still to be read,
/// and a revoked chain has no status list written down for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_revoked_certificate_refuses_the_credentials_signed_under_it() {
    let (plane, bearer) = plane_that_verifies().await;
    let issuer = CertifiedIssuer::new();
    realm_trusting(&plane, &bearer, &issuer).await;
    let presents = || present_pid(&plane, &bearer, &issuer, None);
    assert_eq!(presents().await, REVOCATION_NOT_READ_YET);
    assert_eq!(read_lists(&plane).await, (2, 0));
    assert_eq!(presents().await, "verified");

    let due = "UPDATE certificate_revocation_lists SET due_at = now()";
    issuer.revoke_under_issuing(&[STATUS_SIGNER_SERIAL], now() - 30);
    rewrite(&plane, due).await;
    assert_eq!(read_lists(&plane).await, (2, 0));
    assert_eq!(
        presents().await,
        "verified",
        "another certificate's revocation"
    );

    issuer.revoke_under_issuing(&[STATUS_SIGNER_SERIAL, SIGNER_SERIAL], now() - 20);
    rewrite(&plane, due).await;
    assert_eq!(read_lists(&plane).await, (2, 0));
    assert_eq!(presents().await, CERTIFICATE_REVOKED);
    assert_eq!(
        present_pid(&plane, &bearer, &issuer, Some(1)).await,
        CERTIFICATE_REVOKED
    );
    assert_eq!(
        counted(&plane, "credential_status_lists").await,
        0,
        "a status list was written down for a revoked chain"
    );

    // An older list served again does not undo the revocation.
    issuer.revoke_under_issuing(&[], now() - 40);
    rewrite(&plane, due).await;
    assert_eq!(read_lists(&plane).await, (1, 0), "the older list was kept");
    assert_eq!(presents().await, CERTIFICATE_REVOKED);

    issuer.revoke_under_issuing(&[], now() - 10);
    issuer.revoke_under_root(&[ISSUING_SERIAL], now() - 10);
    rewrite(&plane, due).await;
    assert_eq!(read_lists(&plane).await, (2, 0));
    assert_eq!(
        presents().await,
        CERTIFICATE_REVOKED,
        "the authority that certified the signer"
    );
    // A revocation is said before a list that may no longer be relied on.
    rewrite(
        &plane,
        "UPDATE certificate_revocation_lists SET usable_until = now() - interval '1 second' \
         WHERE uri LIKE '%/crl/issuing.crl'",
    )
    .await;
    assert_eq!(presents().await, CERTIFICATE_REVOKED);

    issuer.revoke_under_root(&[], now() - 5);
    rewrite(&plane, due).await;
    assert_eq!(read_lists(&plane).await, (2, 0));
    assert_eq!(presents().await, "verified");
    // Its chain's lists read, a credential citing a status list for the first
    // time waits for that one alone.
    assert_eq!(
        present_pid(&plane, &bearer, &issuer, Some(1)).await,
        LIST_NOT_READ_YET
    );
    assert_eq!(counted(&plane, "credential_status_lists").await, 1);

    // A certificate naming a list is written down once a day, so the sweep
    // knows a list in use.
    let cited_lately = "certificate_revocation_lists WHERE cited_at > now() - interval '1 minute'";
    rewrite(
        &plane,
        "UPDATE certificate_revocation_lists SET cited_at = now() - interval '23 hours'",
    )
    .await;
    assert_eq!(presents().await, "verified");
    assert_eq!(counted(&plane, cited_lately).await, 0);
    rewrite(
        &plane,
        "UPDATE certificate_revocation_lists SET cited_at = now() - interval '25 hours'",
    )
    .await;
    assert_eq!(presents().await, "verified");
    assert_eq!(counted(&plane, cited_lately).await, 2);

    rewrite(
        &plane,
        "UPDATE certificate_revocation_lists SET usable_until = now() - interval '1 second'",
    )
    .await;
    assert_eq!(presents().await, REVOCATION_STALE);

    // A list that could not be read, of an issuer the realm trusts through
    // another authority, is said to be so: what its address serves is no
    // list, or is past what this server reads.
    let unread = CertifiedIssuer::new();
    unread.publish(
        "/crl/issuing.crl",
        "application/pkix-crl",
        b"no list".to_vec(),
    );
    let anchor = deposit(&plane, &bearer, &unread.root.certificate).await;
    let (status, named) =
        name_by_certificate(&plane, &bearer, &unread.iss(), &[&anchor], &[PID]).await;
    assert_eq!(status, StatusCode::CREATED, "{named}");
    let fails = || present_pid(&plane, &bearer, &unread, None);
    assert_eq!(fails().await, REVOCATION_NOT_READ_YET);
    assert_eq!(
        read_lists(&plane).await,
        (1, 0),
        "the authority's list alone"
    );
    assert_eq!(fails().await, REVOCATION_NEVER_READ);
    let unread_list = format!("{}/crl/issuing.crl", unread.base);
    assert_eq!(
        revocation_failure(&plane, &unread_list).await,
        REVOCATION_UNREADABLE
    );
    for (octets, why) in [
        (4 * 1024 * 1024 - 1, REVOCATION_UNREADABLE),
        (4 * 1024 * 1024, REVOCATION_UNFETCHED),
    ] {
        unread.publish("/crl/issuing.crl", "application/pkix-crl", vec![0; octets]);
        rewrite(&plane, due).await;
        read_lists(&plane).await;
        assert_eq!(
            revocation_failure(&plane, &unread_list).await,
            why,
            "{octets}"
        );
    }

    // A realm that closes the verifier has its lists read no more.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/features/wallet-verifier"),
        &bearer,
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    rewrite(&plane, due).await;
    let refreshed =
        scheduler::revocation_lists::refresh_every_realm(&plane.tenancy(), &support::sealing())
            .await
            .expect("the realms listed");
    assert_eq!((refreshed.kept, refreshed.unread), (0, 0), "{refreshed:?}");
}

/// How many rows of the realm `of` names, a table and what narrows it.
async fn counted(plane: &Plane, of: &str) -> i64 {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    transaction
        .query_one(&format!("SELECT count(*) FROM {of}"), &[])
        .await
        .expect("a count")
        .get(0)
}

/// Why the revocation list at `uri` was last not kept.
async fn revocation_failure(plane: &Plane, uri: &str) -> String {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    transaction
        .query_one(
            "SELECT failure FROM certificate_revocation_lists WHERE uri = $1",
            &[&uri],
        )
        .await
        .expect("the list")
        .get::<_, Option<String>>(0)
        .unwrap_or_default()
}

/// The status list of an issuer trusted by certificate is read only under a
/// certificate of the authorities it is trusted through: one carrying no
/// chain, or one under another authority, leaves its credentials refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_status_list_is_read_under_a_certificate_of_its_issuers_authorities() {
    let (plane, bearer) = plane_that_verifies().await;
    let issuer = CertifiedIssuer::new();
    realm_trusting(&plane, &bearer, &issuer).await;
    let presents = || present_pid(&plane, &bearer, &issuer, Some(1));
    let stranger = CertifiedIssuer::new();
    issuer.publish_status_list(&[0], &stranger.status_signer.key, &stranger.chain());
    assert_eq!(presents().await, REVOCATION_NOT_READ_YET);
    assert_eq!(
        read_lists(&plane).await,
        (2, 0),
        "a list under another authority was kept"
    );
    assert_eq!(presents().await, LIST_NEVER_READ);
    assert_eq!(list_failure(&plane).await, LIST_UNANCHORED);

    let due = "UPDATE credential_status_lists SET due_at = now()";
    issuer.publish_status_list(&[0], &issuer.status_signer.key, &[]);
    rewrite(&plane, due).await;
    assert_eq!(
        read_lists(&plane).await,
        (0, 0),
        "a list carrying no chain was kept"
    );
    assert_eq!(list_failure(&plane).await, LIST_UNCHAINED);

    // A signer its authority revoked signs no list the realm keeps.
    issuer.publish_status_list(
        &[0],
        &issuer.status_signer.key,
        &[
            issuer.status_signer.certificate.clone(),
            issuer.issuing.certificate.clone(),
        ],
    );
    issuer.revoke_under_issuing(&[STATUS_SIGNER_SERIAL], now() - 30);
    rewrite(
        &plane,
        "UPDATE certificate_revocation_lists SET due_at = now()",
    )
    .await;
    rewrite(&plane, due).await;
    assert_eq!(read_lists(&plane).await, (2, 0));
    assert_eq!(list_failure(&plane).await, CERTIFICATE_REVOKED);

    issuer.revoke_under_issuing(&[], now() - 20);
    rewrite(
        &plane,
        "UPDATE certificate_revocation_lists SET due_at = now()",
    )
    .await;
    rewrite(&plane, due).await;
    assert_eq!(read_lists(&plane).await, (2, 1));
    assert_eq!(presents().await, "verified");

    // A list kept stays while the revocation of its signer cannot be
    // established: it is read again later, and relied on until it runs out.
    rewrite(
        &plane,
        "UPDATE certificate_revocation_lists SET usable_until = now() - interval '1 second'",
    )
    .await;
    rewrite(&plane, due).await;
    assert_eq!(read_lists(&plane).await, (0, 0));
    assert_eq!(list_failure(&plane).await, REVOCATION_STALE);
    assert_eq!(
        counted(&plane, "credential_status_lists WHERE statuses IS NOT NULL").await,
        1,
        "the list kept was forgotten for a revocation list gone stale"
    );

    // What a signer signed is no longer relied on once its authority revokes
    // it: the list kept is forgotten, until one is read under a certificate
    // that holds.
    issuer.revoke_under_issuing(&[STATUS_SIGNER_SERIAL], now() - 10);
    rewrite(
        &plane,
        "UPDATE certificate_revocation_lists SET due_at = now()",
    )
    .await;
    rewrite(&plane, due).await;
    assert_eq!(read_lists(&plane).await, (2, 0));
    assert_eq!(list_failure(&plane).await, CERTIFICATE_REVOKED);
    assert_eq!(presents().await, LIST_NEVER_READ);
    let renewed = certify(Issued {
        name: "PID Status",
        issuer: Some(&issuer.issuing),
        authority: false,
        serial: 0x23,
        revocation_list: Some(&format!("{}/crl/issuing.crl", issuer.base)),
        valid: YEAR,
    });
    issuer.publish_status_list(
        &[0],
        &renewed.key,
        &[
            renewed.certificate.clone(),
            issuer.issuing.certificate.clone(),
        ],
    );
    rewrite(&plane, due).await;
    assert_eq!(read_lists(&plane).await, (0, 1));
    assert_eq!(presents().await, "verified");
}

/// Why the realm's one status list was last not kept.
async fn list_failure(plane: &Plane) -> String {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    transaction
        .query_one("SELECT failure FROM credential_status_lists", &[])
        .await
        .expect("the list")
        .get::<_, Option<String>>(0)
        .unwrap_or_default()
}

/// An issuer is named by certificate through authorities the realm trusts and
/// for the types it issues, within the bounds, read back as it was named,
/// trusted anew through others, and an authority it is trusted through is not
/// withdrawn from under it. Its metadata is not read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_issuer_is_named_by_certificate_through_the_realms_authorities() {
    let (plane, bearer) = plane_that_verifies().await;
    let issuer = CertifiedIssuer::new();
    let (anchor, id) = realm_trusting(&plane, &bearer, &issuer).await;
    let issuers = format!("/admin/realms/{REALM}/credential-issuers");

    let (status, listed) = asked(&plane, Method::GET, &issuers, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let named = &listed["items"][0];
    assert_eq!(
        (
            &named["trusted_by"],
            &named["anchors"],
            &named["credential_types"],
            &named["keys"],
            &named["read_from"],
        ),
        (
            &json!("certificate"),
            &json!([anchor]),
            &json!([PID]),
            &json!([]),
            &Value::Null,
        ),
        "{named}"
    );

    for (issuer_named, anchors, types, said) in [
        (
            "https://other.example/pid",
            vec!["0000"],
            vec![PID],
            "trust the issuer through one to ten of the authorities this realm trusts",
        ),
        (
            "https://other.example/pid",
            vec![],
            vec![PID],
            "trust the issuer through one to ten of the authorities this realm trusts",
        ),
        // The authorities are judged before the types.
        (
            "https://other.example/pid",
            vec!["0000"],
            vec![],
            "trust the issuer through one to ten of the authorities this realm trusts",
        ),
        (
            "https://other.example/pid",
            vec![anchor.as_str()],
            vec![],
            "name the one to twenty credential types the issuer issues",
        ),
        (
            "http://other.example/pid",
            vec![anchor.as_str()],
            vec![PID],
            "name the issuer as its credentials name it: an https address",
        ),
    ] {
        let (status, told) =
            name_by_certificate(&plane, &bearer, issuer_named, &anchors, &types).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
        assert_eq!(told["message"], said);
    }
    let (status, told) =
        name_by_certificate(&plane, &bearer, &issuer.iss(), &[&anchor], &[PID]).await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");

    // Within the bounds and no further: ten authorities, twenty types of 256
    // characters, a name of 200.
    let mut ten = vec![anchor.clone()];
    for serial in 0x41..0x4a {
        let root = certify(Issued {
            name: "Another Root",
            issuer: None,
            authority: true,
            serial,
            revocation_list: None,
            valid: YEAR,
        });
        ten.push(deposit(&plane, &bearer, &root.certificate).await);
    }
    let eleventh = deposit(&plane, &bearer, &CertifiedIssuer::new().root.certificate).await;
    let eleven: Vec<&String> = ten.iter().chain([&eleventh]).collect();
    let twenty: Vec<String> = (0..19)
        .map(|at| format!("urn:example:type:{at}"))
        .chain(["x".repeat(256)])
        .collect();
    let other = "https://other.example/pid";
    let longest = format!("https://other.example/{}", "a".repeat(2048 - 22));
    assert_eq!(longest.len(), 2048);
    let named_as = |change: &dyn Fn(&mut Value)| {
        let mut body = json!({
            "name": "x".repeat(200),
            "issuer": other,
            "trusted_by": "certificate",
            "anchors": ten,
            "credential_types": twenty,
        });
        change(&mut body);
        body
    };
    let names = "give the issuer a name of at most 200 characters";
    let authorities = "trust the issuer through one to ten of the authorities this realm trusts";
    let types = "name the one to twenty credential types the issuer issues";
    let by_metadata = "this issuer is trusted by its metadata, not by certificate";
    for (body, said) in [
        (named_as(&|body| body["name"] = json!(" ")), names),
        (
            named_as(&|body| body["name"] = json!("x".repeat(201))),
            names,
        ),
        (
            named_as(&|body| body["issuer"] = json!(format!("{longest}a"))),
            "name the issuer as its credentials name it: an https address",
        ),
        (
            named_as(&|body| body["anchors"] = json!(eleven)),
            authorities,
        ),
        (
            named_as(&|body| {
                body["credential_types"]
                    .as_array_mut()
                    .expect("types")
                    .push(json!("urn:example:type:20"))
            }),
            types,
        ),
        (
            named_as(&|body| body["credential_types"] = json!(["x".repeat(257)])),
            types,
        ),
        (
            named_as(&|body| body["credential_types"] = json!([PID, " "])),
            types,
        ),
        (
            json!({ "name": "PID", "issuer": other, "anchors": [anchor] }),
            by_metadata,
        ),
        (
            json!({ "name": "PID", "issuer": other, "credential_types": [PID] }),
            by_metadata,
        ),
    ] {
        let (status, told) = asked(&plane, Method::POST, &issuers, &bearer, Some(body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
        assert_eq!(told["message"], said);
    }
    let (status, bounded) = asked(
        &plane,
        Method::POST,
        &issuers,
        &bearer,
        Some(named_as(&|body| body["issuer"] = json!(longest))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{bounded}");
    assert_eq!(
        (
            bounded["anchors"].as_array().map(Vec::len),
            bounded["credential_types"].as_array().map(Vec::len)
        ),
        (Some(10), Some(20))
    );
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{issuers}/{}", bounded["id"].as_str().expect("an id")),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("{issuers}/{id}/keys"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(
        told["message"],
        "this issuer is trusted by certificate: it publishes no keys to read"
    );

    let second = deposit(&plane, &bearer, &CertifiedIssuer::new().root.certificate).await;
    let (status, retrusted) = asked(
        &plane,
        Method::PUT,
        &format!("{issuers}/{id}/trust"),
        &bearer,
        Some(json!({
            "anchors": [second, format!(" {second} ")],
            "credential_types": [PID, "urn:eudi:mdl:1", format!(" {PID} ")],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{retrusted}");
    assert_eq!(retrusted["anchors"], json!([second]));
    assert_eq!(
        retrusted["credential_types"],
        json!(["urn:eudi:mdl:1", PID]),
        "named once and in order: {retrusted}"
    );
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{issuers}/nobody/trust"),
        &bearer,
        Some(json!({ "anchors": [second], "credential_types": [PID] })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");

    let anchors = format!("/admin/realms/{REALM}/trust-anchors");
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{anchors}/{second}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(
        told["message"],
        "an issuer this realm names is trusted through this authority: trust it through \
         another, or forget it, first"
    );
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{anchors}/{anchor}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "an authority no issuer is trusted through"
    );
    // The issuer is no longer trusted through the first authority.
    assert_eq!(
        present(&plane, &bearer, &issuer, &issuer.signed(), &pid_query()).await,
        CREDENTIAL_UNANCHORED
    );
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{issuers}/{id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{anchors}/{second}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    for (authorities, said) in [
        (
            json!([{ "type": "etsi_tl", "values": ["https://lotl.example"] }]),
            "trusted authorities are matched by aki alone",
        ),
        (
            json!([{ "type": "aki", "values": ["not base64url!"] }]),
            "an aki entry holds one to fifty key identifiers in base64url",
        ),
        (
            json!([]),
            "trusted authorities are one to ten entries, each a type and its values",
        ),
    ] {
        let mut query = pid_query();
        query["credentials"][0]["trusted_authorities"] = authorities;
        let (status, told) = asked(
            &plane,
            Method::POST,
            &format!("/admin/realms/{REALM}/presentations"),
            &bearer,
            Some(json!({ "dcql_query": query })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
        assert_eq!(told["message"], said);
    }
}

/// One way per issuer: an issuer the realm trusts by its metadata is verified
/// by the keys it publishes, whatever chain its credentials carry, holds to
/// no authority a query trusts, and is not trusted anew by certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_issuer_trusted_by_its_metadata_is_not_verified_by_a_chain() {
    let (plane, bearer) = plane_that_verifies().await;
    let issuer = CertifiedIssuer::new();
    super::wallet::verifier_running();
    mint_request_key(&plane, &bearer).await;
    deposit(&plane, &bearer, &issuer.root.certificate).await;
    let published = EcKeyPair::generate(EcCurve::P256).expect("a key");
    issuer.publish(
        "/.well-known/jwt-vc-issuer/pid",
        "application/json",
        json!({
            "issuer": issuer.iss(),
            "jwks": { "keys": [published.to_jwk_public_key().as_ref()] },
        })
        .to_string()
        .into_bytes(),
    );
    let issuers = format!("/admin/realms/{REALM}/credential-issuers");
    let (status, named) = super::wallet::asked_under(
        &plane,
        config::serving::Egress::Anywhere,
        Method::POST,
        &issuers,
        &bearer,
        Some(json!({ "name": "PID provider", "issuer": issuer.iss() })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{named}");
    assert_eq!(named["trusted_by"], "metadata");

    let chained = issuer.signed();
    assert_eq!(
        present(&plane, &bearer, &issuer, &chained, &pid_query()).await,
        "a credential's signature is not its issuer's",
        "a chain up to an authority the realm trusts, of an issuer trusted by its keys"
    );
    let keyed = Signed {
        key: &published,
        ..issuer.signed()
    };
    assert_eq!(
        present(&plane, &bearer, &issuer, &keyed, &pid_query()).await,
        "verified"
    );
    let mut trusting = pid_query();
    let identifier = subject_key_identifier(&issuer.issuing.certificate).expect("an identifier");
    trusting["credentials"][0]["trusted_authorities"] =
        json!([{ "type": "aki", "values": [BASE64URL_NOPAD.encode(&identifier)] }]);
    assert_eq!(
        present(&plane, &bearer, &issuer, &keyed, &trusting).await,
        "a credential's chain names none of the authorities the query trusts"
    );

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{issuers}/{}/trust", named["id"].as_str().expect("an id")),
        &bearer,
        Some(json!({ "anchors": [], "credential_types": [PID] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(
        told["message"],
        "this issuer is trusted by its metadata, not by certificate"
    );
}
