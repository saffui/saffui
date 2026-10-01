#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use super::wallet::{
    answered, ask_for, asked, client_id_and_nonce, encrypted, identity_answer, identity_query,
    pid_query, plane_that_verifies, realm_ready_for_identity, realm_ready_to_verify, standing_of,
};
use actix_web::http::{Method, StatusCode};
use serde_json::{Value, json};
use services::verifier::status::{
    LIST_NEVER_READ, LIST_NOT_READ_YET, LIST_OTHER_PURPOSE, LIST_STALE, LISTS_FULL, REVOKED,
    STATUS_DENIES, STATUS_DISCLOSED, STATUS_OUT_OF_LIST, SUSPENDED,
};
use store::tenancy::TenantContext;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// What an issuer's status host serves, by path: the media type and the body.
type Published = Arc<Mutex<HashMap<String, (&'static str, String)>>>;

/// A host serving whatever status lists the test publishes on it, and nothing
/// else: a token only to whoever asks for one, as §8.1 has a verifier ask.
fn serve_status_lists() -> (String, Published) {
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
            let found = served.lock().expect("the lists").get(asked.path()).cloned();
            let accepted = asked
                .headers()
                .get("accept")
                .and_then(|accepted| accepted.to_str().ok())
                .map(str::to_owned);
            async move {
                match found {
                    Some((media_type, _))
                        if media_type == "application/statuslist+jwt"
                            && accepted.as_deref() != Some(media_type) =>
                    {
                        HttpResponse::NotAcceptable().finish()
                    }
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

fn publish(published: &Published, path: &str, media_type: &'static str, body: String) {
    published
        .lock()
        .expect("the lists")
        .insert(path.to_owned(), (media_type, body));
}

/// One pass of the scheduled reading, as a node runs it.
async fn read_lists(plane: &Plane) -> scheduler::status_lists::Refreshed {
    scheduler::status_lists::refresh_every_realm(&plane.tenancy(), &support::sealing())
        .await
        .expect("the realms listed")
}

/// Make every list of the realm due now, or no longer relied on.
async fn rewrite_lists(plane: &Plane, set: &str) {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    transaction
        .execute(&format!("UPDATE credential_status_lists SET {set}"), &[])
        .await
        .expect("the lists rewritten");
    transaction.commit().await.expect("committed");
}

/// A token list's statuses, compressed as §4.1 writes them.
fn compressed_statuses(statuses: &[u8]) -> String {
    use std::io::Write;
    let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    zlib.write_all(statuses).expect("compressed");
    data_encoding::BASE64URL_NOPAD.encode(&zlib.finish().expect("compressed"))
}

fn list_claims(uri: &str, issued_at: i64, statuses: &[u8]) -> Value {
    json!({
        "sub": uri,
        "iat": issued_at,
        "exp": issued_at + 3_600,
        "ttl": 600,
        "status_list": { "bits": 2, "lst": compressed_statuses(statuses) },
    })
}

/// Present the PID the wallet holds for a request the realm asks, and say what
/// the request came to: verified, or the reason it failed.
async fn present_pid(plane: &Plane, bearer: &str, wallet: &super::wallet::Wallet) -> String {
    let (asked_for, request) = ask_for(plane, bearer, &pid_query()).await;
    let (client_id, nonce) = client_id_and_nonce(&request);
    let answer = json!({
        "vp_token": { "pid": [wallet.presented(client_id, nonce)] },
        "state": request["state"],
    });
    settled(plane, bearer, &asked_for, &request, &answer).await
}

async fn settled(
    plane: &Plane,
    bearer: &str,
    asked_for: &Value,
    request: &serde_json::Map<String, Value>,
    answer: &Value,
) -> String {
    let response = encrypted(request, answer);
    let (status, told) = answered(plane, request, &[("response", &response)]).await;
    let standing = standing_of(plane, bearer, &asked_for["id"]).await;
    match standing["status"].as_str() {
        Some("verified") => {
            assert_eq!(status, StatusCode::OK, "{told}");
            "verified".to_owned()
        }
        _ => {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
            assert_eq!(standing["status"], "failed", "{standing}");
            standing["outcome"]["reason"]
                .as_str()
                .expect("a reason")
                .to_owned()
        }
    }
}

/// An SD-JWT VC is held to the Token Status List its issuer signs it as citing:
/// refused until the scheduled pass has read the list, then by what the status
/// it cites says, the list read again as it falls due and never replaced by an
/// older writing or one another key signed. Nothing of the list is fetched
/// while a person presents.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_sd_jwt_credential_is_held_to_the_status_list_its_issuer_signs() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_ready_to_verify(&plane, &bearer).await;
    let (lists, published) = serve_status_lists();
    let uri = format!("{lists}/statuslists/1");
    let citing = |index: u64| wallet.citing(json!({ "status_list": { "idx": index, "uri": uri } }));
    let now = chrono::Utc::now().timestamp();
    // Two bits to a status: valid, revoked, suspended, and three, which says
    // nothing this verifier reads as holding.
    let statuses = [0b1110_0100, 0b0000_0000];
    publish(
        &published,
        "/statuslists/1",
        "application/statuslist+jwt",
        wallet.signed_status_list(&list_claims(&uri, now - 60, &statuses)),
    );

    assert_eq!(
        present_pid(&plane, &bearer, &citing(0)).await,
        LIST_NOT_READ_YET
    );
    assert_eq!(
        present_pid(&plane, &bearer, &citing(0)).await,
        LIST_NOT_READ_YET,
        "a presentation read the list itself"
    );
    let refreshed = read_lists(&plane).await;
    assert_eq!((refreshed.kept, refreshed.unread), (1, 0));
    for (index, verdict) in [
        (0, "verified"),
        (1, REVOKED),
        (2, SUSPENDED),
        (3, STATUS_DENIES),
        (4, "verified"),
        (8, STATUS_OUT_OF_LIST),
        (u64::MAX, STATUS_OUT_OF_LIST),
    ] {
        assert_eq!(
            present_pid(&plane, &bearer, &citing(index)).await,
            verdict,
            "{index}"
        );
    }
    assert_eq!(
        present_pid(&plane, &bearer, &wallet).await,
        "verified",
        "a credential citing no status was refused"
    );
    assert_eq!(
        present_pid(&plane, &bearer, &citing(0).concealing_status()).await,
        STATUS_DISCLOSED
    );

    // The issuer revokes the first: seen once the list falls due again.
    let revoked = [0b1110_0101, 0b0000_0000];
    publish(
        &published,
        "/statuslists/1",
        "application/statuslist+jwt",
        wallet.signed_status_list(&list_claims(&uri, now, &revoked)),
    );
    assert_eq!(
        read_lists(&plane).await.kept,
        0,
        "a list was read before it was due"
    );
    assert_eq!(present_pid(&plane, &bearer, &citing(0)).await, "verified");
    rewrite_lists(&plane, "due_at = now() - interval '1 second'").await;
    assert_eq!(read_lists(&plane).await.kept, 1);
    assert_eq!(present_pid(&plane, &bearer, &citing(0)).await, REVOKED);

    // An older writing served again, or a list another key signed, is not kept:
    // the revocation holds.
    for served in [
        wallet.signed_status_list(&list_claims(&uri, now - 60, &statuses)),
        super::wallet::Wallet::new(lists.clone(), {
            crypto::jose::jwk::alg::ed::EdKeyPair::generate(crypto::jose::jwk::Ed25519)
                .expect("another key")
        })
        .signed_status_list(&list_claims(&uri, now + 60, &statuses)),
    ] {
        publish(
            &published,
            "/statuslists/1",
            "application/statuslist+jwt",
            served,
        );
        rewrite_lists(&plane, "due_at = now() - interval '1 second'").await;
        let refreshed = read_lists(&plane).await;
        assert_eq!((refreshed.kept, refreshed.unread), (0, 1));
        assert_eq!(present_pid(&plane, &bearer, &citing(0)).await, REVOKED);
    }

    // What was read last may be relied on only so long.
    rewrite_lists(&plane, "usable_until = now() - interval '1 second'").await;
    assert_eq!(present_pid(&plane, &bearer, &citing(0)).await, LIST_STALE);

    // A list nothing is served at is written down, then said unread.
    let missing = wallet.citing(json!({
        "status_list": { "idx": 0, "uri": format!("{lists}/statuslists/missing") }
    }));
    assert_eq!(
        present_pid(&plane, &bearer, &missing).await,
        LIST_NOT_READ_YET
    );
    let refreshed = read_lists(&plane).await;
    assert_eq!(refreshed.unread, 1, "{refreshed:?}");
    assert_eq!(
        present_pid(&plane, &bearer, &missing).await,
        LIST_NEVER_READ
    );
    let refreshed = read_lists(&plane).await;
    assert_eq!(
        (refreshed.kept, refreshed.unread),
        (0, 0),
        "a list that could not be read was tried again at once"
    );

    // A list of many statuses travels larger than a request object may.
    let mut drawn = 0x2545_f491_4f6c_dd1d_u64;
    let many: Vec<u8> = (0..96 * 1024)
        .map(|_| {
            drawn ^= drawn << 13;
            drawn ^= drawn >> 7;
            drawn ^= drawn << 17;
            drawn as u8
        })
        .collect();
    let big = format!("{lists}/statuslists/big");
    let token = wallet.signed_status_list(&json!({
        "sub": big,
        "iat": now,
        "status_list": { "bits": 1, "lst": compressed_statuses(&many) },
    }));
    assert!(token.len() > 64 * 1024, "{}", token.len());
    publish(
        &published,
        "/statuslists/big",
        "application/statuslist+jwt",
        token,
    );
    let citing_big =
        |index: u64| wallet.citing(json!({ "status_list": { "idx": index, "uri": big } }));
    assert_eq!(
        present_pid(&plane, &bearer, &citing_big(0)).await,
        LIST_NOT_READ_YET
    );
    assert_eq!(read_lists(&plane).await.kept, 1);
    for index in [0_u64, 1, 7, 786_431] {
        let set = (many[(index / 8) as usize] >> (index % 8)) & 1 == 1;
        assert_eq!(
            present_pid(&plane, &bearer, &citing_big(index)).await,
            if set { REVOKED } else { "verified" },
            "{index}"
        );
    }

    // A citation is noted, a day apart at most, so the sweep knows a list in use.
    rewrite_lists(&plane, "cited_at = now() - interval '2 days'").await;
    present_pid(&plane, &bearer, &citing_big(0)).await;
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    let uncited: Vec<String> = transaction
        .query(
            "SELECT uri FROM credential_status_lists \
             WHERE cited_at < now() - interval '1 day' ORDER BY uri",
            &[],
        )
        .await
        .expect("a census")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        uri_paths(&uncited),
        ["/statuslists/1", "/statuslists/missing"]
    );

    // A realm follows a thousand lists at most: a credential citing one more
    // is refused.
    transaction
        .execute(
            "INSERT INTO credential_status_lists \
                 (tenant, realm_id, issuer_id, uri, format, due_at, cited_at) \
             SELECT tenant, realm_id, issuer_id, 'https://filler.example/' || n, 'token', \
                    now() + interval '1 day', now() \
             FROM realm_credential_issuers, \
                  generate_series(1, 1000 - (SELECT count(*) FROM credential_status_lists)::int) n",
            &[],
        )
        .await
        .expect("the realm filled");
    transaction.commit().await.expect("committed");
    let one_more = wallet.citing(json!({
        "status_list": { "idx": 0, "uri": format!("{lists}/statuslists/one-more") }
    }));
    assert_eq!(present_pid(&plane, &bearer, &one_more).await, LISTS_FULL);

    // A realm that closes the verifier has its lists read no more.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}/features/wallet-verifier", support::REALM),
        &bearer,
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    rewrite_lists(&plane, "due_at = now() - interval '1 second'").await;
    let refreshed = read_lists(&plane).await;
    assert_eq!((refreshed.kept, refreshed.unread), (0, 0), "{refreshed:?}");
}

/// The paths of addresses on the status host.
fn uri_paths(uris: &[String]) -> Vec<String> {
    uris.iter()
        .map(|uri| url::Url::parse(uri).expect("an address").path().to_owned())
        .collect()
}

/// The identity credential under the VCDM 2.0 context, citing `status`, and
/// presented the way 2.0 presents: under the same context.
fn identity_citing(
    wallet: &super::wallet::IdentityWallet,
    status: Value,
    request: &serde_json::Map<String, Value>,
) -> Value {
    let credential = wallet.issued_as(|credential, _| {
        let members = credential.as_object_mut().expect("a credential");
        let context = members["@context"][1].clone();
        members.insert(
            "@context".to_owned(),
            json!([
                jsonld::built_in::CREDENTIALS_V2,
                context,
                jsonld::built_in::ED25519_2020_V1
            ]),
        );
        let issued = members.remove("issuanceDate").expect("a date of issue");
        let expires = members.remove("expirationDate").expect("an expiry");
        members.insert("validFrom".to_owned(), issued);
        members.insert("validUntil".to_owned(), expires);
        if !status.is_null() {
            members.insert("credentialStatus".to_owned(), status);
        }
    });
    let (client_id, nonce) = client_id_and_nonce(request);
    let presentation =
        wallet.presented_as(vec![credential], client_id, nonce, |presentation, _| {
            presentation["@context"] = json!([
                jsonld::built_in::CREDENTIALS_V2,
                jsonld::built_in::JWS_2020_V1
            ]);
        });
    identity_answer(presentation, request)
}

fn bitstring_entry(uri: &str, purpose: &str, index: u64) -> Value {
    json!({
        "type": "BitstringStatusListEntry",
        "statusPurpose": purpose,
        "statusListIndex": index.to_string(),
        "statusListCredential": uri,
    })
}

/// A JSON-LD credential under the VCDM 2.0 context is held to the Bitstring
/// Status Lists its entries cite, each read off the dataset its proof signs,
/// the bits read from the most significant, revocation and suspension both
/// refused, and an entry naming a purpose its list does not serve refused too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_json_ld_credential_is_held_to_its_bitstring_status_lists() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_ready_for_identity(&plane, &bearer).await;
    let (lists, published) = serve_status_lists();
    let revocations = format!("{lists}/status/revocation");
    let suspensions = format!("{lists}/status/suspension");
    let short = format!("{lists}/status/short");
    // 131 072 statuses, the fifth set: the fifth bit from the left.
    let mut statuses = vec![0u8; 16_384];
    statuses[0] = 0b0000_0100;
    for (uri, path, purpose) in [
        (&revocations, "/status/revocation", "revocation"),
        (&suspensions, "/status/suspension", "suspension"),
    ] {
        publish(
            &published,
            path,
            "application/vc",
            wallet
                .signed_status_list(uri, purpose, &statuses)
                .to_string(),
        );
    }
    publish(
        &published,
        "/status/short",
        "application/vc",
        wallet
            .signed_status_list(&short, "revocation", &statuses[..1_024])
            .to_string(),
    );
    let query = identity_query(&[&["credentialSubject", "fullName"]]);
    let present = |status: Value| {
        let (plane, bearer, wallet, query) = (&plane, bearer.as_str(), &wallet, &query);
        async move {
            let (asked_for, request) = ask_for(plane, bearer, query).await;
            let answer = identity_citing(wallet, status, &request);
            settled(plane, bearer, &asked_for, &request, &answer).await
        }
    };

    assert_eq!(
        present(Value::Null).await,
        "verified",
        "a 2.0 credential citing nothing"
    );
    assert_eq!(
        present(json!([
            bitstring_entry(&revocations, "revocation", 4),
            bitstring_entry(&suspensions, "suspension", 4),
        ]))
        .await,
        LIST_NOT_READ_YET
    );
    assert_eq!(
        present(bitstring_entry(&short, "revocation", 4)).await,
        LIST_NOT_READ_YET
    );
    let refreshed = read_lists(&plane).await;
    assert_eq!((refreshed.kept, refreshed.unread), (2, 1), "{refreshed:?}");

    for (status, verdict) in [
        (
            json!([
                bitstring_entry(&revocations, "revocation", 4),
                bitstring_entry(&suspensions, "suspension", 4),
            ]),
            "verified",
        ),
        (bitstring_entry(&revocations, "revocation", 5), REVOKED),
        (bitstring_entry(&suspensions, "suspension", 5), SUSPENDED),
        (
            bitstring_entry(&revocations, "revocation", 131_072),
            STATUS_OUT_OF_LIST,
        ),
        (
            bitstring_entry(&revocations, "suspension", 4),
            LIST_OTHER_PURPOSE,
        ),
        (bitstring_entry(&short, "revocation", 4), LIST_NEVER_READ),
    ] {
        assert_eq!(present(status.clone()).await, verdict, "{status}");
    }
    let kept = kept_outcomes(&plane).await;
    assert!(
        !kept.contains(&revocations) && !kept.contains("131072"),
        "a status a credential cited was kept: {kept}"
    );
}

/// What every request the realm asked came to, as kept.
async fn kept_outcomes(plane: &Plane) -> String {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    let rows = transaction
        .query("SELECT outcome::text FROM presentation_requests", &[])
        .await
        .expect("the requests");
    rows.iter()
        .filter_map(|row| row.get::<_, Option<String>>(0))
        .collect::<Vec<_>>()
        .join("\n")
}
