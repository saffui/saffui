use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::{Duration, Utc};
use deadpool_postgres::Pool;
use secrecy::ExposeSecret;
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::dto::uncached;

/// How long the answer to one screen stays good. Gateways cut idle sessions
/// far sooner; this only bounds how long an anchor row can lie around.
const SCREEN_LIFESPAN: i64 = 180;

/// What a gateway posts, in the shape the common aggregators speak: the
/// gateway's own session id, the dialling phone in international form, and
/// everything typed so far joined by `*`.
#[derive(serde::Deserialize)]
#[allow(non_snake_case, reason = "the field names are the aggregators' wire")]
pub struct Dialled {
    pub sessionId: Option<String>,
    pub phoneNumber: Option<String>,
    pub text: Option<String>,
}

/// One leg of a USSD conversation with the realm's doorbell.
///
/// The gateway is the caller and must prove it: a callback that can name any
/// phone number decides sign-ins on behalf of whoever it names, so without
/// the realm's secret nothing here answers. The person is the number, which
/// only identifies where exactly one account has proven it, and every
/// answer a stranger could provoke reads the same as an empty doorbell.
pub async fn callback(
    request: HttpRequest,
    realm: web::Path<String>,
    body: Option<web::Form<Dialled>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
) -> HttpResponse {
    let now = Utc::now();
    let Ok(mut connection) = pool.get().await else {
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "");
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return plain(StatusCode::NOT_FOUND, "");
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "");
    };
    let Ok(ring) = store::keyring::load(
        &transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    else {
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "");
    };
    let Ok(Some(secret)) =
        store::providers::ussd::load_secret(&transaction, &ring, &sealing.envelope).await
    else {
        // No gateway named is a door that does not exist.
        return plain(StatusCode::NOT_FOUND, "");
    };
    if !presented_secret_matches(&request, &sealing, &secret) {
        return plain(StatusCode::UNAUTHORIZED, "");
    }

    let Some(body) = body.map(|held| held.into_inner()) else {
        return plain(StatusCode::BAD_REQUEST, "");
    };
    let (Some(session_id), Some(phone)) = (
        body.sessionId.filter(|held| !held.is_empty()),
        body.phoneNumber.filter(|held| !held.is_empty()),
    ) else {
        return plain(StatusCode::BAD_REQUEST, "");
    };
    let Ok(Some(realm_row)) = store::providers::realms::of_context(&transaction).await else {
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "");
    };
    let tongue = realm_row.default_locale.as_deref().unwrap_or("en");

    // The number identifies the way it does at the login: proven, and one
    // account's. Anyone else hears an empty doorbell, in those exact bytes.
    let compact: String = phone.chars().filter(|held| !held.is_whitespace()).collect();
    let person = match store::providers::users::sole_by_proven_phone(&transaction, &compact).await {
        Ok(found) => found.filter(|held| held.enabled),
        Err(_) => return plain(StatusCode::INTERNAL_SERVER_ERROR, ""),
    };

    // The last thing typed on this session, whatever came before it: a
    // person who mistyped once still answers with their next digit.
    let answered = body
        .text
        .as_deref()
        .unwrap_or("")
        .rsplit('*')
        .next()
        .unwrap_or("")
        .trim()
        .to_owned();

    let answer = match (person, answered.as_str()) {
        (None, _) => end(nothing_waiting(tongue)),
        (Some(person), "1" | "2") => {
            let Ok(anchored) =
                store::providers::ussd::take_anchor(&transaction, &session_id, now).await
            else {
                return plain(StatusCode::INTERNAL_SERVER_ERROR, "");
            };
            match anchored.filter(|(user, _)| *user == person.user_id) {
                None => end(screen_gone(tongue)),
                Some((_, digest)) => {
                    let approved = answered == "1";
                    let Ok(decided) = store::providers::backchannel::decide(
                        &transaction,
                        &digest,
                        &person.user_id,
                        approved,
                        now,
                    )
                    .await
                    else {
                        return plain(StatusCode::INTERNAL_SERVER_ERROR, "");
                    };
                    match decided {
                        None => end(nothing_waiting(tongue)),
                        Some(decided) => {
                            let ping =
                                super::ciba::ping_of(&transaction, &sealing, &context, &decided)
                                    .await;
                            if transaction.commit().await.is_err() {
                                return plain(StatusCode::INTERNAL_SERVER_ERROR, "");
                            }
                            if let Some((endpoint, bearer, auth_req_id)) = ping {
                                super::ciba::deliver_ping(endpoint, bearer, auth_req_id).await;
                            }
                            return plain(StatusCode::OK, &end(decided_words(tongue, approved)));
                        }
                    }
                }
            }
        }
        (Some(person), _) => {
            // First visit, or an answer that was neither digit: show the
            // oldest waiting request and anchor it to this session, so the
            // digit that comes back decides the request that was shown.
            let Ok(waiting) =
                store::providers::backchannel::pending_for(&transaction, &person.user_id, now)
                    .await
            else {
                return plain(StatusCode::INTERNAL_SERVER_ERROR, "");
            };
            match waiting.first() {
                None => end(nothing_waiting(tongue)),
                Some((digest, request)) => {
                    if store::providers::ussd::anchor(
                        &transaction,
                        &session_id,
                        &person.user_id,
                        digest,
                        now + Duration::seconds(SCREEN_LIFESPAN),
                    )
                    .await
                    .is_err()
                    {
                        return plain(StatusCode::INTERNAL_SERVER_ERROR, "");
                    }
                    format!(
                        "CON {}",
                        doorbell_screen(
                            tongue,
                            &request.client_id,
                            request.binding_message.as_deref()
                        )
                    )
                }
            }
        }
    };
    if transaction.commit().await.is_err() {
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "");
    }
    plain(StatusCode::OK, &answer)
}

/// Whether the caller presented the realm's secret, compared through the
/// digest so equality takes the same time however wrong the guess is.
fn presented_secret_matches(
    request: &HttpRequest,
    sealing: &Sealing,
    secret: &secrecy::SecretBox<String>,
) -> bool {
    let Some(presented) = request
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|held| held.to_str().ok())
        .and_then(|held| held.strip_prefix("Bearer "))
    else {
        return false;
    };
    let hashed = |value: &str| {
        sealing
            .provider
            .digest()
            .hash(crypto::provider::HashAlg::Sha256, value.as_bytes())
            .ok()
    };
    match (hashed(presented), hashed(secret.expose_secret())) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn plain(status: StatusCode, body: &str) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(status))
        .insert_header(("Content-Type", "text/plain; charset=utf-8"))
        .body(body.to_owned())
}

fn end(words: String) -> String {
    format!("END {words}")
}

/// The waiting request, said in one screen: who asks, the binding message
/// when the client sent one, and the two digits that answer. Held under a
/// gateway screen's size by cutting the client's parts, never the digits.
fn doorbell_screen(tongue: &str, client_id: &str, binding_message: Option<&str>) -> String {
    let mut named = client_id.chars().take(40).collect::<String>();
    if let Some(message) = binding_message.filter(|held| !held.is_empty()) {
        named.push_str(": ");
        named.extend(message.chars().take(60));
    }
    match tongue {
        "fr" => format!("Connexion {named}\n1 Approuver\n2 Refuser"),
        _ => format!("Sign-in {named}\n1 Approve\n2 Refuse"),
    }
}

fn nothing_waiting(tongue: &str) -> String {
    match tongue {
        "fr" => "Aucune demande en attente.".to_owned(),
        _ => "Nothing is waiting for you.".to_owned(),
    }
}

fn screen_gone(tongue: &str) -> String {
    match tongue {
        "fr" => "Session expiree. Recomposez pour reessayer.".to_owned(),
        _ => "That screen has expired. Dial again.".to_owned(),
    }
}

fn decided_words(tongue: &str, approved: bool) -> String {
    match (tongue, approved) {
        ("fr", true) => "Demande approuvee.".to_owned(),
        ("fr", false) => "Demande refusee.".to_owned(),
        (_, true) => "Request approved.".to_owned(),
        (_, false) => "Request refused.".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every screen this bridge can speak fits a gateway's message, in both
    /// tongues and with the longest parts a client could send.
    #[test]
    fn every_screen_fits_one_gateway_message() {
        let long_client = "c".repeat(120);
        let long_message = "m".repeat(200);
        for tongue in ["en", "fr"] {
            for screen in [
                format!(
                    "CON {}",
                    doorbell_screen(tongue, &long_client, Some(&long_message))
                ),
                end(nothing_waiting(tongue)),
                end(screen_gone(tongue)),
                end(decided_words(tongue, true)),
                end(decided_words(tongue, false)),
            ] {
                assert!(
                    screen.chars().count() <= 160,
                    "a screen outgrew the gateway: {screen}"
                );
            }
        }
    }
}
