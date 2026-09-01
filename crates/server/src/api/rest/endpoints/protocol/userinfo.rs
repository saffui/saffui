use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::{Value, json};
use services::userinfo::{self, Untold};
use store::tenancy::{Tenancy, resolve};

use crate::api::provenance::read_client_certificate;
use crate::api::rest::endpoints::protocol::basic;
use crate::api::rest::endpoints::protocol::dto::uncached;

/// Tell what the token allows.
///
/// Both verbs, as OIDC Core §5.3.1 requires. A client that can only issue one of
/// them is one this endpoint would be unreachable from.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn tell(
    request: HttpRequest,
    realm: web::Path<String>,
    body: Option<web::Form<Carried>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<crate::api::config::Sealing>,
    origin: web::Data<config::serving::PublicOrigin>,
) -> HttpResponse {
    let now = Utc::now();
    let Some(bearer) = presented(&request, body.as_deref()) else {
        return challenged("a bearer token is required");
    };
    let Ok(mut connection) = pool.get().await else {
        return faulted();
    };
    // Answered as an unacceptable token, not as a missing realm: which realms
    // exist is not something a caller holding no valid token gets to map.
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return challenged("the token presented is not one this realm accepts");
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return faulted();
    };
    let Ok(keys) = services::realm::published_keys(&transaction).await else {
        return faulted();
    };

    // RFC 8705 §3. Read only from a proxy this deployment named, so an
    // ordinary caller cannot claim a certificate by writing a header.
    let certificate = read_client_certificate(&request, sealing.provider.as_ref());

    // RFC 9449 §7.1. Proven here, where the token is presented, and carrying
    // `ath`: a proof that did not name this token would bind a request holding
    // another one.
    // §4.3: one proof and exactly one. Reading the first of two would verify
    // one header while the other rode along unexamined.
    if request.headers().get_all("dpop").count() > 1 {
        return challenged("one proof, exactly");
    }
    let proven = match request.headers().get("dpop") {
        None => None,
        Some(proof) => {
            let Ok(proof) = proof.to_str() else {
                return challenged("the proof could not be read");
            };
            match services::dpop::proven(
                &transaction,
                sealing.provider.as_ref(),
                proof,
                services::dpop::Bound {
                    method: request.method().as_str(),
                    url: &format!(
                        "{}/realms/{}/protocol/openid-connect/userinfo",
                        origin.as_str(),
                        context.realm_id
                    ),
                    access_token: Some(&bearer),
                },
                now,
            )
            .await
            {
                Ok(proven) => Some(proven),
                Err(_) => return challenged("the proof does not bind this request"),
            }
        }
    };
    // The spend above has to outlive this read, or the same proof presents
    // again tomorrow: a replay refused on paper and rolled back in practice
    // is not refused. Committed here and the claims read on a fresh
    // transaction, so a failure past this point costs nothing recorded.
    let transaction = if proven.is_some() {
        if transaction.commit().await.is_err() {
            return challenged("the proof could not be spent");
        }
        let Ok(fresh) = tenancy.transaction(&mut connection, &context).await else {
            return challenged("the realm could not be read");
        };
        fresh
    } else {
        transaction
    };

    match userinfo::claims_for(
        &transaction,
        &keys,
        &bearer,
        services::token::Proofs {
            key: proven.as_ref(),
            certificate: certificate.as_deref(),
        },
        now,
    )
    .await
    {
        Ok(answer) if !answer.is_a_token() => {
            uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
                .json(Value::Object(answer.claims))
        }
        // §5.3.2: a client that registered a signed or encrypted response is
        // answered with one or not at all. Falling back to JSON would answer a
        // client that is going to verify a signature with something that has
        // none, and one that is going to decrypt with something readable.
        Ok(answer) => {
            let Ok(ring) = store::keyring::load(
                &transaction,
                &sealing.envelope,
                &context.tenant,
                &context.realm_id,
            )
            .await
            else {
                return faulted();
            };
            let signing = services::grant::Signing {
                provider: sealing.provider.as_ref(),
                ring: &ring,
                envelope: &sealing.envelope,
            };
            match userinfo::told_answer(
                &transaction,
                &signing,
                &origin.issuer(&context.realm_id),
                &answer,
            )
            .await
            {
                Ok(told) => uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
                    .insert_header(("Content-Type", "application/jwt"))
                    .body(told),
                Err(_) => unsignable(),
            }
        }
        Err(Untold::InvalidToken) => {
            tracing::warn!("userinfo refused");
            challenged("the token presented is not one this realm accepts")
        }
        Err(Untold::Unreadable) => faulted(),
    }
}

/// What a form body may carry, RFC 6750 §2.2.
#[derive(Debug, Deserialize)]
pub struct Carried {
    pub access_token: Option<String>,
}

/// The header, or the form field RFC 6750 §2.2 also allows, and never both.
/// The query form is deliberately not read: a token in a URL lands in logs
/// and history.
fn presented(request: &HttpRequest, body: Option<&Carried>) -> Option<String> {
    // RFC 9449 §7.1 beside RFC 6750: a bound token arrives under the `DPoP`
    // scheme, an unbound one under `Bearer`, and the scheme is name-matched
    // the case-insensitive way §11.1 of RFC 9110 reads every scheme. Which
    // proof the token then needs is the token's `cnf` to say, not the
    // scheme's.
    let from_header = basic::bearer(request).or_else(|| {
        let header = request.headers().get("authorization")?.to_str().ok()?;
        let (scheme, token) = header.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("DPoP") {
            return None;
        }
        let token = token.trim();
        (!token.is_empty()).then(|| token.to_owned())
    });
    match (from_header, body.and_then(|form| form.access_token.clone())) {
        (Some(header), None) => Some(header),
        (None, Some(field)) if !field.is_empty() => Some(field),
        // Two tokens is one more than a request may carry: §2 forbids it, and
        // picking one would let the other ride along unexamined.
        _ => None,
    }
}

/// RFC 6750 §3: a bearer failure carries a challenge saying what was wrong with
/// the credential, and nothing about who holds one.
fn challenged(description: &str) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(StatusCode::UNAUTHORIZED))
        .insert_header((
            "WWW-Authenticate",
            format!(r#"Bearer error="invalid_token", error_description="{description}""#),
        ))
        .json(json!({
            "error": "invalid_token",
            "error_description": description,
        }))
}

/// A client registered a signature this realm holds no key for. Its own
/// error, because "the realm could not be read" would send an operator
/// looking at the database rather than at the key it never generated.
fn unsignable() -> HttpResponse {
    tracing::warn!("a registered userinfo signature could not be made");
    uncached(&mut HttpResponseBuilder::new(
        StatusCode::INTERNAL_SERVER_ERROR,
    ))
    .json(json!({
        "error": "server_error",
        "error_description": "this realm holds no key for the signature this client registered",
    }))
}

fn faulted() -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(
        StatusCode::INTERNAL_SERVER_ERROR,
    ))
    .json(json!({
        "error": "server_error",
        "error_description": "the realm could not be read",
    }))
}
