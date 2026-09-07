//! The native MCP endpoint: an agent obtains and attenuates its capability
//! tokens over the protocol it already speaks.
//!
//! One JSON-RPC 2.0 door, three methods (`initialize`, `tools/list`,
//! `tools/call`), two tools (`capability.mint`, `capability.attenuate`),
//! and nothing else: the admin plane is not for sale here, deliberately.
//! Both tools are a facade over the one exchange the token endpoint
//! performs, so every guard that holds there holds here: the realm's
//! switch, the opt-in, the narrowest root, the act chain, the depth bound.
//!
//! The bearer is the whole authentication: an agent's platform-minted
//! token names its client in `azp`, and that client is who exchanges. A
//! capability token presented back the same way is an attenuation.

use actix_web::{HttpRequest, HttpResponse, web};
use chrono::Utc;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use serde_json::{Value, json};
use services::grant::{self, Ungranted};
use store::keyring;
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;

/// The protocol revision this door speaks.
const PROTOCOL: &str = "2025-06-18";

/// One JSON-RPC answer, always 200: the transport is healthy, the message
/// says what happened.
fn answered(id: Value, result: Value) -> HttpResponse {
    HttpResponse::Ok().json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn refused(id: Value, code: i64, message: &str) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    }))
}

/// A tool that ran and has something to say, or a tool that refused: both
/// are results, MCP-shaped, so a host renders them instead of crashing.
fn told(id: Value, text: String, is_error: bool) -> HttpResponse {
    answered(
        id,
        json!({
            "content": [{ "type": "text", "text": text }],
            "isError": is_error,
        }),
    )
}

pub async fn serve(
    request: HttpRequest,
    realm: web::Path<String>,
    body: web::Json<Value>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let now = Utc::now();
    let asked = body.into_inner();
    let id = asked.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = asked.get("method").and_then(Value::as_str) else {
        return refused(id, -32600, "a request names its method");
    };

    let Ok(mut connection) = pool.get().await else {
        return refused(id, -32000, "the realm could not be read");
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        // The same face a missing realm wears everywhere else.
        return HttpResponse::NotFound().finish();
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return refused(id, -32000, "the realm could not be read");
    };
    let Ok(held) = store::providers::realms::load(&transaction, &context.realm_id).await else {
        return refused(id, -32000, "the realm could not be read");
    };
    let Some(held) = held else {
        return HttpResponse::NotFound().finish();
    };
    // The whole door answers to the realm's switch, initialize included: a
    // host learns the truth at the handshake, not at the first mint.
    if held.agent_exchange_enabled != Some(true) {
        return refused(id, -32000, "this realm does not mint capability tokens");
    }

    match method {
        "initialize" => answered(
            id,
            json!({
                "protocolVersion": PROTOCOL,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "saffui", "version": env!("CARGO_PKG_VERSION") },
            }),
        ),
        "notifications/initialized" => HttpResponse::Accepted().finish(),
        "tools/list" => answered(
            id,
            json!({
                "tools": [
                    {
                        "name": "capability.mint",
                        "description": "Exchange the presented token for a short-lived \
                                        capability token naming exactly these tools.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "capabilities": {
                                    "type": "string",
                                    "description": "Space-separated tool names, exact or a prefix ending in *.",
                                },
                                "audience": { "type": "string" },
                                "scope": { "type": "string" },
                            },
                            "required": ["capabilities"],
                        },
                    },
                    {
                        "name": "capability.attenuate",
                        "description": "Exchange the presented capability token for a \
                                        strictly narrower one; asking wider refuses whole.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "capabilities": { "type": "string" },
                                "audience": { "type": "string" },
                            },
                            "required": ["capabilities"],
                        },
                    },
                ],
            }),
        ),
        "tools/call" => {
            let name = asked
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if name != "capability.mint" && name != "capability.attenuate" {
                return refused(id, -32602, "no such tool");
            }
            let Some(capabilities) = asked
                .pointer("/params/arguments/capabilities")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|held| !held.is_empty())
            else {
                return refused(id, -32602, "capabilities names the tools wanted");
            };
            let audience = asked
                .pointer("/params/arguments/audience")
                .and_then(Value::as_str);
            let scope = asked
                .pointer("/params/arguments/scope")
                .and_then(Value::as_str);

            // The bearer is the subject and the client at once: what it
            // says in `azp` is who exchanges, under every gate the exchange
            // already holds.
            let presented = request
                .headers()
                .get("authorization")
                .and_then(|held| held.to_str().ok())
                .and_then(|held| held.strip_prefix("Bearer "))
                .map(str::to_owned);
            let Some(presented) = presented else {
                return HttpResponse::Unauthorized()
                    .insert_header(("www-authenticate", "Bearer"))
                    .finish();
            };
            let (Ok(ring), Ok(keys)) = (
                keyring::load(
                    &transaction,
                    &sealing.envelope,
                    &context.tenant,
                    &context.realm_id,
                )
                .await,
                services::realm::published_keys(&transaction).await,
            ) else {
                return refused(id, -32000, "the realm could not be read");
            };
            let Ok(verified) = services::token::verify_presented(
                &transaction,
                &keys,
                &presented,
                services::token::Binding::Reported,
                now,
            )
            .await
            else {
                return HttpResponse::Unauthorized()
                    .insert_header(("www-authenticate", "Bearer"))
                    .finish();
            };
            let Some(client) = verified
                .claims
                .get("azp")
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                return told(
                    id,
                    "the token names no client to exchange as".to_owned(),
                    true,
                );
            };
            let Ok(Some(client)) = store::providers::clients::load(&transaction, &client).await
            else {
                return told(
                    id,
                    "the token names no client to exchange as".to_owned(),
                    true,
                );
            };

            let exchanged = grant::token_exchange(
                &transaction,
                &grant::Signing {
                    provider: sealing.provider.as_ref(),
                    ring: &ring,
                    envelope: &sealing.envelope,
                },
                &grant::Within {
                    tenant: &context,
                    realm: &held,
                    issuer: &origin.issuer(&context.realm_id),
                    bound_to: None,
                    certified_by: None,
                },
                &client,
                &grant::Exchanging {
                    subject_token: &presented,
                    actor_token: None,
                    scope,
                    audience,
                    capabilities: Some(capabilities),
                    keys: &keys,
                },
                request
                    .app_data::<web::Data<services::pdp::Journal>>()
                    .map(|held| held.get_ref()),
                now,
            )
            .await;
            match exchanged {
                Ok(granted) => {
                    if transaction.commit().await.is_err() {
                        return refused(id, -32000, "the grant could not be recorded");
                    }
                    told(
                        id,
                        json!({
                            "access_token": granted.access_token,
                            "token_type": "Bearer",
                            "expires_in": granted.expires_in,
                            "scope": granted.scope,
                        })
                        .to_string(),
                        false,
                    )
                }
                // The one refusal with the operator's own words rides them;
                // the rest collapse, exactly as the token endpoint answers.
                Err(Ungranted::AgentsOff) => told(
                    id,
                    "this realm does not mint capability tokens".to_owned(),
                    true,
                ),
                Err(Ungranted::Unauthorized) => {
                    told(id, "this client may not use this grant".to_owned(), true)
                }
                Err(_) => told(id, "the exchange was refused".to_owned(), true),
            }
        }
        _ => refused(id, -32601, "no such method"),
    }
}
