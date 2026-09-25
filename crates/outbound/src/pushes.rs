//! What the outbox pushes, and to whom: SCIM connectors, receivers of security
//! events and webhooks, each reached under the egress policy, and the proof an
//! operator asks of one of them.

use config::serving::Egress;
use services::messaging::outbox;
use store::tenancy::UnitOfWork;
use ureq::unversioned::resolver::DefaultResolver;

use crate::egress::{Outward, PATIENCE, may_dial};

pub async fn opened_bearer(
    transaction: &UnitOfWork,
    sealing: &crate::Sealing,
    context: &store::tenancy::TenantContext,
    provider: &models::entities::authz::IdentityProviderModel,
) -> Option<String> {
    use data_encoding::BASE64;
    let sealed = provider
        .configs
        .as_ref()?
        .get(services::scim::outbound::SEALED_BEARER)?
        .as_str()?;
    let sealed = BASE64.decode(sealed.as_bytes()).ok()?;
    let ring = store::keyring::load(
        transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    .ok()?;
    let opened = ring
        .open(
            &sealing.envelope,
            "identity-provider-secret",
            &provider.internal_id,
            &sealed,
        )
        .await
        .ok()?;
    String::from_utf8(crypto::secrecy::ExposeSecret::expose_secret(&opened).clone()).ok()
}

/// The synthetic telling, delivered now and answered with what the far
/// side said: signed like any real one, so the consumer's verification is
/// exercised too.
async fn ask_webhook(
    hook: &services::messaging::webhook::Webhook,
    signature: &str,
    body: String,
    egress: Egress,
) -> Proof {
    let url = hook.url.clone();
    let signature = signature.to_owned();
    let answered = tokio::task::spawn_blocking(move || {
        if !may_dial(&url, egress) {
            return None;
        }
        let agent = far_side_agent(egress);
        match agent
            .post(&url)
            .header("content-type", "application/json")
            .header("x-saffui-signature", &signature)
            .header("x-saffui-event", "saffui.subscription.test")
            .header("x-saffui-event-id", "0")
            .send(body.as_str())
        {
            Ok(answer) => Some(answer.status().as_u16()),
            Err(ureq::Error::StatusCode(code)) => Some(code),
            Err(_) => None,
        }
    })
    .await
    .unwrap_or(None);
    match answered {
        Some(status) if (200..300).contains(&status) => Proof {
            proven: true,
            how: "pushed",
            status: Some(status),
            said: String::new(),
        },
        Some(status) => Proof {
            proven: false,
            how: "answered",
            status: Some(status),
            said: "the far side answered, and refused".to_owned(),
        },
        None => Proof {
            proven: false,
            how: "unreachable",
            status: None,
            said: "nothing answered at the webhook's url".to_owned(),
        },
    }
}

pub async fn opened_webhook_secret(
    transaction: &UnitOfWork,
    sealing: &crate::Sealing,
    context: &store::tenancy::TenantContext,
    provider: &models::entities::authz::IdentityProviderModel,
) -> Option<String> {
    use data_encoding::BASE64;
    let sealed = provider
        .configs
        .as_ref()?
        .get(services::messaging::webhook::SEALED_SECRET)?
        .as_str()?;
    let sealed = BASE64.decode(sealed.as_bytes()).ok()?;
    let ring = store::keyring::load(
        transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    .ok()?;
    let opened = ring
        .open(
            &sealing.envelope,
            "identity-provider-secret",
            &provider.internal_id,
            &sealed,
        )
        .await
        .ok()?;
    String::from_utf8(crypto::secrecy::ExposeSecret::expose_secret(&opened).clone()).ok()
}

/// One signed telling to one webhook: these exact bytes, their signature,
/// and the two headers a consumer dedups and routes by.
pub async fn push_json(
    hook: &services::messaging::webhook::Webhook,
    signature: &str,
    kind: &str,
    event_id: i64,
    body: String,
    egress: Egress,
) -> bool {
    let url = hook.url.clone();
    let signature = signature.to_owned();
    let kind = kind.to_owned();
    tokio::task::spawn_blocking(move || {
        if !may_dial(&url, egress) {
            return false;
        }
        let agent = far_side_agent(egress);
        agent
            .post(&url)
            .header("content-type", "application/json")
            .header("x-saffui-signature", &signature)
            .header("x-saffui-event", &kind)
            .header("x-saffui-event-id", &event_id.to_string())
            .send(body.as_str())
            .is_ok()
    })
    .await
    .unwrap_or(false)
}

/// The agent every ask to a far side rides: a short global timeout, no
/// redirects followed, the platform's own roots trusted.
fn far_side_agent(egress: Egress) -> ureq::Agent {
    ureq::Agent::with_parts(
        ureq::Agent::config_builder()
            .timeout_global(Some(PATIENCE))
            .max_redirects(0)
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .provider(ureq::tls::TlsProvider::NativeTls)
                    .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                    .build(),
            )
            .build(),
        ureq::unversioned::transport::DefaultConnector::new(),
        Outward(DefaultResolver::default(), egress),
    )
}

/// Hand one Security Event Token to one receiver, RFC 8935: a POST whose
/// body is the token, acknowledged with a bare success.
pub async fn push_set(
    receiver: &services::messaging::caep::Receiver,
    bearer: Option<&str>,
    set: &str,
    egress: Egress,
) -> bool {
    let Some(endpoint) = receiver.endpoint.clone() else {
        return false;
    };
    let bearer = bearer.map(str::to_owned);
    let set = set.to_owned();
    tokio::task::spawn_blocking(move || {
        if !may_dial(&endpoint, egress) {
            return false;
        }
        let agent = far_side_agent(egress);
        let mut asked = agent
            .post(&endpoint)
            .header("content-type", "application/secevent+jwt")
            .header("accept", "application/json");
        if let Some(bearer) = bearer {
            asked = asked.header("authorization", &format!("Bearer {bearer}"));
        }
        asked.send(set.as_str()).is_ok()
    })
    .await
    .unwrap_or(false)
}

/// Reconcile-then-write, the way the cloud provisioners do it: find the
/// person at the far side by our identifier, then create, correct, or
/// delete. Every path is idempotent, which is what at-least-once needs.
pub async fn push_one(
    connector: &services::scim::outbound::Connector,
    bearer: Option<&str>,
    event: &outbox::OutboxEvent,
    egress: Egress,
) -> bool {
    let base = connector.base_url.clone();
    let bearer = bearer.unwrap_or_default().to_owned();
    let event = event.clone();
    tokio::task::spawn_blocking(move || {
        if !may_dial(&base, egress) {
            return false;
        }
        let agent = far_side_agent(egress);
        let authorization = format!("Bearer {bearer}");
        let found: Option<String> = agent
            .get(&format!(
                "{base}/Users?filter=externalId%20eq%20%22{}%22",
                event.user_id
            ))
            .header("authorization", &authorization)
            .call()
            .ok()
            .and_then(|mut response| {
                response
                    .body_mut()
                    .with_config()
                    .limit(64 * 1024)
                    .read_to_string()
                    .ok()
                    .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
                    .and_then(|body| body["Resources"][0]["id"].as_str().map(str::to_owned))
            });

        match (event.kind.as_str(), found) {
            (outbox::USER_DELETED, Some(id)) => agent
                .delete(&format!("{base}/Users/{id}"))
                .header("authorization", &authorization)
                .call()
                .is_ok(),
            (outbox::USER_DELETED, None) => true,
            (_, Some(id)) => {
                let patch = serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": [{ "op": "replace", "value": {
                        "active": event.payload["enabled"],
                        "emails": [{ "value": event.payload["email"], "primary": true }],
                    }}],
                });
                agent
                    .patch(&format!("{base}/Users/{id}"))
                    .header("authorization", &authorization)
                    .header("content-type", "application/scim+json")
                    .send(patch.to_string())
                    .is_ok()
            }
            (_, None) => {
                let created = serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": event.payload["user_name"],
                    "externalId": event.user_id,
                    "active": event.payload["enabled"],
                    "emails": [{ "value": event.payload["email"], "primary": true }],
                });
                agent
                    .post(&format!("{base}/Users"))
                    .header("authorization", &authorization)
                    .header("content-type", "application/scim+json")
                    .send(created.to_string())
                    .is_ok()
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// What one prove answered: whether the pipe held, how it was exercised,
/// and what the far side said, in a status and words an operator can act on.
#[derive(Debug)]
pub struct Proof {
    pub proven: bool,
    /// "answered", "pushed", "queued" or "unreachable": the shape the
    /// exercise took, so the console can say the right sentence.
    pub how: &'static str,
    pub status: Option<u16>,
    pub said: String,
}

/// Why no prove could even be attempted.
#[derive(Debug)]
pub enum Unprovable {
    NoSuchProvider,
    Disabled,
    NotProvable(String),
    Backend,
}

/// Exercise one connector's pipe because an operator asked, and answer what
/// the far side said. A SCIM connector is asked for its
/// ServiceProviderConfig; a push receiver is handed a freshly signed
/// verification event; a collector has one queued to take on its next poll.
pub async fn prove_delivery(
    transaction: &UnitOfWork,
    sealing: &crate::Sealing,
    origin: &config::serving::PublicOrigin,
    context: &store::tenancy::TenantContext,
    alias: &str,
    egress: Egress,
) -> Result<Proof, Unprovable> {
    let row = services::federation::brokering::read_provider(transaction, alias)
        .await
        .map_err(|_| Unprovable::Backend)?
        .ok_or(Unprovable::NoSuchProvider)?;
    if row.enabled == Some(false) {
        return Err(Unprovable::Disabled);
    }
    if services::scim::outbound::is_outbound(&row) {
        let connector = services::scim::outbound::Connector::parse(&row)
            .map_err(|why| Unprovable::NotProvable(why.to_string()))?;
        let bearer = opened_bearer(transaction, sealing, context, &row).await;
        return Ok(ask_scim_root(&connector, bearer.as_deref(), egress).await);
    }
    if services::messaging::webhook::is_webhook(&row) {
        let hook = services::messaging::webhook::Webhook::parse(&row)
            .map_err(|why| Unprovable::NotProvable(why.to_string()))?;
        let body = serde_json::json!({
            "event_id": 0,
            "kind": "saffui.subscription.test",
            "realm": context.realm_id,
            "user_id": "",
            "occurred_at": chrono::Utc::now().to_rfc3339(),
            "payload": {},
        })
        .to_string();
        let signature = opened_webhook_secret(transaction, sealing, context, &row)
            .await
            .and_then(|secret| {
                services::messaging::webhook::signature(
                    sealing.provider.as_ref(),
                    &secret,
                    body.as_bytes(),
                )
            })
            .ok_or_else(|| {
                Unprovable::NotProvable("the webhook's secret could not be opened".to_owned())
            })?;
        return Ok(ask_webhook(&hook, &signature, body, egress).await);
    }
    if services::messaging::caep::is_receiver(&row) {
        let receiver = services::messaging::caep::Receiver::parse(&row)
            .map_err(|why| Unprovable::NotProvable(why.to_string()))?;
        let ring = store::keyring::load(
            transaction,
            &sealing.envelope,
            &context.tenant,
            &context.realm_id,
        )
        .await
        .map_err(|_| Unprovable::Backend)?;
        let mut drawn = [0u8; 8];
        sealing
            .provider
            .rand()
            .fill(&mut drawn)
            .map_err(|_| Unprovable::Backend)?;
        let state = data_encoding::HEXLOWER.encode(&drawn);
        let set = services::messaging::caep::verification_set(
            transaction,
            &services::oidc::grant::Signing {
                provider: sealing.provider.as_ref(),
                ring: &ring,
                envelope: &sealing.envelope,
            },
            &origin.issuer(&context.realm_id),
            &receiver,
            alias,
            &state,
            chrono::Utc::now(),
        )
        .await
        .map_err(|_| {
            Unprovable::NotProvable("the realm holds no key to sign the event".to_owned())
        })?;
        return Ok(match receiver.delivery {
            services::messaging::caep::Delivery::Push => {
                let bearer = opened_bearer(transaction, sealing, context, &row).await;
                push_verification(&receiver, bearer.as_deref(), &set.token, egress).await
            }
            services::messaging::caep::Delivery::Poll => {
                services::messaging::caep::queue_set(transaction, &row.internal_id, &set)
                    .await
                    .map_err(|_| Unprovable::Backend)?;
                Proof {
                    proven: true,
                    how: "queued",
                    status: None,
                    said: "the verification event waits for the collector's next poll".to_owned(),
                }
            }
        });
    }
    Err(Unprovable::NotProvable(
        "this provider is neither an outbound connector nor an event receiver".to_owned(),
    ))
}

/// Ask the SCIM root who it is, the way RFC 7644 lets anybody ask: GET
/// ServiceProviderConfig with the bearer attached. Answering 2xx with a
/// document naming its schemas proves the root and the bearer in one trip.
async fn ask_scim_root(
    connector: &services::scim::outbound::Connector,
    bearer: Option<&str>,
    egress: Egress,
) -> Proof {
    let asked = format!("{}/ServiceProviderConfig", connector.base_url);
    let authorization = bearer.map(|held| format!("Bearer {held}"));
    let answered = tokio::task::spawn_blocking(move || {
        if !may_dial(&asked, egress) {
            return Err("the endpoint is not allowed by egress policy".to_owned());
        }
        let agent = far_side_agent(egress);
        let mut asking = agent.get(&asked).header("accept", "application/scim+json");
        if let Some(authorization) = &authorization {
            asking = asking.header("authorization", authorization);
        }
        match asking.call() {
            Ok(mut answer) => {
                let status = answer.status().as_u16();
                let body = answer
                    .body_mut()
                    .with_config()
                    .limit(64 * 1024)
                    .read_to_string()
                    .unwrap_or_default();
                Ok((status, body))
            }
            Err(ureq::Error::StatusCode(code)) => Ok((code, String::new())),
            Err(why) => Err(why.to_string()),
        }
    })
    .await
    .unwrap_or_else(|_| Err("the ask never came back".to_owned()));
    match answered {
        Ok((status, body)) if (200..300).contains(&status) => {
            let spoke_scim = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .is_some_and(|told| told.get("schemas").is_some());
            if spoke_scim {
                Proof {
                    proven: true,
                    how: "answered",
                    status: Some(status),
                    said: "the SCIM root answered as itself".to_owned(),
                }
            } else {
                Proof {
                    proven: false,
                    how: "answered",
                    status: Some(status),
                    said: "something answered, but not with a ServiceProviderConfig".to_owned(),
                }
            }
        }
        Ok((status @ (401 | 403), _)) => Proof {
            proven: false,
            how: "answered",
            status: Some(status),
            said: "the root refused the bearer".to_owned(),
        },
        Ok((status, _)) => Proof {
            proven: false,
            how: "answered",
            status: Some(status),
            said: format!("the root answered {status}"),
        },
        Err(why) => Proof {
            proven: false,
            how: "unreachable",
            status: None,
            said: why,
        },
    }
}

/// Hand the verification event to a push receiver and answer what it said;
/// the delivery loop's own push only wants a yes or no, an operator wants
/// the status and the words.
async fn push_verification(
    receiver: &services::messaging::caep::Receiver,
    bearer: Option<&str>,
    set: &str,
    egress: Egress,
) -> Proof {
    let Some(endpoint) = receiver.endpoint.clone() else {
        return Proof {
            proven: false,
            how: "unreachable",
            status: None,
            said: "the receiver names no endpoint".to_owned(),
        };
    };
    let authorization = bearer.map(|held| format!("Bearer {held}"));
    let set = set.to_owned();
    let answered = tokio::task::spawn_blocking(move || {
        if !may_dial(&endpoint, egress) {
            return Err("the endpoint is not allowed by egress policy".to_owned());
        }
        let agent = far_side_agent(egress);
        let mut asking = agent
            .post(&endpoint)
            .header("content-type", "application/secevent+jwt")
            .header("accept", "application/json");
        if let Some(authorization) = &authorization {
            asking = asking.header("authorization", authorization);
        }
        match asking.send(set.as_str()) {
            Ok(answer) => Ok(answer.status().as_u16()),
            Err(ureq::Error::StatusCode(code)) => Ok(code),
            Err(why) => Err(why.to_string()),
        }
    })
    .await
    .unwrap_or_else(|_| Err("the ask never came back".to_owned()));
    match answered {
        Ok(status) if (200..300).contains(&status) => Proof {
            proven: true,
            how: "pushed",
            status: Some(status),
            said: "the receiver took the verification event".to_owned(),
        },
        Ok(status @ (401 | 403)) => Proof {
            proven: false,
            how: "pushed",
            status: Some(status),
            said: "the receiver refused the bearer".to_owned(),
        },
        Ok(status) => Proof {
            proven: false,
            how: "pushed",
            status: Some(status),
            said: format!("the receiver answered {status}"),
        },
        Err(why) => Proof {
            proven: false,
            how: "unreachable",
            status: None,
            said: why,
        },
    }
}
