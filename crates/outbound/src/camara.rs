//! Asking a carrier, over CAMARA, whether the SIM behind a number changed
//! lately.
//!
//! CAMARA holds a SIM change to be personal data, so the question is asked on
//! a token for that one number: a backchannel authentication request naming
//! it, the token that request earns at the carrier's token endpoint, and the
//! check under that token. At each endpoint the realm proves itself with an
//! assertion its own key signed for that endpoint alone.

use std::time::{Duration, Instant};

use chrono::Utc;
use config::serving::Egress;
use crypto::provider::CryptoProvider;
use models::entities::sim_swap::SimSwapSettings;

use crate::egress::{may_dial, outward_agent_reading_refusals};

/// What the check is for, the one purpose CAMARA wants named, beside the
/// check's own scope.
const SCOPE: &str = "openid dpv:FraudPreventionAndDetection sim-swap:check";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const CIBA_GRANT: &str = "urn:openid:params:grant-type:ciba";

/// How long the whole question may take, three calls and any polling: a
/// person is waiting for a code.
const PATIENCE: Duration = Duration::from_secs(8);

/// How long to wait before asking the token endpoint again when the carrier
/// names no interval, CIBA's own default.
const DEFAULT_INTERVAL: u64 = 5;

/// The most one answer is read to. A carrier's answer is a few fields.
const CEILING: u64 = 16 * 1024;

/// Why no verdict came back.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the carrier gave no answer: {0}")]
pub struct Unanswered(pub String);

/// Whether the SIM behind `phone` changed within the realm's window.
pub async fn sim_changed(
    provider: &dyn CryptoProvider,
    settings: &SimSwapSettings,
    phone: &str,
    egress: Egress,
) -> Result<bool, Unanswered> {
    let started = Instant::now();
    for endpoint in [
        &settings.authorize_url,
        &settings.token_url,
        &settings.check_url,
    ] {
        if !may_dial(endpoint, egress) {
            return Err(Unanswered(
                "an endpoint this egress policy does not dial".to_owned(),
            ));
        }
    }

    let (status, told) = post(
        &settings.authorize_url,
        Body::Form(vec![
            ("login_hint", format!("tel:{phone}")),
            ("scope", SCOPE.to_owned()),
            ("client_id", settings.client_id.clone()),
            ("client_assertion_type", ASSERTION_TYPE.to_owned()),
            (
                "client_assertion",
                assertion(provider, settings, &settings.authorize_url)?,
            ),
        ]),
        None,
        egress,
        started,
    )
    .await?;
    let Some(request) = told["auth_req_id"].as_str().filter(|_| status == 200) else {
        return Err(Unanswered(format!(
            "the backchannel endpoint answered {status}"
        )));
    };
    let mut interval = told["interval"].as_u64().unwrap_or(DEFAULT_INTERVAL);

    let token = loop {
        let (status, told) = post(
            &settings.token_url,
            Body::Form(vec![
                ("grant_type", CIBA_GRANT.to_owned()),
                ("auth_req_id", request.to_owned()),
                ("client_id", settings.client_id.clone()),
                ("client_assertion_type", ASSERTION_TYPE.to_owned()),
                (
                    "client_assertion",
                    assertion(provider, settings, &settings.token_url)?,
                ),
            ]),
            None,
            egress,
            started,
        )
        .await?;
        if status == 200
            && let Some(token) = told["access_token"].as_str()
        {
            break token.to_owned();
        }
        match told["error"].as_str() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 5,
            _ => {
                return Err(Unanswered(format!("the token endpoint answered {status}")));
            }
        }
        let wait = Duration::from_secs(interval);
        if started.elapsed() + wait >= PATIENCE {
            return Err(Unanswered("no token came in time".to_owned()));
        }
        tokio::time::sleep(wait).await;
    };

    let (status, told) = post(
        &settings.check_url,
        Body::Json(serde_json::json!({ "maxAge": settings.max_age_hours })),
        Some(&token),
        egress,
        started,
    )
    .await?;
    match told["swapped"].as_bool() {
        Some(swapped) if status == 200 => Ok(swapped),
        _ => Err(Unanswered(format!("the check answered {status}"))),
    }
}

/// A fresh assertion addressed to one endpoint.
fn assertion(
    provider: &dyn CryptoProvider,
    settings: &SimSwapSettings,
    endpoint: &str,
) -> Result<String, Unanswered> {
    services::token::assertion::client_assertion(
        provider,
        &settings.key,
        &settings.client_id,
        endpoint,
        Utc::now(),
    )
    .map_err(|_| Unanswered("the assertion could not be signed".to_owned()))
}

enum Body {
    Form(Vec<(&'static str, String)>),
    Json(serde_json::Value),
}

/// One call, within what is left of the question's patience, answered with
/// its status and whatever JSON came back.
async fn post(
    url: &str,
    body: Body,
    bearer: Option<&str>,
    egress: Egress,
    started: Instant,
) -> Result<(u16, serde_json::Value), Unanswered> {
    let left = PATIENCE
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| Unanswered("the carrier took too long".to_owned()))?;
    let url = url.to_owned();
    let bearer = bearer.map(str::to_owned);
    tokio::task::spawn_blocking(move || {
        let agent = outward_agent_reading_refusals(egress, left);
        let mut asking = agent.post(&url);
        if let Some(bearer) = &bearer {
            asking = asking.header("authorization", &format!("Bearer {bearer}"));
        }
        let answered = match body {
            Body::Form(fields) => asking.send_form(
                fields
                    .iter()
                    .map(|(name, value)| (*name, value.as_str()))
                    .collect::<Vec<_>>(),
            ),
            Body::Json(json) => asking
                .header("content-type", "application/json")
                .header("x-correlator", &correlator())
                .send(json.to_string()),
        };
        let mut response = answered.map_err(|why| Unanswered(why.to_string()))?;
        let status = response.status().as_u16();
        let read = response
            .body_mut()
            .with_config()
            .limit(CEILING)
            .read_to_string()
            .unwrap_or_default();
        Ok((status, serde_json::from_str(&read).unwrap_or_default()))
    })
    .await
    .map_err(|_| Unanswered("the call did not finish".to_owned()))?
}

/// A name for one check, which CAMARA echoes back so both sides can find it
/// in their logs; derived from the clock rather than drawn, since it proves
/// nothing.
fn correlator() -> String {
    format!(
        "saffui-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default()
    )
}
