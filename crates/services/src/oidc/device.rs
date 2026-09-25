use auth::login::throttle;
use chrono::{DateTime, Duration, Utc};
use crypto::provider::CryptoProvider;
use models::entities::attributes::AttributeValue;
use models::entities::client::ClientModel;
use models::entities::device::{DeviceCodeModel, DeviceCodeState};
use serde_json::json;
use store::providers::clients;
use store::providers::protocol::{devices, login};
use store::tenancy::UnitOfWork;

/// RFC 8628 §3.4, the grant a device polls with.
pub const GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The client bag key opting a client into the device grant. Presence is the
/// permission, the way the backchannel's delivery flag is, unless what is
/// present says no.
pub const GRANT_FLAG: &str = "device.grant";

/// How long the pair of codes lives, §3.2's guidance.
/// The default when the realm has not said.
const CODE_LIFESPAN: i64 = 600;

/// How often the device may poll, §3.2's default.
/// The default polling pace when the realm has not said.
const POLL_INTERVAL: i32 = 5;

/// How long the login a verification opens may sit half finished.
const LOGIN_LIFESPAN: i64 = 900;

/// The letters a short code is drawn from: no vowels, so it spells nothing,
/// and none of the shapes people misread for each other.
const USER_CODE_LETTERS: &[u8] = b"BCDFGHJKMNPQRSTVWXZ";

pub fn allows_device(client: &ClientModel) -> bool {
    client
        .configs
        .as_ref()
        .and_then(|bag| bag.get(GRANT_FLAG))
        .is_some_and(|held| match held {
            AttributeValue::Bool(on) => *on,
            AttributeValue::Str(said) => !matches!(
                said.trim().to_ascii_lowercase().as_str(),
                "" | "false" | "off" | "no" | "0"
            ),
            _ => false,
        })
}

/// What §3.2 answers the device with.
#[derive(Debug)]
pub struct Opened {
    pub device_code: String,
    /// As the person will read it, with the separator.
    pub user_code: String,
    pub expires_in: i64,
    pub interval: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unopened {
    #[error("this client may not use the device grant")]
    Unauthorized,
    #[error("the store could not answer")]
    Unreadable,
}

/// Open a device sign-in: mint the long secret the device polls with and the
/// short code the person types, §3.1 and §3.2.
pub async fn open(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    client: &ClientModel,
    scope: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Opened, Unopened> {
    if !allows_device(client) {
        return Err(Unopened::Unauthorized);
    }
    let scope = crate::oidc::authorize::granted_scope(
        transaction,
        &client.client_id,
        scope.unwrap_or_default(),
    )
    .await
    .map_err(|_| Unopened::Unreadable)?;

    // The realm's pacing where it set one; the row keeps its birth interval,
    // so a later retune never reshapes a code already in someone's hand.
    let (lifespan, interval) = match store::providers::realms::of_context(transaction).await {
        Ok(Some(realm)) => (
            realm.device_code_lifespan.map_or(CODE_LIFESPAN, i64::from),
            realm.device_poll_interval.unwrap_or(POLL_INTERVAL),
        ),
        _ => (CODE_LIFESPAN, POLL_INTERVAL),
    };
    let device_code = drawn_secret(provider)?;
    let user_code = drawn_user_code(provider)?;
    devices::open(
        transaction,
        provider.digest(),
        &device_code,
        &DeviceCodeModel {
            tenant: String::new(),
            realm_id: String::new(),
            user_code: user_code.clone(),
            client_id: client.client_id.clone(),
            scope,
            state: DeviceCodeState::Pending,
            user_id: None,
            session_id: None,
            auth_time: None,
            acr: None,
            org_id: None,
            org_name: None,
            interval_secs: interval,
            last_polled_at: None,
            approved_at: None,
            expires_at: now + Duration::seconds(lifespan),
            created_at: None,
        },
    )
    .await
    .map_err(|_| Unopened::Unreadable)?;

    Ok(Opened {
        device_code,
        user_code: format!("{}-{}", &user_code[..4], &user_code[4..]),
        expires_in: lifespan,
        interval,
    })
}

/// A short code as the row keeps it: uppercase, letters only. Separators and
/// case are the person's business, not the comparison's.
pub fn normalized_user_code(typed: &str) -> String {
    typed
        .chars()
        .filter(|held| held.is_ascii_alphanumeric())
        .map(|held| held.to_ascii_uppercase())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unverifiable {
    /// Unknown, expired or already decided: one answer, so the page tells
    /// nobody which short codes are live.
    #[error("that code does not stand")]
    NoSuchCode,
    /// Too many codes that did not stand from where this one came from, until
    /// this instant.
    #[error("too many codes were tried from this address; try again later")]
    Throttled { until: i64 },
    #[error("the store could not answer")]
    Unreadable,
}

/// Turn a typed short code into a login for the person to run, §3.3.
///
/// The login is the realm's ordinary browser flow for the device's client,
/// so every factor, consent and organization rule holds here too. The row's
/// digest rides the notes; the flow's completion approves the row instead of
/// minting a browser answer.
///
/// The address typing is weighed before any code is looked up, and every code
/// that does not stand is counted against it, §5.1: a short code is guessable
/// only as fast as the door lets it be tried. A miss has written its count,
/// and the caller commits it: rolled back, a wrong guess costs nothing.
pub async fn begin_verification(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    realm_name: &str,
    from: Option<&str>,
    typed: &str,
    now: DateTime<Utc>,
) -> Result<String, Unverifiable> {
    let realm = store::providers::realms::of_context(transaction)
        .await
        .map_err(|_| Unverifiable::Unreadable)?
        .ok_or(Unverifiable::Unreadable)?;
    let knock = throttle::Knock::typing_user_code(from);
    if let Some(until) = throttle::until(transaction, &realm, &knock, now)
        .await
        .map_err(|_| Unverifiable::Unreadable)?
    {
        return Err(Unverifiable::Throttled { until });
    }
    let user_code = normalized_user_code(typed);
    let Some((waiting, client)) = read_standing_code(transaction, &user_code, now).await? else {
        throttle::count(transaction, &realm, &knock, now)
            .await
            .map_err(|_| Unverifiable::Unreadable)?;
        return Err(Unverifiable::NoSuchCode);
    };
    let flow = crate::oidc::authorize::browser_flow(transaction, &client)
        .await
        .map_err(|_| Unverifiable::Unreadable)?;

    let auth_session_id =
        crate::oidc::authorize::draw_id(provider).map_err(|_| Unverifiable::Unreadable)?;
    login::start(
        transaction,
        &login::AuthSession {
            session_id: auth_session_id.clone(),
            client_id: client.client_id.clone(),
            flow_id: flow,
            execution_id: None,
            user_id: None,
            // Where the person lands when the login is over: the device page,
            // telling them to go back to their device. Nothing redeemable
            // travels there.
            redirect_uri: format!("/realms/{realm_name}/protocol/openid-connect/device#approved"),
            expires_at: now + Duration::seconds(LOGIN_LIFESPAN),
            notes: json!({
                "scope": waiting.scope,
                // The flow's completion reads this and approves the row
                // instead of minting a browser answer.
                "device_user_code": user_code,
                "response_mode": "query",
                "response_type": "none",
            }),
        },
    )
    .await
    .map_err(|_| Unverifiable::Unreadable)?;

    Ok(auth_session_id)
}

/// The live row behind a short code and the client it opens a login for, or
/// nothing when either is gone.
async fn read_standing_code(
    transaction: &UnitOfWork,
    user_code: &str,
    now: DateTime<Utc>,
) -> Result<Option<(DeviceCodeModel, ClientModel)>, Unverifiable> {
    if user_code.is_empty() {
        return Ok(None);
    }
    let Some(waiting) = devices::pending_by_user_code(transaction, user_code, now)
        .await
        .map_err(|_| Unverifiable::Unreadable)?
    else {
        return Ok(None);
    };
    Ok(clients::load(transaction, &waiting.client_id)
        .await
        .map_err(|_| Unverifiable::Unreadable)?
        .map(|client| (waiting, client)))
}

fn drawn_secret(provider: &dyn CryptoProvider) -> Result<String, Unopened> {
    let mut drawn = [0_u8; 32];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unopened::Unreadable)?;
    Ok(data_encoding::HEXLOWER.encode(&drawn))
}

/// Eight letters from an alphabet of nineteen: about 34 bits, which §5.1
/// calls enough exactly because the row is short-lived and the door that
/// reads it is rate limited.
fn drawn_user_code(provider: &dyn CryptoProvider) -> Result<String, Unopened> {
    let mut drawn = [0_u8; 8];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unopened::Unreadable)?;
    Ok(drawn
        .iter()
        .map(|held| USER_CODE_LETTERS[*held as usize % USER_CODE_LETTERS.len()] as char)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flagged(held: Option<AttributeValue>) -> ClientModel {
        let mut client = models::entities::client::ClientCreateModel {
            name: "tv".into(),
            display_name: "tv".into(),
            description: String::new(),
            enabled: Some(true),
        }
        .into_model(
            "tv".into(),
            "main".into(),
            models::auditable::AuditableModel::from_creator("acme".into(), "root".into()),
        );
        client.configs = held.map(|held| [(GRANT_FLAG.to_owned(), held)].into_iter().collect());
        client
    }

    /// Presence opts a client in, unless what is present says no.
    #[test]
    fn a_flag_that_says_no_opts_nobody_in() {
        let said = |text: &str| Some(AttributeValue::Str(text.to_owned()));
        for (held, allowed) in [
            (None, false),
            (said("true"), true),
            (said("enabled"), true),
            (Some(AttributeValue::Bool(true)), true),
            (said("false"), false),
            (said(" FALSE "), false),
            (said("off"), false),
            (said("no"), false),
            (said("0"), false),
            (said(""), false),
            (Some(AttributeValue::Bool(false)), false),
            (Some(AttributeValue::Int(1)), false),
        ] {
            assert_eq!(allows_device(&flagged(held.clone())), allowed, "{held:?}");
        }
    }

    #[test]
    fn a_typed_code_is_read_the_way_people_type_it() {
        for (typed, kept) in [
            ("wdjb-mjht", "WDJBMJHT"),
            ("WDJB MJHT", "WDJBMJHT"),
            (" wd-jb-mj-ht ", "WDJBMJHT"),
        ] {
            assert_eq!(normalized_user_code(typed), kept);
        }
    }
}
