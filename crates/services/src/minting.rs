use chrono::{DateTime, Duration, Utc};
use crypto::provider::CryptoProvider;
use data_encoding::HEXLOWER;
use deadpool_postgres::Transaction;
use models::entities::acr::{self, AchievedAuth};
use models::entities::oidc::AuthorizationCode;
use serde_json::Value;
use store::providers::{login, oidc};
use store::tenancy::TenantContext;

use crate::landing::{Landing, ResponseMode};
use crate::response_type::ResponseType;

/// Why a login could not be turned into an answer for the client.
pub use auth::login::browser::Unanswerable;

/// The client a code is minted for.
async fn client_of(
    transaction: &Transaction<'_>,
    client_id: &str,
) -> Result<models::entities::client::ClientModel, Unanswerable> {
    store::providers::clients::load(transaction, client_id)
        .await
        .map_err(|_| Unanswerable::Unreadable)?
        .ok_or(Unanswerable::Unrunnable)
}

/// What a code is minted against, gathered so two callers state the same facts.
pub struct Authorized<'a> {
    pub client_id: &'a str,
    pub user_id: &'a str,
    pub session_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub state: Option<&'a str>,
    /// What this login is known by in the browser, §4.2. Absent where the
    /// login was not made in one.
    pub browser_state: Option<&'a str>,
    /// How the answer travels, as the request that opened this named it.
    pub mode: ResponseMode,
    /// What comes back.
    pub asked_for: ResponseType,
    /// Both needed only when something is minted here.
    pub signing: Option<&'a crate::grant::Signing<'a>>,
    pub realm: Option<&'a models::entities::realm::RealmModel>,
    pub issuer: &'a str,
    pub nonce: Option<&'a str>,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    /// When the user authenticated, not when this code was minted. `max_age`
    /// asks about the first, and a session begun at nine and re-authenticated
    /// at noon is three hours old with an authentication minutes old.
    pub auth_time: i64,
    /// The level the login actually reached. Frozen here because by redemption
    /// the session may have stepped up in another tab, and a value resolved
    /// then would attest to a strength this code was never issued under.
    pub acr: Option<&'a str>,
    /// The `claims` the request named, as the store keeps them.
    pub claims: Option<&'a Value>,
}

/// Mint a code and say where the browser goes with it.
///
/// Shared, because `/authorize` mints one when it finds a live login and this
/// module mints one when a flow just finished. Two mintings would be two places
/// for a field to be forgotten.
pub async fn mint_code(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &TenantContext,
    authorized: &Authorized<'_>,
    now: DateTime<Utc>,
) -> Result<Landing, Unanswerable> {
    // An implicit request gets nothing to redeem, and a code minted anyway is
    // a spendable credential nobody comes back for.
    let raw = authorized
        .asked_for
        .code
        .then(|| draw(provider))
        .transpose()?;
    if let Some(raw) = &raw {
        oidc::mint_code(
            transaction,
            &AuthorizationCode {
                code_hash: digest(provider, raw.as_bytes())?,
                tenant: tenant.tenant.clone(),
                realm_id: tenant.realm_id.clone(),
                client_id: authorized.client_id.to_owned(),
                user_id: authorized.user_id.to_owned(),
                session_id: authorized.session_id.to_owned(),
                redirect_uri: authorized.redirect_uri.to_owned(),
                scope: authorized.scope.to_owned(),
                nonce: authorized.nonce.map(str::to_owned),
                code_challenge: authorized.code_challenge.map(str::to_owned),
                code_challenge_method: authorized.code_challenge_method.map(str::to_owned),
                auth_time: authorized.auth_time,
                acr: authorized.acr.map(str::to_owned),
                org_id: None,
                org_name: None,
                claims: authorized.claims.cloned(),
            },
            now + Duration::seconds(CODE_LIFESPAN),
        )
        .await
        .map_err(|_| Unanswerable::Unreadable)?;
    }

    let mut answer = Landing::new(authorized.redirect_uri, authorized.mode);
    if let Some(raw) = &raw {
        answer = answer.carrying("code", raw.as_str());
    }
    // After the code: the identity token carries its hash.
    if authorized.asked_for.mints_here() {
        let (Some(signing), Some(realm)) = (authorized.signing, authorized.realm) else {
            return Err(Unanswerable::Unrunnable);
        };
        let handed = crate::implicit::issue(
            transaction,
            signing,
            tenant,
            authorized.asked_for,
            &crate::implicit::Established {
                client: &client_of(transaction, authorized.client_id).await?,
                realm,
                issuer: authorized.issuer,
                user_id: authorized.user_id,
                session_id: authorized.session_id,
                scope: authorized.scope,
                nonce: authorized.nonce,
                auth_time: authorized.auth_time,
                acr: authorized.acr,
                code: raw.as_deref(),
                claims: authorized.claims,
            },
            now,
        )
        .await
        .map_err(|_| Unanswerable::Unrunnable)?;
        for (named, value) in handed {
            answer = answer.carrying(named, value);
        }
    }
    // §2: the client is told the state of the session it just joined, so its
    // own iframe can ask later whether it is still that one.
    let session_state = authorized.browser_state.and_then(|held| {
        auth::session_state::state_for(
            provider,
            authorized.client_id,
            authorized.redirect_uri,
            held,
        )
    });
    // RFC 9207: which server answered. A client talking to two providers can
    // otherwise be made to take one's answer for the other's.
    Ok(answer
        .carrying_any("state", authorized.state)
        .carrying_any("session_state", session_state.as_deref())
        .carrying("iss", authorized.issuer))
}

/// How long a code may sit before it is spent.
///
/// One minute, which is OIDC Core §3.1.3.3's guidance. It travels through a
/// browser redirect and is spent immediately after, so anything longer is a
/// window nobody uses and an attacker might.
const CODE_LIFESPAN: i64 = 60;

fn draw(provider: &dyn CryptoProvider) -> Result<String, Unanswerable> {
    let mut drawn = [0_u8; 32];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unanswerable::Unreadable)?;
    Ok(HEXLOWER.encode(&drawn))
}

/// The digest the row is keyed by. The raw code goes to the browser and is
/// never stored, so a leaked table yields nothing spendable.
fn digest(provider: &dyn CryptoProvider, raw: &[u8]) -> Result<String, Unanswerable> {
    let hashed = provider
        .digest()
        .hash(crypto::provider::HashAlg::Sha256, raw)
        .map_err(|_| Unanswerable::Unreadable)?;
    Ok(HEXLOWER.encode(&hashed))
}

/// A note the request wrote when the login opened.
fn noted<'a>(notes: &'a Value, named: &str) -> Option<&'a str> {
    notes.get(named).and_then(Value::as_str)
}

/// How the answer travels, as the request that opened the login named it.
fn answering(notes: &Value) -> ResponseMode {
    ResponseMode::read(noted(notes, "response_mode")).unwrap_or_default()
}

/// What the request asked to come back with.
fn coming_back(notes: &Value) -> ResponseType {
    noted(notes, "response_type")
        .and_then(ResponseType::read)
        .unwrap_or(ResponseType {
            code: true,
            id_token: false,
            token: false,
        })
}

/// Where the browser goes once a login established somebody.
///
/// The protocol's half of an admission: authentication says who the person is
/// and hands back the login it just closed, and this reads what the request had
/// asked for out of it. Nothing here is authentication, and nothing there is
/// protocol.
pub async fn landed(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &TenantContext,
    admitted: &auth::login::browser::Admission,
    signing: Option<&store::keyring::Signing<'_>>,
    issuer: &str,
    now: DateTime<Utc>,
) -> Result<Landing, Unanswerable> {
    // Read here rather than threaded in: the realm's map is what turns what
    // the flow reached into an `acr`, and that is this side's business.
    let realm = &store::providers::realms::load(transaction, &tenant.realm_id)
        .await
        .map_err(|_| Unanswerable::Unreadable)?
        .ok_or(Unanswerable::Unrunnable)?;
    let notes = &admitted.login.notes;
    mint_code(
        transaction,
        provider,
        tenant,
        &Authorized {
            client_id: &admitted.login.client_id,
            user_id: &admitted.user_id,
            session_id: &admitted.session_id,
            redirect_uri: &admitted.login.redirect_uri,
            scope: noted(notes, "scope").unwrap_or_default(),
            state: noted(notes, "state"),
            browser_state: admitted.browser_state.as_deref(),
            mode: answering(notes),
            asked_for: coming_back(notes),
            signing,
            realm: Some(realm),
            issuer,
            nonce: noted(notes, "nonce"),
            code_challenge: noted(notes, "code_challenge"),
            code_challenge_method: noted(notes, "code_challenge_method"),
            claims: notes.get("claims").filter(|asked| asked.is_object()),
            auth_time: admitted.auth_time,
            // Frozen at admission. By redemption the session may have stepped
            // up in another tab, and a value resolved then would attest to a
            // strength this code was never issued under.
            acr: admitted.reached.and_then(|loa| {
                realm.acr_loa_map.as_ref().and_then(|map| {
                    acr::acr_claim(
                        map,
                        AchievedAuth {
                            loa,
                            auth_time: admitted.auth_time,
                        },
                    )
                })
            }),
        },
        now,
    )
    .await
}

/// Where the browser goes when the login ended without establishing anybody.
///
/// The client hears why at its own redirect, the way it asked to hear it.
pub fn refused(login: &login::AuthSession, error: &'static str, issuer: &str) -> Landing {
    let notes = &login.notes;
    Landing::new(&login.redirect_uri, answering(notes))
        .carrying("error", error)
        .carrying_any("state", noted(notes, "state"))
        // RFC 9207: the answer names who sent it, so a client with several
        // providers cannot be handed one provider's answer as another's.
        .carrying("iss", issuer)
}
