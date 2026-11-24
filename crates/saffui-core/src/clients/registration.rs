//! Initial access tokens: what an administrator hands out so that clients
//! register themselves through the protocol (RFC 7591, section 3), for a
//! number of registrations and a time. Shown once, kept by their digest.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::store::ListWindow;
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::authz::admin::AdminCaller;
use crate::authz::roles::describe_actor;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::instant::write_instant;
use crate::secret::Secret;

/// The most clients one initial access token registers.
pub const MOST_INITIAL_TOKEN_USES: u32 = 100;
/// The longest an initial access token lives.
pub const LONGEST_INITIAL_TOKEN_LIFE: Duration = Duration::days(30);
/// How many initial access tokens a realm holds at once with a use left.
pub const MOST_LIVE_INITIAL_TOKENS: u64 = 100;

/// An initial access token as an administrator sees it: never its digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialAccessToken {
    pub id: Uuid,
    pub uses_left: u32,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    /// The client of the administration plane that made it.
    pub created_by: String,
}

/// Draws a token handed out once, 256 bits written in base64url, and its
/// digest, which is all that is kept of it.
///
/// # Errors
///
/// Returns [`ErrorCode::RandomUnavailable`].
pub(crate) fn draw_bearer_token(app: &App) -> Result<(Secret, [u8; 32]), Failure> {
    let mut random = [0_u8; 32];
    app.random
        .fill(&mut random)
        .map_err(|_| Failure::new(ErrorCode::RandomUnavailable))?;
    let token = URL_SAFE_NO_PAD.encode(random);
    let digest = app.digester.sha256(token.as_bytes());
    Ok((Secret::new(token.into_bytes()), digest))
}

/// Draws the identifier of a registered client: 128 bits in base64url,
/// nothing the client chose, never in the shape of a person's.
///
/// # Errors
///
/// Returns [`ErrorCode::RandomUnavailable`].
pub(crate) fn draw_client_identifier(app: &App) -> Result<String, Failure> {
    let mut random = [0_u8; 16];
    app.random
        .fill(&mut random)
        .map_err(|_| Failure::new(ErrorCode::RandomUnavailable))?;
    Ok(URL_SAFE_NO_PAD.encode(random))
}

/// Makes an initial access token for `uses` registrations within
/// `lifetime_seconds`, and returns it: the one time it is shown.
///
/// # Errors
///
/// Returns [`ErrorCode::RequestInvalid`] for no use, more than a hundred, or
/// a lifetime of nothing or past thirty days,
/// [`ErrorCode::InitialTokenLimitReached`] for a realm that holds
/// [`MOST_LIVE_INITIAL_TOKENS`] with a use left already, or the storage
/// failure.
pub async fn create_initial_access_token(
    app: &App,
    caller: &AdminCaller,
    uses: u32,
    lifetime_seconds: i64,
) -> Result<(InitialAccessToken, Secret), Failure> {
    let lifetime = Duration::seconds(lifetime_seconds);
    if !(1..=MOST_INITIAL_TOKEN_USES).contains(&uses)
        || lifetime <= Duration::ZERO
        || lifetime > LONGEST_INITIAL_TOKEN_LIFE
    {
        return Err(Failure::new(ErrorCode::RequestInvalid));
    }
    let (token, digest) = draw_bearer_token(app)?;
    let now = app.now();
    let made = InitialAccessToken {
        id: mint_id(app)?,
        uses_left: uses,
        expires_at: now + lifetime,
        created_at: now,
        created_by: caller.client.client_id.clone(),
    };
    let mut work = app.storage.begin(caller.scope).await?;
    if work.count_live_initial_access_tokens(now).await? >= MOST_LIVE_INITIAL_TOKENS {
        return Err(Failure::new(ErrorCode::InitialTokenLimitReached));
    }
    work.insert_initial_access_token(&made, &digest).await?;
    let told = json!({
        "actor": describe_actor(caller),
        "expires_at": write_instant(made.expires_at),
        "token_id": made.id.to_string(),
        "uses": uses,
    });
    record_event(app, work.as_mut(), EventKind::InitialTokenCreated, told).await?;
    work.commit().await?;
    Ok((made, token))
}

/// Lists the initial access tokens of the realm of the caller, spent and
/// expired ones included, until an administrator removes them.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn list_initial_access_tokens(
    app: &App,
    caller: &AdminCaller,
    window: ListWindow,
) -> Result<Vec<InitialAccessToken>, Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    Ok(work.list_initial_access_tokens(window).await?)
}

/// Takes an initial access token back, spent or not.
///
/// # Errors
///
/// Returns [`ErrorCode::InitialTokenNotFound`] or the storage failure.
pub async fn delete_initial_access_token(
    app: &App,
    caller: &AdminCaller,
    token_id: Uuid,
) -> Result<(), Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    if !work.delete_initial_access_token(token_id).await? {
        return Err(Failure::new(ErrorCode::InitialTokenNotFound));
    }
    let told = json!({ "actor": describe_actor(caller), "token_id": token_id.to_string() });
    record_event(app, work.as_mut(), EventKind::InitialTokenDeleted, told).await?;
    work.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{
        MOST_LIVE_INITIAL_TOKENS, create_initial_access_token, delete_initial_access_token,
        list_initial_access_tokens,
    };
    use crate::authz::capability::Capability;
    use crate::clients::store::ListWindow;
    use crate::error::ErrorCode;
    use crate::oidc::scenario::Scenario;
    use crate::testkit::drive::complete;

    #[test]
    fn an_initial_token_is_made_for_one_to_a_hundred_uses_and_at_most_thirty_days() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::RealmWrite]);
        let make = |uses, seconds| {
            complete(create_initial_access_token(
                &scenario.app,
                &operator,
                uses,
                seconds,
            ))
            .map(|(made, _)| made.uses_left)
            .map_err(|failure| failure.code)
        };

        for (uses, seconds) in [
            (0, 3600),
            (101, 3600),
            (1, 0),
            (1, -1),
            (1, 30 * 86_400 + 1),
        ] {
            assert_eq!(
                make(uses, seconds),
                Err(ErrorCode::RequestInvalid),
                "{uses} uses, {seconds} s"
            );
        }
        assert_eq!(make(100, 30 * 86_400), Ok(100));
        assert_eq!(make(1, 1), Ok(1));
    }

    #[test]
    fn a_realm_holds_a_hundred_live_initial_tokens_and_a_spent_or_expired_one_frees_its_place() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::RealmWrite]);
        let make = |seconds| {
            complete(create_initial_access_token(
                &scenario.app,
                &operator,
                1,
                seconds,
            ))
            .map(|(made, _)| made.id)
            .map_err(|failure| failure.code)
        };
        let short = make(60).expect("a token that expires first");
        for _ in 1..MOST_LIVE_INITIAL_TOKENS {
            make(3600).expect("a token");
        }

        assert_eq!(make(3600), Err(ErrorCode::InitialTokenLimitReached));
        scenario.clock.advance(std::time::Duration::from_mins(1));
        assert!(make(3600).is_ok(), "an expired token is not live");
        assert_eq!(make(3600), Err(ErrorCode::InitialTokenLimitReached));
        assert_eq!(
            complete(delete_initial_access_token(&scenario.app, &operator, short)),
            Ok(()),
            "an expired token is still listed until it is taken back"
        );
    }

    #[test]
    fn an_initial_token_is_shown_once_listed_without_it_and_taken_back_once() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::RealmWrite]);
        let (made, token) = complete(create_initial_access_token(
            &scenario.app,
            &operator,
            3,
            3600,
        ))
        .expect("a token");
        assert_eq!(token.expose().len(), 43, "256 bits in base64url");
        assert_eq!(made.created_by, "operator");

        let window = ListWindow { first: 0, max: 10 };
        let listed =
            complete(list_initial_access_tokens(&scenario.app, &operator, window)).expect("a list");
        assert_eq!(listed, std::slice::from_ref(&made));
        assert!(
            !format!("{listed:?}").contains(std::str::from_utf8(token.expose()).expect("text")),
            "a list never holds the token"
        );

        assert_eq!(
            complete(delete_initial_access_token(
                &scenario.app,
                &operator,
                made.id
            )),
            Ok(())
        );
        assert_eq!(
            complete(delete_initial_access_token(
                &scenario.app,
                &operator,
                made.id
            ))
            .map_err(|failure| failure.code),
            Err(ErrorCode::InitialTokenNotFound)
        );
        assert_eq!(
            complete(delete_initial_access_token(
                &scenario.app,
                &operator,
                Uuid::nil()
            ))
            .map_err(|failure| failure.code),
            Err(ErrorCode::InitialTokenNotFound)
        );
        let kinds = scenario.read_event_kinds();
        let said: Vec<&str> = kinds
            .iter()
            .map(String::as_str)
            .filter(|kind| kind.starts_with("client.initial_token"))
            .collect();
        assert_eq!(
            said,
            [
                "client.initial_token_created",
                "client.initial_token_deleted"
            ]
        );
        for event in scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
        {
            assert!(
                !event
                    .to_string()
                    .contains(std::str::from_utf8(token.expose()).expect("text")),
                "no event holds the token: {event}"
            );
        }
    }
}
