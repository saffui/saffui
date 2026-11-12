use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::jws::sign_compact;
use super::store::RefreshToken;
use super::{
    ACCESS_TOKEN_LIFETIME_SECONDS, ACCESS_TOKEN_TYPE, IDENTITY_TOKEN_TYPE, IssuedAccessToken,
};
use crate::app::App;
use crate::authz::admin::ADMIN_SCOPE;
use crate::claims::rules::WrittenClaims;
use crate::directory::Person;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::keys::SigningKey;
use crate::keys::jwks::open_signing_key;
use crate::login::assurance::Assurance;
use crate::login::session::{AuthenticationMethod, Session};
use crate::ports::crypto::SignatureAlgorithm;
use crate::ports::storage::UnitOfWork;
use crate::secret::Secret;

/// How long an identity token is good for: long enough to be read once.
const IDENTITY_TOKEN_LIFETIME_SECONDS: u64 = 300;

#[derive(Clone, Copy)]
pub struct AccessTokenSubject<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub client_id: &'a str,
    pub scopes: &'a [String],
    /// The session behind the token, when a person is.
    pub session: Option<&'a Session>,
    /// What the evaluator wrote for this token: claims, audiences, and how
    /// long what it says stands.
    pub claims: Option<&'a WrittenClaims>,
}

#[derive(Clone, Copy)]
pub struct IdentityTokenSubject<'a> {
    pub issuer: &'a str,
    pub person: &'a Person,
    pub client_id: &'a str,
    /// What the evaluator wrote for this token.
    pub claims: &'a WrittenClaims,
    pub nonce: Option<&'a str>,
    /// The session behind the token: when the person proved who they are,
    /// and with what.
    pub session: &'a Session,
}

/// The key of the realm, opened once for every token of one answer.
pub struct MintingKey {
    key: SigningKey,
    private_key: Secret,
}

/// Opens the key the tokens of the realm are signed with.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when the realm cannot sign, or
/// the storage failure.
pub async fn open_minting_key(app: &App, work: &mut dyn UnitOfWork) -> Result<MintingKey, Failure> {
    let (key, private_key) = open_signing_key(app, work, SignatureAlgorithm::Es256).await?;
    Ok(MintingKey { key, private_key })
}

fn sign_claims(
    app: &App,
    key: &MintingKey,
    token_type: &str,
    claims: &Value,
) -> Result<String, Failure> {
    sign_compact(
        app.signer.as_ref(),
        &key.key,
        &key.private_key,
        token_type,
        claims,
    )
    .map_err(|_| Failure::with_detail(ErrorCode::CryptoUnavailable, "a token cannot be signed"))
}

/// When a token issued at `issued_at` expires. A token that says a role
/// lives no longer than the role.
fn settle_expiry(issued_at: i64, lifetime_seconds: u64, until: Option<OffsetDateTime>) -> i64 {
    let lifetime_ends = issued_at.saturating_add_unsigned(lifetime_seconds);
    until.map_or(lifetime_ends, |until| {
        until.unix_timestamp().min(lifetime_ends)
    })
}

/// Adds what the evaluator wrote beside the claims of the protocol: a claim
/// already written stays as it is.
fn add_evaluated_claims(claims: &mut Value, written: &WrittenClaims) {
    let Some(claims) = claims.as_object_mut() else {
        return;
    };
    for (name, value) in &written.claims {
        claims.entry(name.clone()).or_insert_with(|| value.clone());
    }
}

/// Mints an access token signed by the key of the realm.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when the key does not sign, or
/// [`ErrorCode::RandomUnavailable`].
pub fn mint_access_token(
    app: &App,
    key: &MintingKey,
    subject: AccessTokenSubject<'_>,
) -> Result<IssuedAccessToken, Failure> {
    let issued_at = app.now().unix_timestamp();
    let expires_at = settle_expiry(
        issued_at,
        ACCESS_TOKEN_LIFETIME_SECONDS,
        subject.claims.and_then(|written| written.until),
    );
    let scope = subject.scopes.join(" ");
    // For the realm that issued it, named first, then for what the mappers
    // name. A token for the administration plane is for the realm alone.
    let mut audiences = vec![subject.issuer];
    let for_the_plane = subject.scopes.iter().any(|scope| scope == ADMIN_SCOPE);
    if let Some(written) = subject.claims.filter(|_| !for_the_plane) {
        let named = written.audiences.iter().map(String::as_str);
        audiences.extend(named.filter(|audience| *audience != subject.issuer));
    }
    let audience = match audiences.as_slice() {
        [issuer] => json!(issuer),
        all => json!(all),
    };
    let mut claims = json!({
        "iss": subject.issuer,
        "sub": subject.subject,
        "aud": audience,
        "client_id": subject.client_id,
        "scope": scope,
        "iat": issued_at,
        "exp": expires_at,
        "jti": mint_id(app)?.to_string(),
    });
    if let Some(session) = subject.session {
        claims["sid"] = Value::String(session.id.to_string());
        // What a resource server weighs before an action that asks for more
        // (RFC 9068, section 2.2.1).
        claims["auth_time"] = json!(session.authenticated_at.unix_timestamp());
        claims["acr"] = json!(Assurance::reached_by(session).name());
    }
    if let Some(written) = subject.claims {
        add_evaluated_claims(&mut claims, written);
    }
    Ok(IssuedAccessToken {
        token: sign_claims(app, key, ACCESS_TOKEN_TYPE, &claims)?,
        expires_in: u64::try_from(expires_at - issued_at).unwrap_or(0),
        scope,
    })
}

/// Mints the identity token of a person for one client. What it says of the
/// person beyond who they are and how they proved it is what the evaluator
/// wrote for it.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when the key does not sign.
pub fn mint_identity_token(
    app: &App,
    key: &MintingKey,
    subject: IdentityTokenSubject<'_>,
) -> Result<String, Failure> {
    let issued_at = app.now().unix_timestamp();
    let person = subject.person;
    let mut claims = json!({
        "iss": subject.issuer,
        "sub": person.id.to_string(),
        "aud": subject.client_id,
        "iat": issued_at,
        "exp": settle_expiry(issued_at, IDENTITY_TOKEN_LIFETIME_SECONDS, subject.claims.until),
        // When the person proved who they are, not when this token was made.
        "auth_time": subject.session.authenticated_at.unix_timestamp(),
        "sid": subject.session.id.to_string(),
    });
    if let Some(nonce) = subject.nonce {
        claims["nonce"] = Value::String(nonce.to_owned());
    }
    claims["amr"] = write_methods(&subject.session.methods);
    claims["acr"] = json!(Assurance::reached_by(subject.session).name());
    add_evaluated_claims(&mut claims, subject.claims);
    sign_claims(app, key, IDENTITY_TOKEN_TYPE, &claims)
}

/// Names what proved the person (RFC 8176), and says so when it took more
/// than one factor.
fn write_methods(methods: &[AuthenticationMethod]) -> Value {
    let mut names: Vec<&str> = methods.iter().map(|method| method.name()).collect();
    if names.len() > 1 {
        names.push("mfa");
    }
    json!(names)
}

/// The longest a refresh token lives. It never outlives its session.
pub const REFRESH_TOKEN_LIFETIME: Duration = Duration::days(30);

pub struct RefreshGrant<'a> {
    /// The family the new token belongs to: every token of one grant.
    pub family: Uuid,
    pub client_id: &'a str,
    pub session: &'a Session,
    pub scopes: &'a [String],
}

/// Mints a refresh token, keeps its digest, and returns the token itself:
/// the one time it exists outside the client.
///
/// # Errors
///
/// Returns [`ErrorCode::RandomUnavailable`] or the storage failure.
pub async fn issue_refresh_token(
    app: &App,
    work: &mut dyn UnitOfWork,
    grant: RefreshGrant<'_>,
) -> Result<String, Failure> {
    let mut random = [0_u8; 32];
    app.random
        .fill(&mut random)
        .map_err(|_| Failure::new(ErrorCode::RandomUnavailable))?;
    let token = URL_SAFE_NO_PAD.encode(random);
    let now = app.now();
    work.insert_refresh_token(&RefreshToken {
        token_digest: app.digester.sha256(token.as_bytes()).to_vec(),
        family: grant.family,
        client_id: grant.client_id.to_owned(),
        person: grant.session.person,
        session: grant.session.id,
        scopes: grant.scopes.to_vec(),
        issued_at: now,
        expires_at: (now + REFRESH_TOKEN_LIFETIME).min(grant.session.expires_at),
    })
    .await?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::{Value, json};

    use super::{AccessTokenSubject, MintingKey, mint_access_token, open_minting_key};
    use crate::app::App;
    use crate::claims::rules::WrittenClaims;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::create_realm;
    use crate::testkit::memory::MemoryStorage;

    const ISSUER: &str = "https://id.example.test/realms/acme";

    fn open_key() -> (App, MintingKey) {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
        let key = complete(open_minting_key(&app, work.as_mut())).expect("the key of the realm");
        (app, key)
    }

    /// The claims of an access token of the service `billing`, minted with
    /// what the evaluator wrote.
    fn mint_with(app: &App, key: &MintingKey, written: &WrittenClaims) -> Value {
        let scopes = ["invoices:read".to_owned()];
        let minted = mint_access_token(
            app,
            key,
            AccessTokenSubject {
                issuer: ISSUER,
                subject: "billing",
                client_id: "billing",
                scopes: &scopes,
                session: None,
                claims: Some(written),
            },
        )
        .expect("a token");
        let payload = minted.token.split('.').nth(1).expect("a compact token");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
            .expect("claims")
    }

    #[test]
    fn a_claim_the_evaluator_wrote_never_replaces_one_of_the_protocol() {
        let (app, key) = open_key();
        let written = WrittenClaims {
            claims: json!({
                "sub": "someone-else",
                "client_id": "console",
                "scope": "admin",
                "dept": "audit",
            })
            .as_object()
            .cloned()
            .expect("an object"),
            ..WrittenClaims::default()
        };

        let claims = mint_with(&app, &key, &written);

        assert_eq!(claims["sub"], "billing");
        assert_eq!(claims["client_id"], "billing");
        assert_eq!(claims["scope"], "invoices:read");
        assert_eq!(
            claims["dept"], "audit",
            "what the protocol does not write is added"
        );
    }

    #[test]
    fn an_access_token_is_for_its_realm_first_then_for_each_audience_once() {
        let (app, key) = open_key();
        let audiences_of = |named: &[&str]| {
            let written = WrittenClaims {
                audiences: named
                    .iter()
                    .map(|audience| (*audience).to_owned())
                    .collect(),
                ..WrittenClaims::default()
            };
            mint_with(&app, &key, &written)["aud"].clone()
        };

        assert_eq!(audiences_of(&[]), json!(ISSUER), "one audience is a text");
        assert_eq!(
            audiences_of(&["https://a.example.org", "https://b.example.org"]),
            json!([ISSUER, "https://a.example.org", "https://b.example.org"])
        );
        assert_eq!(
            audiences_of(&[ISSUER, "https://a.example.org"]),
            json!([ISSUER, "https://a.example.org"]),
            "the realm is named once"
        );
        assert_eq!(audiences_of(&[ISSUER]), json!(ISSUER));
    }

    #[test]
    fn a_token_for_the_administration_plane_is_for_its_realm_alone() {
        let (app, key) = open_key();
        let written = WrittenClaims {
            audiences: vec!["https://api.example.org".to_owned()],
            ..WrittenClaims::default()
        };
        let scopes = ["admin".to_owned(), "invoices:read".to_owned()];

        let minted = mint_access_token(
            &app,
            &key,
            AccessTokenSubject {
                issuer: ISSUER,
                subject: "operator",
                client_id: "operator",
                scopes: &scopes,
                session: None,
                claims: Some(&written),
            },
        )
        .expect("a token");

        let payload = minted.token.split('.').nth(1).expect("a compact token");
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
                .expect("claims");
        assert_eq!(claims["aud"], json!(ISSUER));
    }
}
