use chrono::{Duration, Utc};
use crypto::jose::jws::ES256;
use crypto::jose::jwt;
use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, SignAlg};
use models::entities::keys::{KeyStatus, KeyUse, RealmSigningKey, RealmSigningKeyView};
use services::token::issuance::{Kind, Minting, Unmintable, mint_token};
use services::token::{Refused, verify_signature_and_window};

fn provider() -> OpenSslProvider {
    OpenSslProvider::new(&CryptoConfig {
        fips_required: false,
        pkcs11: None,
    })
    .expect("a software provider")
}

/// A real key pair, because a token signed with a placeholder proves nothing
/// about whether this realm would take it back.
fn signing_key() -> (RealmSigningKey, RealmSigningKeyView) {
    let pair = ES256.generate_key_pair().expect("a P-256 pair");
    let public = serde_json::to_value(pair.to_jwk_public_key().as_ref()).expect("a public jwk");

    let signing = RealmSigningKey {
        tenant: "acme".into(),
        realm_id: "main".into(),
        kid: "k-1".into(),
        algorithm: SignAlg::Es256,
        key_use: KeyUse::Sig,
        status: KeyStatus::Active,
        priority: 100,
        private_pem: pair.to_pem_private_key(),
        public_jwk: public.clone(),
        created_at: 1_700_000_000,
    };
    let published = RealmSigningKeyView {
        kid: "k-1".into(),
        realm_id: "main".into(),
        algorithm: SignAlg::Es256,
        key_type: "EC".into(),
        key_use: KeyUse::Sig,
        status: KeyStatus::Active,
        priority: 100,
        public_jwk: public,
        created_at: 1_700_000_000,
    };
    (signing, published)
}

fn minting<'a>(kind: Kind, now: chrono::DateTime<Utc>) -> Minting<'a> {
    Minting {
        bound_to: None,
        certified_by: None,
        kind,
        issuer: "main",
        subject: "ada",
        audiences: vec!["saffui-admin".to_owned()],
        party: "app",
        session_id: "s-1",
        scope: "openid admin",
        lifespan: Duration::minutes(5),
        now,
        extra: serde_json::Map::new(),
    }
}

/// The whole point: what this mints, this accepts. Written as one test because
/// a mint that is only checked against a decoder proves the token parses, not
/// that the realm's own gate lets it through.
#[test]
fn what_the_realm_mints_the_realm_takes_back() {
    let provider = provider();
    let (signing, published) = signing_key();
    let now = Utc::now();

    let minted = mint_token(&provider, &signing, minting(Kind::Access, now)).expect("a token");

    let verified = verify_signature_and_window(&[published], &minted.token, now)
        .expect("the realm refused what it had just minted");

    assert_eq!(verified.subject, "ada");
    assert_eq!(verified.audiences, vec!["saffui-admin".to_owned()]);
    assert_eq!(verified.scope, "openid admin");
    assert_eq!(
        verified.token_id.as_deref(),
        Some(minted.token_id.as_str()),
        "the identifier a withdrawal would be written against is not the one in the token"
    );
    assert_eq!(verified.claims.get("typ").unwrap(), "Bearer");
    assert_eq!(verified.claims.get("azp").unwrap(), "app");
    assert_eq!(verified.claims.get("sid").unwrap(), "s-1");
}

/// The three instants have to be whole seconds. Written as fractions they read
/// as absent to anything expecting an integer, and a lever that reads one then
/// falls back to whatever it decided absence means.
#[test]
fn the_instants_are_whole_seconds() {
    let provider = provider();
    let (signing, _) = signing_key();
    let now = Utc::now();

    let minted = mint_token(&provider, &signing, minting(Kind::Access, now)).expect("a token");
    let (payload, _) = jwt::decode_with_verifier(
        &minted.token,
        &ES256
            .verifier_from_jwk(
                &crypto::jose::jwk::Jwk::from_map(signing.public_jwk.as_object().unwrap().clone())
                    .unwrap(),
            )
            .unwrap(),
    )
    .expect("a readable token");

    for claim in ["iat", "nbf", "exp"] {
        let value = payload.claim(claim).expect("the instant is stated");
        assert!(
            value.as_i64().is_some(),
            "{claim} is {value}, which reads as nothing to anything expecting an integer"
        );
    }
    assert_eq!(
        payload.claim("exp").unwrap().as_i64().unwrap(),
        minted.expires_at.timestamp()
    );
}

/// The header names the kind, so a gate can refuse a token before it has
/// trusted a byte of the body.
#[test]
fn the_header_says_which_kind_it_is() {
    let provider = provider();
    let (signing, _) = signing_key();
    let now = Utc::now();

    for (kind, media_type, claimed) in [
        (Kind::Access, "at+jwt", "Bearer"),
        (Kind::Identity, "JWT", "ID"),
        (Kind::Refresh, "JWT", "Refresh"),
    ] {
        let minted = mint_token(&provider, &signing, minting(kind, now)).expect("a token");
        let header = jwt::decode_header(&minted.token).expect("a readable header");
        assert_eq!(header.claim("typ").unwrap(), media_type);
        assert_eq!(header.claim("kid").unwrap(), "k-1");
        assert_eq!(
            header.claim("alg").unwrap(),
            "ES256",
            "the header named an algorithm the key was not published for"
        );
        assert_eq!(kind.claimed(), claimed);
    }
}

/// Two tokens minted in the same instant are still two tokens. An identifier
/// derived from anything shared would let one withdrawal reach both, or neither.
#[test]
fn every_token_gets_an_identifier_of_its_own() {
    let provider = provider();
    let (signing, _) = signing_key();
    let now = Utc::now();

    let first = mint_token(&provider, &signing, minting(Kind::Access, now)).expect("a token");
    let second = mint_token(&provider, &signing, minting(Kind::Access, now)).expect("a token");
    assert_ne!(first.token_id, second.token_id);
    assert_eq!(first.token_id.len(), 32);
}

/// A claim the flow adds cannot displace one the token is judged by. Otherwise a
/// client registration naming a mapper called `sub` would be a way to mint a
/// token for anybody.
#[test]
fn an_added_claim_cannot_displace_a_named_one() {
    let provider = provider();
    let (signing, published) = signing_key();
    let now = Utc::now();

    let mut asked = minting(Kind::Access, now);
    asked.extra.insert("sub".into(), serde_json::json!("root"));
    asked
        .extra
        .insert("exp".into(), serde_json::json!(i64::MAX));
    asked.extra.insert("nonce".into(), serde_json::json!("n-1"));

    let minted = mint_token(&provider, &signing, asked).expect("a token");
    let verified = verify_signature_and_window(&[published], &minted.token, now).expect("a token");

    assert_eq!(
        verified.subject, "ada",
        "an added claim renamed the subject"
    );
    assert_eq!(
        verified.claims.get("exp").unwrap().as_i64().unwrap(),
        minted.expires_at.timestamp(),
        "an added claim moved the window"
    );
    assert_eq!(verified.claims.get("nonce").unwrap(), "n-1");
}

/// A token nobody is the audience of is one every audience check has to decide
/// what to do about, and the answers differ per gate.
#[test]
fn a_token_for_nobody_is_not_minted() {
    let provider = provider();
    let (signing, _) = signing_key();
    let mut asked = minting(Kind::Access, Utc::now());
    asked.audiences.clear();

    assert_eq!(
        mint_token(&provider, &signing, asked).expect_err("a token for nobody"),
        Unmintable::NoAudience
    );
}

/// The window is not advisory. A token minted five minutes ago with a five
/// minute lifespan is over, and its own realm says so.
#[test]
fn the_window_it_states_is_the_window_it_gets() {
    let provider = provider();
    let (signing, published) = signing_key();
    let now = Utc::now();

    let minted = mint_token(&provider, &signing, minting(Kind::Access, now)).expect("a token");
    assert_eq!(
        verify_signature_and_window(&[published], &minted.token, now + Duration::minutes(6))
            .expect_err("a token past its window"),
        Refused::OutsideWindow
    );
}
