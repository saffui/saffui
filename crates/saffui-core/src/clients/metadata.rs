//! The metadata a client sends to register itself (RFC 7591, section 2, and
//! OpenID Connect Dynamic Client Registration, section 2), read against the
//! settings of the realm. A member this version does not know is passed
//! over. A member it knows and does not honor is refused when it asks for
//! something: a client that expects its tokens bound to a key, encrypted or
//! signed again, or its keys fetched, would be served less than it asked.

use serde_json::{Map, Value};

use super::{AssertionAlgorithm, ClientAuthMethod, check_scope_token};
use crate::error::{ErrorCode, Failure};
use crate::ports::crypto::SignatureAlgorithm;
use crate::secret::Secret;
use crate::tenancy::settings::RealmSettings;

/// Known, and not honored. Each asks for a safeguard or a path this realm
/// does not hold.
pub const UNHONORED_MEMBERS: [&str; 32] = [
    // Keys and lists fetched from an address of the client.
    "jwks_uri",
    "sector_identifier_uri",
    "request_uris",
    // Sign-ins a client bounds by default.
    "default_max_age",
    "default_acr_values",
    // Identity tokens and answers encrypted, or signed again.
    "id_token_encrypted_response_alg",
    "id_token_encrypted_response_enc",
    "userinfo_signed_response_alg",
    "userinfo_encrypted_response_alg",
    "userinfo_encrypted_response_enc",
    "authorization_signed_response_alg",
    "authorization_encrypted_response_alg",
    "authorization_encrypted_response_enc",
    "introspection_signed_response_alg",
    "introspection_encrypted_response_alg",
    "introspection_encrypted_response_enc",
    // Requests signed, encrypted, or pushed first (RFC 9101, RFC 9126).
    "request_object_signing_alg",
    "request_object_encryption_alg",
    "request_object_encryption_enc",
    "require_signed_request_object",
    "require_pushed_authorization_requests",
    // Tokens bound to a key or a certificate (RFC 9449, RFC 8705).
    "dpop_bound_access_tokens",
    "tls_client_certificate_bound_access_tokens",
    "tls_client_auth_subject_dn",
    "tls_client_auth_san_dns",
    "tls_client_auth_san_uri",
    "tls_client_auth_san_ip",
    "tls_client_auth_san_email",
    // Sign-outs told to the client.
    "frontchannel_logout_uri",
    "frontchannel_logout_session_required",
    "backchannel_logout_uri",
    "backchannel_logout_session_required",
];

/// What the metadata of a client asks, once read. Its name is the
/// identifier of the client when it gives none (RFC 7591, section 2).
// No `Debug`: it carries the secret a change presents.
pub struct WantedMetadata {
    pub name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub method: ClientAuthMethod,
    pub signing: Option<AssertionAlgorithm>,
    /// RS256 when it names none (OpenID Connect Dynamic Client
    /// Registration, section 2).
    pub id_token_alg: SignatureAlgorithm,
    /// The scopes it asks for, each written as a scope, once. None asked:
    /// all those its realm lets a registered client have.
    pub scopes: Option<Vec<String>>,
    pub jwks: Option<Value>,
    /// What a request to change a registration says it is (RFC 7592,
    /// section 2.2). Passed over at a registration.
    pub client_id: Option<String>,
    pub client_secret: Option<Secret>,
}

fn refuse(member: &str) -> Failure {
    Failure::with_detail(ErrorCode::ClientMetadataInvalid, member.to_owned())
}

/// Whether a member asks for anything: null and false ask for nothing.
fn asks_for_something(value: &Value) -> bool {
    !matches!(value, Value::Null | Value::Bool(false))
}

fn read_text<'a>(members: &'a Map<String, Value>, name: &str) -> Result<Option<&'a str>, Failure> {
    match members.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(refuse(name)),
    }
}

fn read_texts(members: &Map<String, Value>, name: &str) -> Result<Option<Vec<String>>, Failure> {
    match members.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| refuse(name))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(refuse(name)),
    }
}

/// Reads the scopes a client asks for, each written as a scope, once.
fn read_requested_scopes(asked: Option<&str>) -> Result<Option<Vec<String>>, Failure> {
    let Some(text) = asked else {
        return Ok(None);
    };
    let mut scopes: Vec<String> = Vec::new();
    for token in text.split(' ').filter(|token| !token.is_empty()) {
        check_scope_token(token)?;
        if !scopes.iter().any(|known| known == token) {
            scopes.push(token.to_owned());
        }
    }
    Ok(Some(scopes))
}

/// Judges what a client asks against the settings of its realm, and returns
/// the scopes it is allowed: each it asks among those the realm lets a
/// registered client have, all of those when it asks none, and at most as
/// many addresses of each kind as the realm lets it give. The one rule of a
/// registration and of a change, judged on the settings held.
///
/// # Errors
///
/// Returns [`ErrorCode::ScopeNotAllowed`], or
/// [`ErrorCode::ClientMetadataInvalid`] with the member that gives too many
/// addresses.
pub fn judge_wanted_metadata(
    wanted: &WantedMetadata,
    settings: &RealmSettings,
) -> Result<Vec<String>, Failure> {
    let most = usize::try_from(settings.max_redirect_uris).unwrap_or(usize::MAX);
    for (member, addresses) in [
        ("redirect_uris", &wanted.redirect_uris),
        (
            "post_logout_redirect_uris",
            &wanted.post_logout_redirect_uris,
        ),
    ] {
        if addresses.len() > most {
            return Err(refuse(member));
        }
    }
    let Some(asked) = &wanted.scopes else {
        return Ok(settings.registrable_scopes.clone());
    };
    if asked
        .iter()
        .all(|scope| settings.registrable_scopes.contains(scope))
    {
        Ok(asked.clone())
    } else {
        Err(Failure::new(ErrorCode::ScopeNotAllowed))
    }
}

/// Reads the metadata a client sent to register itself, or to change its
/// registration, as far as it is read without the settings of its realm:
/// [`judge_wanted_metadata`] judges the rest. A registered client signs
/// people in with a code, and does nothing else: it gives addresses to send
/// them back to, and asks no other grant.
///
/// # Errors
///
/// Returns [`ErrorCode::SoftwareStatementRefused`],
/// [`ErrorCode::RedirectUriInvalid`] without an address to send people
/// back to, [`ErrorCode::ScopeInvalid`] for a scope, and
/// [`ErrorCode::ClientMetadataInvalid`] with the member it refused for
/// anything else.
pub fn read_client_metadata(document: &Value) -> Result<WantedMetadata, Failure> {
    let members = document
        .as_object()
        .ok_or_else(|| refuse("not an object"))?;
    if members
        .get("software_statement")
        .is_some_and(asks_for_something)
    {
        return Err(Failure::new(ErrorCode::SoftwareStatementRefused));
    }
    if let Some(member) = UNHONORED_MEMBERS
        .iter()
        .find(|name| members.get(**name).is_some_and(asks_for_something))
    {
        return Err(refuse(member));
    }
    if read_text(members, "subject_type")?.is_some_and(|kind| kind != "public") {
        return Err(refuse("subject_type"));
    }
    let redirect_uris = read_texts(members, "redirect_uris")?.unwrap_or_default();
    if redirect_uris.is_empty() {
        return Err(Failure::with_detail(
            ErrorCode::RedirectUriInvalid,
            "redirect_uris",
        ));
    }
    let post_logout_redirect_uris =
        read_texts(members, "post_logout_redirect_uris")?.unwrap_or_default();
    // A refresh token comes with a code: asking for both asks nothing more.
    let grants = read_texts(members, "grant_types")?
        .unwrap_or_else(|| vec!["authorization_code".to_owned()]);
    if !grants.iter().any(|grant| grant == "authorization_code")
        || !grants
            .iter()
            .all(|grant| matches!(grant.as_str(), "authorization_code" | "refresh_token"))
    {
        return Err(refuse("grant_types"));
    }
    let responses =
        read_texts(members, "response_types")?.unwrap_or_else(|| vec!["code".to_owned()]);
    if responses.is_empty() || responses.iter().any(|kind| kind != "code") {
        return Err(refuse("response_types"));
    }
    let method = match read_text(members, "token_endpoint_auth_method")? {
        None => ClientAuthMethod::ClientSecretBasic,
        Some(name) => {
            ClientAuthMethod::parse(name).ok_or_else(|| refuse("token_endpoint_auth_method"))?
        }
    };
    let signing = read_text(members, "token_endpoint_auth_signing_alg")?
        .map(|name| {
            AssertionAlgorithm::parse(name).ok_or_else(|| refuse("token_endpoint_auth_signing_alg"))
        })
        .transpose()?;
    let id_token_alg = match read_text(members, "id_token_signed_response_alg")? {
        None => SignatureAlgorithm::Rs256,
        Some(name) => {
            SignatureAlgorithm::parse(name).ok_or_else(|| refuse("id_token_signed_response_alg"))?
        }
    };
    let jwks = match members.get("jwks") {
        None | Some(Value::Null) => None,
        Some(jwks @ Value::Object(_)) => Some(jwks.clone()),
        Some(_) => return Err(refuse("jwks")),
    };
    Ok(WantedMetadata {
        name: read_text(members, "client_name")?.map(str::to_owned),
        redirect_uris,
        post_logout_redirect_uris,
        method,
        signing,
        id_token_alg,
        scopes: read_requested_scopes(read_text(members, "scope")?)?,
        jwks,
        client_id: read_text(members, "client_id")?.map(str::to_owned),
        client_secret: read_text(members, "client_secret")?
            .map(|secret| Secret::new(secret.as_bytes().to_vec())),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{UNHONORED_MEMBERS, WantedMetadata, judge_wanted_metadata, read_client_metadata};
    use crate::clients::{AssertionAlgorithm, ClientAuthMethod};
    use crate::error::ErrorCode;
    use crate::ports::crypto::SignatureAlgorithm;
    use crate::secret::Secret;
    use crate::tenancy::settings::RealmSettings;

    const CALLBACK: &str = "https://registered.example.org/cb";

    fn read(document: &Value) -> Result<WantedMetadata, ErrorCode> {
        read_client_metadata(document).map_err(|failure| failure.code)
    }

    fn with(member: &str, value: Value) -> Value {
        let mut document = json!({ "redirect_uris": [CALLBACK] });
        document[member] = value;
        document
    }

    #[test]
    fn a_client_that_says_only_where_to_send_people_back_is_read_with_the_defaults() {
        let read = read(&json!({ "redirect_uris": [CALLBACK] })).expect("metadata");

        assert_eq!(read.name, None);
        assert_eq!(read.redirect_uris, [CALLBACK]);
        assert!(read.post_logout_redirect_uris.is_empty());
        assert_eq!(read.method, ClientAuthMethod::ClientSecretBasic);
        assert_eq!(read.signing, None);
        assert_eq!(read.id_token_alg, SignatureAlgorithm::Rs256);
        assert_eq!(read.scopes, None, "all the realm lets it have");
        assert_eq!(read.jwks, None);
        assert_eq!(read.client_id, None);
        assert!(read.client_secret.is_none());
        assert_eq!(
            judge_wanted_metadata(&read, &RealmSettings::default()),
            Ok(vec![
                "openid".to_owned(),
                "profile".to_owned(),
                "email".to_owned()
            ])
        );
    }

    #[test]
    fn each_member_known_and_not_honored_is_refused_and_named_when_it_asks_for_something() {
        for member in UNHONORED_MEMBERS {
            for asking in [
                json!(true),
                json!("https://registered.example.org/x"),
                json!(60),
            ] {
                let refused = read_client_metadata(&with(member, asking.clone()));
                assert_eq!(
                    refused.as_ref().map(|_| ()).map_err(|failure| failure.code),
                    Err(ErrorCode::ClientMetadataInvalid),
                    "{member}: {asking}"
                );
                assert_eq!(
                    refused.err().and_then(|failure| failure.detail).as_deref(),
                    Some(member),
                    "the refusal names {member}"
                );
            }
            for asking_nothing in [Value::Null, json!(false)] {
                assert!(
                    read(&with(member, asking_nothing.clone())).is_ok(),
                    "{member}: {asking_nothing} asks for nothing"
                );
            }
        }
    }

    #[test]
    fn a_software_statement_is_refused_in_its_own_words() {
        assert_eq!(
            read(&with(
                "software_statement",
                json!("eyJhbGciOiJSUzI1NiJ9.e30.c2ln")
            ))
            .map(|_| ()),
            Err(ErrorCode::SoftwareStatementRefused)
        );
    }

    #[test]
    fn a_member_this_version_does_not_know_or_that_asks_for_no_safeguard_is_passed_over() {
        for (member, value) in [
            ("logo_uri", json!("https://registered.example.org/logo.png")),
            ("contacts", json!(["ops@example.org"])),
            ("software_id", json!("4NRB1-0XZABZI9E6-5SM3R")),
            ("require_auth_time", json!(true)),
            ("application_type", json!("web")),
            ("a_member_from_later", json!({ "deep": [1, 2] })),
        ] {
            assert!(read(&with(member, value)).is_ok(), "{member}");
        }
    }

    #[test]
    fn a_registered_client_signs_people_in_with_a_code_and_asks_no_other_grant() {
        for (document, why) in [
            (json!({}), "no address to send people back to"),
            (json!({ "redirect_uris": [] }), "an empty list of addresses"),
            (
                with(
                    "grant_types",
                    json!(["authorization_code", "client_credentials"]),
                ),
                "a client registered by anyone never acts as itself",
            ),
            (with("grant_types", json!(["refresh_token"])), "no code"),
            (
                with("grant_types", json!(["implicit"])),
                "no implicit grant",
            ),
            (
                with("response_types", json!(["code", "token"])),
                "a token in the address",
            ),
            (with("response_types", json!([])), "no answer at all"),
            (
                with("subject_type", json!("pairwise")),
                "a subject per client",
            ),
            (
                with("token_endpoint_auth_method", json!("tls_client_auth")),
                "a certificate",
            ),
            (
                with(
                    "token_endpoint_auth_method",
                    json!("self_signed_tls_client_auth"),
                ),
                "a certificate of its own",
            ),
            (
                with("id_token_signed_response_alg", json!("none")),
                "an unsigned token",
            ),
            (
                with("token_endpoint_auth_signing_alg", json!("none")),
                "an unsigned assertion",
            ),
            (with("jwks", json!(["a list"])), "keys that are no set"),
            (with("client_name", json!(42)), "a name that is no text"),
            (json!(["not", "an", "object"]), "no object"),
        ] {
            assert!(
                matches!(
                    read(&document),
                    Err(ErrorCode::ClientMetadataInvalid | ErrorCode::RedirectUriInvalid)
                ),
                "{why}"
            );
        }
        assert_eq!(
            read(&json!({})).map(|_| ()),
            Err(ErrorCode::RedirectUriInvalid)
        );
        let both = read(&with(
            "grant_types",
            json!(["authorization_code", "refresh_token"]),
        ))
        .expect("a code and its refresh");
        assert_eq!(both.method, ClientAuthMethod::ClientSecretBasic);
    }

    #[test]
    fn a_method_an_algorithm_and_keys_are_read_as_named() {
        let read = read(&json!({
            "redirect_uris": [CALLBACK],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "id_token_signed_response_alg": "ES256",
            "jwks": { "keys": [] },
            "client_name": "Registered",
        }))
        .expect("metadata");

        assert_eq!(read.method, ClientAuthMethod::PrivateKeyJwt);
        assert_eq!(read.signing, AssertionAlgorithm::parse("ES256"));
        assert_eq!(read.id_token_alg, SignatureAlgorithm::Es256);
        assert_eq!(read.jwks, Some(json!({ "keys": [] })));
        assert_eq!(read.name.as_deref(), Some("Registered"));
    }

    #[test]
    fn a_client_is_allowed_only_scopes_the_realm_lets_a_registered_client_have() {
        let settings = RealmSettings {
            registrable_scopes: vec!["openid".to_owned(), "email".to_owned()],
            ..RealmSettings::default()
        };
        let scoped = |scope: &str| {
            read_client_metadata(&with("scope", json!(scope)))
                .and_then(|read| judge_wanted_metadata(&read, &settings))
                .map_err(|failure| failure.code)
        };

        assert_eq!(
            scoped("openid email openid"),
            Ok(vec!["openid".to_owned(), "email".to_owned()])
        );
        for refused in ["openid offline_access", "admin", "openid roles"] {
            assert_eq!(
                scoped(refused),
                Err(ErrorCode::ScopeNotAllowed),
                "{refused}"
            );
        }
        assert_eq!(scoped("open\"id"), Err(ErrorCode::ScopeInvalid));
        assert_eq!(
            read_client_metadata(&json!({ "redirect_uris": [CALLBACK] }))
                .and_then(|read| judge_wanted_metadata(&read, &settings)),
            Ok(settings.registrable_scopes.clone()),
            "none named: all the realm allows"
        );
    }

    #[test]
    fn a_client_gives_at_most_as_many_addresses_of_each_kind_as_the_realm_lets_it() {
        let settings = RealmSettings {
            max_redirect_uris: 2,
            ..RealmSettings::default()
        };
        let addresses = |count: usize| -> Vec<String> {
            (0..count)
                .map(|index| format!("https://registered.example.org/{index}"))
                .collect()
        };
        let read = |redirects: usize, goodbyes: usize| {
            let document = json!({
                "redirect_uris": addresses(redirects),
                "post_logout_redirect_uris": addresses(goodbyes),
            });
            read_client_metadata(&document)
                .and_then(|read| judge_wanted_metadata(&read, &settings))
                .map(|_| ())
                .map_err(|failure| failure.detail)
        };

        assert_eq!(read(2, 2), Ok(()));
        assert_eq!(read(3, 0), Err(Some("redirect_uris".to_owned())));
        assert_eq!(
            read(1, 3),
            Err(Some("post_logout_redirect_uris".to_owned()))
        );
    }

    #[test]
    fn a_request_to_change_a_registration_says_which_client_and_secret_it_holds() {
        let read = read(&json!({
            "redirect_uris": [CALLBACK],
            "client_id": "registered",
            "client_secret": "the secret",
            "registration_access_token": "passed over",
        }))
        .expect("metadata");

        assert_eq!(read.client_id.as_deref(), Some("registered"));
        assert_eq!(
            read.client_secret.as_ref().map(Secret::expose),
            Some(&b"the secret"[..])
        );
    }
}
