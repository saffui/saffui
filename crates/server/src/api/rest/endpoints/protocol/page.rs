use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder, web};
use config::serving::PublicOrigin;

use crate::api::rest::endpoints::protocol::dto::uncached;
use crate::api::rest::endpoints::protocol::{brands, i18n};

const CHECK_SESSION: &str = include_str!("ui/check-session.html");
const CHECK_SESSION_SCRIPT: &str = include_str!("ui/check-session.js");
const SCRIPT: &str = include_str!("ui/login.js");
const STYLE: &str = include_str!("ui/login.css");

/// What the browser may do on this page: load this server's script and style,
/// call this server back or post the form to it, and nothing else. No inline
/// code, no frames, no submission to anywhere but here.
const POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                      connect-src 'self'; form-action 'self'; frame-ancestors 'none'; \
                      base-uri 'none'";

/// Where `/auth` sends a browser when the deployment names no other page.
pub fn location(origin: &PublicOrigin, realm: &str) -> String {
    format!(
        "{}/realms/{realm}/protocol/openid-connect/login",
        origin.as_str()
    )
}

/// Whether the caller is a browser, which is told in a page, or anything
/// else, which is told in JSON.
pub fn wants_page(request: &actix_web::HttpRequest) -> bool {
    request
        .headers()
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"))
}

/// A notice with nothing to run: a title and the body's inner HTML, which the
/// caller has already escaped, under the same style as the login page.
pub fn notice(status: StatusCode, title: &str, inner: &str) -> HttpResponse {
    told(status, title, inner, false, None)
}

/// The same, allowing the frames a front-channel logout puts in the page and
/// leaving for `landing` once they have had a moment to load.
pub fn notice_with_frames(
    status: StatusCode,
    title: &str,
    inner: &str,
    landing: Option<&str>,
) -> HttpResponse {
    told(status, title, inner, true, landing)
}

fn told(
    status: StatusCode,
    title: &str,
    inner: &str,
    frames: bool,
    landing: Option<&str>,
) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(status))
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header((
            "Content-Security-Policy",
            if frames {
                "default-src 'none'; style-src 'self'; form-action 'self'; \
                 frame-ancestors 'none'; frame-src https:"
            } else {
                "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'"
            },
        ))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             {leaving}<title>{title}</title>\
             <link rel=\"stylesheet\" href=\"login.css\"></head>\
             <body><main><h1>{title}</h1>{inner}</main></body></html>",
            title = escaped(title),
            // Markup rather than a script, because this page runs none. Two
            // seconds is what the frames get before the browser leaves.
            leaving = landing.map_or_else(String::new, |landing| format!(
                "<meta http-equiv=\"refresh\" content=\"2;url={}\">",
                escaped(landing)
            )),
        ))
}

/// The five characters HTML reads as markup, spelled so it does not.
pub fn escaped(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&#39;".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

/// What the login this browser holds says about the page shown for it. Every
/// part is advisory: anything unreadable reads as nothing said.
#[derive(Default)]
struct LiveLogin {
    /// The client's `ui_locales`, raw, OIDC Core §3.1.2.1. It outranks the
    /// browser's own list, and the realm decides what of it is honoured.
    ui_locales: Option<String>,
    /// Where somebody goes back to if the login dies behind the page.
    way_back: Option<WayBack>,
}

/// The application a login came from, as the page offers it back.
struct WayBack {
    address: String,
    name: String,
}

/// Which optional doors this realm opens on the sign-in page, as the tokens
/// the page reads off its own body. A realm that cannot be read opens none:
/// a door shown without its mechanism behind it is a lie the page tells.
async fn doors_of_realm(
    pool: &deadpool_postgres::Pool,
    tenancy: &store::tenancy::Tenancy,
    realm: &str,
) -> (
    String,
    String,
    Option<serde_json::Value>,
    Option<models::entities::realm::PasswordPolicy>,
) {
    let nothing = || (String::new(), String::new(), None, None);
    let Ok(mut connection) = pool.get().await else {
        return nothing();
    };
    let Ok(context) = store::tenancy::resolve::realm_by_name(&connection, realm).await else {
        return nothing();
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return nothing();
    };
    let Ok(Some(held)) = store::providers::realms::load(&transaction, &context.realm_id).await
    else {
        return nothing();
    };
    let mut doors = Vec::new();
    if held.reset_password_allowed == Some(true) {
        doors.push("reset");
    }
    if held.remember_me == Some(true) {
        doors.push("remember");
    }
    if held.webauthn_passwordless == Some(true) {
        doors.push("passkey");
    }
    if held.registration_allowed == Some(true) {
        doors.push("register");
        if held.register_email_as_username == Some(true) {
            doors.push("register-email");
        }
    }
    if offers_recovery_codes(&transaction, held.browser_flow.as_deref()).await {
        doors.push("recovery-code");
    }
    let idps = match store::providers::brokering::list_providers(&transaction).await {
        Ok(rows) => federated_doors(realm, &rows),
        Err(_) => String::new(),
    };
    (
        doors.join(" "),
        idps,
        held.page_overrides,
        held.password_policy,
    )
}

/// The realm's browsable providers as ready markup: one anchor per door,
/// straight to the broker, so the page works with no script at all.
///
/// The identity_providers table also holds connectors that no browser can
/// be sent to; what earns a door here is an `authorization_endpoint`.
fn federated_doors(realm: &str, rows: &[models::entities::authz::IdentityProviderModel]) -> String {
    let mut doors = String::new();
    for held in rows {
        if held.enabled == Some(false) {
            continue;
        }
        let browsable = held
            .configs
            .as_ref()
            .is_some_and(|bag| bag.get("authorization_endpoint").is_some());
        if !browsable {
            continue;
        }
        let shown = if held.display_name.trim().is_empty() {
            &held.provider_id
        } else {
            &held.display_name
        };
        let mark = brands::mark_of(&held.provider_id)
            .or_else(|| brands::mark_of(shown))
            .map(str::to_owned)
            .unwrap_or_else(|| {
                let initial = shown.chars().next().map(char::to_uppercase);
                let initial: String = initial.into_iter().flatten().collect();
                format!(
                    r#"<span class="idp-mark" aria-hidden="true">{}</span>"#,
                    escaped(&initial)
                )
            });
        doors.push_str(&format!(
            r#"<a class="idp-door" href="/realms/{}/broker/{}/login">{mark}<span>{}</span></a>"#,
            escaped(realm),
            escaped(&held.provider_id),
            escaped(shown),
        ));
    }
    doors
}

/// Whether this realm's browser flow has a step that takes a printed code.
///
/// The realm's flow and not the client's: the page is built before any client
/// is named, so a client that overrides the binding to a flow of its own is not
/// read here. Offering the field where no step takes it costs a person one
/// wrong guess; hiding it where one does would cost them the way back.
///
/// One level deep. A sub-flow is walked, because the built browser flow keeps
/// its second factors in one, and a step buried two flows down is a shape
/// nothing this build provisions.
async fn offers_recovery_codes(
    transaction: &deadpool_postgres::Transaction<'_>,
    bound: Option<&str>,
) -> bool {
    use models::entities::auth::ExecutionStep;
    use store::providers::auth_flows;

    let Ok(Some(flow)) = auth_flows::flow_by_alias(transaction, bound.unwrap_or("browser")).await
    else {
        return false;
    };
    let Ok(steps) = auth_flows::executions_of(transaction, &flow.flow_id).await else {
        return false;
    };
    for step in &steps {
        if !step.is_enabled() {
            continue;
        }
        match &step.step {
            ExecutionStep::Authenticator { authenticator, .. } => {
                if authenticator == "recovery-code" {
                    return true;
                }
            }
            ExecutionStep::SubFlow { flow_id } => {
                let Ok(inner) = auth_flows::executions_of(transaction, flow_id).await else {
                    continue;
                };
                if inner.iter().any(|held| {
                    held.is_enabled()
                        && matches!(
                            &held.step,
                            ExecutionStep::Authenticator { authenticator, .. }
                                if authenticator == "recovery-code"
                        )
                }) {
                    return true;
                }
            }
        }
    }
    false
}

/// Read the login this browser holds, for the page shown for it.
///
/// Only a live one, and this is the last moment the server knows which
/// application it came from: an expired row is swept, and the refusal that
/// follows can no longer name one. So the way back is written into the page
/// now, and the script shows it if the login dies behind the page.
async fn read_live_login(
    request: &actix_web::HttpRequest,
    pool: &deadpool_postgres::Pool,
    tenancy: &store::tenancy::Tenancy,
    realm: &str,
) -> LiveLogin {
    let Some(binding) = super::binding::read(request, super::binding::AUTH_SESSION) else {
        return LiveLogin::default();
    };
    let Ok(mut connection) = pool.get().await else {
        return LiveLogin::default();
    };
    let Ok(context) = store::tenancy::resolve::realm_by_name(&connection, realm).await else {
        return LiveLogin::default();
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return LiveLogin::default();
    };
    let Ok(Some(login)) = store::providers::login::resume(&transaction, &binding).await else {
        return LiveLogin::default();
    };
    let ui_locales = login
        .notes
        .get("ui_locales")
        .and_then(|held| held.as_str())
        .map(str::to_owned);
    let way_back = match store::providers::clients::load(&transaction, &login.client_id).await {
        Ok(Some(client)) => find_way_back(&client),
        _ => None,
    };
    LiveLogin {
        ui_locales,
        way_back,
    }
}

/// Where somebody is sent back to when the login a page was served for can no
/// longer finish: the client's home page, or its root otherwise.
fn find_way_back(client: &models::entities::client::ClientModel) -> Option<WayBack> {
    // A self-registered client writes its own home page, and an address of any
    // other scheme runs as script in the origin people type passwords into.
    let address = [client.client_uri.as_deref(), client.root_url.as_deref()]
        .into_iter()
        .flatten()
        .find(|held| commons::address::is_https_or_loopback(held))?;
    let name = [&client.display_name, &client.name]
        .into_iter()
        .find(|held| !held.trim().is_empty())
        .unwrap_or(&client.client_id);
    Some(WayBack {
        address: address.to_owned(),
        name: name.clone(),
    })
}

/// What this realm says about tongues, read fresh; a realm that cannot be
/// read speaks the whole build, which is what every realm said before it
/// could say anything.
pub(in crate::api) async fn tongues_of_realm(
    pool: &deadpool_postgres::Pool,
    tenancy: &store::tenancy::Tenancy,
    realm: &str,
) -> i18n::RealmTongues {
    let fallback = || i18n::RealmTongues::of(None, None);
    let Ok(mut connection) = pool.get().await else {
        return fallback();
    };
    let Ok(context) = store::tenancy::resolve::realm_by_name(&connection, realm).await else {
        return fallback();
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return fallback();
    };
    match store::providers::realms::load(&transaction, &context.realm_id).await {
        Ok(Some(held)) => i18n::RealmTongues::of(
            held.supported_locales.as_deref(),
            held.default_locale.as_deref(),
        ),
        _ => fallback(),
    }
}

/// The sign-in page in the tongue asked for, the request's own say first and
/// the browser's list otherwise, told which it got and that the answer
/// varies by the asking.
fn page(
    request: &actix_web::HttpRequest,
    live: &LiveLogin,
    tongues: &i18n::RealmTongues,
    doors: &str,
    idps: &str,
    overrides: Option<&serde_json::Value>,
    policy: Option<&models::entities::realm::PasswordPolicy>,
) -> HttpResponse {
    let tongue = tongues.negotiated(
        live.ui_locales.as_deref(),
        request
            .headers()
            .get("accept-language")
            .and_then(|value| value.to_str().ok()),
    );
    let body = match overrides {
        Some(spoken) => i18n::page_over(tongue, spoken),
        None => i18n::page_in(tongue).to_owned(),
    };
    // A door like the others, read off the body by the script, with the anchor
    // it opens already written into the page.
    let (doors, address, name) = match &live.way_back {
        Some(back) => (
            [doors, "back"].join(" ").trim().to_owned(),
            back.address.as_str(),
            back.name.as_str(),
        ),
        None => (doors.to_owned(), "", ""),
    };
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header(("Content-Language", tongue))
        .insert_header(("Vary", "Accept-Language"))
        .insert_header(("Content-Security-Policy", POLICY))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(
            body.replace("{doors}", &escaped(&doors))
                .replace("{idps}", idps)
                .replace(
                    "{policy}",
                    &policy
                        .map(|held| i18n::policy_checklist(tongue, held))
                        .unwrap_or_default(),
                )
                .replace("{back-address}", &escaped(address))
                .replace("{back-name}", &escaped(name)),
        )
}

/// What sends the form-post page on. Served rather than written into it: a
/// page that allows inline script allows every inline script.
pub async fn form_post_script() -> HttpResponse {
    serve(
        "text/javascript; charset=utf-8",
        crate::api::rest::endpoints::protocol::answering::SCRIPT,
    )
}

/// Session Management 1.0 §4.1, the frame a relying party loads.
///
/// Framed on purpose, which is why this one page does not refuse framing as
/// every other does. It holds nothing and does nothing: it reads a cookie,
/// digests four strings and answers the frame that asked. Whoever loads it
/// learns only what they already sent plus whether it matched.
pub async fn check_session() -> HttpResponse {
    framed("text/html; charset=utf-8", CHECK_SESSION)
}

pub async fn check_session_script() -> HttpResponse {
    framed("text/javascript; charset=utf-8", CHECK_SESSION_SCRIPT)
}

pub async fn script() -> HttpResponse {
    serve("text/javascript; charset=utf-8", SCRIPT)
}

/// The stylesheet, wearing the realm's overrides after its own defaults and
/// the organization's after the realm's. A theme that cannot be read leaves
/// the look beneath it rather than a broken page: the door already refused
/// anything unsound, so a failure here is a store fault and never the
/// caller's.
///
/// Which organization is read off the login this browser holds, where the
/// request that opened it named one. It is a look and not an entitlement:
/// the page is dressed before anyone has proved who they are, which is the
/// point of dressing it, and membership is enforced where the tokens are.
pub async fn style(
    request: actix_web::HttpRequest,
    realm: web::Path<String>,
    pool: web::Data<deadpool_postgres::Pool>,
    tenancy: web::Data<store::tenancy::Tenancy>,
) -> HttpResponse {
    let mut dressed: Option<String> = None;
    if let Ok(mut connection) = pool.get().await
        && let Ok(context) = store::tenancy::resolve::realm_by_name(&connection, &realm).await
        && let Ok(transaction) = tenancy.transaction(&mut connection, &context).await
    {
        let mut sheet = STYLE.to_owned();
        if let Ok(Some(theme)) =
            store::providers::realms::theme_of(&transaction, &context.realm_id).await
            && let Ok(overrides) = services::theme::css_of(&theme)
        {
            sheet.push('\n');
            sheet.push_str(&overrides);
            dressed = Some(sheet.clone());
        }
        if let Some(binding) = super::binding::read(&request, super::binding::AUTH_SESSION)
            && let Ok(Some(login)) = store::providers::login::resume(&transaction, &binding).await
            && let Some(slug) = login
                .notes
                .get("organization")
                .and_then(|held| held.as_str())
            && let Ok(Some(org)) =
                store::providers::organizations::load_by_name(&transaction, slug).await
            && org.enabled
            && let Ok(Some(theme)) =
                store::providers::organizations::theme_of(&transaction, &org.org_id).await
            && let Ok(overrides) = services::theme::css_of(&theme)
        {
            sheet.push('\n');
            sheet.push_str(&overrides);
            dressed = Some(sheet);
        }
    }
    match dressed {
        Some(body) => uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
            .insert_header(("Content-Type", "text/css; charset=utf-8"))
            .insert_header(("Content-Security-Policy", POLICY))
            .insert_header(("X-Content-Type-Options", "nosniff"))
            .insert_header(("X-Frame-Options", "DENY"))
            .insert_header(("Referrer-Policy", "no-referrer"))
            .body(body),
        None => serve("text/css; charset=utf-8", STYLE),
    }
}

/// The same, for the one page whose job is to be inside somebody else's.
fn framed(content_type: &'static str, body: &'static str) -> HttpResponse {
    HttpResponseBuilder::new(StatusCode::OK)
        .insert_header(("Content-Type", content_type))
        .insert_header((
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; base-uri 'none'",
        ))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        // Read on every navigation of a page that never changes, so it is
        // allowed to be kept rather than fetched each time.
        .insert_header(("Cache-Control", "public, max-age=300"))
        .body(body)
}

fn serve(content_type: &'static str, body: &'static str) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .insert_header(("Content-Type", content_type))
        .insert_header(("Content-Security-Policy", POLICY))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(body)
}

/// The page a mailed sign-in link lands on.
///
/// It spends nothing. A link in a mailbox is followed by more than the person
/// it was sent to: scanners and previewers fetch every URL they see, and a link
/// that signed somebody in on being fetched would be spent before they read the
/// message. What lands here is a button, and a button is not fetched.
///
/// The value is written into the form and nowhere else. Rendered into a page
/// this server serves, so nothing else on it can read it, and the page carries
/// no script and no referrer.
pub async fn magic_link(
    request: actix_web::HttpRequest,
    realm: web::Path<String>,
    pool: web::Data<deadpool_postgres::Pool>,
    tenancy: web::Data<store::tenancy::Tenancy>,
    asked: web::Query<Followed>,
) -> HttpResponse {
    let asked = asked.into_inner();
    // Which link was followed decides which field the page posts back. A page
    // that always posted the same one would spend a sign-in token where an
    // address was being confirmed.
    let followed = asked
        .magic_link
        .filter(|held| !held.is_empty())
        .map(|token| ("magic_link", token))
        .or_else(|| {
            asked
                .verify_email
                .filter(|held| !held.is_empty())
                .map(|token| ("verify_email", token))
        });
    let Some((named, token)) = followed else {
        let live = read_live_login(&request, &pool, &tenancy, &realm).await;
        let tongues = tongues_of_realm(&pool, &tenancy, &realm).await;
        let (doors, idps, overrides, policy) = doors_of_realm(&pool, &tenancy, &realm).await;
        return page(
            &request,
            &live,
            &tongues,
            &doors,
            &idps,
            overrides.as_ref(),
            policy.as_ref(),
        );
    };
    let body = LINK_PAGE
        .replace(
            "{action}",
            &escaped(&format!("/realms/{realm}/protocol/openid-connect/login")),
        )
        .replace("{field}", &escaped(named))
        .replace("{token}", &escaped(&token));
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header(("Content-Security-Policy", POLICY))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(body)
}

#[derive(serde::Deserialize)]
pub struct Followed {
    pub magic_link: Option<String>,
    pub verify_email: Option<String>,
}

const LINK_PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Sign in</title>
<link rel="stylesheet" href="login.css"></head>
<body><main><h1>Sign in</h1>
<p>Follow through to finish signing in on this browser.</p>
<form method="post" action="{action}">
<input type="hidden" name="{field}" value="{token}">
<button type="submit">Continue</button>
</form></main></body></html>
"#;

#[derive(serde::Deserialize)]
pub struct Resetting {
    pub token: Option<String>,
    pub user: Option<String>,
}

/// Where a mailed reset link lands: two fields and the token, and nothing that
/// says whether the link is any good. Telling that here would answer it to
/// whoever holds the link rather than to whoever can set a password.
pub async fn reset_password(
    request: actix_web::HttpRequest,
    realm: web::Path<String>,
    pool: web::Data<deadpool_postgres::Pool>,
    tenancy: web::Data<store::tenancy::Tenancy>,
    asked: web::Query<Resetting>,
) -> HttpResponse {
    let asked = asked.into_inner();
    let (Some(token), Some(user)) = (
        asked.token.filter(|held| !held.is_empty()),
        asked.user.filter(|held| !held.is_empty()),
    ) else {
        let tongues = tongues_of_realm(&pool, &tenancy, &realm).await;
        let (doors, idps, overrides, policy) = doors_of_realm(&pool, &tenancy, &realm).await;
        return page(
            &request,
            &LiveLogin::default(),
            &tongues,
            &doors,
            &idps,
            overrides.as_ref(),
            policy.as_ref(),
        );
    };
    let body = RESET_PAGE
        .replace(
            "{action}",
            &escaped(&format!(
                "/realms/{realm}/protocol/openid-connect/reset-password"
            )),
        )
        .replace("{token}", &escaped(&token))
        .replace("{user}", &escaped(&user));
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header(("Content-Security-Policy", POLICY))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(body)
}

const RESET_PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Set a new password</title>
<link rel="stylesheet" href="login.css"></head>
<body><main><h1>Set a new password</h1>
<form method="post" action="{action}">
<input type="hidden" name="token" value="{token}">
<input type="hidden" name="user" value="{user}">
<label for="password">New password</label>
<input id="password" name="password" type="password" autocomplete="new-password" required>
<button type="submit">Set password</button>
</form>
<p id="refused" class="flash" role="alert">That password was refused. Try another.</p>
<p id="no-such-link" class="flash" role="alert">This link has been used, or has expired. Ask for another.</p>
</main></body></html>
"#;

#[cfg(test)]
mod tests {
    use super::SCRIPT;
    use super::federated_doors;
    use super::find_way_back;
    use super::i18n;
    use models::auditable::AuditableModel;
    use models::entities::client::{ClientCreateModel, ClientModel};

    fn client_at(home: Option<&str>, root: Option<&str>) -> ClientModel {
        let mut client = ClientCreateModel {
            name: "billing".into(),
            display_name: "Billing".into(),
            description: String::new(),
            enabled: Some(true),
        }
        .into_model(
            "billing-app".into(),
            "main".into(),
            AuditableModel::from_creator("local".into(), "root".into()),
        );
        client.client_uri = home.map(str::to_owned);
        client.root_url = root.map(str::to_owned);
        client
    }

    /// The home page first, the root otherwise, and an address that could run
    /// as script is passed over rather than offered.
    #[test]
    fn the_way_back_is_the_home_page_then_the_root() {
        let address = |home, root| find_way_back(&client_at(home, root)).map(|back| back.address);
        assert_eq!(
            address(
                Some("https://app.example/home"),
                Some("https://app.example")
            ),
            Some("https://app.example/home".to_owned())
        );
        assert_eq!(
            address(None, Some("https://app.example")),
            Some("https://app.example".to_owned())
        );
        assert_eq!(
            address(Some("javascript:alert(1)"), Some("https://app.example")),
            Some("https://app.example".to_owned()),
            "an address that runs as script was offered"
        );
        assert_eq!(address(Some("javascript:alert(1)"), None), None);
        assert_eq!(address(None, None), None);
    }

    /// Named as a person knows the application: its display name, its name,
    /// and its identifier when it was given neither.
    #[test]
    fn the_way_back_is_named_as_a_person_knows_the_application() {
        let mut client = client_at(Some("https://app.example"), None);
        let name = |client: &ClientModel| find_way_back(client).map(|back| back.name);
        assert_eq!(name(&client), Some("Billing".to_owned()));
        client.display_name = " ".into();
        assert_eq!(name(&client), Some("billing".to_owned()));
        client.name = String::new();
        assert_eq!(name(&client), Some("billing-app".to_owned()));
    }

    /// The script reaches for the page by identifier, and a page that lost one
    /// hands it `null`. Every name it asks for has to be on every render of
    /// the page.
    #[test]
    fn every_element_the_script_reaches_for_is_on_the_page() {
        let mut asked = Vec::new();
        let mut rest = SCRIPT;
        while let Some(at) = rest.find("getElementById(\"") {
            rest = &rest[at + "getElementById(\"".len()..];
            let end = rest.find('"').expect("an unterminated identifier");
            asked.push(&rest[..end]);
            rest = &rest[end..];
        }
        assert!(asked.len() >= 8, "the identifiers were not read: {asked:?}");
        for tongue in i18n::TONGUES {
            let page = i18n::page_in(tongue);
            for named in &asked {
                // A capture ending in `-` is a family the script builds the
                // rest of at runtime; the page has to carry at least one.
                if let Some(family) = named.strip_suffix('-') {
                    assert!(
                        page.contains(&format!("id=\"{family}-")),
                        "the script asks for `{family}-*`, which the {tongue} page does not carry"
                    );
                    continue;
                }
                assert!(
                    page.contains(&format!("id=\"{named}\"")),
                    "the script asks for `{named}`, which the {tongue} page does not carry"
                );
            }
        }
    }

    fn provider(
        alias: &str,
        display: &str,
        enabled: bool,
        browsable: bool,
    ) -> models::entities::authz::IdentityProviderModel {
        let mut configs = models::entities::attributes::AttributesMap::default();
        if browsable {
            configs.insert(
                "authorization_endpoint".to_owned(),
                models::entities::attributes::AttributeValue::Str(
                    "https://upstream.example/auth".to_owned(),
                ),
            );
        }
        models::entities::authz::IdentityProviderModel {
            internal_id: alias.to_owned(),
            realm_id: "r".to_owned(),
            provider_id: alias.to_owned(),
            name: alias.to_owned(),
            display_name: display.to_owned(),
            description: String::new(),
            enabled: Some(enabled),
            trust_email: None,
            configs: Some(configs),
            metadata: models::auditable::AuditableModel::from_creator(
                "t".to_owned(),
                "test".to_owned(),
            ),
        }
    }

    /// A door per browsable provider and none for the rest: a connector has
    /// no authorization endpoint and earns none, a disabled provider shows
    /// nothing, a recognised name carries its mark, an unknown one its
    /// initial, and every written value lands escaped.
    #[test]
    fn only_browsable_providers_earn_a_door_and_each_wears_its_mark() {
        let rows = vec![
            provider("google", "Google", true, true),
            provider("the-ear", "", true, false),
            provider("okta", "Okta", false, true),
            provider("wiki<d>", "Wiki & Co", true, true),
        ];
        let doors = federated_doors("main", &rows);

        assert!(doors.contains("/realms/main/broker/google/login"));
        assert!(doors.contains("#4285F4"), "the recognised mark is missing");
        assert!(!doors.contains("the-ear"), "a connector earned a door");
        assert!(!doors.contains("okta"), "a disabled provider earned a door");
        assert!(
            doors.contains("broker/wiki&lt;d&gt;/login") && doors.contains("Wiki &amp; Co"),
            "a written value reached the page unescaped: {doors}"
        );
        assert!(
            doors.contains(r#"<span class="idp-mark" aria-hidden="true">W</span>"#),
            "an unknown provider does not wear its initial: {doors}"
        );
    }

    /// The theme door admits exactly the fifteen names; a sheet that grew a
    /// sixteenth would carry styling no realm can ever reach. Every custom
    /// property the sheet declares has to be one the door admits, however
    /// freely it derives further values from them.
    #[test]
    fn the_sheet_declares_no_token_the_theme_door_does_not_admit() {
        let mut declared = Vec::new();
        let mut rest = super::STYLE;
        while let Some(at) = rest.find("--") {
            rest = &rest[at + 2..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || *c == '-')
                .collect();
            if !name.is_empty() && rest[name.len()..].trim_start().starts_with(':') {
                declared.push(name);
            }
        }
        assert!(
            declared.len() >= services::theme::TOKENS.len(),
            "the sheet no longer declares the contract: {declared:?}"
        );
        for name in &declared {
            assert!(
                services::theme::TOKENS.contains(&name.as_str()),
                "the sheet declares `--{name}`, which the theme door does not admit: \
                 a realm can never override it. Derive it from the fifteen, or widen \
                 the contract in services::theme deliberately."
            );
        }
    }

    /// A round the script cannot name lands on its own last branch, which says
    /// only that something went wrong. Every outcome the endpoint speaks has to
    /// be one the script answers.
    #[test]
    fn every_outcome_the_endpoint_speaks_is_one_the_script_answers() {
        for named in [
            "challenge",
            "consent",
            "organization",
            "locked-out",
            "refused",
            "admitted",
            "sent_back",
        ] {
            assert!(
                SCRIPT.contains(&format!("\"{named}\"")),
                "the endpoint answers `{named}`, which the script never names"
            );
        }
    }
}
