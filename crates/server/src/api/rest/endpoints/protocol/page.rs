use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder, web};
use config::serving::PublicOrigin;
use store::error::StoreError;
use store::tenancy::RealmNamed;

use crate::api::rest::endpoints::protocol::dto::uncached;
use crate::api::rest::endpoints::protocol::{brands, i18n};

const CHECK_SESSION: &str = include_str!("ui/check-session.html");
const CHECK_SESSION_SCRIPT: &str = include_str!("ui/check-session.js");
const SCRIPT: &str = include_str!("ui/login.js");
const STYLE: &str = include_str!("ui/login.css");

/// What the browser may do on this page: load this server's script and style,
/// show the images the page draws itself (the enrolment QR code is a `data:`
/// image), call this server back or post the form to it, and nothing else. No
/// inline code, no frames, no submission to anywhere but here.
const POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                      img-src 'self' data:; connect-src 'self'; form-action 'self'; \
                      frame-ancestors 'none'; base-uri 'none'";

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

/// What a page door shows when no connection to the database was had.
pub fn notice_unavailable() -> HttpResponse {
    notice(
        StatusCode::SERVICE_UNAVAILABLE,
        "Try again in a moment",
        "<p>The server cannot answer for the moment. Wait a little, then try again.</p>",
    )
}

/// The same for a door either a browser or a client may reach: a page to the
/// one, the OAuth refusal to the other.
pub fn answer_unavailable_to(request: &actix_web::HttpRequest) -> HttpResponse {
    if wants_page(request) {
        return notice_unavailable();
    }
    super::dto::answer_unavailable()
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

/// Which page is being looked at, and with whose words.
#[derive(serde::Deserialize)]
pub struct Looking {
    /// A draft the console kept a moment ago. Absent shows what is saved.
    pub draft: Option<String>,
}

/// The pages a realm can be shown before anybody uses them.
const LOOKABLE: [&str; 4] = ["login", "device", "requests", "reset"];

/// Strip a rendered page of everything that could send anything anywhere.
///
/// This is the whole security of the preview. The draft behind it is written
/// by an administrator, but the page is opened by a browser carrying nothing,
/// so the link is as good as public for as long as it lives. A sign-in page
/// that cannot submit cannot collect a password, and a leaked preview is then
/// a picture rather than a door.
///
/// The form is unmade rather than pointed somewhere harmless. A form left
/// standing and merely turned to `get` would serialise whatever was typed into
/// the address bar, which puts a password in a URL, a history and a log: worse
/// than what it was meant to prevent. Without a form there is nothing to
/// serialise and nowhere for it to go. The fields still draw, so the page
/// still looks like itself, and the script that would have worked them is
/// commented out on the way past.
fn made_inert(body: &str, banner: &str) -> String {
    body.replace("<form", "<div data-was-a-form")
        .replace("</form>", "</div>")
        .replace("<script", "<!-- script")
        .replace("</script>", "-->")
        .replacen(
            "<main>",
            &format!("<main><p id=\"preview-banner\">{}</p>", escaped(banner)),
            1,
        )
}

/// A hosted page as it would look, with wording that may not be saved yet.
///
/// Its own route rather than a flag on the real pages: nothing here can change
/// how a sign-in behaves, because none of it sits on that path.
pub async fn looked_at(
    request: actix_web::HttpRequest,
    path: web::Path<(String, String)>,
    tenancy: web::Data<store::tenancy::Tenancy>,
    asked: web::Query<Looking>,
) -> HttpResponse {
    let (realm, which) = path.into_inner();
    if !LOOKABLE.contains(&which.as_str()) {
        return told_nothing(StatusCode::NOT_FOUND);
    }
    let tongues = tongues_of_realm(&tenancy, &realm).await;
    let tongue = tongues.negotiated(
        None,
        request
            .headers()
            .get("accept-language")
            .and_then(|held| held.to_str().ok()),
    );
    let (doors, idps, saved, policy) = doors_of_realm(&tenancy, &realm).await;

    // The draft when one is named and still lives, and what is saved otherwise.
    // A draft that has expired shows the saved wording rather than an error: the
    // page is the answer to "what does this look like", and it still is.
    let drafted = match asked.into_inner().draft {
        Some(held) if !held.is_empty() => draft_of_realm(&tenancy, &realm, &held).await,
        _ => None,
    };
    let spoken = drafted.as_ref().or(saved.as_ref());

    let body = match (which.as_str(), spoken) {
        ("login", Some(words)) => i18n::page_over(tongue, words),
        ("login", None) => i18n::page_in(tongue).to_owned(),
        ("device", Some(words)) => i18n::device_page_over(tongue, words),
        ("device", None) => i18n::device_page_in(tongue).to_owned(),
        ("requests", Some(words)) => i18n::requests_page_over(tongue, words),
        ("requests", None) => i18n::requests_page_in(tongue).to_owned(),
        (_, Some(words)) => i18n::reset_page_over(tongue, words),
        (_, None) => i18n::reset_page_in(tongue).to_owned(),
    };

    // The same tokens the real pages carry, filled with nothing: the page is
    // read and never answered, so there is nothing for them to name.
    let body = body
        .replace("{doors}", &escaped(&doors))
        .replace("{idps}", &idps)
        .replace(
            "{policy}",
            &policy
                .as_ref()
                .map(|held| i18n::policy_checklist(tongue, held))
                .unwrap_or_default(),
        )
        .replace("{token}", "")
        .replace("{action}", "#")
        .replace("{user}", "")
        .replace("{address}", "")
        .replace("{name}", "");

    let banner = spoken
        .and_then(|words| words.get(tongue))
        .and_then(|words| words.get("preview-banner"))
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| built_banner(tongue), str::to_owned);

    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header(("Content-Security-Policy", POLICY))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .insert_header(("X-Robots-Tag", "noindex, nofollow"))
        .body(made_inert(&body, &banner))
}

fn built_banner(tongue: &str) -> String {
    if tongue == "fr" {
        "Aperçu. Rien sur cette page ne peut être envoyé.".to_owned()
    } else {
        "Preview. Nothing on this page can be submitted.".to_owned()
    }
}

/// What a kept draft holds, where it is still worth reading.
async fn draft_of_realm(
    tenancy: &store::tenancy::Tenancy,
    realm: &str,
    draft: &str,
) -> Option<serde_json::Value> {
    let transaction = tenancy.begin_in(RealmNamed::ByName(realm)).await.ok()?;
    services::realm::page_previews::read_page_preview(&transaction, draft)
        .await
        .ok()
        .flatten()
}

fn told_nothing(status: StatusCode) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(status)).finish()
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
    /// What the form carries to show it was served here for this login. None
    /// where no login is open, which is a page whose form is refused anyway.
    page_token: Option<String>,
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
    tenancy: &store::tenancy::Tenancy,
    realm: &str,
) -> (
    String,
    String,
    Option<serde_json::Value>,
    Option<models::entities::realm::PasswordPolicy>,
) {
    let nothing = || (String::new(), String::new(), None, None);
    let Ok(context) = tenancy.resolve(RealmNamed::ByName(realm)).await else {
        return nothing();
    };
    let Ok(transaction) = tenancy.begin(&context).await else {
        return nothing();
    };
    let Ok(Some(held)) = services::realm::named(&transaction, &context.realm_id).await else {
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
    if services::oidc::sign_in::offers_recovery_codes(&transaction, held.browser_flow.as_deref())
        .await
    {
        doors.push("recovery-code");
    }
    let idps = match services::federation::brokering::read_providers(&transaction).await {
        Ok(rows) => federated_doors(&rows),
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
/// be sent to; what earns a door here is an `authorization_endpoint`, or SAML
/// named as the protocol, since a SAML provider is reached through the metadata
/// it was set up with rather than through an endpoint in the bag.
fn federated_doors(rows: &[models::entities::authz::IdentityProviderModel]) -> String {
    let mut doors = String::new();
    for held in rows {
        if held.enabled == Some(false) {
            continue;
        }
        let browsable = services::federation::saml_brokering::is_saml(held)
            || held
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
            r#"<a class="idp-door" href="broker/{}/login">{mark}<span>{}</span></a>"#,
            escaped(&held.provider_id),
            escaped(shown),
        ));
    }
    doors
}

/// Read the login this browser holds, for the page shown for it.
///
/// Only a live one, and this is the last moment the server knows which
/// application it came from: an expired row is swept, and the refusal that
/// follows can no longer name one. So the way back is written into the page
/// now, and the script shows it if the login dies behind the page.
async fn read_live_login(
    request: &actix_web::HttpRequest,
    tenancy: &store::tenancy::Tenancy,
    sealing: &crate::api::config::Sealing,
    realm: &str,
) -> LiveLogin {
    let Some(binding) = super::binding::read(request, super::binding::AUTH_SESSION) else {
        return LiveLogin::default();
    };
    let Ok(context) = tenancy.resolve(RealmNamed::ByName(realm)).await else {
        return LiveLogin::default();
    };
    let Ok(transaction) = tenancy.begin(&context).await else {
        return LiveLogin::default();
    };
    let Ok(Some(login)) = services::oidc::sign_in::read_open_login(&transaction, &binding).await
    else {
        return LiveLogin::default();
    };
    let ui_locales = login
        .notes
        .get("ui_locales")
        .and_then(|held| held.as_str())
        .map(str::to_owned);
    let way_back = match services::client::read_client(&transaction, &login.client_id).await {
        Ok(Some(client)) => find_way_back(&client),
        _ => None,
    };
    // Minted here rather than on its own trip: this transaction is open and
    // this login already read, and a page served on every sign-in does not
    // need a fourth visit to the database to say where its form came from.
    let page_token = match store::keyring::load(
        &transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    {
        Ok(ring) => super::forgery::mint(&ring, &sealing.envelope, &binding).await,
        Err(_) => None,
    };
    LiveLogin {
        ui_locales,
        way_back,
        page_token,
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
    tenancy: &store::tenancy::Tenancy,
    realm: &str,
) -> i18n::RealmTongues {
    let fallback = || i18n::RealmTongues::of(None, None);
    let Ok(context) = tenancy.resolve(RealmNamed::ByName(realm)).await else {
        return fallback();
    };
    let Ok(transaction) = tenancy.begin(&context).await else {
        return fallback();
    };
    match services::realm::named(&transaction, &context.realm_id).await {
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
                .replace("{back-name}", &escaped(name))
                .replace(
                    "{token}",
                    &escaped(live.page_token.as_deref().unwrap_or_default()),
                ),
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
    tenancy: web::Data<store::tenancy::Tenancy>,
) -> HttpResponse {
    let mut dressed: Option<String> = None;
    if let Ok(transaction) = tenancy.begin_in(RealmNamed::ByName(&realm)).await {
        let context = transaction.context().clone();
        let mut sheet = STYLE.to_owned();
        if let Some(overrides) =
            services::realm::theme::read_realm_css(&transaction, &context.realm_id).await
        {
            sheet.push('\n');
            sheet.push_str(&overrides);
            dressed = Some(sheet.clone());
        }
        if let Some(binding) = super::binding::read(&request, super::binding::AUTH_SESSION)
            && let Ok(Some(login)) =
                services::oidc::sign_in::read_open_login(&transaction, &binding).await
            && let Some(slug) = login
                .notes
                .get("organization")
                .and_then(|held| held.as_str())
            && let Some(overrides) =
                services::realm::theme::read_organization_css(&transaction, slug).await
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

/// The realm's look for its account console, which carries the defaults in its
/// own sheet and wears only what the realm overrides. Empty for a realm left
/// undressed, for a name that is no realm, and when the store cannot say: the
/// console keeps its own look, and the answer does not tell the three apart.
/// The realm's mark, as the bytes that were weighed on the way in.
///
/// Served under the type recorded beside them rather than one guessed here, and
/// with sniffing turned off, so a browser draws what the door accepted and
/// never something it decided the bytes looked more like.
pub async fn serve_realm_logo(
    realm: web::Path<String>,
    tenancy: web::Data<store::tenancy::Tenancy>,
) -> HttpResponse {
    let context = match tenancy.resolve(RealmNamed::ByName(&realm)).await {
        Ok(context) => context,
        Err(StoreError::Unavailable) => return told_nothing(StatusCode::SERVICE_UNAVAILABLE),
        Err(_) => return told_nothing(StatusCode::NOT_FOUND),
    };
    let transaction = match tenancy.begin(&context).await {
        Ok(transaction) => transaction,
        Err(StoreError::Unavailable) => return told_nothing(StatusCode::SERVICE_UNAVAILABLE),
        Err(_) => return told_nothing(StatusCode::NOT_FOUND),
    };
    let Ok(Some((bytes, kind))) =
        services::realm::theme::read_realm_logo(&transaction, &context.realm_id).await
    else {
        // A realm keeping none is a mark that is not there, and the page falls
        // back to the letters it drew before any of this existed.
        return told_nothing(StatusCode::NOT_FOUND);
    };
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .insert_header(("Content-Type", kind))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("Content-Security-Policy", "default-src 'none'; sandbox"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(bytes)
}

pub async fn serve_realm_theme(
    realm: web::Path<String>,
    tenancy: web::Data<store::tenancy::Tenancy>,
) -> HttpResponse {
    let mut overrides = String::new();
    if let Ok(transaction) = tenancy.begin_in(RealmNamed::ByName(&realm)).await
        && let Some(held) =
            services::realm::theme::read_realm_css(&transaction, &transaction.context().realm_id)
                .await
    {
        overrides = held;
    }
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .insert_header(("Content-Type", "text/css; charset=utf-8"))
        .insert_header(("Content-Security-Policy", POLICY))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(overrides)
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
    tenancy: web::Data<store::tenancy::Tenancy>,
    sealing: web::Data<crate::api::config::Sealing>,
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
        let live = read_live_login(&request, &tenancy, &sealing, &realm).await;
        let tongues = tongues_of_realm(&tenancy, &realm).await;
        let (doors, idps, overrides, policy) = doors_of_realm(&tenancy, &realm).await;
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
    // This page posts to the same door the sign-in form posts to, so it carries
    // what that door asks of a form. The login is the one this browser already
    // holds: a link is followed in the browser that started the sign-in.
    let minted = read_live_login(&request, &tenancy, &sealing, &realm)
        .await
        .page_token
        .unwrap_or_default();
    let body = LINK_PAGE
        .replace(
            "{action}",
            &escaped(&format!("/realms/{realm}/protocol/openid-connect/login")),
        )
        .replace("{field}", &escaped(named))
        .replace("{token}", &escaped(&token))
        .replace("{page-token}", &escaped(&minted));
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
<input type="hidden" name="page_token" value="{page-token}">
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
    tenancy: web::Data<store::tenancy::Tenancy>,
    asked: web::Query<Resetting>,
) -> HttpResponse {
    let asked = asked.into_inner();
    let (Some(token), Some(user)) = (
        asked.token.filter(|held| !held.is_empty()),
        asked.user.filter(|held| !held.is_empty()),
    ) else {
        let tongues = tongues_of_realm(&tenancy, &realm).await;
        let (doors, idps, overrides, policy) = doors_of_realm(&tenancy, &realm).await;
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
    reset_form(&request, &tenancy, &realm, &token, &user, None).await
}

/// The page a reset link opens, with one of its lines shown where something
/// has to be said.
///
/// Served rather than redirected to, because the only two things worth saying
/// come out of a form the caller filled: the token it carries has not been
/// weighed at the point the password is refused, so putting it back into an
/// address would be writing a caller's text into a URL. Written into the page
/// it is escaped, which is what the page already does with it.
pub async fn reset_form(
    request: &actix_web::HttpRequest,
    tenancy: &store::tenancy::Tenancy,
    realm: &str,
    token: &str,
    user: &str,
    shown: Option<&str>,
) -> HttpResponse {
    let tongues = tongues_of_realm(tenancy, realm).await;
    let tongue = tongues.negotiated(
        None,
        request
            .headers()
            .get("accept-language")
            .and_then(|held| held.to_str().ok()),
    );
    let (.., overrides, _) = doors_of_realm(tenancy, realm).await;
    let mut body = match overrides.as_ref() {
        Some(spoken) => i18n::reset_page_over(tongue, spoken),
        None => i18n::reset_page_in(tongue).to_owned(),
    }
    .replace(
        "{action}",
        &escaped(&format!(
            "/realms/{realm}/protocol/openid-connect/reset-password"
        )),
    )
    .replace("{token}", &escaped(token))
    .replace("{user}", &escaped(user));
    // The line shown by taking its hiding class off. The page hides these by
    // class and reveals by fragment, and a fragment is the one thing a server
    // cannot set on a response it is writing.
    if let Some(said) = shown {
        body = body.replacen(
            &format!("id=\"{said}\" class=\"flash\""),
            &format!("id=\"{said}\""),
            1,
        );
    }
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header(("Content-Security-Policy", POLICY))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(body)
}

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
    /// no authorization endpoint and earns none, a SAML provider earns one
    /// through its protocol, a disabled provider shows nothing, a recognised
    /// name carries its mark, an unknown one its initial, and every written
    /// value lands escaped.
    #[test]
    fn only_browsable_providers_earn_a_door_and_each_wears_its_mark() {
        let saml = |alias: &str, display: &str, enabled: bool| {
            let mut row = provider(alias, display, enabled, false);
            row.configs.get_or_insert_with(Default::default).insert(
                "protocol".into(),
                models::entities::attributes::AttributeValue::Str("saml".into()),
            );
            row
        };
        let rows = vec![
            provider("google", "Google", true, true),
            provider("the-ear", "", true, false),
            provider("okta", "Okta", false, true),
            provider("wiki<d>", "Wiki & Co", true, true),
            saml("corp", "Corp SSO", true),
            saml("partner", "Partner SSO", false),
        ];
        let doors = federated_doors(&rows);

        assert!(doors.contains(r#"href="broker/google/login""#), "{doors}");
        assert!(doors.contains("#4285F4"), "the recognised mark is missing");
        assert!(!doors.contains("the-ear"), "a connector earned a door");
        assert!(!doors.contains("okta"), "a disabled provider earned a door");
        assert!(
            doors.contains(r#"href="broker/corp/login""#) && doors.contains("Corp SSO"),
            "a SAML provider earned no door: {doors}"
        );
        assert!(
            !doors.contains("partner"),
            "a disabled SAML provider earned a door"
        );
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
            declared.len() >= services::realm::theme::TOKENS.len(),
            "the sheet no longer declares the contract: {declared:?}"
        );
        for name in &declared {
            assert!(
                services::realm::theme::TOKENS.contains(&name.as_str()),
                "the sheet declares `--{name}`, which the theme door does not admit: \
                 a realm can never override it. Derive it from the fifteen, or widen \
                 the contract in services::realm::theme deliberately."
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
            "throttled",
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
