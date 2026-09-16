//! What proves a posted form came from a page this deployment served.
//!
//! The script posts JSON, and a browser will not send that content type to
//! another origin without asking this server first. A form is the path a
//! browser with no script takes, and a form is also what any other site can
//! post without asking anybody. So a form carries a value the page it came
//! from was rendered with, sealed for the login the browser holds.
//!
//! Sealing rather than signing: a sealed value is bound to its scope, so one
//! minted for another login, or for anything else this realm seals, opens as
//! nothing here. Nothing is stored and nothing expires on its own, because the
//! login it names is what it outlives or does not.

use crypto::envelope::Envelope;
use data_encoding::BASE64URL_NOPAD;
use store::keyring::RealmKeyring;

/// What the value is sealed for, and never what anything else is.
const PURPOSE: &str = "login-form";

/// The value a page carries for this login, or nothing when it cannot be
/// minted. A page rendered without one is a page whose form will be refused,
/// which is what an unreadable keyring should cost.
pub async fn mint(ring: &RealmKeyring, envelope: &Envelope, auth_session: &str) -> Option<String> {
    ring.seal(envelope, PURPOSE, auth_session, auth_session.as_bytes())
        .await
        .ok()
        .map(|sealed| BASE64URL_NOPAD.encode(&sealed))
}

/// Whether this value was minted by this realm for this login.
///
/// Opening it is the whole proof: the scope is authenticated, so a value that
/// opens under this login's name was sealed under it here.
pub(crate) async fn minted_here(
    ring: &RealmKeyring,
    envelope: &Envelope,
    auth_session: &str,
    offered: Option<&str>,
) -> bool {
    let Some(offered) = offered.filter(|held| !held.is_empty()) else {
        return false;
    };
    let Ok(sealed) = BASE64URL_NOPAD.decode(offered.as_bytes()) else {
        return false;
    };
    ring.open(envelope, PURPOSE, auth_session, &sealed)
        .await
        .is_ok()
}

/// Whether the browser says this request was started by another site.
///
/// The header is the browser's own word rather than the caller's: a page on
/// another site cannot write it. Absent it says nothing, which is what an older
/// browser and a caller that is not a browser both look like, so on its own it
/// refuses nothing and the minted value stays the barrier.
pub(crate) fn came_from_another_site(request: &actix_web::HttpRequest) -> bool {
    request
        .headers()
        .get("sec-fetch-site")
        .and_then(|held| held.to_str().ok())
        .is_some_and(|said| said.eq_ignore_ascii_case("cross-site"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header is read for one word and nothing else: same-origin, same-site
    /// and none are a browser saying this was started here, and an absent header
    /// is a browser that does not speak of it.
    #[test]
    fn only_a_cross_site_start_is_refused() {
        for (said, refused) in [
            ("cross-site", true),
            ("CROSS-SITE", true),
            ("same-origin", false),
            ("same-site", false),
            ("none", false),
            ("", false),
        ] {
            let request = actix_web::test::TestRequest::post()
                .insert_header(("sec-fetch-site", said))
                .to_http_request();
            assert_eq!(
                came_from_another_site(&request),
                refused,
                "sec-fetch-site: {said}"
            );
        }
        assert!(
            !came_from_another_site(&actix_web::test::TestRequest::post().to_http_request()),
            "a browser that says nothing was read as saying something"
        );
    }
}
