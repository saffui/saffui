use actix_web::HttpRequest;
use actix_web::http::header::AUTHORIZATION;

/// A presented token is the whole authority: there is no fallback to a
/// cookie, and a scheme other than Bearer presents nothing here.
pub(crate) fn read_bearer_token(request: &HttpRequest) -> Option<String> {
    let header = request.headers().get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = header.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("Bearer")
        .then(|| token.trim().to_owned())
}
