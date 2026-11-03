//! What every answer of the data plane says to the browser that receives
//! it, whatever handler wrote it. A page adds its own content policy.

use actix_web::middleware::DefaultHeaders;
use saffui_core::app::App as Product;

/// How long a browser remembers to reach this origin over TLS only: a year.
const TRANSPORT_SECURITY: &str = "max-age=31536000";

/// The headers of every answer. An answer is never guessed to be of another
/// type than it says, never framed, and never sends where it came from. An
/// origin served over TLS says so once and is then never asked in clear.
pub(crate) fn protect_answers(product: &Product) -> DefaultHeaders {
    let headers = DefaultHeaders::new()
        .add(("X-Content-Type-Options", "nosniff"))
        .add(("X-Frame-Options", "DENY"))
        .add(("Referrer-Policy", "no-referrer"));
    if product
        .settings
        .public_origin
        .as_str()
        .starts_with("https://")
    {
        headers.add(("Strict-Transport-Security", TRANSPORT_SECURITY))
    } else {
        headers
    }
}
