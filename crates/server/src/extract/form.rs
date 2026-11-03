//! A form, read once the guard of its page let the post through.

use actix_web::{FromRequest, HttpRequest, web};
use serde::de::DeserializeOwned;

/// Reads the form of a post its guard let through: a handler that takes
/// `web::Form` reads it before its first line. The limit is the plane's; a
/// form too large or malformed reads as none.
pub(crate) async fn read_posted_form<T: DeserializeOwned + 'static>(
    http: &HttpRequest,
    payload: web::Payload,
) -> Option<T> {
    let mut payload = payload.into_inner();
    web::Form::<T>::from_request(http, &mut payload)
        .await
        .ok()
        .map(web::Form::into_inner)
}
