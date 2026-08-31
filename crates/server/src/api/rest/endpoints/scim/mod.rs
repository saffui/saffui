pub mod discovery;
pub mod groups;
pub mod users;

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder};
use serde_json::Value;
use services::scim::Refusal;

pub const CONTENT_TYPE: &str = "application/scim+json";

pub fn answered(status: StatusCode, body: Value) -> HttpResponse {
    HttpResponseBuilder::new(status)
        .content_type(CONTENT_TYPE)
        .json(body)
}

pub fn refused(refusal: &Refusal) -> HttpResponse {
    answered(
        StatusCode::from_u16(refusal.status).unwrap_or(StatusCode::BAD_REQUEST),
        refusal.body(),
    )
}

pub fn unavailable() -> HttpResponse {
    refused(&Refusal {
        status: 500,
        scim_type: None,
        detail: "the realm could not be read".into(),
    })
}

/// Where this realm's SCIM root answers, for the location and $ref fields.
pub fn base_of(
    request: &HttpRequest,
    origin: &config::serving::PublicOrigin,
    realm: &str,
) -> String {
    let _ = request;
    format!(
        "{}/realms/{realm}/scim/v2",
        origin.as_str().trim_end_matches('/')
    )
}

/// The 1-based window of §3.4.2.4, folded to the store's 0-based one.
pub fn window(query: &str) -> (i64, models::paging::Window) {
    let mut start_index: i64 = 1;
    let mut count: i64 = 100;
    for piece in query.split('&') {
        let mut halves = piece.splitn(2, '=');
        match (halves.next(), halves.next()) {
            (Some("startIndex"), Some(value)) => {
                start_index = value.parse().unwrap_or(1).max(1);
            }
            (Some("count"), Some(value)) => {
                count = value.parse().unwrap_or(100).clamp(0, 200);
            }
            _ => {}
        }
    }
    (
        start_index,
        models::paging::Window {
            first: start_index - 1,
            max: count,
            clamped: false,
        },
    )
}

pub fn filter_of(query: &str) -> Option<String> {
    for piece in query.split('&') {
        if let Some(encoded) = piece.strip_prefix("filter=") {
            let decoded: String = urlencoding_decode(encoded);
            return Some(decoded);
        }
    }
    None
}

fn urlencoding_decode(encoded: &str) -> String {
    let mut out = Vec::with_capacity(encoded.len());
    let bytes = encoded.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
