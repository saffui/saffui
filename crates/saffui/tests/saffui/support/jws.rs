//! A signed token in its compact form, taken apart and put together by hand.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use super::read_json;

pub fn decode_part(part: &str) -> Value {
    read_json(&String::from_utf8(URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("text"))
}

pub fn write_input(header: &Value, claims: &Value) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}
