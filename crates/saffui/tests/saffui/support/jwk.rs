//! What a published key may hold.

/// Whether a published key holds exactly the members of the public half of
/// its type: none that a private key carries, whatever its name.
pub fn holds_public_members_only(key: &serde_json::Value) -> bool {
    let expected: &[&str] = match key["kty"].as_str() {
        Some("RSA") => &["alg", "e", "kid", "kty", "n", "use"],
        Some("EC") => &["alg", "crv", "kid", "kty", "use", "x", "y"],
        Some("OKP") => &["alg", "crv", "kid", "kty", "use", "x"],
        _ => return false,
    };
    let mut names: Vec<&str> = key
        .as_object()
        .map(|members| members.keys().map(String::as_str).collect())
        .unwrap_or_default();
    names.sort_unstable();
    names == expected
}
