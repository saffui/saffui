/// Whether an address is https, or plain http to `localhost`, `127.0.0.1` or
/// `[::1]` spelled exactly; any other spelling of loopback is refused.
pub fn is_https_or_loopback(address: &str) -> bool {
    if address
        .strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty())
    {
        return true;
    }
    let Some(rest) = address.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // Whatever stands before an `@` is credentials, and the host is after it.
    if authority.contains('@') {
        return false;
    }
    let host = match authority.strip_prefix('[') {
        Some(bracketed) => bracketed
            .split_once(']')
            .filter(|(_, after)| after.is_empty() || after.starts_with(':'))
            .map(|(inner, _)| inner),
        None => authority.split(':').next(),
    };
    matches!(host, Some("localhost" | "127.0.0.1" | "::1"))
}

#[cfg(test)]
mod tests {
    use super::is_https_or_loopback;

    /// Plain http is a developer's machine or nothing, and a host is read the
    /// way a browser reads it, credentials and all.
    #[test]
    fn plain_http_is_accepted_only_on_loopback() {
        for accepted in [
            "https://app.example",
            "https://app.example/home?from=login#top",
            "http://localhost:8080/console/",
            "http://localhost",
            "http://127.0.0.1:3000",
            "http://[::1]:8080/",
        ] {
            assert!(is_https_or_loopback(accepted), "{accepted} was refused");
        }
        for refused in [
            "javascript:alert(1)",
            "JAVASCRIPT:alert(1)",
            " https://app.example",
            "data:text/html,<script>alert(1)</script>",
            "https://",
            "",
            "//app.example",
            "http://app.example",
            "http://localhost.evil.example/",
            "http://localhost@evil.example/",
            "http://localhost:8080@evil.example/",
            "http://127.0.0.1.evil.example/",
            "http://[::1].evil.example/",
        ] {
            assert!(!is_https_or_loopback(refused), "{refused} was accepted");
        }
    }
}
