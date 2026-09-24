use store::providers::authz_routes::AuthzRoute;

/// Which route answers for this request, or none.
///
/// The realm's routes are asked in their own order and the first match
/// answers, so what an operator reads from the top is what runs. Nothing
/// matching is not an omission to paper over: a path whose meaning the realm
/// has not stated is a path nothing may be permitted on.
pub fn matched<'a>(routes: &'a [AuthzRoute], method: &str, path: &str) -> Option<&'a AuthzRoute> {
    // The query part is not the resource. Two callers asking about one path
    // with different queries ask about one thing, and a pattern written
    // against a query is a pattern the next caller sidesteps by reordering
    // it.
    let path = path.split(['?', '#']).next().unwrap_or(path);
    routes
        .iter()
        .filter(|route| route.enabled)
        .find(|route| admits(&route.method, method) && admits(&route.path, path))
}

/// One held pattern against one asked name: exact, or a prefix ending in
/// `*`. The same grammar the capability grants and the webhook filters use,
/// because a second grammar is a second set of edge cases.
fn admits(held: &str, asked: &str) -> bool {
    match held.strip_suffix('*') {
        None => held == asked,
        Some(prefix) => asked.starts_with(prefix),
    }
}

/// Whether a pattern is one the matcher can read, for the door that writes
/// routes to refuse what would silently match nothing or everything by
/// accident. A bare `*` is deliberate and allowed; a `*` in the middle is
/// not, since the grammar has no such thing and would match literally.
pub fn pattern_reads(pattern: &str) -> bool {
    !pattern.is_empty()
        && !pattern.contains(char::is_whitespace)
        && pattern.find('*').is_none_or(|at| at + 1 == pattern.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(id: &str, method: &str, path: &str, priority: i32) -> AuthzRoute {
        AuthzRoute {
            route_id: id.into(),
            method: method.into(),
            path: path.into(),
            server_id: "billing".into(),
            resource: format!("{id}-resource"),
            scope: "read".into(),
            action: "invoke".into(),
            priority,
            enabled: true,
        }
    }

    /// The order is the operator's, and the first match answers: two routes
    /// covering one path is not a puzzle to solve, it is a list to read.
    #[test]
    fn the_first_route_that_covers_the_request_answers_it() {
        let routes = [
            route("admin", "*", "/api/admin/*", 10),
            route("reads", "GET", "/api/*", 20),
            route("everything", "*", "*", 90),
        ];

        assert_eq!(
            matched(&routes, "DELETE", "/api/admin/users/7").map(|held| held.route_id.as_str()),
            Some("admin")
        );
        assert_eq!(
            matched(&routes, "GET", "/api/invoices").map(|held| held.route_id.as_str()),
            Some("reads")
        );
        assert_eq!(
            matched(&routes, "POST", "/api/invoices").map(|held| held.route_id.as_str()),
            Some("everything"),
            "the verb narrows a route, so a write falls through the read-only one"
        );
        assert_eq!(
            matched(&routes, "GET", "/api/admin/users").map(|held| held.route_id.as_str()),
            Some("admin"),
            "the earlier route wins where two cover one path"
        );
    }

    #[test]
    fn a_path_nothing_covers_is_answered_by_nothing() {
        let routes = [route("reads", "GET", "/api/*", 10)];
        assert!(matched(&routes, "GET", "/health").is_none());
        assert!(
            matched(&routes, "GET", "/ap").is_none(),
            "a prefix of the prefix is not under it"
        );

        let mut asleep = route("reads", "GET", "/api/*", 10);
        asleep.enabled = false;
        assert!(
            matched(&[asleep], "GET", "/api/invoices").is_none(),
            "a disabled route covers nothing"
        );
    }

    /// The query is the caller's to write, so it cannot be what a route is
    /// chosen by: otherwise `/api/admin/x?a=b` and `/api/admin/x` are two
    /// paths, and one of them dodges the route the other faces.
    #[test]
    fn what_follows_a_question_mark_does_not_choose_the_route() {
        let routes = [
            route("admin", "*", "/api/admin/*", 10),
            route("everything", "*", "*", 90),
        ];
        for asked in [
            "/api/admin/users?shadow=/api/public",
            "/api/admin/users#fragment",
        ] {
            assert_eq!(
                matched(&routes, "GET", asked).map(|held| held.route_id.as_str()),
                Some("admin"),
                "{asked}"
            );
        }
    }

    #[test]
    fn a_pattern_the_matcher_cannot_read_is_refused_at_the_door() {
        for good in ["*", "/api/*", "/exact/path", "GET"] {
            assert!(pattern_reads(good), "{good}");
        }
        for bad in ["", "/api/*/deep", "* ", "/a b"] {
            assert!(!pattern_reads(bad), "{bad}");
        }
    }
}
