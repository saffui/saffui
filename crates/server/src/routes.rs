//! Which action each route requires.
//!
//! One table, read by the guard. The alternative is deriving the action from
//! the path, and that produces wrong answers quietly: a branch that splits
//! on path segments puts an organization's branding under the theme family, and
//! one that ignores the method charges a read the price of a write. Both are
//! silent, and the tests that catch them are tests of the derivation rather than
//! of the route.
//!
//! Declaring it beside the path removes the class. A route absent from this
//! table is refused rather than guessed at, so adding a handler and forgetting
//! its action closes the door instead of opening it.
//!
//! The word is `action` and not `capability`. A capability is an unforgeable
//! thing whose holder may act by holding it; here a caller presents an identity
//! and the server looks up what that identity may do, which is the opposite
//! arrangement. The type is already called `AdminAction`, and a third name for
//! one thing is one more thing that can disagree.

use actix_web::http::Method;
use models::entities::authz::AdminAction;

/// One route, and the action it requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRoute {
    pub method: Method,
    /// The registered pattern, not the request path: `/admin/realms/{realm}`
    /// rather than `/admin/realms/main`, so the lookup is an equality and never
    /// a match.
    pub pattern: &'static str,
    pub action: AdminAction,
}

/// Every admin route, with the action it requires.
pub fn routes() -> Vec<AdminRoute> {
    vec![
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms",
            action: AdminAction::RealmList,
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms",
            action: AdminAction::RealmCreate,
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}",
            action: AdminAction::RealmRead,
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}",
            action: AdminAction::RealmWrite,
        },
    ]
}

/// What this route requires, or nothing if it is not declared.
///
/// The method is part of the question. A table that answered by path alone
/// would charge a read what a write costs, or the reverse, which is worse.
pub fn required(method: &Method, pattern: &str) -> Option<AdminAction> {
    routes()
        .into_iter()
        .find(|route| route.method == method && route.pattern == pattern)
        .map(|route| route.action)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One entry per method and path. A duplicate means two answers to one
    /// question, and which one applies would depend on the order of this list.
    #[test]
    fn no_route_is_declared_twice() {
        let mut seen = std::collections::HashSet::new();
        for route in routes() {
            assert!(
                seen.insert((route.method.clone(), route.pattern)),
                "{} {} is declared twice",
                route.method,
                route.pattern
            );
        }
    }

    /// The method is part of the answer, which is the whole reason this is a
    /// table and not a path prefix.
    #[test]
    fn two_methods_on_one_path_cost_differently() {
        assert_eq!(
            required(&Method::GET, "/admin/realms/{realm}"),
            Some(AdminAction::RealmRead)
        );
        assert_eq!(
            required(&Method::PUT, "/admin/realms/{realm}"),
            Some(AdminAction::RealmWrite)
        );
    }

    /// A route nobody declared is refused rather than guessed at.
    #[test]
    fn an_undeclared_route_requires_nothing_and_is_therefore_refused() {
        assert_eq!(required(&Method::DELETE, "/admin/realms/{realm}"), None);
        assert_eq!(required(&Method::GET, "/admin/whatever"), None);
    }

    /// A pattern, never a path. Looking up a concrete path would silently miss.
    #[test]
    fn the_lookup_is_on_the_pattern_and_not_the_path() {
        assert_eq!(required(&Method::GET, "/admin/realms/main"), None);
    }
}
