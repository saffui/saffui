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

use actix_web::Route;
use actix_web::http::Method;
use actix_web::web;
use models::entities::authz::AdminAction;

use crate::api::rest::endpoints::admin::realms;

/// One route: the verb, the path, what it costs, and what answers it.
///
/// The four together, once. Written apart, the mount and the table of costs are
/// two lists that agree until one of them is edited, and the one that gets
/// edited is the mount: a handler arrives, nothing charges it, and the guard
/// refuses a route that looks like it should work.
#[derive(Clone)]
pub struct AdminRoute {
    pub method: Method,
    /// The registered pattern, not the request path: `/admin/realms/{realm}`
    /// rather than `/admin/realms/main`, so the lookup is an equality.
    pub pattern: &'static str,
    pub action: AdminAction,
    /// What actix mounts, once something answers it. A builder rather than a
    /// value, since registering consumes a route and this table is read twice.
    ///
    /// `None` declares what the plane will carry before it carries it: the cost
    /// is settled here first, so a handler arriving later cannot arrive without
    /// one, and until then the route is simply not there.
    pub handler: Option<fn() -> Route>,
}

impl std::fmt::Debug for AdminRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} ({:?})", self.method, self.pattern, self.action)
    }
}

/// Every admin route.
pub fn routes() -> Vec<AdminRoute> {
    vec![
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms",
            action: AdminAction::RealmList,
            handler: Some(|| web::get().to(realms::list)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms",
            action: AdminAction::RealmCreate,
            handler: None,
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}",
            action: AdminAction::RealmRead,
            handler: Some(|| web::get().to(realms::get)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}",
            action: AdminAction::RealmWrite,
            handler: None,
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
