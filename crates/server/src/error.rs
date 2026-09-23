use commons::error::ErrorCode;
use commons::http::ApiError;
use store::error::StoreError;

use crate::middleware::admin_policy::Refusal;

/// The answer a refused request receives.
///
/// Every refusal renders as the same code. A caller that could tell "you may
/// not" from "this route wants something you do not hold" would have a probe
/// for the shape of the admin plane.
pub fn refused(refusal: Refusal) -> ApiError {
    // The reason is not lost: it is what the decision returned, and the log
    // records it. This is only what travels back.
    tracing::warn!(reason = ?refusal, "admin request refused");
    ApiError::new(ErrorCode::AccessDenied)
}

/// A request that carried no token, or one this deployment cannot read.
///
/// Distinct from a refusal because it is actionable: a caller with no token can
/// go and get one, and telling it so reveals nothing about what it would then
/// be allowed to do.
pub fn unauthenticated() -> ApiError {
    ApiError::new(ErrorCode::Unauthorized)
}

/// A unit of work that could not be opened. No connection to be had is the one
/// failure a caller can wait out, so it is told; the rest is the server's own.
pub fn refuse_unopened_work(why: StoreError) -> ApiError {
    match why {
        StoreError::Unavailable => ApiError::new(ErrorCode::ServiceUnavailable),
        _ => ApiError::new(ErrorCode::InternalError),
    }
}

/// A caller whose realm could not be opened, answered as a missing token is
/// but when no connection was had: nothing about the realm had been asked, and
/// a console told it is signed out would drop a sign-in that still stands.
pub fn refuse_unestablished_caller(why: StoreError) -> ApiError {
    match why {
        StoreError::Unavailable => ApiError::new(ErrorCode::ServiceUnavailable),
        _ => unauthenticated(),
    }
}

/// A store that failed once the caller's realm was found: logged, and answered
/// as the server's fault, never as a token to go and get again.
pub fn report_store_failure(why: impl std::fmt::Display) -> ApiError {
    ApiError::with_detail(ErrorCode::InternalError, why.to_string())
}

/// A token turned away, or a store that could not say whether to: only the
/// first is answered as a missing token.
pub fn refuse_unverified_token(why: services::token::Refused) -> ApiError {
    match why {
        services::token::Refused::Unestablished => report_store_failure(why),
        _ => unauthenticated(),
    }
}

/// The same, for what the realm says of a token that verified.
pub fn refuse_unestablished_context(why: services::context::NotEstablished) -> ApiError {
    match why {
        services::context::NotEstablished::Unreadable
        | services::context::NotEstablished::Unverified(services::token::Refused::Unestablished) => {
            report_store_failure(why)
        }
        _ => unauthenticated(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_missing_connection_is_worth_waiting_out() {
        assert_eq!(
            refuse_unopened_work(StoreError::Unavailable).code(),
            ErrorCode::ServiceUnavailable
        );
        assert_eq!(
            refuse_unopened_work(StoreError::Backend).code(),
            ErrorCode::InternalError
        );
    }

    /// A door that throws its failure away cannot tell a missing connection
    /// from the rest, and answers a wait-and-retry as the server's own fault.
    #[test]
    fn no_door_throws_away_why_it_could_not_open() {
        let mut offenders = Vec::new();
        let mut pending = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
        while let Some(path) = pending.pop() {
            if path.is_dir() {
                pending.extend(
                    std::fs::read_dir(&path)
                        .unwrap()
                        .map(|entry| entry.unwrap().path()),
                );
                continue;
            }
            if path.extension().is_none_or(|kind| kind != "rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for door in [".begin(", ".begin_in(", ".begin_snapshot(", ".resolve("] {
                for (at, _) in source.match_indices(door) {
                    if !source[..at].trim_end().ends_with("tenancy") {
                        continue;
                    }
                    let mut depth = 0;
                    let closed = source[at..]
                        .char_indices()
                        .find(|&(_, held)| {
                            depth += match held {
                                '(' => 1,
                                ')' => -1,
                                _ => 0,
                            };
                            held == ')' && depth == 0
                        })
                        .map(|(offset, _)| at + offset + 1)
                        .unwrap();
                    let after: String = source[closed..]
                        .chars()
                        .filter(|held| !held.is_whitespace())
                        .take(20)
                        .collect();
                    if after.starts_with(".await.map_err(|_|") {
                        let line = source[..at].lines().count();
                        offenders.push(format!("{}:{line}", path.display()));
                    }
                }
            }
        }
        assert!(offenders.is_empty(), "{offenders:#?}");
    }

    /// A realm nobody holds is still answered as a missing token, so the door
    /// cannot be asked which realms exist.
    #[test]
    fn a_caller_is_told_to_wait_only_for_a_missing_connection() {
        assert_eq!(
            refuse_unestablished_caller(StoreError::Unavailable).code(),
            ErrorCode::ServiceUnavailable
        );
        for why in [
            StoreError::Backend,
            StoreError::NotFound {
                asked: "elsewhere".into(),
            },
        ] {
            assert_eq!(
                refuse_unestablished_caller(why).code(),
                ErrorCode::Unauthorized
            );
        }
    }
}
