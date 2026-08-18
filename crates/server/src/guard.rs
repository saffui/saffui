//! What the admin plane asks before it lets a request through.
//!
//! Four questions, in order, and each is refused rather than assumed. The
//! decision itself is a pure function: what reaches it is what the transport
//! managed to establish, and what it answers is the only thing that opens the
//! door.

use models::entities::authz::AdminAction;

/// What the caller presented, once the transport has verified it.
///
/// Built only from a token whose signature checked out against the realm's
/// published keys. A caller cannot construct one with different contents,
/// because nothing here parses: the fields arrive already established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presented {
    pub subject: String,
    pub audiences: Vec<String>,
    /// Space separated, as the token carries it.
    pub scope: String,
}

impl Presented {
    fn has_scope(&self, wanted: &str) -> bool {
        self.scope.split_whitespace().any(|scope| scope == wanted)
    }
}

/// Why a request was refused.
///
/// Each is a distinct answer, and which one a caller is told is not decided
/// here: this says what happened, and the layer that answers decides how much
/// of it to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The route declares no action. Refused rather than guessed at, so adding
    /// a handler and forgetting its action closes the door.
    Undeclared,
    /// The token was issued for somebody else's ears.
    WrongAudience,
    /// It does not carry the scope the admin plane requires.
    MissingScope,
    /// A valid token, held by someone this route is not for.
    NotHeld,
}

/// What the admin plane requires of every token, whatever the route.
#[derive(Debug, Clone)]
pub struct AdminPolicy {
    /// The audiences a token may name. Empty refuses everything, which is the
    /// right answer for a deployment that has not said: a plane that admits
    /// any audience until configured is one that is open on first boot.
    pub audiences: Vec<String>,
    pub scope: String,
}

/// Whether this request may proceed.
///
/// The order is the design. Nothing the route requires is consulted
/// until the token is established as one this deployment accepts, so a token
/// from another issuer's realm cannot probe which actions exist by the shape of
/// the refusal it earns.
pub fn decide(
    required: Option<AdminAction>,
    presented: &Presented,
    held: &[AdminAction],
    policy: &AdminPolicy,
) -> Result<AdminAction, Refusal> {
    if !presented
        .audiences
        .iter()
        .any(|audience| policy.audiences.iter().any(|allowed| allowed == audience))
    {
        return Err(Refusal::WrongAudience);
    }

    if !presented.has_scope(&policy.scope) {
        return Err(Refusal::MissingScope);
    }

    let required = required.ok_or(Refusal::Undeclared)?;

    if !held.contains(&required) {
        return Err(Refusal::NotHeld);
    }

    Ok(required)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> AdminPolicy {
        AdminPolicy {
            audiences: vec!["saffui-admin".into()],
            scope: "admin".into(),
        }
    }

    fn presented() -> Presented {
        Presented {
            subject: "ada".into(),
            audiences: vec!["saffui-admin".into()],
            scope: "openid admin".into(),
        }
    }

    #[test]
    fn a_held_action_on_a_declared_route_is_allowed() {
        assert_eq!(
            decide(
                Some(AdminAction::RealmRead),
                &presented(),
                &[AdminAction::RealmRead, AdminAction::UserRead],
                &policy(),
            ),
            Ok(AdminAction::RealmRead)
        );
    }

    /// A deployment that has not said which audiences it accepts admits none.
    /// The opposite default is a plane that is open until somebody configures
    /// it shut.
    #[test]
    fn an_unconfigured_plane_admits_nobody() {
        let empty = AdminPolicy {
            audiences: Vec::new(),
            scope: "admin".into(),
        };
        assert_eq!(
            decide(
                Some(AdminAction::RealmRead),
                &presented(),
                &[AdminAction::RealmRead],
                &empty,
            ),
            Err(Refusal::WrongAudience)
        );
    }

    #[test]
    fn a_token_for_another_audience_is_refused() {
        let elsewhere = Presented {
            audiences: vec!["some-app".into()],
            ..presented()
        };
        assert_eq!(
            decide(
                Some(AdminAction::RealmRead),
                &elsewhere,
                &[AdminAction::RealmRead],
                &policy(),
            ),
            Err(Refusal::WrongAudience)
        );
    }

    /// The scope is matched whole. A token carrying `administrator` does not
    /// carry `admin`, and a substring match would say it does.
    #[test]
    fn the_scope_is_matched_whole() {
        for scope in ["administrator", "adminread", "not-admin", ""] {
            let carrying = Presented {
                scope: scope.into(),
                ..presented()
            };
            assert_eq!(
                decide(
                    Some(AdminAction::RealmRead),
                    &carrying,
                    &[AdminAction::RealmRead],
                    &policy(),
                ),
                Err(Refusal::MissingScope),
                "{scope} was accepted as the admin scope"
            );
        }
    }

    /// A route nobody declared is refused, and refused after the token has been
    /// established rather than before: which actions exist is not
    /// something an unaccepted token gets to learn.
    #[test]
    fn an_undeclared_route_is_refused_but_only_once_the_token_is_accepted() {
        assert_eq!(
            decide(None, &presented(), &[AdminAction::RealmRead], &policy()),
            Err(Refusal::Undeclared)
        );

        let elsewhere = Presented {
            audiences: vec!["some-app".into()],
            ..presented()
        };
        assert_eq!(
            decide(None, &elsewhere, &[], &policy()),
            Err(Refusal::WrongAudience),
            "an unaccepted token learned that the route was undeclared"
        );
    }

    #[test]
    fn an_action_not_held_is_refused() {
        assert_eq!(
            decide(
                Some(AdminAction::RealmWrite),
                &presented(),
                &[AdminAction::RealmRead],
                &policy(),
            ),
            Err(Refusal::NotHeld)
        );
        assert_eq!(
            decide(Some(AdminAction::RealmWrite), &presented(), &[], &policy()),
            Err(Refusal::NotHeld)
        );
    }
}
