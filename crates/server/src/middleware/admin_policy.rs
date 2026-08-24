use models::entities::authz::AdminAction;
use services::token::Verified;

/// The client that obtained the token, which is not who the token is for.
fn authorized_party(verified: &Verified) -> Option<&str> {
    verified.claims.get("azp").and_then(|party| party.as_str())
}

fn carries_scope(verified: &Verified, wanted: &str) -> bool {
    verified.scope.split_whitespace().any(|held| held == wanted)
}

/// Why a request was refused.
///
/// Each is a distinct answer, and which one a caller is told is not decided
/// here: this says what happened, and the layer that answers decides how much
/// of it to say.
///
/// `WrongParty` is the one worth spelling out. Who a token is for and who asked
/// for it are two questions, and only the second stops an application that can
/// also obtain a token for this audience from presenting it and spending an
/// admin's authority on its own errands. A token naming no party is refused
/// rather than trusted.
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
    /// Obtained by a client that is not part of this plane.
    WrongParty,
}

/// What the admin plane requires of every token, whatever the route.
///
/// Neither list has a default and an empty one admits nobody, which is the
/// right answer for a deployment that has not said: a plane open until somebody
/// configures it shut is open on first boot, the one moment nobody is looking.
#[derive(Debug, Clone)]
pub struct AdminPolicy {
    /// The audiences a token may name. Empty refuses everything.
    pub audiences: Vec<String>,
    /// The clients that may ask for a token this plane accepts. Empty refuses
    /// everything, for the same reason the audiences do.
    pub parties: Vec<String>,
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
    verified: &Verified,
    held: &[AdminAction],
    policy: &AdminPolicy,
) -> Result<AdminAction, Refusal> {
    if !verified
        .audiences
        .iter()
        .any(|audience| policy.audiences.iter().any(|allowed| allowed == audience))
    {
        return Err(Refusal::WrongAudience);
    }

    match authorized_party(verified) {
        Some(party) if policy.parties.iter().any(|allowed| allowed == party) => {}
        _ => return Err(Refusal::WrongParty),
    }

    if !carries_scope(verified, &policy.scope) {
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
            parties: vec!["saffui-console".into()],
            scope: "admin".into(),
        }
    }

    /// A token that checked out, carrying what this plane reads of it.
    fn presented() -> Verified {
        let mut claims = serde_json::Map::new();
        claims.insert("azp".into(), serde_json::json!("saffui-console"));
        Verified {
            subject: "ada".into(),
            audiences: vec!["saffui-admin".into()],
            scope: "openid admin".into(),
            token_id: None,
            claims,
        }
    }

    /// The same, with one claim replaced. Named so a test says which one thing
    /// it arranged wrong.
    fn claiming(key: &str, value: serde_json::Value) -> Verified {
        let mut verified = presented();
        verified.claims.insert(key.into(), value);
        verified
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
            parties: vec!["saffui-console".into()],
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
        let elsewhere = Verified {
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
            let carrying = Verified {
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

        let elsewhere = Verified {
            audiences: vec!["some-app".into()],
            ..presented()
        };
        assert_eq!(
            decide(None, &elsewhere, &[], &policy()),
            Err(Refusal::WrongAudience),
            "an unaccepted token learned that the route was undeclared"
        );
    }

    /// Who the token is for and who obtained it are two questions. An admin
    /// holds a token their own tooling asked for; another application able to
    /// obtain one for the same audience would otherwise spend that authority.
    #[test]
    fn a_token_another_application_asked_for_is_refused() {
        let elsewhere = claiming("azp", serde_json::json!("some-app"));
        assert_eq!(
            decide(
                Some(AdminAction::RealmRead),
                &elsewhere,
                &[AdminAction::RealmRead],
                &policy(),
            ),
            Err(Refusal::WrongParty)
        );

        let mut anonymous = presented();
        anonymous.claims.remove("azp");
        assert_eq!(
            decide(
                Some(AdminAction::RealmRead),
                &anonymous,
                &[AdminAction::RealmRead],
                &policy(),
            ),
            Err(Refusal::WrongParty),
            "a token naming no party was trusted"
        );

        let unconfigured = AdminPolicy {
            parties: Vec::new(),
            ..policy()
        };
        assert_eq!(
            decide(
                Some(AdminAction::RealmRead),
                &presented(),
                &[AdminAction::RealmRead],
                &unconfigured,
            ),
            Err(Refusal::WrongParty),
            "a plane that named no console admitted one"
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
