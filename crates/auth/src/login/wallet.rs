use std::future::Future;
use std::pin::Pin;

use serde_json::{Value, json};
use store::tenancy::UnitOfWork;

use crate::login::authenticator::{Authenticator, Challenge};
use crate::login::enrolment::LINK_WALLET_IDENTITY;

/// What a login asks a wallet's presentation for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// To link the identity it proves to the account signing in.
    Link,
    /// To prove an identity the account already linked.
    Factor,
}

impl Purpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Factor => "factor",
        }
    }
}

/// A presentation asked for: the request, and the link a wallet opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    pub request_id: String,
    pub uri: String,
}

/// Why nothing was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unasked {
    /// The realm keeps no profile to ask a wallet by.
    NotOffered,
    /// It does, and asking failed.
    Unavailable,
}

/// Where a presentation a login asked for stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presented {
    /// Open, and nobody answered yet.
    Waiting,
    /// Answered with a credential that verified, naming the identity it
    /// proves by its issuer and the digest the realm keeps identities under.
    Identified { issuer: String, digest: String },
    /// Run out unanswered, or gone.
    Lapsed,
    /// Answered, and it proved nothing: refused in the wallet, or a
    /// credential that did not verify.
    Unproven,
}

/// The verifier a login asks a wallet through, seen from the login.
///
/// A port, like the directory: the login asks these two questions, and the
/// request, its signature and its verification live with whoever hands the
/// implementation in. Both run inside the login's own transaction.
pub trait Wallet: Send + Sync {
    /// Ask for the realm's credential, for this login and the person it names.
    fn ask<'a>(
        &'a self,
        transaction: &'a UnitOfWork,
        purpose: Purpose,
        login_session: &'a str,
        user_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Asked, Unasked>> + Send + 'a>>;

    /// Where a presentation stands, read for the login that asked for it: a
    /// request another login asked for reads as lapsed.
    fn standing<'a>(
        &'a self,
        transaction: &'a UnitOfWork,
        request_id: &'a str,
        login_session: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Presented, ()>> + Send + 'a>>;
}

/// The verifier, and the login every presentation it asks for is bound to.
#[derive(Clone, Copy)]
pub struct Asking<'a> {
    pub verifier: &'a dyn Wallet,
    pub login_session: &'a str,
}

/// What an asked presentation shows and keeps. Shown: the link a wallet
/// opens, and the same link drawn for a wallet on another device to scan.
/// Kept: the request and its link, never the drawing, since a login's notes
/// are bounded and a QR code is kilobytes where its link is a line.
pub fn draw_challenge(asked: &Asked) -> Challenge {
    Challenge {
        shown: json!({
            "wallet": { "uri": asked.uri, "qr": commons::qr::draw_qr_svg(&asked.uri) },
        }),
        remembered: json!({ "request": asked.request_id, "uri": asked.uri }),
    }
}

/// The request a round kept under the step's or the ceremony's name.
pub fn read_kept_request(kept: &Value) -> Option<Asked> {
    Some(Asked {
        request_id: kept.get("request")?.as_str()?.to_owned(),
        uri: kept.get("uri")?.as_str()?.to_owned(),
    })
}

/// The presentation a login waits on, read off its notes. The ceremony's
/// first: it runs only once the flow has passed, so a request it kept is
/// newer than any the step left behind.
pub fn find_waiting_request(notes: &Value) -> Option<Asked> {
    [LINK_WALLET_IDENTITY, Authenticator::Wallet.as_str()]
        .iter()
        .find_map(|named| notes.get(*named).and_then(read_kept_request))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The drawing is shown and never kept, and what is kept reads back as the
    /// request it was: under the ceremony's name before the step's.
    #[test]
    fn a_request_is_kept_by_its_link_and_shown_drawn() {
        let asked = Asked {
            request_id: "r-1".to_owned(),
            uri: "openid4vp://authorize?client_id=x&request_uri=y".to_owned(),
        };
        let challenge = draw_challenge(&asked);
        assert_eq!(
            challenge.remembered,
            json!({ "request": "r-1", "uri": asked.uri })
        );
        assert_eq!(challenge.shown["wallet"]["uri"], json!(asked.uri));
        assert!(
            challenge.shown["wallet"]["qr"]
                .as_str()
                .is_some_and(|drawn| drawn.contains("<svg")),
            "{}",
            challenge.shown
        );
        assert_eq!(
            read_kept_request(&challenge.remembered),
            Some(asked.clone())
        );

        let older = json!({ "request": "r-0", "uri": "openid4vp://older" });
        let notes = json!({
            "wallet": older,
            LINK_WALLET_IDENTITY: challenge.remembered,
            "remember_me": true,
        });
        assert_eq!(find_waiting_request(&notes), Some(asked));
        assert_eq!(
            find_waiting_request(&json!({ "wallet": older })).map(|held| held.request_id),
            Some("r-0".to_owned())
        );
        assert_eq!(
            find_waiting_request(&json!({ "totp-register": older })),
            None
        );
        assert_eq!(
            find_waiting_request(&json!({ "wallet": { "request": "r-1" } })),
            None
        );
    }
}
