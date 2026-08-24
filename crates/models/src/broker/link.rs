use serde::{Deserialize, Serialize};

/// What the upstream asserted, after the id token has been verified and its
/// claims checked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamIdentity {
    /// The upstream subject. Immutable at the provider, and the only value a
    /// federated link may be keyed on.
    pub external_user_id: String,
    pub external_username: Option<String>,
    pub email: Option<String>,
    /// Whether the upstream says it verified the address. An assertion rather
    /// than a fact: it is only as good as the provider making it.
    pub email_verified: bool,
}

/// Why matching an address was not enough to link automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum LinkRefusal {
    /// The provider is not trusted for addresses, so its assertions about them
    /// are not proof of ownership whatever it claims.
    #[error("the identity provider is not trusted for email addresses")]
    ProviderNotTrusted,
    /// The upstream did not say it verified the address.
    #[error("the identity provider did not verify the address")]
    UpstreamEmailUnverified,
    /// The local account's own address is unverified, so it is not established
    /// that it belongs to whoever holds that address either.
    #[error("the local account's address is itself unverified")]
    LocalEmailUnverified,
}

/// What the callback should do with an upstream identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkDecision {
    /// Already linked. Log this user in.
    AlreadyLinked { user_id: String },
    /// Safe to link: the address is verified on both sides and the provider is
    /// trusted to say so.
    LinkToExisting { user_id: String },
    /// Nothing local claims this identity. Create an account.
    CreateNew,
    /// A local account matches by address, and linking it is not safe. The user
    /// has to prove they hold that account, by logging into it or through a
    /// verification mail, before the link is made.
    RequireExplicitLink {
        user_id: String,
        reason: LinkRefusal,
    },
}

/// A local account an address matched, as far as this decision cares.
#[derive(Debug, Clone)]
pub struct LocalAccount {
    pub user_id: String,
    pub email_verified: bool,
}

/// Decide who an upstream identity is locally.
///
/// `existing_link` is the stored link for this provider and subject.
/// `matching_local` is an account found by address, which a caller looks up only
/// when there is an address to look up.
///
/// The order matters. An existing link is consulted first and wins
/// unconditionally: once a federated identity is bound to a local user, no later
/// assertion about an address may move it, or changing the address upstream
/// would be enough to redirect a login to a different account.
pub fn decide_link(
    existing_link: Option<&str>,
    upstream: &UpstreamIdentity,
    provider_trusts_email: bool,
    matching_local: Option<&LocalAccount>,
) -> LinkDecision {
    if let Some(user_id) = existing_link {
        return LinkDecision::AlreadyLinked {
            user_id: user_id.to_owned(),
        };
    }

    let Some(local) = matching_local else {
        return LinkDecision::CreateNew;
    };

    // All three have to hold. Each on its own is insufficient, and the order
    // below is only the order the reasons are reported in.
    let refusal = if !provider_trusts_email {
        Some(LinkRefusal::ProviderNotTrusted)
    } else if !upstream.email_verified {
        Some(LinkRefusal::UpstreamEmailUnverified)
    } else if !local.email_verified {
        Some(LinkRefusal::LocalEmailUnverified)
    } else {
        None
    };

    match refusal {
        Some(reason) => LinkDecision::RequireExplicitLink {
            user_id: local.user_id.clone(),
            reason,
        },
        None => LinkDecision::LinkToExisting {
            user_id: local.user_id.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(email_verified: bool) -> UpstreamIdentity {
        UpstreamIdentity {
            external_user_id: "upstream-sub-1".into(),
            external_username: Some("ada".into()),
            email: Some("ada@example.test".into()),
            email_verified,
        }
    }

    fn local(email_verified: bool) -> LocalAccount {
        LocalAccount {
            user_id: "local-ada".into(),
            email_verified,
        }
    }

    /// An existing link wins over everything. Once a federated identity is bound
    /// to a local user, changing the address upstream must not move it.
    #[test]
    fn an_existing_link_is_never_overridden() {
        let decision = decide_link(
            Some("local-bound"),
            &upstream(true),
            true,
            Some(&local(true)),
        );
        assert_eq!(
            decision,
            LinkDecision::AlreadyLinked {
                user_id: "local-bound".to_owned()
            }
        );

        // Not even when everything about the match points elsewhere.
        assert_eq!(
            decide_link(
                Some("local-bound"),
                &upstream(false),
                false,
                Some(&local(false))
            ),
            LinkDecision::AlreadyLinked {
                user_id: "local-bound".to_owned()
            }
        );
    }

    /// Nothing local claiming the identity is an account to create, whatever the
    /// provider says about the address.
    #[test]
    fn no_local_match_creates_an_account() {
        for trusted in [true, false] {
            for verified in [true, false] {
                assert_eq!(
                    decide_link(None, &upstream(verified), trusted, None),
                    LinkDecision::CreateNew
                );
            }
        }
    }

    /// All three conditions have to hold. This is the whole point: any one of
    /// them missing turns a match into a takeover.
    #[test]
    fn linking_automatically_needs_every_condition() {
        assert_eq!(
            decide_link(None, &upstream(true), true, Some(&local(true))),
            LinkDecision::LinkToExisting {
                user_id: "local-ada".to_owned()
            }
        );

        let cases = [
            (false, true, true, LinkRefusal::ProviderNotTrusted),
            (true, false, true, LinkRefusal::UpstreamEmailUnverified),
            (true, true, false, LinkRefusal::LocalEmailUnverified),
            // And with more than one missing, it still refuses.
            (false, false, false, LinkRefusal::ProviderNotTrusted),
            (true, false, false, LinkRefusal::UpstreamEmailUnverified),
        ];

        for (trusted, upstream_verified, local_verified, reason) in cases {
            assert_eq!(
                decide_link(
                    None,
                    &upstream(upstream_verified),
                    trusted,
                    Some(&local(local_verified))
                ),
                LinkDecision::RequireExplicitLink {
                    user_id: "local-ada".to_owned(),
                    reason
                },
                "trusted={trusted} upstream={upstream_verified} local={local_verified}"
            );
        }
    }

    /// Every combination is covered, and exactly one of the eight links
    /// automatically. Counted rather than eyeballed, since the failure here is a
    /// case nobody thought about.
    #[test]
    fn exactly_one_combination_links_automatically() {
        let mut linked = 0;
        for trusted in [true, false] {
            for upstream_verified in [true, false] {
                for local_verified in [true, false] {
                    let decision = decide_link(
                        None,
                        &upstream(upstream_verified),
                        trusted,
                        Some(&local(local_verified)),
                    );
                    if matches!(decision, LinkDecision::LinkToExisting { .. }) {
                        linked += 1;
                        assert!(trusted && upstream_verified && local_verified);
                    }
                }
            }
        }
        assert_eq!(linked, 1, "only all three holding may link");
    }
}
