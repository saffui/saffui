//! What a realm may say in its own words, and what each of those messages
//! needs to keep working.
//!
//! One table, because one field holds them all: a realm files every rewording
//! under `mail_templates`, and the door that weighs that field has to know both
//! families. Split in two, the door would weigh one and wave the other through.

use crate::messaging::notices::NoticeKind;

/// What a message of this kind cannot do without.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rewordable {
    /// Whether the body has to carry `{{link}}`.
    ///
    /// A letter that exists to be followed is nothing without it, so the door
    /// refuses a rewording that drops it. A security notice carries no link at
    /// all and demanding one would refuse every rewording of one.
    pub carries_link: bool,
}

/// The four letters this build sends that are followed rather than read.
pub const LETTERS: [&str; 4] = [
    "magic_link",
    "verify_email",
    "reset_password",
    "subject_request",
];

/// Whether a realm may file a rewording under this name, and what it owes.
pub fn rewordable(kind: &str) -> Option<Rewordable> {
    if LETTERS.contains(&kind) {
        return Some(Rewordable { carries_link: true });
    }
    // A notice tells somebody what already happened to their account. There is
    // nothing to follow, which is why the link rule is the wrong rule here.
    NoticeKind::parse(kind).map(|_| Rewordable {
        carries_link: false,
    })
}

/// Every name a realm may file a rewording under, letters first.
pub fn every_kind() -> impl Iterator<Item = &'static str> {
    LETTERS
        .into_iter()
        .chain(NoticeKind::ALL.into_iter().map(NoticeKind::as_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A letter is followed, so it keeps its link rule. A notice is read, so
    /// demanding one would refuse every rewording of one.
    #[test]
    fn a_letter_owes_its_link_and_a_notice_owes_none() {
        assert_eq!(
            rewordable("magic_link"),
            Some(Rewordable { carries_link: true })
        );
        assert_eq!(
            rewordable("password-changed"),
            Some(Rewordable {
                carries_link: false
            })
        );
    }

    #[test]
    fn a_name_this_build_never_sends_is_not_one() {
        assert_eq!(rewordable("invented_elsewhere"), None);
        assert_eq!(rewordable(""), None);
        // A notice kind spelled the way a letter kind is spelled is still not
        // one: the two families name themselves differently on purpose.
        assert_eq!(rewordable("password_changed"), None);
    }

    /// Every kind the build sends can be reworded, which is the whole claim.
    #[test]
    fn every_kind_this_build_sends_can_be_said_another_way() {
        let held: Vec<&str> = every_kind().collect();
        assert_eq!(held.len(), LETTERS.len() + NoticeKind::ALL.len());
        for kind in &held {
            assert!(rewordable(kind).is_some(), "{kind} is offered and refused");
        }
    }
}
