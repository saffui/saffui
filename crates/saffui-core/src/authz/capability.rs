//! The capabilities of the administration plane: a closed vocabulary. A name
//! that is not written here grants nothing, and there is no wildcard.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    RealmRead,
    ClientRead,
    ClientWrite,
    AuditRead,
}

impl Capability {
    pub const ALL: [Self; 4] = [
        Self::RealmRead,
        Self::ClientRead,
        Self::ClientWrite,
        Self::AuditRead,
    ];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::RealmRead => "realm:read",
            Self::ClientRead => "client:read",
            Self::ClientWrite => "client:write",
            Self::AuditRead => "audit:read",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|capability| capability.name() == name)
    }
}

#[cfg(test)]
mod tests {
    use super::Capability;

    #[test]
    fn a_name_is_read_back_to_its_capability_and_nothing_else_is() {
        for capability in Capability::ALL {
            assert_eq!(Capability::parse(capability.name()), Some(capability));
        }
        for name in ["*", "client:*", "client", "CLIENT:READ", ""] {
            assert_eq!(Capability::parse(name), None, "{name:?}");
        }
    }
}
