//! What a request said about where it came from.
//!
//! Two observed facts, neither of them an identity: the address this deployment
//! believes the caller has, and the `User-Agent` string verbatim. Nothing here
//! derives a device from them, because a caller controls both and a derived
//! device would be something this server acts on.

/// How much of a `User-Agent` is kept. Long enough for every real browser and
/// short enough that a caller cannot use the column as storage.
pub const AGENT_LIMIT: usize = 512;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Provenance {
    pub address: Option<String>,
    pub agent: Option<String>,
}

impl Provenance {
    /// Build from what a request carried, cutting the agent to a length and to
    /// what prints: a caller that sends control characters is writing into
    /// whatever renders the value later.
    pub fn seen(address: Option<&str>, agent: Option<&str>) -> Self {
        Provenance {
            address: address.map(str::to_owned).filter(|seen| !seen.is_empty()),
            agent: agent.map(readable).filter(|kept| !kept.is_empty()),
        }
    }
}

fn readable(agent: &str) -> String {
    agent
        .chars()
        .filter(|character| !character.is_control())
        .take(AGENT_LIMIT)
        .collect::<String>()
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_agent_is_cut_to_a_length_and_to_what_prints() {
        let long = Provenance::seen(None, Some(&"x".repeat(1000)));
        assert_eq!(long.agent.unwrap().len(), AGENT_LIMIT);

        assert_eq!(
            Provenance::seen(None, Some("  Chrome\tand more  ")).agent,
            Some("Chromeand more".to_owned()),
            "a control character survived"
        );
        assert_eq!(Provenance::seen(None, Some("  \t ")).agent, None);
        assert_eq!(Provenance::seen(Some(""), None).address, None);
    }
}
