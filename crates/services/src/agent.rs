//! Reading a browser and a system out of a `User-Agent`.
//!
//! A heuristic, and read rather than stored for that reason: the string a
//! browser sent does not change, and what can be told from it does. A parse
//! written into a column ages with the row and cannot be improved without one
//! migration per improvement.
//!
//! It answers for the common browsers and nothing more. Privacy browsers spell
//! themselves as Chrome on purpose, so this reports what they chose to say.

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Reading {
    pub browser: Option<&'static str>,
    pub system: Option<&'static str>,
    pub mobile: bool,
}

pub fn read_agent(agent: &str) -> Reading {
    Reading {
        browser: browser(agent),
        system: system(agent),
        mobile: mobile(agent),
    }
}

/// Order decides. Edge and Opera both spell Chrome, and Chrome spells Safari,
/// so the narrower token is asked first.
fn browser(agent: &str) -> Option<&'static str> {
    [
        ("Edg/", "Edge"),
        ("Edge", "Edge"),
        ("OPR/", "Opera"),
        ("Opera", "Opera"),
        ("Firefox", "Firefox"),
        ("FxiOS", "Firefox"),
        ("CriOS", "Chrome"),
        ("Chrome", "Chrome"),
        ("Safari", "Safari"),
    ]
    .into_iter()
    .find(|(token, _)| agent.contains(token))
    .map(|(_, named)| named)
}

/// Android says Linux too, and every iOS browser says Mac OS X, so both are
/// asked before the thing they also claim to be.
fn system(agent: &str) -> Option<&'static str> {
    [
        ("Windows", "Windows"),
        ("Android", "Android"),
        ("iPhone", "iOS"),
        ("iPad", "iOS"),
        ("Mac OS X", "macOS"),
        ("Macintosh", "macOS"),
        ("Linux", "Linux"),
    ]
    .into_iter()
    .find(|(token, _)| agent.contains(token))
    .map(|(_, named)| named)
}

fn mobile(agent: &str) -> bool {
    ["Mobile", "iPhone", "Android"]
        .iter()
        .any(|token| agent.contains(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                                  (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    const EDGE_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                                (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
    const SAFARI_IPHONE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) \
                                 AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 \
                                 Mobile/15E148 Safari/604.1";
    const FIREFOX_LINUX: &str =
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0";
    const CHROME_ANDROID: &str = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 \
                                  (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";

    #[test]
    fn a_browser_that_spells_another_is_read_as_itself() {
        assert_eq!(read_agent(CHROME_WINDOWS).browser, Some("Chrome"));
        assert_eq!(
            read_agent(EDGE_WINDOWS).browser,
            Some("Edge"),
            "Edge was read as the Chrome it also spells"
        );
        assert_eq!(read_agent(SAFARI_IPHONE).browser, Some("Safari"));
        assert_eq!(read_agent(FIREFOX_LINUX).browser, Some("Firefox"));
    }

    #[test]
    fn a_system_that_spells_another_is_read_as_itself() {
        assert_eq!(read_agent(CHROME_WINDOWS).system, Some("Windows"));
        assert_eq!(
            read_agent(CHROME_ANDROID).system,
            Some("Android"),
            "Android was read as the Linux it also spells"
        );
        assert_eq!(
            read_agent(SAFARI_IPHONE).system,
            Some("iOS"),
            "an iPhone was read as the Mac it also spells"
        );
        assert_eq!(read_agent(FIREFOX_LINUX).system, Some("Linux"));
    }

    #[test]
    fn a_phone_is_told_from_a_desktop() {
        assert!(read_agent(SAFARI_IPHONE).mobile);
        assert!(read_agent(CHROME_ANDROID).mobile);
        assert!(!read_agent(CHROME_WINDOWS).mobile);
        assert!(!read_agent(FIREFOX_LINUX).mobile);
    }

    #[test]
    fn something_that_is_no_browser_is_read_as_nothing() {
        assert_eq!(read_agent("curl/8.4.0"), Reading::default());
        assert_eq!(read_agent(""), Reading::default());
    }
}
