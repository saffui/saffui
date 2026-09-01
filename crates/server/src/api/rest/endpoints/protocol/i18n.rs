use std::sync::LazyLock;

use fluent_bundle::{FluentBundle, FluentResource};
use unic_langid::LanguageIdentifier;

/// The tongues the hosted pages speak, in the order they are held. The first
/// is the answer when the browser asks for none of them.
pub const TONGUES: [&str; 2] = ["en", "fr"];

const TEMPLATE: &str = include_str!("ui/login.html");
const STRINGS: [&str; 2] = [
    include_str!("ui/themes/en.ftl"),
    include_str!("ui/themes/fr.ftl"),
];

/// The sign-in page in every tongue, rendered once. A missing string is a
/// build fault, so it stops the process rather than serving a page with a
/// hole in it.
static PAGES: LazyLock<[String; 2]> = LazyLock::new(|| {
    [
        rendered(TONGUES[0], STRINGS[0]),
        rendered(TONGUES[1], STRINGS[1]),
    ]
});

/// Which of the spoken tongues an `Accept-Language` value asks for: the first
/// primary tag that names one, read in the order the browser wrote them. The
/// weights are left unread; a browser that ranks `fr` below `en` and still
/// sends `fr` first is rare enough to be wrong about.
pub fn spoken(accept: Option<&str>) -> &'static str {
    accept
        .into_iter()
        .flat_map(|held| held.split(','))
        .filter_map(first_spoken_of)
        .next()
        .unwrap_or(TONGUES[0])
}

/// The first spoken tongue a `ui_locales` value names, OIDC Core §3.1.2.1:
/// space separated, most wanted first. `None` when it names only tongues the
/// pages do not speak, so the browser's own list can still answer.
pub fn first_spoken(ui_locales: &str) -> Option<&'static str> {
    ui_locales
        .split_whitespace()
        .filter_map(first_spoken_of)
        .next()
}

fn first_spoken_of(asked: &str) -> Option<&'static str> {
    let primary = asked
        .split(';')
        .next()?
        .trim()
        .split('-')
        .next()?
        .to_ascii_lowercase();
    TONGUES.into_iter().find(|tongue| *tongue == primary)
}

/// The rendered page in the given tongue; anything unspoken gets the first.
pub fn page_in(tongue: &str) -> &'static str {
    let at = TONGUES.iter().position(|held| *held == tongue).unwrap_or(0);
    &PAGES[at]
}

/// The template with every `{{name}}` replaced by that tongue's string,
/// escaped on the way in: the strings are prose, and prose holds no markup.
fn rendered(tongue: &str, strings: &str) -> String {
    let locale: LanguageIdentifier = tongue.parse().expect("a language tag");
    let mut bundle = FluentBundle::new(vec![locale]);
    bundle.set_use_isolating(false);
    let resource = FluentResource::try_new(strings.to_owned())
        .unwrap_or_else(|_| panic!("the {tongue} strings do not parse"));
    bundle
        .add_resource(resource)
        .unwrap_or_else(|_| panic!("the {tongue} strings repeat a name"));

    let mut page = String::with_capacity(TEMPLATE.len());
    let mut rest = TEMPLATE;
    while let Some(at) = rest.find("{{") {
        page.push_str(&rest[..at]);
        rest = &rest[at + 2..];
        let end = rest.find("}}").expect("an unterminated marker");
        let name = &rest[..end];
        rest = &rest[end + 2..];
        if name == "lang" {
            page.push_str(tongue);
            continue;
        }
        let message = bundle
            .get_message(name)
            .unwrap_or_else(|| panic!("`{name}` is not among the {tongue} strings"));
        let pattern = message
            .value()
            .unwrap_or_else(|| panic!("`{name}` has no value"));
        let mut errors = Vec::new();
        let value = bundle.format_pattern(pattern, None, &mut errors);
        assert!(errors.is_empty(), "`{name}` did not format: {errors:?}");
        page.push_str(&super::page::escaped(&value));
    }
    page.push_str(rest);
    page
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both renders resolve every marker, and each speaks its own tongue
    /// where the browser reads it: the root's `lang` and the title.
    #[test]
    fn the_page_speaks_every_tongue_it_promises() {
        for tongue in TONGUES {
            let page = page_in(tongue);
            assert!(!page.contains("{{"), "an unresolved marker in {tongue}");
            assert!(page.contains(&format!("<html lang=\"{tongue}\">")));
        }
        assert!(page_in("en").contains("<title>Sign in</title>"));
        assert!(page_in("fr").contains("<title>Se connecter</title>"));
        assert!(page_in("nothing-spoken").contains("<title>Sign in</title>"));
    }

    /// `ui_locales` is space separated and advisory: the first spoken tongue
    /// answers, and a list naming none leaves the browser's list to answer.
    #[test]
    fn ui_locales_speaks_first_and_yields_when_unspoken() {
        for (asked, told) in [
            ("fr-CA fr en", Some("fr")),
            ("de en-GB", Some("en")),
            ("de ja", None),
            ("", None),
        ] {
            assert_eq!(first_spoken(asked), told, "{asked:?}");
        }
    }

    /// The browser's list is read in its own order, by primary tag, first
    /// spoken match wins, and silence means the first tongue.
    #[test]
    fn the_asked_tongue_is_the_first_spoken_one() {
        for (asked, told) in [
            (None, "en"),
            (Some("en-US,en;q=0.9"), "en"),
            (Some("fr-CH, fr;q=0.9, en;q=0.8"), "fr"),
            (Some("FR"), "fr"),
            (Some("de-DE,de;q=0.9"), "en"),
            (Some("da, fr;q=0.8, en;q=0.7"), "fr"),
            (Some(""), "en"),
        ] {
            assert_eq!(spoken(asked), told, "{asked:?}");
        }
    }
}
