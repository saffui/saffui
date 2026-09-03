use std::sync::LazyLock;

use fluent_bundle::{FluentBundle, FluentResource};
use unic_langid::LanguageIdentifier;

/// The tongues the hosted pages speak, in the order they are held. The first
/// is the answer when the browser asks for none of them.
pub const TONGUES: [&str; 2] = ["en", "fr"];

const TEMPLATE: &str = include_str!("ui/login.html");
const DEVICE_TEMPLATE: &str = include_str!("ui/device.html");
const REQUESTS_TEMPLATE: &str = include_str!("ui/requests.html");
const STRINGS: [&str; 2] = [
    include_str!("ui/themes/en.ftl"),
    include_str!("ui/themes/fr.ftl"),
];

/// The hosted pages in every tongue, rendered once. A missing string is a
/// build fault, so it stops the process rather than serving a page with a
/// hole in it.
static PAGES: LazyLock<[String; 2]> = LazyLock::new(|| {
    [
        rendered(TEMPLATE, TONGUES[0], STRINGS[0]),
        rendered(TEMPLATE, TONGUES[1], STRINGS[1]),
    ]
});
static DEVICE_PAGES: LazyLock<[String; 2]> = LazyLock::new(|| {
    [
        rendered(DEVICE_TEMPLATE, TONGUES[0], STRINGS[0]),
        rendered(DEVICE_TEMPLATE, TONGUES[1], STRINGS[1]),
    ]
});
static REQUESTS_PAGES: LazyLock<[String; 2]> = LazyLock::new(|| {
    [
        rendered(REQUESTS_TEMPLATE, TONGUES[0], STRINGS[0]),
        rendered(REQUESTS_TEMPLATE, TONGUES[1], STRINGS[1]),
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

/// What a realm says about tongues, reduced to what this build can honour.
///
/// The offered list is the realm's cut of the built tongues, every built one
/// when the realm says nothing, and never empty: a realm naming only tongues
/// the build does not speak offers the whole build rather than silence. The
/// fallback is the realm's default where it is offered, the first offered
/// tongue otherwise.
pub struct RealmTongues {
    offered: Vec<&'static str>,
    fallback: &'static str,
}

impl RealmTongues {
    pub fn of(supported: Option<&[String]>, default_locale: Option<&str>) -> Self {
        let offered: Vec<&'static str> = match supported {
            Some(named) if !named.is_empty() => TONGUES
                .into_iter()
                .filter(|tongue| named.iter().any(|asked| asked.eq_ignore_ascii_case(tongue)))
                .collect(),
            _ => TONGUES.to_vec(),
        };
        let offered = if offered.is_empty() {
            TONGUES.to_vec()
        } else {
            offered
        };
        let fallback = default_locale
            .and_then(|asked| offered.iter().find(|held| asked.eq_ignore_ascii_case(held)))
            .copied()
            .unwrap_or(offered[0]);
        RealmTongues { offered, fallback }
    }

    /// What discovery publishes as `ui_locales_supported`.
    pub fn offered(&self) -> &[&'static str] {
        &self.offered
    }

    /// The tongue this realm answers with: the request's own say first, the
    /// browser's list next, both held to what the realm offers, and the
    /// realm's fallback when neither speaks.
    pub fn negotiated(&self, ui_locales: Option<&str>, accept: Option<&str>) -> &'static str {
        ui_locales
            .and_then(first_spoken)
            .filter(|tongue| self.offered.contains(tongue))
            .or_else(|| {
                accept
                    .into_iter()
                    .flat_map(|held| held.split(','))
                    .filter_map(first_spoken_of)
                    .find(|tongue| self.offered.contains(tongue))
            })
            .unwrap_or(self.fallback)
    }
}

/// Every key the pages speak, with the built value per tongue. Parsed off
/// the same sources the bundles are built from; the values in these files
/// are single-line by construction, which is what the parse leans on.
pub static CATALOGUE: LazyLock<Vec<(String, [String; 2])>> = LazyLock::new(|| {
    let read = |source: &str| -> std::collections::BTreeMap<String, String> {
        source
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once(" = ")?;
                let shaped = name
                    .chars()
                    .all(|held| held.is_ascii_lowercase() || held.is_ascii_digit() || held == '-');
                (shaped && !name.is_empty()).then(|| (name.to_owned(), value.to_owned()))
            })
            .collect()
    };
    let (en, fr) = (read(STRINGS[0]), read(STRINGS[1]));
    en.iter()
        .map(|(name, value)| {
            (
                name.clone(),
                [
                    value.clone(),
                    fr.get(name).cloned().unwrap_or_else(|| value.clone()),
                ],
            )
        })
        .collect()
});

/// Whether the build speaks this key at all, which is what a realm override
/// is checked against: a realm cannot invent a string no page reads.
pub fn knows_key(name: &str) -> bool {
    CATALOGUE.iter().any(|(held, _)| held == name)
}

/// The sign-in page with a realm's words layered over the build's: the same
/// walk the startup render does, asking the overrides first. Rendered per
/// request, and only for the rare realm that says anything.
pub fn page_over(tongue: &str, overrides: &serde_json::Value) -> String {
    rendered_over(TEMPLATE, tongue, overrides)
}

fn rendered_over(template: &str, tongue: &str, overrides: &serde_json::Value) -> String {
    let at = TONGUES.iter().position(|held| *held == tongue).unwrap_or(0);
    let spoken = overrides.get(TONGUES[at]);
    let mut page = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(found) = rest.find("{{") {
        page.push_str(&rest[..found]);
        rest = &rest[found + 2..];
        let end = rest.find("}}").expect("an unterminated marker");
        let name = &rest[..end];
        rest = &rest[end + 2..];
        if name == "lang" {
            page.push_str(TONGUES[at]);
            continue;
        }
        if let Some(said) = spoken
            .and_then(|held| held.get(name))
            .and_then(serde_json::Value::as_str)
        {
            page.push_str(&super::page::escaped(said));
            continue;
        }
        let built = CATALOGUE
            .iter()
            .find(|(held, _)| held == name)
            .map(|(_, values)| values[at].as_str())
            .unwrap_or("");
        page.push_str(&super::page::escaped(built));
    }
    page.push_str(rest);
    page
}

/// The rendered sign-in page in the given tongue; anything unspoken gets the
/// first.
pub fn page_in(tongue: &str) -> &'static str {
    let at = TONGUES.iter().position(|held| *held == tongue).unwrap_or(0);
    &PAGES[at]
}

/// The rendered device page, RFC 8628 §3.3, the same way.
pub fn device_page_in(tongue: &str) -> &'static str {
    let at = TONGUES.iter().position(|held| *held == tongue).unwrap_or(0);
    &DEVICE_PAGES[at]
}

/// The rendered doorbell page, where a person answers what waits on them.
pub fn requests_page_in(tongue: &str) -> &'static str {
    let at = TONGUES.iter().position(|held| *held == tongue).unwrap_or(0);
    &REQUESTS_PAGES[at]
}

/// The template with every `{{name}}` replaced by that tongue's string,
/// escaped on the way in: the strings are prose, and prose holds no markup.
fn rendered(template: &str, tongue: &str, strings: &str) -> String {
    let locale: LanguageIdentifier = tongue.parse().expect("a language tag");
    let mut bundle = FluentBundle::new(vec![locale]);
    bundle.set_use_isolating(false);
    let resource = FluentResource::try_new(strings.to_owned())
        .unwrap_or_else(|_| panic!("the {tongue} strings do not parse"));
    bundle
        .add_resource(resource)
        .unwrap_or_else(|_| panic!("the {tongue} strings repeat a name"));

    let mut page = String::with_capacity(template.len());
    let mut rest = template;
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

    /// Both renders of both pages resolve every marker, and each speaks its
    /// own tongue where the browser reads it: the root's `lang` and the title.
    #[test]
    fn the_page_speaks_every_tongue_it_promises() {
        for tongue in TONGUES {
            for page in [
                page_in(tongue),
                device_page_in(tongue),
                requests_page_in(tongue),
            ] {
                assert!(!page.contains("{{"), "an unresolved marker in {tongue}");
                assert!(page.contains(&format!("<html lang=\"{tongue}\">")));
            }
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

    /// The realm narrows what the build speaks and names the silence answer:
    /// a French-only realm answers French to an English browser, a named
    /// default answers silence, and a realm naming only unspoken tongues
    /// falls back to the whole build.
    #[test]
    fn the_realm_narrows_the_tongues_and_names_the_silence() {
        let french_only = RealmTongues::of(Some(&["fr".to_owned()]), None);
        assert_eq!(french_only.offered(), &["fr"]);
        assert_eq!(french_only.negotiated(None, Some("en-US,en;q=0.9")), "fr");
        assert_eq!(french_only.negotiated(Some("fr en"), None), "fr");

        let defaulted = RealmTongues::of(None, Some("fr"));
        assert_eq!(defaulted.negotiated(None, None), "fr");
        assert_eq!(defaulted.negotiated(None, Some("en")), "en");
        assert_eq!(defaulted.negotiated(Some("en"), None), "en");

        let unspoken = RealmTongues::of(Some(&["de".to_owned()]), Some("de"));
        assert_eq!(unspoken.offered(), TONGUES.as_slice());
        assert_eq!(unspoken.negotiated(None, None), "en");

        let cased = RealmTongues::of(Some(&["FR".to_owned(), "en".to_owned()]), Some("FR"));
        assert_eq!(cased.negotiated(None, None), "fr");
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
