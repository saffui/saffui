//! The HTML half of a message: one layout this build owns, with named places
//! a realm's words are put into.
//!
//! The shape of this module is the security decision behind it. A realm writes
//! wording and never markup, so there is no template of somebody else's to
//! parse, validate or sanitise: every place a word lands has one grammar,
//! decided here once, and the words go through it on the way in.
//!
//! The text half is untouched and still sent. A reader whose client shows text
//! sees exactly what this build has always sent, and the two halves say the
//! same thing because they are written from the same words.

/// The five characters HTML reads as markup, spelled so it does not.
///
/// Used for every place that holds words: a title, a paragraph, a button's
/// label. An attribute is a different grammar and has its own function.
pub fn as_text(value: &str) -> String {
    let mut held = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => held.push_str("&amp;"),
            '<' => held.push_str("&lt;"),
            '>' => held.push_str("&gt;"),
            '"' => held.push_str("&quot;"),
            '\'' => held.push_str("&#39;"),
            _ => held.push(character),
        }
    }
    held
}

/// An address fit to sit in an `href`, or nothing.
///
/// The scheme is weighed before the escaping, and only the two that fetch a
/// page are allowed. Every link this build writes is built from its own origin
/// today, which is exactly why the check is here: "we build it" is a fact about
/// today and not a property of the code, and a `javascript:` address reaching
/// an `href` is the one way a letter could run something.
///
/// A refused address is answered as nothing rather than as a broken button, and
/// the text half still carries the address in full, so a reader loses nothing.
pub fn as_address(link: &str) -> Option<String> {
    let held = link.trim();
    let scheme = held
        .split_once(':')
        .map(|(scheme, _)| scheme.to_ascii_lowercase());
    match scheme.as_deref() {
        Some("http" | "https") => Some(as_text(held)),
        _ => None,
    }
}

/// One letter, written from the words the text half is written from.
///
/// `template` is the wording before anything was put into it, so `{{link}}` is
/// still standing where it stands: what comes before it and what comes after
/// become paragraphs, and the marker itself becomes the button. A wording that
/// names no link is a letter with no button, which is the right answer for the
/// messages that carry a code instead.
pub fn written(
    subject: &str,
    template: &str,
    link: &str,
    said: &[(&str, &str)],
    button: &str,
) -> String {
    // The wording decides whether there is a button, not the caller: a message
    // that carries a code names no link, and handing one an address would put
    // a button under words that never promised one.
    let named = template.split_once("{{link}}");
    let (before, after) = named.unwrap_or((template, ""));
    let mut body = String::new();
    body.push_str(&paragraphs(before, said));
    if let Some(address) = named.and_then(|_| as_address(link)) {
        body.push_str(&format!(
            "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" \
             style=\"margin:24px auto\"><tr><td align=\"center\" bgcolor=\"#1f2937\" \
             style=\"border-radius:6px\"><a href=\"{address}\" \
             style=\"display:inline-block;padding:12px 22px;font-family:Helvetica,Arial,sans-serif;\
             font-size:15px;color:#ffffff;text-decoration:none\">{}</a></td></tr></table>",
            as_text(button)
        ));
    }
    body.push_str(&paragraphs(after, said));

    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{}</title></head>\
         <body style=\"margin:0;padding:0;background:#f4f4f5\">\
         <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">\
         <tr><td align=\"center\" style=\"padding:24px 12px\">\
         <table role=\"presentation\" width=\"600\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" \
         style=\"max-width:600px;width:100%;background:#ffffff;border-radius:8px\">\
         <tr><td style=\"padding:28px 28px 8px;font-family:Helvetica,Arial,sans-serif;\
         font-size:19px;font-weight:600;color:#111827\">{}</td></tr>\
         <tr><td style=\"padding:0 28px 28px;font-family:Helvetica,Arial,sans-serif;\
         font-size:15px;line-height:1.55;color:#374151\">{body}</td></tr>\
         </table></td></tr></table></body></html>",
        as_text(subject),
        as_text(subject),
    )
}

/// Blank lines part one paragraph from the next, exactly as they do in the
/// text half, and a single newline inside one is a line break there too.
fn paragraphs(text: &str, said: &[(&str, &str)]) -> String {
    let mut held = String::new();
    for block in text.split("\n\n") {
        let worded = block.trim();
        if worded.is_empty() {
            continue;
        }
        let mut filled = worded.to_owned();
        for (name, value) in said {
            filled = filled.replace(&format!("{{{{{name}}}}}"), value);
        }
        // Escaped AFTER the names are put in, so a value carrying a bracket is
        // spelled out rather than landing as markup. The wording around it is
        // this build's or the realm's, and neither is trusted more than the
        // other here: both go through the same door.
        let drawn = as_text(&filled).replace('\n', "<br>");
        held.push_str(&format!("<p style=\"margin:0 0 14px\">{drawn}</p>"));
    }
    held
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORDING: &str =
        "Somebody asked to sign in as you.\n\nOpen this within ten minutes.\n\n{{link}}\n";

    #[test]
    fn words_are_spelled_out_rather_than_read_as_markup() {
        assert_eq!(as_text("a & b"), "a &amp; b");
        assert_eq!(as_text("<b>"), "&lt;b&gt;");
        assert_eq!(as_text("say \"it\""), "say &quot;it&quot;");
        assert_eq!(as_text("it's"), "it&#39;s");
    }

    /// Every link this build writes comes from its own origin today, which is
    /// exactly why the scheme is weighed: that is a fact about today and not a
    /// property of the code.
    #[test]
    fn only_an_address_that_fetches_a_page_reaches_an_href() {
        assert!(as_address("https://saffui.example/reset?token=abc").is_some());
        assert!(as_address("http://localhost:8080/login").is_some());
        for refused in [
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "  javascript:alert(1)  ",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox",
            "/realms/main/login",
            "",
        ] {
            assert_eq!(as_address(refused), None, "{refused} reached an href");
        }
    }

    /// A scheme is a scheme whatever case it was typed in, so an address
    /// written in capitals keeps its button instead of losing it in silence.
    #[test]
    fn a_scheme_is_weighed_whatever_case_it_was_written_in() {
        assert!(as_address("HTTPS://saffui.example/x").is_some());
        assert!(as_address("Http://saffui.example/x").is_some());
    }

    /// Escaped once and only once. Escaping the wording before the values are
    /// put in would leave a realm writing "Tom & Jerry" reading "Tom &amp;
    /// Jerry", which is a rule applied twice rather than a rule applied.
    #[test]
    fn words_are_escaped_once_and_not_twice() {
        let held = written("Tom & Jerry", "Ada & Grace wrote it.\n", "", &[], "Open");
        assert!(held.contains("Ada &amp; Grace"), "{held}");
        assert!(
            !held.contains("&amp;amp;"),
            "the wording was escaped twice: {held}"
        );
    }

    /// The one that matters. A value put into the wording is data, and data
    /// carrying a bracket is spelled out rather than landing as markup.
    #[test]
    fn a_value_carrying_markup_is_spelled_out() {
        let written = written(
            "Your code",
            "Here is your code: {{code}}\n",
            "",
            &[(
                "code",
                "<script>fetch('https://elsewhere.example')</script>",
            )],
            "Open",
        );
        assert!(written.contains("&lt;script&gt;"), "{written}");
        assert!(
            !written.contains("<script>"),
            "a value landed as markup: {written}"
        );
    }

    /// A subject is a place for words too, and the same door.
    #[test]
    fn a_subject_carrying_markup_is_spelled_out() {
        let written = written("<img onerror=alert(1)>", "Hello.\n", "", &[], "Open");
        assert!(!written.contains("<img onerror"), "{written}");
        assert!(written.contains("&lt;img onerror"), "{written}");
    }

    #[test]
    fn the_link_becomes_a_button_where_the_wording_names_one() {
        let held = written(
            "Sign in",
            WORDING,
            "https://saffui.example/go?t=1",
            &[],
            "Sign in",
        );
        assert!(
            held.contains("href=\"https://saffui.example/go?t=1\""),
            "{held}"
        );
        assert!(held.contains(">Sign in</a>"), "{held}");
        // The words around it are paragraphs, in the order they were written.
        let asked = held.find("Somebody asked").expect("the first paragraph");
        let opened = held.find("Open this within").expect("the second paragraph");
        let button = held.find("href=").expect("the button");
        assert!(asked < opened && opened < button, "{held}");
    }

    /// Answered as nothing rather than as a broken button: the text half still
    /// carries the address in full, so a reader loses nothing.
    #[test]
    fn an_address_that_is_refused_leaves_no_button_at_all() {
        let held = written("Sign in", WORDING, "javascript:alert(1)", &[], "Sign in");
        assert!(
            !held.contains("href="),
            "a refused address still drew a button: {held}"
        );
        assert!(!held.contains("javascript"), "{held}");
        assert!(
            held.contains("Somebody asked"),
            "the words went with it: {held}"
        );
    }

    /// The messages that carry a code name no link, and a letter with no link
    /// is a letter with no button rather than one with an empty one.
    #[test]
    fn a_wording_that_names_no_link_has_no_button() {
        let held = written(
            "Your code",
            "Here it is: {{code}}\n",
            "https://saffui.example/x",
            &[("code", "123456")],
            "Open",
        );
        assert!(!held.contains("href="), "{held}");
        assert!(held.contains("123456"), "{held}");
    }
}
