use serde_json::Value;

/// The token names the hosted pages read, and the only names a realm may
/// override: the stylesheet's own contract, spelled once here so the door
/// and the sheet cannot drift.
pub const TOKENS: [&str; 15] = [
    "brand-primary",
    "brand-on-primary",
    "bg",
    "surface",
    "ink",
    "muted",
    "border",
    "danger",
    "radius",
    "font-sans",
    "card-border-width",
    "card-shadow",
    "logo-display",
    "logo-radius",
    "field-bg",
];

/// How much of a picture a realm may keep as its mark.
///
/// The mark is drawn a few dozen pixels wide, so anything past this is not a
/// logo, it is a file somebody parked in a realm row. Named here rather than
/// at the door so the bench and the door weigh the same number.
pub const LARGEST_LOGO: usize = 64 * 1024;

/// Why a picture cannot be a realm's mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unusable {
    #[error("a mark is at most 64 KiB")]
    TooBig,
    /// Said of anything whose first bytes are not a raster picture this build
    /// recognises, SVG included.
    #[error("a mark is a PNG, a JPEG, a GIF or a WebP")]
    NotAPicture,
}

/// What a realm's mark is, read off the bytes themselves.
///
/// Judged on the content and never on what an upload called itself: a name and
/// a declared type are both the caller's to write, and this decides what gets
/// served back under a type of our choosing.
///
/// SVG is refused whatever it claims to be, and not because it cannot be
/// drawn. It is a document: served from this origin it runs its own script the
/// moment somebody opens its address directly, which would turn a realm's logo
/// into a way to run code as this site. A raster picture carries no such
/// thing, so the rule is the format and not a sanitiser nobody can be sure of.
pub fn weigh_logo(bytes: &[u8]) -> Result<&'static str, Unusable> {
    if bytes.len() > LARGEST_LOGO {
        return Err(Unusable::TooBig);
    }
    let starts = |head: &[u8]| bytes.starts_with(head);
    if starts(b"\x89PNG\r\n\x1a\n") {
        return Ok("image/png");
    }
    if starts(b"\xff\xd8\xff") {
        return Ok("image/jpeg");
    }
    if starts(b"GIF87a") || starts(b"GIF89a") {
        return Ok("image/gif");
    }
    // RIFF names its size in the four bytes between the two tags, so the
    // second tag is read where it sits rather than searched for.
    if starts(b"RIFF") && bytes.len() >= 12 && &bytes[8..12] == b"WEBP" {
        return Ok("image/webp");
    }
    Err(Unusable::NotAPicture)
}

/// Whether a value may sit inside a CSS declaration without being able to
/// leave it. A stylesheet is executable enough: a value that could close the
/// declaration, open a block, or reach the network is refused, not escaped.
fn safe(value: &str) -> bool {
    let sound = !value.is_empty()
        && value.len() <= 120
        && value.chars().all(|held| {
            held.is_ascii_alphanumeric()
                || matches!(
                    held,
                    ' ' | '#' | '%' | ',' | '.' | '(' | ')' | '\'' | '"' | '-'
                )
        });
    let lowered = value.to_ascii_lowercase();
    sound && !lowered.contains("url(") && !lowered.contains("expression(")
}

/// Turn a stored theme into the override block the stylesheet appends.
///
/// The shape is `{"light": {token: value}, "dark": {token: value}}`, either
/// half optional. Refused whole on the first unknown name or unsound value:
/// a theme half-applied would look like a bug in the default.
pub fn css_of(theme: &Value) -> Result<String, &'static str> {
    let held = theme.as_object().ok_or("a theme is an object")?;
    for key in held.keys() {
        if key != "light" && key != "dark" {
            return Err("a theme holds light and dark, nothing else");
        }
    }
    let mut css = String::new();
    if let Some(light) = held.get("light") {
        css.push_str(&block(":root", light)?);
    }
    if let Some(dark) = held.get("dark") {
        css.push_str("@media (prefers-color-scheme: dark){");
        css.push_str(&block(":root", dark)?);
        css.push('}');
    }
    Ok(css)
}

fn block(selector: &str, tokens: &Value) -> Result<String, &'static str> {
    let held = tokens.as_object().ok_or("a theme half is an object")?;
    let mut css = format!("{selector}{{");
    for (name, value) in held {
        if !TOKENS.contains(&name.as_str()) {
            return Err("a token the pages do not read");
        }
        let value = value.as_str().ok_or("a token's value is a string")?;
        if !safe(value) {
            return Err("a token's value cannot leave its declaration");
        }
        css.push_str(&format!("--{name}:{value};"));
    }
    css.push('}');
    Ok(css)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_theme_renders_whole_or_refuses_whole() {
        let dressed = css_of(&json!({
            "light": { "brand-primary": "#12305e", "radius": "0px" },
            "dark": { "brand-primary": "#9dbdf0" },
        }))
        .unwrap();
        assert!(dressed.contains(":root{--brand-primary:#12305e;--radius:0px;}"));
        assert!(dressed.contains("prefers-color-scheme: dark"));
        assert!(dressed.contains("--brand-primary:#9dbdf0;"));

        for refused in [
            json!({ "light": { "made-up": "#fff" } }),
            json!({ "light": { "brand-primary": "#111;}body{background:red" } }),
            json!({ "light": { "card-shadow": "url(https://evil.example)" } }),
            json!({ "light": { "brand-primary": 7 } }),
            json!({ "noon": {} }),
            json!(["not", "an", "object"]),
        ] {
            assert!(css_of(&refused).is_err(), "{refused}");
        }

        // The whole contract is coverable, and the grammar admits the shapes
        // real values take.
        let full: serde_json::Map<String, serde_json::Value> = TOKENS
            .iter()
            .map(|name| ((*name).to_owned(), json!("0 1px 2px rgb(15 25 45 (0.10))")))
            .collect();
        assert!(css_of(&json!({ "light": full })).is_ok());
    }
}

#[cfg(test)]
mod marks {
    use super::*;

    fn png() -> Vec<u8> {
        let mut held = b"\x89PNG\r\n\x1a\n".to_vec();
        held.extend_from_slice(&[0; 32]);
        held
    }

    #[test]
    fn a_mark_is_read_off_its_own_bytes() {
        assert_eq!(weigh_logo(&png()), Ok("image/png"));
        assert_eq!(weigh_logo(b"\xff\xd8\xffsomething"), Ok("image/jpeg"));
        assert_eq!(weigh_logo(b"GIF89a and the rest"), Ok("image/gif"));
        assert_eq!(weigh_logo(b"RIFF\0\0\0\0WEBPVP8 "), Ok("image/webp"));
    }

    /// Refused whatever it calls itself. Served from this origin it is a
    /// document that runs its own script the moment its address is opened, so
    /// the rule is the format and not a sanitiser.
    #[test]
    fn a_drawing_that_can_carry_a_script_is_refused() {
        for held in [
            &b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>"[..],
            &b"<?xml version=\"1.0\"?><svg/>"[..],
            &b"\xef\xbb\xbf<svg/>"[..],
        ] {
            assert_eq!(weigh_logo(held), Err(Unusable::NotAPicture), "{held:?}");
        }
    }

    #[test]
    fn what_is_not_a_picture_at_all_is_refused() {
        assert_eq!(weigh_logo(b""), Err(Unusable::NotAPicture));
        assert_eq!(weigh_logo(b"GIF"), Err(Unusable::NotAPicture));
        // RIFF without the second tag is some other RIFF file, not a picture.
        assert_eq!(weigh_logo(b"RIFF\0\0\0\0AVI LIST"), Err(Unusable::NotAPicture));
    }

    /// The two refusals are distinct so an operator is told which rule they
    /// hit rather than being left to guess between a format and a size.
    #[test]
    fn a_picture_past_the_cap_says_so_rather_than_saying_it_is_no_picture() {
        let mut huge = png();
        huge.resize(LARGEST_LOGO + 1, 0);
        assert_eq!(weigh_logo(&huge), Err(Unusable::TooBig));
        let mut just_under = png();
        just_under.resize(LARGEST_LOGO, 0);
        assert_eq!(weigh_logo(&just_under), Ok("image/png"));
    }
}
