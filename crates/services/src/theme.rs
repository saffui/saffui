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
