//! A page writes what it shows as text only while nothing turns its
//! escaping off. This reads the templates and the sources of the crate: no
//! template lets a value through, picks another escaper, reaches askama by a
//! path, names a file outside `templates/` or hands a value to the script or
//! the style; no derive picks an escaper or hides from the count; and the
//! sources name nothing of askama but its trait, its result and its error.

use std::fs;
use std::path::{Path, PathBuf};

/// What lets a value through a template, blanks removed: the filter that
/// marks it safe, a filter that names its own escaper, the same two over a
/// block, the wrappers askama writes as they are, and askama by a path.
const DISARMING: [&str; 9] = [
    "|safe",
    "|escape(",
    "|e(",
    "filtersafe",
    "filterescape(",
    "filtere(",
    "Safe",
    "askama::",
    "filters::",
];

/// The tags by which a template names another.
const NAMING: [&str; 3] = ["include", "extends", "import"];

/// What a source may name of askama.
const ADMITTED: [&str; 3] = ["Template", "Result", "Error"];

fn remove_blanks(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn is_html(named: &str) -> bool {
    Path::new(named)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("html"))
}

/// A path that stays under `templates/`, where the scan reads.
fn is_kept_inside(named: &str) -> bool {
    !named.starts_with('/') && !named.contains("..")
}

/// What may stand in a script or a style, blanks removed: the nonce, and a
/// file brought whole that is no HTML template, so is scanned as text.
fn remove_admitted_tags(inside: &str) -> String {
    let mut left = inside.replace("nonce=\"{{nonce}}\"", "");
    while let Some(start) = left.find("{%include\"") {
        let rest = &left[start + "{%include\"".len()..];
        let Some((named, after)) = rest.split_once('"') else {
            break;
        };
        let Some(after) = after.strip_prefix("%}") else {
            break;
        };
        if is_html(named) {
            break;
        }
        left = format!("{}{after}", &left[..start]);
    }
    left
}

/// Checks a template: `Err` names what would let a value through.
fn check_template(name: &str, template: &str) -> Result<(), String> {
    let compact = remove_blanks(template);
    if let Some(form) = DISARMING.into_iter().find(|form| compact.contains(form)) {
        return Err(form.to_owned());
    }
    for tag in NAMING {
        for after in compact.split(&format!("{tag}\"")).skip(1) {
            let named = after.split('"').next().unwrap_or_default();
            if !is_kept_inside(named) {
                return Err(format!("{tag} \"{named}\""));
            }
        }
    }
    if !is_html(name) {
        return match ["{{", "{%"].into_iter().find(|tag| compact.contains(tag)) {
            Some(tag) => Err(format!("{tag} in a template that is no HTML")),
            None => Ok(()),
        };
    }
    let lowered = compact.to_lowercase();
    for element in ["script", "style"] {
        for after in lowered.split(&format!("<{element}")).skip(1) {
            let inside = after
                .split(&format!("</{element}"))
                .next()
                .unwrap_or_default();
            let left = remove_admitted_tags(inside);
            if left.contains("{{") || left.contains("{%") {
                return Err(format!("a value in the {element}"));
            }
        }
    }
    Ok(())
}

/// Checks a source: the number of pages it derives, or `Err` with what
/// would let a value through.
fn check_source(source: &str) -> Result<usize, String> {
    let compact = remove_blanks(source);
    for (at, _) in compact.match_indices("askama::") {
        let named = &compact[at + "askama::".len()..];
        let admitted = ADMITTED.into_iter().any(|item| {
            named.strip_prefix(item).is_some_and(|after| {
                !after
                    .starts_with(|character: char| character.is_alphanumeric() || character == '_')
            })
        });
        if !admitted {
            let shown: String = named.chars().take(24).collect();
            return Err(format!("askama::{shown}"));
        }
    }
    for attribute in compact.split("#[cfg_attr(").skip(1) {
        let attribute = attribute.split(")]").next().unwrap_or_default();
        if attribute.to_lowercase().contains("template") {
            return Err(format!("cfg_attr({attribute})"));
        }
    }
    let derived = compact
        .split("#[derive(")
        .skip(1)
        .filter_map(|list| list.split(")]").next())
        .filter(|list| {
            list.split(',')
                .any(|item| item == "Template" || item.ends_with("::Template"))
        })
        .count();
    let attributes: Vec<&str> = compact
        .split("#[template(")
        .skip(1)
        .map(|attribute| attribute.split(")]").next().unwrap_or_default())
        .collect();
    if attributes.len() != derived {
        return Err(format!(
            "{derived} derived pages for {} templates named",
            attributes.len()
        ));
    }
    for attribute in attributes {
        let named = attribute
            .strip_prefix("path=\"")
            .and_then(|rest| rest.strip_suffix('"'))
            .filter(|named| is_html(named) && !named.contains('"'));
        match named {
            Some(named) if is_kept_inside(named) => {}
            _ => return Err(format!("template({attribute})")),
        }
    }
    Ok(derived)
}

fn collect_files(folder: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(folder).expect("a readable folder") {
        let path = entry.expect("a readable entry").path();
        if path.is_dir() {
            collect_files(&path, found);
        } else {
            found.push(path);
        }
    }
}

fn read_crate_folder(name: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    collect_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join(name),
        &mut found,
    );
    found
}

#[test]
fn no_template_lets_a_value_through_unescaped() {
    let templates = read_crate_folder("templates");

    for path in &templates {
        let template = fs::read_to_string(path).expect("a readable template");
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        assert_eq!(
            check_template(name, &template),
            Ok(()),
            "{} lets a value through",
            path.display()
        );
    }
    assert!(
        templates.len() >= 9,
        "the scan found {} templates: it reads nothing",
        templates.len()
    );
}

#[test]
fn no_source_reaches_askama_for_more_than_its_pages() {
    let mut derived = 0;

    for path in read_crate_folder("src") {
        let source = fs::read_to_string(&path).expect("a readable source");
        match check_source(&source) {
            Ok(pages) => derived += pages,
            Err(form) => panic!("{}: {form}", path.display()),
        }
    }
    assert!(
        derived >= 6,
        "the scan found {derived} pages: it reads nothing"
    );
}

#[test]
fn the_scan_tells_a_value_written_as_text_from_one_let_through() {
    for (name, written) in [
        ("page.html", "<p>{{ name }}</p>"),
        ("page.html", "<p>{{ name|escape }}</p>"),
        (
            "page.html",
            "{% for scope in scopes %}<li>{{ scope }}</li>{% endfor %}",
        ),
        (
            "page.html",
            "{% extends \"base.html\" %}{% include \"login/form.html\" %}",
        ),
        (
            "base.html",
            "<style nonce=\"{{ nonce }}\">{# -#}\n body{margin:0}</style>\
             <script nonce=\"{{ nonce }}\">{% include \"key_script.js\" %}</script>",
        ),
        (
            "key_script.js",
            "{#- what it does -#}\n(function () { var a = {}; })();",
        ),
    ] {
        assert_eq!(check_template(name, written), Ok(()), "{written}");
    }
    for (name, let_through) in [
        ("page.html", "<p>{{ name|safe }}</p>"),
        ("page.html", "<p>{{ name | safe }}</p>"),
        ("page.html", "<p>{{ name|e(\"txt\") }}</p>"),
        ("page.html", "<p>{{ name|escape( \"none\" ) }}</p>"),
        ("page.html", "{% filter safe %}{{ name }}{% endfilter %}"),
        (
            "page.html",
            "{%- filter escape(\"txt\") -%}{{ name }}{% endfilter %}",
        ),
        ("page.html", "<p>{{ Safe(name) }}</p>"),
        ("page.html", "<p>{{ askama::filters::safe(name, ())? }}</p>"),
        (
            "page.html",
            "<p>{{ askama::filters::escape(name, askama::filters::Text)? }}</p>",
        ),
        ("page.html", "<p>{{ filters::safe(name, ())? }}</p>"),
        ("page.html", "{% include \"../outside.html\" %}"),
        ("page.html", "{% include \"/etc/outside.html\" %}"),
        ("page.html", "{% extends \"../base.html\" %}"),
        ("page.html", "{% import \"/macros.html\" as macros %}"),
        ("key_script.js", "var name = \"{{ name }}\";"),
        ("key_style.css", "{% if dark %}body{color:#fff}{% endif %}"),
        (
            "page.html",
            "<script nonce=\"{{ nonce }}\">var name = \"{{ name }}\";</script>",
        ),
        (
            "page.html",
            "<style nonce=\"{{ nonce }}\">{% if dark %}body{color:#fff}{% endif %}</style>",
        ),
        (
            "page.html",
            "<script nonce=\"{{ nonce }}\">{% include \"values.html\" %}</script>",
        ),
    ] {
        assert!(check_template(name, let_through).is_err(), "{let_through}");
    }
}

#[test]
fn the_scan_tells_a_page_escaped_by_askama_from_one_let_through() {
    let page = "use askama::Template;\n\
                #[derive(Template)]\n\
                #[template(path = \"login/sign_in.html\")]\n\
                struct SignInPage;\n\
                fn answer(rendered: askama::Result<String>) {}\n\
                fn fail() -> askama::Error { askama::Error::Fmt }";
    assert_eq!(check_source(page), Ok(1));

    for let_through in [
        "use askama::filters::Safe;",
        "use askama::{Template, filters};",
        "impl askama :: filters :: HtmlSafe for Name {}",
        "fn wrap(name: &str) -> askama::filters::MaybeSafe<&str> {}",
        "#[derive(Template)]\n#[template(path = \"a.html\", escape = \"none\")]\nstruct A;",
        "#[derive(Template)]\n# [ template ( path = \"a.html\" , escape = \"none\" ) ]\nstruct A;",
        "#[derive(Template)]\n#[template(path = \"a.txt\")]\nstruct A;",
        "#[derive(Template)]\n#[template(path = \"../a.html\")]\nstruct A;",
        "#[derive(Template)]\n#[template(path = \"/a.html\")]\nstruct A;",
        "#[derive(Debug, Template)]\nstruct A;",
        "#[derive(Template)]\n#[template(path = \"a.html\")]\n#[cfg_attr(test, template(path = \"a.txt\"))]\nstruct A;",
    ] {
        assert!(check_source(let_through).is_err(), "{let_through}");
    }
}
