//! A page writes what it shows as text only while nothing turns its
//! escaping off. This reads the templates and the derives that name them:
//! no template lets a value through or picks another escaper, no derive
//! picks one, and no type is marked safe to write as it is.

use std::fs;
use std::path::{Path, PathBuf};

/// What lets a value through a template, blanks removed: the filter that
/// marks it safe, a filter that names its own escaper, the same two over a
/// block, and the wrappers askama writes as they are.
const DISARMING: [&str; 7] = [
    "|safe",
    "|escape(",
    "|e(",
    "filtersafe",
    "filterescape(",
    "filtere(",
    "Safe",
];

/// What marks a Rust type as written without escaping.
const MARKERS: [&str; 2] = ["HtmlSafe", "MaybeSafe"];

fn find_disarming(template: &str) -> Option<&'static str> {
    let compact: String = template
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    DISARMING.into_iter().find(|form| compact.contains(form))
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
        assert_eq!(
            find_disarming(&template),
            None,
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
fn no_page_picks_its_own_escaper_and_no_type_is_written_as_it_is() {
    let mut derived = 0;

    for path in read_crate_folder("src") {
        let source = fs::read_to_string(&path).expect("a readable source");
        for attribute in source.split("#[template(").skip(1) {
            let (attribute, _) = attribute.split_once(")]").expect("a closed attribute");
            derived += 1;
            assert!(
                attribute.trim().starts_with("path = ")
                    && attribute.trim().ends_with(".html\"")
                    && !attribute.contains("escape"),
                "{}: a page names an HTML template and nothing else ({attribute})",
                path.display()
            );
        }
        for marker in MARKERS {
            assert!(!source.contains(marker), "{}: {marker}", path.display());
        }
    }
    assert!(
        derived >= 6,
        "the scan found {derived} pages: it reads nothing"
    );
}

#[test]
fn the_scan_tells_a_value_written_as_text_from_one_let_through() {
    for written in [
        "<p>{{ name }}</p>",
        "<p>{{ name|escape }}</p>",
        "{% for scope in scopes %}<li>{{ scope }}</li>{% endfor %}",
    ] {
        assert_eq!(find_disarming(written), None, "{written}");
    }
    for let_through in [
        "<p>{{ name|safe }}</p>",
        "<p>{{ name | safe }}</p>",
        "<p>{{ name|e(\"txt\") }}</p>",
        "<p>{{ name|escape( \"none\" ) }}</p>",
        "{% filter safe %}{{ name }}{% endfilter %}",
        "{%- filter escape(\"txt\") -%}{{ name }}{% endfilter %}",
        "<p>{{ askama::filters::Safe(name) }}</p>",
    ] {
        assert!(find_disarming(let_through).is_some(), "{let_through}");
    }
}
