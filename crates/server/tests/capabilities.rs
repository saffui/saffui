//! A handler of the administration plane that declares no capability would
//! have no guard in front of it. This reads the sources: every verb macro
//! under `endpoints/admin` carries the guard and the capability it requires.

use std::fs;
use std::path::Path;

const VERBS: [&str; 5] = ["#[get(", "#[post(", "#[put(", "#[delete(", "#[patch("];
const GUARD: &str = "wrap = \"RequireCapability(Capability::";

/// Each verb macro of a source, as written, with the function under it.
/// The formatter breaks a long macro over several lines: it is read whole.
fn collect_handlers(source: &str) -> Vec<(String, String)> {
    let mut handlers = Vec::new();
    let mut written: Option<String> = None;
    let mut closed = false;
    for line in source.lines() {
        let line = line.trim();
        if VERBS.iter().any(|verb| line.starts_with(verb)) {
            closed = line.ends_with(")]");
            written = Some(line.to_owned());
        } else if let Some(macro_text) = written.as_mut().filter(|_| !closed) {
            macro_text.push(' ');
            macro_text.push_str(line);
            closed = line.ends_with(")]");
        } else if let Some((_, after)) = line.split_once("async fn ")
            && let Some(macro_text) = written.take()
        {
            let name: String = after
                .chars()
                .take_while(|character| character.is_alphanumeric() || *character == '_')
                .collect();
            handlers.push((name, macro_text));
        }
    }
    handlers
}

#[test]
fn every_handler_of_the_administration_plane_declares_the_capability_it_requires() {
    let folder = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api/rest/endpoints/admin");
    let mut seen = 0;
    for entry in fs::read_dir(&folder).expect("the admin endpoints exist") {
        let path = entry.expect("a readable entry").path();
        let source = fs::read_to_string(&path).expect("a readable source");
        for (name, written) in collect_handlers(&source) {
            seen += 1;
            assert!(
                written.contains(GUARD),
                "{}: {name} declares no capability (found {written:?})",
                path.display()
            );
        }
    }
    assert!(
        seen >= 2,
        "the scan found {seen} handlers: it reads nothing"
    );
}

#[test]
fn the_scan_tells_a_handler_that_declares_its_capability_from_one_that_does_not() {
    const SOURCE: &str = r#"
#[get("/admin/v1/realms/{realm}", wrap = "RequireCapability(Capability::RealmRead)")]
pub async fn read_realm(caller: Caller, product: web::Data<Product>) -> HttpResponse {
}

#[get(
    "/admin/v1/realms/{realm}/clients",
    wrap = "RequireCapability(Capability::ClientRead)"
)]
pub async fn list_clients(caller: Caller) -> HttpResponse {
}

#[post("/admin/v1/realms/{realm}/open")]
pub async fn leave_open(
    product: web::Data<Product>,
) -> HttpResponse {
}

pub async fn help_without_a_macro(product: web::Data<Product>) -> HttpResponse {
}
"#;

    let handlers = collect_handlers(SOURCE);

    assert_eq!(handlers.len(), 3);
    assert_eq!(handlers[0].0, "read_realm");
    assert!(handlers[0].1.contains(GUARD));
    assert_eq!(handlers[1].0, "list_clients");
    assert!(
        handlers[1].1.contains(GUARD),
        "a macro broken over several lines is read whole: {:?}",
        handlers[1]
    );
    assert_eq!(handlers[2].0, "leave_open");
    assert!(
        !handlers[2].1.contains(GUARD),
        "a route without a declared capability is seen as open: {:?}",
        handlers[2]
    );
}
