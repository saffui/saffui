//! A handler that carries a verb macro and is not mounted compiles, and
//! answers nowhere. This reads the sources and compares the two lists.

use std::fs;
use std::path::Path;

const VERB_MACROS: [&str; 10] = [
    "get", "post", "put", "delete", "patch", "head", "options", "trace", "connect", "route",
];

/// Where handlers live, under the sources of the crate. `api/config.rs` names
/// each one by its path from here.
const ENDPOINTS: &str = "api/rest/endpoints";

#[test]
fn every_handler_under_a_verb_macro_is_mounted_in_api_config() {
    let sources = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mounting =
        fs::read_to_string(sources.join("api/config.rs")).expect("api/config.rs is readable");

    let handlers = collect_handlers(&sources, &sources.join(ENDPOINTS));
    assert!(
        !handlers.is_empty(),
        "no verb macro was found under src: the scan reads nothing"
    );
    assert_eq!(
        find_shared_name(&handlers),
        None,
        "two handlers give the same name: one mounting line cannot prove both"
    );

    for handler in &handlers {
        assert!(
            is_mounted(&mounting, handler),
            "{handler} carries a verb macro and is not mounted in api/config.rs"
        );
    }
}

#[test]
fn the_detector_names_the_function_under_each_verb_macro_of_a_fixed_text() {
    const SOURCE: &str = r#"
        #[derive(Default)]
        pub struct DrainFlag;

        /// Liveness.
        #[get("/livez")]
        pub async fn report_liveness() -> HttpResponse {
            HttpResponse::Ok().finish()
        }

        #[actix_web::post("/token")]
        /// The fn below is the handler, whatever this line seems to name.
        #[allow(clippy::unused_async)]
        pub(crate) async fn handle<'a>(form: web::Form<Grant<'a>>) -> HttpResponse {
            HttpResponse::Ok().finish()
        }

        // #[get("/gone")]
        // pub async fn report_gone() -> HttpResponse {}

        pub async fn help_without_a_macro() {}
    "#;

    assert_eq!(
        find_handler_functions(SOURCE),
        ["report_liveness", "handle"]
    );
}

#[test]
fn a_handler_is_mounted_by_its_whole_path_on_a_line_that_is_not_a_comment() {
    const MOUNTING: &str = "
        config
            .service(health::report_liveness)
            // .service(health::report_readiness)
            .service(oidc::token::handle);
    ";

    assert!(is_mounted(MOUNTING, "health::report_liveness"));
    assert!(is_mounted(MOUNTING, "oidc::token::handle"));
    assert!(
        !is_mounted(MOUNTING, "health::report_readiness"),
        "a commented line mounts nothing"
    );
    assert!(
        !is_mounted(MOUNTING, "token::handle"),
        "a handler is mounted by its whole path, not by the end of it"
    );
}

#[test]
fn a_handler_is_named_by_the_path_of_its_file_under_endpoints() {
    let endpoints = Path::new("src/api/rest/endpoints");
    let name = |file: &str| name_module(endpoints, Path::new(file));

    assert_eq!(
        name("src/api/rest/endpoints/health.rs").as_deref(),
        Some("health::")
    );
    assert_eq!(
        name("src/api/rest/endpoints/oidc/token.rs").as_deref(),
        Some("oidc::token::")
    );
    assert_eq!(
        name("src/api/rest/endpoints/oidc/mod.rs").as_deref(),
        Some("oidc::")
    );
    assert_eq!(name("src/serve.rs"), None, "a file outside has no name");
}

#[test]
fn a_name_that_two_handlers_give_is_found() {
    let handlers = ["health::report", "oidc::token::handle", "health::report"].map(String::from);

    assert_eq!(find_shared_name(&handlers), Some("health::report"));
    assert_eq!(find_shared_name(&handlers[..2]), None);
}

/// Every handler under `directory`, named as `api/config.rs` must write it.
fn collect_handlers(directory: &Path, endpoints: &Path) -> Vec<String> {
    let mut handlers = Vec::new();
    for entry in fs::read_dir(directory).expect("a source directory is readable") {
        let path = entry.expect("a directory entry is readable").path();
        if path.is_dir() {
            handlers.extend(collect_handlers(&path, endpoints));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let source = fs::read_to_string(&path).expect("a source file is readable");
            for function in find_handler_functions(&source) {
                let module = name_module(endpoints, &path).unwrap_or_else(|| {
                    panic!(
                        "{} carries a verb macro outside {ENDPOINTS}",
                        path.display()
                    )
                });
                handlers.push(format!("{module}{function}"));
            }
        }
    }
    handlers
}

/// What `api/config.rs` writes before the function: `oidc::token::` for
/// `oidc/token.rs`, `oidc::` for `oidc/mod.rs`. `None` outside `endpoints`.
fn name_module(endpoints: &Path, file: &Path) -> Option<String> {
    let relative = file.strip_prefix(endpoints).ok()?.with_extension("");
    let mut module = String::new();
    for segment in &relative {
        let segment = segment.to_string_lossy();
        if segment != "mod" {
            module.push_str(&segment);
            module.push_str("::");
        }
    }
    Some(module)
}

/// The function that follows each verb macro of a source text.
fn find_handler_functions(source: &str) -> Vec<&str> {
    let mut lines = read_code_lines(source);
    let mut functions = Vec::new();
    while let Some(line) = lines.next() {
        if is_verb_macro(line) {
            let function = lines
                .by_ref()
                .find_map(name_function)
                .expect("a function follows a verb macro");
            functions.push(function);
        }
    }
    functions
}

/// The lines of a source text, trimmed, without those that are comments.
fn read_code_lines(source: &str) -> impl Iterator<Item = &str> {
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
}

fn is_verb_macro(line: &str) -> bool {
    line.strip_prefix("#[")
        .and_then(|attribute| attribute.split_once('('))
        .is_some_and(|(path, _)| VERB_MACROS.contains(&path.rsplit("::").next().unwrap_or(path)))
}

fn name_function(line: &str) -> Option<&str> {
    let (_, after_keyword) = line.split_once("fn ")?;
    after_keyword.split(['(', '<']).next()
}

fn is_mounted(mounting: &str, handler: &str) -> bool {
    let service = format!(".service({handler})");
    read_code_lines(mounting).any(|line| line.contains(&service))
}

/// A name that two handlers give: one mounting line could not prove both.
fn find_shared_name(handlers: &[String]) -> Option<&str> {
    let mut names: Vec<&str> = handlers.iter().map(String::as_str).collect();
    names.sort_unstable();
    names
        .windows(2)
        .find(|pair| pair[0] == pair[1])
        .map(|pair| pair[0])
}
