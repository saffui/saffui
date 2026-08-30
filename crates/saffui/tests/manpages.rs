//! The manual pages, written by the binary a packager will call.

use std::process::Command;

#[test]
fn the_binary_writes_a_page_per_command() {
    let out = std::env::temp_dir().join(format!("saffui-man-{}", std::process::id()));
    let ran = Command::new(env!("CARGO_BIN_EXE_saffui"))
        .args(["manpages", "--out"])
        .arg(&out)
        .output()
        .expect("the binary runs");
    assert!(ran.status.success(), "{ran:?}");

    let pages: Vec<String> = std::fs::read_dir(&out)
        .expect("the directory was created")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    // One page for the binary, and one per leaf command. The exact count
    // moves with the tree; what must hold is that the tree is covered.
    assert!(pages.contains(&"saffui.1".to_owned()), "{pages:?}");
    assert!(pages.contains(&"saffui-admin.1".to_owned()), "{pages:?}");
    assert!(pages.contains(&"saffui-serve.1".to_owned()), "{pages:?}");
    assert!(pages.iter().all(|named| named.ends_with(".1")), "{pages:?}");
    let body = std::fs::read_to_string(out.join("saffui-admin.1")).expect("a readable page");
    assert!(body.contains(".TH"), "not a roff page: {body:.>40}");

    std::fs::remove_dir_all(&out).ok();
}
