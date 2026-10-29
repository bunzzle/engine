use std::fs;
use std::path::{Path, PathBuf};

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn unsafe_code_lives_only_in_sys() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir");
    let root = fs::read_to_string(crates.join("../Cargo.toml")).expect("workspace manifest");
    assert!(root.contains("unsafe_code = \"forbid\""));
    for entry in fs::read_dir(crates).expect("read crates") {
        let dir = entry.expect("entry").path();
        if dir.file_name().is_some_and(|n| n == "sys") {
            continue;
        }
        let manifest = fs::read_to_string(dir.join("Cargo.toml")).expect("manifest");
        assert!(
            manifest.contains("[lints]\nworkspace = true"),
            "{} must use the workspace lints",
            dir.display()
        );
        let mut files = Vec::new();
        sources(&dir, &mut files);
        for file in files {
            let text = fs::read_to_string(&file).expect("source");
            let found = text
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|word| word == "unsafe" || word == "SAFETY");
            assert!(!found, "{} mentions unsafe", file.display());
        }
    }
}
