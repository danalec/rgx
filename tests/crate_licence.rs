// SPDX-License-Identifier: Apache-2.0

//! Every crate carries the licence, and every crate carries the notice.
//!
//! A crate on crates.io is downloaded on its own: the licence file that
//! travels with it is the one a reader opens, and Apache-2.0 section 4(c)
//! asks for the attribution notices of the NOTICE wherever the work is
//! distributed. Two copies that drift are worse than one copy, so the
//! test compares them instead of trusting them — the same rule the
//! generated tables follow, where a header lost on every regeneration was
//! the bug.

use std::path::{Path, PathBuf};

/// The licence every crate ships.
const LICENCE: &str = "LICENSE-APACHE";
/// The attribution notices every crate ships.
const NOTICE: &str = "NOTICE";
/// The copyright holder the licence names.
const HOLDER: &str = "Copyright 2026 Dan Alec Yamaguchi";

fn crates(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let dir = root.join("crates");
    for entry in std::fs::read_dir(&dir).expect("the tree has a crates directory") {
        let path = entry.expect("a readable entry").path();
        if path.is_dir() {
            out.push(path);
        }
    }
    out.sort();
    out
}

#[test]
fn every_crate_carries_the_licence_and_the_notice() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let notice = std::fs::read_to_string(root.join(NOTICE)).expect("the tree has a NOTICE");

    for dir in crates(&root) {
        let name = dir.file_name().unwrap().to_string_lossy().to_string();

        let licence_path = dir.join(LICENCE);
        let licence = std::fs::read_to_string(&licence_path)
            .unwrap_or_else(|e| panic!("{name}: no {LICENCE}: {e}"));
        assert!(
            licence.contains(HOLDER),
            "{name}: its {LICENCE} names no copyright holder, or names another one"
        );

        let notice_path = dir.join(NOTICE);
        let crate_notice = std::fs::read_to_string(&notice_path)
            .unwrap_or_else(|e| panic!("{name}: no {NOTICE}: {e}"));
        assert_eq!(
            crate_notice, notice,
            "{name}: its {NOTICE} drifted from the tree's"
        );
    }
}

#[test]
fn the_tree_declares_one_licence_everywhere() {
    // The licence field of a package is what crates.io shows on its page.
    // A package that declares something else is a package whose page says
    // something the tree does not.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut manifests = vec![root.join("Cargo.toml")];
    manifests.extend(crates(&root).iter().map(|d| d.join("Cargo.toml")));

    for manifest in manifests {
        let text = std::fs::read_to_string(&manifest).expect("a readable manifest");
        let name = manifest
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Cargo.toml")
            .to_string();
        let field = text
            .lines()
            .find(|l| l.trim_start().starts_with("license"))
            .unwrap_or_else(|| panic!("{name}: no licence field"));
        assert_eq!(
            field.trim(),
            "license = \"Apache-2.0\"",
            "{name}: the licence field is not Apache-2.0"
        );
    }
}
