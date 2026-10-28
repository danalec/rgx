// SPDX-License-Identifier: Apache-2.0

//! The published packages must not carry the EGM contracts.
//!
//! The contracts are the working documents of the review loop: one per
//! directory, gitignored, and about the code rather than of it. They sit
//! inside the packages' source directories, and every manifest in the tree
//! includes `/src/**` -- so cargo carried every one of them into the
//! published crate. The registry is for the code, and a user who installed
//! the crate would have had the project's working papers in their registry
//! cache.
//!
//! The exclusion cannot be an `exclude`: cargo says so itself, "both
//! package.include and package.exclude are specified; the exclude list will
//! be ignored". It has to be a negation inside the `include` list, and the
//! list is per package, so a package added later would carry the contracts
//! unless somebody remembered.
//!
//! This asks cargo what each package would carry, which is the only answer
//! that counts: `cargo package --list` is the list the registry receives.

use std::path::Path;
use std::process::Command;

/// The packages of the workspace: the members the root manifest names, and
/// the root package itself.
fn packages() -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("the root manifest");

    let mut names = Vec::new();
    let mut in_members = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_members = line == "[workspace]";
            continue;
        }
        if !in_members {
            continue;
        }
        if line == "members = [" {
            in_members = true;
            continue;
        }
        if line == "]" {
            break;
        }
        if let Some(member) = line.strip_prefix('"').and_then(|l| l.strip_suffix(',')) {
            let member = member.trim_matches('"');
            if let Some(name) = member.rsplit('/').next() {
                names.push(name.to_string());
            }
        }
    }

    // The root package, which is not a member of itself.
    let mut in_package = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package {
            if let Some(name) = line.strip_prefix("name = ") {
                names.push(name.trim_matches('"').to_string());
                break;
            }
        }
    }
    names
}

/// The files cargo would put in the package.
fn listed(pkg: &str) -> Vec<String> {
    let out = Command::new(env!("CARGO"))
        .args(["package", "--list", "-p", pkg, "--allow-dirty"])
        .output()
        .expect("cargo runs");
    assert!(
        out.status.success(),
        "cargo package --list failed for {pkg}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect()
}

#[test]
fn no_package_carries_a_contract() {
    let packages = packages();
    assert!(
        !packages.is_empty(),
        "the workspace's packages were not found"
    );

    let mut offenders = Vec::new();
    for pkg in &packages {
        for file in listed(pkg) {
            if file.ends_with("EGM.md") {
                offenders.push(format!("{pkg}: {file}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the contracts are working documents and must not go to the registry, \
         but {} would carry one:\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
}

#[test]
fn every_package_names_the_exclusion() {
    // The list is per package, so a package added later would carry the
    // contracts unless somebody remembered. The rule is in the manifest.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut missing = Vec::new();
    for pkg in packages() {
        let dir = if pkg == "rgx-search" {
            root.to_path_buf()
        } else {
            root.join("crates").join(&pkg)
        };
        let manifest = std::fs::read_to_string(dir.join("Cargo.toml"))
            .unwrap_or_else(|e| panic!("{pkg} has a manifest: {e}"));
        if !manifest.contains("!/src/**/EGM.md") {
            missing.push(pkg);
        }
    }
    assert!(
        missing.is_empty(),
        "these packages would carry the contracts, because their include list \
         does not negate them: {}",
        missing.join(", ")
    );
}
