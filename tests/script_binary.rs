// SPDX-License-Identifier: Apache-2.0

//! Every script that names the rgx binary has to name it the way the host
//! names it.
//!
//! The first version of this class of harness wrote down the Windows name
//! (`rgx.exe`), so on a Unix host it resolved nothing at all; the ones
//! that took the other direction wrote down the bare name, so on the
//! Windows host they resolved nothing either. One of them did both: it
//! stripped the `.exe` and added it straight back, so it always ended up
//! on the spelling that does not exist -- and the `diodicity` harness,
//! whose TV arm stripped a `.exe` that was not there and added one that
//! was, always ended up on the name that does not exist.
//!
//! The house's own idiom is the Windows name first and then the bare one
//! -- `benchmark/diffrig/fuzz.py` and `scripts/bench-status.sh` wrote it
//! down first -- and this holds the tree to it.

use std::path::{Path, PathBuf};

/// The scripts that name one platform's binary on purpose.
///
/// A script of this list is that platform's own: the Linux half of a pair
/// whose other half is the Windows one, the script that builds the Linux
/// artifacts in Docker, the orchestrator that runs on the Windows host,
/// and the harness that drives the Win32 API. Each of them names the
/// binary the way its own host names it.
///
/// The list is checked against the tree: a file of it that is gone or
/// renamed is a hole in the rule, and the test says so rather than
/// quietly shrinking the rule.
const PLATFORM_SIDE: &[&str] = &[
    // The Linux half of a pair whose other half is the Windows one.
    "scripts/build-release.sh",
    "benchmark/extent-ab.sh",
    // It builds the Linux artifacts in Docker, on a Linux host.
    "scripts/build-linux.sh",
    // The orchestrator of the Windows release: it runs on the Windows host
    // and packages the Windows artifacts.
    "scripts/release-all.sh",
    // The Win32 API harness, whose Unix twin is the POSIX-pty one.
    "benchmark/diffrig/conpty.py",
];

/// The scripts of the tree, and the harnesses under `benchmark/`.
fn scripts() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    for dir in ["scripts", "benchmark"] {
        collect(&root.join(dir), &mut out);
    }
    out.sort();
    out
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
            continue;
        }
        let name = path.to_string_lossy();
        if name.ends_with(".sh") || name.ends_with(".py") {
            out.push(path);
        }
    }
}

/// The path of a script, relative to the repository root.
fn relative(path: &Path) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.strip_prefix(&root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// The script names the binary it runs.
fn names_the_binary(text: &str) -> bool {
    text.contains("rgx.exe") || text.contains("release/rgx")
}

/// The Windows spelling is on offer.
fn offers_the_windows_name(text: &str) -> bool {
    text.contains("rgx.exe")
}

/// The bare spelling is on offer: named in full, held in a list of names,
/// or reached by stripping the `.exe` off the Windows one.
fn offers_the_bare_name(text: &str) -> bool {
    if text.contains("%.exe") {
        return true;
    }
    let without_windows = text.replace("rgx.exe", "");
    without_windows.contains("\"rgx\"")
        || without_windows.contains("'rgx'")
        || without_windows.contains("release/rgx")
}

/// A spelling is FORCED when the script strips the `.exe` and adds it
/// straight back: the path it builds is then always the one the host does
/// not have.
fn forces_a_spelling(text: &str) -> bool {
    text.lines().any(|line| match line.find("%.exe") {
        Some(i) => line[i + 5..].contains(".exe"),
        None => false,
    })
}

#[test]
fn every_script_that_names_the_binary_offers_both_spellings() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for name in PLATFORM_SIDE {
        assert!(
            root.join(name).exists(),
            "the platform-side script {name} is gone or renamed: the list of \\
             the exceptions has to be the truth, not a history"
        );
    }

    let mut checked = 0;
    for path in scripts() {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if !names_the_binary(&text) {
            continue;
        }
        let name = relative(&path);
        if PLATFORM_SIDE.contains(&name.as_str()) {
            continue;
        }
        checked += 1;
        assert!(
            offers_the_windows_name(&text),
            "{name} names the binary without the Windows spelling: it resolves \\
             nothing on the Windows host"
        );
        assert!(
            offers_the_bare_name(&text),
            "{name} names the binary without the bare spelling: it resolves \\
             nothing on the Unix host"
        );
        assert!(
            !forces_a_spelling(&text),
            "{name} forces a spelling: it strips the .exe and adds it straight \\
             back, so it always ends up on the name the host does not have"
        );
    }
    assert!(
        checked >= 10,
        "the scan found only {checked} scripts that name the binary: the walk \\
         is broken, and a green run over nothing is not a green run"
    );
}
