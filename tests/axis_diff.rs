// SPDX-License-Identifier: Apache-2.0

//! The two axes, compared per file, have to name the same files.
//!
//! `scripts/axis-diff.py` compares what the pack engine answers with what
//! the direct engine answers over the same tree, per file. The comparison
//! only means something when both sides name the same file the same way,
//! and the first version got that by GUESS: the pack arm was given no
//! root, so it printed a bare relative path where the direct arm printed
//! an absolute one, and the key was inferred from a cargo registry marker
//! and then from a list of directory names that look like a root
//! component. On any corpus that is not a cargo registry nothing lined up
//! at all: every file came out "only in ref" and "only in packs", and the
//! verdict said SUBSET about a pack that had never been asked.
//!
//! What this holds down: the two arms are given the same root, so they
//! print the same string for the same file, and the key is the path under
//! that root. And a store that was built over ANOTHER tree is refused with
//! a message instead of a verdict, because the counts of two different
//! trees say nothing about the pack. A store that is not there at all is
//! refused the same way, because `rgx --tv-store` builds one over the root
//! when the path holds none -- and a harness that let that through would be
//! measuring a store it built itself.

use std::path::PathBuf;
use std::process::Command;

mod common;

fn rgx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rgx"))
}

///
/// The directory is one of this run's own: `common::scratch` owns the rule
/// its name follows, and the rule is written down there.
fn scratch(tag: &str) -> PathBuf {
    common::scratch(&format!("axis-diff-{tag}"))
}

/// The python that runs the script, or None when the machine has none.
///
/// The script is a harness and not part of the product, so a machine
/// without a python does not fail the gate over it: the comparison is
/// simply not made there. The CI runners carry one on all three
/// platforms, so the comparison IS made there.
fn python() -> Option<&'static str> {
    for name in ["python3", "python"] {
        let ok = Command::new(name)
            .arg("-c")
            .arg("pass")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return Some(name);
        }
    }
    None
}

/// Run the comparison and give back the exit code and the two streams.
fn axis_diff(args: &[&str]) -> (i32, String, String) {
    let py = python().expect("the script needs a python");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("axis-diff.py");
    let out = Command::new(py)
        .arg(&script)
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("spawn axis-diff.py");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// One number of the table the script prints.
fn field(stdout: &str, name: &str) -> Option<i64> {
    stdout.lines().find_map(|l| {
        l.trim()
            .strip_prefix(name)
            .and_then(|rest| rest.trim().parse().ok())
    })
}

/// A store over the given tree.
fn build_store(tree: &PathBuf, store: &PathBuf) {
    let out = rgx()
        .arg("--tv-build")
        .arg("--tv-store")
        .arg(store)
        .arg(tree)
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "--tv-build failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The two axes over one tree answer about the same files.
///
/// The corpus is a plain directory with one file that has the needle and
/// one that has not, and the store is built over that same directory. The
/// pack engine holds the tree and the direct engine walks it, and the two
/// have to name the same file the same way -- which is the whole point of
/// the comparison and the thing the guessing key could not do.
#[test]
fn the_two_axes_name_the_same_files_over_the_same_tree() {
    if python().is_none() {
        eprintln!("no python on the PATH; the axis comparison is not made here");
        return;
    }
    let corpus = scratch("same");
    let store = scratch("same-store");
    std::fs::write(corpus.join("a.txt"), b"a needle in a file\n").unwrap();
    std::fs::write(corpus.join("b.txt"), b"nothing to see here\n").unwrap();
    build_store(&corpus, &store);

    let (code, stdout, stderr) = axis_diff(&[
        "--root",
        corpus.to_str().unwrap(),
        "--store",
        store.to_str().unwrap(),
        "--rgx",
        env!("CARGO_BIN_EXE_rgx"),
        "--pattern",
        "needle",
    ]);
    assert_eq!(code, 0, "the comparison did not pass:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("VERDICT: SUPERSET"),
        "the pack is not a superset of the direct answer:\n{stdout}"
    );
    assert_eq!(
        field(&stdout, "files in ref"),
        Some(1),
        "the direct arm did not find the one file:\n{stdout}"
    );
    assert_eq!(
        field(&stdout, "files in packs"),
        Some(1),
        "the pack did not find the one file:\n{stdout}"
    );
    assert_eq!(
        field(&stdout, "in common"),
        Some(1),
        "the two sides did not name the same file:\n{stdout}"
    );
    assert_eq!(
        field(&stdout, "only in ref"),
        Some(0),
        "the direct arm had a file the pack did not:\n{stdout}"
    );
    assert_eq!(
        field(&stdout, "only in packs"),
        Some(0),
        "the pack had a file the direct arm did not:\n{stdout}"
    );
}

/// A store over another tree is refused, and no verdict is printed.
///
/// The counts of two different trees say nothing about the pack, and a
/// verdict about them reads as a finding about the engine. The harness
/// has to say that the two sides are not comparable and stop there.
#[test]
fn a_store_over_another_tree_is_refused_and_no_verdict_is_printed() {
    if python().is_none() {
        eprintln!("no python on the PATH; the axis comparison is not made here");
        return;
    }
    let corpus = scratch("mine");
    let other = scratch("other");
    let store = scratch("other-store");
    std::fs::write(corpus.join("a.txt"), b"a needle in a file\n").unwrap();
    std::fs::write(other.join("b.txt"), b"a needle in another file\n").unwrap();
    // The store holds the OTHER tree, and the comparison is asked about
    // the first one.
    build_store(&other, &store);

    let (code, stdout, stderr) = axis_diff(&[
        "--root",
        corpus.to_str().unwrap(),
        "--store",
        store.to_str().unwrap(),
        "--rgx",
        env!("CARGO_BIN_EXE_rgx"),
        "--pattern",
        "needle",
    ]);
    assert_eq!(code, 2, "the mismatch was not refused:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("VERDICT"),
        "a verdict was printed about two different trees:\n{stdout}"
    );
    assert!(
        stderr.contains("another tree"),
        "the refusal did not say what was wrong:\n{stderr}"
    );
}

/// A store that is not there is refused, and nothing is built in its place.
///
/// `rgx --tv-store` builds a store over the root when the path holds no
/// store, so a harness that let a missing store through would compare the
/// direct answer against a store it had just built: the verdict would be
/// about that store and not about the pack the caller named, and the
/// harness would have written to a path nobody asked it to write to. The
/// refusal comes before anything is run, and the path is still empty
/// afterwards.
#[test]
fn a_store_that_is_not_there_is_refused_and_nothing_is_built() {
    if python().is_none() {
        eprintln!("no python on the PATH; the axis comparison is not made here");
        return;
    }
    let corpus = scratch("absent");
    // A path that does not exist: the scratch dir is made, the store in it
    // is not.
    let store = scratch("absent-store").join("store");
    std::fs::write(corpus.join("a.txt"), b"a needle in a file\n").unwrap();
    assert!(!store.exists(), "the store path was there before the run");

    let (code, stdout, stderr) = axis_diff(&[
        "--root",
        corpus.to_str().unwrap(),
        "--store",
        store.to_str().unwrap(),
        "--rgx",
        env!("CARGO_BIN_EXE_rgx"),
        "--pattern",
        "needle",
    ]);
    assert_eq!(
        code, 2,
        "the missing store was not refused:\n{stdout}\n{stderr}"
    );
    assert!(
        !stdout.contains("VERDICT"),
        "a verdict was printed about a store that was not there:\n{stdout}"
    );
    assert!(
        stderr.contains("no pack store"),
        "the refusal did not say what was wrong:\n{stderr}"
    );
    assert!(
        !store.exists(),
        "the harness built the store itself: {}",
        store.display()
    );
}
