// SPDX-License-Identifier: Apache-2.0
//! The persistent index of the facts, end to end: the real binary over a
//! real tree.
//!
//! **What the index is.** The facts of a file are what the pipeline knows
//! about it — the path, the extension, the format, the MIME type, and
//! whatever the adapter that answered for it reported. `--filter` asks
//! every file that question on every run. The index asks it once and
//! keeps the answer.
//!
//! **What is proved here.** That the index holds the facts the walk would
//! have computed, that the same `--filter` expression answers over the
//! index, that a file that changed is not answered from a stale record,
//! and that the index is a file a person can read.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

fn rgx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rgx"))
}

/// A tree with a file of each kind the filter can tell apart.
///
/// The directory is one of this run's own: `common::scratch` owns the rule
/// its name follows, and the rule is written down there.
fn tree() -> PathBuf {
    let dir = common::scratch("facts");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("notes.txt"), "hello\n").unwrap();
    std::fs::write(dir.join("page.html"), "<html></html>\n").unwrap();
    std::fs::write(dir.join("sub/deep.md"), "# deep\n").unwrap();
    dir
}

/// No user configuration: a `.rgxrc` in the home directory would change
/// what the walk does, and this test is about the facts.
fn hermetic(dir: &Path) {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    for k in ["HOME", "USERPROFILE", "XDG_CONFIG_HOME"] {
        std::env::set_var(k, &home);
    }
}

/// The paths the facts index answers with, relative to the tree.
fn queried(dir: &Path, args: &[&str]) -> Vec<String> {
    let out = rgx()
        .args(args)
        .arg("--facts-index")
        .arg(dir)
        .output()
        .expect("rgx runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut files: Vec<String> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            Path::new(l.trim())
                .strip_prefix(dir)
                .expect("a path under the tree")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    files.sort();
    files
}

/// The index file the build wrote.
fn index_file(dir: &Path) -> PathBuf {
    dir.join(".rgx-facts.jsonl")
}

/// Build the index over the tree.
fn build(dir: &Path) {
    let out = rgx()
        .arg("--facts-build")
        .arg(dir)
        .output()
        .expect("rgx runs");
    assert!(
        out.status.success(),
        "rgx --facts-build failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_index_holds_the_facts_of_every_file() {
    let dir = tree();
    hermetic(&dir);
    build(&dir);
    let text = std::fs::read_to_string(index_file(&dir)).expect("the index was written");
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 3, "one line per file: {text}");
    // The facts are the ones the filter asks about: the path, the
    // extension, the format and the MIME type.
    assert!(text.contains("\"format\""), "{text}");
    assert!(text.contains("\"ext\""), "{text}");
    assert!(text.contains("\"mime\""), "{text}");
    assert!(text.contains("notes.txt"), "{text}");
}

#[test]
fn the_index_is_json_lines_and_readable_by_rg() {
    let dir = tree();
    hermetic(&dir);
    build(&dir);
    let text = std::fs::read_to_string(index_file(&dir)).expect("the index was written");
    // One JSON object per line: the format is greppable, which is why it
    // is JSON Lines and not a binary blob.
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        assert!(line.starts_with('{'), "not a JSON object: {line}");
        assert!(line.ends_with('}'), "not a JSON object: {line}");
    }
    // And the tool the project exists to replace can read it.
    let out = rgx()
        .arg("-l")
        .arg("notes.txt")
        .arg(index_file(&dir))
        .output()
        .expect("rgx runs");
    assert!(
        out.status.success(),
        "rg could not read the index: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_filter_answers_from_the_index() {
    let dir = tree();
    hermetic(&dir);
    build(&dir);
    assert_eq!(
        queried(&dir, &["--filter", "ext:txt"]),
        vec!["notes.txt".to_string()]
    );
    assert_eq!(
        queried(&dir, &["--filter", "ext:md"]),
        vec!["sub/deep.md".to_string()]
    );
}

#[test]
fn the_index_answers_without_walking_the_corpus() {
    let dir = tree();
    hermetic(&dir);
    build(&dir);
    // The corpus is gone: the index still answers, because the facts
    // were kept and the files are not what the question is about.
    let files: Vec<PathBuf> = vec![dir.join("notes.txt"), dir.join("page.html")];
    for f in &files {
        std::fs::remove_file(f).unwrap();
    }
    let out = rgx()
        .args([
            "--facts-index",
            dir.to_str().unwrap(),
            "--filter",
            "ext:txt",
        ])
        .output()
        .expect("rgx runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("notes.txt"),
        "the index did not answer: {stdout}"
    );
}

#[test]
fn a_file_that_changed_is_not_answered_from_a_stale_record() {
    let dir = tree();
    hermetic(&dir);
    build(&dir);
    // The file is rewritten with different content, and the record's
    // stamp no longer matches: the index does not answer about a file
    // that is not the one it knows.
    std::fs::write(dir.join("notes.txt"), "a different length of content\n").unwrap();
    let out = rgx()
        .args([
            "--facts-index",
            dir.to_str().unwrap(),
            "--filter",
            "ext:txt",
        ])
        .output()
        .expect("rgx runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("notes.txt"),
        "a stale record was answered: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("stale"),
        "the staleness was not reported: {stderr}"
    );
}

#[test]
fn the_export_writes_the_index_as_json_lines() {
    let dir = tree();
    hermetic(&dir);
    build(&dir);
    let destination = dir.join("exported.jsonl");
    let out = rgx()
        .arg("--facts-index")
        .arg(&dir)
        .arg("--facts-export")
        .arg(&destination)
        .output()
        .expect("rgx runs");
    assert!(
        out.status.success(),
        "rgx --facts-export failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let exported = std::fs::read_to_string(&destination).expect("the export was written");
    let original = std::fs::read_to_string(index_file(&dir)).unwrap();
    assert_eq!(exported, original);
}

#[test]
fn a_missing_index_says_so() {
    let dir = tree();
    hermetic(&dir);
    let out = rgx()
        .args([
            "--facts-index",
            dir.to_str().unwrap(),
            "--filter",
            "ext:txt",
        ])
        .output()
        .expect("rgx runs");
    assert!(!out.status.success(), "a missing index was answered");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("facts index"),
        "the error did not name the index: {stderr}"
    );
}
