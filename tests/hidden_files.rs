// SPDX-License-Identifier: Apache-2.0
//! The hidden-file policy, end to end: the real binary over a real tree.
//!
//! **The hidden files are read by default.** A format that keeps its own
//! metadata in a dotfile — a Zarr array's `.zarray`, a `.zattrs`, a
//! `.gitignore` — is invisible otherwise, and a search tool that cannot see
//! the metadata cannot read the format. `--no-hidden` puts ripgrep's
//! default back.
//!
//! **The repository's own state is never read**, whatever the flag says. It
//! is metadata *about* the corpus rather than the corpus, and it is
//! routinely larger than the tree it describes. The rules inside it are
//! still applied — a `.gitignore` and a `.git/info/exclude` are read and
//! honoured — they are just not listed.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

const NEEDLE: &str = "needle";

fn rgx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rgx"))
}

/// A tree with a hidden file, a hidden directory, and a repository's own
/// state in it.
///
/// The directory is one of this run's own: `common::scratch` owns the rule
/// its name follows, and the rule is written down there.
fn tree() -> PathBuf {
    let dir = common::scratch("hidden");
    std::fs::create_dir_all(dir.join(".cache")).unwrap();
    std::fs::create_dir_all(dir.join(".git/objects")).unwrap();
    let in_needle = |what: &str| format!("{NEEDLE} {what}\n");
    std::fs::write(dir.join("plain.txt"), in_needle("in the open")).unwrap();
    std::fs::write(dir.join(".notes.txt"), in_needle("in a dotfile")).unwrap();
    std::fs::write(dir.join(".cache/inside.txt"), in_needle("in a hidden dir")).unwrap();
    std::fs::write(dir.join(".git/config"), in_needle("in the repo state")).unwrap();
    std::fs::write(dir.join(".git/objects/aa"), in_needle("in the repo state")).unwrap();
    dir
}

/// No user configuration: a `.rgxrc` in the home directory would change what
/// the walk does, and this test is about the walk.
fn hermetic(dir: &Path) {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    for k in ["HOME", "USERPROFILE", "XDG_CONFIG_HOME"] {
        std::env::set_var(k, &home);
    }
}

/// The files rgx reports a needle in, as paths relative to the tree.
fn listed(dir: &Path, args: &[&str]) -> Vec<String> {
    let out = rgx()
        .args(args)
        .arg("-l")
        .arg(NEEDLE)
        .arg(dir)
        .output()
        .expect("rgx runs");
    assert!(
        out.status.success(),
        "rgx failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut files: Vec<String> = String::from_utf8_lossy(&out.stdout)
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

#[test]
fn the_hidden_files_are_read_by_default() {
    let dir = tree();
    hermetic(&dir);
    assert_eq!(
        listed(&dir, &[]),
        vec![
            ".cache/inside.txt".to_string(),
            ".notes.txt".to_string(),
            "plain.txt".to_string(),
        ]
    );
}

#[test]
fn no_hidden_skips_the_hidden_files() {
    let dir = tree();
    hermetic(&dir);
    assert_eq!(
        listed(&dir, &["--no-hidden"]),
        vec!["plain.txt".to_string()]
    );
}

#[test]
fn the_hidden_flag_is_still_accepted() {
    let dir = tree();
    hermetic(&dir);
    // It is the default now, so the flag changes nothing -- but it is
    // accepted, because a script that passes it should not break.
    assert_eq!(listed(&dir, &["--hidden"]), listed(&dir, &[]));
}

#[test]
fn the_repository_state_is_never_read() {
    let dir = tree();
    hermetic(&dir);
    // Nor with the ignore rules turned off: the state directory is not
    // corpus, and no flag says it is.
    for args in [vec![], vec!["--no-ignore"], vec!["--no-ignore", "--hidden"]] {
        let found = listed(&dir, &args);
        assert!(
            !found.iter().any(|f| f.starts_with(".git/")),
            "the repository state was read with {args:?}: {found:?}"
        );
    }
}
