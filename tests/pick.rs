// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for `--pick`, the fzf frontend.
//!
//! The picker is a real external program, so the tests supply one: a script
//! that stands in for `fzf` on the three questions that matter — what it
//! selects, what it exits with, and what argv it was given. The one test that
//! cannot substitute a script (no fzf anywhere on PATH) asserts the error
//! path, which is also the path a user without fzf installed takes.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

/// A stand-in for fzf: a batch file on Windows, a shell script elsewhere.
/// Both read the candidate list on stdin and write the selection on stdout,
/// which is the whole contract rgx depends on.
fn picker(tag: &str, windows_body: &str, unix_body: &str) -> PathBuf {
    let dir = common::scratch(&format!("pick-test-{tag}"));
    if cfg!(windows) {
        let path = dir.join("fakefzf.bat");
        std::fs::write(&path, format!("@echo off\r\n{windows_body}\r\n")).unwrap();
        path
    } else {
        let path = dir.join("fakefzf.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{unix_body}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }
}

///
/// The directory is one of this run's own: `common::scratch` owns the rule
/// its name follows, and the rule is written down there.
fn fixture() -> PathBuf {
    let dir = common::scratch("pick-fixture");
    std::fs::write(dir.join("a.txt"), "alpha needle one\nbeta two\n").unwrap();
    std::fs::write(dir.join("b.txt"), "gamma needle three\ndelta four\n").unwrap();
    dir
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rgx"))
        .args(args)
        .output()
        .expect("failed to spawn rgx");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn pick_with(picker: &Path, pattern: &str, dir: &Path) -> (i32, String, String) {
    run(&[
        "--pick",
        "--fzf-binary",
        picker.to_str().unwrap(),
        pattern,
        dir.to_str().unwrap(),
    ])
}

#[test]
fn a_selection_is_printed_and_exits_zero() {
    let dir = fixture();
    let fzf = picker(
        "select",
        "set /p line=\r\necho %line%",
        "IFS= read -r line\nprintf '%s\\n' \"$line\"",
    );
    let (code, stdout, stderr) = pick_with(&fzf, "needle", &dir);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    assert!(
        stdout.contains("needle"),
        "the selection reaches stdout: {stdout:?}"
    );
    assert_eq!(
        stdout.lines().count(),
        1,
        "exactly what was picked: {stdout:?}"
    );
}

#[test]
fn a_dismissed_picker_exits_one_with_nothing_on_stdout() {
    let dir = fixture();
    let fzf = picker("dismiss", "exit /b 130", "exit 130");
    let (code, stdout, _) = pick_with(&fzf, "needle", &dir);
    assert_eq!(code, 1, "a dismissal is not a selection");
    assert!(stdout.is_empty(), "nothing was chosen: {stdout:?}");
}

#[test]
fn a_search_with_no_matches_exits_one() {
    let dir = fixture();
    let fzf = picker("nomatch", "exit /b 1", "exit 1");
    let (code, stdout, _) = pick_with(&fzf, "no-such-token-anywhere", &dir);
    assert_eq!(code, 1);
    assert!(stdout.is_empty());
}

#[test]
fn a_crashing_picker_is_a_failure_not_a_quiet_no_match() {
    let dir = fixture();
    let fzf = picker("crash", "exit /b 2", "exit 2");
    let (code, _, stderr) = pick_with(&fzf, "needle", &dir);
    assert_eq!(code, 2, "a broken picker is an error: {stderr:?}");
    assert!(stderr.contains("exited with"), "{stderr:?}");
}

#[test]
fn a_missing_picker_says_so_and_exits_two() {
    let dir = fixture();
    let (code, _, stderr) = run(&[
        "--pick",
        "--fzf-binary",
        "rgx-no-such-picker-anywhere",
        "needle",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(code, 2, "{stderr:?}");
    assert!(stderr.contains("cannot run"), "{stderr:?}");
}

#[test]
fn picker_arguments_are_passed_through_verbatim() {
    let dir = fixture();
    let fzf = picker("argv", "echo %*", "printf '%s\\n' \"$*\"");
    let (code, stdout, stderr) = run(&[
        "--pick",
        "--fzf-binary",
        fzf.to_str().unwrap(),
        "--fzf-arg=--height=40%",
        "--fzf-arg=--multi",
        "needle",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr:?}");
    assert!(stdout.contains("--height=40%"), "{stdout:?}");
    assert!(stdout.contains("--multi"), "{stdout:?}");
}

#[test]
fn the_search_beneath_the_picker_is_the_normal_search() {
    let dir = fixture();
    let (_, expected, _) = run(&["needle", dir.to_str().unwrap()]);
    let fzf = picker("passthrough", "findstr /r \"^\"", "cat");
    // a picker that echoes everything it was given must have been given
    // exactly the output rgx would have printed
    let (code, stdout, stderr) = pick_with(&fzf, "needle", &dir);
    assert_eq!(code, 0, "{stderr:?}");
    // the walk is parallel, so the two runs agree as sets, not in order
    let mut want: Vec<String> = expected.lines().map(str::to_string).collect();
    let mut got: Vec<String> = stdout.lines().map(|l| l.trim_end().to_string()).collect();
    want.sort();
    got.sort();
    assert_eq!(got, want, "the picker saw rgx's own output");
}

#[test]
fn pick_is_opt_in() {
    let dir = fixture();
    let (code, stdout, stderr) = run(&["needle", dir.to_str().unwrap()]);
    assert_eq!(code, 0, "{stderr:?}");
    assert!(stdout.contains("a.txt") && stdout.contains("b.txt"));
    assert!(
        !stderr.contains("fzf"),
        "nothing about the picker without --pick"
    );
}
