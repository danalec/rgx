// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

mod common;

struct Scratch(PathBuf);

impl Scratch {
    ///
    /// The directory is one of this run's own: `common::scratch` owns the rule
    /// its name follows, and the rule is written down there.
    fn new(tag: &str) -> Scratch {
        Scratch(common::scratch(&format!("lock-{tag}")))
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        fs::write(self.0.join(name), bytes).expect("write fixture");
    }
    fn path(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// rgx searches stdin when it is piped, so the path must be passed
/// explicitly and stdin closed, or the run searches the empty pipe.
fn run(dir: &PathBuf, args: &[&str]) -> (String, String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_rgx"))
        .args(args)
        .arg(".")
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .expect("run rgx");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// Office owner-lock files are transient binary scratch files. They must not
/// be walked, listed by --files, or reported as matches.
#[test]
fn office_lock_files_are_skipped() {
    let s = Scratch::new("lock");
    // the lock file is office-shaped by name; the searchable file is plain
    // text so no adapter claims it and it is searched raw
    s.write("~$budget.xlsx", b"\x00\x01ZIRCALOY\x00\x02");
    s.write("real.txt", b"ZIRCALOY");

    let (stdout, _, _) = run(s.path(), &["--files"]);
    assert!(
        !stdout.contains("~$budget.xlsx"),
        "lock file must not be listed by --files, got: {stdout}"
    );
    assert!(stdout.contains("real.txt"), "got: {stdout}");

    // searching the raw bytes must not report the lock file either
    let (stdout, _, _) = run(s.path(), &["-a", "ZIRCALOY"]);
    assert!(
        !stdout.contains("~$budget.xlsx"),
        "lock file must not produce matches, got: {stdout}"
    );
    assert!(stdout.contains("real.txt"), "got: {stdout}");
}

/// The lock-file exclude is a walker-level default, so it must not interfere
/// with ordinary files that merely contain a dollar sign.
#[test]
fn non_lock_dollar_files_are_still_searched() {
    let s = Scratch::new("dollar");
    s.write("a$b.txt", b"ZIRCALOY");
    s.write("~notlock.txt", b"ZIRCALOY");

    let (stdout, _, _) = run(s.path(), &["--files"]);
    assert!(stdout.contains("a$b.txt"), "got: {stdout}");
    assert!(stdout.contains("~notlock.txt"), "got: {stdout}");
}
