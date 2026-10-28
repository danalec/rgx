// SPDX-License-Identifier: Apache-2.0

//! The count of the tests, and the note that says what it was taken after.
//!
//! The notes of the project carry the count in two places -- the line that
//! says how many tests pass, and the comment in the workflow -- and the
//! history of the counts is a list of clauses, each one saying what a
//! re-snapshot was after. The tool that writes the count writes the note
//! into the newest clause and leaves the older ones alone: the history is
//! cumulative, and a tool that rewrote every clause would replace the
//! history with the last note.
//!
//! The two twins have to write the same bytes. The script that runs on
//! Linux and the one that runs on Windows are the same job, and a note that
//! lands in a different place on each of them is a note that is wrong in
//! one of them. The note also has to survive the characters that a
//! substitution would take for itself: an "&" is the whole match in a sed
//! replacement, and a "$" is a group in a regex replacement, and a note
//! that holds one of them was a note that came out wrong.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

/// The notes of the project, with three clauses of history: the first one
/// has a header that holds more than one line, and the third one says
/// "once more", the way the notes say it when the count was snapped again.
const NOTES: &str = "\
# The notes of the project

**2,555 tests pass, 0 fail, 8 ignored** across 45 test binaries plus 12 doctest
targets, from `cargo test --release --locked --workspace --no-fail-fast`
(the count is the one of the platform the gate ran on: the symlink case of
`tests/walk_diff.rs` is `#[cfg(windows)]` on one side and `#[cfg(unix)]` on
the other, so Linux and macOS hold one test less -- 2 554 -- and the CI
runs the gate on all three)
(re-snapped 2026-10-25, after the type filter learned to be
ripgrep's: a type is a set of patterns and a file matches every one of
them)
(re-snapped 2026-10-23, after the cache comparison learned to ask the tree:
the three new tests are the probe that says whether the fixture can be
read, the answer that is not retried, and the retry that is bounded)
(re-snapped 2026-10-22 once more, after the Ogg comment headers and the ASF
family: the six new tests are the three that read the Ogg comment)
";

/// The workflow, with the comment that says the same count.
const WORKFLOW: &str = "\
name: CI
on: [push]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: the gate
        run: cargo test --release --locked --workspace
        # just that package: the 2,555 tests in the workspace -- including
        # the ones that need a file the runner has to fetch first.
";

/// A note with the characters a substitution takes for itself.
const NOTE: &str = "the note learned what it was taken after & kept the $ signs";

/// The date the stamp writes, which is not the date of the machine: a
/// test that read the clock would not be a test of the date.
const DATE: &str = "2026-10-26";

struct Scratch(PathBuf);

impl Scratch {
    ///
    /// The directory is one of this run's own: `common::scratch` owns the rule
    /// its name follows, and the rule is written down there.
    fn new(tag: &str) -> Scratch {
        Scratch(common::scratch(&format!("count-note-{tag}")))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, body: &str) -> PathBuf {
        let path = self.path(name);
        // The notes of the project are a Windows checkout, and the stamp
        // has to keep the carriage returns: a twin that rewrote the line
        // endings would put a whole file of differences in the diff of
        // every commit. The endings of the body are normalised first: the
        // notes of a checkout that already carries them would otherwise
        // get a second carriage return on every line.
        let bytes: Vec<u8> = body
            .replace("\r\n", "\n")
            .replace('\n', "\r\n")
            .into_bytes();
        std::fs::write(&path, bytes).expect("fixture");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a twin said: the code it left behind, the line it printed, and the
/// line it refused with.
#[derive(Debug)]
struct Said {
    code: i32,
    out: String,
    err: String,
}

/// The two stamps, one per twin, over two copies of the same files.
struct Stamped {
    sh_notes: PathBuf,
    ps_notes: PathBuf,
    sh: Said,
    ps: Said,
}

/// The bash that runs the scripts. On Windows the `bash` on the PATH is
/// the one of the Windows Subsystem for Linux, which is not the bash the
/// runner uses: the Git Bash is the one that reads these scripts.
fn bash() -> String {
    #[cfg(windows)]
    {
        for candidate in [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files (x86)\Git\bin\bash.exe",
        ] {
            if Path::new(candidate).exists() {
                return candidate.to_string();
            }
        }
        // The git of a scoop or a chocolatey install does not live in
        // `C:\Program Files\Git`, and the git on the PATH says where its
        // own install is: `--exec-path` is `<root>\mingw64\libexec\git-core`.
        if let Some(root) = git_root() {
            let candidate = root.join("bin").join("bash.exe");
            if candidate.exists() {
                return candidate.to_string_lossy().to_string();
            }
        }
        // And then any `bash` on the PATH that is not the Subsystem's.
        if let Some(candidate) = bash_on_path() {
            return candidate;
        }
    }
    "bash".to_string()
}

/// The root of the install the git on the PATH belongs to.
#[cfg(windows)]
fn git_root() -> Option<PathBuf> {
    let out = Command::new("git").arg("--exec-path").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        return None;
    }
    let path = PathBuf::from(text);
    let root = path.parent()?.parent()?.parent()?.to_path_buf();
    if root.join("bin").join("bash.exe").exists() {
        Some(root)
    } else {
        None
    }
}

/// The `bash` on the PATH that is not the Windows Subsystem's.
#[cfg(windows)]
fn bash_on_path() -> Option<String> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join("bash.exe");
        if !candidate.exists() {
            continue;
        }
        let text = candidate.to_string_lossy().to_ascii_lowercase();
        if text.contains("\\windows\\system32\\") || text.contains("\\windowsapps\\") {
            continue;
        }
        return Some(candidate.to_string_lossy().to_string());
    }
    None
}

/// The PowerShell that runs the twin. The GitHub runners carry it on the
/// three platforms, and the name is the one of the newer shell.
fn powershell() -> String {
    for candidate in ["pwsh", "powershell"] {
        let found = Command::new(candidate)
            .arg("-NoProfile")
            .arg("-Command")
            .arg("exit 0")
            .output();
        if let Ok(out) = found {
            if out.status.success() {
                return candidate.to_string();
            }
        }
    }
    panic!("the Windows twin needs a PowerShell: it is the other half of the pair");
}

/// A path the bash of this machine understands: on Windows the scripts
/// are given a path like /c/Users/..., and the drive letter of a path
/// like C:\Users\... becomes /c.
fn for_bash(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        format!("/{drive}{}", &text[2..])
    } else {
        text
    }
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The stamp the shell script writes: the arguments, and the note.
fn stamp_with_sh(
    script: &Path,
    notes: &Path,
    workflow: &Path,
    passed: u32,
    ignored: u32,
    note: &str,
) -> Said {
    let out = Command::new(bash())
        .arg(for_bash(script))
        .arg("--agents")
        .arg(for_bash(notes))
        .arg("--workflow")
        .arg(for_bash(workflow))
        .arg("--passed")
        .arg(passed.to_string())
        .arg("--ignored")
        .arg(ignored.to_string())
        .arg("--date")
        .arg(DATE)
        .arg("--note")
        .arg(note)
        .output()
        .expect("the bash of this machine must run the script");
    Said {
        code: out.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The stamp the PowerShell writes: the arguments, and the note.
fn stamp_with_ps(
    script: &Path,
    notes: &Path,
    workflow: &Path,
    passed: u32,
    ignored: u32,
    note: &str,
) -> Said {
    let out = Command::new(powershell())
        .arg("-NoProfile")
        .arg("-File")
        .arg(script)
        .arg("-Agents")
        .arg(notes)
        .arg("-Workflow")
        .arg(workflow)
        .arg("-Passed")
        .arg(passed.to_string())
        .arg("-Ignored")
        .arg(ignored.to_string())
        .arg("-Date")
        .arg(DATE)
        .arg("-Note")
        .arg(note)
        .output()
        .expect("the PowerShell of this machine must run the script");
    Said {
        code: out.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The two stamps, one per twin, over two copies of the same files.
fn stamp_both(scratch: &Scratch, passed: u32, ignored: u32, note: &str) -> Stamped {
    let sh_notes = scratch.write("notes.sh.md", NOTES);
    let sh_workflow = scratch.write("ci.sh.yml", WORKFLOW);
    let ps_notes = scratch.write("notes.ps.md", NOTES);
    let ps_workflow = scratch.write("ci.ps.yml", WORKFLOW);

    let script = repo().join("scripts").join("stamp-count.sh");
    let twin = repo().join("scripts").join("stamp-count.ps1");
    Stamped {
        sh: stamp_with_sh(&script, &sh_notes, &sh_workflow, passed, ignored, note),
        ps: stamp_with_ps(&twin, &ps_notes, &ps_workflow, passed, ignored, note),
        sh_notes,
        ps_notes,
    }
}

#[test]
fn the_note_lands_in_the_newest_clause_and_the_older_ones_keep_their_story() {
    let scratch = Scratch::new("newest");
    let stamped = stamp_both(&scratch, 2571, 8, NOTE);

    assert_eq!(
        stamped.sh.code, 0,
        "the shell script failed: {}",
        stamped.sh.err
    );
    assert_eq!(
        stamped.ps.code, 0,
        "the Windows script failed: {}",
        stamped.ps.err
    );

    let written = std::fs::read_to_string(&stamped.sh_notes).expect("the stamped notes");
    let twin = std::fs::read_to_string(&stamped.ps_notes).expect("the stamped notes of the twin");

    // The header of the newest clause is the one the note was written
    // into, and the body of the clause is the body it had.
    assert!(
        written.contains(&format!(
            "(re-snapped {DATE}, after {NOTE} landed: a type is a set of patterns"
        )),
        "the note did not land in the newest clause:\n{written}"
    );

    // The older clauses are the history, and the history is not rewritten.
    assert!(
        written.contains(
            "(re-snapped 2026-10-23, after the cache comparison learned to ask the tree:\r\nthe three new tests are the probe that says whether the fixture can be\r\nread, the answer that is not retried, and the retry that is bounded)"
        ),
        "the clause of 2026-10-23 was rewritten:\n{written}"
    );
    assert!(
        written.contains(
            "(re-snapped 2026-10-22 once more, after the Ogg comment headers and the ASF\r\nfamily: the six new tests are the three that read the Ogg comment)"
        ),
        "the clause of 2026-10-22 was rewritten:\n{written}"
    );

    // The count of the tests, with the thousands the notes write.
    assert!(
        written.contains("**2,571 tests pass, 0 fail, 8 ignored**"),
        "the count was not stamped:\n{written}"
    );

    // The two twins wrote the same bytes.
    assert_eq!(
        written, twin,
        "the shell script and the Windows script wrote different notes"
    );
    assert_eq!(
        stamped.sh.out, stamped.ps.out,
        "the shell script and the Windows script said different things"
    );
}

#[test]
fn the_stamp_keeps_the_carriage_returns_of_a_windows_checkout() {
    let scratch = Scratch::new("crlf");
    let stamped = stamp_both(&scratch, 2571, 8, NOTE);
    assert_eq!(stamped.sh.code, 0, "{}", stamped.sh.err);
    assert_eq!(stamped.ps.code, 0, "{}", stamped.ps.err);

    for path in [&stamped.sh_notes, &stamped.ps_notes] {
        let bytes = std::fs::read(path).expect("the stamped notes");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("\r\n"),
            "the stamp took the carriage returns of {}",
            path.display()
        );
        for (i, byte) in bytes.iter().enumerate() {
            if *byte == b'\n' {
                assert_eq!(
                    bytes[i - 1],
                    b'\r',
                    "a line ending lost its carriage return at byte {i} of {}",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn the_workflow_says_the_same_count_as_the_notes() {
    let scratch = Scratch::new("workflow");
    let sh_workflow = scratch.write("ci.sh.yml", WORKFLOW);
    let ps_workflow = scratch.write("ci.ps.yml", WORKFLOW);

    let script = repo().join("scripts").join("stamp-count.sh");
    let twin = repo().join("scripts").join("stamp-count.ps1");
    let sh = stamp_with_sh(
        &script,
        &scratch.write("notes.sh.md", NOTES),
        &sh_workflow,
        2571,
        8,
        NOTE,
    );
    let ps = stamp_with_ps(
        &twin,
        &scratch.write("notes.ps.md", NOTES),
        &ps_workflow,
        2571,
        8,
        NOTE,
    );
    assert_eq!(sh.code, 0, "{}", sh.err);
    assert_eq!(ps.code, 0, "{}", ps.err);

    for path in [&sh_workflow, &ps_workflow] {
        let text = std::fs::read_to_string(path).expect("the stamped workflow");
        assert!(
            text.contains("the 2,571 tests in the workspace"),
            "the workflow does not say the count:\n{text}"
        );
    }
}

#[test]
fn a_count_of_seven_digits_is_written_with_its_thousands() {
    // The number of the tests is written with the thousands the notes use,
    // and the sed that did it was a GNU one: on macOS it left the number
    // alone, and the two twins wrote 2,575 and 2575 into the same notes.
    // The count of a number that has more than four digits is counted from
    // the right, so 1234567 is 1,234,567 and not 1234,567.
    let scratch = Scratch::new("digits");
    let stamped = stamp_both(&scratch, 1_234_567, 8, NOTE);
    assert_eq!(stamped.sh.code, 0, "{}", stamped.sh.err);
    assert_eq!(stamped.ps.code, 0, "{}", stamped.ps.err);

    for path in [&stamped.sh_notes, &stamped.ps_notes] {
        let text = std::fs::read_to_string(path).expect("the stamped notes");
        assert!(
            text.contains("**1,234,567 tests pass, 0 fail, 8 ignored**"),
            "the count was not written with its thousands:\n{text}"
        );
    }
    assert_eq!(
        std::fs::read(&stamped.sh_notes).unwrap(),
        std::fs::read(&stamped.ps_notes).unwrap(),
        "the shell script and the Windows script wrote different notes"
    );
}

#[test]
fn a_note_with_a_colon_is_refused_and_the_notes_are_left_alone() {
    let scratch = Scratch::new("colon");
    let stamped = stamp_both(&scratch, 2571, 8, "the note: with a colon");

    assert_eq!(
        stamped.sh.code, 2,
        "the shell script took a note it cannot place: {:?}",
        stamped.sh
    );
    assert_eq!(
        stamped.ps.code, 2,
        "the Windows script took a note it cannot place: {:?}",
        stamped.ps
    );
    assert!(
        stamped.sh.err.contains("colon"),
        "the shell script did not say why it refused: {}",
        stamped.sh.err
    );
    assert!(
        stamped.ps.err.contains("colon"),
        "the Windows script did not say why it refused: {}",
        stamped.ps.err
    );

    // The refusal is a refusal and not a half stamp: the notes are the
    // ones that were there.
    for path in [&stamped.sh_notes, &stamped.ps_notes] {
        let text = std::fs::read_to_string(path).expect("the notes");
        assert!(
            text.contains("**2,555 tests pass, 0 fail, 8 ignored**"),
            "the notes were stamped by a stamp that was refused:\n{text}"
        );
        assert!(
            text.contains("(re-snapped 2026-10-25, after the type filter learned to be"),
            "the history was rewritten by a stamp that was refused:\n{text}"
        );
    }
}

#[test]
fn an_empty_note_stamps_the_counts_and_leaves_the_history_alone() {
    let scratch = Scratch::new("empty");
    let stamped = stamp_both(&scratch, 2571, 8, "");
    assert_eq!(stamped.sh.code, 0, "{}", stamped.sh.err);
    assert_eq!(stamped.ps.code, 0, "{}", stamped.ps.err);

    for path in [&stamped.sh_notes, &stamped.ps_notes] {
        let text = std::fs::read_to_string(path).expect("the notes");
        assert!(
            text.contains("**2,571 tests pass, 0 fail, 8 ignored**"),
            "the count was not stamped:\n{text}"
        );
        assert!(
            text.contains("(re-snapped 2026-10-25, after the type filter learned to be"),
            "the history was rewritten by a stamp that had no note:\n{text}"
        );
    }
    assert_eq!(
        std::fs::read(&stamped.sh_notes).unwrap(),
        std::fs::read(&stamped.ps_notes).unwrap(),
        "the shell script and the Windows script wrote different notes"
    );
}

#[test]
fn the_notes_of_the_project_are_stamped_the_same_way_by_both_twins() {
    // The notes of the repository, copied: the stamp runs over the real
    // file and not over a fixture, because the fixture is written by the
    // same hand as the test and would agree with a broken script.
    let scratch = Scratch::new("repo");
    let notes =
        std::fs::read_to_string(repo().join("AGENTS.md")).expect("the notes of the project");
    let workflow =
        std::fs::read_to_string(repo().join(".github/workflows/ci.yml")).expect("the workflow");

    let sh_notes = scratch.write("notes.sh.md", &notes);
    let sh_workflow = scratch.write("ci.sh.yml", &workflow);
    let ps_notes = scratch.write("notes.ps.md", &notes);
    let ps_workflow = scratch.write("ci.ps.yml", &workflow);

    let script = repo().join("scripts").join("stamp-count.sh");
    let twin = repo().join("scripts").join("stamp-count.ps1");
    let sh = stamp_with_sh(&script, &sh_notes, &sh_workflow, 2571, 8, NOTE);
    let ps = stamp_with_ps(&twin, &ps_notes, &ps_workflow, 2571, 8, NOTE);
    assert_eq!(
        sh.code, 0,
        "the shell script failed on the notes of the project: {}",
        sh.err
    );
    assert_eq!(
        ps.code, 0,
        "the Windows script failed on the notes of the project: {}",
        ps.err
    );

    let written = std::fs::read_to_string(&sh_notes).expect("the stamped notes");
    assert_eq!(
        written,
        std::fs::read_to_string(&ps_notes).expect("the stamped notes of the twin"),
        "the two twins stamped the notes of the project differently"
    );

    // One clause changed, and it is the first one.
    let before = notes.matches("(re-snapped ").count();
    let after = written.matches("(re-snapped ").count();
    assert_eq!(before, after, "the stamp wrote a clause of its own");
    let first = written.find("(re-snapped ").expect("a clause");
    assert!(
        written[first..].starts_with(&format!("(re-snapped {DATE}, after {NOTE} landed:")),
        "the first clause is not the one that was stamped:\n{}",
        &written[first..first + 120]
    );
    // The count of the tests is in the notes, and it was stamped.
    assert!(
        written.contains("**2,571 tests pass, 0 fail, 8 ignored**"),
        "the count of the notes of the project was not stamped"
    );
}
