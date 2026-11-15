// SPDX-License-Identifier: Apache-2.0

//! `--pick`: rgx's output handed to an external `fzf`.
//!
//! The picker is a separate program, found by scanning `PATH` for the
//! candidate names below — the same probe `rgx-adapters-docs` uses to find
//! soffice and tesseract, memoised per process for the same reason (an
//! unscanned `PATH` costs one stat per candidate per file).
//!
//! Nothing here runs unless `--pick` was given: no probe, no spawn, no
//! terminal check. The exit status is the whole contract of a grep-shaped
//! tool, so it is spelled out rather than inherited:
//!
//! | code | meaning |
//! |------|---------|
//! | 0    | the search matched and the picker returned a selection |
//! | 1    | nothing matched, or the user dismissed the picker |
//! | 2    | no `fzf` on `PATH`, or it could not be run |

use rgx_core::Result;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;

/// Picker binaries, first hit on `PATH` wins.
const CANDIDATES: &[&str] = &["fzf", "sk", "peco", "fz"];

/// How the picker is invoked.
pub struct Request<'a> {
    /// argv appended after the binary, unparsed — one flag per element, so
    /// nothing the user wrote is re-split by a shell
    pub args: &'a [String],
    /// an explicit picker path; `PATH` is scanned when this is `None`
    pub binary: Option<&'a str>,
}

/// The search to offer, run on its own thread so its bytes reach the picker
/// as they are produced rather than after the whole walk finishes.
pub type Search =
    Box<dyn FnOnce(&mut (dyn Write + Send + 'static)) -> Result<bool> + Send + 'static>;

/// Runs `search` with its output on the picker's stdin, prints what the
/// picker returns, and yields the process exit status.
pub fn pick(search: Search, req: &Request<'_>) -> Result<i32> {
    let binary = match req.binary {
        Some(p) => p.to_string(),
        None => locate().ok_or_else(|| {
            rgx_core::anyhow!(
                "--pick needs fzf: none of {} is on PATH (install one, or point --fzf-binary at it)",
                CANDIDATES.join(", ")
            )
        })?,
    };
    let mut child = Command::new(&binary)
        .args(req.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // fzf draws on the terminal it opens for itself; its own complaints
        // belong on our stderr, not folded into a pipe
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| rgx_core::anyhow!("--pick: cannot run {binary}: {e}"))?;

    let mut stdin = child.stdin.take().expect("stdin was piped");
    let (tx, rx) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        let out = search(&mut stdin);
        // the picker's list is only final at EOF
        drop(stdin);
        let _ = tx.send(out);
    });

    let mut selected = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        // an fzf that dies mid-read must not take the search down with it
        let _ = stdout.read_to_string(&mut selected);
    }
    let code = wait(&mut child);
    let searched = rx.recv().unwrap_or(Ok(false));
    let _ = writer.join();

    searched?;
    if code == 0 && !selected.is_empty() {
        let mut out = std::io::stdout();
        out.write_all(selected.as_bytes())?;
        out.flush()?;
    }
    status(code, selected.is_empty())
}

/// Maps a finished picker to rgx's exit status. fzf exits 130 when the user
/// dismisses it and 1 when its list is empty; both are "the user got
/// nothing", which is what 1 already means to every other rgx caller.
fn status(code: i32, no_selection: bool) -> Result<i32> {
    match (code, no_selection) {
        (0, false) => Ok(0),
        (0 | 1 | 130, _) => Ok(1),
        c => Err(rgx_core::anyhow!("the picker exited with {}", c.0)),
    }
}

/// Reaps the picker. A child that died from a signal has no exit code of its
/// own; it is reported as 1, which reads as "nothing was selected".
fn wait(child: &mut Child) -> i32 {
    match child.wait() {
        Ok(s) => s.code().unwrap_or(1),
        Err(_) => 1,
    }
}

fn locate() -> Option<String> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static FOUND: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    let mut memo = FOUND
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    for name in CANDIDATES {
        let hit = memo
            .entry((*name).to_string())
            .or_insert_with(|| scan(name));
        if let Some(path) = hit.as_ref() {
            return Some(path.clone());
        }
    }
    None
}

fn scan(binary: &str) -> Option<String> {
    if binary.contains('/') || binary.contains('\\') {
        return Path::new(binary).is_file().then(|| binary.to_string());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
        #[cfg(windows)]
        {
            for ext in ["exe", "bat", "cmd"] {
                let candidate = candidate.with_extension(ext);
                if candidate.is_file() {
                    return Some(candidate.to_string_lossy().into_owned());
                }
            }
        }
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_selection_is_zero_and_a_dismissal_is_one() {
        assert_eq!(status(0, false).unwrap(), 0);
        assert_eq!(status(0, true).unwrap(), 1);
        // fzf's own "no match" and "user pressed ESC" statuses
        assert_eq!(status(1, true).unwrap(), 1);
        assert_eq!(status(130, true).unwrap(), 1);
        // anything else is a broken picker, not a search with no matches
        assert!(status(2, true).is_err());
        assert!(status(127, true).is_err());
    }

    #[test]
    fn a_missing_picker_is_an_error_not_a_quiet_one() {
        let req = Request {
            args: &[],
            binary: Some("rgx-no-such-picker"),
        };
        let e = pick(Box::new(|_| Ok(true)), &req).unwrap_err();
        assert!(format!("{e:#}").contains("cannot run"), "{e:#}");
    }

    #[test]
    fn candidates_include_fallbacks() {
        assert!(CANDIDATES.contains(&"fzf"));
        assert!(CANDIDATES.contains(&"sk"));
        assert!(CANDIDATES.contains(&"peco"));
        assert!(CANDIDATES.contains(&"fz"));
    }

    #[test]
    fn an_absent_name_is_not_located() {
        assert!(scan("rgx-no-such-picker").is_none());
        assert!(scan("rgx-no-such-picker/sub").is_none());
    }
}
