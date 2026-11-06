// SPDX-License-Identifier: Apache-2.0

//! The manual against the external tools the tree spawns.
//!
//! `rgx` reaches outside itself for two families: the picker on `--pick`, and
//! the docs family's office and OCR tools. Every one of them is optional --
//! the adapter declines when the binary is not on `PATH` -- and every one of
//! them has to be named where the user will look for it. A user who does not
//! know that the OCR of a PDF needs a rasteriser installs tesseract and
//! still gets nothing.
//!
//! The manual named two of the office tools and two of the four pickers,
//! and it named the pickers in the wrong order: the code's list is `fzf`,
//! `sk`, `peco`, `fz`, and the manual said "the first of `fzf`, `fz`". It
//! also left out the office binary's second name, `libreoffice`, which is
//! what a distribution that does not ship `soffice` has on `PATH`.
//!
//! Nothing held that list. `tests/manual_flags.rs` holds the manual's flags
//! against the binary, and the crate READMEs are held against the registry,
//! but the manual's list of external tools was held by nothing at all -- so
//! a tool the tree stops spawning stayed in the manual, and a tool it
//! starts spawning stayed out of it.
//!
//! The names are taken from the code, not written down here: the picker's
//! candidates are the array in `src/pick.rs` and the docs family's are the
//! literals that crate looks up on `PATH`. A list written down in the test
//! would hold the manual against itself.

use std::path::Path;

/// The names of the string literals in the array that follows a marker.
///
/// The marker ends where the array's own `[` is, so the scan starts at the
/// first literal and stops at the array's `]`.
fn array_after(text: &str, marker: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut names = Vec::new();
    let mut from = 0usize;
    while let Some(at) = text[from..].find(marker) {
        let mut i = from + at + marker.len();
        while i < bytes.len() {
            match bytes[i] {
                b'"' => {
                    let close = match text[i + 1..].find('"') {
                        Some(k) => i + 1 + k,
                        None => break,
                    };
                    names.push(text[i + 1..close].to_string());
                    i = close + 1;
                }
                b']' => break,
                _ => i += 1,
            }
        }
        from = if i > from + at + marker.len() {
            i
        } else {
            from + at + marker.len()
        };
    }
    names
}

/// The names a `which("...")` call looks up on `PATH`.
///
/// A `which(b)` call over a list is not one of these: the list it walks is
/// read on its own.
fn looked_up(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut from = 0usize;
    while let Some(at) = text[from..].find("which(\"") {
        let start = from + at + "which(\"".len();
        let close = match text[start..].find('"') {
            Some(k) => start + k,
            None => break,
        };
        names.push(text[start..close].to_string());
        from = close + 1;
    }
    names
}

/// The picker's candidates, in the order the code has them.
fn picker_candidates() -> Vec<String> {
    array_after(&read("src/pick.rs"), "const CANDIDATES: &[&str] = &[")
}

/// Every external binary the tree can spawn.
///
/// The office binary is looked up twice in the source -- once to ask whether
/// it is there at all and once to choose which of the two names to run -- so
/// the list is a set: the same tool twice is one tool to name.
fn external_tools() -> Vec<String> {
    let docs = read("crates/rgx-adapters-docs/src/lib.rs");
    let mut names = Vec::new();
    names.extend(picker_candidates());
    names.extend(array_after(&docs, "binaries: &["));
    names.extend(array_after(&docs, ": &[&str] = &["));
    names.extend(looked_up(&docs));

    let mut seen = Vec::new();
    for name in names {
        if !seen.contains(&name) {
            seen.push(name);
        }
    }
    seen
}

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{relative} is there: {e}"))
}

fn read_manual() -> String {
    read("MANUAL.md")
}

/// A byte that is part of a word, so that a name inside a longer word is not
/// a mention of it.
fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// The byte index of a whole-word occurrence of `name` in `text`.
///
/// The boundaries are what make this usable on the two-letter names: `sk` is
/// not inside "disk", and `fz` is not inside "fzf".
fn word_at(text: &str, name: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let needle = name.as_bytes();
    if needle.is_empty() {
        return None;
    }
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let before_is_clear = i == 0 || !is_name_byte(bytes[i - 1]);
            let after = i + needle.len();
            let after_is_clear = after >= bytes.len() || !is_name_byte(bytes[after]);
            if before_is_clear && after_is_clear {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn names_it(text: &str, name: &str) -> bool {
    word_at(text, name).is_some()
}

#[test]
fn the_manual_names_every_external_tool_the_tree_spawns() {
    let manual = read_manual();
    let tools = external_tools();

    assert!(
        tools.len() >= 5,
        "the extraction found {} external tools, which is too few to be the \
         code's own list: {:?}",
        tools.len(),
        tools
    );

    let missing: Vec<&String> = tools.iter().filter(|t| !names_it(&manual, t)).collect();
    assert!(
        missing.is_empty(),
        "the tree spawns {} external tools and the manual does not name {}: {}",
        tools.len(),
        missing.len(),
        missing
            .iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

#[test]
fn the_pickers_default_lists_the_candidates_in_the_code_order() {
    let manual = read_manual();
    let candidates = picker_candidates();
    assert!(
        !candidates.is_empty(),
        "the picker's candidates were not found"
    );

    let row = manual
        .lines()
        .find(|line| line.trim_start().starts_with("| `--fzf-binary"))
        .expect("the manual's flag table has a row for --fzf-binary");

    // The order is the claim: the manual says which one is the default, and
    // the default is the first of them.
    let mut at = 0usize;
    for name in &candidates {
        let found = word_at(&row[at..], name).unwrap_or_else(|| {
            panic!("the --fzf-binary row does not name {name}, in that order:\n  {row}")
        });
        at += found + name.len();
    }
}
