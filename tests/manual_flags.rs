// SPDX-License-Identifier: Apache-2.0

//! MANUAL.md against the binary it documents.
//!
//! The manual says "Every flag, what it does, and where it differs from
//! ripgrep" (MANUAL.md §"Flags"), and the flags it lists are the binary's
//! own grammar. Nothing held the two together: the crate READMEs are held
//! against the registry by `tests/crate_readmes.rs`, and the EGM contracts
//! are held for shape, but the manual was held by nothing at all -- so a
//! flag the binary has can be missing from it, and a flag it does not have
//! can be in it.
//!
//! Both happened. `--stats` was in the binary and in no document, and
//! `--adapter-view` was in the manual and in no binary: the policy it
//! describes is the environment variable `RGX_ADAPTER_VIEW`, and the
//! manual said so itself eleven lines further down.

use std::path::Path;
use std::process::Command;

/// The long flags the binary accepts.
fn binary_flags() -> Vec<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_rgx"))
        .arg("--help")
        .output()
        .expect("the binary runs");
    let text = String::from_utf8_lossy(&out.stdout);
    flags_in(&text)
}

/// The long flags a text mentions.
///
/// The scanner keeps a table separator (`|---|---|`) out of it, because a
/// flag has a letter or a digit after the dashes, and it keeps a VALUE out
/// of it too: `--fzf-arg=--multi` names one flag of `rgx` and carries
/// another in its value, and that other is the picker's.
fn flags_in(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut flags: Vec<String> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
            let before_is_clear = i == 0
                || !(bytes[i - 1] == b'='
                    || bytes[i - 1] == b'-'
                    || bytes[i - 1].is_ascii_alphanumeric());
            let mut j = i + 2;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'-') {
                j += 1;
            }
            let has_a_name = j > i + 2 && bytes[i + 2].is_ascii_alphanumeric();
            if before_is_clear && has_a_name {
                let name = text[i..j].to_string();
                if !flags.contains(&name) {
                    flags.push(name);
                }
            }
            i = j;
            continue;
        }
        i += 1;
    }
    flags.sort();
    flags
}

/// The first cell of every table row: that is where the manual states what
/// `rgx` accepts, as opposed to the third cell, which is what `rg` does.
fn flag_cells(manual: &str) -> Vec<(String, String)> {
    let mut cells = Vec::new();
    for line in manual.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let first = line.split('|').nth(1).unwrap_or("").trim().to_string();
        if !first.starts_with('`') {
            continue;
        }
        if !flags_in(&first).iter().any(|f| f.starts_with("--")) {
            continue;
        }
        cells.push((first, line.to_string()));
    }
    cells
}

/// A line that says a flag is NOT accepted is a claim about its absence,
/// and a line that mentions `cargo` is a build command and not an `rgx`
/// invocation. Both are the manual being careful, and neither is drift.
fn line_excuses_a_flag(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    l.contains("cargo")
        || l.contains("not accepted")
        || l.contains("is not ")
        || l.contains("does not")
        || l.contains("no `--")
        || l.contains("not recognised")
        || l.contains("not recognized")
}

fn read_manual() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("MANUAL.md");
    std::fs::read_to_string(&path).expect("MANUAL.md is there")
}

#[test]
fn the_manual_documents_every_flag_the_binary_has() {
    let manual = read_manual();
    let documented = flags_in(&manual);
    let binary = binary_flags();

    let missing: Vec<&String> = binary.iter().filter(|f| !documented.contains(f)).collect();
    assert!(
        missing.is_empty(),
        "the binary accepts {} and the manual says it lists every flag: {}",
        missing.len(),
        missing
            .iter()
            .map(|f| f.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

#[test]
fn every_flag_the_manual_claims_accepted_exists_in_the_binary() {
    let manual = read_manual();
    let binary = binary_flags();

    for (cell, line) in flag_cells(&manual) {
        for flag in flags_in(&cell) {
            assert!(
                binary.contains(&flag),
                "the manual's table row names {flag}, and the binary has no such \
                 flag:\n  {cell}\n  in: {line}"
            );
        }
    }
}

#[test]
fn a_flag_the_manual_mentions_is_either_a_real_one_or_said_to_be_absent() {
    let manual = read_manual();
    let binary = binary_flags();

    let mut offenders: Vec<String> = Vec::new();
    for (number, line) in manual.lines().enumerate() {
        if line_excuses_a_flag(line) {
            continue;
        }
        for flag in flags_in(line) {
            if !binary.contains(&flag) {
                offenders.push(format!("line {}: {flag} -- {}", number + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the manual names flags the binary does not have, and does not say they \
         are absent:\n  {}",
        offenders.join("\n  ")
    );
}
