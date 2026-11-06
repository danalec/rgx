// SPDX-License-Identifier: Apache-2.0

//! Golden-sample verification against real-world files harvested from the
//! host machine (scripts/harvest-golden.ps1). Complements the synthetic
//! fixtures: parsers proven well-formed survive what real producers ship.
//!
//! The test is opt-in: when `tests/golden/` does not exist (CI, fresh
//! clones — the samples are gitignored), everything passes vacuously.

use std::path::Path;
use std::process::Command;

fn rgx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rgx"))
}

#[test]
fn golden_samples_match() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let manifest = dir.join("manifest.tsv");
    if !manifest.exists() {
        eprintln!("no golden samples harvested; run scripts/harvest-golden.ps1");
        return;
    }
    let mut checked = 0;
    for line in std::fs::read_to_string(&manifest).unwrap().lines() {
        let Some((file, pattern)) = line.split_once('\t') else {
            continue;
        };
        let path = dir.join(file);
        let out = rgx().args(["-l", pattern]).arg(&path).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{file}: real-world sample must match {pattern:?} (stderr: {})",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(file),
            "{file}: -l must list the file"
        );
        checked += 1;
    }
    assert!(checked > 0, "manifest.tsv listed no samples");
}
