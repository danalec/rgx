// SPDX-License-Identifier: Apache-2.0

//! The ablation switches change cost, never answers.
//!
//! What this holds down: `RGX_ABLATE_MASK` and `RGX_ABLATE_NGRAM` are
//! research instrumentation for the paper's end-to-end tier comparison, so
//! every run that uses them compares a result against the same run without
//! them. A difference in stdout is a bug in the fallback path behind the
//! switch -- a lost match is the failure mode -- and the vacuity half of
//! each test proves the switch did something, so a green pair cannot mean
//! both arms ran the same code.

use std::path::PathBuf;
use std::process::Command;

mod common;

fn rgx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rgx"))
}

/// A corpus where one pattern prunes: eight files, two holding the needle.
/// The store is built once and shared by both arms of every comparison.
///
/// The directory is one of this run's own: `common::scratch` owns the rule
/// its name follows, and the rule is written down there.
fn fixture() -> (PathBuf, PathBuf) {
    let dir = common::scratch("ablation");
    let store = dir.join("store");
    let corpus = dir.join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    for i in 0..8 {
        let body = if i < 2 {
            "needle in file\nfn main() { let x = e42; }\nfoo bar baz\n"
        } else {
            "fn helper() {}\nother pub fn shape\ne7 filler\n"
        };
        std::fs::write(corpus.join(format!("f{i}.txt")), body).unwrap();
    }
    let out = rgx()
        .arg("--tv-build")
        .arg(&corpus)
        .args(["--tv-store"])
        .arg(&store)
        .output()
        .expect("spawn rgx --tv-build");
    assert_eq!(out.status.code(), Some(0), "tv-build failed: {out:?}");
    (corpus, store)
}

fn run(cmd: &mut Command) -> (String, String, i32) {
    let out = cmd.output().expect("spawn rgx");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or(-1),
    )
}

/// The n-gram switch: same answers with the filter standing down, and the
/// prune counter proving it really stood down.
#[test]
fn the_ngram_ablation_changes_no_answer_and_prunes_nothing() {
    let (_corpus, store) = fixture();

    let plain = run(rgx()
        .arg("needle")
        .args(["--tv-store"])
        .arg(&store)
        .arg("-c")
        .env("RGX_NGRAM_STATS", "1")
        .env_remove("RGX_ADAPTER_VIEW"));
    let ablated = run(rgx()
        .arg("needle")
        .args(["--tv-store"])
        .arg(&store)
        .arg("-c")
        .env("RGX_NGRAM_STATS", "1")
        .env("RGX_ABLATE_NGRAM", "1")
        .env_remove("RGX_ADAPTER_VIEW"));

    assert_eq!(
        plain.0, ablated.0,
        "ablation must change cost, never stdout:\nplain={}\nablated={}",
        plain.0, ablated.0
    );
    assert_eq!(plain.2, ablated.2, "exit codes must agree");

    // Vacuity: the filter must have pruned something in the plain arm and
    // nothing in the ablated one, or both arms ran the same code.
    let pruned = |stderr: &str| -> usize {
        stderr
            .lines()
            .find(|l| l.contains("rgx-ngram: pruned"))
            .unwrap_or_else(|| panic!("no n-gram stats line in stderr:\n{stderr}"))
            .split_whitespace()
            .nth(2)
            .expect("pruned count")
            .parse()
            .expect("numeric pruned count")
    };
    assert!(
        pruned(&plain.1) > 0,
        "the fixture must prune in the plain arm:\n{}",
        plain.1
    );
    assert_eq!(
        pruned(&ablated.1),
        0,
        "the ablated arm must prune nothing:\n{}",
        ablated.1
    );

    std::fs::remove_dir_all(store.parent().unwrap()).ok();
}

/// The mask switch: a pattern grid where every answer must survive the
/// compiled mask being declined at compile time.
#[test]
fn the_mask_ablation_changes_no_answer() {
    let (corpus, store) = fixture();

    for pat in [
        "e[0-9]",
        "foo.*bar",
        "(pub|fn) [a-z]+",
        "pub fn",
        "a|b",
        "^needle",
        r"\d+em",
    ] {
        for (label, extra) in [("direct", None), ("tv", Some("--tv-store"))] {
            let mut plain = rgx();
            plain
                .arg(pat)
                .arg("-c")
                .arg(&corpus)
                .env_remove("RGX_ADAPTER_VIEW")
                .env_remove("RGX_NGRAM_STATS");
            let mut ablated = rgx();
            ablated
                .arg(pat)
                .arg("-c")
                .arg(&corpus)
                .env_remove("RGX_ADAPTER_VIEW")
                .env_remove("RGX_NGRAM_STATS")
                .env("RGX_ABLATE_MASK", "1");
            if let Some(flag) = extra {
                plain.args([flag]).arg(&store);
                ablated.args([flag]).arg(&store);
            }
            let a = run(&mut plain);
            let b = run(&mut ablated);
            assert_eq!(
                a.0, b.0,
                "pattern {pat:?} ({label}) must report the same lines \
                 with the mask declined:\nplain={}\nablated={}",
                a.0, b.0
            );
            assert_eq!(a.2, b.2, "pattern {pat:?} ({label}) exit codes must agree");
        }
    }

    std::fs::remove_dir_all(store.parent().unwrap()).ok();
}

/// Vacuity for the mask switch: `e[0-9]` compiles a mask anchor, and with
/// the switch set the same compile must carry none -- or the two arms of
/// `the_mask_ablation_changes_no_answer` ran the same code and proved
/// nothing. The check is at the library seam (`anchor_info`) because the
/// search path's map form does not tally into `RGX_MASK_STATS`; the setter
/// is the in-process form of the same switch, and this test binary is the
/// only thing compiling patterns in this process, so nothing races it.
#[test]
fn the_mask_ablation_really_removes_the_mask() {
    use rgx_core::regex::ByteRegex;

    let has_mask = |pat: &str| -> bool {
        ByteRegex::new(pat.as_bytes())
            .expect("pattern compiles")
            .anchor_info()
            .iter()
            .any(|a| matches!(a.kind, "matchmask" | "premask"))
    };

    assert!(
        has_mask("e[0-9]"),
        "e[0-9] must compile a mask anchor, or this test proves nothing"
    );
    rgx_core::set_ablate_mask(true);
    let ablated = has_mask("e[0-9]");
    rgx_core::set_ablate_mask(false);
    assert!(
        !ablated,
        "with the switch set, no mask anchor may be offered"
    );
}
