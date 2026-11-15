// SPDX-License-Identifier: Apache-2.0

//! The adapter rollup in the pack store's `ngram` field: what it must
//! cover, when the filter may use it, and what it must never do.
//!
//! `FileRecord::ngram` is the OR rollup over the file's own text and every
//! unit the adapter pipeline can produce (`SIG_COVERS_ADAPTER`), signed
//! under an extraction fingerprint the head names. These tests are the FNR
//! teeth: a container whose text lives only in its member must still match
//! through the store (a raw-only signature would prune it), a container
//! whose member lacks the needle must actually be pruned (a filter that
//! stood down for everything would pass every test above silently), and a
//! query whose extraction context moved must stand the filter down and keep
//! the answer.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::write::GzEncoder;
use flate2::Compression;

mod common;

/// The needle's 4-grams must be absent from a fixture's compressed bytes
/// for that fixture to prove anything: `hit` would match on its raw text
/// alone (the filter passes it for the wrong reason) and `miss` would not
/// prune (its rollup holds the grams by collision). Compressed streams
/// holding no gram of the needle are the only fixtures where the rollup is
/// the difference between a match and a lost match.
fn assert_grams_absent(hay: &[u8], needle: &str, what: &str) {
    for gram in needle.as_bytes().windows(4) {
        assert!(
            !hay.windows(4).any(|w| w == gram),
            "{what}: compressed bytes carry the gram {gram:?} of the needle"
        );
    }
}

fn write_gz(path: &Path, member: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut enc = GzEncoder::new(&mut buf, Compression::best());
    enc.write_all(member.as_bytes()).unwrap();
    enc.finish().unwrap();
    fs::write(path, &buf).unwrap();
    buf
}

/// A member with the needle line buried in compressible filler. Two
/// properties make this fixture honest, and both are asserted where they
/// matter. The filler is a repeated common-word line: it compresses to
/// nothing (so the needle's literals come out of deflate huffman-coded at a
/// bit offset rather than byte-aligned in the stream) and its 4-grams are
/// background noise the signature layer skips (so the member's signature is
/// the needle's bits and a sparse few, not the all-ones a page of varied
/// text produces -- a saturated signature can never prune anything).
fn filled_member(needle_line: &str) -> String {
    let mut s = String::new();
    for i in 0..200 {
        if i == 100 {
            s.push_str(needle_line);
            s.push('\n');
        }
        s.push_str("the cat sat on the mat the cat sat on the mat\n");
    }
    s
}

///
/// The directory is one of this run's own: `common::scratch` owns the rule
/// its name follows, and the rule is written down there.
fn scratch(tag: &str) -> PathBuf {
    common::scratch(&format!("sigroll-{tag}"))
}

fn rgx() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rgx"));
    c.env_remove("RGX_ADAPTER_VIEW");
    c.env_remove("RGX_BASE");
    c
}

/// pruned N of M -- what `RGX_NGRAM_STATS=1` prints on stderr. The counter
/// is the proof the filter engaged at all.
fn prune_counts(stderr: &str) -> (usize, usize) {
    let line = stderr
        .lines()
        .find(|l| l.contains("rgx-ngram: pruned"))
        .unwrap_or_else(|| panic!("no ngram stats line in stderr:\n{stderr}"));
    let mut it = line
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty());
    let pruned = it.next().expect("pruned count").parse().unwrap();
    let total = it.next().expect("total count").parse().unwrap();
    (pruned, total)
}

const NEEDLE: &str = "zqxneedle42flyer";

/// The two directions of the filter's FNR=0 contract, in one query. The
/// hit container holds the needle only in its member text -- the store must
/// find it, which a raw-only signature would have pruned away -- and the
/// miss container holds it nowhere, so the filter must reject it before its
/// bytes are read. A regression of the rollup loses the hit; a regression of
/// the engagement (standing down for everything) moves the prune counter to
/// zero.
#[test]
fn the_rollup_finds_a_member_only_needle_and_prunes_the_container_that_lacks_it() {
    let d = scratch("fnr");
    let store = scratch("fnr-store");
    let hit = write_gz(
        &d.join("hit.txt.gz"),
        &filled_member(&format!("{NEEDLE} in the member")),
    );
    // The miss member is small on purpose: a page of varied text saturates
    // the 512-bit signature and a saturated record can never be pruned.
    let miss = write_gz(&d.join("miss.txt.gz"), "nothing to see in this member\n");
    fs::write(d.join("plain.txt"), format!("{NEEDLE} in plain text\n")).unwrap();
    assert_grams_absent(&hit, NEEDLE, "hit.txt.gz");
    assert_grams_absent(&miss, NEEDLE, "miss.txt.gz");
    // The teeth of the find half: signed over its raw bytes alone, the hit
    // is a file the filter must reject. Only the member's text in the
    // rollup keeps it in the answer.
    let q = rgx_core::ngram::query_sig512(NEEDLE, false).expect("the needle is a literal");
    assert!(
        !rgx_core::ngram::build_stored_sig512(&hit).contains_query(&q),
        "the hit fixture's raw signature would prune it; it proves nothing"
    );

    let b = rgx()
        .arg("--tv-build")
        .arg("--tv-store")
        .arg(&store)
        .arg(&d)
        .output()
        .unwrap();
    assert!(
        b.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&b.stderr)
    );

    let q = rgx()
        .env("RGX_NGRAM_STATS", "1")
        .arg("--tv")
        .arg("--tv-store")
        .arg(&store)
        .args(["-c", NEEDLE])
        .arg(&d)
        .output()
        .unwrap();
    assert!(q.status.success(), "{}", String::from_utf8_lossy(&q.stderr));
    let store_out = String::from_utf8_lossy(&q.stdout).to_string();

    let direct = rgx()
        .args(["--engine", "rgx", "-c", NEEDLE])
        .arg(&d)
        .output()
        .unwrap();
    assert_eq!(
        store_out,
        String::from_utf8_lossy(&direct.stdout).to_string(),
        "the store and the direct engine must agree, count for count"
    );
    assert!(
        store_out.contains("hit.txt.gz"),
        "the member-only needle must be found"
    );
    assert!(!store_out.contains("miss.txt.gz"));

    let (pruned, total) = prune_counts(&String::from_utf8_lossy(&q.stderr));
    assert_eq!(total, 3, "three active files in the fixture");
    assert_eq!(
        pruned, 1,
        "exactly the miss container is prunable -- 0 means the filter stood down for everything"
    );

    let _ = fs::remove_dir_all(&d);
    let _ = fs::remove_dir_all(&store);
}

/// The rollups were signed under one extraction context; a query running a
/// different one (here: a member budget that would truncate what the
/// pipeline extracts) is not covered by them, so the filter must stand down
/// on adapter-claimed records and the answer must not move.
#[test]
fn the_filter_stands_down_when_the_extraction_context_moves() {
    let d = scratch("fpmismatch");
    let store = scratch("fpmismatch-store");
    write_gz(
        &d.join("hit.txt.gz"),
        &filled_member(&format!("{NEEDLE} in the member")),
    );
    write_gz(&d.join("miss.txt.gz"), "nothing to see in this member\n");
    fs::write(d.join("plain.txt"), format!("{NEEDLE} in plain text\n")).unwrap();

    let b = rgx()
        .arg("--tv-build")
        .arg("--tv-store")
        .arg(&store)
        .arg(&d)
        .output()
        .unwrap();
    assert!(
        b.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&b.stderr)
    );

    let run = |budget: Option<&str>| {
        let mut c = rgx();
        c.env("RGX_NGRAM_STATS", "1");
        if let Some(b) = budget {
            c.env("RGX_MAX_MEMBERS", b);
        }
        let out = c
            .arg("--tv")
            .arg("--tv-store")
            .arg(&store)
            .args(["-c", NEEDLE])
            .arg(&d)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    };

    // The same single-member containers answer under either budget, so any
    // answer difference would be the filter's doing, not the corpus's.
    let base = run(None);
    let moved = run(Some("2"));
    assert_eq!(
        String::from_utf8_lossy(&base.stdout),
        String::from_utf8_lossy(&moved.stdout),
        "a moved extraction context may change pruning, never the answer"
    );
    assert!(String::from_utf8_lossy(&base.stdout).contains("hit.txt.gz"));

    let (base_pruned, _) = prune_counts(&String::from_utf8_lossy(&base.stderr));
    let (moved_pruned, _) = prune_counts(&String::from_utf8_lossy(&moved.stderr));
    assert_eq!(base_pruned, 1, "under the signing context the miss prunes");
    assert_eq!(
        moved_pruned, 0,
        "under a moved context the filter stands down on claimed files"
    );

    let _ = fs::remove_dir_all(&d);
    let _ = fs::remove_dir_all(&store);
}

/// A container rewritten to lose its old member and gain a new one goes
/// through the update path, which must re-sign it through the same hook the
/// build used: the fresh member is found (count parity with the direct
/// engine), and the tombstoned one answers nothing.
#[test]
fn an_incremental_update_re_signs_a_changed_container() {
    let d = scratch("update");
    let store = scratch("update-store");
    let old_gz = write_gz(
        &d.join("a.txt.gz"),
        &filled_member("old marker in the member"),
    );
    fs::write(d.join("b.txt"), "marker in plain text\n").unwrap();

    let b = rgx()
        .arg("--tv-build")
        .arg("--tv-store")
        .arg(&store)
        .arg(&d)
        .output()
        .unwrap();
    assert!(
        b.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&b.stderr)
    );

    // The member changes: "old marker" is lost, "fresh marker" gained.
    let new_gz = write_gz(
        &d.join("a.txt.gz"),
        &filled_member("fresh marker in the member"),
    );
    assert_grams_absent(&old_gz, "old marker", "the old a.txt.gz");
    assert_grams_absent(&new_gz, "fresh marker", "the new a.txt.gz");
    let u = rgx()
        .arg("--tv-build")
        .arg("--tv-store")
        .arg(&store)
        .arg(&d)
        .output()
        .unwrap();
    assert!(
        u.status.success(),
        "update failed: {}",
        String::from_utf8_lossy(&u.stderr)
    );

    // `--sort path` on both sides: an update is append-only, so a changed
    // record's manifest slot is not its walk slot and the two engines'
    // default orders legitimately differ. Sorted, the answers must be
    // identical line for line.
    let q = |pat: &str, extra: &[&str]| {
        let store_out = rgx()
            .arg("--tv")
            .arg("--tv-store")
            .arg(&store)
            .args(extra)
            .args(["--sort", "path"])
            .arg(pat)
            .arg(&d)
            .output()
            .unwrap();
        let direct = rgx()
            .args(["--engine", "rgx"])
            .args(extra)
            .args(["--sort", "path"])
            .arg(pat)
            .arg(&d)
            .output()
            .unwrap();
        (
            String::from_utf8_lossy(&store_out.stdout).to_string(),
            String::from_utf8_lossy(&direct.stdout).to_string(),
        )
    };

    let (store_marker, direct_marker) = q("marker", &["-n"]);
    assert_eq!(store_marker, direct_marker, "count parity after the update");
    assert!(
        store_marker.contains("fresh marker"),
        "the gained member answers"
    );
    assert!(
        !store_marker.contains("old marker"),
        "the tombstoned member must be gone"
    );

    let (store_old, direct_old) = q("old marker", &["-c"]);
    assert_eq!(store_old, direct_old);
    assert!(
        store_old.trim().is_empty(),
        "nothing holds the lost member's text"
    );

    let _ = fs::remove_dir_all(&d);
    let _ = fs::remove_dir_all(&store);
}

/// The whole point: `--tv` and the direct engine answer one mixed tree --
/// text, containers, an empty file -- with the same lines and the same
/// counts.
#[test]
fn the_store_and_the_direct_engine_agree_on_a_mixed_tree() {
    let d = scratch("mixed");
    let store = scratch("mixed-store");
    fs::write(d.join("one.txt"), format!("marker in one\n{NEEDLE} too\n")).unwrap();
    fs::write(d.join("two.txt"), "marker in two\n").unwrap();
    write_gz(&d.join("three.txt.gz"), "marker in three's member\n");
    write_gz(&d.join("four.txt.gz"), "no needle here\n");
    fs::write(d.join("empty.txt"), "").unwrap();

    let b = rgx()
        .arg("--tv-build")
        .arg("--tv-store")
        .arg(&store)
        .arg(&d)
        .output()
        .unwrap();
    assert!(
        b.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&b.stderr)
    );

    for extra in [&["-c"][..], &["-n"][..], &["-n", "-F"][..]] {
        let store_out = rgx()
            .arg("--tv")
            .arg("--tv-store")
            .arg(&store)
            .args(extra)
            .arg("marker")
            .arg(&d)
            .output()
            .unwrap();
        assert!(
            store_out.status.success(),
            "{}",
            String::from_utf8_lossy(&store_out.stderr)
        );
        let direct = rgx()
            .args(["--engine", "rgx"])
            .args(extra)
            .arg("marker")
            .arg(&d)
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&store_out.stdout),
            String::from_utf8_lossy(&direct.stdout),
            "mode {extra:?} must agree between engines"
        );
    }

    let _ = fs::remove_dir_all(&d);
    let _ = fs::remove_dir_all(&store);
}
