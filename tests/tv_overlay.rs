// SPDX-License-Identifier: Apache-2.0

//! The dirty-file overlay: a store the filesystem has moved answers from
//! the disk for the changed files and from the packs for the rest.
//!
//! What these hold down: `run_tv_query` re-reads every record the manifest
//! and the filesystem disagree on and searches the bytes it finds now, so
//! a stale store is a slower store and never a wrong answer. The one rule
//! that must not regress is the n-gram filter's: a dirty file's stored
//! signature covers the bytes the build saw, so the filter stands down on
//! it -- pruning on a stale signature is exactly how a filter loses a
//! match to an edit.

use std::path::PathBuf;
use std::process::Command;

mod common;

fn rgx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rgx"))
}

///
/// The directory is one of this run's own: `common::scratch` owns the rule
/// its name follows, and the rule is written down there.
fn scratch(tag: &str) -> PathBuf {
    common::scratch(&format!("tv-overlay-{tag}"))
}

/// An edit whose match lives only in the bytes written after the build.
///
/// What this holds down: the file's stored signature is the signature of
/// content that no longer exists. If the n-gram filter evaluated it
/// against the query, the file would be pruned before its bytes were read
/// and the match would vanish from the store's answer while the direct
/// path printed it. The overlay must stand the filter down on every dirty
/// record; this is the false-negative the whole filter contract exists to
/// forbid.
#[test]
fn an_edit_the_stored_signature_would_prune_is_still_found() {
    let dir = scratch("fnr");
    std::fs::write(dir.join("a.txt"), b"filler text without the literal\n").unwrap();
    std::fs::write(dir.join("z.txt"), b"nothing to see here\n").unwrap();

    let build = rgx().arg("--tv-build").arg(&dir).output().expect("spawn");
    assert!(build.status.success(), "--tv-build failed");

    // The query's required literal appears only in the rewritten bytes;
    // the build signed content that held none of its 4-grams.
    std::fs::write(
        dir.join("a.txt"),
        b"the magic xyzzy42 appears only after the build\n",
    )
    .unwrap();

    let dir_s = dir.to_string_lossy().to_string();
    for extra in [vec!["--tv"], vec![]] {
        let mut args = extra.clone();
        args.extend(["-F", "-n", "xyzzy42", dir_s.as_str()]);
        let label = format!("{args:?}");
        let out = rgx()
            .args(args)
            .env_remove("RGX_ADAPTER_VIEW")
            .output()
            .expect("spawn");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            stdout.contains("a.txt:1") && stdout.contains("xyzzy42"),
            "the overlay must find a match that lives only in the edited \
             bytes (args {label}):\n{stdout}"
        );
        assert_eq!(out.status.code(), Some(0), "match must set the status");
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// A container rewritten after the build is searched through the adapter
/// pipeline on its new bytes.
///
/// What this holds down: the adapter branch runs on whatever bytes the
/// overlay supplies, so a changed `.gz` must answer with its new member --
/// member path included -- exactly as the direct path does. The container
/// case is the whole point of the overlay: the signature that would prune
/// it covers compressed bytes nobody searches.
#[test]
fn a_rewritten_container_is_searched_through_the_adapter() {
    let dir = scratch("zip");
    let gz_of = |text: &[u8]| {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(text).unwrap();
        enc.finish().unwrap()
    };
    std::fs::write(dir.join("b.txt.gz"), gz_of(b"stale member content\n")).unwrap();
    std::fs::write(dir.join("plain.txt"), b"untouched\n").unwrap();

    let build = rgx().arg("--tv-build").arg(&dir).output().expect("spawn");
    assert!(build.status.success(), "--tv-build failed");

    std::fs::write(
        dir.join("b.txt.gz"),
        gz_of(b"fresh marker only in the new member\n"),
    )
    .unwrap();

    let dir_s = dir.to_string_lossy().to_string();
    for extra in [vec!["--tv"], vec![]] {
        let mut args = extra.clone();
        args.extend(["-F", "-n", "marker", dir_s.as_str()]);
        let label = format!("{args:?}");
        let out = rgx()
            .args(args)
            .env_remove("RGX_ADAPTER_VIEW")
            .output()
            .expect("spawn");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            stdout.contains("b.txt.gz!b.txt"),
            "the rewritten member must be reported through the adapter \
             (args {label}):\n{stdout}"
        );
        assert!(
            !stdout.contains("stale member"),
            "the old member's bytes are gone and must not be answered:\n{stdout}"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// The overlay answers exactly what the direct path answers, deletions
/// included.
///
/// What this holds down: parity is the direction's falsifier. One file is
/// edited, one deleted, one left alone; every flag shape that counts or
/// lists (`-c`, `-n`, `--files`) must agree line for line with
/// `--engine rgx` on the same tree. A deleted file owes nothing to
/// anyone -- no match, no listing -- and a file added after the build is
/// the boundary neither side sees.
#[test]
fn the_overlay_answers_exactly_what_the_direct_path_answers() {
    let dir = scratch("parity");
    let store = scratch("parity-store");
    std::fs::write(dir.join("keep.txt"), b"alpha common marker\n").unwrap();
    std::fs::write(dir.join("edit.txt"), b"old marker line\n").unwrap();
    std::fs::write(dir.join("gone.txt"), b"marker to remove\n").unwrap();

    let build = rgx()
        .arg("--tv-build")
        .arg("--tv-store")
        .arg(&store)
        .arg(&dir)
        .output()
        .expect("spawn");
    assert!(build.status.success(), "--tv-build failed");

    std::fs::write(dir.join("edit.txt"), b"fresh marker line\n").unwrap();
    std::fs::remove_file(dir.join("gone.txt")).unwrap();

    let dir_s = dir.to_string_lossy().to_string();
    let run = |args: &[&str]| -> (Vec<String>, String, i32) {
        let mut full = args.to_vec();
        full.push(&dir_s);
        let out = rgx()
            .args(full)
            .env_remove("RGX_ADAPTER_VIEW")
            .output()
            .expect("spawn");
        let mut lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        lines.sort();
        (
            lines,
            String::from_utf8_lossy(&out.stderr).to_string(),
            out.status.code().unwrap_or(-1),
        )
    };

    for extra in [
        vec!["-F", "-n", "marker"],
        vec!["-F", "-c", "marker"],
        vec!["--files"],
    ] {
        let mut direct = vec!["--engine", "rgx"];
        direct.extend_from_slice(&extra);
        let (d_lines, _, d_code) = run(&direct);
        let mut tv = vec!["--tv", "--tv-store"];
        tv.push(store.to_str().unwrap());
        tv.extend_from_slice(&extra);
        let (t_lines, t_err, t_code) = run(&tv);

        assert_eq!(
            t_lines, d_lines,
            "--tv overlay must answer what the direct path answers for \
             {extra:?}:\n{t_err}"
        );
        assert_eq!(
            t_code, d_code,
            "exit status must agree for {extra:?}:\n{t_err}"
        );
    }

    // The deletion is visible, not just tolerated: no listing, no count.
    let (files, _, _) = run(&["--files"]);
    assert!(
        !files.iter().any(|l| l.contains("gone.txt")),
        "a deleted file must vanish from the listing:\n{files:#?}"
    );
    assert!(
        !files
            .iter()
            .any(|l| l.contains("edit.txt") && l.contains("gone")),
        "sanity: the fixture's names must be distinct:\n{files:#?}"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&store).ok();
}

/// A `--tv-pre-extract` store keeps its member answers through the
/// overlay, drift or none.
///
/// What this holds down: a member record's name (`container!member`) is no
/// path on disk, and the overlay once judged every such record gone-on-disk
/// and dropped the container's whole answer from a store nothing had
/// changed in -- a wrong answer replacing the right one the pack held. The
/// rule is the owner's: a member record is stale exactly when its container
/// is, fresh records are answered from the pack, and a changed container's
/// members are answered from its current extraction.
#[test]
fn a_pre_extract_store_keeps_its_member_answers() {
    let dir = scratch("prex");
    let gz_of = |text: &[u8]| {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(text).unwrap();
        enc.finish().unwrap()
    };
    std::fs::write(dir.join("a.txt"), b"plain needle line\n").unwrap();
    std::fs::write(dir.join("b.txt.gz"), gz_of(b"needle only in the member\n")).unwrap();

    let build = rgx()
        .arg("--tv-build")
        .arg("--tv-pre-extract")
        .arg(&dir)
        .output()
        .expect("spawn");
    assert!(
        build.status.success(),
        "--tv-build --tv-pre-extract failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let dir_s = dir.to_string_lossy().to_string();
    let sorted = |args: &[&str]| -> Vec<String> {
        let mut full = args.to_vec();
        full.push(dir_s.as_str());
        let out = rgx()
            .args(full)
            .env_remove("RGX_ADAPTER_VIEW")
            .output()
            .expect("spawn");
        let mut v: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        v.sort();
        v
    };

    let direct = sorted(&["--engine", "rgx", "-F", "-n", "needle"]);
    assert!(
        direct.iter().any(|l| l.contains("b.txt.gz!b.txt")),
        "the fixture's member must be findable at all:\n{direct:#?}"
    );
    for arm in [vec!["--tv"], vec![]] {
        let mut args = arm.clone();
        args.extend(["-F", "-n", "needle"]);
        assert_eq!(
            sorted(&args),
            direct,
            "a fresh pre-extract store must answer like the direct path \
             (arm {arm:?})"
        );
    }

    // The detector promotes a fresh pre-extract store -- the owner-aware
    // freshness rule is what stops member names reading as gone-on-disk.
    let explain = rgx()
        .args(["--explain-engine", "-F", "-n", "needle"])
        .arg(&dir)
        .output()
        .expect("spawn");
    let stderr = String::from_utf8_lossy(&explain.stderr).to_string();
    assert!(
        stderr.contains("selected engine: tv"),
        "a fresh pre-extract store must promote:\n{stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A container rewritten after a pre-extract build is re-extracted for its
/// members by the overlay.
///
/// What this holds down: the member records of a changed container hold
/// the extraction the build made -- text that no longer exists. The overlay
/// must answer them from the container's current bytes, which is what a
/// rebuild would have stored, and say nothing for members the new bytes no
/// longer contain.
#[test]
fn a_rewritten_container_in_a_pre_extract_store_is_re_extracted() {
    let dir = scratch("prex-dirty");
    let gz_of = |text: &[u8]| {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(text).unwrap();
        enc.finish().unwrap()
    };
    std::fs::write(dir.join("plain.txt"), b"untouched\n").unwrap();
    std::fs::write(
        dir.join("b.txt.gz"),
        gz_of(b"old marker text in the member\n"),
    )
    .unwrap();

    let build = rgx()
        .arg("--tv-build")
        .arg("--tv-pre-extract")
        .arg(&dir)
        .output()
        .expect("spawn");
    assert!(build.status.success(), "--tv-build failed");

    std::fs::write(
        dir.join("b.txt.gz"),
        gz_of(b"fresh marker text only in the new member\n"),
    )
    .unwrap();

    let dir_s = dir.to_string_lossy().to_string();
    let sorted = |args: &[&str]| -> (Vec<String>, String, i32) {
        let mut full = args.to_vec();
        full.push(dir_s.as_str());
        let out = rgx()
            .args(full)
            .env_remove("RGX_ADAPTER_VIEW")
            .output()
            .expect("spawn");
        let mut v: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        v.sort();
        (
            v,
            String::from_utf8_lossy(&out.stderr).to_string(),
            out.status.code().unwrap_or(-1),
        )
    };

    let (d_lines, _, d_code) = sorted(&["--engine", "rgx", "-F", "-n", "marker"]);
    let (t_lines, t_err, t_code) = sorted(&["--tv", "-F", "-n", "marker"]);
    assert_eq!(
        t_lines, d_lines,
        "the overlay must answer the rewritten member exactly as the \
         direct path does:\n{t_err}"
    );
    assert_eq!(t_code, d_code, "exit status must agree:\n{t_err}");
    assert!(
        t_lines.iter().any(|l| l.contains("fresh marker")),
        "the new member's text must be found:\n{t_lines:#?}"
    );
    assert!(
        !t_lines.iter().any(|l| l.contains("old marker")),
        "the old member's text is gone from disk and must not be answered:\n{t_lines:#?}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
