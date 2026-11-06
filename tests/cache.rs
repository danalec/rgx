// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the extraction cache (`--cache`).
//!
//! The question these answer is not "does the cache work" but "can it serve
//! something the search would not have produced". Every test below either
//! counts a miss where a hit would be wrong, or compares cached output
//! against the uncached output of the same tree.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

/// A fresh temporary directory of its own: a test that put the cache inside
/// the tree it searches would be searching its own entries.
///
/// The name and the rule behind it belong to `common::scratch`, which is
/// where the house keeps them: the counter that makes the name unique
/// inside the process, and the `create_dir` that makes the directory one
/// this run created -- a name that is taken is not reused, it is moved
/// past.
fn scratch(tag: &str) -> PathBuf {
    common::scratch(&format!("cache-{tag}"))
}

/// A tree of zips: the archive adapter does real work per file, so a hit is
/// worth having and a stale hit would be visible in the output.
fn fixture() -> PathBuf {
    let dir = scratch("fixture");
    for i in 0..3 {
        zip(&dir.join(format!("pack{i}.zip")), i);
    }
    dir
}

/// The lines the fixture answers: three zips, five members each, and the
/// member `m` carries `m + 1` needle lines, so `3 * (1 + 2 + 3 + 4 + 5)`.
const EXPECTED_LINES: usize = 45;

fn zip(path: &Path, tag: usize) {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for m in 0..5 {
            w.start_file(format!("member{m}.txt"), opts).unwrap();
            let body = format!("filler\nneedle {tag}-{m}\n").repeat(m + 1);
            w.write_all(body.as_bytes()).unwrap();
        }
        w.finish().unwrap();
    }
    std::fs::write(path, buf).unwrap();
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    /// `(hits, misses, stored, errors)` from the cache summary rgx prints
    /// when `--cache` is on.
    fn cache_tally(&self) -> (u64, u64, u64, u64) {
        let line = self
            .stderr
            .lines()
            .find(|l| l.starts_with("cache: "))
            .unwrap_or_else(|| panic!("no cache summary in stderr:\n{}", self.stderr));
        let n = |i: usize| -> u64 { line.split_whitespace().nth(i).unwrap().parse().unwrap() };
        (n(1), n(3), n(5), n(7))
    }
}

fn run(args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_rgx"))
        .args(args)
        .output()
        .expect("failed to spawn rgx");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn searched(dir: &Path, cache: &Path, extra: &[&str]) -> Run {
    let mut args = vec!["--cache", cache.to_str().unwrap()];
    args.extend_from_slice(extra);
    args.push("needle");
    args.push(dir.to_str().unwrap());
    run(&args)
}

fn lines(s: &str) -> Vec<String> {
    let mut v: Vec<String> = s.lines().map(str::to_string).collect();
    v.sort();
    v
}

/// Whether the three zips the fixture is made of can be read.
///
/// This is the question that separates the two ways a comparison can fail.
/// A file that cannot be opened, or a tree that lost one, is the machine's
/// answer and not the tool's: rgx walks past a path it cannot read and
/// says nothing about it, so a run over a tree that lost a file answers
/// *nothing* and carries no reason -- and "nothing" is indistinguishable
/// from "the cache lost the answer" unless the tree is asked.
///
/// So the tree is asked here, by the test, with its own read: a tree the
/// test can read is a tree the run could have read.
fn tree_is_readable(dir: &Path) -> bool {
    (0..3).all(|i| std::fs::read(dir.join(format!("pack{i}.zip"))).is_ok())
}

/// A run that answered less than it should is retried, a bounded number of
/// times.
///
/// The run that re-reads the files meets the filesystem: a file that is
/// momentarily unreadable -- a scanner holding it open on the runner --
/// makes that run answer less, and an answer that carries no reason
/// cannot be told apart from a cache that lost the answer.
///
/// So a short answer is retried, and the tree is asked afterwards so the
/// failure says which of the two it was. A persistent shortfall is still a
/// failure: the retry buys the machine a second chance, it does not buy a
/// broken cache one.
fn retried(mut f: impl FnMut() -> Run, expected: usize) -> (Run, u32) {
    const ATTEMPTS: u32 = 5;
    let mut attempt = 0;
    loop {
        attempt += 1;
        let out = f();
        if out.stdout.lines().count() >= expected || attempt >= ATTEMPTS {
            return (out, attempt);
        }
        std::thread::sleep(std::time::Duration::from_millis(100 * attempt as u64));
    }
}

/// The archive budget the producers read from the environment moves the
/// units without moving the `Ctx`, so it belongs in the memo's key: a
/// truncated extraction made under `RGX_MAX_MEMBERS=2` used to be served
/// unchanged by a run without it, and the members past the cap stayed
/// invisible until the file itself changed.
#[test]
fn a_cache_entry_made_under_a_small_budget_is_not_served_under_a_larger_one() {
    let dir = scratch("budget-key");
    zip(&dir.join("pack.zip"), 0);
    let cache = scratch("budget-key-cache");

    let small = Command::new(env!("CARGO_BIN_EXE_rgx"))
        .env("RGX_MAX_MEMBERS", "2")
        .args([
            "--cache",
            cache.to_str().unwrap(),
            "needle",
            dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to spawn rgx");
    assert_eq!(small.status.code(), Some(0));
    let small_out = String::from_utf8_lossy(&small.stdout);
    assert!(
        !small_out.contains("member4"),
        "the small budget truncated before it: {small_out}"
    );

    let full = Command::new(env!("CARGO_BIN_EXE_rgx"))
        .args([
            "--cache",
            cache.to_str().unwrap(),
            "needle",
            dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to spawn rgx");
    assert_eq!(full.status.code(), Some(0));
    let full_out = String::from_utf8_lossy(&full.stdout);
    assert!(
        full_out.contains("member4"),
        "the full budget must re-extract, not serve the truncated entry: {full_out}"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&cache).ok();
}

#[test]
fn a_second_run_over_an_unchanged_tree_hits() {
    let dir = fixture();
    let cache = scratch("cache");
    let first = searched(&dir, &cache, &[]);
    assert_eq!(first.code, 0);
    assert_eq!(
        (0, 3, 3, 0),
        first.cache_tally(),
        "a cold run stores one entry per file"
    );

    let second = searched(&dir, &cache, &[]);
    assert_eq!((3, 0, 0, 0), second.cache_tally(), "an unchanged tree hits");
    assert_eq!(
        lines(&first.stdout),
        lines(&second.stdout),
        "a hit is invisible in the output"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_cached_run_answers_exactly_as_the_uncached_one() {
    let dir = fixture();
    let cache = scratch("cache");
    // The run that fills the memo reads the files, so it is the run that
    // meets the filesystem. A memo filled short is a memo the comparison
    // below would measure against a short answer.
    let (populate, populate_attempts) = retried(|| searched(&dir, &cache, &[]), EXPECTED_LINES);
    assert_eq!(
        populate.stdout.lines().count(),
        EXPECTED_LINES,
        "the run that fills the memo answered {} of {EXPECTED_LINES} lines after \
         {populate_attempts} attempt(s); the tree is {}; it exited {} and said:\n{}",
        populate.stdout.lines().count(),
        if tree_is_readable(&dir) {
            "readable"
        } else {
            "NOT readable"
        },
        populate.code,
        populate.stderr
    );
    let cached = searched(&dir, &cache, &[]);
    assert_eq!(
        cached.cache_tally(),
        (3, 0, 0, 0),
        "the run under test is a hit on the memo"
    );
    // The cached run has to answer the whole tree, or the comparison below
    // is between two answers that are both short: an empty answer on both
    // sides is equal to an empty answer on one side, and the assertion
    // would pass on a cache that answers nothing at all.
    assert_eq!(
        cached.stdout.lines().count(),
        EXPECTED_LINES,
        "the cached run answered {} lines, not {EXPECTED_LINES}:\n{}",
        cached.stdout.lines().count(),
        cached.stderr
    );
    let (plain, plain_attempts) =
        retried(|| run(&["needle", dir.to_str().unwrap()]), EXPECTED_LINES);
    assert_eq!(
        lines(&cached.stdout),
        lines(&plain.stdout),
        "the uncached run answered {} of {EXPECTED_LINES} lines after {plain_attempts} \
         attempt(s); the tree it reads is {}; it exited {} and said:\n{}",
        plain.stdout.lines().count(),
        if tree_is_readable(&dir) {
            "readable"
        } else {
            "NOT readable"
        },
        plain.code,
        plain.stderr
    );
    assert_eq!(cached.code, plain.code);
    std::fs::remove_dir_all(&dir).ok();
}

/// The probe that tells the two failures apart is itself worth a test: a
/// tree the test can read is a tree the run could have read, and a tree
/// that lost a file is a tree the run was right to say nothing about.
#[test]
fn the_tree_probe_says_whether_the_tree_can_be_read() {
    let dir = fixture();
    assert!(tree_is_readable(&dir), "the fixture is intact");

    let gone = dir.join("pack1.zip");
    std::fs::remove_file(&gone).unwrap();
    assert!(
        !tree_is_readable(&dir),
        "a tree that lost a file is not readable"
    );

    std::fs::remove_dir_all(&dir).ok();
    assert!(
        !tree_is_readable(&dir),
        "a tree that is gone is not readable"
    );
}

/// An answer that is complete is not retried: the retry exists for the
/// machine that lost a file, and a complete answer is an answer.
#[test]
fn a_complete_answer_is_not_retried() {
    let mut calls = 0;
    let (out, attempts) = retried(
        || {
            calls += 1;
            Run {
                code: 0,
                stdout: "needle\n".repeat(EXPECTED_LINES),
                stderr: String::new(),
            }
        },
        EXPECTED_LINES,
    );
    assert_eq!(calls, 1, "a complete answer ends the retry");
    assert_eq!(attempts, 1);
    assert_eq!(out.stdout.lines().count(), EXPECTED_LINES);
}

/// A short answer is retried, and the retry is bounded: a run that never
/// answers what it should is handed over as the failure it is, and not
/// retried for ever.
#[test]
fn a_short_answer_is_retried_and_the_retry_is_bounded() {
    let mut calls = 0;
    let (out, attempts) = retried(
        || {
            calls += 1;
            Run {
                code: 1,
                stdout: String::new(),
                stderr: String::new(),
            }
        },
        EXPECTED_LINES,
    );
    assert_eq!(calls, 5, "the retry is bounded");
    assert_eq!(attempts, 5);
    assert!(out.stdout.is_empty());
}

/// A touched file is re-read, but it is not re-extracted: the content
/// layer catches it.
///
/// The alias is keyed by the path, the size and the mtime, so a touch
/// misses it — the file is read again and hashed. The content key is the
/// bytes, and the bytes did not change, so the extraction is reused. The
/// file is answered from the cache either way; what changes is that the
/// work is a hash instead of a full extraction.
#[test]
fn touching_a_file_does_not_reextract() {
    let dir = fixture();
    let cache = scratch("cache");
    searched(&dir, &cache, &[]);
    let target = dir.join("pack1.zip");
    // a write that leaves the bytes alone and moves the mtime alone: the
    // case a size-only key would get wrong
    filetime_touch(&target);
    let after = searched(&dir, &cache, &[]);
    assert_eq!(
        (3, 0, 0, 0),
        after.cache_tally(),
        "the touched file is re-read but not re-extracted"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn changing_the_bytes_misses() {
    let dir = fixture();
    let cache = scratch("cache");
    searched(&dir, &cache, &[]);
    zip(&dir.join("pack2.zip"), 99); // same member names, different content
    let after = searched(&dir, &cache, &[]);
    assert_eq!((2, 1, 1, 0), after.cache_tally());
    assert!(
        after.stdout.contains("needle 99-4"),
        "the new content is what gets searched:\n{}",
        after.stdout
    );
    assert!(
        !after.stdout.contains("needle 2-4"),
        "no stale member text survives"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Moves a file's modification time forward without touching its contents.
#[cfg(unix)]
fn filetime_touch(path: &Path) {
    let out = Command::new("touch").arg(path).output().unwrap();
    assert!(out.status.success());
}

/// Windows has no `touch`: rewrite the file, which moves its mtime, then
/// put the original bytes back so only the timestamp differs.
///
/// **The rewrite is retried until the mtime actually moves, and this is the
/// whole point of the function.** The previous version did it once and
/// explained why that was enough — "a same-length rewrite on NTFS can land in
/// the same 100ns tick only if the clock did not move; sleep is not needed
/// because the write itself takes far longer than the tick". Both halves of
/// that are wrong. NTFS *stores* 100ns but its timestamp update granularity is
/// about 15.6 ms, so a fast rewrite routinely lands on the value it already
/// had; and the alias key is exactly `mtime_nanos` (`src/cache.rs`), so an
/// unchanged mtime is an alias HIT and this test would not be testing what it
/// says it tests.
///
/// That is an intermittent that only shows on a fast, idle machine — which is
/// why it appeared twice in ~25 runs here and never once when the box was
/// busy. Asserting the invariant directly turns a silent flake into either a
/// pass or an honest failure.
#[cfg(windows)]
fn filetime_touch(path: &Path) {
    let bytes = std::fs::read(path).unwrap();
    let before = std::fs::metadata(path).unwrap().modified().unwrap();
    for _ in 0..16 {
        std::fs::write(path, &bytes).unwrap();
        let after = std::fs::metadata(path).unwrap().modified().unwrap();
        if after != before {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!(
        "filetime_touch: 16 rewrites left the mtime at {:?}; the filesystem's \
         timestamp granularity is coarser than this test assumes",
        before
    );
}

#[test]
fn changing_an_extraction_flag_misses() {
    let dir = fixture();
    let cache = scratch("cache");
    searched(&dir, &cache, &[]);
    let after = searched(&dir, &cache, &["--max-adapter-depth", "2"]);
    assert_eq!(
        (0, 3, 3, 0),
        after.cache_tally(),
        "a different Ctx is a different key"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_damaged_entry_is_re_extracted_not_served() {
    let dir = fixture();
    let cache = scratch("cache");
    searched(&dir, &cache, &[]);
    let good = searched(&dir, &cache, &[]);
    assert_eq!((3, 0, 0, 0), good.cache_tally());
    for entry in entries(&cache) {
        let raw = std::fs::read(&entry).unwrap();
        std::fs::write(&entry, &raw[..raw.len() / 2]).unwrap();
    }
    let after = searched(&dir, &cache, &[]);
    assert_eq!(
        (0, 3, 3, 3),
        after.cache_tally(),
        "a truncated entry is a miss"
    );
    assert_eq!(
        lines(&good.stdout),
        lines(&after.stdout),
        "and the answer is unchanged"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn clear_empties_the_cache() {
    let dir = fixture();
    let cache = scratch("cache");
    searched(&dir, &cache, &[]);
    let cleared = run(&["--cache", cache.to_str().unwrap(), "--cache-clear"]);
    assert_eq!(0, cleared.code, "{}", cleared.stderr);
    // Each file in the tree is two entries in the cache: the content entry
    // that holds the extraction and the alias that points at it. Three
    // files, six entries.
    assert!(
        cleared.stderr.contains("6 cache entries removed"),
        "{}",
        cleared.stderr
    );
    let after = searched(&dir, &cache, &[]);
    assert_eq!((0, 3, 3, 0), after.cache_tally());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn prune_keeps_recent_entries() {
    let dir = fixture();
    let cache = scratch("cache");
    searched(&dir, &cache, &[]);
    let pruned = run(&["--cache", cache.to_str().unwrap(), "--cache-prune"]);
    assert_eq!(0, pruned.code, "{}", pruned.stderr);
    assert!(
        pruned.stderr.contains("0 cache entries removed"),
        "{}",
        pruned.stderr
    );
    let after = searched(&dir, &cache, &[]);
    assert_eq!(
        (3, 0, 0, 0),
        after.cache_tally(),
        "nothing recent was dropped"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_cache_is_off_unless_asked_for() {
    let dir = fixture();
    // pointed at an empty directory: a run that wrote anything there would
    // be writing a memo nobody asked for
    let target = scratch("envcache");
    std::fs::remove_dir_all(&target).ok();
    let out = Command::new(env!("CARGO_BIN_EXE_rgx"))
        .env("RGX_CACHE_DIR", &target)
        .args(["needle", dir.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(!out.stdout.is_empty(), "the search still runs");
    assert!(
        !stderr.contains("cache:"),
        "no summary without --cache: {stderr}"
    );
    assert!(!target.exists(), "nothing is written without the flag");
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&target).ok();
}

/// The `read=` field of the `profile:` line, in nanoseconds.
///
/// `RGX_PROFILE=1` makes the walker time the disk read separately from the
/// adapter work, which is the only way to observe that a memo hit skipped
/// the file rather than merely skipped the decode.
fn profile_read_ns(stderr: &str) -> u64 {
    let line = stderr
        .lines()
        .find(|l| l.starts_with("profile: "))
        .unwrap_or_else(|| panic!("no profile line in stderr:\n{stderr}"));
    let dur = line
        .split_whitespace()
        .nth(1)
        .and_then(|f| f.strip_prefix("read="))
        .unwrap_or_else(|| panic!("no read= field in: {line}"));
    assert!(
        dur.ends_with("ns") || dur.ends_with("µs") || dur.ends_with("ms") || dur.ends_with('s'),
        "unexpected duration shape: {dur}"
    );
    let (num, scale): (&str, f64) = if let Some(v) = dur.strip_suffix("ns") {
        (v, 1.0)
    } else if let Some(v) = dur.strip_suffix("µs") {
        (v, 1_000.0)
    } else if let Some(v) = dur.strip_suffix("us") {
        (v, 1_000.0)
    } else if let Some(v) = dur.strip_suffix("ms") {
        (v, 1_000_000.0)
    } else if let Some(v) = dur.strip_suffix('s') {
        (v, 1_000_000_000.0)
    } else {
        panic!("unexpected duration shape: {dur}")
    };
    (num.parse::<f64>().expect("numeric duration") * scale) as u64
}

fn profiled(dir: &Path, cache: &Path) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_rgx"))
        .args([
            "--cache",
            cache.to_str().unwrap(),
            "needle",
            dir.to_str().unwrap(),
        ])
        .env("RGX_PROFILE", "1")
        .output()
        .expect("failed to spawn rgx");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A memo hit must skip the *read*, not only the adapter work.
///
/// The cache key is derived from the `stat` the walk already did, plus the
/// adapter chain and the config, so nothing about it needs the file's bytes.
/// Consulting the memo after `fs::read` therefore bought the decode and
/// nothing else -- the file was still opened and read on every run. The hit
/// moves above the read, and a hit now costs no I/O at all.
#[test]
fn a_cache_hit_does_not_read_the_file() {
    let dir = fixture();
    let cache = scratch("hitread");

    let first = profiled(&dir, &cache);
    assert_eq!(first.code, 0, "{}", first.stderr);
    assert!(
        profile_read_ns(&first.stderr) > 0,
        "the first run is a miss:\n{}",
        first.stderr
    );

    let second = profiled(&dir, &cache);
    assert_eq!(second.code, 0, "{}", second.stderr);
    assert_eq!(
        lines(&first.stdout),
        lines(&second.stdout),
        "a hit answers exactly as a miss does"
    );
    assert_eq!(
        profile_read_ns(&second.stderr),
        0,
        "a memo hit still read the file:\n{}",
        second.stderr
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&cache).ok();
}

fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(entries(&p));
        } else if p.extension().map(|x| x == "ext").unwrap_or(false) {
            out.push(p);
        }
    }
    out
}

/// The content entries in a cache: the files that hold an extraction, as
/// opposed to the aliases that point at one.
fn content_entries(cache: &Path) -> Vec<PathBuf> {
    let c = cache.join("c");
    if !c.exists() {
        return Vec::new();
    }
    entries(&c)
}

/// The aliases in a cache.
fn alias_entries(cache: &Path) -> Vec<PathBuf> {
    let a = cache.join("a");
    let mut out = Vec::new();
    if !a.exists() {
        return out;
    }
    for e in std::fs::read_dir(&a).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            for f in std::fs::read_dir(&p).unwrap().flatten() {
                out.push(f.path());
            }
        } else {
            out.push(p);
        }
    }
    out
}

/// Two copies of the same file are extracted once.
///
/// The content key is the bytes plus the name, so two files with the same
/// bytes under the same name share one extraction, wherever they live. The
/// first file pays for it; the second one is answered from the content entry
/// and only writes its alias.
#[test]
fn two_copies_of_the_same_file_are_extracted_once() {
    let dir = scratch("copies");
    let a = dir.join("a");
    let b = dir.join("b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    zip(&a.join("pack.zip"), 1);
    // the same bytes under the same name, in another directory
    std::fs::copy(a.join("pack.zip"), b.join("pack.zip")).unwrap();
    let cache = scratch("cache");

    let first = searched(&dir, &cache, &[]);
    assert_eq!(0, first.code, "{}", first.stderr);
    assert_eq!(
        (1, 1, 1, 0),
        first.cache_tally(),
        "one extraction, one content hit"
    );
    assert_eq!(
        1,
        content_entries(&cache).len(),
        "one content entry for two files"
    );
    assert_eq!(2, alias_entries(&cache).len(), "one alias per file");

    let second = searched(&dir, &cache, &[]);
    assert_eq!(
        (2, 0, 0, 0),
        second.cache_tally(),
        "the second run hits both aliases and reads nothing"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A file that moved is not extracted again.
///
/// The alias is keyed by the path, so moving the file misses it. The
/// content key is the bytes, and they did not change, so the extraction is
/// reused.
#[test]
fn a_moved_file_is_not_extracted_again() {
    let dir = scratch("moved");
    std::fs::create_dir_all(dir.join("a")).unwrap();
    zip(&dir.join("a").join("pack.zip"), 1);
    let cache = scratch("cache");

    let first = searched(&dir, &cache, &[]);
    assert_eq!(0, first.code, "{}", first.stderr);
    assert_eq!((0, 1, 1, 0), first.cache_tally());

    std::fs::create_dir_all(dir.join("b")).unwrap();
    std::fs::rename(
        dir.join("a").join("pack.zip"),
        dir.join("b").join("pack.zip"),
    )
    .unwrap();
    let after = searched(&dir, &cache, &[]);
    assert_eq!(
        (1, 0, 0, 0),
        after.cache_tally(),
        "the moved file is answered from the content entry"
    );
    assert_eq!(
        1,
        content_entries(&cache).len(),
        "the move did not create a second extraction"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// The same bytes under a different name are a different extraction.
///
/// The name is in the content key because the extension picks the parser
/// and a report that names the file names the file. Two files that happen
/// to hold the same bytes are not interchangeable, and the cache says so.
#[test]
fn the_same_bytes_under_another_name_are_extracted_again() {
    let dir = scratch("names");
    zip(&dir.join("pack.zip"), 1);
    std::fs::copy(dir.join("pack.zip"), dir.join("other.zip")).unwrap();
    let cache = scratch("cache");

    let first = searched(&dir, &cache, &[]);
    assert_eq!(0, first.code, "{}", first.stderr);
    assert_eq!(
        (0, 2, 2, 0),
        first.cache_tally(),
        "two names, two extractions"
    );
    assert_eq!(2, content_entries(&cache).len());
    std::fs::remove_dir_all(&dir).ok();
}
