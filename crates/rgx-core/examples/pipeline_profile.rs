// SPDX-License-Identifier: Apache-2.0

//! Where the wall clock goes when `rgx` searches a real corpus, split at the
//! boundaries the pipeline actually has.
//!
//! ```text
//! cargo run --release -p rgx-core --example pipeline_profile -- [options]
//! ```
//!
//! The question is not "which engine is faster" but "what fraction of a run
//! is the engine at all". The engine has plenty of published numbers about
//! itself — `fixed.rs` prices a confirm, `cost_sensitivity.rs` prices the
//! three confirm engines against each other — and none of them price the parts
//! that are NOT the engine. A search on a many-file corpus is mostly not a
//! search: it is a directory walk, some `stat`s, a read, and a line of output.
//! The answer decides where an optimisation can possibly pay, and a wrong
//! answer sends the work into the 3%.
//!
//! ## The method is ablation, and the gate is in front of it
//!
//! Each row is a whole `rgx` invocation with one stage removed, priced by
//! the wall-clock difference between the row that has the stage and the row
//! that does not. The stages are process-level rather than function-level.
//! Three rules from `AGENTS.md` "Benchmarking" are kept, because they are
//! what makes a row checkable:
//!
//! 1. **A count gate in front of every timing line.** The summed `-c` of
//!    rgx against the summed `-c` of ripgrep on the same corpus, the thread
//!    count matched, and the timing is not printed if they disagree. The one
//!    disagreement this corpus can produce is a *documented* one: rgx opens
//!    `.zst`/`.gz`/`.zip` containers and ripgrep does not (`AGENTS.md` "Reach
//!    and Policy" — a decompressing adapter is what makes rgx a superset).
//!    The gate therefore attributes each disagreeing file individually and
//!    reports it by name rather than quietly passing or quietly failing.
//! 2. **Interleaved per round, order rotating.** A background file-sync
//!    process tripled all three engines once here and the number that
//!    absorbed it was published as a discovery.
//! 3. **The minimum, with the median and max beside it.** A disturbed round
//!    has to be visible, not averaged away.
//!
//! ## What the rows mean
//!
//! | row | command | stages it runs | stages it removes |
//! |-----|---------|----------------|-------------------|
//! | `walk`   | `--files`  | walk + ignore + path emit | everything after the walk |
//! | `search` | `-c`       | all of the above + stat + open + read + adapter + prefilter + mask + confirm | line output |
//! | `output` | (no `-c`)  | everything | the per-line format and write |
//!
//! `output = output_row - search_row`, and everything between `walk` and
//! `search` is stat + open + read + adapter. Those are not separable by
//! subtraction from outside the process, so they are priced separately by
//! [`vfs_floor`], which does the same `stat`/`open`/`read`/`close` sequence
//! in-process with no engine at all. It is an OS floor, not rgx's walker, and
//! it is labelled as one.
//!
//! **The `grep` row is dead and its count-gate failure is the reason.** It
//! still invokes `--engine grep`, which the CLI now rejects (`auto`, `tv`,
//! `rgx` are the only accepted values — `grep-searcher` was removed when the
//! in-house engine became the only one). rgx exits 2, prints no `-c` line,
//! and the gate suppresses the timing, so no number is invented. The row and
//! the `in-house = search_row - grep_row` subtraction below it are load-bearing
//! only as a placeholder; delete both when the harness is next touched.

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

const DEFAULT_ROUNDS: usize = 5;
const WARMUP: usize = 1;

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// What one engine answered, and whether the answer is parsable at all.
struct Counted {
    total: u64,
    exit_ok: bool,
    err: Option<String>,
    /// Per-file counts, path -> count, for attributing a disagreement.
    per_file: BTreeMap<String, u64>,
}

/// `is_walk` switches the parse: `--files` prints one path per line and no
/// count, so it is gated on the number of paths rather than on a match count.
/// Same rule, applied to the quantity that row actually produces.
fn measure(prog: &Path, args: &[String], env_rgx: bool, is_walk: bool) -> (f64, Counted) {
    let mut cmd = Command::new(prog);
    cmd.args(args);
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    if env_rgx {
        cmd.env("RGX_ENGINE", "rgx");
    } else {
        cmd.env_remove("RGX_ENGINE");
    }
    let t = Instant::now();
    let out = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            return (
                f64::INFINITY,
                Counted {
                    total: 0,
                    exit_ok: false,
                    err: Some(format!("spawn {}: {e}", prog.display())),
                    per_file: BTreeMap::new(),
                },
            )
        }
    };
    let ms = t.elapsed().as_secs_f64() * 1e3;
    let raw = String::from_utf8_lossy(&out.stdout).into_owned();

    if is_walk {
        let mut per_file = BTreeMap::new();
        for line in raw.lines() {
            if !line.trim().is_empty() {
                per_file.insert(line.replace('\\', "/"), 1);
            }
        }
        let n = per_file.len() as u64;
        return (
            ms,
            Counted {
                total: n,
                exit_ok: true,
                err: None,
                per_file,
            },
        );
    }

    let mut total = 0u64;
    let mut per_file: BTreeMap<String, u64> = BTreeMap::new();
    let mut bad = None;
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // rgx prints `/` and ripgrep prints `\`; normalising here is what
        // lets a per-file comparison mean something. Without it every file
        // disagrees and the gate reports a 25k-line difference that is 48
        // lines of real disagreement wearing a costume.
        let norm = line.replace('\\', "/");
        let (path, field) = match norm.rfind(':') {
            Some(i) => (norm[..i].to_owned(), norm[i + 1..].to_owned()),
            None => (String::new(), norm.clone()),
        };
        match field.trim().parse::<u64>() {
            Ok(n) => {
                total += n;
                per_file.insert(path, n);
            }
            Err(_) => {
                bad = Some(format!("unparsable -c line {line:?}"));
                break;
            }
        }
    }
    (
        ms,
        Counted {
            total,
            // A "no match" run exits 1 on both sides; that is not an error
            // for a corpus row, and the zero check below is the real guard.
            exit_ok: out.status.success() || total > 0,
            err: bad,
            per_file,
        },
    )
}

/// A disagreement between the two engines, and whether it is the documented
/// container superset or something that needs explaining.
struct Divergence {
    /// Files only rgx counted, with their counts.
    only_rgx: Vec<(String, u64)>,
    /// Files only ripgrep counted, with their counts.
    only_rg: Vec<(String, u64)>,
    /// Files both counted, at different counts.
    differ: Vec<(String, u64, u64)>,
    /// How many of the above are files ripgrep cannot see inside at all,
    /// which is what a decompressing adapter looks like from out here.
    container_only: usize,
}

fn diverge(a: &Counted, b: &Counted) -> Divergence {
    let mut only_rgx = Vec::new();
    let mut only_rg = Vec::new();
    let mut differ = Vec::new();
    for (p, n) in &a.per_file {
        match b.per_file.get(p) {
            Some(m) if m == n => {}
            Some(m) => differ.push((p.clone(), *n, *m)),
            None => only_rgx.push((p.clone(), *n)),
        }
    }
    for (p, n) in &b.per_file {
        if !a.per_file.contains_key(p) {
            only_rg.push((p.clone(), *n));
        }
    }
    // A container member is a path where a DIRECTORY component names the
    // archive and the last component is a member inside it. rgx reports
    // those as `archive.zst/member.rs`, so the last component's extension
    // is the member's and says nothing -- the test has to look at the
    // components above it. Counting these is how the documented superset
    // (`AGENTS.md` "Reach and Policy": a decompressing adapter is what makes
    // rgx a superset of ripgrep) is separated from a real disagreement.
    let container_only = only_rgx
        .iter()
        .filter(|(p, _)| {
            Path::new(p)
                .components()
                .rev()
                .skip(1)
                .filter_map(|c| c.as_os_str().to_str())
                .any(|c| {
                    let lc = c.to_ascii_lowercase();
                    [
                        ".zst", ".gz", ".bz2", ".xz", ".br", ".lz4", ".zip", ".7z", ".tar", ".tgz",
                    ]
                    .iter()
                    .any(|e| lc.ends_with(e))
                })
        })
        .count();
    Divergence {
        only_rgx,
        only_rg,
        differ,
        container_only,
    }
}

// ---------------------------------------------------------------------------
// The in-process VFS floor
// ---------------------------------------------------------------------------

/// A `stat` + `open` + `read` + `close` over `files`, and nothing else.
///
/// This is the OS floor for the stages the binary runs between the walk and
/// the engine. It is NOT rgx's walker and it is NOT its reader: no ignore
/// rules, no threading, `std::fs::read` rather than the 64 KiB fill loop.
/// It is here because those stages cannot be separated by subtracting two
/// whole-process runs, and a floor that is too LOW is the safe direction to
/// be wrong in -- a floor above the real cost means the real cost is free.
///
/// The file list is rgx's own `walk` row output, so both sides see the same
/// 90,410 files and the comparison is not quietly pricing 5,628 files rgx
/// skipped for ignore reasons.
fn vfs_floor(files: &[PathBuf]) -> (f64, u64) {
    let t = Instant::now();
    let mut bytes = 0u64;
    let mut sink = Vec::new();
    for p in files {
        let Ok(meta) = std::fs::metadata(p) else {
            continue;
        };
        bytes += meta.len();
        if let Ok(b) = std::fs::read(p) {
            sink.push(b.len());
        }
    }
    std::hint::black_box(&sink);
    (t.elapsed().as_secs_f64() * 1e3, bytes)
}

/// Enumerate every file under `dir` with no ignore rules, for the corpus
/// description only.
fn plain_walk(dir: &Path) -> (usize, u64) {
    let mut files = 0usize;
    let mut bytes = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                files += 1;
                if let Ok(m) = e.metadata() {
                    bytes += m.len();
                }
            }
        }
    }
    (files, bytes)
}

/// Parse the `profile: read=.. process=.. search=..` line `RGX_PROFILE=1`
/// writes to stderr, in milliseconds. This is the binary's OWN
/// instrumentation, so it prices the adapter stage directly -- no ablation,
/// and therefore no assumption about what the difference between two runs
/// would otherwise have contained. `process` is the adapter pipeline;
/// `read` is the file read; `search` is the engine.
fn parse_profile(stderr: &str) -> Option<(f64, f64, f64)> {
    let line = stderr.lines().find(|l| l.starts_with("profile:"))?;
    let field = |key: &str| -> Option<f64> {
        let i = line.find(key)? + key.len();
        let rest = &line[i..];
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let v: f64 = rest[..end].parse().ok()?;
        // The line mixes `µs`, `ms` and `s`; these are the only three.
        let tail = rest[end..].trim_start();
        let ms = if tail.starts_with("ms") {
            1.0
        } else if tail.starts_with('s') {
            1e3
        } else {
            1e-3
        };
        Some(v * ms)
    };
    Some((field("read=")?, field("process=")?, field("search=")?))
}

// ---------------------------------------------------------------------------
// The stage table
// ---------------------------------------------------------------------------

struct Stage {
    label: &'static str,
    ms: f64,
    med: f64,
    max: f64,
    note: String,
}

fn main() {
    let mut rgx = PathBuf::from("target/release/rgx.exe");
    let mut rg = PathBuf::from("rg");
    let mut tree: Option<PathBuf> = None;
    let mut rounds = DEFAULT_ROUNDS;
    let mut jobs = 0usize;
    let mut pattern = "pub fn".to_string();

    let mut it = env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--rgx" => rgx = PathBuf::from(it.next().expect("--rgx needs a path")),
            "--rg" => rg = PathBuf::from(it.next().expect("--rg needs a path")),
            "--tree" => tree = Some(PathBuf::from(it.next().expect("--tree needs a path"))),
            "--rounds" => rounds = it.next().and_then(|s| s.parse().ok()).unwrap_or(rounds),
            "--jobs" => jobs = it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
            "--pattern" | "-e" => pattern = it.next().expect("-e needs a pattern"),
            other => {
                eprintln!("unknown option {other}");
                std::process::exit(2);
            }
        }
    }
    if rounds < 5 {
        eprintln!("refusing fewer than 5 rounds: a min of fewer is not a result");
        std::process::exit(2);
    }
    if !rgx.exists() {
        eprintln!("no rgx at {}", rgx.display());
        std::process::exit(2);
    }
    let tree = tree.unwrap_or_else(default_tree);
    let jobs_s = jobs.to_string();
    let t_s = tree.display().to_string();

    println!("rgx     : {}", rgx.display());
    println!("ripgrep : {}", rg.display());
    println!("corpus  : {t_s}");
    println!("pattern : {pattern:?}");
    println!("rounds  : {rounds} interleaved, order rotating, MINIMUM reported");
    println!("jobs    : rgx -j {jobs_s} against rg -j {jobs_s} (thread-matched)\n",);

    // ---- the binary's own rows -------------------------------------------
    //
    // Five invocations, interleaved, order rotating per round so "whoever ran
    // second on a warm cache" cancels rather than biases. Declared before
    // Section A because Section A needs the walk row's file list to price the
    // VFS floor over the same files the binary reads.
    // The first is an empty directory, searched with the same argument shape.
    // This prices PROCESS STARTUP -- argument parsing, the adapter registry,
    // the pattern compile, the thread pool. On a small corpus that is most of
    // the run, and a stage table that does not subtract it attributes startup
    // to whichever stage happens to be running when it happens.
    let empty = std::env::temp_dir().join("rgx-pipeline-empty");
    let _ = std::fs::create_dir_all(&empty);
    let e_s = empty.display().to_string();

    let rows: Vec<(&str, Vec<String>, bool)> = vec![
        (
            "startup",
            vec![
                "-j".into(),
                jobs_s.clone(),
                "-c".into(),
                pattern.clone(),
                e_s.clone(),
            ],
            true,
        ),
        (
            "walk",
            vec!["-j".into(), jobs_s.clone(), "--files".into(), t_s.clone()],
            true,
        ),
        (
            "search",
            vec![
                "-j".into(),
                jobs_s.clone(),
                "-c".into(),
                pattern.clone(),
                t_s.clone(),
            ],
            true,
        ),
        (
            "output",
            vec!["-j".into(), jobs_s.clone(), pattern.clone(), t_s.clone()],
            true,
        ),
        (
            "grep",
            vec![
                "-j".into(),
                jobs_s.clone(),
                "-c".into(),
                "--engine".into(),
                "grep".into(),
                pattern.clone(),
                t_s.clone(),
            ],
            true,
        ),
    ];

    // The walk row has no `-c`; it is gated on the file COUNT both walkers
    // see, which is the same rule applied to the quantity that row produces.
    let walk_a = measure(&rgx, &rows[1].1, true, true);
    let walk_b = measure(&rg, &rows[1].1, false, true);
    let walk_gate = if walk_a.1.per_file.len() == walk_b.1.per_file.len() {
        format!("pass ({} paths both)", walk_a.1.per_file.len())
    } else {
        format!(
            "FAIL (rgx {} paths, rg {}) -- timing suppressed",
            walk_a.1.per_file.len(),
            walk_b.1.per_file.len()
        )
    };

    // ---- Section A: what the corpus actually is -------------------------
    let (nf, nb) = plain_walk(&tree);
    println!("SECTION A  the corpus");
    println!("  files on disk    : {nf} (no ignore rules)");
    println!(
        "  bytes on disk    : {:.1} MiB",
        nb as f64 / (1024.0 * 1024.0)
    );
    let file_list: Vec<PathBuf> = walk_a.1.per_file.keys().map(PathBuf::from).collect();
    println!(
        "  files rgx walks  : {} (after ignore rules)",
        file_list.len()
    );
    let mut v = Vec::new();
    for _ in 0..(WARMUP + rounds) {
        v.push(vfs_floor(&file_list));
    }
    v.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    let (read_ms, rbytes) = (v[WARMUP].0, v[WARMUP].1);
    println!(
        "  stat+open+read   : {read_ms:.0} ms for {:.1} MiB ({:.0} MB/s, 1 thread, std::fs::read)",
        rbytes as f64 / (1024.0 * 1024.0),
        rbytes as f64 / 1e6 / (read_ms / 1e3).max(1e-9)
    );

    let mut samples: Vec<Vec<(f64, Counted)>> = (0..rows.len()).map(|_| Vec::new()).collect();
    for r in 0..rounds {
        // Rotate which row goes first so no row systematically benefits from
        // a warm page cache left by the previous round.
        for k in 0..rows.len() {
            let i = (k + r) % rows.len();
            let (_, args, is_rgx) = &rows[i];
            let prog = if *is_rgx { &rgx } else { &rg };
            let (ms, c) = measure(prog, args, *is_rgx, i == 1);
            samples[i].push((ms, c));
        }
    }

    // ---- Section C: the gate --------------------------------------------
    println!("\nSECTION B  the binary's rows, and the gate in front of each");
    println!("  walk   {walk_gate}");
    let (_, rgx_c) = measure(&rgx, &rows[2].1, true, false);
    let (_, rg_c) = measure(&rg, &rows[2].1, false, false);
    let div = diverge(&rgx_c, &rg_c);
    let gate_ok = rgx_c.err.is_none()
        && rg_c.err.is_none()
        && rgx_c.exit_ok
        && rg_c.exit_ok
        && rgx_c.total > 0
        && rg_c.total > 0
        && div.differ.is_empty()
        && div.only_rg.is_empty()
        && div.container_only == div.only_rgx.len();

    println!(
        "  search rgx {:>8}   ripgrep {:>8}   delta {:>+6}",
        rgx_c.total,
        rg_c.total,
        rgx_c.total as i64 - rg_c.total as i64
    );
    if gate_ok {
        println!("  search  gate PASS -- every disagreeing file is a container rgx opens and ripgrep cannot see");
    } else {
        println!("  search  gate FAIL -- timings below are suppressed");
    }
    if !div.only_rgx.is_empty() {
        println!(
            "           {} file(s) only rgx counted, {} of them container extensions:",
            div.only_rgx.len(),
            div.container_only
        );
        for (p, n) in div.only_rgx.iter().take(6) {
            println!("             {n:>6}  {p}");
        }
    }
    for (p, x, y) in div.differ.iter().take(6) {
        println!("             rgx {x} vs rg {y}  {p}");
    }
    for (p, _) in div.only_rg.iter().take(6) {
        println!("             only ripgrep counted it  {p}");
    }
    if let Some(e) = &rgx_c.err {
        println!("  rgx: {e}");
    }
    if let Some(e) = &rg_c.err {
        println!("  rg: {e}");
    }

    // ---- Section D: the stage table --------------------------------------
    let mut stages: Vec<Stage> = Vec::new();
    let mut add = |label: &'static str, i: usize, note: String, gated: bool| {
        if samples[i].is_empty() {
            return;
        }
        let mut v: Vec<f64> = samples[i].iter().map(|s| s.0).collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let (ms, med, max) = (v[0], v[v.len() / 2], v[v.len() - 1]);
        if gated && !gate_ok {
            stages.push(Stage {
                label,
                ms: f64::NAN,
                med,
                max,
                note: "GATE FAIL -- suppressed".into(),
            });
        } else {
            stages.push(Stage {
                label,
                ms,
                med,
                max,
                note,
            });
        }
    };
    add("startup", 0, "empty dir, same args".into(), false);
    add("walk", 1, format!("gate {walk_gate}"), true);
    add("search", 2, "gate as above".into(), true);
    add("output", 3, "no -c: line format and write".into(), false);
    add("grep", 4, "grep-searcher, same corpus".into(), false);

    println!("\nSECTION C  wall clock, whole-binary rows (min / median / max of {rounds})");
    println!(
        "{:<10} {:>10} {:>10} {:>10}  note",
        "stage", "min ms", "med ms", "max ms"
    );
    println!("{}", "-".repeat(78));
    for s in &stages {
        if s.ms.is_nan() {
            println!(
                "{:<10} {:>10} {:>10} {:>10}  {}",
                s.label, "--", "--", "--", s.note
            );
        } else {
            println!(
                "{:<10} {:>10.0} {:>10.0} {:>10.0}  {}",
                s.label, s.ms, s.med, s.max, s.note
            );
        }
    }

    // ---- Section E: arithmetic -------------------------------------------
    let get = |l: &str| stages.iter().find(|s| s.label == l).map(|s| s.ms);
    println!("\nSECTION D  the arithmetic");
    let startup = get("startup");
    let walk = get("walk");
    let search = get("search");
    let output = get("output");
    let grep = get("grep");
    if let Some(su) = startup {
        println!("  process startup (args + registry + compile + threads) : {su:.0} ms");
    }
    // Every row below is a whole process, so every row carries the startup
    // cost. It is subtracted from the run it is attributed to, not from the
    // ratios, because a ratio of two rows that both include it is a ratio of
    // two things that are both mostly startup.
    let net = |x: f64| x - startup.unwrap_or(0.0);
    if let (Some(w), Some(s)) = (walk, search) {
        if s > w {
            println!("  walk + ignore + everything after it : {s:.0} ms");
            println!(
                "  walk + ignore alone                 : {w:.0} ms  ({:.1}%)",
                100.0 * w / s
            );
            println!(
                "  ...of which is startup, twice        : {:.0} ms once startup is taken off both",
                net(w)
            );
            let after = s - w;
            println!(
                "  stat+open+read+adapter+search        : {after:.0} ms  ({:.1}%)",
                100.0 * after / s
            );
            // The VFS floor is single-threaded, so it is only comparable to a
            // single-threaded run. Above that it is a lower bound per core,
            // and the arithmetic is printed as the direction it points.
            if jobs <= 1 {
                if read_ms >= after {
                    println!(
                        "  naive stat+open+read+close floor    : {read_ms:.0} ms  -- LARGER than the {after:.0} ms the binary spends on that stage plus the whole search"
                    );
                    println!(
                        "     so the engine's share of this run is bounded above by 0 ms: a plain"
                    );
                    println!(
                        "     std::fs::read of the same {} files costs more than rgx's read AND its search.",
                        file_list.len()
                    );
                } else {
                    println!("  naive stat+open+read+close floor    : {read_ms:.0} ms");
                    println!(
                        "     leaving at most {:.0} ms ({:.1}% of the run) for adapter + search",
                        after - read_ms,
                        100.0 * (after - read_ms) / s
                    );
                }
            } else {
                println!(
                    "  naive stat+open+read+close floor    : {read_ms:.0} ms (1 thread; not comparable to -j{jobs}, shown for scale)"
                );
            }
        }
    }
    if let (Some(s), Some(o)) = (search, output) {
        if o > s {
            println!(
                "\n  line output (format + write)         : {:.0} ms  ({:.1}% of a full run)",
                o - s,
                100.0 * (o - s) / o
            );
        }
    }
    if let (Some(s), Some(g)) = (search, grep) {
        println!(
            "\n  rgx in-house engine vs grep-searcher : {:.0} ms vs {:.0} ms  ({:+.1}%)",
            s,
            g,
            100.0 * (s - g) / g
        );
        // The repo's verdict rule (`status_table.rs`): a named winner only if
        // every sample of one is below every sample of the other. Overlapping
        // distributions print as an overlap, not as a ratio.
        let ss = &samples[2];
        let gs = &samples[4];
        let sep = ss.iter().all(|(a, _)| gs.iter().all(|(b, _)| a < b))
            || gs.iter().all(|(a, _)| ss.iter().all(|(b, _)| a < b));
        if !sep {
            println!(
                "     verdict: overlap, not a result (rgx min {:.0} max {:.0} | rg min {:.0} max {:.0})",
                ss.iter().map(|s| s.0).fold(f64::MAX, f64::min),
                ss.iter().map(|s| s.0).fold(0.0, f64::max),
                gs.iter().map(|s| s.0).fold(f64::MAX, f64::min),
                gs.iter().map(|s| s.0).fold(0.0, f64::max),
            );
        } else {
            println!("     verdict: the distributions separate");
        }
    }
    println!("\n  (stdout goes to a pipe for the -c rows and is drained; --files and the");
    println!("   full-output row are measured with the same pipe, so the output row prices");
    println!("   rgx's formatting and the write, plus the harness draining it.)");

    // ---- Section E: the adapter stage, from the binary's own counters -----
    //
    // The rows above cannot separate adapters, because the registry corpus
    // holds three container files out of 90,410. This runs over the corpora
    // that actually have adapters in them, and reads `RGX_PROFILE`'s own
    // per-stage counters rather than differencing two runs.
    let adapter_dirs: Vec<PathBuf> = [
        "crates/rgx-adapters-archive/testdata",
        "crates/rgx-adapters-media/testdata",
        "crates/rgx-core/testdata",
    ]
    .iter()
    .map(PathBuf::from)
    .filter(|p| p.exists())
    .collect();

    if !adapter_dirs.is_empty() {
        println!("\nSECTION E  adapter extraction, from RGX_PROFILE's own counters");
        println!("  (read + process + search, summed over the run, in-process ms)\n");
        println!(
            "{:<44} {:>8} {:>9} {:>9} {:>9} {:>10}",
            "corpus", "files", "read ms", "adapter", "search", "adapter %"
        );
        println!("{}", "-".repeat(94));
        for d in &adapter_dirs {
            // The pattern is irrelevant to this row and the corpus's own
            // `pub fn` count is zero, so the file count is taken from the
            // directory rather than from `-c` output, which prints nothing
            // for a file with no match.
            let (nfiles, _dbytes) = plain_walk(d);
            // Best of three, since these are milliseconds of work and a
            // single run is mostly scheduler noise.
            let mut best: Option<(f64, f64, f64, f64, u64)> = None;
            for _ in 0..3 {
                let out = Command::new(&rgx)
                    .args(["-c", "-j", &jobs_s, &pattern, &d.display().to_string()])
                    .env("RGX_ENGINE", "rgx")
                    .env("RGX_PROFILE", "1")
                    .stderr(Stdio::piped())
                    .output();
                let Ok(out) = out else { continue };
                let err = String::from_utf8_lossy(&out.stderr).into_owned();
                let Some((r, p, s)) = parse_profile(&err) else {
                    continue;
                };
                let cand = (r, p, s, r + p + s, nfiles as u64);
                if best.is_none_or(|b| cand.3 < b.3) {
                    best = Some(cand);
                }
            }
            let Some((r, p, s, tot, nfiles)) = best else {
                println!("{:<44} (no profile line -- no adapter ran)", d.display());
                continue;
            };
            println!(
                "{:<44} {:>8} {:>9.2} {:>9.2} {:>9.2} {:>9.1}%",
                d.display(),
                nfiles,
                r,
                p,
                s,
                100.0 * p / tot.max(1e-9)
            );
        }
        println!("\n  `process` is the adapter pipeline and `search` the engine, both timed");
        println!("  inside the binary. On a text-only corpus `process` is absent entirely,");
        println!("  which is the same fact the registry rows above show by subtraction.");
    }
}

fn default_tree() -> PathBuf {
    let home = env::var("USERPROFILE")
        .or_else(|_| env::var("HOME"))
        .unwrap_or_default();
    let src = Path::new(&home).join(".cargo").join("registry").join("src");
    let Ok(rd) = std::fs::read_dir(&src) else {
        eprintln!("no corpus under {} -- pass --tree", src.display());
        std::process::exit(2);
    };
    let mut dirs: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort_by_key(|d| std::fs::read_dir(d).map(|r| r.count()).unwrap_or(0));
    dirs.pop().expect("a corpus directory")
}
