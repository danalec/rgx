// SPDX-License-Identifier: Apache-2.0

//! Does the `crates` ignore cost scale with the NUMBER OF `.gitignore` PATTERNS?
//!
//! Build:  rustc -O --edition 2021 -o walk_patterns scripts/walk_patterns.rs
//! Run:    ./walk_patterns            (uses target/release/rgx.exe, the repo `crates/`)
//!         ./walk_patterns --only-scale
//!
//! WHAT IS ESTABLISHED SO FAR, all measured on this machine with
//! `walk_phase.rs`'s method (Rust-side `Instant`, `Stdio::null`, 9 rounds,
//! spawn floor subtracted):
//!
//!   - the walk is 11.40 ms of a 13.30 ms run; read+engine is 1.59 ms, so the
//!     search engine cannot move this corpus.
//!   - `--no-ignore` takes the `crates` walk from 11.07 to 3.83 ms net: 7.2 ms
//!     of ignore for 628 entries, ~11.5 us/entry, against 0.36 us/entry on a
//!     generated tree with a 5-line .gitignore.
//!   - redirecting the global gitignore away (`XDG_CONFIG_HOME`,
//!     `GIT_CONFIG_GLOBAL`) recovers only 0.53 ms, which REFUTES the
//!     `any_git -> absbase -> per-entry absolute String` hypothesis.
//!
//! The candidate mechanism left is in `walk.rs`. `Node::any_git` comes from
//! `has_git` = `(ctx.git_ignore || ctx.git_exclude) && (found.dot_git ||
//! found.jj)` (line 1783). WITHOUT a `.git`, `any_git` is false and the chain
//! walk at lines 1049-1054 SKIPS both `nd.git_ignore.matched(...)` and
//! `nd.git_exclude.matched(...)` at every level -- so a `.gitignore` in a tree
//! with no `.git` is read, compiled, and never consulted. WITH a `.git`,
//! `any_git` flips for the whole subtree and every entry is tested against
//! every compiled pattern of every rule set above it.
//!
//! If that is the cost it MUST scale with pattern count, which is the one
//! variable no earlier probe moved. So: same generated tree, one variable.
//!
//! WHY THIS IS WRITTEN IN RUST, AND WHY IT GENERATES ITS TREES
//!
//! An earlier Python probe produced a wall of false readings, all of them its
//! own fault rather than rgx's:
//!
//!   - a probe tree nested inside another probe tree (`probe-tmp/p0` holding a
//!     second `probe-tmp/p1`) made the walk of the outer root compile the inner
//!     root's name;
//!   - Python string literals for the real file names `src/ppmd7.rs` and
//!     `src/unpack3.rs` carry `\p` and `\u`, which are Python escape sequences
//!     and made the harness die with the same
//!     "unicode property `\p` is not supported" message rgx prints -- so a
//!     harness bug was repeatedly mistaken for an rgx bug;
//!   - crashed probe runs left trees behind in %TEMP% that the next run walked.
//!
//! Three habits follow, and they are the point of the rewrite rather than an
//! aside. Trees are GENERATED here, so no name ever passes through a Python
//! literal. Cleanup removes exactly the one directory this process created, by
//! a path it built itself, and nothing else -- an earlier `rm -rf` from this
//! same session destroyed `benchmark/` and `tests/` and had to be restored from
//! git. And every invocation's exit status is checked, so a run that fails for
//! any reason is reported as such instead of being timed as if it had worked.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

const ROUNDS: usize = 9;
const RGX: &str = "target/release/rgx.exe";

/// Pattern counts to sweep. 0 and 5 bracket the empty and trivial cases; 65 is
/// the size of the repo's own `.gitignore`; the rest test linearity rather
/// than assuming it.
const SWEEP: [usize; 6] = [0, 5, 20, 65, 130, 260];

/// One `rgx` invocation, timed with Rust-side `Instant` and `Stdio::null`, so
/// no shell timer and no pipeline is inside the measured interval.
///
/// Returns `Err` on a non-zero exit. A probe that times a failed run reports
/// a number for work that never happened, which is how the Python harness
/// managed to look like it was measuring rgx.
fn run(args: &[&str]) -> Result<f64, String> {
    let mut cmd = Command::new(RGX);
    cmd.args(args);
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());
    if std::env::var_os("RGX_PROBE_TRACE").is_some() {
        eprintln!("    run: {:?} (cwd {:?})", args, std::env::current_dir());
    }
    let t = Instant::now();
    let out = cmd.output().map_err(|e| format!("spawn {RGX}: {e}"))?;
    let ms = t.elapsed().as_secs_f64() * 1e3;
    if out.status.success() {
        Ok(ms)
    } else {
        // The stderr is the whole diagnosis. An earlier Python harness
        // discarded it and reported the same message as an rgx bug it had
        // caused itself, so a failure here is never silent.
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!(
            "exit {} for {:?}\n      stderr: {}",
            out.status,
            args,
            err.trim()
        ))
    }
}

/// Minimum of `ROUNDS` timed samples, 2 warmups discarded first.
///
/// The minimum rather than the mean: the minimum is the sample least
/// contaminated by whatever else the box was doing, and it is what the
/// published tables use.
fn best(args: &[&str]) -> Result<f64, String> {
    for _ in 0..2 {
        run(args)?;
    }
    let mut v = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        v.push(run(args)?);
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Ok(v[0])
}

/// `n` gitignore lines that match nothing in the tree, so the PATTERN COUNT
/// moves while the set's selectivity stays at exactly zero. The extension is
/// deliberately absent from every real file in the tree, so a bug that treats
/// the rules as a whitelist shows up as a file count change rather than
/// hiding.
fn patterns(n: usize) -> String {
    let mut s = String::with_capacity(n * 28);
    for i in 0..n {
        s.push_str(&format!("zzz-never-matches-{i}.qqq\n"));
    }
    s
}

/// A tree with `dirs` subdirectories and `per_dir` files in each, so the entry
/// count and the directory count are both fixed across the sweep. A root
/// `.gitignore` with `patterns` lines, and optionally a `.git` directory.
fn build(root: &Path, dirs: usize, per_dir: usize, npat: usize, dotgit: bool) {
    let _ = fs::remove_dir_all(root);
    fs::create_dir_all(root).expect("create root");
    fs::write(root.join(".gitignore"), patterns(npat)).expect("write .gitignore");
    if dotgit {
        fs::create_dir_all(root.join(".git")).expect("create .git");
    }
    for d in 0..dirs {
        let sub = root.join(format!("d{d}"));
        fs::create_dir_all(&sub).expect("create subdir");
        for f in 0..per_dir {
            // `format!` keeps every byte explicit, so no name here can be
            // mistaken for an escape sequence the way a Python literal was.
            fs::write(sub.join(format!("f{f}.rs")), b"fn main() {}\n").expect("write file");
        }
    }
}

/// Every path under `root`, sorted, so a failing run can print the tree it was
/// actually given rather than the one the code intended to build.
fn walk(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap_or(&p).display().to_string();
            out.push(rel.clone());
            if p.is_dir() {
                stack.push(p);
            }
        }
    }
    out.sort();
    out
}

/// **The experiment that separates compilation from matching.**
///
/// The sweep above varies pattern count at a FIXED entry count, so a cost
/// that is per-pattern whether it comes from `ByteRegex::new` once per
/// `.gitignore` or from `matched` once per (entry x pattern) looks
/// identical. They separate on the entry axis: a per-pattern cost scales
/// with patterns and not with entries; a per-entry cost scales with both.
///
/// This holds the pattern count at 65 and walks 1x1, 4x4, 8x8 and 16x16, so
/// entries run 1, 16, 64 and 256. Flat says the cost is the compile, linear
/// says it is the match.
fn entry_axis(floor: f64, ws: &Path, npat: usize) -> Result<(), String> {
    println!("\n  pattern count held at {npat}; entry count moved\n");
    println!(
        "    {:>12} {:>10} {:>12} {:>12} {:>12}",
        "entries", "rules on", "--no-ignore", "ignore cost", "us/entry"
    );
    for (dirs, per_dir) in [(1usize, 1usize), (4, 4), (8, 8), (16, 16), (16, 64)] {
        let root = ws.join(format!("e{dirs}x{per_dir}"));
        build(&root, dirs, per_dir, npat, true);
        let s = root.to_string_lossy().to_string();
        let on = best(&["-j", "32", "--files", &s])? - floor;
        let off = best(&["-j", "32", "--files", "--no-ignore", &s])? - floor;
        let entries = dirs * per_dir;
        let cost = on - off;
        println!(
            "    {:>12} {:>9.2}ms {:>10.2}ms {:>10.2}ms {:>11.3}",
            entries, on, off, cost, cost * 1000.0 / entries as f64
        );
    }
    println!();
    println!("    flat in entries  -> the cost is COMPILING the set, once per");
    println!("                       .gitignore, not matching it per entry");
    println!("    linear in entries-> the cost is MATCHING, per (entry x pattern)");
    Ok(())
}

/// The one directory this process owns. Cleanup below touches exactly this.
///
/// The name is deliberately free of backslashes. A walk root that CONTAINS one
/// makes rgx compile the path itself as a regex and fail -- see
/// `walk_root_backslash_bug` below, which is the reason this is written down
/// rather than left as a comment that ages into a mystery.
fn workspace() -> PathBuf {
    let base = std::env::temp_dir();
    base.join("rgx-walk-ignore-cost")
}

/// A walk root whose own path contains a backslash sequence the byte engine
/// cannot parse.
///
/// This is a demonstration, not a measurement: it takes the SAME generated
/// tree and the SAME `.gitignore`, and changes only the walk root's name.
/// `p-sweep` has no backslash in it and works; `p\probe` has one and does not.
/// The tree is generated with `format!`, so the backslash is a real separator
/// that `os.scandir`/`read_dir` reports as part of a component name on this
/// platform -- which is what makes it a property of the input rather than of
/// this harness.
fn walk_root_backslash_bug(ws: &Path, dirs: usize, per_dir: usize) -> Result<(), String> {
    println!("\n  a walk root whose PATH contains a backslash\n");
    println!("    {:<16} {:>10}", "walk root", "result");
    // Both roots hold an identical tree; only the directory NAME differs.
    let good = ws.join("p-sweep");
    build(&good, dirs, per_dir, 5, true);
    let bad = ws.join("p").join("probe");
    build(&bad, dirs, per_dir, 5, true);

    for (label, root) in [("p-sweep", &good), ("p\\probe", &bad)] {
        let s = root.to_string_lossy().to_string();
        match run(&["--files", &s]) {
            Ok(_) => println!("    {label:<16} {:>10}", "ok"),
            Err(e) => {
                let first = e.lines().next().unwrap_or("").trim();
                println!("    {label:<16} {first:>10}")
            }
        }
    }
    // The asymmetry that matters: the SAME tree, reached through a path that
    // contains a backslash and one that does not. If both fail the walk root's
    // own path is not the input, and the difference is somewhere else.
    println!("\n  the same tree, two walk roots, one of them containing a backslash:");
    let alt = ws.join("x-probe-y");
    build(&alt, dirs, per_dir, 5, true);
    for (label, root) in [("no backslash", &good), ("with backslash", &bad)] {
        let s = root.to_string_lossy().to_string();
        match run(&["--files", &s]) {
            Ok(_) => println!("    {label:<16} ok"),
            Err(e) => println!(
                "    {label:<16} {}",
                e.lines().nth(1).unwrap_or("").trim()
            ),
        }
    }
    Ok(())
}

struct Cell {
    npat: usize,
    dotgit: bool,
    on: f64,
    off: f64,
}

/// The scale sweep: one generated tree, `.git` present, only the pattern
/// count moving. Returns the cells and the per-entry divisor.
fn sweep(floor: f64, ws: &Path, dirs: usize, per_dir: usize) -> Result<Vec<Cell>, String> {
    let mut cells = Vec::new();
    for &npat in &SWEEP {
        let root = ws.join(format!("p{npat}"));
        build(&root, dirs, per_dir, npat, true);
        let s = root.to_string_lossy().to_string();
        let on = best(&["-j", "32", "--files", &s])? - floor;
        let off = best(&["-j", "32", "--files", "--no-ignore", &s])? - floor;
        cells.push(Cell {
            npat,
            dotgit: true,
            on,
            off,
        });
    }
    Ok(cells)
}

/// The control axis: the same tree with and without a `.git`, at a fixed
/// pattern count. This is the row that says whether the pattern-count slope
/// below is the whole story or only part of it.
fn git_axis(floor: f64, ws: &Path, dirs: usize, per_dir: usize, npat: usize) -> Result<(), String> {
    println!("\n  the other axis: `.git` present or absent, {npat} patterns, same tree\n");
    println!("    {:<14} {:>10} {:>12} {:>12}", ".git", "rules on", "--no-ignore", "ignore cost");
    for &dotgit in &[false, true] {
        let root = ws.join(if dotgit { "gityes" } else { "gitno" });
        build(&root, dirs, per_dir, npat, dotgit);
        let s = root.to_string_lossy().to_string();
        let on = best(&["-j", "32", "--files", &s])? - floor;
        let off = best(&["-j", "32", "--files", "--no-ignore", &s])? - floor;
        println!(
            "    {:<14} {:>9.2}ms {:>10.2}ms {:>10.2}ms",
            if dotgit { "yes" } else { "no" },
            on,
            off,
            on - off
        );
    }
    Ok(())
}

/// The published `crates` row, measured the same way so the synthetic numbers
/// above have something real to be compared against.
fn real_crates(floor: f64) -> Result<(), String> {
    if !Path::new("crates").is_dir() {
        println!("\n  (no `crates/` here -- skipping the real-tree row)");
        return Ok(());
    }
    println!("\n  the real tree, for comparison (the bench's own arguments)\n");
    println!("    {:<20} {:>10} {:>12} {:>12}", "row", "rules on", "--no-ignore", "ignore cost");
    let globs = ["-g", "!testdata", "-g", "!*.bin", "-g", "!*.gz"];
    let mut walk_args = vec!["-j", "32", "--files"];
    walk_args.extend_from_slice(&globs);
    walk_args.push("crates");
    let on = best(&walk_args)? - floor;

    let mut ni_args = vec!["-j", "32", "--files", "--no-ignore"];
    ni_args.extend_from_slice(&globs);
    ni_args.push("crates");
    let off = best(&ni_args)? - floor;

    println!(
        "    {:<20} {:>9.2}ms {:>10.2}ms {:>10.2}ms",
        "crates --files", on, off, on - off
    );

    let mut count_args = vec!["-j", "32", "-c", "fn main"];
    count_args.extend_from_slice(&globs);
    count_args.push("crates");
    let on2 = best(&count_args)? - floor;
    println!(
        "    {:<20} {:>9.2}ms {:>10} {:>12}",
        "crates -c 'fn main'",
        on2,
        "-",
        format!("read+engine {:.2}ms", on2 - on)
    );
    Ok(())
}

fn main() {
    if !Path::new(RGX).exists() {
        eprintln!("no {RGX} -- cargo build --release --bin rgx first");
        std::process::exit(2);
    }

    // Before anything is measured: is the walk root even usable? Ten identical
    // runs on one fixed tree, reporting the exit-code histogram. Everything
    // below is conditional on this being stable, and an earlier version of
    // this harness spent a dozen turns assuming it was when it was not. It is
    // the cheapest check here and the one that would have caught that.
    {
        let ws0 = workspace().join("selftest");
        let _ = fs::remove_dir_all(&ws0);
        let root = ws0.join("p0");
        build(&root, 4, 4, 5, true);
        let s = root.to_string_lossy().to_string();
        let mut ok = 0usize;
        let mut first_err = String::new();
        for i in 0..10 {
            match run(&["-j", "32", "--files", &s]) {
                Ok(_) => ok += 1,
                Err(e) => {
                    if first_err.is_empty() {
                        first_err = e.lines().nth(1).unwrap_or("").trim().to_string();
                    }
                    let _ = i;
                }
            }
        }
        println!("rgx ignore-cost attribution, {ROUNDS} rounds, min reported");
        if ok == 10 {
            println!("self-test: 10/10 runs of one fixed walk root succeeded");
        } else {
            println!("self-test: {ok}/10 runs FAILED -- this walk root is not usable");
            println!("  first failure: {first_err}");
            println!("\n  stopping: every number below would be measured on a shape");
            println!("  rgx cannot walk at all, which is a different question from");
            println!("  the one this probe asks. Re-run under a different name.");
            let _ = fs::remove_dir_all(&ws0);
            std::process::exit(2);
        }
        let _ = fs::remove_dir_all(&ws0);
    }

    let floor = best(&["--version"]).expect("spawn floor");
    println!("spawn floor {floor:.2} ms\n");

    // 16 dirs x 16 files = 256 files, close to the 201 the `crates` copy has,
    // so the per-entry figures are comparable to the ones already published.
    let (dirs, per_dir) = if std::env::args().any(|a| a == "--small") {
        (1usize, 1usize)
    } else {
        (16usize, 16usize)
    };
    let files = dirs * per_dir;

    let ws = workspace();
    let _ = fs::remove_dir_all(&ws);

    // The demo builds trees under this same workspace. Whether running it
    // first affects the sweep is exactly the question, so it is opt-in rather
    // than assumed harmless.
    if std::env::args().any(|a| a == "--backslash-demo") {
        if let Err(e) = walk_root_backslash_bug(&ws, dirs, per_dir) {
            eprintln!("backslash demo failed to set up: {e}");
        }
    }

    println!("\n  generated tree: {dirs} dirs x {per_dir} files = {files} files, one .gitignore");
    println!("varying ONLY the pattern count; every pattern matches nothing\n");
    println!("  {:>8} {:>10} {:>12} {:>12} {:>12}", "patterns", "rules on", "--no-ignore", "ignore cost", "us/entry");
    println!("  {}", "-".repeat(58));

    let cells = match sweep(floor, &ws, dirs, per_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sweep failed: {e}");
            // Dump what was on disk when it failed. Every earlier wrong turn in
            // this investigation came from reasoning about a tree nobody had
            // looked at; the state at the moment of failure is the thing that
            // answers it.
            let root = ws.join("p0");
            eprintln!("\n  tree at failure: {}", root.display());
            for entry in walk(&root) {
                eprintln!("    {entry}");
            }
            // The exact bytes handed to the child, in hex. A path that carries
            // a stray separator or a non-ASCII byte is invisible in the
            // `{s}` above and is exactly the kind of thing that makes a
            // reproduction fail from inside a program and succeed from a shell.
            let s = root.to_string_lossy().to_string();
            eprintln!("    argv path bytes ({}):", s.len());
            for (i, b) in s.bytes().enumerate() {
                eprintln!("      {i:>3} 0x{b:02x} {b:>3} {:?}", b as char);
            }
            let _ = fs::remove_dir_all(&ws);
            std::process::exit(2);
        }
    };
    for c in &cells {
        let cost = c.on - c.off;
        println!(
            "  {:>8} {:>9.2}ms {:>10.2}ms {:>10.2}ms {:>11.3}",
            c.npat, c.on, c.off, cost, cost * 1000.0 / files as f64
        );
    }

    if cells.len() >= 2 {
        let a = cells.first().unwrap();
        let b = cells.last().unwrap();
        let slope = ((b.on - b.off) - (a.on - a.off)) * 1000.0
            / (b.npat - a.npat).max(1) as f64;
        println!("\n  marginal cost per PATTERN ({} -> {}): {slope:.3} us", a.npat, b.npat);
        println!("  marginal cost per entry per pattern:                {:>8.5} us", slope / files as f64);
        let grew = (b.on - b.off) > (a.on - a.off) * 1.5;
        if grew {
            println!("\n  Scales with pattern count, which is what `any_git` predicts:");
            println!("  without a `.git` the chain walk skips `git_ignore.matched`");
            println!("  entirely (walk.rs:1049-1054); with one, every entry is tested");
            println!("  against every compiled pattern of every rule set above it.");
        } else {
            println!("\n  Does NOT scale with pattern count, so per-entry pattern");
            println!("  matching is not the mechanism.");
        }
    }

    if let Err(e) = entry_axis(floor, &ws, 65) {
        eprintln!("entry axis failed: {e}");
    }
    if let Err(e) = git_axis(floor, &ws, dirs, per_dir, 65) {
        eprintln!("git axis failed: {e}");
    }
    if let Err(e) = real_crates(floor) {
        eprintln!("real-tree row failed: {e}");
    }

    // Exactly one directory, built above, removed here. Nothing else.
    let _ = fs::remove_dir_all(&ws);
    println!("\n  probe workspace removed: {}", ws.display());
}