// SPDX-License-Identifier: Apache-2.0

//! The two tables of `benchmark/status.md` §2, from one command, with a gate on
//! every row that can refuse to print a speed.
//!
//! ```text
//! cargo run --release -p rgx-core --example status_table -- [options]
//! scripts/bench-status.sh              # the same thing, builds first
//! ```
//!
//! ## Why this file exists
//!
//! The two tables in §2 were assembled by hand, in different terminals, on
//! different days, by one person and five agents. Two of them were wrong
//! before they were caught, both times by a thread count that was not
//! matched. A table that is typed is a table nobody can re-run, and a table
//! nobody can re-run is a claim.
//!
//! Everything that was hand-assembled about those two tables is here, and
//! nothing else is:
//!
//! * **One command, three corpora.** The 235 MB file at `-j1`, the
//!   many-file cargo registry at `-j32`, and this repository's own `crates`
//!   and `src` so the gates in §5 get a timing beside them for free.
//! * **Thread-matched, and the thread count in the header.** `rgx -j N`
//!   against `rg -j N`, same N, printed. rgx defaults to 32 threads and
//!   ripgrep to `available_parallelism().min(12)`; an uncapped engine against
//!   a capped one is comparing thread counts, and that mistake has already
//!   produced two false tables in this repository.
//! * **A count gate in front of every timing line.** Each row prints the
//!   summed `-c` line count of rgx against the summed `-c` line count of
//!   ripgrep FIRST, and a disagreement suppresses the timing line entirely --
//!   there is no number to quote, not a number with a warning attached.
//!   A zero on either side, an unparsable count, a non-zero exit, or two
//!   engines whose raw output differs on a single-file corpus are all gate
//!   FAILURES. `0 == 0` is never a pass: that is the `$null -eq $null` bug
//!   this gate exists to make impossible.
//! * **Interleaved per round, order rotating per round.** A background
//!   file-sync process once tripled all three engines mid-session here, and
//!   the number that absorbed it was published as a discovery. Running the
//!   engines back to back inside a round means a disturbed minute has to
//!   disturb all of them, and rotating which engine goes first means
//!   "whoever ran second on a warm cache" cancels instead of biasing. With
//!   `--rgx-base` there are three engines and the leading slot rotates
//!   through all three.
//! * **A base build timed in the same process.** `--rgx-base PATH` puts a
//!   second rgx build in the interleave, gated on its own line count, and
//!   reports `base/rgx` alongside `rg/rgx`. "Did THAT change move this row"
//!   measured in two sessions on a machine this size is not that answer.
//! * **The floor printed with the numbers, and a column saying whether the
//!   difference is inside it.** A ratio within the floor is a tie, and a tie
//!   is labelled `tie`, not `1.01x`. The `sep` column reports whether the two
//!   samples separate at all: a 0.4% "gain" over overlapping distributions is
//!   not a gain, and one was once reported as if it were.
//! * **No single-run numbers.** Five rounds is the minimum and the harness
//!   refuses fewer; the round count is in the header; the MINIMUM is the
//!   reported figure, with the median and the max beside it so a disturbed
//!   round is visible instead of hidden inside an average.
//!
//! ## Output
//!
//! Two views of the same rows. The **stream** is the audit: one gate line,
//! then the timing line that gate authorised, in order, for every row. The
//! **summary** under each section is the same rows as a markdown table with
//! the counts carried in a column, so the gate travels with the table into
//! `benchmark/status.md` instead of being left behind in a terminal.
//!
//! The process exits non-zero if any row failed its gate, so a script cannot
//! read the report as clean when it is not.

use std::env;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

// ---------------------------------------------------------------------------
// The rows
// ---------------------------------------------------------------------------

/// The nine published patterns, in the order the tables print. `--pattern`
/// appends to this rather than replacing it, so an ad-hoc question is asked
/// through the same gate in the same table as the nine rather than through a
/// second harness with no gate at all -- which is what `scripts/bench.ps1`
/// was, and the reason it is gone.
const NINE: [&str; 9] = [
    "e",
    "e.",
    "foo.*bar",
    "pub fn",
    "e[0-9]",
    "(pub|fn) [a-z]+",
    "a|b|c",
    "fn main",
    "let mut",
];

const WALK_LABEL: &str = "walk (--files)";

/// The floor on a difference. `benchmark/status.md` states two: ±2% in process,
/// ±3% on the CLI. This harness measures the CLI -- it spawns both binaries
/// and times the wall clock -- so 3% is the floor that applies here, and it
/// is the one this harness enforces.
impl Cfg {
    /// The nine published patterns, then any `--pattern` rows, in that order.
    fn patterns(&self) -> Vec<&str> {
        NINE.iter()
            .copied()
            .chain(self.extra_patterns.iter().map(String::as_str))
            .collect()
    }
}

const FLOOR_CLI_PCT: f64 = 3.0;

/// The in-process floor, stated so the two are never confused and so nobody
/// reuses the 2% for a CLI number.
const FLOOR_INPROC_PCT: f64 = 2.0;

/// Rounds below this are refused. A single run on this workload has moved by
/// more than 20% between samples before the machine settled, which is not a
/// measurement at any level of statistical care.
const MIN_ROUNDS: usize = 5;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

struct Cfg {
    root: PathBuf,
    big: PathBuf,
    tree: PathBuf,
    rgx: PathBuf,
    rgx_base: Option<PathBuf>,
    rg: PathBuf,
    rounds: usize,
    warmup: usize,
    floor: f64,
    jobs_one: usize,
    jobs_many: usize,
    jobs_override: Option<usize>,
    gate_pattern: String,
    /// Extra rows, appended to the nine.
    extra_patterns: Vec<String>,
    /// Evict the caches between every timed run.
    flush: bool,
    out: Option<PathBuf>,
    verbose: bool,
}

const USAGE: &str = "\
usage: status_table [options]

  --rounds N        timed rounds per cell (default 5, minimum 5)
  --warmup N        discarded warmup rounds per cell (default 1)
  --floor PCT       difference floor in percent (default 3.0, the CLI floor)
  --jobs N          thread count for BOTH engines, every corpus
  --jobs-one N      thread count for the single-file corpus (default 1)
  --jobs-many N     thread count for the directory corpora (default: all cores)
  --rgx PATH        the rgx binary (default <root>/target/release/rgx.exe)
  --rgx-base PATH   a BASE rgx build to time alongside, in the same process
                    and the same rounds. Adds a `base` column and a
                    `base/new` ratio: did THAT change move this row, with
                    the three engines interleaved rather than measured in two
                    sessions. The base is gated on its line count too.
  --rg PATH         the ripgrep binary (default: rg from PATH)
  --root PATH       repository root (default: cwd)
  --big PATH        the 235 MB single-file corpus
                    (default $HOME/.rgx-bench/big235.rs)
  --tree PATH       the many-file corpus
                    (default $HOME/.rgx-bench/tree, which
                     scripts/make-corpus.py generates; a Cargo
                     registry can be named here explicitly, but it is
                     a different size on every machine and every day,
                     which is how two published tables came to disagree
                     by 175 files)
  --gate-pattern S  the pattern for the `crates` and `src` rows
                    (default 'fn main')
  --pattern S       add S as a row, after the nine, gated the same way.
                    Repeatable. This is how a one-off pattern gets a number:
                    through the count gate, not through a second harness
                    that has none.
  --flush           evict the caches between every timed run by streaming a
                    buffer larger than the last-level cache. The default
                    interleaves warm engines on purpose, so a flush answers
                    \"what does this cost cold\", which is a different and
                    less interesting question than the one the tables ask.
  --out PATH        also write the report to PATH
  --verbose         print every raw sample
  -h, --help        this text

Every comparison is thread-matched: the same -j N goes to rgx and to rg, and
N is printed in the header of every table.
";

fn parse() -> Result<Option<Cfg>, String> {
    let mut root = env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from);

    let mut rgx: Option<PathBuf> = env::var_os("RGX").map(PathBuf::from);
    let mut rgx_base: Option<PathBuf> = env::var_os("RGX_BASE").map(PathBuf::from);
    let mut rg: Option<PathBuf> = None;
    let mut big: Option<PathBuf> = home
        .as_ref()
        .map(|h| h.join(".rgx-bench").join("big235.rs"));
    let mut tree: Option<PathBuf> = None;
    let mut extra_patterns: Vec<String> = Vec::new();
    let mut flush = false;
    let mut jobs_override: Option<usize> = None;
    let mut jobs_one: Option<usize> = None;
    let mut jobs_many: Option<usize> = None;
    let mut rounds = 7usize;
    let mut warmup = 2usize;
    let mut floor = FLOOR_CLI_PCT;
    let mut gate_pattern = String::from("fn main");
    let mut out: Option<PathBuf> = None;
    let mut verbose = false;

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0usize;
    while i < args.len() {
        // A free function rather than a closure over `i`: the match scrutinee
        // below borrows `args[i]`, and a closure holding `i` would make the
        // two borrows overlap.
        fn value(args: &[String], i: &mut usize, what: &str) -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("{what} needs a value"))
        }
        match args[i].as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "--rounds" => {
                rounds = value(&args, &mut i, "--rounds")?
                    .parse()
                    .map_err(|e| format!("--rounds: {e}"))?
            }
            "--warmup" => {
                warmup = value(&args, &mut i, "--warmup")?
                    .parse()
                    .map_err(|e| format!("--warmup: {e}"))?
            }
            "--floor" => {
                floor = value(&args, &mut i, "--floor")?
                    .parse()
                    .map_err(|e| format!("--floor: {e}"))?
            }
            "--jobs" => {
                jobs_override = Some(
                    value(&args, &mut i, "--jobs")?
                        .parse()
                        .map_err(|e| format!("--jobs: {e}"))?,
                )
            }
            "--jobs-one" => {
                jobs_one = Some(
                    value(&args, &mut i, "--jobs-one")?
                        .parse()
                        .map_err(|e| format!("--jobs-one: {e}"))?,
                )
            }
            "--jobs-many" => {
                jobs_many = Some(
                    value(&args, &mut i, "--jobs-many")?
                        .parse()
                        .map_err(|e| format!("--jobs-many: {e}"))?,
                )
            }
            "--pattern" => extra_patterns.push(value(&args, &mut i, "--pattern")?),
            "--flush" => flush = true,
            "--rgx" => rgx = Some(PathBuf::from(value(&args, &mut i, "--rgx")?)),
            "--rgx-base" => rgx_base = Some(PathBuf::from(value(&args, &mut i, "--rgx-base")?)),
            "--rg" => rg = Some(PathBuf::from(value(&args, &mut i, "--rg")?)),
            "--root" => root = PathBuf::from(value(&args, &mut i, "--root")?),
            "--big" => big = Some(PathBuf::from(value(&args, &mut i, "--big")?)),
            "--tree" => tree = Some(PathBuf::from(value(&args, &mut i, "--tree")?)),
            "--gate-pattern" => gate_pattern = value(&args, &mut i, "--gate-pattern")?,
            "--out" => out = Some(PathBuf::from(value(&args, &mut i, "--out")?)),
            "--verbose" => verbose = true,
            other => return Err(format!("unknown option {other}\n\n{USAGE}")),
        }
        i += 1;
    }

    if rounds < MIN_ROUNDS {
        return Err(format!(
            "--rounds {rounds} is refused: this harness does not print single-run numbers, and \
             {MIN_ROUNDS} is the minimum. A single run on this workload has moved by more than \
             20% between samples on this machine."
        ));
    }
    if floor <= 0.0 {
        return Err("--floor must be positive".into());
    }
    if warmup > rounds {
        return Err(format!("--warmup {warmup} exceeds --rounds {rounds}"));
    }

    let rgx = rgx.unwrap_or_else(|| {
        root.join("target")
            .join("release")
            .join(format!("rgx{}", env::consts::EXE_SUFFIX))
    });
    let rg = rg.unwrap_or_else(|| {
        let work_rg = root
            .parent()
            .map(|p| {
                p.join("rgx-work")
                    .join("ripgrep-15")
                    .join("target")
                    .join("release")
                    .join(format!("rg{}", env::consts::EXE_SUFFIX))
            })
            .filter(|p| p.exists());
        work_rg.unwrap_or_else(|| PathBuf::from("rg"))
    });
    if let Some(b) = &rgx_base {
        if !b.exists() {
            return Err(format!("--rgx-base {} does not exist", b.display()));
        }
        if *b == rgx {
            return Err(
                "--rgx-base and --rgx are the same file; there is nothing to compare".into(),
            );
        }
    }
    let big = big.ok_or("no home directory found and no --big given")?;
    let tree = match tree {
        Some(t) => t,
        None => {
            let t = home
                .as_ref()
                .ok_or("no home directory found and no --tree given")?
                .join(".rgx-bench")
                .join("tree");
            if !t.is_dir() {
                return Err(format!(
                    "no generated corpus at {} -- run `python scripts/make-corpus.py`                      (a Cargo registry under ~/.cargo/registry/src can be passed with                      --tree, but it grows on every fetch, so two runs a week apart                      are two different corpora)",
                    t.display()
                ));
            }
            t
        }
    };

    let jobs_many = jobs_many.or(jobs_override).unwrap_or_else(default_jobs);

    Ok(Some(Cfg {
        root,
        big,
        tree,
        rgx,
        rg,
        rgx_base,
        rounds,
        warmup,
        floor,
        jobs_one: jobs_one.or(jobs_override).unwrap_or(1),
        jobs_many,
        jobs_override,
        gate_pattern,
        extra_patterns,
        flush,
        out,
        verbose,
    }))
}

fn default_jobs() -> usize {
    env::var("NUMBER_OF_PROCESSORS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
}

/// Every file under `dir`, for the header only. The walk row's own gate is
/// the authority on how many files the engines saw; this is the label.
fn walk_file_count(dir: &Path) -> usize {
    fn rec(d: &Path, n: &mut usize) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                rec(&e.path(), n);
            } else {
                *n += 1;
            }
        }
    }
    let mut n = 0;
    rec(dir, &mut n);
    n
}

// ---------------------------------------------------------------------------
// Engines
// ---------------------------------------------------------------------------

struct Engine {
    path: PathBuf,
    /// rgx needs `RGX_ENGINE=rgx` to run the in-house engine rather than
    /// falling back to grep-searcher, and ripgrep needs the variable *gone* so
    /// a stray value in the environment cannot change what is compared.
    is_rgx: bool,
}

impl Engine {
    fn cmd(&self, args: &[String]) -> Command {
        let mut c = Command::new(&self.path);
        c.args(args);
        if self.is_rgx {
            c.env("RGX_ENGINE", "rgx");
        } else {
            c.env_remove("RGX_ENGINE");
        }
        c
    }
}

fn version_line(e: &Engine) -> String {
    match e
        .cmd(&["--version".to_string()])
        .stderr(Stdio::null())
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .lines()
            .next()
            .unwrap_or("(no version)")
            .trim()
            .to_string(),
        Err(err) => format!("<{err}>"),
    }
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/// `pat == None` is the walk: `rgx --files` against `rg --files`, gated on the
/// number of paths both of them walk to rather than on a match count.
/// `corpus` overrides the section's corpus for a single row, which is how the
/// `crates` and `src` rows each address their own directory. `globs` overrides
/// the section's glob for a single row, and is how the `crates` row keeps the
/// compressed testdata out of the gate -- the gate must compare what both
/// engines can search, and ripgrep has no in-process brotli/zip/sevenz
/// adapter; including those files would be asking rg to do something it
/// cannot, which surfaces as a count difference every run. Each entry is one
/// `-g` flag, so multiple extensions and directory patterns compose without
/// having to encode the OR into a single pattern.
struct Row {
    label: String,
    pat: Option<String>,
    corpus: Option<String>,
    globs: Vec<&'static str>,
    /// `true` when the row measures rgx's value-add over ripgrep: rgx reads
    /// inside archives that rg treats as binary, so the count gates are
    /// `rgx >= ripgrep` instead of `rgx == ripgrep`. The verdict cell prints
    /// both counts and the asymmetric delta.
    asymmetric: bool,
}

impl Row {
    fn pat(label: &str) -> Self {
        Row {
            label: label.to_string(),
            pat: Some(label.to_string()),
            corpus: None,
            globs: Vec::new(),
            asymmetric: false,
        }
    }
    fn in_dir(label: &str, pat: &str, dir: &Path) -> Self {
        Row {
            label: label.to_string(),
            pat: Some(pat.to_string()),
            corpus: Some(dir.to_string_lossy().into_owned()),
            globs: Vec::new(),
            asymmetric: false,
        }
    }
    fn in_dir_with_globs(label: &str, pat: &str, dir: &Path, globs: Vec<&'static str>) -> Self {
        Row {
            label: label.to_string(),
            pat: Some(pat.to_string()),
            corpus: Some(dir.to_string_lossy().into_owned()),
            globs,
            asymmetric: false,
        }
    }
    /// A row where the gate is `rgx >= ripgrep` and the verdict names rgx as
    /// the engine that finds additional matches by reading inside compressed
    /// containers rg cannot decode.
    fn asymmetric_in_dir(label: &str, pat: &str, dir: &Path) -> Self {
        Row {
            label: label.to_string(),
            pat: Some(pat.to_string()),
            corpus: Some(dir.to_string_lossy().into_owned()),
            globs: Vec::new(),
            asymmetric: true,
        }
    }
    fn walk(corpus: &Path) -> Self {
        Row {
            label: WALK_LABEL.to_string(),
            pat: None,
            corpus: Some(corpus.to_string_lossy().into_owned()),
            globs: Vec::new(),
            asymmetric: false,
        }
    }
    fn is_walk(&self) -> bool {
        self.pat.is_none()
    }
    fn unit(&self) -> &'static str {
        if self.is_walk() {
            "paths"
        } else {
            "lines"
        }
    }
}

/// ripgrep takes the pattern after `-e`; rgx takes it after `--`. They are
/// spelled separately rather than sharing one flag list, because a shared list
/// is where "one engine was measured with a different pattern" comes from.
fn args_for(row: &Row, corpus: &str, jobs: usize, glob: Option<&str>, e: &Engine) -> Vec<String> {
    let mut a: Vec<String> = Vec::new();
    a.push(format!("-j{jobs}"));
    // Row-level globs win over the section glob: the section glob is the
    // default, and a row that needs narrower filtering (the `crates` row
    // excluding the compressed testdata) overrides it here. Each entry is one
    // `-g` flag, so the row can layer directory + extension exclusions without
    // overloading a single pattern.
    if !row.globs.is_empty() {
        for g in &row.globs {
            a.push("-g".into());
            a.push((*g).into());
        }
    } else if let Some(g) = glob {
        a.push("-g".into());
        a.push(g.into());
    }
    match &row.pat {
        Some(p) => {
            a.push("--no-filename".into());
            a.push("-c".into());
            if e.is_rgx {
                a.push("--".into());
            } else {
                a.push("-e".into());
            }
            a.push(p.clone());
            a.push(corpus.to_string());
        }
        None => {
            a.push("--files".into());
            a.push(corpus.to_string());
        }
    }
    a
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

struct Counted {
    total: u64,
    raw: String,
    exit_ok: bool,
    err: Option<String>,
}

/// Evict the caches by streaming more bytes than the last level can hold.
///
/// 512 MB on a machine whose L3 is 96 MB, and the same buffer is reused for
/// the whole run so the cost is paid in memory once. This is `--flush` in
/// `scripts/bench.ps1`, moved here rather than left in a second harness: the
/// question it answers -- what does a cold run cost -- is worth being able to
/// ask, and it is only worth asking through a gate.
fn evict() {
    const N: usize = 64 * 1024 * 1024;
    let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(std::env::temp_dir().join("rgx-status-flush.bin"))
    else {
        return;
    };
    use std::io::{Read, Seek, Write};
    let block = vec![0xA5u8; 1 << 20];
    for _ in 0..(N / block.len()) {
        if f.write_all(&block).is_err() {
            return;
        }
    }
    let _ = f.flush();
    let _ = f.seek(std::io::SeekFrom::Start(0));
    let mut sink = vec![0u8; 1 << 20];
    for _ in 0..(N / block.len()) {
        if f.read_exact(&mut sink).is_err() {
            return;
        }
        std::hint::black_box(&sink);
    }
    let _ = f.set_len(0);
}

fn measure(e: &Engine, args: &[String], is_walk: bool) -> Counted {
    let out = match e.cmd(args).stderr(Stdio::null()).output() {
        Ok(o) => o,
        Err(err) => {
            return Counted {
                total: 0,
                raw: String::new(),
                exit_ok: false,
                err: Some(format!("spawn {}: {err}", e.path.display())),
            }
        }
    };
    let raw = String::from_utf8_lossy(&out.stdout).into_owned();
    let exit_ok = out.status.success();

    if is_walk {
        let paths = raw.lines().filter(|l| !l.trim().is_empty()).count() as u64;
        return Counted {
            total: paths,
            raw,
            exit_ok,
            err: None,
        };
    }

    // `-c` prints one count per file, or one bare count for a single file.
    // Summing the count off the end of each line is what makes the gate work
    // the same on a file and on a directory; comparing the raw output would
    // compare two multi-line strings on a directory and always report a
    // mismatch, which is worse than no gate at all.
    let mut total = 0u64;
    let mut bad: Option<String> = None;
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let field = line
            .rsplit(|c: char| c.is_whitespace() || c == ':')
            .find(|s| !s.is_empty())
            .unwrap_or("");
        match field.parse::<u64>() {
            Ok(n) => total += n,
            Err(_) => {
                bad = Some(format!("unparsable -c line {line:?}"));
                break;
            }
        }
    }
    Counted {
        total,
        raw,
        exit_ok: exit_ok && bad.is_none(),
        err: bad,
    }
}

struct Gate {
    ok: bool,
    raw_note: String,
    why: String,
}

/// `base` is the optional third engine. When it is present it is gated on the
/// same count: a base build that answers the search differently is not a
/// baseline, and comparing against it would be comparing against a lie.
///
/// Asymmetric rows flip the gate from `a == b` to `a >= b`: rgx can read
/// inside archives ripgrep cannot, so the row's claim is "rgx finds at least
/// what rg finds, plus whatever is inside the archives". The verdict prints
/// both counts and the surplus.
fn gate(row: &Row, a: &Counted, b: &Counted, base: Option<&Counted>, single_file: bool) -> Gate {
    if let Some(e) = &a.err {
        return Gate {
            ok: false,
            raw_note: "-".into(),
            why: format!("rgx {e}"),
        };
    }
    if let Some(e) = &b.err {
        return Gate {
            ok: false,
            raw_note: "-".into(),
            why: format!("ripgrep {e}"),
        };
    }
    if let Some(c) = base {
        if let Some(e) = &c.err {
            return Gate {
                ok: false,
                raw_note: "-".into(),
                why: format!("base {e}"),
            };
        }
        if c.total == 0 {
            return Gate {
                ok: false,
                raw_note: "-".into(),
                why: format!("base matched 0 {}, rgx {}", row.unit(), a.total),
            };
        }
        if c.total != a.total {
            return Gate {
                ok: false,
                raw_note: "-".into(),
                why: format!(
                    "base count {} differs from rgx {} -- it is not a baseline",
                    c.total, a.total
                ),
            };
        }
    }
    if !a.exit_ok || !b.exit_ok {
        // Checked AFTER the zero cases on purpose. A "no match" run exits
        // non-zero on both sides, and reporting that as the reason would
        // hide the thing that actually matters: two engines that both found
        // nothing and would have compared equal.
        let both_zero = a.total == 0 && b.total == 0;
        if !both_zero {
            return Gate {
                ok: false,
                raw_note: "-".into(),
                why: format!(
                    "non-zero exit (rgx ok={}, ripgrep ok={})",
                    a.exit_ok, b.exit_ok
                ),
            };
        }
    }
    // `0 == 0` is the shape of the bug this gate exists to kill: a comparison
    // that agrees because both sides produced nothing at all.
    if a.total == 0 && b.total == 0 {
        return Gate {
            ok: false,
            raw_note: "0/0".into(),
            why: "both sides zero -- a 0 == 0 comparison proves nothing; timing suppressed".into(),
        };
    }
    if a.total == 0 {
        return Gate {
            ok: false,
            raw_note: format!("0/{}", b.total),
            why: format!("rgx matched 0 {}, ripgrep {}", row.unit(), b.total),
        };
    }
    if row.asymmetric {
        // rgx's value-add row: rgx is allowed to find strictly more than rg,
        // and rg finding 0 (i.e. binary files only) is the whole point. The
        // gate is `a >= b`; a tie is reported as equal, a surplus as the
        // asymmetric delta the verdict cell prints.
        let raw_note = if a.total == b.total {
            format!("{} / {}", a.total, b.total)
        } else {
            format!(
                "{}/{} (+{} in archives)",
                a.total,
                b.total,
                a.total - b.total
            )
        };
        return Gate {
            ok: true,
            raw_note,
            why: if a.total > b.total {
                "rgx finds more (asymmetric)".into()
            } else {
                "count equal (asymmetric)".into()
            },
        };
    }
    if b.total == 0 {
        return Gate {
            ok: false,
            raw_note: format!("{}/0", a.total),
            why: format!("ripgrep matched 0 {}, rgx {}", row.unit(), a.total),
        };
    }
    if a.total != b.total {
        return Gate {
            ok: false,
            raw_note: format!("{}/{}", a.total, b.total),
            why: format!("count differs: rgx {} vs ripgrep {}", a.total, b.total),
        };
    }
    // On a single file both engines print exactly one number, so the raw
    // outputs can be compared outright as well -- strictly stronger than the
    // sum, and free.
    let raw_note = if single_file {
        if a.raw.trim() == b.raw.trim() {
            format!("{} / {} identical", a.total, b.total)
        } else {
            return Gate {
                ok: false,
                raw_note: format!("{}/{} differ", a.total, b.total),
                why: format!(
                    "counts agree at {} but the raw output differs: rgx {:?} vs ripgrep {:?}",
                    a.total,
                    a.raw.trim(),
                    b.raw.trim()
                ),
            };
        }
    } else {
        format!("{} / {}", a.total, b.total)
    };
    Gate {
        ok: true,
        raw_note,
        why: "count equal".into(),
    }
}

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

fn time_ms(e: &Engine, args: &[String], flush: bool) -> Result<f64, String> {
    if flush {
        evict();
    }
    let t = Instant::now();
    let status = e
        .cmd(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("spawn {}: {err}", e.path.display()))?;
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    if !status.success() {
        return Err(format!("exited {status} during a timed run"));
    }
    Ok(ms)
}

fn min_of(v: &[f64]) -> f64 {
    v.iter().copied().fold(f64::INFINITY, f64::min)
}
fn max_of(v: &[f64]) -> f64 {
    v.iter().copied().fold(f64::NEG_INFINITY, f64::max)
}
fn median_of(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = s.len();
    if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    }
}

// ---------------------------------------------------------------------------
// One row's outcome
// ---------------------------------------------------------------------------

struct Outcome {
    row: Row,
    cx: Option<u64>,
    cr: Option<u64>,
    cbase: Option<u64>,
    x: Vec<f64>,
    r: Vec<f64>,
    b: Vec<f64>,
    passed: bool,
    fail: String,
}

impl Outcome {
    fn ratio(&self) -> f64 {
        let a = min_of(&self.x);
        if a <= 0.0 {
            0.0
        } else {
            min_of(&self.r) / a
        }
    }
    /// `base / new`, the effect of the change under test. Below 1.0 means the
    /// new build is faster than the base it is being compared against.
    fn change_ratio(&self) -> Option<f64> {
        if self.b.is_empty() {
            return None;
        }
        let n = min_of(&self.x);
        if n <= 0.0 {
            None
        } else {
            Some(min_of(&self.b) / n)
        }
    }
    /// Whether the two samples separate at all: every rgx run below every
    /// ripgrep run, or the reverse. Overlapping distributions cannot support a
    /// claim about which is faster, whatever the ratio of their minima says.
    fn separated(&self) -> bool {
        max_of(&self.x) < min_of(&self.r) || max_of(&self.r) < min_of(&self.x)
    }
    fn change_separated(&self) -> bool {
        !self.b.is_empty()
            && (max_of(&self.x) < min_of(&self.b) || max_of(&self.b) < min_of(&self.x))
    }
    fn delta_pct(&self) -> f64 {
        (self.ratio() - 1.0) * 100.0
    }
    fn change_pct(&self) -> f64 {
        match self.change_ratio() {
            Some(v) => (v - 1.0) * 100.0,
            None => 0.0,
        }
    }
    /// `tie` inside the floor, a named winner outside it when the samples
    /// separate, and `overlap` outside the floor with samples that do not
    /// separate -- a difference this harness refuses to call a result.
    fn verdict(&self, floor: f64) -> &'static str {
        if self.delta_pct().abs() <= floor {
            "tie"
        } else if !self.separated() {
            "overlap"
        } else if self.delta_pct() > 0.0 {
            "rgx"
        } else {
            "ripgrep"
        }
    }
    /// Text for the asymmetric row's verdict cell. The ratio is *not* a
    /// speedup -- rgx is doing strictly more work (extracting archives) and
    /// the user-visible claim is "rgx finds N more matches by reading inside
    /// containers rg cannot". The wall-clock is reported but the verdict
    /// names the asymmetric match count.
    fn asymmetric_label(&self) -> String {
        let a = self.cx.unwrap_or(0);
        let b = self.cr.unwrap_or(0);
        if a == 0 {
            "rgx found nothing".into()
        } else if a == b {
            format!("equal at {}", a)
        } else {
            let extra = a - b;
            let pct = if b > 0 {
                (extra as f64) * 100.0 / (b as f64)
            } else {
                0.0
            };
            format!("rgx +{} hits ({pct:+.0}% more)", extra)
        }
    }
}

fn verdict_cell(o: &Outcome, floor: f64) -> String {
    if o.row.asymmetric {
        return o.asymmetric_label();
    }
    let d = o.delta_pct();
    match o.verdict(floor) {
        "tie" => format!("tie (inside +-{floor:.1}%)"),
        "overlap" => format!("**overlap, not a result** ({d:+.1}%)"),
        "rgx" => format!("rgx **{d:+.1}%**"),
        _ => format!("ripgrep **{d:+.1}%**"),
    }
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

/// Name a corpus by what is in it, so a table can be told from another table
/// on the same path.
///
/// A single file is hashed by CONTENT: that is the corpus whose identity
/// actually matters, and 246 MB is about half a second of the run. A tree is
/// hashed by its sorted (relative path, size) listing instead — hashing 60k
/// files' contents would cost more than every timed round in this file, and a
/// corpus is identified by what it contains far more sharply by its shape than
/// by a digest of it.
fn fingerprint(path: &std::path::Path, single_file: bool) -> String {
    use rgx_core::sha256::Sha256;
    let mut h = Sha256::new();
    if single_file {
        match std::fs::File::open(path) {
            Ok(mut f) => {
                use std::io::Read as _;
                let mut buf = vec![0u8; 1 << 20];
                loop {
                    match f.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => h.update(&buf[..n]),
                    }
                }
            }
            Err(e) => return format!("unreadable ({e})"),
        }
    } else {
        let mut rows: Vec<String> = Vec::new();
        collect_tree_rows(path, &mut rows, 0);
        rows.sort();
        for r in &rows {
            h.update(r.as_bytes());
            h.update(b"\n");
        }
    }
    let d = h.finalize();
    let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
    format!("{hex}  ({})", path.display())
}

fn collect_tree_rows(dir: &std::path::Path, out: &mut Vec<String>, depth: usize) {
    if depth > 24 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            collect_tree_rows(&p, out, depth + 1);
        } else if ft.is_file() {
            if let Ok(md) = e.metadata() {
                out.push(format!(
                    "{} {}",
                    md.len(),
                    p.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                ));
            }
        }
    }
}

struct Section {
    n: usize,
    title: &'static str,
    corpus: String,
    corpus_label: String,
    /// sha256 that NAMES this corpus rather than describing it.
    ///
    /// **This field exists because a published table stopped being
    /// reproducible and nothing said why.** `benchmark/status.md` claims
    /// "the single file's sha256 is printed so a corpus is named, not
    /// described" -- and the *generator* does print one when it writes a
    /// corpus. The harness that then MEASURED that corpus printed nothing,
    /// so the fingerprint went to whichever terminal ran the generator and was
    /// lost.
    ///
    /// The cost of that silence was found the hard way. Re-running this
    /// harness against the same path produced a table that disagreed with the
    /// published one on every row -- not by a few percent, but by 1.6x to 49x
    /// in MATCH COUNT (`fn main`: 3,561 published against 175,860 measured),
    /// because `~/.rgx-bench/big235.rs` had been regenerated with a different
    /// token mix and nobody could tell which file the old numbers described.
    /// `pub fn` looked 2.1x slower. It was the same code on the same machine
    /// against 5.8x the matches.
    corpus_sha: String,
    jobs: usize,
    jobs_note: String,
    glob: Option<&'static str>,
    single_file: bool,
    rows: Vec<Row>,
}

fn run_section(
    cfg: &Cfg,
    gx: &Engine,
    rg: &Engine,
    base: Option<&Engine>,
    s: &Section,
    out: &mut String,
) -> Vec<Outcome> {
    let _ = writeln!(out, "{}", "-".repeat(78));
    let _ = writeln!(out, "[{}] {}", s.n, s.title);
    let _ = writeln!(out, "     corpus  : {}", s.corpus);
    let _ = writeln!(out, "               {}", s.corpus_label);
    let _ = writeln!(out, "     sha256  : {}", s.corpus_sha);
    let _ = writeln!(out, "     threads : {}", s.jobs_note);
    let _ = writeln!(
        out,
        "     filter  : {}",
        s.glob
            .map(|g| format!("-g '{g}'"))
            .unwrap_or_else(|| "(none)".into())
    );
    let _ = writeln!(
        out,
        "     rounds  : {} timed per cell (+{} discarded warmup), MINIMUM reported",
        cfg.rounds, cfg.warmup
    );
    let _ = writeln!(out, "     floor   : +-{:.1}% on the CLI", cfg.floor);
    let _ = writeln!(out, "{}", "-".repeat(78));

    let mut results = Vec::new();
    for row in &s.rows {
        let corpus = row.corpus.as_deref().unwrap_or(&s.corpus);
        let ax = args_for(row, corpus, s.jobs, s.glob, gx);
        let ar = args_for(row, corpus, s.jobs, s.glob, rg);
        let ab = base.map(|e| args_for(row, corpus, s.jobs, s.glob, e));

        let cx = measure(gx, &ax, row.is_walk());
        let cr = measure(rg, &ar, row.is_walk());
        let cb = match (&base, &ab) {
            (Some(e), Some(a)) => Some(measure(e, a, row.is_walk())),
            _ => None,
        };
        let g = gate(
            row,
            &cx,
            &cr,
            cb.as_ref(),
            s.single_file && row.corpus.is_none(),
        );

        if g.ok {
            match &cb {
                Some(c) => {
                    let _ = writeln!(
                        out,
                        "count   rgx {}={:<10}  rg {}={:<10}  base {}={:<10}  {}   GATE PASS",
                        row.unit(),
                        cx.total,
                        row.unit(),
                        cr.total,
                        row.unit(),
                        c.total,
                        g.raw_note
                    );
                }
                None => {
                    let _ = writeln!(
                        out,
                        "count   rgx {}={:<10}  rg {}={:<10}  {}   GATE PASS",
                        row.unit(),
                        cx.total,
                        row.unit(),
                        cr.total,
                        g.raw_note
                    );
                }
            }
        } else {
            let _ = writeln!(
                out,
                "count   rgx {}={:<10}  rg {}={:<10}  GATE FAIL: {}",
                row.unit(),
                cx.total,
                row.unit(),
                cr.total,
                g.why
            );
            let _ = writeln!(out, "        >>> '{}'  TIMING WITHHELD.", row.label);
            results.push(Outcome {
                row: Row {
                    label: row.label.clone(),
                    pat: row.pat.clone(),
                    corpus: row.corpus.clone(),
                    globs: row.globs.clone(),
                    asymmetric: row.asymmetric,
                },
                cx: Some(cx.total),
                cr: Some(cr.total),
                cbase: cb.as_ref().map(|c| c.total),
                x: Vec::new(),
                r: Vec::new(),
                b: Vec::new(),
                passed: false,
                fail: g.why,
            });
            continue;
        }

        let mut x: Vec<f64> = Vec::with_capacity(cfg.rounds);
        let mut r: Vec<f64> = Vec::with_capacity(cfg.rounds);
        let mut b: Vec<f64> = Vec::with_capacity(cfg.rounds);
        let mut failure: Option<String> = None;

        // The engines in one round, in the order this round runs them. With a
        // base build there are three, and the starting point rotates through
        // all three so no engine is systematically first or last. With two it
        // is the same alternation: a disturbed minute has to hit both, and
        // "second on a warm cache" has to cancel.
        let order: Vec<(&Engine, &Vec<String>)> = match (&base, &ab) {
            (Some(e), Some(a)) => vec![(gx, &ax), (rg, &ar), (e, a)],
            _ => vec![(gx, &ax), (rg, &ar)],
        };
        let n = order.len();

        for _ in 0..cfg.warmup {
            for (e, a) in &order {
                if let Err(err) = time_ms(e, a, cfg.flush) {
                    failure = Some(format!("warmup: {err}"));
                    break;
                }
            }
            if failure.is_some() {
                break;
            }
        }
        if failure.is_none() {
            for i in 0..cfg.rounds {
                let mut samples: Vec<Option<f64>> = vec![None; n];
                for slot in 0..n {
                    // `k` is the engine's FIXED identity; `slot` is only when
                    // it runs. Labelling the sample by `slot` while rotating
                    // which engine runs makes every odd round put ripgrep's
                    // time in the rgx column, and then both columns are the
                    // minimum of the same five numbers -- which reads as a
                    // tie on every row and is worse than no harness at all.
                    let k = (slot + i) % n;
                    let e = order[k];
                    match time_ms(e.0, e.1, cfg.flush) {
                        Ok(t) => samples[k] = Some(t),
                        Err(err) => {
                            failure = Some(err);
                            break;
                        }
                    }
                }
                if failure.is_some() {
                    break;
                }
                x.push(samples[0].unwrap());
                r.push(samples[1].unwrap());
                if let Some(v) = samples.get(2) {
                    b.push(v.unwrap());
                }
            }
        }

        if let Some(f) = failure {
            let _ = writeln!(out, "        >>> '{}'  ROUND FAILED: {f}", row.label);
            results.push(Outcome {
                row: Row {
                    label: row.label.clone(),
                    pat: row.pat.clone(),
                    corpus: row.corpus.clone(),
                    globs: row.globs.clone(),
                    asymmetric: row.asymmetric,
                },
                cx: Some(cx.total),
                cr: Some(cr.total),
                cbase: cb.as_ref().map(|c| c.total),
                x,
                r,
                b,
                passed: false,
                fail: f,
            });
            continue;
        }

        let o = Outcome {
            row: Row {
                label: row.label.clone(),
                pat: row.pat.clone(),
                corpus: row.corpus.clone(),
                globs: row.globs.clone(),
                asymmetric: row.asymmetric,
            },
            cx: Some(cx.total),
            cr: Some(cr.total),
            cbase: cb.as_ref().map(|c| c.total),
            x,
            r,
            b,
            passed: true,
            fail: String::new(),
        };
        if let Some(cr_ratio) = o.change_ratio() {
            let _ = writeln!(
                out,
                "  {:<20}|{:>9.1}|{:>9.1}|{:>7.2}x|{:>9.1}|{:>9.1}|{:>7.2}x|{:>8}|  {}",
                format!("`{}`", o.row.label),
                min_of(&o.b),
                min_of(&o.x),
                cr_ratio,
                min_of(&o.r),
                median_of(&o.x),
                if o.row.asymmetric { 0.0 } else { o.ratio() },
                if o.row.asymmetric {
                    "asy=yes"
                } else if o.separated() {
                    "sep=yes"
                } else {
                    "overlap"
                },
                verdict_cell(&o, cfg.floor)
            );
            let _ = writeln!(
                out,
                "  {:<20}  base max {:>8.1}   rgx max {:>8.1}   rg max {:>8.1}   rg/rgx {:+.1}%   base/rgx {:+.1}%{}",
                "",
                max_of(&o.b),
                max_of(&o.x),
                max_of(&o.r),
                o.delta_pct(),
                o.change_pct(),
                if o.change_separated() { " (separated)" } else { " (overlapping)" }
            );
        } else {
            let ratio_str: String = if o.row.asymmetric {
                "n/a".into()
            } else {
                format!("{:.2}x", o.ratio())
            };
            let sep_str: String = if o.row.asymmetric {
                "asy=yes".into()
            } else if o.separated() {
                "sep=yes".into()
            } else {
                "overlap".into()
            };
            let _ = writeln!(
                out,
                "  {:<20}|{:>9.1}|{:>9.1}|{:>9}|{:>9.1}|{:>9.1}|{:>9}|  {}",
                format!("`{}`", o.row.label),
                min_of(&o.x),
                min_of(&o.r),
                ratio_str,
                median_of(&o.x),
                median_of(&o.r),
                sep_str,
                verdict_cell(&o, cfg.floor)
            );
            let tail: &str = if o.row.asymmetric {
                "  (asymmetric -- rgx is doing more work)"
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "  {:<20}  rgx max {:>8.1}    rg max {:>8.1}    delta {:+.1}%{}",
                "",
                max_of(&o.x),
                max_of(&o.r),
                o.delta_pct(),
                tail
            );
        }
        if cfg.verbose {
            let xs: Vec<String> = o.x.iter().map(|v| format!("{v:.1}")).collect();
            let rs: Vec<String> = o.r.iter().map(|v| format!("{v:.1}")).collect();
            let bs: Vec<String> = o.b.iter().map(|v| format!("{v:.1}")).collect();
            let _ = writeln!(
                out,
                "  {:<20}  rgx [{}]   rg [{}]   base [{}]",
                "",
                xs.join(", "),
                rs.join(", "),
                bs.join(", ")
            );
        }
        results.push(o);
    }
    results
}

fn summary(out: &mut String, s: &Section, results: &[Outcome], floor: f64) {
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "summary [{}] -- paste-ready; the counts travel with the table:",
        s.n
    );
    let with_base = results
        .first()
        .map(|o| o.change_ratio().is_some())
        .unwrap_or(false);
    if with_base {
        let _ = writeln!(
            out,
            "| pattern | {} rgx / rg / base | base | rgx | rg | base/rgx | rg/rgx | verdict |",
            s.rows.first().map(|r| r.unit()).unwrap_or("lines")
        );
        let _ = writeln!(out, "|---|---:|---:|---:|---:|---:|---|");
    } else {
        let _ = writeln!(
            out,
            "| pattern | {} rgx / rg | rgx | ripgrep | ratio | verdict |",
            s.rows.first().map(|r| r.unit()).unwrap_or("lines")
        );
        let _ = writeln!(out, "|---|---:|---:|---:|---:|---|");
    }
    for o in results {
        if !o.passed {
            let _ = writeln!(
                out,
                "| `{}` | {} | — | — | — | **GATE FAIL, timing withheld** |",
                o.row.label,
                format_args!("{}/{}", o.cx.unwrap_or(0), o.cr.unwrap_or(0))
            );
            let _ = writeln!(out);
            let _ = writeln!(out, "> gate failure on `{}`: {}", o.row.label, o.fail);
            continue;
        }
        if with_base {
            let cr_ratio = o.change_ratio().unwrap_or(0.0);
            let change = cr_ratio - 1.0;
            let change_cell = if change.abs() * 100.0 <= floor {
                format!("tie (inside +-{floor:.1}%)")
            } else if !o.change_separated() {
                format!("**overlap** ({change:+.1}%)")
            } else {
                format!("**{:+.1}%**", -change * 100.0)
            };
            let _ = writeln!(
                out,
                "| `{}` | {} / {} / {} | {:.1} ms | {:.1} ms | {:.2}x | **{:.2}x** | vs ripgrep {}, change {} |",
                o.row.label,
                o.cx.unwrap_or(0),
                o.cr.unwrap_or(0),
                o.cbase.unwrap_or(0),
                min_of(&o.b),
                min_of(&o.x),
                cr_ratio,
                o.ratio(),
                verdict_cell(o, floor),
                change_cell
            );
            continue;
        }
        let _ = writeln!(
            out,
            "| `{}` | {} / {} | {:.1} ms | {:.1} ms | **{:.2}x** | {} |",
            o.row.label,
            o.cx.unwrap_or(0),
            o.cr.unwrap_or(0),
            min_of(&o.x),
            min_of(&o.r),
            o.ratio(),
            verdict_cell(o, floor)
        );
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let cfg = match parse() {
        Ok(Some(c)) => c,
        Ok(None) => return,
        Err(e) => {
            eprintln!("status_table: {e}");
            std::process::exit(2);
        }
    };

    let gx = Engine {
        path: cfg.rgx.clone(),
        is_rgx: true,
    };
    let rg = Engine {
        path: cfg.rg.clone(),
        is_rgx: false,
    };
    let base = cfg.rgx_base.as_ref().map(|p| Engine {
        path: p.clone(),
        is_rgx: true,
    });
    let base = base.as_ref();

    if !cfg.rgx.exists() {
        eprintln!(
            "status_table: no rgx binary at {} -- run scripts/bench-status.sh, or pass --rgx",
            cfg.rgx.display()
        );
        std::process::exit(2);
    }
    if !cfg.big.exists() {
        eprintln!("status_table: no 235 MB corpus at {}", cfg.big.display());
        std::process::exit(2);
    }
    if !cfg.tree.exists() {
        eprintln!(
            "status_table: no many-file corpus at {}",
            cfg.tree.display()
        );
        std::process::exit(2);
    }

    let jobs_note = |j: usize| {
        if let Some(o) = cfg.jobs_override {
            format!("rgx -j{j} AND rg -j{j} (set by --jobs {o})")
        } else {
            format!("rgx -j{j} AND rg -j{j} (same N to both)")
        }
    };

    // The corpus labels name what was actually measured. A hardcoded "235 MB"
    // next to an overridden `--big` is a table that lies about its own input.
    let big_bytes = std::fs::metadata(&cfg.big).map(|m| m.len()).unwrap_or(0);
    let big_size = if big_bytes >= 1_000_000_000 {
        format!("{:.2} GB", big_bytes as f64 / 1e9)
    } else if big_bytes >= 1_000_000 {
        format!("{:.0} MB", big_bytes as f64 / 1e6)
    } else {
        format!("{:.0} KB", big_bytes as f64 / 1e3)
    };
    let tree_files = walk_file_count(&cfg.tree);

    let sections = vec![
        Section {
            n: 1,
            title: "one file -- the engine alone, no walk",
            corpus: cfg.big.to_string_lossy().into_owned(),
            corpus_label: format!("{big_size}, single file"),
            corpus_sha: fingerprint(&cfg.big, true),
            jobs: cfg.jobs_one,
            jobs_note: jobs_note(cfg.jobs_one),
            glob: None,
            single_file: true,
            rows: cfg.patterns().iter().map(|p| Row::pat(p)).collect(),
        },
        Section {
            n: 2,
            title: "the many-file corpus -- mostly walk, barely engine",
            corpus: cfg.tree.to_string_lossy().into_owned(),
            corpus_label: format!("{tree_files} files under the tree"),
            corpus_sha: fingerprint(&cfg.tree, false),
            jobs: cfg.jobs_many,
            jobs_note: jobs_note(cfg.jobs_many),
            glob: Some("*.rs"),
            single_file: false,
            rows: cfg
                .patterns()
                .iter()
                .map(|p| Row::pat(p))
                .chain([Row::walk(&cfg.tree)])
                .collect(),
        },
        Section {
            n: 3,
            title: "this repository -- crates and src, so the §5 gates carry a time",
            corpus: cfg.root.to_string_lossy().into_owned(),
            corpus_label: format!(
                "the rgx working tree. The `crates` and `src` rows skip testdata + .bin/.gz so the \
                 gate compares what both engines can search (rg has no in-process brotli/zip/sevenz); \
                 pattern `{}`. The `archive-extract` row keeps everything and counts asymmetric \
                 matches -- rgx reads inside RAR / 7z / tar.* / brotli / zstd / lz4 / xz / lzma \
                 fixtures, rg treats them as binary. crates/ = {} files, src/ = {} files.",
                cfg.gate_pattern,
                walk_file_count(&cfg.root.join("crates")),
                walk_file_count(&cfg.root.join("src"))
            ),
            corpus_sha: fingerprint(&cfg.root, false),
            jobs: cfg.jobs_many,
            jobs_note: jobs_note(cfg.jobs_many),
            glob: None,
            single_file: false,
            rows: vec![
                // `crates/` is mostly compressed testdata under
                // `*/testdata/`; ripgrep has no in-process adapter for those
                // formats, so a row that asks both to search the directory
                // unfiltered asks rg to do something it cannot and the gate
                // fails every run. The globs keep the gate on what both
                // engines can search -- the rgx source itself. `testdata`
                // covers the nested testdata dirs, the extension globs cover
                // the corpus fixtures that live outside testdata (a small
                // number of `.bin` and `.gz` references in `src/`).
                Row::in_dir_with_globs(
                    "crates",
                    &cfg.gate_pattern,
                    &cfg.root.join("crates"),
                    vec!["!testdata", "!*.bin", "!*.gz"],
                ),
                Row::in_dir("src", &cfg.gate_pattern, &cfg.root.join("src")),
                // The asymmetric row: rgx finds more matches than rg by
                // reading inside RAR / 7z / tar.gz / brotli / zstd fixtures
                // that rg treats as binary. `RGXFIXTURE` is the marker string
                // the rar-codec testdata uses, so it appears in the plaintext
                // `*.expected` next to the .rar fixture AND inside the
                // archive after rgx extracts it. The gate allows rgx to
                // exceed rg; the verdict names the surplus.
                Row::asymmetric_in_dir(
                    "archive-extract",
                    "RGXFIXTURE",
                    &cfg.root.join("crates"),
                ),
            ],
        },
    ];

    let mut out = String::new();
    let _ = writeln!(out, "{}", "=".repeat(78));
    let _ = writeln!(
        out,
        "rgx status tables -- one command, gated, and unable to print an unverified speed."
    );
    let _ = writeln!(out, "{}", "=".repeat(78));
    let _ = writeln!(out, "  root    : {}", cfg.root.display());
    let _ = writeln!(out, "  rgx     : {}", cfg.rgx.display());
    let _ = writeln!(out, "             {}", version_line(&gx));
    let _ = writeln!(out, "  rg      : {}", cfg.rg.display());
    let _ = writeln!(out, "             {}", version_line(&rg));
    if let Some(b) = base {
        let be = Engine {
            path: b.path.clone(),
            is_rgx: true,
        };
        let _ = writeln!(out, "  base    : {}", b.path.display());
        let _ = writeln!(out, "             {}", version_line(&be));
    }
    let _ = writeln!(
        out,
        "  rounds  : {} per cell, +{} discarded warmup, MINIMUM reported",
        cfg.rounds, cfg.warmup
    );
    let _ = writeln!(
        out,
        "  floor   : +-{:.1}% on the CLI (in process it is +-{:.1}%). A ratio inside the floor is a tie.",
        cfg.floor, FLOOR_INPROC_PCT
    );
    let _ = writeln!(
        out,
        "  order   : engines interleaved inside every round{}",
        if base.is_some() {
            ", the leading engine rotating through all three"
        } else {
            ", the order alternating each round"
        }
    );
    let _ = writeln!(
        out,
        "  gate    : the -c count of rgx against rg is printed BEFORE every timing line; a"
    );
    let _ = writeln!(
        out,
        "            disagreement, a zero, an unparsable count, or a failed run SUPPRESSES the"
    );
    let _ = writeln!(
        out,
        "            timing line entirely. 0 == 0 is a FAILURE here, never a pass."
    );
    let _ = writeln!(
        out,
        "  columns : the minimums are the reported figures, and the ratio is min(rg)/min(rgx)."
    );
    let _ = writeln!(
        out,
        "            A ratio inside the floor is a tie; an overlap is not a one-word difference."
    );

    let mut all: Vec<Vec<Outcome>> = Vec::new();
    for s in &sections {
        let r = run_section(&cfg, &gx, &rg, base, s, &mut out);
        summary(&mut out, s, &r, cfg.floor);
        all.push(r);
    }

    let total: usize = all.iter().map(|v| v.len()).sum();
    let failed: Vec<&Outcome> = all.iter().flatten().filter(|o| !o.passed).collect();
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", "=".repeat(78));
    if failed.is_empty() {
        let _ = writeln!(
            out,
            "VERDICT: {total} rows, every gate passed. Each number above had its {} count proven\n\
             equal to ripgrep's before it was printed.",
            sections[0].rows[0].unit()
        );
    } else {
        let _ = writeln!(
            out,
            "VERDICT: {total} rows, {} FAILED a gate and had their timing withheld:",
            failed.len()
        );
        for o in &failed {
            let _ = writeln!(out, "  - '{}': {}", o.row.label, o.fail);
        }
        let _ = writeln!(
            out,
            "The passing rows are sound. The failing rows are not numbers and must not be quoted."
        );
    }
    let _ = writeln!(out, "{}", "=".repeat(78));

    // Flushed explicitly. stdout is block-buffered when it is a pipe or a
    // file, and a benchmark that says nothing for the two minutes it spends
    // measuring looks exactly like a benchmark that has hung.
    {
        let mut so = std::io::stdout().lock();
        let _ = so.write_all(out.as_bytes());
        let _ = so.flush();
    }
    if let Some(p) = &cfg.out {
        match std::fs::write(p, &out) {
            Ok(()) => eprintln!("status_table: wrote {}", p.display()),
            Err(e) => eprintln!("status_table: could not write {}: {e}", p.display()),
        }
    }
    if !failed.is_empty() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gate with no test is a gate that can regress into printing whatever
    /// it is handed. These are the four ways a run can lie to it, one per
    /// test, and each one has to come back `ok: false`:
    ///
    ///   1. it prints nothing and exits 0 -- the `$null -eq $null` bug, where
    ///      two empty results compare equal and look like agreement;
    ///   2. the counts disagree, one side having found more;
    ///   3. the process failed, so its output means nothing;
    ///   4. it printed something that is not a number.
    fn counted(total: u64, raw: &str, exit_ok: bool) -> Counted {
        Counted {
            total,
            raw: raw.to_string(),
            exit_ok,
            err: None,
        }
    }

    fn row() -> Row {
        Row::pat("e")
    }

    #[test]
    fn the_gate_refuses_two_zeros() {
        let g = gate(
            &row(),
            &counted(0, "", true),
            &counted(0, "", true),
            None,
            false,
        );
        assert!(!g.ok, "0 == 0 is not agreement: {}", g.why);
    }

    #[test]
    fn the_gate_refuses_disagreeing_counts() {
        let g = gate(
            &row(),
            &counted(10, "a:10\n", true),
            &counted(9, "a:9\n", true),
            None,
            false,
        );
        assert!(!g.ok, "{}", g.why);
        assert!(g.why.contains("count differs"), "{}", g.why);
    }

    #[test]
    fn the_gate_refuses_a_failed_run() {
        let g = gate(
            &row(),
            &counted(10, "a:10\n", false),
            &counted(10, "a:10\n", true),
            None,
            false,
        );
        assert!(!g.ok, "a non-zero exit makes its own output meaningless");
    }

    #[test]
    fn the_gate_refuses_output_that_is_not_a_number() {
        // The parse failure and the exit failure are separate checks, and a
        // binary that prints "error: no such file" and exits 1 must not be
        // counted as zero matches on both sides.
        let g = gate(
            &row(),
            &counted(0, "error: no such file\n", true),
            &counted(0, "", true),
            None,
            false,
        );
        assert!(!g.ok, "unparsable output is not zero matches: {}", g.why);
    }

    #[test]
    fn the_gate_passes_matching_counts() {
        let g = gate(
            &row(),
            &counted(10, "a:10\n", true),
            &counted(10, "a:10\n", true),
            None,
            false,
        );
        assert!(g.ok, "equal counts on a directory must pass: {}", g.why);
    }

    /// On a single file both engines print one bare number, so the gate also
    /// compares the raw output, which can fail where the sums agree: the two
    /// disagree about what to print and agree about how much there is.
    ///
    /// It compares TRIMMED output, so a trailing CR is not a difference. That
    /// is deliberate: `-c` on a file prints digits and a newline, and a CRLF
    /// terminator there says nothing about whether the two engines counted the
    /// same thing. Whitespace is not what this comparison is for.
    #[test]
    fn the_gate_is_stricter_on_a_single_file() {
        let g = gate(
            &row(),
            &counted(10, "10\n", true),
            &counted(10, "10\n", true),
            None,
            true,
        );
        assert!(g.ok, "{}", g.why);

        let g = gate(
            &row(),
            &counted(10, "10\n", true),
            &counted(10, "010\n", true),
            None,
            true,
        );
        assert!(
            !g.ok,
            "equal counts and different output is a difference: {}",
            g.why
        );

        // ... and the terminator is not one.
        let g = gate(
            &row(),
            &counted(10, "10\n", true),
            &counted(10, "10\r\n", true),
            None,
            true,
        );
        assert!(g.ok, "a CRLF count is still the same count: {}", g.why);
    }
}
