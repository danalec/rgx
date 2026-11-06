// SPDX-License-Identifier: Apache-2.0

//! The `-j` saturation curve: where does thread scaling stop buying, and is
//! `auto = all cores` still the right default past that point?
//!
//! ```text
//! cargo run --release -p rgx-core --example thread_curve -- \
//!     --corpus <repo>/crates --corpus ~/.rgx-bench/tree \
//!     --note "PROVISIONAL: contended machine"
//! ```
//!
//! ## Why this file exists
//!
//! `-j auto` means "every logical processor". Little's law (`L = lambda*W`,
//! a bookkeeping identity for any stable system) says the pool that sustains
//! a workload is its arrival rate times its measured service time -- so the
//! useful width is the saturation point, not the core count, whenever the
//! bottleneck is not CPU (walk/ignore-rule compilation and memory bandwidth
//! are the two named candidates on this tool). This harness measures the
//! curve so the question is answered by a number instead of an intuition, and
//! it stays re-runnable: one command, every `-j` interleaved in one session.
//!
//! ## The rules it inherits from `status_table.rs` (AGENTS.md 9)
//!
//! * **Count gate in front of every timing line.** Every `-j` of a workload
//!   must report the same count (paths walked, or summed `-c` lines) before
//!   any timing is printed. A disagreement suppresses the workload's timings
//!   entirely and fails the process exit code.
//! * **The zero rule, with one carve-out.** `0 == 0` proves nothing for a hit
//!   row -- a hit row with a zero count is a gate FAILURE. The miss workload
//!   is defined to find nothing: its gate is "every `-j` agrees at zero AND
//!   exits 1", and its timing is labelled as scan cost with no hit-count
//!   evidence. The label travels with the table.
//! * **Rounds and rotation.** Minimum 5 timed rounds (default 7), warmups
//!   discarded, the MINIMUM reported with median and max beside it, and the
//!   `-j` order rotates per round so a disturbed minute lands on every arm.
//! * **A verdict that can refuse.** Inside the floor a row is a tie. A winner
//!   is named only when every sample of one side is below every sample of the
//!   other AND the floor-subtracted minima differ by more than the floor.
//!   Otherwise: "overlap, not a result".
//! * **The spawn floor is measured and subtracted, not assumed.** A Windows
//!   process spawn costs ~16 ms on this machine and a constant offset
//!   compresses every ratio toward 1. The floor is the minimum of 25
//!   `--version` spawns taken in the same session; both raw and subtracted
//!   figures are printed. When a minimum does not clear the floor the
//!   subtracted figure is `n/a` -- that number does not exist.
//!
//! ## What it prints
//!
//! Per corpus and workload: the saturation curve (`-j` vs wall, throughput
//! `lambda`, effective parallelism `L = lambda*W` with `W` the `-j1`
//! floor-subtracted service time per file), the derived cap (smallest `-j`
//! whose minimum is within the floor of the best), and the policy rows
//! comparing `auto = all cores` against every measured width on the same
//! gates. Exit is non-zero if any gate failed.

use std::env;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

/// The floor on a difference, in percent: the CLI floor from AGENTS.md 9,
/// applied to the floor-subtracted minima. Subtracting the spawn floor is
/// what rule 4 requires before a ratio is believed; a subtracted ratio
/// outside this band is the only shape this harness calls a difference.
const FLOOR_PCT: f64 = 3.0;

/// Rounds below this are refused, as in `status_table.rs`: single runs on
/// this workload have moved 20% between samples while the machine settled.
const MIN_ROUNDS: usize = 5;

const USAGE: &str = "\
usage: thread_curve [options]

  --corpus PATH     corpus directory; repeatable (each gets the full
                    workload set: walk, hit, miss)
  --jobs LIST       comma list of -j values to sweep
                    (default: 1,2,4,... doubling up to all logical CPUs)
  --rounds N        timed rounds per cell (default 7, minimum 5)
  --warmup N        discarded warmup rounds (default 2)
  --pattern S       hit pattern (default 'let')
  --miss S          miss pattern (default a token that appears nowhere)
  --rgx PATH        the rgx binary (default <root>/target/release/rgx.exe)
  --root PATH       repository root (default: cwd)
  --floor-ms MS     override the measured spawn floor
  --note S          free text for the header (e.g. a contention caveat)
  --out PATH        also write the report to PATH
  --verbose         print every raw sample
  -h, --help        this text

The decisive re-run is the same command with --note dropped and the machine
quiet; nothing else about the invocation encodes this session's load.
";

struct Cfg {
    corpora: Vec<PathBuf>,
    jobs: Vec<usize>,
    rounds: usize,
    warmup: usize,
    pattern: String,
    miss: String,
    rgx: PathBuf,
    floor_ms: f64,
    note: Option<String>,
    out: Option<PathBuf>,
    verbose: bool,
}

/// The three workloads every corpus gets. The walk is the pure pipeline
/// question; the hit adds read+scan+sink; the miss is the walk plus a full
/// scan with nothing to report -- the shape a failed search pays.
#[derive(Clone, Copy, PartialEq)]
enum Work {
    Walk,
    Hit,
    Miss,
}

impl Work {
    fn label(&self) -> &'static str {
        match self {
            Work::Walk => "walk (--files)",
            Work::Hit => "hit (-c)",
            Work::Miss => "miss (-c)",
        }
    }
    /// What the count gate counts for this workload.
    fn unit(&self) -> &'static str {
        match self {
            Work::Walk => "paths",
            _ => "lines",
        }
    }
    /// A walk lists paths; the others print `-c` counts.
    fn is_walk(&self) -> bool {
        matches!(self, Work::Walk)
    }
}

/// One (corpus, workload) sweep: the gate totals and the raw samples, both
/// indexed by the sweep widths.
struct Cell {
    work: Work,
    jobs: Vec<usize>,
    /// The gate total (identical across widths by the time it is used).
    count: u64,
    /// Service units = files examined, for lambda and W. The walk count.
    n_files: u64,
    /// Raw wall samples per width, one Vec of rounds each.
    samples: Vec<Vec<f64>>,
}

fn parse() -> Result<Option<Cfg>, String> {
    let root_default = env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    let mut corpora: Vec<PathBuf> = Vec::new();
    let mut jobs: Option<Vec<usize>> = None;
    let mut rounds = 7usize;
    let mut warmup = 2usize;
    let mut pattern = String::from("let");
    // The miss token is assembled from halves at run time so the full string
    // never appears in any file -- this example sits inside the `crates`
    // corpus, and a literal default made the miss row match its own source.
    let mut miss = String::from(concat!("rgx_thread_curve_mis", "s_token_7f3a"));
    let mut rgx: Option<PathBuf> = env::var_os("RGX").map(PathBuf::from);
    let mut root = root_default;
    let mut floor_ms: Option<f64> = None;
    let mut note: Option<String> = None;
    let mut out: Option<PathBuf> = None;
    let mut verbose = false;

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0usize;
    while i < args.len() {
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
            "--corpus" => corpora.push(PathBuf::from(value(&args, &mut i, "--corpus")?)),
            "--jobs" => {
                let raw = value(&args, &mut i, "--jobs")?;
                let mut v = Vec::new();
                for part in raw.split(',') {
                    let n: usize = part
                        .trim()
                        .parse()
                        .map_err(|e| format!("--jobs {part:?}: {e}"))?;
                    if n == 0 {
                        return Err("--jobs: 0 is not a width to sweep".into());
                    }
                    if !v.contains(&n) {
                        v.push(n);
                    }
                }
                v.sort_unstable();
                if v.is_empty() {
                    return Err("--jobs: empty sweep".into());
                }
                jobs = Some(v);
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
            "--pattern" => pattern = value(&args, &mut i, "--pattern")?,
            "--miss" => miss = value(&args, &mut i, "--miss")?,
            "--rgx" => rgx = Some(PathBuf::from(value(&args, &mut i, "--rgx")?)),
            "--root" => root = PathBuf::from(value(&args, &mut i, "--root")?),
            "--floor-ms" => {
                floor_ms = Some(
                    value(&args, &mut i, "--floor-ms")?
                        .parse()
                        .map_err(|e| format!("--floor-ms: {e}"))?,
                )
            }
            "--note" => note = Some(value(&args, &mut i, "--note")?),
            "--out" => out = Some(PathBuf::from(value(&args, &mut i, "--out")?)),
            "--verbose" => verbose = true,
            other => return Err(format!("unknown option {other}\n\n{USAGE}")),
        }
        i += 1;
    }

    if corpora.is_empty() {
        return Err(format!("at least one --corpus is needed\n\n{USAGE}"));
    }
    for c in &corpora {
        if !c.is_dir() {
            return Err(format!("--corpus {} is not a directory", c.display()));
        }
    }
    if rounds < MIN_ROUNDS {
        return Err(format!(
            "--rounds {rounds} is refused: this harness does not print single-run numbers, and \
             {MIN_ROUNDS} is the minimum."
        ));
    }
    if warmup > rounds {
        return Err(format!("--warmup {warmup} exceeds --rounds {rounds}"));
    }
    if matches!(floor_ms, Some(f) if f <= 0.0) {
        return Err("--floor-ms must be positive".into());
    }
    let rgx = rgx.unwrap_or_else(|| {
        root.join("target")
            .join("release")
            .join(format!("rgx{}", env::consts::EXE_SUFFIX))
    });
    if !rgx.exists() {
        return Err(format!(
            "no rgx binary at {} -- build it first (cargo build --release)",
            rgx.display()
        ));
    }

    Ok(Some(Cfg {
        corpora,
        jobs: jobs.unwrap_or_else(default_jobs),
        rounds,
        warmup,
        pattern,
        miss,
        rgx,
        floor_ms: floor_ms.unwrap_or(-1.0), // negative marks "measure it"
        note,
        out,
        verbose,
    }))
}

/// 1,2,4,... up to the logical CPU count, with the count itself appended.
/// The point of the sweep is to see saturation *before* the end, so the
/// endpoint must be the width `auto` picks.
fn default_jobs() -> Vec<usize> {
    let n = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    let mut v = Vec::new();
    let mut j = 1usize;
    while j < n {
        v.push(j);
        j *= 2;
    }
    v.push(n);
    v
}

// ---------------------------------------------------------------------------
// Running one command
// ---------------------------------------------------------------------------

/// rgx is pinned to the in-house engine name for the same reason
/// `status_table.rs` pins it: `auto` is a detector, and a sweep whose arms
/// could pick different engines is not a thread sweep.
fn cmd(rgx: &Path, args: &[String]) -> Command {
    let mut c = Command::new(rgx);
    c.args(args);
    c.env("RGX_ENGINE", "rgx");
    c
}

fn workload_args(work: Work, pattern: &str, jobs: usize, corpus: &Path) -> Vec<String> {
    let mut a: Vec<String> = vec![format!("-j{jobs}")];
    match work {
        Work::Walk => {
            a.push("--files".into());
        }
        Work::Hit | Work::Miss => {
            a.push("-c".into());
            a.push("--".into());
            a.push(pattern.to_string());
        }
    }
    a.push(corpus.to_string_lossy().into_owned());
    a
}

/// The gate run: capture stdout, count what the workload counts, and record
/// whether the exit code is the one this workload owes. `-c` prints a count
/// per file (optionally `path:count`); summing the last field handles both
/// shapes, which is how `status_table.rs` counts too.
fn gate_run(rgx: &Path, args: &[String], work: Work) -> Result<(u64, bool), String> {
    let out = cmd(rgx, args)
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    let raw = String::from_utf8_lossy(&out.stdout);
    let count = if work.is_walk() {
        raw.lines().filter(|l| !l.trim().is_empty()).count() as u64
    } else {
        let mut total = 0u64;
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
                Err(_) => return Err(format!("unparsable -c line {line:?}")),
            }
        }
        total
    };
    // A walk and a hit owe success; a miss owes exactly the no-match exit.
    let exit_ok = match work {
        Work::Miss => out.status.code() == Some(1),
        _ => out.status.success(),
    };
    Ok((count, exit_ok))
}

/// One timed sample. The exit code must be the one the gate run recorded,
/// or the sample is a different workload than the gate admitted.
fn timed_run(rgx: &Path, args: &[String], work: Work) -> Result<f64, String> {
    let t = Instant::now();
    let status = cmd(rgx, args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("spawn: {e}"))?;
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    let exit_ok = match work {
        Work::Miss => status.code() == Some(1),
        _ => status.success(),
    };
    if !exit_ok {
        return Err(format!("exited {status} during a timed run"));
    }
    Ok(ms)
}

/// The spawn floor: the minimum of 25 `--version` spawns, this harness's
/// measurement of what a Windows process launch costs before rgx does any
/// work. `benchmark/status.md` measured a `print!("hi")` binary at 16.4
/// ms/iter and `rgx --version` at 17.5 on this machine class, so this figure
/// is ~1 ms conservative -- subtracting it under-states the work, never
/// over-states it.
fn measure_floor_ms(rgx: &Path) -> f64 {
    let args = vec!["--version".to_string()];
    let mut best = f64::INFINITY;
    for _ in 0..25 {
        let t = Instant::now();
        let ok = cmd(rgx, &args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            best = best.min(t.elapsed().as_secs_f64() * 1000.0);
        }
    }
    if best.is_finite() {
        best
    } else {
        0.0
    }
}

fn version_line(rgx: &Path) -> String {
    match cmd(rgx, &["--version".to_string()])
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
// Statistics and verdicts
// ---------------------------------------------------------------------------

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
    s[s.len() / 2]
}

/// The policy verdict, per AGENTS.md 9 rules 3 and 4. `mina`/`minb` are the
/// floor-subtracted minima when the floor was subtractable and the raw
/// minima otherwise (the caller then says so). A winner needs BOTH the floor
/// AND separation -- every sample of one side below every sample of the
/// other. Refusing is an outcome this function takes seriously.
fn verdict(mina: f64, minb: f64, a: &[f64], b: &[f64]) -> Option<&'static str> {
    if !(mina.is_finite() && minb.is_finite()) {
        return None;
    }
    let (lo, hi) = if mina <= minb {
        (mina, minb)
    } else {
        (minb, mina)
    };
    if hi <= 0.0 {
        return None;
    }
    let pct = (hi - lo) / lo * 100.0;
    if pct <= FLOOR_PCT {
        return Some("tie");
    }
    let a_below_b = a.iter().all(|x| b.iter().all(|y| x < y));
    let b_below_a = b.iter().all(|x| a.iter().all(|y| x < y));
    if a_below_b {
        Some("a")
    } else if b_below_a {
        Some("b")
    } else {
        Some("overlap")
    }
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

/// Gate + timing for one (corpus, workload) across the whole `-j` sweep.
/// Rounds interleave every width, and the leading slot rotates per round so
/// "whoever ran warm" cancels instead of biasing the widest arm.
fn sweep(
    rgx: &Path,
    cfg: &Cfg,
    work: Work,
    corpus: &Path,
    n_files: u64,
    out: &mut String,
) -> Option<Cell> {
    let pattern = match work {
        Work::Walk => String::new(),
        Work::Hit => cfg.pattern.clone(),
        Work::Miss => cfg.miss.clone(),
    };
    let mut cell = Cell {
        work,
        jobs: cfg.jobs.clone(),
        count: 0,
        n_files,
        samples: vec![Vec::new(); cfg.jobs.len()],
    };

    // The gate, once per width, before any timing is believed.
    let mut counts = Vec::new();
    let mut exits = Vec::new();
    let mut gate_ok = true;
    for &j in &cfg.jobs {
        let args = workload_args(work, &pattern, j, corpus);
        match gate_run(rgx, &args, work) {
            Ok((count, exit_ok)) => {
                counts.push(count);
                exits.push(exit_ok);
            }
            Err(e) => {
                let _ = writeln!(out, "  gate FAIL  -j{j}: {e}");
                gate_ok = false;
                counts.push(0);
                exits.push(false);
            }
        }
    }
    let first = counts.first().copied().unwrap_or(0);
    let agree = counts.iter().all(|&c| c == first);
    let exits_ok = exits.iter().all(|&e| e);
    let zero_shape_ok = match work {
        Work::Hit | Work::Walk => first > 0,
        Work::Miss => first == 0,
    };
    if !agree {
        let _ = writeln!(
            out,
            "  gate FAIL  counts disagree across -j: {counts:?} -- timings suppressed"
        );
        gate_ok = false;
    }
    if !exits_ok {
        let _ = writeln!(
            out,
            "  gate FAIL  wrong exit code at some -j: {exits:?} -- timings suppressed"
        );
        gate_ok = false;
    }
    if !zero_shape_ok {
        let _ = writeln!(
            out,
            "  gate FAIL  {} count {first} is not the shape this workload owes -- timings suppressed",
            work.unit()
        );
        gate_ok = false;
    }
    if !gate_ok {
        return None;
    }
    cell.count = first;
    if work == Work::Walk {
        // The walk count is the file set every workload of this corpus pays
        // a visit to -- the service-unit count for lambda and W.
        cell.n_files = first;
    }
    let _ = writeln!(
        out,
        "  gate PASS  {first} {} at every -j{}",
        work.unit(),
        if work == Work::Miss {
            " (zero by design: scan cost only, no hit-count evidence)"
        } else {
            ""
        }
    );

    // Warmups, discarded whole.
    for w in 0..cfg.warmup {
        for k in 0..cfg.jobs.len() {
            let j = cfg.jobs[(k + w) % cfg.jobs.len()];
            let args = workload_args(work, &pattern, j, corpus);
            if let Err(e) = timed_run(rgx, &args, work) {
                let _ = writeln!(out, "  warmup FAIL -j{j}: {e}");
                return None;
            }
        }
    }

    // Timed rounds, order rotating per round.
    for r in 0..cfg.rounds {
        for k in 0..cfg.jobs.len() {
            let idx = (k + r) % cfg.jobs.len();
            let j = cfg.jobs[idx];
            let args = workload_args(work, &pattern, j, corpus);
            match timed_run(rgx, &args, work) {
                Ok(ms) => {
                    if cfg.verbose {
                        let _ = writeln!(out, "    sample round {r} -j{j}: {ms:.2} ms");
                    }
                    cell.samples[idx].push(ms);
                }
                Err(e) => {
                    let _ = writeln!(out, "  timed FAIL -j{j}: {e}");
                    return None;
                }
            }
        }
    }
    Some(cell)
}

/// `min_ms - floor_ms`, only when that is a positive number. A wall time the
/// spawn floor covers whole has no subtracted figure -- the column says
/// `n/a` instead of printing arithmetic on noise.
fn sub(min_ms: f64, floor_ms: f64) -> Option<f64> {
    (min_ms - floor_ms > 0.0).then_some(min_ms - floor_ms)
}

/// The curve table for one cell: `-j`, raw min/med/max, floor-subtracted
/// minimum, throughput lambda, and L = lambda*W with W derived from `-j1`.
/// `sub1` is the `-j1` floor-subtracted wall -- the serial service time of
/// the whole workload; dividing by the file count gives W per file. L is
/// then `sub1/sub_j`, the effective parallelism the width sustains, and
/// `j - L` is the worker width spent above what the workload sustains.
fn curve(out: &mut String, cell: &Cell, floor_ms: f64) {
    let mins: Vec<f64> = cell.samples.iter().map(|s| min_of(s)).collect();
    let sub1 = mins.first().copied().and_then(|m| sub(m, floor_ms));
    let n = cell.n_files;

    let _ = writeln!(
        out,
        "  | -j | min ms | med | max | min-floor | lambda files/s | L=lambda*W | j - L |"
    );
    let _ = writeln!(out, "  |---:|---:|---:|---:|---:|---:|---:|---:|");
    for (k, s) in cell.samples.iter().enumerate() {
        let min_ms = min_of(s);
        let (sub_s, lam_s, l_s, idle_s) = match (sub(min_ms, floor_ms), sub1) {
            (Some(v), Some(s1)) if n > 0 => {
                let lambda = n as f64 / (v / 1000.0);
                let l = s1 / v;
                (
                    format!("{v:.1}"),
                    format!("{lambda:.0}"),
                    format!("{l:.2}"),
                    format!("{:.1}", cell.jobs[k] as f64 - l),
                )
            }
            _ => ("n/a".into(), "n/a".into(), "n/a".into(), "n/a".into()),
        };
        let _ = writeln!(
            out,
            "  | {} | {min_ms:.1} | {:.1} | {:.1} | {sub_s} | {lam_s} | {l_s} | {idle_s} |",
            cell.jobs[k],
            median_of(s),
            max_of(s),
        );
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

fn main() {
    let mut out = String::new();
    let code = match run(&mut out) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("thread_curve: {e}");
            2
        }
    };
    print!("{out}");
    std::process::exit(code);
}

fn run(out: &mut String) -> Result<i32, String> {
    let Some(cfg) = parse()? else {
        return Ok(0);
    };

    let floor_ms = if cfg.floor_ms >= 0.0 {
        cfg.floor_ms
    } else {
        measure_floor_ms(&cfg.rgx)
    };

    let _ = writeln!(out, "# thread_curve: -j saturation sweep");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- rgx: `{}` ({})",
        cfg.rgx.display(),
        version_line(&cfg.rgx)
    );
    let _ = writeln!(
        out,
        "- logical CPUs: {}, sweep -j: {:?}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        cfg.jobs
    );
    let _ = writeln!(
        out,
        "- spawn floor: {floor_ms:.2} ms (min of 25 `--version` spawns{}), subtracted where a minimum clears it",
        if cfg.floor_ms >= 0.0 {
            " -- overridden by --floor-ms"
        } else {
            ""
        }
    );
    let _ = writeln!(
        out,
        "- rounds: {} (min reported; median/max beside), warmup {}, floor +-{FLOOR_PCT:.1}% on floor-subtracted minima",
        cfg.rounds, cfg.warmup
    );
    let _ = writeln!(
        out,
        "- hit pattern: `{}`, miss pattern: `{}`",
        cfg.pattern, cfg.miss
    );
    if let Some(n) = &cfg.note {
        let _ = writeln!(out, "- note: {n}");
    }
    let _ = writeln!(out);

    let mut any_gate_fail = false;
    let mut all_cells: Vec<(String, Cell)> = Vec::new();

    for corpus in &cfg.corpora {
        let label = corpus
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| corpus.display().to_string());
        let _ = writeln!(out, "## corpus `{label}` ({})", corpus.display());
        let mut n_files = 0u64;
        for work in [Work::Walk, Work::Hit, Work::Miss] {
            let _ = writeln!(out, "### {label} -- {}", work.label());
            match sweep(&cfg.rgx, &cfg, work, corpus, n_files, out) {
                Some(cell) => {
                    if work == Work::Walk {
                        n_files = cell.count;
                    }
                    curve(out, &cell, floor_ms);
                    let _ = writeln!(out);
                    all_cells.push((label.clone(), cell));
                }
                None => {
                    any_gate_fail = true;
                    let _ = writeln!(out);
                }
            }
        }
    }

    // W and the derived cap, one line per (corpus, workload). The cap is the
    // smallest width whose minimum is within the floor of the best width's --
    // the width past which more workers buy nothing measurable.
    let _ = writeln!(out, "## derived service time and saturation");
    for (label, cell) in &all_cells {
        let mins: Vec<f64> = cell.samples.iter().map(|s| min_of(s)).collect();
        let sub1 = mins.first().copied().and_then(|m| sub(m, floor_ms));
        let best_k = mins
            .iter()
            .enumerate()
            .min_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(k, _)| k)
            .unwrap_or(0);
        let best = mins[best_k];
        let cap_k = mins
            .iter()
            .position(|&m| m <= best * (1.0 + FLOOR_PCT / 100.0))
            .unwrap_or(best_k);
        let w_line = match (sub1, cell.n_files) {
            (Some(s1), n) if n > 0 => format!("{:.3} ms/file", s1 / n as f64),
            _ => "n/a (wall did not clear the spawn floor)".to_string(),
        };
        let l_star = match (sub1, sub(best, floor_ms)) {
            (Some(s1), Some(b)) => format!("{:.2}", s1 / b),
            _ => "n/a".to_string(),
        };
        let _ = writeln!(
            out,
            "- `{label}` {}: W = {w_line}; saturation cap = -j{} (best min {best:.1} ms at -j{}); L* = lambda*W = {l_star}",
            cell.work.label(),
            cell.jobs[cap_k],
            cell.jobs[best_k],
        );
    }
    let _ = writeln!(out);

    // Policy rows: `auto = all cores` (the widest swept) against every other
    // width on the same gate. The derived cap is one of these rows; which
    // one is the line above.
    let _ = writeln!(out, "## policy comparison (a = widest = `auto` side)");
    let _ = writeln!(
        out,
        "(min = raw wall minimum; comp = the figure the verdict compares, floor-subtracted when possible)"
    );
    for (label, cell) in &all_cells {
        let wide = cell.jobs.len() - 1;
        let wa = min_of(cell.samples.last().unwrap_or(&Vec::new()));
        let suba = sub(wa, floor_ms);
        let _ = writeln!(out, "### `{label}` {}", cell.work.label());
        let _ = writeln!(
            out,
            "  gate: {} {} at every -j ({} vs {})",
            cell.count,
            cell.work.unit(),
            cell.jobs[wide],
            cell.jobs[..wide]
                .iter()
                .map(|j| j.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
        for k in 0..wide {
            let wb = min_of(&cell.samples[k]);
            let subb = sub(wb, floor_ms);
            let (mina, minb, basis) = match (suba, subb) {
                (Some(sa), Some(sb)) => (sa, sb, ""),
                _ => (wa, wb, " on raw (floor not subtractable)"),
            };
            let line = match verdict(mina, minb, cell.samples.last().unwrap(), &cell.samples[k]) {
                Some("tie") => format!("tie (inside +-{FLOOR_PCT:.1}%{basis})"),
                Some("a") => format!(
                    "-j{} wins by {:.1}%{basis}",
                    cell.jobs[wide],
                    (mina.max(minb) / mina.min(minb) - 1.0) * 100.0,
                ),
                Some("b") => format!(
                    "-j{} wins by {:.1}%{basis}",
                    cell.jobs[k],
                    (mina.max(minb) / mina.min(minb) - 1.0) * 100.0,
                ),
                Some(_) => format!(
                    "overlap, not a result ({:.1}% apart{basis})",
                    (mina.max(minb) / mina.min(minb) - 1.0) * 100.0,
                ),
                None => format!("not a number{basis}"),
            };
            let _ = writeln!(
                out,
                "  -j{} vs -j{}: a {wa:.1} ms (comp {mina:.1}) / b {wb:.1} ms (comp {minb:.1}) -> {line}",
                cell.jobs[wide], cell.jobs[k]
            );
        }
        let _ = writeln!(out);
    }

    if let Some(path) = &cfg.out {
        std::fs::write(path, out.as_bytes())
            .map_err(|e| format!("--out {}: {e}", path.display()))?;
    }
    Ok(if any_gate_fail { 1 } else { 0 })
}
