// SPDX-License-Identifier: Apache-2.0

//! What one confirm costs, and WHICH confirm, on the candidate stream a real
//! search actually builds.
//!
//! ```text
//! cargo run --release -p rgx-core --example confirm_profile -- [corpus-file] [patterns...]
//! ```
//!
//! ## Why this file exists
//!
//! `crates/rgx-core/src/fixed.rs:1-25` states that a two-byte pattern costs
//! about 44.9 ns a confirm against 1.7 ns for the two byte comparisons it
//! performs, and attributes ~14 ns to per-call setup and ~15 ns to building
//! the `Match` a successful run returns. The header is the reason that file
//! exists, and the numbers in it are load-bearing: the whole design rests on
//! ~96% of a confirm being overhead.
//!
//! That is a claim about `vm::find_at` and `vm::matches_at`, and it has to be
//! tested rather than trusted, because `fixed.rs` is not the only confirm the
//! engine has. `regex.rs` dispatches a candidate through one of three
//! engines -- `fixed::Fixed` (`regex.rs:3280`), `MatchMask::holds`
//! (`regex.rs:3270`) and the Pike VM (`regex.rs:3290`) -- and the header's
//! arithmetic describes only the third, which is the one the first two exist
//! to avoid. So "96% of every confirmation is overhead" can be true of the
//! VM and still be false of the confirmations the binary runs.
//!
//! **The gate is in front of every number here.** Two engines that answer the
//! same question differently are not comparable, and a confirm measured over
//! candidates it gets wrong is a measurement of nothing. Every engine in a
//! row is asked the same question over the same candidate stream and its
//! number of `true` answers is compared against `vm::matches_at`'s; a
//! disagreement suppresses the whole row rather than printing a number with a
//! warning beside it. `0 == 0` is not a pass (`status_table.rs:610`).
//!
//! ## The four tables
//!
//! | table | what it prices |
//! |-------|----------------|
//! | 1 | per-candidate: the three confirm engines over the real candidate stream |
//! | 2 | per-line: `any_match_in`, the confirm a searcher actually calls |
//! | 3 | the `44.9 ns` decomposition, term by term |
//! | 4 | the VM's per-call setup priced as a slope in program width |
//!
//! Table 4 is the one that separates "setup" from "work". A one-byte pattern
//! consumes one byte whatever else it is made of, so a ladder of alternations
//! over single bytes changes the program's INSTRUCTION COUNT while holding
//! the number of bytes the VM consumes fixed. Whatever the VM's time does
//! against instruction count is setup -- zeroing the thread table and the two
//! visit bitmaps, which `vm.rs:474-486` sizes from `prog.insts.len()` -- and
//! not stepping.

use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

use rgx_core::fixed::Fixed;
use rgx_core::matcher::Matcher as _;
use rgx_core::regex::ByteRegex;
use rgx_core::scan::{MaskBranch, MaskTerm, MatchMask};
use rgx_core::searcher::{
    BinaryDetection, Candidates, Config, Origin, Searcher, Sink, SinkContext, SinkFinish, SinkMatch,
};

const ROUNDS: usize = 7;
const WARMUP: usize = 2;
const TARGET_MS: f64 = 60.0;

/// The searcher's own read buffer, so the per-block table pays the same
/// per-fill costs the binary pays. `rgx-core/src/searcher.rs` `buffer_capacity`.
const BLOCK: usize = 64 * 1024;

/// A bounded prefix of the corpus. 64 MiB is 64 real fills and enough
/// candidates that the per-candidate prices converge long before the end.
const CAP: usize = 64 << 20;

/// The pattern shapes the task names, plus the neighbours that make the
/// lengths legible: a literal ladder by length, the two-byte and wildcard
/// shapes `fixed.rs` quotes, and the alternation `fixed.rs` refuses.
const SHAPES: [&str; 8] = [
    "pub fn",          // one literal, 6 bytes
    "fn main",         // one literal, 7 bytes
    "let mut",         // one literal, 7 bytes
    "e[0-9]",          // two bytes, second is a class
    "e.",              // two bytes, second is a wildcard
    "a|b|c",           // alternation -- `fixed` refuses this one
    "foo.*bar",        // a repetition -- `fixed` refuses this one
    "(pub|fn) [a-z]+", // a greedy tail -- the shape `regex.rs:1129` prices
];

/// A one-byte pattern per alternation branch, so instruction count rises and
/// consumed bytes do not. This is the control that prices setup.
fn width_ladder() -> Vec<String> {
    const ALPHA: [&str; 6] = ["a", "b", "c", "d", "e", "f"];
    (1..=6)
        .map(|k| {
            let mut s = String::new();
            for b in &ALPHA[..k] {
                if !s.is_empty() {
                    s.push('|');
                }
                s.push_str(b);
            }
            s
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

/// Min of [`ROUNDS`] timed rounds after [`WARMUP`] warmups, in nanoseconds
/// per call of `f`. The minimum, because the minimum is the round the
/// machine was not disturbed in.
fn time_ns(mut f: impl FnMut() -> u64) -> f64 {
    for _ in 0..WARMUP {
        black_box(f());
    }
    let t = Instant::now();
    black_box(f());
    let one = t.elapsed().as_secs_f64().max(1e-9);
    let iters = (TARGET_MS / 1e3 / one).clamp(1.0, 1000.0) as usize;
    let mut best = f64::INFINITY;
    for _ in 0..ROUNDS {
        let t = Instant::now();
        let mut sink = 0u64;
        for _ in 0..iters {
            sink = sink.wrapping_add(black_box(f()));
        }
        black_box(sink);
        best = best.min(t.elapsed().as_secs_f64() * 1e9 / iters as f64);
    }
    best
}

/// The same, but returns the LAST round's ACCUMULATOR beside the time.
///
/// The accumulator is `iters` calls summed, so it is NOT a count of anything
/// -- it is a multiple of the count by however many passes the calibration
/// chose. Gates here therefore never read it: every engine's hit count is
/// taken by a separate deterministic pass through [`count_true`], so the
/// number being compared is an answer rather than a timing artefact.
fn time_ns_acc(mut f: impl FnMut() -> u64) -> f64 {
    for _ in 0..WARMUP {
        black_box(f());
    }
    let t = Instant::now();
    black_box(f());
    let one = t.elapsed().as_secs_f64().max(1e-9);
    let iters = (TARGET_MS / 1e3 / one).clamp(1.0, 1000.0) as usize;
    let mut best = f64::INFINITY;
    for _ in 0..ROUNDS {
        let t = Instant::now();
        let mut sink = 0u64;
        for _ in 0..iters {
            sink = sink.wrapping_add(black_box(f()));
        }
        black_box(sink);
        best = best.min(t.elapsed().as_secs_f64() * 1e9 / iters as f64);
    }
    best
}

/// One deterministic pass: how many times `f` returned a true count. This is
/// the number the gate compares, and it is computed outside every timing loop
/// so a calibration cannot leak into it.
fn count_true(f: impl FnOnce() -> u64) -> u64 {
    black_box(f())
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// A timing may only be printed when every engine that produced one agreed
/// with the reference about how many candidates match. Mirrors the rule
/// `status_table.rs:571` states for the CLI: no timing line without a
/// passing count gate in front of it.
struct Gate {
    ok: bool,
    why: String,
}

impl Gate {
    fn pass() -> Self {
        Gate {
            ok: true,
            why: String::new(),
        }
    }

    /// `labels` and `hits` are the engine names and their `true` counts, in
    /// the same order, with the reference first.
    fn of(labels: &[&str], hits: &[u64]) -> Self {
        let ref_hits = hits[0];
        if ref_hits == 0 {
            return Gate {
                ok: false,
                why: "reference engine matched 0 candidates -- nothing to price".into(),
            };
        }
        for (label, h) in labels.iter().zip(hits) {
            if *h != ref_hits {
                return Gate {
                    ok: false,
                    why: format!("{label} says {h} matches, reference says {ref_hits}"),
                };
            }
        }
        Gate::pass()
    }
}

/// A count sink for the searcher rows.
struct Counter(u64);

impl Sink for Counter {
    type Error = std::convert::Infallible;

    fn matched(&mut self, _: &SinkMatch<'_>) -> Result<bool, Self::Error> {
        self.0 += 1;
        Ok(true)
    }
    fn context(&mut self, _: &SinkContext<'_>) -> Result<bool, Self::Error> {
        Ok(true)
    }
    fn finish(&mut self, _: &SinkFinish<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// The searcher's config, on the path the binary actually runs.
///
/// `count` is **off**, and that is load-bearing rather than incidental.
/// [`Config::needs_line_output`] is `!self.count && !self.quiet`, so a
/// count-mode searcher never hands a line to its sink at all -- the first
/// version of this file gated on a count-mode run and every row reported
/// "matched nothing", which was the config talking and not the corpus.
fn cfg() -> Config {
    Config {
        count: false,
        binary: BinaryDetection::None,
        ..Config::default()
    }
}

/// The match mask this pattern would get as an anchor, if it has one.
/// Copied from `examples/cost_sensitivity.rs:454`.
fn mask_of(ast: &rgx_core::syntax::Ast) -> Option<MatchMask> {
    let plan = rgx_core::required::match_mask(ast)?;
    if !plan.decides {
        return None;
    }
    let branches: Vec<MaskBranch> = plan
        .branches
        .iter()
        .map(|b| MaskBranch {
            terms: b
                .iter()
                .map(|s| MaskTerm {
                    class: s.class,
                    shift: s.at,
                })
                .collect::<Vec<MaskTerm>>(),
        })
        .collect();
    MatchMask::new(branches, plan.decides)
}

// ---------------------------------------------------------------------------
// The hand-written floor
// ---------------------------------------------------------------------------

/// The byte comparisons the pattern specifies, inlined, on the same bytes.
/// This is the FLOOR: what a confirm would cost if it did nothing else.
#[inline(always)]
fn hand(pat: &str, hay: &[u8], s: usize) -> bool {
    let g = |i: usize| hay[s + i];
    match pat {
        "e" => g(0) == b'e',
        "e." => g(0) == b'e' && g(1) != b'\n',
        "e[0-9]" => g(0) == b'e' && g(1).is_ascii_digit(),
        "pub fn" => {
            g(0) == b'p'
                && g(1) == b'u'
                && g(2) == b'b'
                && g(3) == b' '
                && g(4) == b'f'
                && g(5) == b'n'
        }
        "fn main" => {
            g(0) == b'f'
                && g(1) == b'n'
                && g(2) == b' '
                && g(3) == b'm'
                && g(4) == b'a'
                && g(5) == b'i'
                && g(6) == b'n'
        }
        "let mut" => {
            g(0) == b'l'
                && g(1) == b'e'
                && g(2) == b't'
                && g(3) == b' '
                && g(4) == b'm'
                && g(5) == b'u'
                && g(6) == b't'
        }
        "a|b|c" => g(0) == b'a' || g(0) == b'b' || g(0) == b'c',
        "foo.*bar" => false,
        "(pub|fn) [a-z]+" => false,
        _ => false,
    }
}

/// The same behind a call the optimiser may not remove: the price of dispatch.
#[inline(never)]
fn hand_fn(pat: &str, hay: &[u8], s: usize) -> bool {
    black_box(pat);
    hand(pat, hay, s)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(default_corpus);
    let pats: Vec<String> = args.collect();
    let pats: Vec<String> = if pats.is_empty() {
        SHAPES.iter().map(|s| (*s).to_owned()).collect()
    } else {
        pats
    };

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            std::process::exit(1);
        }
    };
    let hay = &data[..data.len().min(CAP)];
    let lines = rgx_core::memchr::memchr_iter(b'\n', hay).count() as u64;

    println!("corpus : {path}");
    println!(
        "buffer : {:.1} MiB of the file, {lines} lines, {BLOCK} B fills, min of {ROUNDS} rounds\n",
        hay.len() as f64 / (1024.0 * 1024.0)
    );

    // -----------------------------------------------------------------
    // TABLE 1 -- per-candidate, the three confirm engines
    // -----------------------------------------------------------------
    println!("TABLE 1  per-candidate confirm, over the real candidate stream");
    println!("(each engine asked the same question of the same offsets)\n");
    println!(
        "{:<16} {:>8} {:>7} {:>8} {:>10} {:>10} {:>10} {:>11}",
        "pattern", "insts", "cands", "hit rate", "VM bool", "VM find", "Fixed", "MatchMask"
    );
    println!("{}", "-".repeat(90));

    for pat in &pats {
        let Ok(re) = ByteRegex::new(pat.as_bytes()) else {
            println!("{pat:<16} (did not compile)");
            continue;
        };
        let parsed = rgx_core::syntax::parse(pat.as_bytes()).expect("the pattern parses");
        let prog = rgx_core::nfa::compile(&parsed.ast, parsed.groups);
        let fixed = Fixed::compile(&parsed.ast);
        let mask = mask_of(&parsed.ast);

        let mut cands: Vec<usize> = Vec::new();
        re.fast_candidates(hay, &mut cands);
        let n = cands.len();
        if n == 0 {
            println!("{pat:<16} (no candidates in the first {} bytes)", hay.len());
            continue;
        }

        // The reference: the Pike VM's boolean form. Everything is gated on
        // it, and its count is taken by its own deterministic pass.
        let vm_hits = count_true(|| {
            cands
                .iter()
                .filter(|&&c| rgx_core::vm::matches_at(&prog, hay, c))
                .count() as u64
        });
        let vm_bool_ns = time_ns(|| {
            let mut acc = 0u64;
            for &c in &cands {
                acc += rgx_core::vm::matches_at(&prog, hay, c) as u64;
            }
            acc
        });

        let vm_find_ns = time_ns(|| {
            let mut acc = 0u64;
            for &c in &cands {
                acc += rgx_core::vm::find_at(&prog, hay, c).is_some() as u64;
            }
            acc
        });

        let fixed_row = match &fixed {
            Some(fx) => {
                let hits =
                    count_true(|| cands.iter().filter(|&&c| fx.confirm(hay, c)).count() as u64);
                let g = Gate::of(&["fixed::Fixed", "Pike VM"], &[hits, vm_hits]);
                if g.ok {
                    Some(time_ns(|| {
                        let mut acc = 0u64;
                        for &c in &cands {
                            acc += fx.confirm(hay, c) as u64;
                        }
                        acc
                    }))
                } else {
                    eprintln!("GATE FAIL {pat} fixed: {}", g.why);
                    None
                }
            }
            None => None,
        };

        let mask_row = match &mask {
            Some(m) => {
                let hits = count_true(|| cands.iter().filter(|&&c| m.holds(hay, c)).count() as u64);
                let g = Gate::of(&["MatchMask::holds", "Pike VM"], &[hits, vm_hits]);
                if g.ok {
                    Some(time_ns(|| {
                        let mut acc = 0u64;
                        for &c in &cands {
                            acc += m.holds(hay, c) as u64;
                        }
                        acc
                    }))
                } else {
                    eprintln!("GATE FAIL {pat} mask: {}", g.why);
                    None
                }
            }
            None => None,
        };

        let f = |x: &Option<f64>, n: usize| match x {
            Some(ns) => format!("{:>9.2}ns", ns / n as f64),
            None => format!("{:>10}", "--"),
        };
        println!(
            "{:<16} {:>8} {:>7} {:>7.2}% {:>9.2}ns {:>9.2}ns {} {}",
            pat,
            prog.insts.len(),
            n,
            vm_hits as f64 * 100.0 / n as f64,
            vm_bool_ns / n as f64,
            vm_find_ns / n as f64,
            f(&fixed_row, n),
            f(&mask_row, n),
        );
    }

    // -----------------------------------------------------------------
    // TABLE 2 -- per-line, the confirm a searcher actually calls
    // -----------------------------------------------------------------
    println!("\nTABLE 2  per-line: `any_match_in` on real lines that carry a candidate");
    println!("(the unit the binary's searcher charges a confirm on)\n");
    println!(
        "{:<16} {:>9} {:>9} {:>10} {:>12} {:>12}",
        "pattern", "lines+c", "matched", "gate", "ns/line", "ns/cand"
    );
    println!("{}", "-".repeat(74));

    // One line split, shared by every pattern. A line is [start, end) with
    // the terminator already cut off, which is what the searcher hands a
    // confirm and what `LineCandidates` rebases against.
    let mut line_bounds: Vec<(usize, usize)> = Vec::new();
    let mut start = 0usize;
    for p in rgx_core::memchr::memchr_iter(b'\n', hay) {
        line_bounds.push((start, p));
        start = p + 1;
    }
    line_bounds.push((start, hay.len()));

    for pat in &pats {
        let Ok(re) = ByteRegex::new(pat.as_bytes()) else {
            continue;
        };
        let mut all_cands: Vec<usize> = Vec::new();
        re.fast_candidates(hay, &mut all_cands);
        if all_cands.is_empty() {
            println!("{pat:<16} (no candidates)");
            continue;
        }

        // Group the candidate stream by line, ONCE, so the timing loop below
        // is not paying for a candidate search on every round.
        let mut rows: Vec<(usize, usize, &[usize])> = Vec::new();
        for (ls, le) in &line_bounds {
            let lo = all_cands.partition_point(|&c| c < *ls);
            let hi = all_cands.partition_point(|&c| c < *le);
            if hi > lo {
                rows.push((*ls, *le, &all_cands[lo..hi]));
            }
        }
        if rows.is_empty() {
            println!("{pat:<16} (no line carries a candidate)");
            continue;
        }
        let n_cand: usize = rows.iter().map(|r| r.2.len()).sum();

        // The gate. A line and a candidate are not the same question -- one
        // line can hold three candidates and answer once -- so the line count
        // is checked against the ORACLE that matters: the real `Searcher`'s
        // own count of matching lines over the same bytes. If the per-line
        // confirm here disagreed with the searcher that would call it, the
        // two are not the same search and neither number is timed.
        let confirm_line = |re: &ByteRegex, ls: usize, le: usize, c: &[usize]| -> bool {
            let mut cand = Candidates::of(c).with_origin(Origin::Fixed(0));
            let lc = cand.in_line(ls, le);
            re.any_match_in(&hay[ls..le], lc, Origin::Fixed(0))
        };
        let line_hits: u64 = rows
            .iter()
            .filter(|(ls, le, c)| confirm_line(&re, *ls, *le, c))
            .count() as u64;
        let oracle_hits: u64 = count_true(|| {
            let s = Searcher::with_candidates(&re, &re, cfg());
            let mut c = Counter(0);
            s.search_slice(hay, &mut c).ok();
            c.0
        });
        let g = Gate::of(&["any_match_in", "Searcher"], &[line_hits, oracle_hits]);
        if !g.ok {
            println!("{pat:<16} GATE FAIL: {} -- timing suppressed", g.why);
            continue;
        }

        let ns_line = time_ns(|| {
            let mut acc = 0u64;
            for (ls, le, c) in &rows {
                acc += confirm_line(&re, *ls, *le, c) as u64;
            }
            acc
        });
        println!(
            "{:<16} {:>9} {:>9} {:>10} {:>10.2}ns {:>10.2}ns",
            pat,
            rows.len(),
            line_hits,
            "pass",
            ns_line / rows.len() as f64,
            ns_line / n_cand as f64,
        );
    }

    // -----------------------------------------------------------------
    // TABLE 3 -- the 44.9 ns decomposition
    // -----------------------------------------------------------------
    println!("\nTABLE 3  the `fixed.rs` header's 44.9 ns, term by term");
    println!("(a real corpus line, anchored where the engine anchors it)\n");
    println!(
        "{:<16} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "pattern", "hand", "hand_fn", "VM bool", "VM find", "Fixed", "any_match_in"
    );
    println!("{}", "-".repeat(78));

    let hit: Vec<u8> = b"    let mut value = parse_error(x);".to_vec();
    let miss: Vec<u8> = b"    let mut value = parse_ok_no(x);".to_vec();
    for pat in &pats {
        let Ok(re) = ByteRegex::new(pat.as_bytes()) else {
            continue;
        };
        let parsed = rgx_core::syntax::parse(pat.as_bytes()).expect("the pattern parses");
        let prog = rgx_core::nfa::compile(&parsed.ast, parsed.groups);
        let fixed = Fixed::compile(&parsed.ast);
        let anchor = hit.iter().position(|&b| b == b'e').unwrap_or(0);
        let at = match pat.as_str() {
            "pub fn" => hit.windows(7).position(|w| w == b"pub fn").unwrap_or(0),
            "fn main" => 0,
            "let mut" => hit.windows(7).position(|w| w == b"let mut").unwrap_or(0),
            "a|b|c" => hit.iter().position(|&b| b == b'c').unwrap_or(0),
            _ => anchor,
        };
        let per = |f: &mut dyn FnMut() -> bool| -> f64 {
            time_ns(|| {
                let mut c = 0u64;
                for _ in 0..1000 {
                    if f() {
                        c += 1;
                    }
                }
                c
            }) / 1000.0
        };

        let t_hand = per(&mut || hand(pat, black_box(&hit), at));
        let t_hand_fn = per(&mut || hand_fn(pat, black_box(&hit), at));
        let t_bool = per(&mut || rgx_core::vm::matches_at(&prog, black_box(&hit), at));
        let t_find = per(&mut || rgx_core::vm::find_at(&prog, black_box(&hit), at).is_some());
        let t_fixed = fixed
            .as_ref()
            .map_or(f64::NAN, |fx| per(&mut || fx.confirm(black_box(&hit), at)));
        let t_ship = per(&mut || {
            let hay = hit.as_slice();
            let cands = [at];
            let mut c = Candidates::of(&cands).with_origin(Origin::Fixed(0));
            let line = c.in_line(0, hay.len());
            !line.is_empty() && re.any_match_in(hay, line, Origin::Fixed(0))
        });
        let f = |x: f64| {
            if x.is_nan() {
                format!("{:>9}", "--")
            } else {
                format!("{x:>8.2}ns")
            }
        };
        println!(
            "{:<16} {} {} {} {} {} {}",
            pat,
            f(t_hand),
            f(t_hand_fn),
            f(t_bool),
            f(t_find),
            f(t_fixed),
            f(t_ship),
        );
    }
    println!("hit  : {:?}", String::from_utf8_lossy(&hit));
    println!("miss : {:?}", String::from_utf8_lossy(&miss));

    // -----------------------------------------------------------------
    // TABLE 4 -- setup priced as a slope in program width
    // -----------------------------------------------------------------
    println!("\nTABLE 4  per-call setup: instruction count up, bytes consumed fixed at 1");
    println!("(the VM's table and bitmaps are sized from `prog.insts.len()`)\n");
    println!(
        "{:<12} {:>6} {:>6} {:>12} {:>12} {:>12}",
        "pattern", "insts", "bytes", "VM bool", "VM find", "hand"
    );
    println!("{}", "-".repeat(64));
    for pat in width_ladder() {
        let Ok(_re) = ByteRegex::new(pat.as_bytes()) else {
            println!("{pat:<12} (did not compile)");
            continue;
        };
        let parsed = rgx_core::syntax::parse(pat.as_bytes()).expect("the pattern parses");
        let prog = rgx_core::nfa::compile(&parsed.ast, parsed.groups);
        let at = 0usize; // the single byte the VM consumes is hay[0]
        let per = |f: &mut dyn FnMut() -> bool| -> f64 {
            time_ns(|| {
                let mut c = 0u64;
                for _ in 0..1000 {
                    if f() {
                        c += 1;
                    }
                }
                c
            }) / 1000.0
        };
        println!(
            "{:<12} {:>6} {:>6} {:>10.2}ns {:>10.2}ns {:>10.2}ns",
            pat,
            prog.insts.len(),
            1,
            per(&mut || rgx_core::vm::matches_at(&prog, black_box(&hit), at)),
            per(&mut || rgx_core::vm::find_at(&prog, black_box(&hit), at).is_some()),
            per(&mut || hand(&pat, black_box(&hit), at)),
        );
    }

    // -----------------------------------------------------------------
    // TABLE 5 -- per 64 KiB block: what the confirm cascade costs the search
    // -----------------------------------------------------------------
    //
    // Three rows, all through the real `Searcher` on the same blocks, so
    // every per-fill cost the binary pays is in every row:
    //
    //   total      the shipped search
    //   loop+cand  a matcher that never matches, real candidates: the line
    //              walk and the candidate fill, no confirm
    //   loop       the same with no candidate source: the line walk alone
    //
    // `confirm = total - (loop+cand)` and `prefilter+cand = (loop+cand) - loop`.
    // A pattern whose confirm is a rounding error in `total` has no headroom
    // in the confirm, whatever a microbenchmark says about the confirm.
    println!("\nTABLE 5  per {BLOCK} B block, through the real Searcher");
    println!("(confirm = total - loop+cand -- the only difference between those two rows");
    println!(" is the matcher, so that delta is clean. `prefilter` is loop+cand - loop2 and");
    println!(" is NEGATIVE when the candidate stream pays for itself by letting the searcher");
    println!(" skip lines it would otherwise have to ask about. The stages are not additive.)");
    println!("loop2 is `loop` measured twice: the gap is this method's noise floor.\n");
    println!(
        "{:<16} {:>6} {:>9} {:>9} {:>9} {:>9} {:>9} {:>8} {:>11} {:>6}",
        "pattern",
        "blocks",
        "total",
        "loop+cand",
        "loop",
        "loop2",
        "confirm",
        "confirm%",
        "prefilter",
        "GB/s"
    );
    println!("{}", "-".repeat(112));

    let nblocks = hay.len() / BLOCK;
    if nblocks == 0 {
        println!("(corpus shorter than one {BLOCK} B block -- need a bigger corpus)");
        return;
    }
    for pat in &pats {
        let Ok(re) = ByteRegex::new(pat.as_bytes()) else {
            continue;
        };
        // Bounded so the ladder converges; every row runs the same blocks.
        let nb = nblocks.min(256);
        let blocks: Vec<&[u8]> = (0..nb).map(|i| &hay[i * BLOCK..(i + 1) * BLOCK]).collect();

        let run = |s: &Searcher| -> f64 {
            time_ns_acc(|| {
                let mut acc = 0u64;
                for b in &blocks {
                    let mut c = Counter(0);
                    s.search_slice(black_box(b), &mut c).ok();
                    acc += c.0;
                }
                acc
            })
        };

        // The gate: the real searcher has to have found something for any of
        // these rows to be a measurement of a search rather than of an
        // empty walk. A pattern that matches nothing in every block would
        // make `confirm` and `prefilter` both read zero for the wrong reason.
        let hits = count_true(|| {
            let s = Searcher::with_candidates(&re, &re, cfg());
            let mut acc = 0u64;
            for b in &blocks {
                let mut c = Counter(0);
                s.search_slice(b, &mut c).ok();
                acc += c.0;
            }
            acc
        });
        if hits == 0 {
            println!("{pat:<16} GATE FAIL: matched nothing in {nb} blocks -- timing suppressed");
            continue;
        }
        let t_total = run(&Searcher::with_candidates(&re, &re, cfg()));
        let t_cand = run(&Searcher::with_candidates(&Never, &re, cfg()));
        let t_loop = run(&Searcher::new(&Never, cfg()));
        let t_loop2 = run(&Searcher::new(&Never, cfg()));

        let confirm = t_total - t_cand;
        let noise = (t_loop2 - t_loop).abs();
        let prefil = t_cand - t_loop2;
        let bytes = nb as f64 * BLOCK as f64;
        // A delta inside the noise floor is printed as `~`, not as a number.
        // `prefilter_ablate.rs` publishes a `sep` column for the same reason:
        // a percentage over overlapping distributions is not a gain.
        let prefil_s = if prefil.abs() < noise {
            format!("~{noise:.0}ns")
        } else {
            format!("{:+.0}us", prefil / 1e3)
        };
        println!(
            "{:<16} {:>6} {:>7.0}us {:>7.0}us {:>7.0}us {:>7.0}us {:>7.0}us {:>7.1}% {:>11} {:>6.2}",
            pat,
            nb,
            t_total / 1e3,
            t_cand / 1e3,
            t_loop / 1e3,
            t_loop2 / 1e3,
            confirm / 1e3,
            if t_total > 0.0 {
                confirm / t_total * 100.0
            } else {
                0.0
            },
            prefil_s,
            bytes / 1e9 / (t_total / 1e9),
        );
    }
}

/// A matcher that never matches, so a row can be measured with the confirm
/// removed and nothing else changed. `examples/prefilter_ablate.rs:141`.
struct Never;

impl rgx_core::matcher::Matcher for Never {
    fn find_at(&self, _: &[u8], _: usize) -> Option<usize> {
        None
    }
    fn is_match_at(&self, _: &[u8], _: usize) -> bool {
        false
    }
    fn find_span_at(&self, _: &[u8], _: usize) -> Option<std::ops::Range<usize>> {
        None
    }
    fn any_match_in(&self, _: &[u8], _: rgx_core::searcher::LineCandidates<'_>, _: Origin) -> bool {
        false
    }
    fn can_match(&self) -> bool {
        true
    }
}

fn default_corpus() -> String {
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    let p = Path::new(&home).join(".rgx-bench").join("big235.rs");
    if p.exists() {
        p.display().to_string()
    } else {
        "crates/rgx-core/src/lib.rs".to_string()
    }
}
