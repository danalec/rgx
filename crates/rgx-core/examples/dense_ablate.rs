// SPDX-License-Identifier: Apache-2.0

//! Where the in-house engine's time goes on DENSE input.
//!
//! ```text
//! cargo run --release -p rgx-core --example dense_ablate -- <corpus-file> [mib]
//! ```
//!
//! **Why this exists.** The in-house engine was measured at 4.8x ripgrep on a
//! pattern that matches nearly every line (`e`) while beating it on a sparse
//! one (`pub fn`). The asymmetry says the cost is per LINE, not per byte and
//! not per match, and this file is what turns that inference into a number per
//! piece: each row switches one piece off or on and the difference is the
//! piece's price.
//!
//! **Method.** One real corpus read into memory, so every row runs over the
//! same bytes in the same process with no I/O in the measurement. Warmup is
//! run and discarded, then 7 timed rounds are taken and the MINIMUM is
//! reported -- the minimum is the round least disturbed by the scheduler,
//! which is the number that describes the code rather than the machine.
//! `black_box` wraps inputs and results so LLVM cannot hoist a row out.
//!
//! **The rows, and what each one is for.**
//!
//! | row | what it isolates |
//! |-----|------------------|
//! | `lines`        | the floor: `memchr` over the buffer counting terminators |
//! | `vm-per-line`  | the Pike VM asked once per line, no searcher around it |
//! | `searcher-1B`  | the searcher + `ByteRegex` on a ONE-byte literal, as shipped |
//! | `searcher-2B`  | the searcher + `ByteRegex` on a two-byte literal (mask prefilter) |
//! | `mask-mat`     | materialising the mask's candidates for the whole buffer |
//! | `memchr-count` | `memchr_iter` over the whole buffer, the ideal dense scan |
//! | `scan` / `confirm` | the two halves of a prefiltered search, per pattern |
//!
//! `lines` and `memchr-count` are the two floors a dense search cannot beat
//! by much. Everything between them is what the engine spends.

use std::hint::black_box;
use std::time::Instant;

use rgx_core::literal::{build_mask, Literal, LiteralSet, MAX_FINGERPRINT};
use rgx_core::regex::ByteRegex;
use rgx_core::searcher::{Config, Sink, SinkContext, SinkFinish, SinkMatch};
use rgx_core::{hybrid::HybridMatcher, scan};

const ROUNDS: usize = 7;
const WARMUP: usize = 2;
const TARGET_MS: f64 = 60.0;

/// The patterns the report must carry, both sides of the prefilter line.
///
/// `e` and `pub fn` already had one; the rest carry a metacharacter and
/// were, until the AST-level extractor landed, the Pike VM once per line.
/// `a|b` is the control that must NOT gain one, and `(pub|fn) [a-z]+` is the
/// nested alternation that no single-branch analysis can reach.
const PATTERNS: &[&str] = &[
    "e",
    "e.",
    "foo.*bar",
    "e[0-9]",
    "a|b",
    "pub fn",
    "(pub|fn) [a-z]+",
    // Three one-byte branches: `memchr3`, or no prefilter at all.
    "a|b|c",
    // A required literal BEHIND a variable-length prefix: the whole-line
    // confirm, and the case that decides whether it is affordable.
    r"\d+em",
    "[a-z]*xyz",
];

/// Counts matching lines. The `-c` shape, which is the one the dense
/// benchmark measures.
#[derive(Default)]
struct Counter {
    lines: u64,
}

impl Sink for Counter {
    type Error = std::convert::Infallible;

    fn matched(&mut self, _: &SinkMatch<'_>) -> Result<bool, Self::Error> {
        self.lines += 1;
        Ok(true)
    }

    fn context(&mut self, _: &SinkContext<'_>) -> Result<bool, Self::Error> {
        Ok(true)
    }

    fn finish(&mut self, _: &SinkFinish<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// `grep`'s own matcher, which is what the binary hands the hybrid for every
/// line the byte engine may not decide.
///
/// A delegate that returns `None` is cheaper than the real one and the
/// difference is not small: a 235 MB Rust corpus has 16,779 non-ASCII lines
/// and the hybrid consults the delegate for each of those that has a
/// A delegate that never matches, standing in for nothing in particular.
///
/// It IS reached: a corpus of Rust source is not all ASCII -- an em dash in
/// a doc comment is enough -- and the hybrid hands every non-ASCII line to
/// the delegate by design. `unreachable!` here was wrong for that reason and
/// the harness caught it by crashing rather than by printing a wrong number.
/// What it costs is the same either way, which is all a timing row needs;
/// the `matches` column comes from the byte engine alone, one row up.
struct NeverAsks;
impl rgx_core::hybrid::UnicodeMatcher for NeverAsks {
    fn find_span(&self, _: &[u8], _: usize) -> Option<std::ops::Range<usize>> {
        None
    }
}

fn time_ms(f: impl Fn() -> u64) -> f64 {
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
        best = best.min(t.elapsed().as_secs_f64() * 1e3 / iters as f64);
    }
    best
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        format!(
            "{}/.rgx-bench/big.rs",
            std::env::var("USERPROFILE").unwrap_or_default()
        )
    });
    let mib: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(256);

    let data = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}\npass a corpus file as the first argument");
        std::process::exit(1);
    });
    let n = (mib * 1024 * 1024).min(data.len());
    let hay = &data[..n];
    let lines = rgx_core::memchr::memchr_iter(b'\n', hay).count() as u64;
    let es = rgx_core::memchr::memchr_iter(b'e', hay).count() as u64;

    println!("corpus : {path}");
    println!(
        "buffer : {:.1} MiB, {lines} lines ({:.1} B/line), {es} `e` ({:.1}% of bytes)",
        hay.len() as f64 / (1024.0 * 1024.0),
        hay.len() as f64 / lines as f64,
        es as f64 / hay.len() as f64 * 100.0
    );
    println!("min of {ROUNDS} timed rounds after {WARMUP} discarded warmup rounds\n");
    println!(
        "{:<16} {:>10} {:>10} {:>10}",
        "row", "ms", "GB/s", "ns/line"
    );

    let report = |name: &str, ms: f64, lines: u64| {
        println!(
            "{name:<16} {ms:>10.1} {:>10.2} {:>10.1}",
            n as f64 / 1e9 / (ms / 1e3),
            ms * 1e6 / lines as f64
        );
    };

    // ---- the floor: split into lines, count them, nothing else -----------
    let t = time_ms(|| rgx_core::memchr::memchr_iter(b'\n', black_box(hay)).count() as u64);
    report("lines", t, lines);

    // ---- the Pike VM, once per line, no searcher ------------------------
    //
    // What `ByteRegex` does for a pattern with no fast literal: the searcher
    // hands it one line's content and it runs `vm::find` over that line.
    let re_1b = ByteRegex::new(b"e").expect("compile e");
    println!(
        "\nByteRegex(\"e\") has_fast_literal = {}, group_count = {}",
        re_1b.has_fast_literal(),
        re_1b.group_count()
    );
    // ---- the searcher over a one-byte literal, exactly as shipped -------
    //
    // A one-byte literal is below `MIN_FINGERPRINT`, so the extractor refuses
    // it and `fast` is `None`. That is the whole ablation: this row runs the
    // Pike VM once per line, and `searcher-2B` below runs the packed mask
    // once per buffer. The difference between them is the cost of the hole.
    let cfg = Config {
        count: true,
        binary: rgx_core::searcher::BinaryDetection::None,
        ..Config::default()
    };
    let t = time_ms(|| {
        let mut sink = Counter::default();
        let s = rgx_core::searcher::Searcher::with_candidates(&re_1b, &re_1b, cfg.clone());
        s.search_slice(black_box(hay), &mut sink).unwrap();
        sink.lines
    });
    report("searcher-1B", t, lines);

    // ---- the same searcher over a two-byte literal (mask prefilter) -----
    let re_2b = ByteRegex::new(b"ee").expect("compile ee");
    println!(
        "ByteRegex(\"ee\") has_fast_literal = {}",
        re_2b.has_fast_literal()
    );
    let t = time_ms(|| {
        let mut sink = Counter::default();
        let s = rgx_core::searcher::Searcher::with_candidates(&re_2b, &re_2b, cfg.clone());
        s.search_slice(black_box(hay), &mut sink).unwrap();
        sink.lines
    });
    report("searcher-2B", t, lines);

    // ---- the same searcher over the sparse pattern, as shipped ---------
    let re_sparse = ByteRegex::new(b"pub fn").expect("compile pub fn");
    let t = time_ms(|| {
        let mut sink = Counter::default();
        let s = rgx_core::searcher::Searcher::with_candidates(&re_sparse, &re_sparse, cfg.clone());
        s.search_slice(black_box(hay), &mut sink).unwrap();
        sink.lines
    });
    report("searcher-sparse", t, lines);

    // ---- the hybrid, which is what the binary actually builds -----------
    let t = time_ms(|| {
        let mut sink = Counter::default();
        let h = HybridMatcher::new(&re_1b, NeverAsks);
        let s = rgx_core::searcher::Searcher::with_candidates(&h, &h, cfg.clone());
        s.search_slice(black_box(hay), &mut sink).unwrap();
        sink.lines
    });
    report("hybrid-1B", t, lines);

    // ---- a pattern with NO prefilter at all: the Pike VM per line ------
    //
    // `e.` has a metacharacter, so the extractor refuses it and there is no
    // fast path of any kind. This is the worst case the engine has, and the
    // row that says whether the no-prefilter hole is still open.
    let re_nopre = ByteRegex::new(b"e.").expect("compile e.");
    println!(
        "ByteRegex(\"e.\") has_fast_literal = {}",
        re_nopre.has_fast_literal()
    );
    let t = time_ms(|| {
        let mut sink = Counter::default();
        let s = rgx_core::searcher::Searcher::with_candidates(&re_nopre, &re_nopre, cfg.clone());
        s.search_slice(black_box(hay), &mut sink).unwrap();
        sink.lines
    });
    report("searcher-nopre", t, lines);

    // ---- the pattern table: prefilter-bearing and prefilter-free ------
    //
    // The rows above isolate pieces; this one is the report. The risk of an
    // AST-level extractor is not that it fails to help the patterns that had
    // no prefilter -- it is that it changes what happens to the ones that
    // already had one, so the table carries BOTH sides: the literal patterns
    // that were already fast and the metacharacter ones that were not.
    println!(
        "\n{:<16} {:>5} {:>9} {:>9} {:>9} {:>9} {:>10}",
        "pattern", "pre", "ms", "GB/s", "ns/line", "hyb ms", "matches"
    );
    for pat in PATTERNS {
        let Ok(re) = ByteRegex::new(pat.as_bytes()) else {
            println!("{pat:<16}  (did not compile)");
            continue;
        };
        let t = time_ms(|| {
            let mut sink = Counter::default();
            let s = rgx_core::searcher::Searcher::with_candidates(&re, &re, cfg.clone());
            s.search_slice(black_box(hay), &mut sink).unwrap();
            sink.lines
        });
        // The same search through the HYBRID, which is what the binary
        // builds: it adds the per-buffer ASCII test and the widening pass, so
        // a difference between this column and the one beside it is a
        // difference in the hybrid and not in the engine.
        let th = time_ms(|| {
            let mut sink = Counter::default();
            let h = HybridMatcher::new(&re, NeverAsks);
            let s = rgx_core::searcher::Searcher::with_candidates(&h, &h, cfg.clone());
            s.search_slice(black_box(hay), &mut sink).unwrap();
            sink.lines
        });
        // And the READER path, fed in 64 KiB chunks, which is what a file
        // larger than `BUFFER_PATH_MAX` actually takes. This column exists
        // because the two above both hand the searcher the whole buffer at
        // once, and the reader path asks for candidates once per FILL — so a
        // per-fill cost that is invisible above is charged 3,670 times here
        // on a 235 MB file. It is the column that caught the anchor
        // measurement being re-run on every one of them.
        //
        // The previous third column ran the search with a `RealDelegate`
        // that wrapped a `grep-regex::RegexMatcher`. The grep-* deps
        // are gone; the in-house engine IS the comparison. The column
        // is the same data the hybrid above measures, with the
        // delegate explicitly returning `None` (the `NeverAsks` case).
        let tgrep = th;
        let tr = time_ms(|| {
            let mut sink = Counter::default();
            let h = HybridMatcher::new(&re, NeverAsks);
            let s = rgx_core::searcher::Searcher::with_candidates(&h, &h, cfg.clone());
            let mut lb = rgx_core::searcher::LineBuffer::new(&cfg);
            let mut at = 0usize;
            let mut read = |b: &mut [u8]| -> Result<usize, std::fmt::Error> {
                let n = b.len().min(64 * 1024).min(hay.len() - at);
                b[..n].copy_from_slice(&hay[at..at + n]);
                at += n;
                Ok(n)
            };
            s.search_reader(&mut read, &mut sink, &mut lb).unwrap();
            sink.lines
        });
        // `-c` counts inside the searcher and never reaches a sink, so the
        // count the timing rows above produce is always zero. One untimed
        // pass with line output on is what turns the column into the number
        // that can be checked against ripgrep's.
        let line_cfg = rgx_core::searcher::Config {
            count: false,
            ..cfg.clone()
        };
        let found = {
            let mut sink = Counter::default();
            let s = rgx_core::searcher::Searcher::with_candidates(&re, &re, line_cfg);
            s.search_slice(black_box(hay), &mut sink).unwrap();
            sink.lines
        };
        let pre = if re.has_fast_literal() {
            "lit"
        } else if re.has_prefilter() {
            "ast"
        } else {
            "-"
        };
        println!(
            "{pat:<16} {pre:>5} {t:>9.1} {:>9.2} {:>9.1} {th:>9.1} {tgrep:>9.1} {tr:>9.1} {found:>10}",
            n as f64 / 1e9 / (t / 1e3),
            t * 1e6 / lines as f64,
        );
    }

    // ---- materialising the mask's candidates for the whole buffer ------
    let set = LiteralSet::exact(vec![Literal::new(b"ee")]);
    let mask = build_mask(&set, MAX_FINGERPRINT).expect("mask");
    let t = time_ms(|| {
        let scratch = scan::candidates(&mask, black_box(hay));
        scratch.len() as u64
    });
    println!(
        "{:<16} {:>10.1} {:>10.2} {:>10.1}   (allocates the candidate vector)",
        "mask-mat",
        t,
        n as f64 / 1e9 / (t / 1e3),
        t * 1e6 / lines as f64
    );

    // ---- the ideal dense scan ------------------------------------------
    let t = time_ms(|| rgx_core::memchr::memchr_iter(b'e', black_box(hay)).count() as u64);
    report("memchr-count", t, lines);

    // ---- the two halves of a prefiltered search ------------------------
    //
    // The pattern table above says WHAT a pattern costs. This says WHY, in the
    // two units a prefilter actually has: how long the scan for candidates
    // takes, and how long confirming them takes. The difference between the
    // two is the per-LINE floor every pattern pays whatever its prefilter, so
    // the three numbers together say whether a pattern is slow because its
    // prefilter is unselective or because its confirm is expensive -- which
    // are opposite fixes.
    //
    // `confirm` is measured the way the searcher measures it: line by line,
    // anchored at `candidate - at`, with the program compiled here rather
    // than borrowed out of the engine, so the number is the confirm and not
    // the searcher around it.
    println!(
        "\n{:<16} {:>10} {:>9} {:>10} {:>9} {:>9}",
        "pattern", "scan ms", "cands", "ns/cand", "confirm ms", "line floor"
    );
    for pat in PATTERNS {
        let Ok(re) = ByteRegex::new(pat.as_bytes()) else {
            continue;
        };
        let mut cands: Vec<usize> = Vec::new();
        let t_scan = time_ms(|| {
            let mut v: Vec<usize> = Vec::new();
            re.fast_candidates(black_box(hay), &mut v);
            v.len() as u64
        });
        re.fast_candidates(hay, &mut cands);
        let n_cand = cands.len() as f64;

        // The offset the candidates must be reduced by, from the same
        // analysis the engine builds its prefilter from.
        let parsed = rgx_core::syntax::parse(pat.as_bytes()).expect("parse");
        let prog = rgx_core::nfa::compile(&parsed.ast, parsed.groups);
        let at = match rgx_core::required::required(&parsed.ast) {
            rgx_core::required::Prefilter::One(r) => r.at,
            rgx_core::required::Prefilter::Alt(a) => a.at,
            rgx_core::required::Prefilter::None => 0,
        };
        let exact = re.has_fast_literal();
        let bounds: Vec<(usize, usize)> = rgx_core::memchr::memchr_iter(b'\n', hay)
            .map(|i| (prev_line_start(hay, i), i))
            .collect();
        let t_confirm = time_ms(|| {
            let mut hits = 0u64;
            let mut ci = 0usize;
            for &(s, e) in black_box(&bounds) {
                let line = &hay[s..e];
                // A cursor, not a filter over the whole vector: the searcher
                // walks the candidates once too, and a filter here would make
                // this row `lines x candidates` and measure nothing else.
                while ci < cands.len() && cands[ci] < s {
                    ci += 1;
                }
                let mut k = ci;
                while k < cands.len() && cands[k] < e {
                    let p = cands[k];
                    k += 1;
                    if exact {
                        hits += u64::from(line.get(p - s).is_some());
                    } else if let Some(x) = p.checked_sub(at + s) {
                        if rgx_core::vm::find_at(&prog, line, x).is_some() {
                            hits += 1;
                        }
                    }
                }
            }
            hits
        });
        // What is left of the shipped time once the scan and the confirm are
        // paid: the per-line walk, which no prefilter can remove.
        let shipped = time_ms(|| {
            let mut sink = Counter::default();
            let s = rgx_core::searcher::Searcher::with_candidates(&re, &re, cfg.clone());
            s.search_slice(black_box(hay), &mut sink).unwrap();
            sink.lines
        });
        let floor = shipped - t_scan - t_confirm;
        println!(
            "{pat:<16} {t_scan:>10.1} {n_cand:>9.0} {:>9.1} {t_confirm:>10.1} {floor:>9.1} (ship {shipped:.1})",
            if n_cand > 0.0 {
                t_confirm * 1e6 / n_cand
            } else {
                0.0
            },
        );
    }
}

/// The start of the line that ends at `nl`, i.e. the byte after the previous
/// terminator. A candidate at `s..e` is inside the line iff `s <= p < e`.
fn prev_line_start(hay: &[u8], nl: usize) -> usize {
    if nl == 0 {
        return 0;
    }
    rgx_core::memchr::memrchr(b'\n', &hay[..nl - 1]).map_or(0, |i| i + 1)
}
