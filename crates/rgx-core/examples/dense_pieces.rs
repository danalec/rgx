// SPDX-License-Identifier: Apache-2.0

//! Decomposing the in-house engine's time on DENSE input, piece by piece.
//!
//! ```text
//! cargo run --release -p rgx-core --example dense_pieces -- <corpus-file>
//! ```
//!
//! **Why this exists.** `dense_ablate.rs` reports what each *configuration*
//! costs. This file reports what each *piece inside the line loop* costs, by
//! rebuilding `Core::run` with one piece at a time and taking the marginal
//! difference between consecutive rows. The last row of each ladder is the
//! shipped code, measured through the real `Searcher`, so the ladder is
//! anchored: a marginal cost that does not sum to the whole is telling us the
//! replication drifted from what ships.
//!
//! **The ladders.**
//!
//! | ladder | rows |
//! |--------|------|
//! | `PATH`  | slice vs reader, bare vs hybrid -- isolates the two axes the binary adds on top of the engine |
//! | `LINE`  | per-line work, cumulative: line split, candidate stream, confirm, bookkeeping |
//! | `BLOCK` | the same lines resolved from per-block index vectors instead of per-line SIMD calls |
//!
//! **Every row is a MINIMUM of 7 timed rounds after 2 discarded warmups**, the
//! same rule `dense_ablate.rs` uses: a single run on this workload moved by
//! more than 20% before the machine settled.

use std::hint::black_box;
use std::time::Instant;

use rgx_core::regex::ByteRegex;
use rgx_core::searcher::{
    BinaryDetection, Candidates, Config, LineBuffer, Origin, Sink, SinkContext, SinkFinish,
    SinkMatch,
};
use rgx_core::{hybrid::HybridMatcher, matcher::Matcher};

const ROUNDS: usize = 7;
const WARMUP: usize = 2;
const TARGET_MS: f64 = 60.0;
const BLOCK: usize = 64 * 1024;

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

/// A delegate that never matches. What it COSTS is the same either way, which
/// is all a timing row needs; the `matches` column comes from the byte engine.
struct NeverAsks;
impl rgx_core::hybrid::UnicodeMatcher for NeverAsks {
    fn find_span(&self, _: &[u8], _: usize) -> Option<std::ops::Range<usize>> {
        None
    }
}

struct Real(rgx_core::regex::ByteRegex);
impl rgx_core::hybrid::UnicodeMatcher for Real {
    fn find_span(&self, line: &[u8], at: usize) -> Option<std::ops::Range<usize>> {
        use rgx_core::regex::Matcher as _;
        self.0.find_at(line, at).map(|i| i..i)
    }
}

fn delegate(pat: &str) -> Real {
    Real(rgx_core::regex::ByteRegex::new(pat.as_bytes()).expect("in-house compiles the pattern"))
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

fn cfg() -> Config {
    Config {
        count: true,
        binary: BinaryDetection::None,
        ..Config::default()
    }
}

/// A block-at-a-time reader over an in-memory corpus, exactly the shape
/// `search_reader` sees: one `&mut [u8]` filled per call.
fn block_reader(hay: &[u8]) -> impl FnMut(&mut [u8]) -> Result<usize, std::fmt::Error> + '_ {
    let at = std::cell::Cell::new(0usize);
    move |b: &mut [u8]| {
        let a = at.get();
        let n = b.len().min(BLOCK).min(hay.len() - a);
        b[..n].copy_from_slice(&hay[a..a + n]);
        at.set(a + n);
        Ok(n)
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        format!(
            "{}/.rgx-bench/big235.rs",
            std::env::var("USERPROFILE").unwrap_or_default()
        )
    });
    let pats: Vec<String> = args.collect();
    let pats: Vec<String> = if pats.is_empty() {
        [
            "e",
            "pub fn",
            "e[0-9]",
            "a|b|c",
            "e.",
            "foo.*bar",
            "(pub|fn) [a-z]+",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    } else {
        pats
    };

    let data = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}");
        std::process::exit(1);
    });
    let n = data.len();
    let hay = &data[..];
    let lines = rgx_core::memchr::memchr_iter(b'\n', hay).count() as u64;
    let nonascii_blocks = (0..n.div_ceil(BLOCK))
        .filter(|&i| !rgx_core::hybrid::is_ascii(&hay[i * BLOCK..(i + 1) * BLOCK.min(n)]))
        .count();
    let nonascii_lines = {
        let mut c = 0u64;
        let mut s = 0usize;
        while s < hay.len() {
            let e = rgx_core::memchr::memchr(b'\n', &hay[s..]).map_or(hay.len(), |i| s + i);
            if !rgx_core::hybrid::is_ascii(&hay[s..e]) {
                c += 1;
            }
            s = e + 1;
        }
        c
    };

    println!("corpus : {path}");
    println!(
        "buffer : {:.1} MiB, {lines} lines ({:.1} B/line)",
        n as f64 / (1024.0 * 1024.0),
        n as f64 / lines as f64
    );
    println!(
        "unicode: {nonascii_lines} non-ASCII lines, {nonascii_blocks}/{} 64 KiB blocks affected\n",
        n.div_ceil(BLOCK)
    );
    println!("min of {ROUNDS} rounds after {WARMUP} warmups\n");

    let rep = |name: &str, ms: f64| {
        println!(
            "{name:<26} {ms:>9.1} ms  {:>7.2} GB/s  {:>6.1} ns/line",
            n as f64 / 1e9 / (ms / 1e3),
            ms * 1e6 / lines as f64
        );
    };

    // ---- the two floors ------------------------------------------------
    let t = time_ms(|| rgx_core::memchr::memchr_iter(b'\n', black_box(hay)).count() as u64);
    rep("floor: one memchr pass", t);

    // ---- what the bit maps themselves cost to fill ---------------------
    //
    // The dense path pays these two before it walks a single line, so they are
    // a fixed cost against the whole buffer and have to be measured as such
    // rather than inferred from the search around them.
    {
        use rgx_core::scan::{byte_bits, term_bits, BitMap};
        let m = std::cell::RefCell::new(BitMap::new());
        let t = time_ms(|| {
            let mut n = 0u64;
            for blk in black_box(hay).chunks(BLOCK) {
                term_bits(b'\n', blk, &mut m.borrow_mut());
                n += blk.len() as u64;
            }
            n
        });
        rep("bits: term fill", t);
        let t = time_ms(|| {
            let mut n = 0u64;
            for blk in black_box(hay).chunks(BLOCK) {
                byte_bits(&[b'e', 0, 0], 1, blk, &mut m.borrow_mut());
                n += blk.len() as u64;
            }
            n
        });
        rep("bits: byte fill (1)", t);
        let t = time_ms(|| {
            let mut n = 0u64;
            for blk in black_box(hay).chunks(BLOCK) {
                byte_bits(b"abc", 3, blk, &mut m.borrow_mut());
                n += blk.len() as u64;
            }
            n
        });
        rep("bits: byte fill (3)", t);
        // And the walking half: every set bit pulled out, which is what the
        // candidate iterator does once per candidate.
        {
            let m2 = std::cell::RefCell::new(BitMap::new());
            byte_bits(&[b'e', 0, 0], 1, &hay[..BLOCK], &mut m2.borrow_mut());
            let hits = 3usize;
            let t = time_ms(|| {
                let mut acc = 0u64;
                for _ in 0..hits {
                    for blk in black_box(hay).chunks(BLOCK) {
                        byte_bits(&[b'e', 0, 0], 1, blk, &mut m.borrow_mut());
                        let mut at = 0usize;
                        while let Some(i) = m.borrow().next_set(at) {
                            acc = acc.wrapping_add(i as u64);
                            at = i + 1;
                        }
                    }
                }
                acc
            });
            rep("bits: fill + walk all", t);
        }
    }

    for pat in &pats {
        println!("\n=== pattern {pat:?} ===");
        let Ok(re) = ByteRegex::new(pat.as_bytes()) else {
            println!("  (did not compile)");
            continue;
        };
        let c = cfg();
        let pre = if re.has_fast_literal() {
            "lit"
        } else if re.has_prefilter() {
            "ast"
        } else {
            "-"
        };
        println!(
            "  prefilter={pre} fast_candidates_lazy={} anchors={}",
            re.fast_candidates_lazy(hay).is_some(),
            re.anchor_count()
        );

        // ================= LADDER 1: PATH =================
        println!("  -- PATH: what the binary adds over the bare engine --");
        let slice_bare = time_ms(|| {
            let mut sink = Counter::default();
            let s = rgx_core::searcher::Searcher::with_candidates(&re, &re, c.clone());
            s.search_slice(black_box(hay), &mut sink).unwrap();
            sink.lines
        });
        let slice_hyb = time_ms(|| {
            let mut sink = Counter::default();
            let h = HybridMatcher::new(&re, NeverAsks);
            let s = rgx_core::searcher::Searcher::with_candidates(&h, &h, c.clone());
            s.search_slice(black_box(hay), &mut sink).unwrap();
            sink.lines
        });
        let rdr_bare = time_ms(|| {
            let mut sink = Counter::default();
            let s = rgx_core::searcher::Searcher::with_candidates(&re, &re, c.clone());
            let mut lb = LineBuffer::new(&c);
            let mut rdr = block_reader(hay);
            s.search_reader(&mut rdr, &mut sink, &mut lb).unwrap();
            sink.lines
        });
        let rdr_hyb = time_ms(|| {
            let mut sink = Counter::default();
            let h = HybridMatcher::new(&re, NeverAsks);
            let s = rgx_core::searcher::Searcher::with_candidates(&h, &h, c.clone());
            let mut lb = LineBuffer::new(&c);
            let mut rdr = block_reader(hay);
            s.search_reader(&mut rdr, &mut sink, &mut lb).unwrap();
            sink.lines
        });
        let rdr_real = time_ms(|| {
            let mut sink = Counter::default();
            let h = HybridMatcher::new(&re, delegate(pat));
            let s = rgx_core::searcher::Searcher::with_candidates(&h, &h, c.clone());
            let mut lb = LineBuffer::new(&c);
            let mut rdr = block_reader(hay);
            s.search_reader(&mut rdr, &mut sink, &mut lb).unwrap();
            sink.lines
        });
        rep("  slice   bare", slice_bare);
        rep("  slice   hybrid", slice_hyb);
        println!(
            "    {:<22} {:>9.1} ms   <- the hybrid's price on one whole buffer",
            "delta",
            slice_hyb - slice_bare
        );
        rep("  reader  bare", rdr_bare);
        rep("  reader  hybrid", rdr_hyb);
        println!(
            "    {:<22} {:>9.1} ms   <- the 64 KiB rolls' price, bare",
            "delta",
            rdr_bare - slice_bare
        );
        println!(
            "    {:<22} {:>9.1} ms   <- hybrid on 64 KiB blocks",
            "delta",
            rdr_hyb - rdr_bare
        );
        rep("  reader  hybrid+grep", rdr_real);

        // What the BINARY's config adds on top of this one: BOM sniffing (a
        // transcoder per fill) and `BinaryDetection::Quit(0)` (a NUL memchr
        // over every fill). Both are per-fill, so on a 235 MB file they are
        // per-64 KiB costs that the stripped harness config never pays.
        let bcfg = Config::default();
        let rdr_bin = time_ms(|| {
            let mut sink = Counter::default();
            let h = HybridMatcher::new(&re, NeverAsks);
            let s = rgx_core::searcher::Searcher::with_candidates(&h, &h, bcfg.clone());
            let mut lb = LineBuffer::new(&bcfg);
            let mut rdr = block_reader(hay);
            s.search_reader(&mut rdr, &mut sink, &mut lb).unwrap();
            sink.lines
        });
        let nobom = Config {
            bom_sniffing: false,
            ..bcfg.clone()
        };
        let rdr_nobom = time_ms(|| {
            let mut sink = Counter::default();
            let h = HybridMatcher::new(&re, NeverAsks);
            let s = rgx_core::searcher::Searcher::with_candidates(&h, &h, nobom.clone());
            let mut lb = LineBuffer::new(&nobom);
            let mut rdr = block_reader(hay);
            s.search_reader(&mut rdr, &mut sink, &mut lb).unwrap();
            sink.lines
        });
        rep("  reader binary-cfg", rdr_bin);
        println!(
            "    {:<22} {:>9.1} ms   <- BOM sniffing per fill",
            "delta",
            rdr_bin - rdr_nobom
        );

        // ================= LADDER 2: LINE =================
        // The per-line loop, rebuilt with pieces added one at a time. The last
        // row must land on `slice bare` above, or the replication has drifted
        // and the marginals mean nothing.
        println!("  -- LINE: the per-line loop, cumulative --");
        let origin = re
            .fast_candidates_lazy(hay)
            .map_or(Origin::Fixed(0), |c| c.origin());
        let line_cfg = |depth: u32| -> u64 {
            let mut hits = 0u64;
            let mut pos = 0usize;
            let mut stream = re.fast_candidates_lazy(hay);
            // depth bit 0: split lines
            // depth bit 1: build the per-line candidate stream
            // depth bit 2: confirm through `&dyn Matcher`
            // depth bit 3: the match/bookkeeping tail
            let m: &dyn Matcher = &re;
            while pos < hay.len() {
                let line_end = match rgx_core::memchr::memchr(b'\n', &hay[pos..]) {
                    Some(i) => pos + i + 1,
                    None => hay.len(),
                };
                if depth & 1 == 0 {
                    pos = line_end;
                    continue;
                }
                let content_end = if line_end > pos && hay[line_end - 1] == b'\n' {
                    line_end - 1
                } else {
                    line_end
                };
                let is_match = if depth & 2 == 0 {
                    false
                } else {
                    let cands = stream.as_mut().map_or_else(
                        || Candidates::every(content_end).in_line(pos, content_end),
                        |s| s.in_line(pos, content_end),
                    );
                    if depth & 4 == 0 {
                        !cands.is_empty()
                    } else {
                        !cands.is_empty() && m.any_match_in(&hay[pos..content_end], cands, origin)
                    }
                };
                if depth & 8 == 0 {
                    if is_match {
                        hits += 1;
                    }
                } else if is_match != c.invert && is_match {
                    hits += 1;
                }
                pos = line_end;
            }
            hits
        };
        let mut prev = 0.0;
        for (depth, name) in [
            (0u32, "L0 split only"),
            (1, "L1 +match count"),
            (3, "L2 +candidate stream"),
            (7, "L3 +confirm (dyn)"),
            (15, "L4 +bookkeeping"),
        ] {
            let t = time_ms(|| line_cfg(depth));
            let label = format!("  {name}");
            rep(&label, t);
            if depth > 0 {
                println!("    {:<22} {:>9.1} ms", "marginal", t - prev);
            }
            prev = t;
        }
        println!(
            "    {:<22} {:>9.1} ms   <- replication vs shipped slice",
            "check",
            prev - slice_bare
        );

        // ================= LADDER 3: BLOCK =================
        // The same lines resolved from per-BLOCK index vectors: line starts and
        // candidate offsets materialised as `u32` for one 64 KiB block at a
        // time. 8 KB and ~14 KB, so both stay in L1/L2, and the per-line SIMD
        // call disappears -- what is left is an array read.
        println!("  -- BLOCK: per-block u32 indexes instead of per-line SIMD --");
        let block_walk = |depth: u32| -> u64 {
            let mut hits = 0u64;
            let mut starts: Vec<u32> = Vec::new();
            let mut cands: Vec<usize> = Vec::new();
            let m: &dyn Matcher = &re;
            for blk in hay.chunks(BLOCK) {
                starts.clear();
                cands.clear();
                starts.push(0u32);
                for i in rgx_core::memchr::memchr_iter(b'\n', blk) {
                    starts.push(i as u32 + 1);
                }
                if depth >= 2 {
                    // `fast_candidates` materialises with `memchr_iter` over the
                    // WHOLE block -- one resumable SIMD pass, one call per hit
                    // amortised over a large range. Draining the lazy stream
                    // here instead would be a per-candidate `memchr` on a tiny
                    // range, which is the cost under test and not the
                    // alternative to it.
                    re.fast_candidates(blk, &mut cands);
                }
                let mut ci = 0usize;
                for w in starts.windows(2) {
                    let (s, e) = (w[0] as usize, w[1] as usize);
                    let content_end = if e > s && blk[e - 1] == b'\n' {
                        e - 1
                    } else {
                        e
                    };
                    if depth < 2 {
                        hits += 1;
                        continue;
                    }
                    while ci < cands.len() && cands[ci] < s {
                        ci += 1;
                    }
                    let mut k = ci;
                    while k < cands.len() && cands[k] < content_end {
                        k += 1;
                    }
                    if k > ci {
                        let rebased: Vec<usize> = cands[ci..k].iter().map(|&o| o - s).collect();
                        let mut sub = Candidates::of(&rebased).with_origin(origin);
                        if depth >= 3
                            && m.any_match_in(
                                &blk[s..content_end],
                                sub.in_line(0, content_end - s),
                                origin,
                            )
                        {
                            hits += 1;
                        }
                    }
                }
            }
            hits
        };
        let mut prev = 0.0;
        for (d, name) in [
            (1u32, "B1 line index only"),
            (2, "B2 +cand index"),
            (3, "B3 +confirm (dyn)"),
        ] {
            let t = time_ms(|| block_walk(d));
            let label = format!("  {name}");
            rep(&label, t);
            if d > 1 {
                println!("    {:<22} {:>9.1} ms", "marginal", t - prev);
            }
            prev = t;
        }

        // The pieces the hybrid pays per BLOCK, isolated: the whole-buffer
        // ASCII test, and -- when the answer is no -- the per-line walk that
        // `widen_to_non_ascii_lines` does.
        if !re.has_fast_literal() {
            let widen: u64 = {
                let mut out = Vec::new();
                let mut n = 0u64;
                for blk in hay.chunks(BLOCK) {
                    if rgx_core::hybrid::is_ascii(blk) {
                        continue;
                    }
                    n += 1;
                    out.clear();
                    re.fast_candidates(blk, &mut out);
                }
                n
            };
            let t_widen = time_ms(|| {
                let mut out = Vec::new();
                let mut n = 0u64;
                for blk in black_box(hay).chunks(BLOCK) {
                    if rgx_core::hybrid::is_ascii(blk) {
                        continue;
                    }
                    n += 1;
                    out.clear();
                    re.fast_candidates(blk, &mut out);
                }
                n
            });
            rep("  hybrid: non-ascii blocks", t_widen);
            println!("    ({widen} blocks)");
        }
    }
}
