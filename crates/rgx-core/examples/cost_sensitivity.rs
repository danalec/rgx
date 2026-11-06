// SPDX-License-Identifier: Apache-2.0

//! The cost model's arithmetic, on the real corpus, with the prices taken apart.
//!
//! ```text
//! cargo run --release -p rgx-core --example cost_sensitivity -- <corpus> [patterns...]
//! ```
//!
//! **What this is for.** `benchmark/status.md` §4 item 1 says the confirm cost
//! model is wrong about `e.` by 12x in one direction and about
//! `(pub|fn) [a-z]+` by 9x in the other, and that both errors live in the same
//! function. This file measures that function: what each pattern's anchors
//! are, what the model scored them at, where the crossover between any two of
//! them sits in ns of confirm price, and what a candidate of each pattern
//! actually costs to confirm by each of the three engines that could do it.
//!
//! **The number this file exists to produce** is the crossover column. Two
//! anchors `A` and `B` with densities `dA`, `dB` and scan prices `nA`, `nB`
//! cost
//!
//! ```text
//!   cost_i(p) = n_i + d_i * p + d_i * m_i
//! ```
//!
//! so they swap at exactly one price,
//!
//! ```text
//!   p* = (nA - nB + dA*mA - dB*mB) / (dB - dA)
//! ```
//!
//! and `p*` is where the model changes its mind. Everything else here is
//! context for reading it: the densities it is built from, and the measured
//! cost of a confirm to check the price against.
//!
//! **Why the prices are swept here and not in the source.** `CONFIRM_NS` is a
//! `const` in `regex.rs`, and a constant cannot be swept. This file therefore
//! re-implements `Anchor::cost` -- four lines, and checked against
//! `ByteRegex::anchor_costs` below, which reports what the real `cost` returned
//! at the real price -- and varies only the price argument. Anything the sweep
//! says about the model is a statement about the model; only the `MEASURED`
//! rows are statements about the machine, and they are timed over the
//! candidate stream the real searcher builds, in this process, on these bytes.
//!
//! **The confirm rows are timed over candidates, not over a buffer.** A
//! confirm's cost is a per-candidate cost, so it is only meaningful against
//! the number of candidates the chosen anchor actually admits -- and the
//! `cands` column is that number, counted, not estimated.

use std::time::Instant;

use rgx_core::fixed::Fixed;
use rgx_core::nfa;
use rgx_core::regex::ByteRegex;
use rgx_core::scan::{BitMap, MatchMask};
use rgx_core::syntax;

const PATTERNS: &[&str] = &[
    "e",
    "fn main",
    "pub fn",
    "let mut",
    "e.",
    "a|b|c",
    "e[0-9]",
    "foo.*bar",
    "(pub|fn) [a-z]+",
];

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(corpus) = args.next() else {
        eprintln!("usage: cost_sensitivity <corpus-file> [patterns...]");
        eprintln!("       corpus defaults to $HOME/.rgx-bench/big235.rs");
        eprintln!("       patterns default to the nine of benchmark/status.md §2.1");
        std::process::exit(2);
    };
    let pats: Vec<String> = args.collect();
    let pats: Vec<&str> = if pats.is_empty() {
        PATTERNS.to_vec()
    } else {
        pats.iter().map(|s| s.as_str()).collect()
    };

    let bytes = match std::fs::read(&corpus) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {corpus}: {e}");
            std::process::exit(2);
        }
    };
    println!("corpus: {corpus} ({} bytes)", bytes.len());
    println!();

    if std::env::var_os("RGX_CHOSEN").is_some() {
        for pat in &pats {
            chosen_at_runtime(pat, &bytes);
        }
        return;
    }

    for pat in &pats {
        report(pat, &bytes);
    }
}

/// **What the running engine decided**, which is not what the model says.
///
/// `FastLiteral::plan` caches its verdict in two atomics on the compiled
/// pattern, so the decision can be read back after a real search by asking
/// about the SAME 64 KiB buffer it measured on. This runs the reader path
/// `src/main.rs` runs -- 64 KiB fills, `search_reader` -- and then reports the
/// anchor the engine actually used next to the one `anchor_costs` scores
/// lowest. A disagreement between the two is the model being wrong; a
/// disagreement between either of them and the wall clock is something else
/// entirely.
fn chosen_at_runtime(pat: &str, hay: &[u8]) {
    use rgx_core::searcher::{
        BinaryDetection, Config, LineBuffer, Searcher, Sink, SinkContext, SinkFinish, SinkMatch,
    };

    struct Counter(u64);
    impl Sink for Counter {
        type Error = core::convert::Infallible;
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

    let re = ByteRegex::new(pat.as_bytes()).expect("parses");
    const FILL: usize = 64 * 1024;
    let cfg = || Config {
        count: true,
        binary: BinaryDetection::None,
        ..Config::default()
    };
    let s = Searcher::with_candidates(&re, &re, cfg());
    let mut c = Counter(0);
    let mut lb = LineBuffer::new(&cfg());
    let mut rest = hay;
    let mut fill_from = move |b: &mut [u8]| {
        let n = core::cmp::min(b.len(), rest.len());
        b[..n].copy_from_slice(&rest[..n]);
        rest = &rest[n..];
        Ok(n)
    };
    s.search_reader(&mut fill_from, &mut c, &mut lb).ok();
    let chosen = re.chosen_anchor(&hay[..FILL.min(hay.len())]);
    let chosen_is = chosen.as_ref().and_then(|k| {
        re.anchor_info()
            .iter()
            .position(|c| c.kind == k.kind && c.at == k.at)
    });
    println!(
        "{:<18} price {:>6.1} ns | runtime anchor: {:<10} (index {:?}) | lines {}",
        pat,
        re.confirm_price(),
        chosen.as_ref().map(|k| k.kind).unwrap_or("none"),
        chosen_is,
        c.0,
    );
    // Which buffer would the model have to have measured to reach THAT
    // verdict? `plan` measures once, on the first buffer it is handed, so the
    // density it used is one prefix of this file -- and which prefix is the
    // difference between the model being wrong and this probe looking at the
    // wrong bytes.
    for &n in &[4096usize, 16384, 32768, 49152, 65536, 131072, 262144] {
        if n > hay.len() {
            break;
        }
        let costs = re.anchor_costs(&hay[..n]);
        let argmin = costs
            .iter()
            .enumerate()
            .min_by(|a, b| a.1.cost.total_cmp(&b.1.cost))
            .map(|(i, _)| i)
            .unwrap_or(0);
        let detail = costs
            .iter()
            .map(|c| format!("{} d={:.3e} c={:.5}", c.info.kind, c.density, c.cost))
            .collect::<Vec<_>>()
            .join(" | ");
        println!(
            "    prefix {n:>7}: argmin index {argmin} ({})   {detail}",
            costs[argmin].info.kind
        );
    }
}

fn report(pat: &str, hay: &[u8]) {
    let re = match ByteRegex::new(pat.as_bytes()) {
        Ok(r) => r,
        Err(e) => {
            println!("== {pat:?}: does not parse: {e}");
            return;
        }
    };
    let parsed = syntax::parse(pat.as_bytes()).expect("parsed above");
    let prog = nfa::compile(&parsed.ast, parsed.groups);
    let fixed = Fixed::compile(&parsed.ast);
    let mask = mask_of(&parsed.ast);

    let costs = re.anchor_costs(hay);
    if costs.is_empty() {
        println!("== {pat:?}: no prefilter");
        return;
    }
    let chosen = re.chosen_anchor(hay);

    println!(
        "== {pat:?}   confirm price in the model: {:.1} ns",
        re.confirm_price()
    );
    println!(
        "   {:>2}  {:<9} {:<6} {:>11} {:>9} {:>8} {:>8} {:>10} {:>5}",
        "#", "scan", "known", "density", "ns/byte", "confirm", "material", "cost ns/B", ""
    );
    for (i, c) in costs.iter().enumerate() {
        let is_chosen = chosen
            .as_ref()
            .is_some_and(|k| k.kind == c.info.kind && k.at == c.info.at && k.known == c.info.known);
        println!(
            "   {:>2}  {:<9} {:<6} {:>11.6} {:>9.4} {:>8.1} {:>8.1} {:>10.4} {:>5}",
            i,
            c.info.kind,
            if c.info.known { "yes" } else { "NO" },
            c.density,
            c.ns_per_byte,
            c.confirm_ns,
            c.materialise_ns,
            c.cost,
            if is_chosen { "<--" } else { "" }
        );
    }

    // The crossover price between every pair, and in which direction.
    if costs.len() > 1 {
        println!("   crossover: the confirm price P at which each pair of anchors swaps");
        println!("     (P is the PATTERN's confirm price; a match mask is charged MASK_CONFIRM_NS regardless of P,");
        println!("      so its row has slope 0 and a line through it is parallel to the P axis)");
        for i in 0..costs.len() {
            for j in (i + 1)..costs.len() {
                let (a, b) = (&costs[i], &costs[j]);
                // cost_i(P) = n_i + d_i * (P or MASK_CONFIRM_NS) + d_i * m_i
                let (na, nb) = (
                    a.ns_per_byte + a.density * a.materialise_ns,
                    b.ns_per_byte + b.density * b.materialise_ns,
                );
                // By SCAN, not by price: see `pick` below for why the two
                // are not the same test once `CONFIRM_NS` and
                // `MASK_CONFIRM_NS` are both 8.0.
                let slope_a = if is_self_priced(a) { 0.0 } else { a.density };
                let slope_b = if is_self_priced(b) { 0.0 } else { b.density };
                let (ca, cb) = (na + a.density * a.confirm_ns, nb + b.density * b.confirm_ns);
                let (sa, sb) = (slope_a, slope_b);
                // Only the SLOPE difference moves the breakpoint: where the two
                // costs cross is `p* + (cb - ca) / (sa - sb)`, and the
                // intercepts are already in hand as `ca` and `cb`. The
                // intercept difference was destructured here and never read.
                let da = sa - sb;
                let label = format!("{:<9} vs {:<9}", a.info.kind, b.info.kind);
                if da.abs() < 1e-15 {
                    println!(
                        "     {label}  parallel: {:<9} is cheaper at every P",
                        if cb < ca { b.info.kind } else { a.info.kind }
                    );
                    continue;
                }
                let p = re.confirm_price() + (cb - ca) / da;
                // Above p*, cost_a rises relative to cost_b, so b wins.
                let winner = if da > 0.0 { b.info.kind } else { a.info.kind };
                let mark = if (p - re.confirm_price()).abs() < 1.0 {
                    "   <== THE SHIPPED PRICE IS ON THIS LINE"
                } else {
                    ""
                };
                println!(
                    "     {label}  p* = {:>9.2} ns   winner above p*: {}  (a={ca:.4} b={cb:.4} at P={:.1}){mark}",
                    p,
                    winner,
                    re.confirm_price()
                );
            }
        }
        // And the single number the reader wants: over what range of P does
        // this pattern's CHOSEN anchor change at all?
        let mut flips: Vec<(f64, String)> = Vec::new();
        let step = 0.25;
        let mut p = 0.0;
        let mut last = pick(&costs, p);
        while p <= 400.0 {
            let w = pick(&costs, p);
            if w != last {
                flips.push((p, format!("{last} -> {w}")));
                last = w;
            }
            p += step;
        }
        if flips.is_empty() {
            println!("   sweep: the chosen anchor is {last} for EVERY P in 0..=400 ns -- the price cannot move it");
        } else {
            let mut v = vec![format!("{:?} at P=0", pick(&costs, 0.0))];
            for (q, s) in &flips {
                v.push(format!("{s} at P={q:.2}"));
            }
            println!("   sweep: {}", v.join(" | "));
        }
    }
    println!();

    // **The first FILL, which is what the model actually sees.**
    //
    // `FastLiteral::plan` measures on the first buffer it is handed and
    // remembers the verdict, and on the reader path that buffer is 64 KiB --
    // not the corpus. `sample_chunks` spreads its 16 windows over whatever it
    // is given, so the densities the model compares are the densities of ONE
    // 64 KiB window of the file, which is a different number from the
    // density of the file. Both are printed, because which one the decision
    // used is the difference between the model being wrong and the model
    // being measured on something else.
    const FILL: usize = 64 * 1024;
    let fill = &hay[..hay.len().min(FILL)];
    let fc = re.anchor_costs(fill);
    println!("   -- the first {FILL} bytes, which is the buffer `plan` measures on --");
    println!(
        "   {:>2}  {:<9} {:>11} {:>9} {:>10} {:>5}",
        "#", "scan", "density", "ns/byte", "cost ns/B", ""
    );
    for (i, c) in fc.iter().enumerate() {
        let is_chosen = costs
            .iter()
            .position(|k| k.info.kind == c.info.kind)
            .is_some_and(|k| k == i);
        println!(
            "   {:>2}  {:<9} {:>11.6} {:>9.4} {:>10.4} {:>5}",
            i, c.info.kind, c.density, c.ns_per_byte, c.cost, ""
        );
        let _ = is_chosen;
    }

    measure_confirms(pat, hay, &re, &prog, fixed.as_ref(), mask.as_ref());
    println!();
}

/// The candidate stream the real searcher builds, and what a confirm of each
/// engine actually costs over it.
fn measure_confirms(
    _pat: &str,
    hay: &[u8],
    re: &ByteRegex,
    prog: &nfa::Program,
    fixed: Option<&Fixed>,
    mask: Option<&MatchMask>,
) {
    // Over a bounded prefix: 64 MiB is 64x the real fill and 5% of the corpus,
    // and the per-candidate prices below are per-candidate so they converge
    // long before the whole 235 MB has been walked.
    const CAP: usize = 64 << 20;
    let hay = &hay[..hay.len().min(CAP)];

    let mut cands: Vec<usize> = Vec::new();
    re.fast_candidates(hay, &mut cands);
    let n = cands.len();
    if n == 0 {
        println!("   MEASURED  no candidates in the first {CAP} bytes");
        return;
    }
    let iters = (4_000_000 / n).clamp(1, 64);
    println!(
        "   MEASURED  {n} candidates over {} bytes, {iters} passes, min of 3",
        hay.len()
    );

    let best3 = |run: &mut dyn FnMut() -> usize| -> (f64, usize) {
        let mut best = f64::INFINITY;
        let mut hits = 0usize;
        for _ in 0..3 {
            let t = Instant::now();
            let mut acc = 0usize;
            for _ in 0..iters {
                acc = run();
            }
            black_box(acc);
            let ns = t.elapsed().as_nanos() as f64 / (iters * n) as f64;
            if ns < best {
                best = ns;
            }
            hits = acc;
        }
        (best, hits)
    };

    // The VM: what `verify` runs when `fixed` declines.
    let (vm_ns, vm_hits) = best3(&mut || {
        let mut acc = 0usize;
        for &c in &cands {
            acc += rgx_core::vm::matches_at(prog, hay, c) as usize;
        }
        acc
    });
    println!("     Pike VM confirm            {vm_ns:>8.2} ns   {vm_hits} true");

    // `fixed`, when the pattern is one it specialises.
    match fixed {
        Some(fx) => {
            let len = fx.len();
            let (fx_ns, fx_hits) = best3(&mut || {
                let mut acc = 0usize;
                for &c in &cands {
                    acc += fx.confirm(hay, c) as usize;
                }
                acc
            });
            let agree = fx_hits == vm_hits;
            println!(
                "     fixed::Fixed (len {len})      {fx_ns:>8.2} ns   {fx_hits} true  {}",
                if agree {
                    "agrees with the VM"
                } else {
                    "*** DISAGREES ***"
                }
            );
        }
        None => println!("     fixed::Fixed                 declined"),
    }

    // The match mask's own confirm: the same AND, over the same bytes, at one
    // candidate offset.
    match mask {
        Some(m) => {
            let (mk_ns, mk_hits) = best3(&mut || {
                let mut acc = 0usize;
                for &c in &cands {
                    acc += m.holds(hay, c) as usize;
                }
                acc
            });
            let agree = mk_hits == vm_hits;
            println!(
                "     MatchMask::holds (w {})     {mk_ns:>8.2} ns   {mk_hits} true  {}",
                m.width(),
                if agree {
                    "agrees with the VM"
                } else {
                    "*** DISAGREES ***"
                }
            );
        }
        None => println!("     MatchMask                    none"),
    }
}

/// The match mask this pattern would get as an anchor, if it has one.
fn mask_of(ast: &syntax::Ast) -> Option<MatchMask> {
    let plan = rgx_core::required::match_mask(ast)?;
    if !plan.decides {
        return None;
    }
    let branches: Vec<rgx_core::scan::MaskBranch> = plan
        .branches
        .iter()
        .map(|b| rgx_core::scan::MaskBranch {
            terms: b
                .iter()
                .map(|s| rgx_core::scan::MaskTerm {
                    class: s.class,
                    shift: s.at,
                })
                .collect::<Vec<rgx_core::scan::MaskTerm>>(),
        })
        .collect();
    MatchMask::new(branches, plan.decides)
}

fn black_box(x: usize) {
    std::hint::black_box(x);
}

/// Whether this anchor carries its OWN confirm price rather than the
/// pattern's -- a match mask, which `Anchor::effective_confirm` charges
/// `MASK_CONFIRM_NS` whatever the pattern's price is.
///
/// **By SCAN and never by price.** `CONFIRM_NS` and `MASK_CONFIRM_NS` are both
/// 8.0, so "is this row's price different from the pattern's?" answers no
/// for every anchor, and a caller that asks it that way sweeps a match
/// mask's confirm with a number it is not charged -- a different model from
/// the one the engine runs, reached by a comparison that looks right.
fn is_self_priced(c: &rgx_core::regex::AnchorCost) -> bool {
    matches!(c.info.kind, "matchmask" | "premask")
}

/// The anchor [`FastLiteral::plan`] would pick at confirm price `p`.
///
/// `Anchor::cost` is `scan + density * confirm + density * materialise`, and
/// the only thing a caller may vary is `confirm`, so this is the whole of the
/// model with its price argument exposed. An anchor that carries its OWN price
/// -- a match mask, at `MASK_CONFIRM_NS` -- keeps it; every other anchor is
/// charged `p`.
///
/// The swept cost is `cost` with its own price term replaced and NOT `cost`
/// recomputed from the terms, because `Anchor::cost` short-circuits a
/// one-byte deciding mask to its scan rate and an unknown-origin anchor to a
/// flat penalty; re-deriving the arithmetic drops both and orders the
/// anchors differently from the engine.
fn pick(costs: &[rgx_core::regex::AnchorCost], p: f64) -> String {
    let mut best = 0usize;
    let mut best_score = f64::INFINITY;
    for (i, c) in costs.iter().enumerate() {
        let score = if is_self_priced(c) {
            c.cost
        } else {
            c.cost - c.density * c.confirm_ns + c.density * p
        };
        if score < best_score {
            best_score = score;
            best = i;
        }
    }
    costs[best].info.kind.to_string()
}

#[allow(dead_code)]
fn unused_bitmap() -> BitMap {
    BitMap::new()
}
