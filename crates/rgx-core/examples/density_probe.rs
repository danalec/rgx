// SPDX-License-Identifier: Apache-2.0

//! The density estimator, measured against the density.
//!
//! ```text
//! cargo run --release -p rgx-core --example density_probe -- <corpus> [patterns...]
//! ```
//!
//! **What this is for.** `FastLiteral::measure` estimates each anchor's
//! candidate density by counting its hits in a sample of the buffer, and
//! `benchmark/status.md` §4 item 1 records what happens when the sample cannot
//! estimate the density it is asked about: on `e[0-9]` the 8 KiB sample finds
//! ZERO hits for the two-position mask, and the scan's true density over the
//! corpus is 0.024%. A sample that answers "zero" when the answer is "almost
//! none" is not a noisy estimate; it is the wrong question.
//!
//! So this file holds the model still and moves one thing: **which bytes the
//! density is counted over.** For each pattern and each arm of
//! [`rgx_core::regex::Sampling`] it prints, at each buffer the engine actually
//! measured on,
//!
//! | column | what it is |
//! |--------|------------|
//! | `true`  | hits counted over EVERY byte of the corpus |
//! | `est`   | hits the estimator found in the sample |
//! | `x`     | est / expected, where expected is `true` x sampled bytes |
//! | `pick`  | the anchor the model takes at that estimate |
//!
//! and the last two tables answer the two questions that matter: **for how
//! many of the nine does each arm pick the anchor the true density would have
//! picked, and what does each arm cost over the whole file.**
//!
//! **The measurement buffers are the engine's, not a stand-in.** The corpus is
//! driven through the real [`rgx_core::searcher::LineBuffer`] -- 64 KiB reads,
//! the doubling `fill` does, the complete-lines-only window `buffer` returns
//! -- and [`rgx_core::regex::ByteRegex::chosen_anchor`] is called on exactly
//! the slice `FastLiteral::plan` sees, at every fill, so the engine's own
//! state evolves the way it does in a search. Which of those fills were
//! *measurements* is read off [`rgx_core::regex::REPLAN`] and the fill
//! lengths, which is the engine's own rule rather than a copy of it. The run
//! then repeats through a real `Searcher` and checks that both paths left the
//! same anchor chosen, which is the check that the drive was faithful.
//!
//! **Pooling is evaluated too, because it is what ships.** The second
//! measurement does not replace the first, it adds to it, so the number the
//! model acts on at the end of the file is a weighted mean of both. Every arm
//! is scored twice: at the first measurement alone, and pooled over both, and
//! the two columns are not the same.

use std::time::Instant;

use rgx_core::regex::{ByteRegex, Sampling, REPLAN};
use rgx_core::searcher::{
    BinaryDetection, Config, LineBuffer, Searcher, Sink, SinkContext, SinkFinish, SinkMatch,
};

const PATTERNS: &[&str] = &[
    "e",
    "e.",
    "a|b|c",
    "e[0-9]",
    "fn main",
    "pub fn",
    "let mut",
    "foo.*bar",
    "(pub|fn) [a-z]+",
];

const ARMS: &[(Sampling, &str)] = &[
    (Sampling::Spread16, "Spread16 shipped"),
    (Sampling::Spread32, "Spread32"),
    (Sampling::Spread64, "Spread64"),
    (Sampling::Prefix8k, "Prefix8k"),
    (Sampling::TwoScaleMin, "TwoScaleMin"),
    (Sampling::Whole, "Whole fill"),
];

fn alloc_vec(n: usize) -> Vec<f64> {
    vec![0.0; n]
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(corpus) = args.next() else {
        eprintln!("usage: density_probe <corpus-file> [patterns...]");
        eprintln!("       corpus defaults to $HOME/.rgx-bench/big235.rs");
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

    let mut summary = Summary {
        rows: Vec::new(),
        cost_ms: alloc_vec(ARMS.len()),
    };
    for pat in &pats {
        summary.add(pat, &bytes);
    }
    summary.report();
}

/// One pattern's whole answer, accumulated into the cross-pattern tables.
#[derive(Default)]
struct Summary {
    rows: Vec<Row>,
    /// (arm, pattern, seconds this arm costs over the whole corpus), summed.
    cost_ms: Vec<f64>,
}

struct Row {
    pat: String,
    arm: usize,
    /// Whether the argmin at the FIRST measurement is the argmin at the true
    /// density.
    right1: bool,
    /// Whether the argmin pooled over every measurement is the argmin at the
    /// true density.
    right_pooled: bool,
    /// Whether the pattern has more than one anchor and any of them with a
    /// non-zero true density. A pattern with one anchor never samples, and one
    /// whose every true density is zero has nothing to choose on; neither can
    /// be answered wrong by an estimator.
    decidable: bool,
    err1: f64,
    err_pooled: f64,
}

impl Summary {
    fn add(&mut self, pat: &str, hay: &[u8]) {
        let re = match ByteRegex::new(pat.as_bytes()) {
            Ok(r) => r,
            Err(e) => {
                println!("== {pat:?}: does not parse: {e}");
                return;
            }
        };
        let info = re.anchor_info();
        if info.is_empty() {
            println!("== {pat:?}: no prefilter");
            return;
        }
        let n = info.len();

        // ---- the truth ----------------------------------------------------
        let true_hits = re.anchor_hits(hay);
        let true_d: Vec<f64> = true_hits
            .iter()
            .map(|&h| h as f64 / hay.len() as f64)
            .collect();
        let true_rows = re.anchor_costs_sampled(hay, Sampling::Whole);
        let true_pick = info[argmin(&true_rows)].kind.to_string();

        println!(
            "== {pat:?}   confirm price {:.1} ns   {n} anchor(s)",
            re.confirm_price()
        );
        println!(
            "   {:>2}  {:<9} {:<6} {:>13} {:>12}  {:>9}",
            "#", "scan", "known", "true hits", "true d", "cost"
        );
        for i in 0..n {
            let c = &true_rows[i];
            println!(
                "   {:>2}  {:<9} {:<6} {:>13} {:>12.3e}  {:>9.4}  {}",
                i,
                c.info.kind,
                if c.info.known { "yes" } else { "NO" },
                true_hits[i],
                true_d[i],
                c.cost,
                if true_pick == c.info.kind {
                    "<-- argmin at the true density"
                } else {
                    ""
                }
            );
        }

        // ---- the engine's own fills ---------------------------------------
        let fills = real_fills(&re, hay);
        let events = fills.events;
        println!(
            "   -- {} fills; the model measured on {} of them: {}",
            fills.fills,
            events.len(),
            events
                .iter()
                .map(|e| format!("fill {} = {} B", e.fill, e.len))
                .collect::<Vec<_>>()
                .join(", ")
        );
        for e in &events {
            let picked = re.chosen_anchor(&e.bytes).map(|k| k.kind.to_string());
            // **How unrepresentative this fill is**, counted over every one of
            // its bytes rather than over any sample of it. The pooled density
            // the model acts on is a weighted mean of these, so the question
            // the re-measurement raises -- does the density change when the
            // buffer grows -- has a numeric answer here: the ratio of the
            // second fill's density to the file's is how much a mean of the two
            // is dragged, and it is not a property of the estimator at all.
            let here = re.anchor_hits(&e.bytes);
            let shape = (0..n)
                .map(|i| {
                    let d = here[i] as f64 / e.len as f64;
                    format!(
                        "{} {:.2e} = {:>5.1}x the file",
                        info[i].kind,
                        d,
                        if true_d[i] > 0.0 { d / true_d[i] } else { 0.0 }
                    )
                })
                .collect::<Vec<_>>()
                .join("   ");
            println!(
                "      after fill {:>3} ({:>7} B) the engine holds {:<10} | {shape}",
                e.fill,
                e.len,
                picked.unwrap_or_default()
            );
        }
        // The real search, on the same bytes, as the check that the drive above
        // reproduced it.
        let searched = drive_real_search(&re, hay);
        let after = re
            .chosen_anchor(events.last().map(|e| e.bytes.as_slice()).unwrap_or(hay))
            .map(|k| k.kind.to_string())
            .unwrap_or_default();
        println!(
            "   a real Searcher over the same bytes leaves the same anchor: {} ({})",
            if searched == after { "yes" } else { "NO" },
            after
        );
        if searched != after {
            println!("   ** the drive above did not reproduce the search **");
        }
        println!();

        let decidable = n > 1 && true_hits.iter().any(|&h| h > 0);
        if !decidable {
            println!(
                "   {}: nothing to choose on, so no arm of the estimator can be wrong.\n",
                if n > 1 {
                    "every anchor's true density is zero"
                } else {
                    "one anchor only -- `plan` returns it without measuring"
                }
            );
            for ai in 0..ARMS.len() {
                self.rows.push(Row {
                    pat: pat.to_string(),
                    arm: ai,
                    right1: true,
                    right_pooled: true,
                    decidable: false,
                    err1: 0.0,
                    err_pooled: 0.0,
                });
            }
            return;
        }

        // ---- every arm, at every measurement ------------------------------
        // Sampled bytes per arm, from the last event; used only for the error column.
        let mut arm_bytes = vec![0usize; ARMS.len()];
        println!(
            "   {:<18} {:>7}  {:>11} {:>11}  {:>8} {:>8}  pooled density (true in brackets)",
            "arm", "bytes", "pick @1", "pick pooled", "err @1", "err pool"
        );
        for (ai, (how, name)) in ARMS.iter().enumerate() {
            let mut pooled_hits = vec![0usize; n];
            let mut pooled_bytes = 0usize;
            let mut first_err = vec![0.0f64; n];
            let mut first_pick = String::new();

            for (ei, e) in events.iter().enumerate() {
                let rows = re.anchor_hits_sampled(&e.bytes, *how);
                let nb = rows.first().map(|&(_, n)| n).unwrap_or(0);
                arm_bytes[ai] = nb;
                for (i, &(h, _)) in rows.iter().enumerate() {
                    pooled_hits[i] += h;
                    pooled_bytes += nb;
                    if ei == 0 && true_d[i] * (nb as f64) >= 1.0 {
                        first_err[i] = ratio_dev(h as f64, true_d[i] * nb as f64);
                    }
                }
                if ei == 0 {
                    first_pick = info[argmin(&re.anchor_costs_sampled(&e.bytes, *how))]
                        .kind
                        .to_string();
                }
            }

            let pooled_d: Vec<f64> = (0..n)
                .map(|i| {
                    if pooled_bytes > 0 {
                        pooled_hits[i] as f64 / pooled_bytes as f64
                    } else {
                        0.0
                    }
                })
                .collect();
            let pooled_pick = if pooled_bytes > 0 {
                info[argmin(&re.anchor_costs_at(&pooled_d))]
                    .kind
                    .to_string()
            } else {
                first_pick.clone()
            };
            let mut pooled_err = 0.0f64;
            for i in 0..n {
                let expect = true_d[i] * pooled_bytes as f64;
                if expect >= 1.0 {
                    pooled_err = pooled_err.max(ratio_dev(pooled_hits[i] as f64, expect));
                }
            }
            let detail = (0..n)
                .map(|i| format!("{} {:.2e} [{:.2e}]", info[i].kind, pooled_d[i], true_d[i]))
                .collect::<Vec<_>>()
                .join("  ");
            let e1 = first_err.iter().copied().fold(0.0f64, f64::max);
            println!(
                "   {:<18} {:>7}  {:>11} {:>11}  {:>7.0}% {:>7.0}%  {detail}",
                name,
                arm_bytes[ai],
                mark(&first_pick, &true_pick),
                mark(&pooled_pick, &true_pick),
                e1 * 100.0,
                pooled_err * 100.0
            );
            self.rows.push(Row {
                pat: pat.to_string(),
                arm: ai,
                right1: first_pick == true_pick,
                right_pooled: pooled_pick == true_pick,
                decidable: true,
                err1: e1,
                err_pooled: pooled_err,
            });
        }

        // ---- what each arm costs over the whole file ------------------------
        println!();
        println!("   cost of counting one buffer's sample, per event, and over the whole file:");
        for (ai, (how, name)) in ARMS.iter().enumerate() {
            let mut per_event = Vec::new();
            let mut total_us = 0.0;
            for e in &events {
                let nb = re
                    .anchor_hits_sampled(&e.bytes, *how)
                    .first()
                    .map(|&(_, n)| n)
                    .unwrap_or(0);
                let reps = reps_for(nb.max(1));
                let t = Instant::now();
                for _ in 0..reps {
                    std::hint::black_box(re.anchor_hits_sampled(&e.bytes, *how));
                }
                let us = t.elapsed().as_secs_f64() * 1e6 / reps as f64;
                total_us += us;
                per_event.push(format!(
                    "{:.1} us / {} B = {:.3} ns/byte",
                    us,
                    nb,
                    us * 1e3 / nb.max(1) as f64
                ));
            }
            self.cost_ms[ai] += total_us / 1e3;
            println!(
                "   {:<18} {}   ->  {:>8.4} ms over this file",
                name,
                per_event.join("  |  "),
                total_us / 1e3
            );
        }
        println!();
        println!("   the true density's argmin is {true_pick}; the engine holds {after}.");
        println!();
    }

    fn report(&self) {
        println!("== across every pattern");
        println!();
        println!(
            "{:<18} {:>11} {:>14} {:>5} {:>10} {:>10}  cost over the corpus",
            "arm", "right @1", "right pooled", "n/a", "worst @1", "worst pool"
        );
        for (ai, (_, name)) in ARMS.iter().enumerate() {
            let rows: Vec<&Row> = self.rows.iter().filter(|r| r.arm == ai).collect();
            let decid: Vec<&&Row> = rows.iter().filter(|r| r.decidable).collect();
            let right1 = decid.iter().filter(|r| r.right1).count();
            let rightp = decid.iter().filter(|r| r.right_pooled).count();
            let na = rows.len() - decid.len();
            let w1 = decid.iter().map(|r| r.err1).fold(0.0f64, f64::max);
            let wp = decid.iter().map(|r| r.err_pooled).fold(0.0f64, f64::max);
            println!(
                "{name:<18} {right1:>8}/{:>2} {rightp:>10}/{:>2} {na:>5} {:>9.0}% {:>9.0}%  {:>8.3} ms",
                decid.len(),
                decid.len(),
                w1 * 100.0,
                wp * 100.0,
                self.cost_ms[ai]
            );
        }
        println!();
        for (ai, (_, name)) in ARMS.iter().enumerate() {
            let rows: Vec<&Row> = self.rows.iter().filter(|r| r.arm == ai).collect();
            let s: Vec<String> = rows
                .iter()
                .map(|r| {
                    if !r.decidable {
                        format!("{} n/a", r.pat)
                    } else if r.right1 && r.right_pooled {
                        format!("{} ok", r.pat)
                    } else if r.right1 {
                        format!("{} pooled-only", r.pat)
                    } else if r.right_pooled {
                        format!("{} first-only", r.pat)
                    } else {
                        format!("{} WRONG", r.pat)
                    }
                })
                .collect();
            println!("  {name}\n      {}", s.join(" | "));
        }
    }
}

/// The symmetric relative deviation of `est` from `expect`, as a fraction.
/// `est / expect` is the ratio a reader wants; the deviation is what makes
/// 0.008x and 26x comparable in one column, and a deviation below 1 means the
/// ratio column.
fn ratio_dev(est: f64, expect: f64) -> f64 {
    if expect <= 0.0 {
        return 0.0;
    }
    let r = est / expect;
    (r - 1.0).abs() / r.max(1.0)
}

fn mark(pick: &str, truth: &str) -> String {
    if pick == truth {
        pick.to_string()
    } else {
        format!("{pick} <<")
    }
}

fn argmin(rows: &[rgx_core::regex::AnchorCost]) -> usize {
    let mut best = 0usize;
    let mut best_score = f64::INFINITY;
    for (i, r) in rows.iter().enumerate() {
        if r.cost < best_score {
            best_score = r.cost;
            best = i;
        }
    }
    best
}

/// One measurement event.
struct Event {
    fill: usize,
    len: usize,
    bytes: Vec<u8>,
}

struct Fills {
    fills: usize,
    events: Vec<Event>,
}

/// Every fill of the real reader path, and the ones `plan` measures on.
///
/// The ladder is the engine's own rule -- `measure` again once a buffer
/// `REPLAN` times the largest measured one arrives -- read off the fill
/// lengths, and `chosen_anchor` is called on every fill's buffer so the
/// engine's cached verdict evolves exactly as it does in a search.
fn real_fills(re: &ByteRegex, hay: &[u8]) -> Fills {
    let cfg = Config {
        count: true,
        binary: BinaryDetection::None,
        ..Config::default()
    };
    let mut lb = LineBuffer::new(&cfg);
    let mut rest = hay;
    let mut fills = 0usize;
    let mut events: Vec<Event> = Vec::new();
    let mut planned = 0usize;
    let mut fill_from = move |b: &mut [u8]| {
        let n = core::cmp::min(b.len(), rest.len());
        b[..n].copy_from_slice(&rest[..n]);
        rest = &rest[n..];
        Ok(n)
    };
    while lb.fill(&mut fill_from).unwrap_or(false) {
        fills += 1;
        let b = lb.buffer().to_vec();
        let len = b.len();
        if len == 0 {
            break;
        }
        // The engine's own decision on this buffer, which also advances the
        // cached verdict and the pooled evidence.
        let _ = re.chosen_anchor(&b);
        // The first fill is always a measurement: `plan` has nothing cached,
        // so it measures. After that the ladder is `REPLAN` times the largest
        // buffer measured so far, which is the engine's own rule.
        if planned == 0 || len >= planned.saturating_mul(REPLAN) {
            events.push(Event {
                fill: fills,
                len,
                bytes: b,
            });
        }
        planned = planned.max(len);
        lb.consume(len);
    }
    Fills { fills, events }
}

/// A real `Searcher` over the same bytes, for the check that the drive above
/// reproduced the engine's own path. Returns the anchor it ended on.
fn drive_real_search(re: &ByteRegex, hay: &[u8]) -> String {
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
    let cfg = Config {
        count: true,
        binary: BinaryDetection::None,
        ..Config::default()
    };
    let s = Searcher::with_candidates(re, re, cfg.clone());
    let mut c = Counter(0);
    let mut lb = LineBuffer::new(&cfg);
    let mut rest = hay;
    let mut fill_from = move |b: &mut [u8]| {
        let n = core::cmp::min(b.len(), rest.len());
        b[..n].copy_from_slice(&rest[..n]);
        rest = &rest[n..];
        Ok(n)
    };
    let _ = s.search_reader(&mut fill_from, &mut c, &mut lb);
    // A fresh, tiny buffer: it is too small to trigger a re-measurement, so
    // this reads the cached decision the search left behind rather than
    // measuring again.
    re.chosen_anchor(&b"the quick brown fox\n"[..])
        .map(|k| k.kind.to_string())
        .unwrap_or_default()
}

fn reps_for(len: usize) -> u64 {
    // Enough passes that the timer is not mostly clock read.
    ((16 << 20) / len.max(1) as u64).clamp(3, 500)
}
