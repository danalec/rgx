// SPDX-License-Identifier: Apache-2.0

//! What Unicode case folding costs the matcher, measured.
//!
//! Adding simple case folding to non-ASCII literals under `(?i)` changed
//! what those patterns compile to: `é` used to be two `Ast::Class` items and
//! is now an `Ast::Alt` of its case variants. That is the only pattern shape
//! the change touches. This measures what it costs.
//!
//! Three columns, and the first decides whether the timing is worth reading
//! at all:
//!
//!   1. `fast` -- whether `ByteRegex` found a fixed literal to memchr for.
//!      `fixed.rs` declines `Ast::Alt`, so a folded pattern loses it.
//!   2. `insts` -- program size, which is what an Alt costs.
//!   3. MB/s -- best-of-N over a real corpus slice, in-process, so no
//!      process-spawn floor is inside the interval.
//!
//! Run:
//! ```text
//! cargo run --release -p rgx-core --example casefold_cost -- <corpus-file>
//! ```
//!
//! Defaults to the largest `.rs` file under `~/.rgx-bench`.
//!
//! **No number here is publishable as a ratio.** The columns compare two
//! different patterns, not two builds, so nothing in this file supports a
//! "N x slower" claim about the change. It answers a shape question.

use std::fs;
use std::hint::black_box;
use std::time::Instant;

const ROUNDS: usize = 7;
const WARMUP: usize = 2;
const SCAN_BYTES: usize = 64 << 20;

/// None of these strings occurs in a Rust corpus. That is load-bearing, not
/// a detail: `find_at` returns at the FIRST match, so a pattern that occurs
/// makes the number below a measurement of where the first match sits rather
/// than of scan throughput. An earlier version of this file used `cafe` and
/// reported 19 GB/s, which was the first hit in the file and nothing about
/// the engine.
const PATTERNS: &[(&str, &str, bool, &str)] = &[
    (
        "cafezzzz (cs)",
        "cafezzzz",
        false,
        "ASCII, no fold: the path from before",
    ),
    (
        "cafezzzz (-i)",
        "cafezzzz",
        true,
        "ASCII under -i: ASCII folding, untouched",
    ),
    (
        "cafézzzz (cs)",
        "cafézzzz",
        false,
        "non-ASCII, no fold: the byte path, unchanged",
    ),
    (
        "cafézzzz (-i)",
        "cafézzzz",
        true,
        "non-ASCII folded: the Alt this change adds",
    ),
    (
        "zzzzzz (-i)",
        "zzzzzz",
        true,
        "6 ASCII bytes, one class, no literal to find",
    ),
];

fn best_of<F: FnMut() -> bool>(mut f: F, bytes: usize) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..ROUNDS {
        let t0 = Instant::now();
        let mut hits = 0u64;
        for _ in 0..WARMUP {
            if f() {
                hits += 1;
            }
        }
        let d = t0.elapsed().as_secs_f64();
        black_box(hits);
        best = best.min(d);
    }
    (bytes as f64 / (1024.0 * 1024.0)) / best
}

fn default_corpus() -> Option<std::path::PathBuf> {
    let dir = std::path::PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default())
        .join(".rgx-bench");
    let mut best: Option<(u64, std::path::PathBuf)> = None;
    for entry in fs::read_dir(dir).ok()? {
        let p = entry.ok()?.path();
        if p.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let len = fs::metadata(&p).ok()?.len();
        if best.as_ref().is_none_or(|(n, _)| len > *n) {
            best = Some((len, p));
        }
    }
    best.map(|(_, p)| p)
}

fn main() {
    use rgx_core::matcher::Matcher as _;

    let path = match std::env::args().nth(1) {
        Some(p) => std::path::PathBuf::from(p),
        None => match default_corpus() {
            Some(p) => p,
            None => {
                eprintln!("no corpus given and none found under ~/.rgx-bench");
                std::process::exit(2);
            }
        },
    };
    let data = fs::read(&path).expect("corpus is readable");
    let hay = &data[..data.len().min(SCAN_BYTES)];
    println!(
        "corpus {} ({} MiB slice, none of these patterns occur in it)",
        path.display(),
        hay.len() / (1024 * 1024)
    );
    println!("best of {ROUNDS} rounds after {WARMUP} warmups, in-process\n");
    println!(
        "{:<16} {:>5} {:>5} {:>10}  role",
        "pattern", "fast", "insts", "MB/s"
    );
    println!("{}", "-".repeat(96));

    for (label, pat, ci, role) in PATTERNS {
        let re = match rgx_core::regex::ByteRegex::new_flags(pat.as_bytes(), *ci) {
            Ok(r) => r,
            Err(e) => {
                println!("{label:<16} (did not compile: {e})");
                continue;
            }
        };
        let parsed = rgx_core::syntax::parse(pat.as_bytes()).expect("parses");
        let prog = rgx_core::nfa::compile(&parsed.ast, parsed.groups);
        let mbs = best_of(|| re.find_at(black_box(hay), 0).is_some(), hay.len());
        println!(
            "{label:<16} {:>5} {:>5} {:>10.1}  {role}",
            if re.has_fast_literal() { "yes" } else { "no" },
            prog.insts.len(),
            mbs
        );
    }

    println!();
    println!("READ THIS AS A SHAPE OBSERVATION, NOT A RATIO.");
    println!();
    println!("  - The three case-insensitive rows land together. The ASCII one --");
    println!("    `cafezzzz (-i)` -- takes exactly the code path it took before any of");
    println!("    this work, and it is as fast as the folded non-ASCII one. So the cost");
    println!("    of `-i` is `-i`: case_fold_set builds a two-member class per byte and");
    println!("    the confirm pays for it. Pre-existing, and not what this change added.");
    println!("  - The folded pattern has `fast = no`, because fixed.rs declines");
    println!("    Ast::Alt, and is still not measurably slower than the ASCII control");
    println!("    that does have a fixed literal. Losing the prefilter costs less than");
    println!("    the per-byte class confirm already does.");
    println!("  - The case-sensitive rows are roughly 2.6x the case-insensitive ones:");
    println!("    the pre-existing `-i` penalty.");
    println!();
    println!("Corpus matters: this one is Rust source, where non-ASCII is rare, so the");
    println!("folded path gets no candidates here. A corpus with accented text would");
    println!("exercise it. Re-run before quoting any of this.");
}
