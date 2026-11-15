// SPDX-License-Identifier: Apache-2.0

//! What one `vm::find_at` costs, per pattern, with no searcher around it —
//! and, below it, WHAT of that cost is the VM.
//!
//! ```text
//! cargo run --release -p rgx-core --example vm_probe -- [patterns...]
//! ```
//!
//! **Why this file exists.** The LINE ladder puts `e.`'s confirm at 181.3 ms
//! over 4,235,366 entries, which is 42.8 ns an entry -- for a program of two
//! instructions that consumes two bytes. That number is too big for the work
//! and too small for a mistake, and "too small for a mistake" is the shape a
//! per-call setup cost has. This file times the anchored VM on a realistic
//! line directly, so the 42.8 ns either survives as the VM's own cost or is
//! shown to be charged somewhere around it.
//!
//! **The lines are the corpus's own**, not synthetic: a 31-byte hand-written
//! line would be the friendliest input the pattern ever sees, and the whole
//! question is whether the real ones behave like it.
//!
//! **The ABLATION block is the answer to "where is it".** Four rows, in the
//! order the cost is paid:
//!
//! | row | what it adds |
//! |-----|--------------|
//! | `hand` | nothing. The two byte compares, inlined, on the same line. |
//! | `hand_fn` | one function call, `#[inline(never)]`. The price of dispatch. |
//! | `vm` | [`rgx_core::vm::matches_at`]. Everything the Pike VM costs. |
//! | `ship` | [`rgx_core::matcher::Matcher::any_match_in`], the confirm the binary runs. |
//!
//! `hand_fn - hand` is the call, `vm - hand_fn` is the VM including its
//! per-call state reset, and `ship - vm` is the loop around it: the candidate
//! walk, `checked_sub`, and the `fast.checks` pre-confirm. Whichever of those
//! three is the 42.8 ns is the thing a specialised confirm has to beat.

use std::hint::black_box;
use std::time::Instant;

const ROUNDS: usize = 7;
const WARMUP: usize = 2;
const TARGET_MS: f64 = 60.0;

fn time_ms(mut f: impl FnMut() -> u64) -> f64 {
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

/// The hand-written confirm for one pattern, inlined, with no bounds check it
/// cannot justify. This is the FLOOR: the answer a specialisation can reach,
/// before any call, any loop and any check is added back.
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
        "a.c" | "a.b" => g(0) == b'a' && g(1) != b'\n' && g(2) != b'\n',
        // A backtracking shape: the point of the row is that it is the SAME
        // kind of thing the specialiser has to decline, so the number next to
        // it is a number it cannot win.
        "foo.*bar" => false,
        _ => false,
    }
}

/// The same, behind a call the optimiser is forbidden to remove.
#[inline(never)]
fn hand_fn(pat: &str, hay: &[u8], s: usize) -> bool {
    black_box(pat);
    hand(pat, hay, s)
}

fn main() {
    let pats: Vec<String> = std::env::args().skip(1).collect();
    let pats: Vec<String> = if pats.is_empty() {
        [
            "e",
            "e.",
            "e[0-9]",
            "pub fn",
            "fn main",
            "let mut",
            "foo.*bar",
            "a.c",
            "a|b|c",
            "(pub|fn) [a-z]+",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    } else {
        pats
    };

    // A line of the shape the corpus is made of, and a second one where the
    // pattern cannot match, so the two are separable: a lazy confirm would
    // price the same as an eager one if the match were at the end.
    let hit: Vec<u8> = b"    let mut value = parse_error(x);".to_vec();
    let miss: Vec<u8> = b"    let mut value = parse_ok_no(x);".to_vec();

    println!(
        "hit  ({} B): {:?}",
        hit.len(),
        String::from_utf8_lossy(&hit)
    );
    println!(
        "miss ({} B): {:?}",
        miss.len(),
        String::from_utf8_lossy(&miss)
    );
    println!("\nmin of {ROUNDS} rounds after {WARMUP} warmups");
    println!(
        "\n{:<16} {:>5} {:>6} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "pattern", "insts", "slots", "find_at", "matches_at", "ship", "hand", "hand_fn", "vm_bool"
    );
    println!("{}", "-".repeat(96));

    for pat in &pats {
        let re = match rgx_core::regex::ByteRegex::new(pat.as_bytes()) {
            Ok(r) => r,
            Err(e) => {
                println!("{pat:<16} (did not compile: {e})");
                continue;
            }
        };
        let parsed = rgx_core::syntax::parse(pat.as_bytes()).expect("the pattern parses");
        let prog = rgx_core::nfa::compile(&parsed.ast, parsed.groups);

        // The candidate offset a prefilter would hand over: the first `e`, or
        // the first byte of the pattern's leading literal, so the call is
        // anchored where the engine actually anchors it.
        let s = hit.iter().position(|&b| b == b'e').unwrap_or(0);

        let per = |f: &mut dyn FnMut() -> bool| -> f64 {
            time_ms(|| {
                let mut c = 0u64;
                for _ in 0..1000 {
                    if f() {
                        c += 1;
                    }
                }
                c
            }) * 1e3
        };

        let t_find = per(&mut || rgx_core::vm::find_at(&prog, black_box(&hit), s).is_some());
        let t_bool = per(&mut || rgx_core::vm::matches_at(&prog, black_box(&hit), s));
        let t_hand = per(&mut || hand(pat, black_box(&hit), s));
        let t_hand_fn = per(&mut || hand_fn(pat, black_box(&hit), s));

        // The confirm the binary actually runs: the same candidate walk, the
        // same `checked_sub`, the same pre-confirm, over a one-candidate line.
        let ship = {
            use rgx_core::matcher::Matcher as _;
            let hay = hit.as_slice();
            let cands: [usize; 1] = [s];
            per(&mut || {
                let mut c = rgx_core::searcher::Candidates::of(&cands)
                    .with_origin(rgx_core::searcher::Origin::Fixed(0));
                let line = c.in_line(0, hay.len());
                !line.is_empty() && re.any_match_in(hay, line, rgx_core::searcher::Origin::Fixed(0))
            })
        };

        println!(
            "{:<16} {:>5} {:>6} {:>7.1}ns {:>7.1}ns {:>7.1}ns {:>7.1}ns {:>7.1}ns {:>7.1}ns",
            pat,
            prog.insts.len(),
            prog.slots,
            t_find,
            t_bool,
            ship,
            t_hand,
            t_hand_fn,
            t_bool,
        );
    }
}
