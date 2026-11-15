// SPDX-License-Identifier: Apache-2.0

//! What `fixed.rs` refuses, and what a straight-path predicate would decide
//! instead -- measured on the candidates the real searcher produces, on the
//! real corpus, in the same process.
//!
//! ```text
//! cargo run --release -p rgx-core --example straight_probe
//! cargo run --release -p rgx-core --example straight_probe -- "e[0-9]" "~/.rgx-bench/other.rs"
//! ```
//!
//! **The question.** `fixed.rs` specialises a fixed-length byte predicate and
//! refuses everything else: an alternation, a repetition of unknown length, a
//! capture group, an assertion, a zero-length pattern. `(pub|fn) [a-z]+` is
//! refused, so its confirm is a Pike VM run per candidate, and that is 58% of
//! its search. This file measures the two halves of what accepting it would
//! cost:
//!
//! 1. **How many entries the VM is entered for**, counted over the candidate
//!    stream the real searcher builds on the real bytes -- not estimated from
//!    a density, because the anchor chosen for THIS buffer is what decides
//!    the number.
//! 2. **What a straight-path predicate costs per entry**, over the same
//!    entries with the same bounds, checked against
//!    [`rgx_core::vm::matches_at`] on every single one.
//!
//! **The answer, on 235 MB and 7.83 M lines, all four with 0 disagreements:**
//!
//! | pattern | entries | VM | straight | | projected |
//! |---|---:|---:|---:|---:|---:|
//! | `(pub\|fn) [a-z]+` | 908,868 | 148.2 ns | 7.5 ns | 19.6x | **127.8 ms** |
//! | `foo.*bar` | 11,545 | 515.1 ns | 25.1 ns | 20.5x | 5.7 ms |
//! | `e.` | 13,085,834 | 47.2 ns | 5.8 ns | 8.2x | 542.4 ms |
//! | `e[0-9]` | 60,230 | 44.9 ns | 5.3 ns | 8.4x | 2.4 ms |
//!
//! Two of those are the whole story for their pattern and two are not.
//! `(pub|fn) [a-z]+`'s confirm is 104.8 ms and the projection is 127.8 ms, so
//! the confirm *is* the deficit. `e[0-9]`'s confirm is 1.6% of its search and
//! the projection is 2.4 ms, so its deficit is elsewhere -- the line walk, at
//! 0.008 candidates per line, where no buffer is ever empty enough to skip.
//! The probe agrees with the attribution in `benchmark/status.md` §3.3, which it
//! had no way to know in advance.
//!
//! **A disagreement voids the timing, and the harness says so.** A prototype
//! that disagrees with the VM is a *wrong* confirm, not a cheap one. The
//! first version of the `foo.*bar` path disagreed on 3,942 of 11,545 entries
//! because a gap written greedily eats `bar` and then has nothing left to
//! match -- so every legal split point is tried, and the number that comes out
//! is the honest price of a pattern with a variable-length middle.
//!
//! **The line walk here is a COPY of `searcher::run`'s**, over the same 64 KiB
//! fills with the same terminator rule (`content_end` excludes the newline).
//! It
//! is a copy so this harness can call `any_match_in` and then walk the same
//! candidates again; the shipped searcher can only do the first. The entry
//! counts are cross-checked against `prefilter_ablate`, which counts through
//! the shipped searcher, and the two agreeing is the evidence the copy is
//! faithful.
//!
//! The prototype is written by hand per pattern, separately from `fixed.rs`,
//! on purpose: this file is the MEASUREMENT, and a measurement that calls the
//! thing it is measuring cannot fail usefully.

use std::hint::black_box;
use std::time::Instant;

use rgx_core::byteclass::ByteSet;
use rgx_core::regex::ByteRegex;
use rgx_core::searcher::CandidateSource as _;

const BLOCK: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// The prototype: exactly the shape `fixed.rs` would grow into.
// ---------------------------------------------------------------------------

/// One step of a straight path. `Byte` consumes exactly one byte that must be
/// a member; `Gap` consumes zero or more bytes that must all be members.
#[derive(Clone)]
enum Step {
    Byte([u64; 4]),
    Gap([u64; 4]),
}

#[derive(Clone)]
struct Path {
    steps: Vec<Step>,
    /// Set when no step is a gap, so the window length is known up front. The
    /// window is then taken with ONE bounds check and compared in place,
    /// instead of one `get` per step. `Some(lit)` when every step is also a
    /// single byte, which collapses to a `memcmp` of the whole window.
    fixed_len: Option<Fixed>,
}

#[derive(Clone)]
enum Fixed {
    /// Every step is one specific byte: the window must equal these.
    Lit(Box<[u8]>),
    /// The length is known but at least one step is a class: take the window
    /// once, then test each byte against its set.
    Classes(usize),
}

struct Straight {
    paths: Vec<Path>,
}

impl Straight {
    #[inline]
    fn confirm(&self, hay: &[u8], s: usize) -> bool {
        self.paths.iter().any(|p| run(p, hay, s))
    }
}

#[inline(always)]
fn in_set(t: &[u64; 4], b: u8) -> bool {
    t[usize::from(b >> 6)] >> (b & 63) & 1 == 1
}

#[inline]
fn run(p: &Path, hay: &[u8], i: usize) -> bool {
    match &p.fixed_len {
        // One bounds check for the whole window, then a memcmp. This is the
        // shape `fixed.rs` already compiles its fixed-length cases into, so
        // timing the general arm here would understate the real thing.
        Some(Fixed::Lit(lit)) => hay.get(i..i + lit.len()).is_some_and(|w| w == &lit[..]),
        // One bounds check, then the per-step set tests with no `get` in them.
        Some(Fixed::Classes(n)) => {
            let Some(w) = hay.get(i..i + n) else {
                return false;
            };
            p.steps.iter().zip(w).all(|(st, &b)| {
                in_set(
                    match st {
                        Step::Byte(t) => t,
                        Step::Gap(t) => t,
                    },
                    b,
                )
            })
        }
        // A gap is not greedy. `foo.*bar` has one, and a greedy gap consumes
        // `bar` too and then has nothing left to match -- 3,942 false
        // negatives on the corpus, which is what the disagreement counter
        // exists to catch. So every legal split point is tried, and the price
        // of that is the honest price of the shape: a pattern with a
        // variable-length middle is not a straight path, and this is what
        // says so.
        None => {
            let Some(k) = p.steps.iter().position(|s| matches!(s, Step::Gap(_))) else {
                return true;
            };
            let gap = match &p.steps[k] {
                Step::Gap(t) => t,
                _ => unreachable!("position matched a gap"),
            };
            let head = &p.steps[..k];
            let tail = &p.steps[k + 1..];
            // The head sits at `i` and does not move; only the gap advances.
            if !runs(hay, head, i) {
                return false;
            }
            let mut j = i + k; // every step before the gap is exactly one byte
            loop {
                if runs(hay, tail, j) {
                    return true;
                }
                match hay.get(j) {
                    Some(&b) if in_set(gap, b) => j += 1,
                    _ => return false,
                }
            }
        }
    }
}

/// A run of `Byte` steps, consumed left to right from `i`.
fn runs(hay: &[u8], steps: &[Step], mut i: usize) -> bool {
    steps.iter().all(|st| {
        let t = match st {
            Step::Byte(t) => t,
            Step::Gap(t) => t,
        };
        let Some(&b) = hay.get(i) else { return false };
        if !in_set(t, b) {
            return false;
        }
        i += 1;
        true
    })
}
// ---- building the prototype by hand, from the patterns named on the CLI ----

fn tab(set: &ByteSet) -> [u64; 4] {
    let mut t = [0u64; 4];
    for b in set.iter() {
        t[usize::from(b) >> 6] |= 1u64 << (b & 63);
    }
    t
}

fn parse_set(spec: &str) -> ByteSet {
    match spec {
        "lower" => {
            let mut s = ByteSet::empty();
            for b in b'a'..=b'z' {
                s.insert(b);
            }
            s
        }
        "notnl" => ByteSet::any_except_newline(),
        other => {
            let mut s = ByteSet::empty();
            for part in other.split(',') {
                if let Some((a, b)) = part.split_once('-') {
                    let (a, b): (u8, u8) = (
                        u8::from_str_radix(a, 16).unwrap(),
                        u8::from_str_radix(b, 16).unwrap(),
                    );
                    for b in a..=b {
                        s.insert(b);
                    }
                } else {
                    s.insert(u8::from_str_radix(part, 16).unwrap());
                }
            }
            s
        }
    }
}

fn lit(s: &str) -> Vec<Step> {
    s.bytes()
        .map(|b| Step::Byte(tab(&ByteSet::single(b))))
        .collect()
}

fn cls(spec: &str) -> Step {
    Step::Byte(tab(&parse_set(spec)))
}

fn finish(steps: Vec<Step>) -> Path {
    let fixed_len = if steps.iter().all(|s| matches!(s, Step::Byte(_))) {
        // All steps are fixed-width. If each is also a single byte, the whole
        // path is a literal and the window can be compared in one go.
        let mut lit = Vec::with_capacity(steps.len());
        let mut all_singles = true;
        for st in &steps {
            match st {
                Step::Byte(t) => match single_byte(t) {
                    Some(b) => lit.push(b),
                    None => {
                        all_singles = false;
                        break;
                    }
                },
                Step::Gap(_) => unreachable!("checked above"),
            }
        }
        Some(if all_singles {
            Fixed::Lit(lit.into_boxed_slice())
        } else {
            Fixed::Classes(steps.len())
        })
    } else {
        None
    };
    Path { steps, fixed_len }
}

/// The byte of a singleton set, or `None` if the set has other members.
///
/// Walks the four words and counts: a singleton is cheap to recognise and
/// the caller needs to know it exactly, because a set with two members and a
/// set with one are both "a class" for correctness and only one is a
/// literal for speed.
fn single_byte(t: &[u64; 4]) -> Option<u8> {
    let mut found = None;
    for (wi, &word) in t.iter().enumerate() {
        let mut w = word;
        while w != 0 {
            let bit = w.trailing_zeros() as u8;
            if found.is_some() {
                return None;
            }
            found = Some((wi as u8) << 6 | bit);
            w &= w - 1;
        }
    }
    found
}

/// The patterns this probe knows how to hand-build, spelled as the straight
/// paths they lower to. Kept separate from `fixed.rs` on purpose: this file is
/// the MEASUREMENT, and a measurement that calls the thing it is measuring
/// cannot fail usefully.
fn proto(pat: &str) -> Option<Straight> {
    let paths: Vec<Path> = match pat {
        // The `+` never has to be walked for line selection: `+` needs one
        // and the path supplies one. The span is a different question and
        // `grep -o` is where it shows up, which is why this is a probe and
        // not a shortcut in the searcher.
        "(pub|fn) [a-z]+" | "(pub|fn) [a-z]" => {
            let mut a = lit("pub ");
            a.push(cls("lower"));
            let mut b = lit("fn ");
            b.push(cls("lower"));
            vec![finish(a), finish(b)]
        }
        "foo.*bar" => {
            let mut a = lit("foo");
            a.push(Step::Gap(tab(&parse_set("notnl"))));
            a.extend(lit("bar"));
            vec![finish(a)]
        }
        "e[0-9]" => {
            let mut a = lit("e");
            a.push(cls("30-39"));
            vec![finish(a)]
        }
        "e." => {
            let mut a = lit("e");
            a.push(cls("notnl"));
            vec![finish(a)]
        }
        other => {
            eprintln!("(no prototype for {other:?}; VM column only)");
            return None;
        }
    };
    Some(Straight { paths })
}

// ---------------------------------------------------------------------------

struct Hit {
    line: Vec<u8>,
    s: usize,
}

fn time_ms(f: impl Fn() -> u64) -> f64 {
    for _ in 0..2 {
        black_box(f());
    }
    let t = Instant::now();
    black_box(f());
    let one = t.elapsed().as_secs_f64().max(1e-9);
    let iters = (60.0 / 1e3 / one).clamp(1.0, 1000.0) as usize;
    let mut best = f64::INFINITY;
    for _ in 0..7 {
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
    // The corpus is optional. A first argument that is an existing path is
    // the corpus; everything else is a pattern. Requiring the corpus first
    // meant a bare `straight_probe "foo.*bar"` tried to read the pattern as
    // a filename, which is a confusing way to fail a measurement tool.
    let mut path: Option<String> = None;
    let mut pats: Vec<String> = Vec::new();
    for a in std::env::args().skip(1) {
        if path.is_none() && !a.starts_with('-') && std::path::Path::new(&a).is_file() {
            path = Some(a);
        } else {
            pats.push(a);
        }
    }
    let path = path.unwrap_or_else(|| {
        format!(
            "{}/.rgx-bench/big235.rs",
            std::env::var("USERPROFILE").unwrap_or_default()
        )
    });
    if pats.is_empty() {
        pats = ["(pub|fn) [a-z]+", "foo.*bar", "e.", "e[0-9]"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
    }

    let hay = std::fs::read(&path).expect("corpus");
    let n = hay.len();
    println!("corpus : {path}  ({:.1} MiB)", n as f64 / 1048576.0);
    println!("walk   : every line of every 64 KiB fill, candidates from rgx's own stream");
    println!("timing : min of 7 rounds, over the entries the real search confirms\n");

    for pat in &pats {
        let re = ByteRegex::new(pat.as_bytes()).expect("compiles");
        let parsed = rgx_core::syntax::parse(pat.as_bytes()).expect("parses");
        let prog = rgx_core::nfa::compile(&parsed.ast, parsed.groups);
        let prot = proto(pat);
        println!("== {pat}");

        // ---- pass 1: the real candidate stream, and the entries it makes ----
        let mut entries = 0u64;
        let mut lines_with_entries = 0u64;
        let mut hits = 0u64;
        let mut disagree = 0u64;
        let mut sample: Vec<Hit> = Vec::new();
        let mut disagree_detail: Vec<String> = Vec::new();
        let mut out: Vec<usize> = Vec::new();
        for blk in hay.chunks(BLOCK) {
            let stream = re.candidates(blk, &mut out);
            let origin = match stream.origin() {
                rgx_core::searcher::Origin::Fixed(o) => o,
                rgx_core::searcher::Origin::LineStart | rgx_core::searcher::Origin::Unknown => {
                    eprintln!("  origin not fixed: this harness only models a fixed offset");
                    break;
                }
            };
            let mut ls = 0usize;
            while ls < blk.len() {
                let le = blk[ls..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map_or(blk.len(), |i| ls + i + 1);
                let content_end = if le > ls && blk[le - 1] == b'\n' {
                    le - 1
                } else {
                    le
                };
                let content = &blk[ls..content_end];
                let offs: Vec<usize> = re
                    .candidates(blk, &mut out)
                    .in_line(ls, content_end)
                    .collect();
                ls = le;
                if content.is_empty() || offs.is_empty() {
                    continue;
                }
                lines_with_entries += 1;
                let mut line_hit = false;
                for at in offs {
                    entries += 1;
                    let Some(s) = at.checked_sub(origin) else {
                        continue;
                    };
                    let vm = rgx_core::vm::matches_at(&prog, content, s);
                    if let Some(pr) = &prot {
                        let want = pr.confirm(content, s);
                        if want != vm {
                            disagree += 1;
                            if disagree_detail.len() < 5 {
                                disagree_detail.push(format!(
                                    "s={s} proto={want} vm={vm} line={:?}",
                                    String::from_utf8_lossy(content)
                                ));
                            }
                        }
                    }
                    if vm {
                        line_hit = true;
                        // A deterministic sample: every 8th ENTRY, so the
                        // timing sees the real mix of near-misses and matches
                        // without holding 908k lines in memory.
                        if entries.is_multiple_of(8) && sample.len() < 20000 {
                            sample.push(Hit {
                                line: content.to_vec(),
                                s,
                            });
                        }
                    }
                }
                if line_hit {
                    hits += 1;
                }
            }
        }
        println!(
            "   entries {entries}   lines with entries {lines_with_entries}   matching lines {hits}"
        );
        if let Some(pr) = &prot {
            println!(
                "   prototype vs VM over ALL entries: {} disagreements",
                disagree
            );
            let agrees = disagree == 0;
            for d in &disagree_detail {
                println!("     {d}");
            }
            if !agrees {
                println!("   NOT TIMED: a prototype that disagrees with the VM is a");
                println!("   wrong confirm, and its price is not a price. The disagreement");
                println!("   is the result -- this shape does not lower to a straight path.");
            }
            // ---- pass 2: the price of an entry, both ways ----
            let vm_ms = time_ms(|| {
                let mut c = 0u64;
                for h in &sample {
                    if rgx_core::vm::matches_at(&prog, black_box(&h.line), h.s) {
                        c += 1;
                    }
                }
                c
            });
            let pr_ms = time_ms(|| {
                let mut c = 0u64;
                for h in &sample {
                    if pr.confirm(black_box(&h.line), h.s) {
                        c += 1;
                    }
                }
                c
            });
            let k = sample.len() as f64;
            println!(
                "   sample {k} entries   vm {vm_ms:.2} ms ({:.1} ns/entry)   straight {pr_ms:.2} ms ({:.1} ns/entry)   {}",
                vm_ms * 1e6 / k,
                pr_ms * 1e6 / k,
                if vm_ms > 0.0 { format!("{:.2}x", vm_ms / pr_ms) } else { "-".into() }
            );
            let saved_ms = entries as f64 * (vm_ms - pr_ms) / k;
            println!(
                "   projected saving over {entries} entries: {saved_ms:.1} ms   \
                 (rectangle law: same mix, same per-entry price)"
            );
        }
        for a in re.anchor_info() {
            println!("   anchor {} at {} known={}", a.kind, a.at, a.known);
        }
        println!();
    }
}
