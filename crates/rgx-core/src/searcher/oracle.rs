// SPDX-License-Identifier: Apache-2.0

//!
//! A differential oracle for the searcher, against the `regex` crate (already
//! a dev-dependency, so this costs nothing new).
//!
//! Restricted to where the two engines are specified to agree. rgx is
//! byte-mode; `regex` is Unicode by default and its `.` counts a codepoint
//! where rgx's counts a byte. So: ASCII haystacks and patterns, and
//! `RegexBuilder` with `.unicode(false)`.
//!
//! What is compared is which lines matched, not byte offsets. Line splitting
//! is rgx's own job, so a differential on offsets would mostly re-test the
//! tokenizer.
//!
//! Both `search_slice` and `search_reader` (at five chunk sizes) are driven
//! over the full matrix. What this file still does not catch is a defect that
//! reproduces identically in rgx and in this file's own offset-to-line
//! mapping.

use alloc::string::String;
use alloc::vec::Vec;

use regex::bytes::RegexBuilder;

use super::*;
use crate::regex::ByteRegex;

/// Records only what the oracle needs: the 1-based line numbers reported as
/// matched, in order. Not the bytes — the bytes are re-derivable from the
/// line number and the haystack, and comparing them would compare the
/// tokenizer twice.
#[derive(Default, Debug, PartialEq, Eq)]
struct LineNumbers(Vec<u64>);

impl Sink for LineNumbers {
    type Error = fmt::Error;

    fn matched(&mut self, mat: &SinkMatch<'_>) -> Result<bool, fmt::Error> {
        if let Some(n) = mat.line_number {
            self.0.push(n);
        }
        Ok(true)
    }

    fn context(&mut self, _ctx: &SinkContext<'_>) -> Result<bool, fmt::Error> {
        Ok(true)
    }

    fn finish(&mut self, _fin: &SinkFinish<'_>) -> Result<(), fmt::Error> {
        Ok(())
    }
}

fn cfg_line_numbers() -> Config {
    Config {
        binary: BinaryDetection::None,
        line_numbers: true,
        ..Config::default()
    }
}

/// The lines of `hay`, content only, terminator cut off.
///
/// This is rgx's contract, so the oracle has to reproduce it or it is
/// comparing two different questions. Two details matter:
///
/// - the terminator is not part of the line, so `[^a]` cannot match the `\n`
///   of an otherwise empty line — a whole-buffer scan does match it;
/// - **a trailing newline does not open a line.** `alpha\n` is one line and an
///   empty buffer is zero lines. `rg` and rgx both agree; an oracle that
///   invents a last empty line disagrees with both.
fn split_lines(hay: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0usize;
    // `memchr_iter`, not `memchr`: the latter returns `Option<usize>`, which
    // iterates once — a mistake this file made and which showed up as every
    // multi-line haystack collapsing to two lines.
    for i in crate::memchr::memchr_iter(b'\n', hay) {
        out.push(&hay[start..i]);
        start = i + 1;
    }
    if start < hay.len() {
        out.push(&hay[start..]);
    }
    out
}

/// The 1-based line numbers `regex` says match, matched **per line** rather
/// than over the whole buffer, for the reasons in [`split_lines`].
///
/// Per-line matching also means the oracle is not re-testing rgx's tokenizer:
/// both sides are given the same lines and asked the same question.
fn oracle_lines(pattern: &str, hay: &[u8]) -> Vec<u64> {
    let Ok(re) = RegexBuilder::new(pattern).unicode(false).build() else {
        // The oracle refused the pattern; the caller filters these out before
        // comparing, so reaching here with a panic would be the filter's bug.
        return Vec::new();
    };
    split_lines(hay)
        .iter()
        .enumerate()
        .filter(|(_, line)| re.is_match(line))
        .map(|(i, _)| i as u64 + 1)
        .collect()
}

/// The line numbers rgx's own searcher reports for the same pattern and bytes.
fn rgx_lines(pattern: &[u8], hay: &[u8]) -> Option<Vec<u64>> {
    let re = ByteRegex::new(pattern).ok()?;
    let s = Searcher::new(&re, cfg_line_numbers());
    let mut rec = LineNumbers::default();
    s.search_slice(hay, &mut rec).expect("search_slice");
    Some(rec.0)
}

/// The same bytes through the READER path, delivered in small fills so the
/// rolling buffer, its `drop`/`roll` logic and the fill-boundary cases are
/// exercised. The slice path has the whole haystack and never rolls; the
/// reader has to survive a line or a match straddling a fill. Comparing the
/// two over the same bytes is the only way one catches the other's defect --
/// `search_slice` and `search_reader` can each be wrong in a way the other
/// is not.
fn rgx_lines_reader(pattern: &[u8], hay: &[u8], chunk: usize) -> Vec<u64> {
    let re = ByteRegex::new(pattern).expect("pattern already compiled on the slice path");
    let cfg = cfg_line_numbers();
    let s = Searcher::new(&re, cfg.clone());
    let mut rec = LineNumbers::default();
    let mut lb = LineBuffer::new(&cfg);
    let mut rest = hay;
    let mut rd = |b: &mut [u8]| {
        let n = core::cmp::min(b.len().min(chunk), rest.len());
        b[..n].copy_from_slice(&rest[..n]);
        rest = &rest[n..];
        Ok(n)
    };
    s.search_reader(&mut rd, &mut rec, &mut lb)
        .expect("search_reader");
    rec.0
}

/// Does the oracle accept this pattern at all? A cell is meaningful only if
/// both engines accept it; `compare` returning `Err` for "one side refused" is
/// not a disagreement.
fn oracle_accepts(pattern: &str) -> bool {
    RegexBuilder::new(pattern).unicode(false).build().is_ok()
}

/// Run one comparison, returning `Err` with a diagnosis when the two disagree.
///
/// The two ways they can legitimately differ, and the reason each is skipped
/// rather than asserted, are in the tests that call this.
fn compare(pattern: &str, hay: &[u8]) -> Result<(), String> {
    let Some(mine) = rgx_lines(pattern.as_bytes(), hay) else {
        return Err(format!(
            "rgx refused {pattern:?}, so there is nothing to compare"
        ));
    };
    if !oracle_accepts(pattern) {
        return Err(format!(
            "regex refused {pattern:?}, so this cell proves nothing"
        ));
    }
    let theirs = oracle_lines(pattern, hay);
    if mine == theirs {
        return Ok(());
    }
    Err(format!(
        "pattern {pattern:?}\nhaystack {:?}\nrgx   {:?}\nregex {:?}",
        String::from_utf8_lossy(hay),
        mine,
        theirs
    ))
}

// ---------------------------------------------------------------------------
// Multi-line: `-U`
// ---------------------------------------------------------------------------
//
// Everything above answers per line, and `split_lines` cuts the terminator off
// — the opposite of what `-U` needs. A multi-line match is found in the whole
// buffer, so the comparison works on match extents and maps an offset back to a
// line.

/// Haystacks where a cross-line match is possible and the answer is not obvious.
const ML_HAYSTACKS: &[(&str, &[u8])] = &[
    ("two lines, no trailing nl", b"alpha\nbeta"),
    ("three lines", b"alpha\nbeta\ngamma\n"),
    ("empty middle line", b"alpha\n\nbeta\n"),
    ("blank line inside a match span", b"alpha\n\n\nbeta\n"),
    ("match ends on the last line", b"alpha\nbeta"),
    ("one line only", b"alpha\n"),
];

/// Patterns that need an explicit newline to cross — these span under `-U`
/// alone, which is the whole point of the flag.
const ML_PATTERNS: &[&str] = &["alpha\nbeta", "alpha\n.*beta", "alpha\n\nbeta"];

/// Patterns that also need `.` to cross, so they span only under
/// `--multiline-dotall`: **ripgrep's `-U` does not make `.` match a newline**,
/// and the two flags have to be gated separately.
const ML_DOTALL_PATTERNS: &[&str] = &["alpha.beta", "alpha.*beta", "alpha.+beta"];

/// The line numbers `regex` says a multiline search matches.
///
/// `dot_matches_new_line` is a parameter because `-U` and `--multiline-dotall`
/// are two flags in ripgrep and the gate has to hold both.
///
/// A match is attributed to the line holding its **first** byte, which is what
/// makes rg's output reproducible: it prints the whole match with each physical
/// line numbered up from where the match began (`3:THREE` / `4:four` for a
/// match over lines 3-4). Once a line is reported, a later match ending on it
/// is not reported again.
fn oracle_multiline_lines(pattern: &str, hay: &[u8], dot_all: bool) -> Vec<u64> {
    let Ok(re) = RegexBuilder::new(pattern)
        .unicode(false)
        .dot_matches_new_line(dot_all)
        .size_limit(1 << 20)
        .build()
    else {
        return Vec::new();
    };
    let line_of =
        |off: usize| -> u64 { 1 + hay[..off].iter().filter(|&&b| b == b'\n').count() as u64 };
    let mut out: Vec<u64> = Vec::new();
    let mut reported: u64 = 0;
    for m in re.find_iter(hay) {
        let line = line_of(m.start());
        if line <= reported {
            continue; // still inside a span already reported
        }
        reported = line;
        out.push(line);
    }
    out
}

/// The line numbers rgx's searcher reports, with `multi_line` on and the
/// pattern compiled with whatever `dot_all` the case is about.
fn rgx_multiline_lines(pattern: &[u8], hay: &[u8], dot_all: bool) -> Option<Vec<u64>> {
    let re = crate::regex::ByteRegex::new_multiline(pattern, false, dot_all).ok()?;
    let config = Config {
        binary: BinaryDetection::None,
        line_numbers: true,
        multi_line: true,
        ..Config::default()
    };
    let s = Searcher::new(&re, config);
    let mut rec = LineNumbers::default();
    s.search_slice(hay, &mut rec).expect("search_slice");
    Some(rec.0)
}

/// One pass of the gate over `patterns` at a given `dot_all`.
fn multiline_pass(
    patterns: &[&str],
    dot_all: bool,
    checked: &mut usize,
    skipped: &mut usize,
    out: &mut Vec<String>,
) {
    for pattern in patterns {
        for (name, hay) in ML_HAYSTACKS {
            let regex_ok = RegexBuilder::new(pattern)
                .unicode(false)
                .dot_matches_new_line(dot_all)
                .build()
                .is_ok();
            let Some(mine) = rgx_multiline_lines(pattern.as_bytes(), hay, dot_all) else {
                *skipped += 1;
                continue;
            };
            if !regex_ok {
                *skipped += 1;
                continue;
            }
            *checked += 1;
            let theirs = oracle_multiline_lines(pattern, hay, dot_all);
            if mine != theirs {
                out.push(format!(
                    "[{name}] {pattern:?} dot_all={dot_all}\nhaystack {:?}\nrgx   {:?}\nregex {:?}",
                    String::from_utf8_lossy(hay),
                    mine,
                    theirs
                ));
            }
        }
    }
}

/// The `-U` gate, in both of its forms. Fails until the searcher honours
/// `Config::multi_line`, and it is written to fail for the right reason: an
/// empty result where the oracle has one, not a panic.
#[test]
fn the_searcher_spans_lines_when_multi_line_is_set() {
    let (mut checked, mut skipped, mut bad) = (0usize, 0usize, Vec::new());
    multiline_pass(ML_PATTERNS, false, &mut checked, &mut skipped, &mut bad);
    multiline_pass(
        ML_DOTALL_PATTERNS,
        true,
        &mut checked,
        &mut skipped,
        &mut bad,
    );

    assert!(
        bad.is_empty(),
        "{} of {} multiline cells disagree:\n\n{}",
        bad.len(),
        checked,
        bad.join("\n\n")
    );
    assert!(checked > 0, "no multiline cell was compared");
}

/// `-U` alone must NOT let `.` cross a newline. This is the assertion that
/// catches the flag being wired to `dot_all` by convenience: `rgx -U
/// alpha.beta` answering where `rg -U alpha.beta` finds nothing would be a
/// behavioural divergence from ripgrep.
#[test]
fn multiline_alone_does_not_make_dot_cross_a_newline() {
    let hay = b"alpha\nbeta\n";
    let re = ByteRegex::new_multiline(b"alpha.beta", false, false).unwrap();
    let s = Searcher::new(
        &re,
        Config {
            binary: BinaryDetection::None,
            line_numbers: true,
            multi_line: true,
            ..Config::default()
        },
    );
    let mut got = LineNumbers::default();
    s.search_slice(hay, &mut got).expect("search");
    assert!(
        got.0.is_empty(),
        "`-U` alone must not make `.` cross a newline: {:?}",
        got.0
    );

    // And with `dot_all` it does — the two flags are different.
    let re = ByteRegex::new_multiline(b"alpha.beta", false, true).unwrap();
    let s = Searcher::new(
        &re,
        Config {
            binary: BinaryDetection::None,
            line_numbers: true,
            multi_line: true,
            ..Config::default()
        },
    );
    let mut got = LineNumbers::default();
    s.search_slice(hay, &mut got).expect("search");
    assert_eq!(got.0, vec![1], "with dot_all the match starts on line 1");
}

/// `-U` and its absence have to be different answers, not the same one
/// twice. Without this, a `-U` searcher that ignored the flag would
/// satisfy the gate on a corpus where no pattern spans a line — the
/// vacuous-matrix failure this file's floors exist to catch.
#[test]
fn multi_line_is_off_by_default_and_the_two_answers_differ() {
    let hay = b"alpha\nbeta\n";
    assert_eq!(
        oracle_multiline_lines("alpha\nbeta", hay, false),
        vec![1],
        "the oracle says the match spans lines 1-2 and is reported where it BEGINS"
    );

    // Off: a cross-line pattern cannot match at all.
    let re = ByteRegex::new(b"alpha.beta").unwrap();
    let s = Searcher::new(
        &re,
        Config {
            binary: BinaryDetection::None,
            line_numbers: true,
            ..Config::default()
        },
    );
    let mut off = LineNumbers::default();
    s.search_slice(hay, &mut off).expect("search");
    assert!(
        off.0.is_empty(),
        "without -U there is nothing to report: {:?}",
        off.0
    );
}

/// ASCII haystacks chosen for the ways a line-oriented searcher goes wrong.
/// Hand-written rather than generated because every entry is a *named* failure
/// mode a generator would not produce. Volume is covered by `generated.rs`
/// elsewhere in this tree.
const HAYSTACKS: &[(&str, &[u8])] = &[
    // Empty input.
    ("empty", b""),
    // A single line with no terminator: distinguishes "reads a line" from
    // "reads a terminator".
    ("one line, unterminated", b"alpha"),
    // An empty first line.
    ("leading newline", b"\nbeta\n"),
    // Trailing terminator: the last line is real, the byte after it is not.
    ("trailing newline", b"alpha\n"),
    // Empty line in the middle.
    ("interior empty line", b"alpha\n\nbeta\n"),
    // CRLF: `\r` belongs to the line. Splits on `\n` alone report `beta\r`.
    ("crlf", b"alpha\r\nbeta\r\ngamma\r\n"),
    // Match at offset 0: catches an anchor bug that fires on the previous line.
    ("match at offset zero", b"needle here\nand there\n"),
    // Match at the final byte: the end of the haystack is not a line boundary.
    ("match at final byte", b"alpha\nneedle"),
    // Two matches on one line: the line is reported once.
    ("two matches, one line", b"needle and needle\nplain\n"),
    // `.*` at its greedy end: where a terminator-leak bug shows up.
    ("greedy to end of line", b"abc\nabcd\nabcde\n"),
    // Pure ASCII: oracle's byte semantics and rgx's agree.
    (
        "ascii only",
        b"pub fn main() {}\nlet x = 1;\npub fn other() {}\n",
    ),
    // Blank lines interleaved: an off-by-one in line numbering becomes visible.
    ("blank lines interleaved", b"needle\n\n\nneedle\n\nneedle\n"),
    // Repeated identical lines: a cache keyed on line content would skip
    // them.
    ("repeated identical lines", b"same\nsame\nsame\nsame\n"),
    // Line that is only the pattern's first byte.
    ("prefix only", b"need\nneedle\nne\n"),
];

/// ASCII patterns chosen to cover the constructs the engine actually
/// compiles, plus the ones that are cheap to get wrong.
///
/// Every one of these is ASCII on purpose — see the module header on why.
const PATTERNS: &[&str] = &[
    // Literals, the common case.
    "needle",
    "a",
    "zzz", // matches nothing anywhere in the corpus
    // Alternation, single-byte and multi-byte.
    "a|b",
    "needle|plain",
    "e.",
    // Classes.
    "[abc]",
    "[^a]",
    "[0-9]",
    // Quantifiers, greedy and lazy.
    "ne+",
    "ne*",
    "n?e",
    "n{2}",
    "ne+dle",
    ".*",
    ".+",
    "[ab]+",
    // Anchors, which is where line semantics live or die.
    "^needle",
    "needle$",
    "^$",
    "^a",
    "e$",
    "^.*$",
    // Boundaries. `\b` is a byte boundary here, which is exactly what the
    // oracle with `unicode(false)` computes, so it is comparable.
    r"\bneedle\b",
    r"\bneed",
    // Word classes, byte-mode.
    r"\w+",
    r"\s",
    // Groups. rgx **matches** through a group; what it has no is capture
    // *reporting*, which is what `-r` needs and why `-r` on a grouped pattern
    // is a separate problem. So these belong in the compared matrix, not in a
    // refusal list.
    "(ab)",
    "(a|b)",
    // Lookaround, which the byte engine refuses — `syntax.rs:430` says
    // "lookahead is not supported by the byte engine". Kept here because a
    // refusal the matrix never reaches is a refusal nobody checks.
    "(?=a)",
    "(?!a)",
    "(?<=a)",
    "(?<!a)",
];

/// Patterns `ByteRegex::new` refuses. A silent acceptance would be worse
/// than a refusal: the answer would be wrong rather than absent.
///
/// Lookaround, and only lookaround: capture groups are accepted because
/// matching through one needs nothing more than an alternation, and only
/// reporting a capture is outside the engine.
const REFUSED: &[&str] = &["(?=a)", "(?!a)", "(?<=a)", "(?<!a)"];

/// Every cell that both engines accept, compared.
#[test]
fn the_searcher_agrees_with_regex_across_the_matrix() {
    let mut checked = 0usize;
    let mut disagreements = Vec::new();
    let mut skipped = 0usize;

    for pattern in PATTERNS {
        for (name, hay) in HAYSTACKS {
            // A cell is meaningful only if BOTH engines accept the pattern.
            let rgx_ok = ByteRegex::new(pattern.as_bytes()).is_ok();
            let regex_ok = oracle_accepts(pattern);
            if !(rgx_ok && regex_ok) {
                skipped += 1;
                continue;
            }
            match compare(pattern, hay) {
                Ok(()) => checked += 1,
                Err(why) => disagreements.push(format!("[{name}] {why}")),
            }
        }
    }

    assert!(
        disagreements.is_empty(),
        "{} of the cells that both engines accept disagree:\n\n{}",
        disagreements.len(),
        disagreements.join("\n\n")
    );
    // A matrix that silently compared almost nothing is a vacuous test.
    assert!(
        checked >= 200,
        "only {checked} cells were compared; the matrix has degenerated"
    );
    assert!(
        skipped > 0,
        "no cell was skipped, so the refusal cases are not being exercised"
    );
}

/// The slice and reader paths must answer the same thing for the same bytes.
///
/// `search_slice` has the whole haystack and never rolls. `search_reader`
/// fills a rolling buffer and carries before-context across the boundary, so
/// a line or a match that straddles a fill is a case only it sees -- and a
/// `drop`/`roll` defect is a case only it can get wrong. Comparing the two
/// over the same bytes is the only check that catches one being wrong where
/// the other is right; the regex oracle above cannot see this at all.
///
/// Chunk sizes are chosen to split lines and matches, not to be convenient:
/// 1 byte forces every line to straddle, and the larger ones straddle on
/// some haystacks and not others.
#[test]
fn the_reader_path_agrees_with_the_slice_path_across_the_matrix() {
    let mut checked = 0usize;
    let mut disagreements = Vec::new();
    for pattern in PATTERNS {
        if ByteRegex::new(pattern.as_bytes()).is_err() {
            continue;
        }
        for (name, hay) in HAYSTACKS {
            let Some(slice) = rgx_lines(pattern.as_bytes(), hay) else {
                continue;
            };
            for chunk in [1usize, 2, 7, 64, 4096] {
                let reader = rgx_lines_reader(pattern.as_bytes(), hay, chunk);
                if reader != slice {
                    disagreements.push(format!(
                        "[{name}] chunk={chunk} pattern={pattern:?}\n  slice={slice:?}\n  reader={reader:?}"
                    ));
                } else {
                    checked += 1;
                }
            }
        }
    }
    assert!(
        disagreements.is_empty(),
        "{} of the slice/reader pairs disagree:\n\n{}",
        disagreements.len(),
        disagreements.join("\n\n")
    );
    assert!(
        checked >= 200,
        "only {checked} slice/reader pairs were compared; the matrix has degenerated"
    );
}

/// The refusal boundary is asserted, not assumed: a pattern the engine cannot
/// compile must come back as an error rather than as a plausible wrong answer.
#[test]
fn lookaround_is_refused_rather_than_mis_evaluated() {
    for p in REFUSED {
        assert!(
            ByteRegex::new(p.as_bytes()).is_err(),
            "{p:?} must be refused — the byte engine has no lookaround, and \
             accepting it would answer wrongly instead of not at all"
        );
    }
}

/// The corpus the rest of the file is measured against is ASCII: it is
/// the precondition under which the comparison is valid.
#[test]
fn the_oracle_matrix_is_ascii_so_the_comparison_is_valid() {
    for (name, hay) in HAYSTACKS {
        assert!(
            hay.is_ascii(),
            "haystack {name:?} holds a byte above 0x7f, which is where the byte \
             engine and `regex` are specified to disagree"
        );
    }
    for p in PATTERNS {
        assert!(p.is_ascii(), "pattern {p:?} is not ASCII");
    }
}

/// Why the matrix is ASCII, demonstrated.
///
/// `.unicode(false)` makes the oracle count bytes, putting the two
/// engines in the same universe. The default `.unicode(true)` counts
/// codepoints, and then `\w`, `.` and `\b` disagree with rgx on any
/// input above `0x7f`. ASCII input is the belt to that braces.
#[test]
fn unicode_mode_is_what_would_break_the_comparison_not_the_input_alone() {
    let non_ascii = "a\u{00e9}b"; // 4 bytes, 3 codepoints
    let bytes = non_ascii.as_bytes();
    assert_eq!(bytes.len(), 4, "the premise: 4 bytes");
    assert_eq!(non_ascii.chars().count(), 3, "…over 3 codepoints");

    // `.` is where the two modes part company.
    let uni = RegexBuilder::new(".").unicode(true).build().unwrap();
    let byte_mode = RegexBuilder::new(".").unicode(false).build().unwrap();
    assert_eq!(
        uni.find_iter(bytes).count(),
        3,
        "unicode mode: a, é, b — three matches"
    );
    assert_eq!(
        byte_mode.find_iter(bytes).count(),
        4,
        "byte mode: a, the two bytes of é, b — which is what rgx sees"
    );
    // The engine agrees with byte mode, not Unicode mode.
    let re = ByteRegex::new(b".").unwrap();
    let mut hits = 0usize;
    let mut at = 0usize;
    while let Some(next) = re.find_at(bytes, at) {
        hits += 1;
        at = next + 1;
        if at >= bytes.len() {
            break;
        }
    }
    assert_eq!(hits, 4, "rgx counts bytes, like the byte-mode oracle");
}
