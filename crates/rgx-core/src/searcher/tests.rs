// SPDX-License-Identifier: Apache-2.0

//!
//! The failure mode that matters for a searcher is *drift*: a line reported
//! as two, a context line as a match, a NUL handled differently. These
//! tests state the line contract directly rather than comparing against a
//! hand-written expectation, because the contract is short and a test that
//! encodes the author's memory of it is only as good as that memory. The
//! cases that are cheap to get wrong — a final line with no terminator, a
//! match across the 64 KiB boundary, `-v` interacting with after-context —
//! each get their own test.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use super::*;
use crate::regex::ByteRegex;

/// Records what a search reported, so a test can assert on it.
#[derive(Default, Debug, PartialEq, Eq)]
struct Recorded {
    matched: Vec<Vec<u8>>,
    context: Vec<Vec<u8>>,
    binary: Option<u64>,
    line_numbers: Vec<Option<u64>>,
}

impl Recorded {
    /// Lines handed to `matched`, as strings, for readable assertions.
    fn matched_lines(&self) -> Vec<String> {
        self.matched
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect()
    }

    /// Lines handed to `context`, as strings.
    fn context_lines(&self) -> Vec<String> {
        self.context
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect()
    }
}

impl Sink for Recorded {
    type Error = fmt::Error;

    fn matched(&mut self, mat: &SinkMatch<'_>) -> Result<bool, fmt::Error> {
        self.matched.push(mat.bytes.to_vec());
        self.line_numbers.push(mat.line_number);
        Ok(true)
    }

    fn context(&mut self, ctx: &SinkContext<'_>) -> Result<bool, fmt::Error> {
        self.context.push(ctx.bytes.to_vec());
        Ok(true)
    }

    fn finish(&mut self, fin: &SinkFinish<'_>) -> Result<(), fmt::Error> {
        self.binary = fin.binary_byte_offset;
        Ok(())
    }
}

/// A sink that stops the search on the first match — how `-q` works.
struct QuitOnMatch(Recorded);

impl Sink for QuitOnMatch {
    type Error = fmt::Error;

    fn matched(&mut self, mat: &SinkMatch<'_>) -> Result<bool, fmt::Error> {
        self.0.matched.push(mat.bytes.to_vec());
        Ok(false)
    }

    fn context(&mut self, _ctx: &SinkContext<'_>) -> Result<bool, fmt::Error> {
        Ok(true)
    }

    fn finish(&mut self, fin: &SinkFinish<'_>) -> Result<(), fmt::Error> {
        self.0.binary = fin.binary_byte_offset;
        Ok(())
    }
}

fn cfg_default() -> Config {
    Config {
        binary: BinaryDetection::None,
        ..Config::default()
    }
}

fn run(pattern: &[u8], hay: &[u8], config: Config) -> Recorded {
    let re = ByteRegex::new(pattern).unwrap();
    let s = Searcher::new(&re, config);
    let mut rec = Recorded::default();
    s.search_slice(hay, &mut rec).expect("search");
    rec
}

#[test]
fn reports_the_matching_line_with_its_terminator() {
    let got = run(b"beta", b"alpha\nbeta\ngamma\n", cfg_default());
    assert_eq!(got.matched_lines(), vec!["beta\n"]);
}

#[test]
fn a_final_line_without_a_terminator_is_still_a_line() {
    let got = run(b"beta", b"alpha\nbeta", cfg_default());
    assert_eq!(
        got.matched_lines(),
        vec!["beta"],
        "no trailing newline, still a line"
    );
}

#[test]
fn several_matches_on_one_line_report_the_line_once() {
    // The search advances by the LINE, not by the match, so a line with
    // three matches is reported once.
    let got = run(b"a", b"xxaxxaxxa\n", cfg_default());
    assert_eq!(got.matched_lines(), vec!["xxaxxaxxa\n"]);
}

#[test]
fn a_match_in_the_last_line_of_a_buffer_with_no_terminator_is_found() {
    let got = run(b"needle", b"no trailing terminator needle", cfg_default());
    assert_eq!(got.matched_lines(), vec!["no trailing terminator needle"]);
}

#[test]
fn an_empty_haystack_reports_nothing() {
    let got = run(b"a", b"", cfg_default());
    assert!(got.matched_lines().is_empty());
    assert!(got.context_lines().is_empty());
}

#[test]
fn inverted_match_reports_the_complement_lines() {
    let got = run(
        b"beta",
        b"alpha\nbeta\ngamma\n",
        Config {
            invert: true,
            ..cfg_default()
        },
    );
    assert_eq!(got.matched_lines(), vec!["alpha\n", "gamma\n"]);
}

#[test]
fn after_context_is_reported_as_context_not_as_a_match() {
    let got = run(
        b"b",
        b"a\nb\nc\nd\n",
        Config {
            after: 2,
            ..cfg_default()
        },
    );
    assert_eq!(got.matched_lines(), vec!["b\n"]);
    assert_eq!(got.context_lines(), vec!["c\n", "d\n"]);
}

#[test]
fn after_context_stops_at_the_end_of_the_buffer() {
    // Asks for 5 after-context lines, none remain.
    let got = run(
        b"b",
        b"a\nb\n",
        Config {
            after: 5,
            ..cfg_default()
        },
    );
    assert!(got.context_lines().is_empty());
}

#[test]
fn quit_after_bounds_reported_matches() {
    let got = run(
        b"a",
        b"a\na\na\na\n",
        Config {
            quit_after: Some(2),
            ..cfg_default()
        },
    );
    assert_eq!(got.matched_lines().len(), 2, "-m 2 reports two lines");
}

#[test]
fn a_sink_returning_false_stops_the_search() {
    // This is `-q`: the sink asks to stop, and the searcher honours it at
    // once rather than draining the buffer.
    let re = ByteRegex::new(b"a").unwrap();
    let s = Searcher::new(&re, cfg_default());
    let mut rec = QuitOnMatch(Recorded::default());
    let keep_going = s.search_slice(b"a\na\na\n", &mut rec).unwrap();
    assert!(!keep_going, "a false from the sink stops the search");
    assert_eq!(
        rec.0.matched_lines(),
        vec!["a\n"],
        "exactly one line reached the sink"
    );
}

#[test]
fn line_numbers_count_from_one() {
    let got = run(
        b"c",
        b"a\nb\nc\n",
        Config {
            line_numbers: true,
            ..cfg_default()
        },
    );
    assert_eq!(got.line_numbers, vec![Some(3)], "c is the third line");
}

/// The line number is tracked when anyone reads it and skipped when no one
/// does. Two halves:
///
/// 1. With context active (`-A`/`-B`/`-C`) the number is `Some` even when
///    `Config::line_numbers` is false, because the printer's `--` separator
///    groups lines by comparing consecutive numbers. Gating on the flag
///    alone is what made every line report `None` and the separator fire
///    between every pair.
/// 2. With no context and `line_numbers: false` the number is `None` and
///    the skip path saves `count_byte` — one SIMD pass per early-exit fill.
#[test]
fn line_numbers_are_reported_when_context_needs_them_and_skipped_otherwise() {
    // Half 1: context active — numbers must be present for the separator.
    let got = run(
        b"b",
        b"a\nb\n",
        Config {
            after: 1,
            ..Config::default()
        },
    );
    assert_eq!(
        got.line_numbers,
        vec![Some(2)],
        "with -A the separator needs the number even without -n"
    );

    // Half 2: no context, no display — the number is not tracked.
    let got = run(b"b", b"a\nb\n", cfg_default());
    assert_eq!(
        got.line_numbers,
        vec![None],
        "without -n or context the number is never counted"
    );

    // Half 2b: `line_numbers: true` — the number is present for display.
    let got = run(
        b"b",
        b"a\nb\n",
        Config {
            line_numbers: true,
            ..Config::default()
        },
    );
    assert_eq!(got.line_numbers, vec![Some(2)], "-n reports the number");
}

#[test]
fn binary_quit_ends_the_search_at_a_nul() {
    // `grep-searcher` looks for the binary byte in the first 64 KiB BEFORE it
    // searches anything, and a sink that does not override `binary_data` stops
    // the search there: nothing is reported at all, not even the matches that
    // sit before the byte. Two versions of this searcher got this wrong in
    // opposite directions, and the tests below are what caught them; the
    // differential in `differential.rs` is what settled it against the real
    // thing.
    let got = run(
        b"x",
        b"x\nx\n\0x\n",
        Config {
            binary: BinaryDetection::Quit(0),
            ..Config::default()
        },
    );
    assert!(
        got.matched_lines().is_empty(),
        "a NUL inside the first 64 KiB reports nothing, got {:?}",
        got.matched_lines()
    );
    assert_eq!(got.binary, Some(4), "the NUL offset is reported");
}

#[test]
fn binary_quit_searches_the_prefix_when_the_nul_is_past_the_probe() {
    // The 64 KiB window is the only place the byte is looked for up front.
    // Past it the search runs and stops at the line carrying the byte, so the
    // lines before it are searched -- which is what a binary file larger than
    // the window looks like.
    let mut hay = vec![b'x', b'\n'];
    hay.resize(crate::searcher::BINARY_PROBE + 1, b'y');
    hay.push(b'\0');
    hay.extend_from_slice(b"x\n");
    let got = run(
        b"x",
        &hay,
        Config {
            binary: BinaryDetection::Quit(0),
            ..Config::default()
        },
    );
    assert_eq!(got.matched_lines(), vec!["x\n"], "the line before the NUL");
    assert_eq!(got.binary, Some(BINARY_PROBE as u64 + 1));
}
#[test]
fn binary_quit_finds_nothing_when_no_line_precedes_the_nul() {
    // `binary1` in the reference is haystack `"\x00a"` -- NUL FIRST, then the
    // text -- with pattern `a` and `quit(0)`, and expects `byte count:0`.
    // (An earlier version of this test used `"a\0"`, which has the bytes in
    // the other order and is a different case entirely.) Nothing precedes the
    // NUL, so there is nothing to search.
    let got = run(
        b"a",
        b"\0a\n",
        Config {
            binary: BinaryDetection::Quit(0),
            ..Config::default()
        },
    );
    assert!(
        got.matched_lines().is_empty(),
        "the NUL precedes every byte, got {:?}",
        got.matched_lines()
    );
    assert_eq!(got.binary, Some(0));
}

#[test]
fn binary_quit_is_a_no_op_when_there_is_no_nul() {
    let got = run(
        b"alpha",
        b"alpha\nbeta\n",
        Config {
            binary: BinaryDetection::Quit(b'Z'),
            ..Config::default()
        },
    );
    assert_eq!(
        got.matched_lines(),
        vec!["alpha\n"],
        "no NUL, so the search is normal"
    );
    assert_eq!(got.binary, None);
}

#[test]
fn binary_convert_reports_the_nul_and_searches_the_bytes_as_they_are() {
    // `Convert` is rgx's rule for a path the user NAMED: the whole file is
    // searched and the offset of the NUL is reported. It does **not** turn
    // the NUL into a line terminator on the slice path.
    //
    // That is the reference's behaviour, and it is not symmetric between its
    // two paths: `grep-searcher`'s READER owns its buffer and rewrites the
    // byte in place (`fill` calls `replace_bytes`), while its SLICE path goes
    // through `core::detect_binary`, which finds the byte, records the offset
    // and returns without touching a thing. A slice search under `Convert`
    // therefore reports the NUL and searches the original bytes, and a NUL is
    // an ordinary byte to the line walker — it is `\n` that ends a line.
    //
    // This test used to assert the opposite, and the opposite is what made the
    // two engines disagree on a named binary file: the sink saw a newline
    // where the reference saw the NUL, and every line after the NUL came out
    // numbered one too high. Count, listing, exit status and `-a` all
    // matched, so no count-based gate saw it.
    let got = run(
        b"beta",
        b"alpha\n\0beta\n",
        Config {
            binary: BinaryDetection::Convert(0),
            ..Config::default()
        },
    );
    assert_eq!(
        got.matched_lines(),
        vec!["\0beta\n"],
        "the line reaches the sink with its NUL, the way the reference's does"
    );
    assert_eq!(got.binary, Some(6), "the NUL is still reported as binary");

    // And the line is ONE line, so the numbering after it is the numbering
    // the reference gives. This is the part that was wrong by one.
    let got = run(
        b"gamma",
        b"alpha\n\0beta\ngamma\n",
        Config {
            binary: BinaryDetection::Convert(0),
            line_numbers: true,
            ..Config::default()
        },
    );
    assert_eq!(
        got.matched_lines(),
        vec!["gamma\n"],
        "three lines, and the third is the third"
    );
    assert_eq!(
        got.line_numbers,
        vec![Some(3)],
        "the NUL is not a line boundary"
    );
}

#[test]
fn binary_none_treats_a_nul_as_an_ordinary_byte() {
    let got = run(b"beta", b"alpha\n\0beta\n", cfg_default());
    assert_eq!(got.matched_lines(), vec!["\0beta\n"]);
    assert_eq!(got.binary, None);
}

// --- before-context, which the first version of this searcher did not
//     emit at all. rgx's printer labels before-context differently from
//     after-context, so wiring the searcher without it made `-B` silently
//     wrong. These tests are why that is caught here rather than in rgx. ---

/// One thing a sink was told, flattened for easy assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    kind: ContextKind,
    line: Option<u64>,
    text: String,
}

/// A sink that records what it was told, in order.
struct Typed {
    seen: Vec<Seen>,
}

impl Sink for Typed {
    type Error = fmt::Error;

    fn matched(&mut self, m: &SinkMatch<'_>) -> Result<bool, fmt::Error> {
        self.seen.push(Seen {
            kind: ContextKind::Other,
            line: m.line_number,
            text: String::from_utf8_lossy(m.bytes).to_string(),
        });
        Ok(true)
    }

    fn context(&mut self, c: &SinkContext<'_>) -> Result<bool, fmt::Error> {
        self.seen.push(Seen {
            kind: c.kind,
            line: c.line_number,
            text: String::from_utf8_lossy(c.bytes).to_string(),
        });
        Ok(true)
    }

    fn finish(&mut self, _f: &SinkFinish<'_>) -> Result<(), fmt::Error> {
        Ok(())
    }
}

fn run_typed(pattern: &[u8], hay: &[u8], config: Config) -> Typed {
    let re = ByteRegex::new(pattern).unwrap();
    let s = Searcher::new(&re, config);
    let mut t = Typed { seen: Vec::new() };
    s.search_slice(hay, &mut t).expect("search");
    t
}

#[test]
fn quit_after_still_emits_the_after_context_of_the_last_match() {
    // rgx's `HitSink` documents this exact divergence against itself:
    // `rg -A 1 -m 1` prints two lines and the sink's early stop printed
    // one. The cause is not the sink -- it is WHEN the searcher stops. If
    // the searcher returns on the line that reached the limit, the after-
    // context of the final match is never emitted. `grep-searcher` sinks the
    // after-context first and stops after.
    let hay = b"needle\nafter1\nafter2\n";
    let t = run_typed(
        b"needle",
        hay,
        Config {
            after: 2,
            quit_after: Some(1),
            line_numbers: true,
            ..cfg_default()
        },
    );
    let texts: Vec<String> = t.seen.iter().map(|e| e.text.clone()).collect();
    assert_eq!(
        texts,
        vec![
            String::from("needle\n"),
            String::from("after1\n"),
            String::from("after2\n"),
        ],
        "the match and its full after-context, despite -m 1"
    );
    // A limit that exceeds the matches must not truncate anything.
    let t2 = run_typed(
        b"needle",
        hay,
        Config {
            after: 2,
            quit_after: Some(5),
            ..cfg_default()
        },
    );
    assert_eq!(t2.seen.len(), 3, "-m 5 with one match changes nothing");
}

#[test]
fn quit_after_with_before_context_emits_the_before_context_of_the_first_match() {
    let hay = b"before\nneedle\n";
    let t = run_typed(
        b"needle",
        hay,
        Config {
            before: 1,
            quit_after: Some(1),
            ..cfg_default()
        },
    );
    let kinds: Vec<ContextKind> = t.seen.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![ContextKind::Before, ContextKind::Other],
        "before-context then the match"
    );
}

#[test]
fn before_context_precedes_the_match_and_is_tagged_before() {
    let hay = b"a\nb\nc\nMATCH\nz\n";
    let t = run_typed(
        b"MATCH",
        hay,
        Config {
            before: 2,
            ..cfg_default()
        },
    );
    let got: Vec<(String, ContextKind, Option<u64>)> = t
        .seen
        .iter()
        .map(|e| (e.text.clone(), e.kind, e.line))
        .collect();
    assert_eq!(
        got,
        vec![
            (String::from("b\n"), ContextKind::Before, Some(2)),
            (String::from("c\n"), ContextKind::Before, Some(3)),
            (String::from("MATCH\n"), ContextKind::Other, Some(4)),
        ],
        "two before-context lines, oldest first, then the match"
    );
}

#[test]
fn before_context_respects_the_configured_count() {
    let hay = b"a\nb\nc\nd\nMATCH\n";
    let t = run_typed(
        b"MATCH",
        hay,
        Config {
            before: 1,
            ..cfg_default()
        },
    );
    // Only the line immediately before the match.
    assert_eq!(t.seen.len(), 2, "one before-context plus the match");
    assert_eq!(t.seen[0].text, "d\n");
    assert_eq!(t.seen[0].kind, ContextKind::Before);
}

#[test]
fn before_context_is_none_when_the_match_is_first() {
    let t = run_typed(
        b"MATCH",
        b"MATCH\nnext\n",
        Config {
            before: 3,
            ..cfg_default()
        },
    );
    assert_eq!(t.seen.len(), 1, "no preceding lines to report");
    assert_eq!(t.seen[0].kind, ContextKind::Other);
}

#[test]
fn before_and_after_context_are_tagged_distinctly() {
    let hay = b"a\nb\nMATCH\nc\nd\n";
    let t = run_typed(
        b"MATCH",
        hay,
        Config {
            before: 1,
            after: 1,
            ..cfg_default()
        },
    );
    let kinds: Vec<ContextKind> = t.seen.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![ContextKind::Before, ContextKind::Other, ContextKind::After],
        "before, match, after"
    );
}

#[test]
fn two_nearby_matches_do_not_reprint_the_shared_line() {
    // The line between two matches is one match's after-context and the
    // other's before-context. It must appear exactly once, tagged `After`
    // (it is emitted first, while scanning forward).
    let hay = b"M1\nmid\nM2\n";
    let t = run_typed(
        b"M[12]",
        hay,
        Config {
            before: 1,
            after: 1,
            ..cfg_default()
        },
    );
    let mid_count = t.seen.iter().filter(|e| e.text == "mid\n").count();
    assert_eq!(mid_count, 1, "the shared context line is reported once");
}

#[test]
fn before_context_carries_line_numbers_when_enabled() {
    // rgx's HitSink prints ctx.line_number(), so a `None` here would make
    // `-B -n` print line 0 for every context line.
    let hay = b"a\nb\nMATCH\n";
    let t = run_typed(
        b"MATCH",
        hay,
        Config {
            before: 2,
            line_numbers: true,
            ..cfg_default()
        },
    );
    let before: Vec<Option<u64>> = t
        .seen
        .iter()
        .filter(|e| e.kind == ContextKind::Before)
        .map(|e| e.line)
        .collect();
    assert_eq!(
        before,
        vec![Some(1), Some(2)],
        "a\n is line 1, b\n is line 2"
    );
}

/// A candidate source that reports every line start: a superset of any real
/// match offset, which is the worst case the contract permits.
/// A candidate source that reports EVERY offset, so it is a genuine superset
/// of any matcher's start offsets.
///
/// An earlier version of this test reported the position of each line
/// terminator, which is not a superset: a match can start mid-line
/// (`xxaxxaxxa` matches `a` at offset 2), and the terminator itself is not a
/// match start for a line's content. It happened to agree with the per-line
/// path only because the terminator used to count as part of the line. With
/// the terminator excluded, a stream that marks terminators covers no line at
/// all -- which is the test now earning its name.
struct EveryOffset;

impl CandidateSource for EveryOffset {
    fn candidates<'a>(&'a self, hay: &'a [u8], out: &'a mut Vec<usize>) -> Candidates<'a> {
        out.clear();
        out.extend(0..=hay.len());
        Candidates::of(out)
    }
}

/// A candidate source that reports nothing.
struct None2;

impl CandidateSource for None2 {
    fn candidates<'a>(&'a self, _hay: &'a [u8], out: &'a mut Vec<usize>) -> Candidates<'a> {
        out.clear();
        Candidates::of(out)
    }
}

#[test]
fn a_candidate_stream_finds_the_same_lines_as_the_per_line_path() {
    let hay = b"alpha\nbeta\ngamma\ndelta\n";
    let re = ByteRegex::new(b"delta").unwrap();
    let cands = EveryOffset;

    let mut plain = Recorded::default();
    Searcher::new(&re, cfg_default())
        .search_slice(hay, &mut plain)
        .unwrap();

    let mut via_cands = Recorded::default();
    Searcher::with_candidates(&re, &cands, cfg_default())
        .search_slice(hay, &mut via_cands)
        .unwrap();

    assert_eq!(plain.matched_lines(), via_cands.matched_lines());
    assert_eq!(plain.matched_lines(), vec!["delta\n"]);
}

#[test]
fn a_candidate_stream_that_reports_nothing_finds_nothing() {
    // The contract says a stream must be a SUPERSET, so an empty stream is
    // authoritative and legitimately finds nothing. This pins that the
    // searcher trusts the stream rather than double-checking it: a stream
    // that under-reports is a matcher bug, and the test records the
    // consequence instead of hiding it.
    let re = ByteRegex::new(b"beta").unwrap();
    let mut rec = Recorded::default();
    Searcher::with_candidates(&re, &None2, cfg_default())
        .search_slice(b"alpha\nbeta\n", &mut rec)
        .unwrap();
    assert!(rec.matched_lines().is_empty());
}

// --- the reader path and its roll buffer ---

/// A `Read`-shaped source over a byte slice, handing out at most `chunk`
/// bytes per call so the buffer boundary is exercised.
struct Chunks<'a> {
    data: &'a [u8],
    chunk: usize,
}

impl<'a> Chunks<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, fmt::Error> {
        if self.data.is_empty() {
            return Ok(0);
        }
        let n = core::cmp::min(core::cmp::min(buf.len(), self.chunk), self.data.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

#[test]
fn the_reader_path_agrees_with_the_slice_path_on_a_small_input() {
    // A haystack that fits in one buffer must produce the same lines either
    // way: the roll's first obligation is to change nothing until it has to.
    let hay = b"alpha\nbeta\ngamma\n";
    let re = ByteRegex::new(b"beta").unwrap();
    let cfg = cfg_default();

    let mut sliced = Recorded::default();
    Searcher::new(&re, cfg.clone())
        .search_slice(hay, &mut sliced)
        .unwrap();

    let mut lb = LineBuffer::new(&cfg);
    let mut src = Chunks {
        data: hay,
        chunk: 7,
    }; // 7 bytes: many fills
    let mut read = Recorded::default();
    let mut rd = |b: &mut [u8]| src.read(b);
    Searcher::new(&re, cfg)
        .search_reader(&mut rd, &mut read, &mut lb)
        .unwrap();

    assert_eq!(
        sliced.matched_lines(),
        read.matched_lines(),
        "one buffer, same lines"
    );
}

#[test]
fn a_match_across_a_buffer_boundary_survives_the_roll() {
    // The roll buffer exists so a needle straddling a fill is not lost.
    // With a 64 KiB buffer the needle is placed so it crosses the edge.
    let edge = 64 * 1024;
    let mut hay = vec![b'x'; edge - 2];
    hay.extend_from_slice(b"NEEDLE");
    hay.extend(core::iter::repeat_n(b'y', 200));

    let re = ByteRegex::new(b"NEEDLE").unwrap();
    let cfg = cfg_default();
    let mut lb = LineBuffer::new(&cfg);
    let mut src = Chunks {
        data: &hay,
        chunk: 8 * 1024,
    };
    let mut rec = Recorded::default();
    let mut rd = |b: &mut [u8]| src.read(b);
    Searcher::new(&re, cfg)
        .search_reader(&mut rd, &mut rec, &mut lb)
        .unwrap();

    assert!(
        rec.matched
            .iter()
            .any(|l| l.windows(6).any(|w| w == b"NEEDLE")),
        "a needle across a buffer boundary must still match; got {} lines",
        rec.matched.len()
    );
}

#[test]
fn the_reader_path_finds_many_lines_across_many_fills() {
    let mut hay = Vec::new();
    for i in 0..500 {
        hay.extend_from_slice(format!("line{i} alpha\n").as_bytes());
    }
    let re = ByteRegex::new(b"alpha").unwrap();
    let cfg = cfg_default();
    let mut lb = LineBuffer::new(&cfg);
    let mut src = Chunks {
        data: &hay,
        chunk: 1000,
    };
    let mut rec = Recorded::default();
    let mut rd = |b: &mut [u8]| src.read(b);
    Searcher::new(&re, cfg)
        .search_reader(&mut rd, &mut rec, &mut lb)
        .unwrap();
    assert_eq!(rec.matched.len(), 500, "every line across many fills");
}

#[test]
fn a_reader_binary_nul_stops_the_search_at_the_first_buffer() {
    // Under Quit the reader stops at the NUL, so a line after it in the
    // SAME fill is not searched either. This is the reader/slice difference
    // the module header claims: a slice is one buffer and sees it.
    let hay = b"alpha\nbeta\n\0gamma\n";
    let re = ByteRegex::new(b"beta").unwrap();
    let cfg = Config {
        binary: BinaryDetection::Quit(0),
        ..Config::default()
    };
    let mut lb = LineBuffer::new(&cfg);
    let mut src = Chunks {
        data: hay,
        chunk: 1000,
    };
    let mut rec = Recorded::default();
    let mut rd = |b: &mut [u8]| src.read(b);
    Searcher::new(&re, cfg)
        .search_reader(&mut rd, &mut rec, &mut lb)
        .unwrap();
    // `beta` sits before the NUL, so it is found; `gamma` after it is not.
    assert_eq!(rec.matched_lines(), vec!["beta\n"]);
}

/// A line longer than the initial buffer is still found, and the buffer
/// grows to hold it whole.
///
/// The buffer starts at 64 KiB and doubles, so a needle sitting across a
/// doubling boundary is only found if the reader keeps growing until the line
/// is complete. This is the case `MAX_BUF` is a backstop for, not a working
/// limit: a 3 MiB line must not be chopped into pieces.
#[test]
fn a_needle_in_a_line_longer_than_the_buffer_is_found() {
    let mut hay = vec![b'x'; 3 * 1024 * 1024];
    hay.extend_from_slice(b"NEEDLE");
    hay.extend(core::iter::repeat_n(b'y', 64));

    let re = ByteRegex::new(b"NEEDLE").unwrap();
    let cfg = cfg_default();
    let mut lb = LineBuffer::new(&cfg);
    let mut src = Chunks {
        data: &hay,
        chunk: 64 * 1024,
    };
    let mut rec = Recorded::default();
    let mut rd = |b: &mut [u8]| src.read(b);
    Searcher::new(&re, cfg)
        .search_reader(&mut rd, &mut rec, &mut lb)
        .unwrap();

    assert!(
        rec.matched
            .iter()
            .any(|l| l.windows(6).any(|w| w == b"NEEDLE")),
        "a needle in a 3 MiB line must be found; got {} lines",
        rec.matched.len()
    );
}

/// A match has to lie inside a line's CONTENT, not run into its terminator.
///
/// `grep-searcher` strips the terminator and matches the remainder, so a
/// pattern that can only be satisfied by the terminator matches nothing. With
/// the terminator left in range, `[^a-z]` matched the `\n` of every line and
/// the searcher reported a degenerate one-byte line -- and the reader
/// differential caught the line numbers drifting from there on.
///
/// The expectations here are `grep`'s, taken from the same cases in
/// `rgx-core`'s differential, which holds this engine to `grep-searcher`
/// directly.
#[test]
fn a_pattern_that_can_match_the_terminator_does_not_match_the_line() {
    // `[^a-z]` matches `\n`, but the match still has to be in the content.
    // `al pha` has a space, so it matches; `alpha` is all letters, so it does
    // not, even though its terminator would have satisfied the class.
    assert_eq!(
        run(b"[^a-z]", b"al pha\n", cfg_default()).matched_lines(),
        vec!["al pha\n".to_string()]
    );
    assert!(
        run(b"[^a-z]", b"alpha\nbeta\n", cfg_default())
            .matched_lines()
            .is_empty(),
        "an all-letter line must not match on its terminator"
    );
    assert_eq!(
        run(b"[^a-z]+", b"al pha\n", cfg_default()).matched_lines(),
        vec!["al pha\n".to_string()]
    );
}

/// A pattern satisfied ONLY by a terminator matches nothing, because the
/// terminator is not part of any line's content.
#[test]
fn a_pattern_that_is_only_the_terminator_matches_nothing() {
    let hay = b"alpha\nbeta\n";
    for pat in [&b"\n"[..], &b"alpha\n"[..]] {
        assert!(
            run(pat, hay, cfg_default()).matched_lines().is_empty(),
            "{:?} must not match a line",
            String::from_utf8_lossy(pat)
        );
    }
}

/// The boundary this change moved: a match may END on the last content byte,
/// and must not be pulled short of it.
///
/// `a` and `pha` both finish exactly at the end of `al pha`'s content, one
/// byte short of the terminator. Before the terminator was excluded they also
/// matched; after, a match running into it does not. Both have to keep
/// matching, or the rule has overshot.
///
/// (`a$` and `x*` would be the obvious additions, but each also tests a
/// separate gap: the in-house engine reads `$` as end-of-buffer where `grep`
/// reads end-of-line, and it short-circuits on a nullable pattern instead of
/// reporting its empty matches. `rgx-core`'s differential drives this
/// searcher with `grep`'s own matcher precisely so the three can be told
/// apart.)
#[test]
fn a_match_may_end_on_the_last_content_byte() {
    for pat in [&b"a"[..], &b"pha"[..], &b"al pha"[..]] {
        assert_eq!(
            run(pat, b"al pha\n", cfg_default()).matched_lines(),
            vec!["al pha\n".to_string()],
            "{:?} ends inside the line and must still match",
            String::from_utf8_lossy(pat)
        );
    }
    // And the byte before the terminator is reachable from the next line too,
    // so the boundary is not special-cased per line.
    assert_eq!(
        run(b"a", b"al pha\nal pha\n", cfg_default()).matched_lines(),
        vec!["al pha\n".to_string(), "al pha\n".to_string()]
    );
}

/// A greedy pattern that would swallow the terminator still matches the line.
///
/// The first cut at the terminator rule kept the whole buffer in range and
/// rejected any span reaching past the content. That is wrong for a greedy
/// pattern: `[^a-z]+` over `123\n` spans `123\n`, so the match was thrown away
/// even though `123` is a match inside the line, and every line whose content
/// was entirely non-letters went unreported. Cutting the terminator off before
/// matching lets the matcher's own greed stop in the right place.
#[test]
fn a_greedy_pattern_that_would_swallow_the_terminator_still_matches() {
    // A line that is entirely non-letters: the match reaches the end of the
    // content, and the terminator is the very next byte.
    for pat in [&b"[^a-z]+"[..], &b"[0-9]+"[..]] {
        assert_eq!(
            run(pat, b"123\n", cfg_default()).matched_lines(),
            vec!["123\n".to_string()],
            "{:?} over an all-non-letter line",
            String::from_utf8_lossy(pat)
        );
    }
    // Over mixed lines each pattern reaches only what it can: `[^a-z]+` finds a
    // non-letter in all three, `[0-9]+` only in the last.
    assert_eq!(
        run(b"[^a-z]+", b"al pha\nend-\n123\n", cfg_default()).matched_lines(),
        vec![
            "al pha\n".to_string(),
            "end-\n".to_string(),
            "123\n".to_string()
        ]
    );
    assert_eq!(
        run(b"[0-9]+", b"al pha\nend-\n123\n", cfg_default()).matched_lines(),
        vec!["123\n".to_string()]
    );
}

/// `^` and `$` anchor the LINE, as they do in `grep`.
///
/// They come for free with matching over the line's content: the matcher never
/// sees the terminator, and it only ever sees one line at a time, so the start
/// of the haystack it is given IS the start of the line. Handing it the
/// buffer instead made both anchors mean start-of-buffer, and `a$` and `^pub`
/// matched nothing at all.
#[test]
fn anchors_are_line_anchors() {
    assert_eq!(
        run(b"a$", b"al pha\nbetb\n", cfg_default()).matched_lines(),
        vec!["al pha\n".to_string()]
    );
    assert_eq!(
        run(b"^pub", b"  pub fn a\npub fn b\n", cfg_default()).matched_lines(),
        vec!["pub fn b\n".to_string()]
    );
    // And an anchor holds per line, not just at the top of the buffer.
    assert_eq!(
        run(b"^[0-9]", b"a\n1b\n2c\n", cfg_default()).matched_lines(),
        vec!["1b\n".to_string(), "2c\n".to_string()]
    );
}

/// A pattern that can match the EMPTY string matches every line, as in
/// `grep`.
///
/// The engine matched the empty string at every offset all along -- an earlier
/// version of the searcher simply refused to look, because `can_match` was
/// answering a different question. It returned "does this program need at
/// least one byte on some path", which is false for `x*`, and the searcher
/// read that as "there is nothing here to find" and reported zero lines. The
/// empty pattern was suppressed the same way, even though the engine matches
/// it at every offset and `empty_pattern_matches_everywhere` says so.
#[test]
fn a_nullable_pattern_matches_every_line() {
    for pat in [
        &b"x*"[..],
        &b"x?"[..],
        &b"x{0,3}"[..],
        &b"(x)*"[..],
        &b""[..],
    ] {
        let got = run(pat, b"abc\ndef\n", cfg_default()).matched_lines();
        assert_eq!(
            got,
            vec!["abc\n".to_string(), "def\n".to_string()],
            "{:?} matches empty, so it matches every line",
            String::from_utf8_lossy(pat)
        );
    }
    // A nullable prefix does not make the rest of the pattern optional: `x*y`
    // still needs a `y`.
    assert_eq!(
        run(b"x*y", b"abc\ny\nzz\n", cfg_default()).matched_lines(),
        vec!["y\n".to_string()]
    );
}

// --- the incremental candidate stream ---
//
// The stream exists so a buffer is scanned once and its candidates consumed in
// order, rather than each line re-deriving them. These tests pin the three
// things that can go wrong: the searcher going back to asking for a span per
// line, the cursor not advancing, and the every-offset supply disagreeing
// with a reported one.

/// A matcher that settles a line from the candidate offsets and records every
/// call to [`Matcher::find_span_at`].
///
/// The counter is the point. A searcher that asks for a span per line is
/// asking the matcher to scan the line again, which is the `lines x buffer`
/// cost the stream exists to remove, and it does so while returning perfectly
/// correct output -- so nothing else in this file would notice.
struct ConfirmsNeedle {
    needle: Vec<u8>,
    span_calls: core::sync::atomic::AtomicUsize,
}

impl ConfirmsNeedle {
    fn new(needle: &[u8]) -> Self {
        Self {
            needle: needle.to_vec(),
            // `AtomicUsize` (not `Cell`) so the test matcher is `Sync`,
            // which `Matcher: Send + Sync` requires.
            span_calls: core::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl Matcher for ConfirmsNeedle {
    fn find_at(&self, hay: &[u8], at: usize) -> Option<usize> {
        self.find_span_at(hay, at).map(|r| r.start)
    }

    fn find_span_at(&self, hay: &[u8], at: usize) -> Option<core::ops::Range<usize>> {
        use core::sync::atomic::Ordering;
        self.span_calls.fetch_add(1, Ordering::Relaxed);
        let n = self.needle.len();
        (at..hay.len().saturating_sub(n) + 1)
            .find(|&i| hay.get(i..i + n) == Some(&self.needle[..]))
            .map(|i| i..i + n)
    }

    fn is_match_at(&self, hay: &[u8], at: usize) -> bool {
        let n = self.needle.len();
        hay.get(at..at + n) == Some(&self.needle[..])
    }

    /// A six-byte literal cannot match the empty line, and saying so here
    /// rather than through the default keeps the default's one `find_span_at`
    /// out of `span_calls` -- the counter is the assertion, and a counter that
    /// also counts the searcher's own question is not a counter.
    fn matches_empty(&self) -> bool {
        false
    }

    fn any_match_in(&self, line: &[u8], cands: LineCandidates<'_>, origin: Origin) -> bool {
        let Origin::Fixed(origin) = origin else {
            return self.needle.is_empty();
        };
        let n = self.needle.len();
        cands.any(|at| {
            line.get(at.saturating_sub(origin)..at.saturating_sub(origin) + n)
                == Some(&self.needle[..])
        })
    }
}

#[test]
fn a_line_is_confirmed_from_the_stream_and_never_rescanned() {
    let mut hay = Vec::new();
    for i in 0..500 {
        hay.extend_from_slice(format!("line {i} is ordinary text\n").as_bytes());
    }
    hay.extend_from_slice(b"line 500 holds the needle\n");
    for i in 501..900 {
        hay.extend_from_slice(format!("line {i} is ordinary text\n").as_bytes());
    }

    let m = ConfirmsNeedle::new(b"needle");
    let mut rec = Recorded::default();
    Searcher::with_candidates(&m, &EveryOffset, cfg_default())
        .search_slice(&hay, &mut rec)
        .unwrap();

    assert_eq!(rec.matched_lines(), vec!["line 500 holds the needle\n"]);
    assert_eq!(
        m.span_calls.load(core::sync::atomic::Ordering::Relaxed),
        0,
        "the line was confirmed from the stream, so the matcher was never asked \
         to scan a line: the buffer is meant to be scanned once, not once per line"
    );
}

#[test]
fn the_stream_hands_each_offset_to_exactly_one_line() {
    // Candidates at line boundaries, several per line, and one on the last
    // byte of a line's content. Every offset must be yielded once, in order,
    // rebased to its own line -- a cursor that did not advance would either
    // repeat an offset or drop it.
    let offsets: Vec<usize> = vec![0, 1, 5, 6, 7, 12, 20];
    let lines: [(usize, usize); 4] = [(0, 6), (6, 12), (12, 20), (20, 25)];
    let mut cands = Candidates::of(&offsets);
    let mut flat: Vec<usize> = Vec::new();
    for (start, end) in lines {
        let rel: Vec<usize> = cands.in_line(start, end).collect();
        // Rebased, ascending, and every one inside the line that took it.
        assert!(
            rel.windows(2).all(|w| w[0] < w[1]) && rel.iter().all(|&o| o < end - start),
            "line {start}..{end} took {rel:?}"
        );
        flat.extend(rel.into_iter().map(|o| o + start));
    }
    flat.extend(cands.in_line(0, 40));
    assert_eq!(flat, offsets, "every offset, once, in ascending order");
}

#[test]
fn an_every_offset_stream_agrees_with_a_reported_one() {
    // `Candidates::every` is what a matcher with no prefilter hands over. It
    // must be indistinguishable from the explicit `0..len`, or the same search
    // would give different lines depending on which supply it was given.
    for len in [0usize, 1, 2, 7, 33, 64] {
        let reported: Vec<usize> = (0..len).collect();
        for start in 0..=len + 1 {
            for end in start..=len + 1 {
                let mut a = Candidates::of(&reported);
                let mut b = Candidates::every(len);
                let x: Vec<usize> = a.in_line(start, end).collect();
                let y: Vec<usize> = b.in_line(start, end).collect();
                assert_eq!(x, y, "len={len} start={start} end={end}");
                // And a later line must not see what an earlier one took.
                let later: Vec<usize> = b.in_line(end, len + 1).collect();
                let want: Vec<usize> = (end..len).map(|o| o - end).collect();
                assert_eq!(later, want, "len={len} start={start} end={end}");
            }
        }
    }
}

#[test]
fn a_byte_stream_agrees_with_a_reported_one() {
    // `Candidates::of_byte` is the DENSE supply: the offsets are found by
    // `memchr` as the line loop pulls them rather than written out up front,
    // which is the whole reason it exists. It therefore has to be
    // indistinguishable from an explicitly reported vector, or the same
    // search would give different lines depending on which supply it was
    // given -- and the vector is what every other supply reduces to.
    for len in [0usize, 1, 2, 7, 33, 64, 200] {
        for needle in [b'e', b'a', b'\n', 0xff] {
            let hay: Vec<u8> = (0..len)
                .map(|i| if i % 3 == 0 { needle } else { b'x' })
                .collect();
            let reported: Vec<usize> = crate::memchr::memchr_iter(needle, &hay).collect();
            for start in 0..=len + 1 {
                for end in start..=len + 1 {
                    let mut a = Candidates::of(&reported);
                    let mut b = Candidates::of_byte(&hay, needle);
                    let x: Vec<usize> = a.in_line(start, end).collect();
                    let y: Vec<usize> = b.in_line(start, end).collect();
                    assert_eq!(x, y, "len={len} needle={needle:#x} start={start} end={end}");
                    // `is_empty` is what the searcher actually reads, and it
                    // goes through `size_hint`, so it is checked on its own
                    // rather than inferred from the collected vector.
                    let mut c = Candidates::of_byte(&hay, needle);
                    let line = c.in_line(start, end);
                    assert_eq!(
                        line.is_empty(),
                        reported.iter().all(|&o| o < start || o >= end)
                    );
                    // And a later line must not see what an earlier one took,
                    // even if the caller abandoned the earlier stream.
                    let later: Vec<usize> = c.in_line(end, len + 1).collect();
                    let want: Vec<usize> = reported
                        .iter()
                        .copied()
                        .filter(|&o| o >= end)
                        .map(|o| o - end)
                        .collect();
                    assert_eq!(
                        later, want,
                        "len={len} needle={needle:#x} start={start} end={end}"
                    );
                }
            }
        }
    }
}

/// A line the byte supply finds nothing in must still be offered to the
/// matcher when the matcher is not the byte engine's -- and the shape that
/// breaks is a buffer whose only occurrence of the byte is ON a terminator,
/// which no line's content contains.
#[test]
fn a_byte_occurrence_on_the_terminator_is_not_a_candidate_for_the_line() {
    let hay = b"alpha\nbeta\n";
    let mut cands = Candidates::of_byte(hay, b'\n');
    // Contents, terminators cut off: line 1 is `alpha`, line 2 is `beta`.
    assert!(
        cands.in_line(0, 5).is_empty(),
        "line 1 has no newline in its content"
    );
    assert!(
        cands.in_line(6, 10).is_empty(),
        "line 2 has no newline in its content"
    );
    // The terminator bytes themselves are in the buffer, and a stream handed
    // the WHOLE buffer -- rather than the searcher's per-line windows -- does
    // find them. The difference is the point: the line windows are what stops
    // a terminator from confirming a line it belongs to neither end of.
    let mut whole = Candidates::of_byte(hay, b'\n');
    assert_eq!(whole.in_line(0, 11).collect::<Vec<_>>(), vec![5, 10]);
}

#[test]
fn a_match_has_to_fit_inside_the_line_that_offers_it() {
    // The confirm sees the line's CONTENT, not the buffer, so a candidate one
    // byte from the end cannot be confirmed by bytes that live past the
    // terminator. `needle` ending on the last content byte is the boundary
    // that must still work; the same bytes straddling a terminator must not.
    let re = ByteRegex::new(b"needle").unwrap();
    let mut at_end = Recorded::default();
    Searcher::with_candidates(&re, &re, cfg_default())
        .search_slice(b"a needle", &mut at_end)
        .unwrap();
    assert_eq!(at_end.matched_lines(), vec!["a needle"]);

    let mut straddle = Recorded::default();
    Searcher::with_candidates(&re, &re, cfg_default())
        .search_slice(b"xxneed\nle\n", &mut straddle)
        .unwrap();
    assert!(
        straddle.matched_lines().is_empty(),
        "a match may not run into the terminator; got {:?}",
        straddle.matched_lines()
    );
}

#[test]
fn a_matcher_with_no_prefilter_still_finds_every_line() {
    // `EveryOffset` is the supply a pattern with no literal fast path gets, and
    // it reaches the searcher through `ByteRegex` itself for any pattern with
    // a metacharacter. The two must not be able to disagree.
    let hay = b"alpha1\nbeta22\ngamma333\ndelta\n";
    for pat in [&b"[0-9]+"[..], &b"a.a"[..], &b"^be"[..], &b"a$"[..]] {
        let re = ByteRegex::new(pat).unwrap();
        let mut plain = Recorded::default();
        Searcher::new(&re, cfg_default())
            .search_slice(hay, &mut plain)
            .unwrap();
        let mut streamed = Recorded::default();
        Searcher::with_candidates(&re, &re, cfg_default())
            .search_slice(hay, &mut streamed)
            .unwrap();
        assert_eq!(
            plain.matched_lines(),
            streamed.matched_lines(),
            "{:?}",
            String::from_utf8_lossy(pat)
        );
    }
}

#[test]
fn the_reader_path_agrees_with_the_slice_path_with_a_stream() {
    // The stream is rebuilt per fill, so a needle that straddles one has to be
    // found in the fill that completes it. The same haystack both ways is the
    // only way to know the per-fill rebuild dropped and duplicated nothing.
    let mut hay = Vec::new();
    for i in 0..3000 {
        hay.extend_from_slice(format!("line {i} of the haystack\n").as_bytes());
    }
    for at in [0usize, 1, 60, 4095, 4096, 4097, 8191, 65535, 65536, 65537] {
        if at + 6 <= hay.len() {
            hay[at..at + 6].copy_from_slice(b"needle");
        }
    }
    // Adjacent offsets land on one line, and the search advances by the line,
    // so the count is of lines and not of planted offsets.
    const NEWLINE: u8 = 10;
    let lines_with_one = hay
        .split(|&b| b == NEWLINE)
        .filter(|l| l.windows(6).any(|w| w == b"needle"))
        .count();
    let re = ByteRegex::new(b"needle").unwrap();
    let cfg = cfg_default();

    let mut sliced = Recorded::default();
    Searcher::with_candidates(&re, &re, cfg.clone())
        .search_slice(&hay, &mut sliced)
        .unwrap();

    let mut lb = LineBuffer::new(&cfg);
    let mut src = Chunks {
        data: &hay,
        chunk: 4096,
    };
    let mut read = Recorded::default();
    let mut rd = |b: &mut [u8]| src.read(b);
    Searcher::with_candidates(&re, &re, cfg)
        .search_reader(&mut rd, &mut read, &mut lb)
        .unwrap();

    assert_eq!(sliced.matched_lines(), read.matched_lines());
    assert_eq!(
        sliced.matched.len(),
        lines_with_one,
        "every planted needle is found, and only on the line that holds it"
    );
    assert!(lines_with_one >= 5, "the fixture has to straddle fills");
}

#[test]
fn a_sparse_stream_over_many_lines_finds_every_needle() {
    // The shape that made the per-line rescan visible: many lines, very few
    // candidates, spread across the buffer. The stream has to be consumed in
    // order or a needle is lost.
    let mut hay = Vec::new();
    let mut want = 0;
    for i in 0..5000 {
        if i % 977 == 0 {
            hay.extend_from_slice(format!("line {i} needle here\n").as_bytes());
            want += 1;
        } else {
            hay.extend_from_slice(format!("line {i} ordinary text\n").as_bytes());
        }
    }
    let re = ByteRegex::new(b"needle").unwrap();
    let mut rec = Recorded::default();
    Searcher::with_candidates(&re, &re, cfg_default())
        .search_slice(&hay, &mut rec)
        .unwrap();
    assert_eq!(rec.matched.len(), want, "every sparse needle is reported");
}

// ---------------------------------------------------------------------------
// The per-buffer early exit.
//
// A skip is a pure speed change: delete it and every result is still correct.
// That is exactly why a differential suite CANNOT tell whether it ran, and
// why the assertion in every test below is on `Searcher::skipped_buffers`
// rather than only on the output. The output assertions are the safety half —
// they are what would catch a skip that dropped a buffer it should not — and
// the counter is the liveness half, which is the only thing that catches an
// optimisation that silently stopped existing.
//
// The trap this section is built around: a skip that drops a buffer which
// really does match is a FALSE NEGATIVE, and its failure mode is a MISSING
// RESULT, which no amount of aggregate-count checking will notice.
// ---------------------------------------------------------------------------

fn run_counted(pattern: &[u8], hay: &[u8], config: Config) -> (Recorded, u64) {
    let re = ByteRegex::new(pattern).unwrap();
    let s = Searcher::with_candidates(&re, &re, config);
    let mut rec = Recorded::default();
    s.search_slice(hay, &mut rec).expect("search");
    (rec, s.skipped_buffers())
}

fn run_reader_counted(pattern: &[u8], hay: &[u8], config: Config, chunk: usize) -> (Recorded, u64) {
    let re = ByteRegex::new(pattern).unwrap();
    let s = Searcher::with_candidates(&re, &re, config.clone());
    let mut rec = Recorded::default();
    let mut lb = LineBuffer::new(&config);
    let mut src = Chunks { data: hay, chunk };
    let mut read = |b: &mut [u8]| src.read(b);
    s.search_reader(&mut read, &mut rec, &mut lb)
        .expect("search");
    (rec, s.skipped_buffers())
}

/// A haystack of `lines` ordinary lines, with `needle` planted on the lines
/// whose index is in `at`. Big enough to fill many 64 KiB reader buffers.
fn sparse(lines: usize, at: &[usize]) -> Vec<u8> {
    let mut hay = Vec::new();
    for i in 0..lines {
        if at.contains(&i) {
            hay.extend_from_slice(format!("line {i} needle here\n").as_bytes());
        } else {
            hay.extend_from_slice(format!("line {i} ordinary text\n").as_bytes());
        }
    }
    hay
}

#[test]
fn a_buffer_the_anchor_finds_nothing_in_is_skipped() {
    let hay = b"alpha\nbeta\ngamma\n";
    let (rec, skipped) = run_counted(b"needle", hay, cfg_default());
    assert!(rec.matched_lines().is_empty());
    assert_eq!(skipped, 1, "the whole buffer was proven empty and skipped");
}

#[test]
fn a_buffer_the_anchor_finds_something_in_is_not_skipped() {
    // The other half of the same question, and the half a "skip everything
    // that looks empty" implementation gets wrong: a buffer that DOES match
    // must be walked, or the result is silently short.
    let (rec, skipped) = run_counted(b"beta", b"alpha\nbeta\ngamma\n", cfg_default());
    assert_eq!(rec.matched_lines(), vec!["beta\n"]);
    assert_eq!(skipped, 0, "a buffer holding the literal is never skipped");
}

#[test]
fn a_dense_buffer_is_never_skipped() {
    let hay = b"a\na\na\na\na\n";
    let (rec, skipped) = run_counted(b"a", hay, cfg_default());
    assert_eq!(rec.matched.len(), 5);
    assert_eq!(skipped, 0);
}

/// A pattern with NO required literal has no anchor to be absent, so the
/// mechanism does not apply to it at all. This is the "it works on this one"
/// case, and it is pinned so it cannot be published as "it works".
#[test]
fn a_pattern_with_no_required_literal_is_never_skipped() {
    // `a*b` has nothing every match must contain, so it streams `Supply::Every`
    // and the skip has nothing to ask. `a*bc` does, and is the contrast.
    assert!(!ByteRegex::new(b"a*b").unwrap().has_prefilter());
    assert!(ByteRegex::new(b"a*bc").unwrap().has_prefilter());
    let (rec, skipped) = run_counted(b"a*b", b"nothing here\nnor here\n", cfg_default());
    assert!(rec.matched_lines().is_empty());
    assert_eq!(
        skipped, 0,
        "a pattern with no required literal has no anchor to be absent"
    );
}

/// The one case where "no candidates in the buffer" is NOT "no match in the
/// buffer": a zero-length line. The line loop already asks the matcher about
/// an empty line by hand, because an empty line has no byte offsets to offer;
/// a skipped buffer never reaches that hand, so a nullable pattern has to be
/// excluded from the skip outright.
#[test]
fn a_pattern_that_matches_an_empty_line_is_never_skipped() {
    for pat in [&b"^"[..], b".*", b"x*", b"a?", b"", b"(a|)"] {
        let Ok(re) = ByteRegex::new(pat) else {
            continue;
        };
        let cfg = cfg_default();
        let s = Searcher::with_candidates(&re, &re, cfg);
        let mut rec = Recorded::default();
        s.search_slice(b"alpha\n\nbeta\n", &mut rec)
            .expect("search");
        assert_eq!(
            s.skipped_buffers(),
            0,
            "{:?} matches the empty line and must be walked",
            String::from_utf8_lossy(pat)
        );
        assert_eq!(
            rec.matched_lines(),
            vec!["alpha\n", "\n", "beta\n"],
            "{:?} must still report the blank line",
            String::from_utf8_lossy(pat)
        );
    }
}

#[test]
fn an_inverted_search_is_never_skipped() {
    // Under `-v` the non-matching lines ARE the output, so a buffer with no
    // candidate is a buffer with nothing to print — the opposite of the case
    // the skip exists for.
    let cfg = Config {
        invert: true,
        ..cfg_default()
    };
    let (rec, skipped) = run_counted(b"needle", b"alpha\nbeta\ngamma\n", cfg);
    assert_eq!(rec.matched_lines(), vec!["alpha\n", "beta\n", "gamma\n"]);
    assert_eq!(skipped, 0, "-v must walk every line");
}

/// After-context is owed by a match that has ALREADY happened, and the anchor
/// says nothing about it: the lines it will cover may hold no candidate at
/// all and still have to be printed.
#[test]
fn a_buffer_with_after_context_still_owed_is_not_skipped() {
    let hay = sparse(12000, &[0, 6000, 11999]);
    let cfg = Config {
        after: 5,
        ..cfg_default()
    };
    let (rec, skipped) = run_reader_counted(b"needle", &hay, cfg, 64 * 1024);
    let after: Vec<String> = rec
        .context
        .iter()
        .map(|b| String::from_utf8_lossy(b).to_string())
        .collect();
    // The match on line 1 owes five lines, and the SECOND fill opens while
    // they are still owed. Skipping that fill would print neither.
    assert_eq!(
        &after[..5],
        &[
            "line 1 ordinary text\n",
            "line 2 ordinary text\n",
            "line 3 ordinary text\n",
            "line 4 ordinary text\n",
            "line 5 ordinary text\n",
        ],
        "the after-context of the first match survives the early exit"
    );
    // The trailing ordinary fills hold nothing and owe nothing, so they are
    // skipped — which is what says the optimisation ran at all.
    assert!(
        skipped >= 1,
        "the trailing ordinary buffers must still be skipped"
    );
}

/// `-c` and `-l` are NOT excluded. A skipped buffer contributes zero matches,
/// which is the whole content of both answers, so excluding them would cost
/// the `-l` case for nothing. This pins that, because "be careful" here means
/// "do not exclude them", and an unstated permission reads as a prohibition.
#[test]
fn counting_and_quiet_are_unaffected_by_the_skip() {
    let hay = sparse(6000, &[4000, 4001, 4002]);

    // The count has to agree with a search that has no candidate stream at
    // all, which is the shape the skip is invisible to.
    let re = ByteRegex::new(b"needle").unwrap();
    let cfg = cfg_default();
    let mut filtered = Recorded::default();
    let s = Searcher::with_candidates(&re, &re, cfg.clone());
    s.search_slice(&hay, &mut filtered).expect("search");
    let mut plain = Recorded::default();
    Searcher::new(&re, cfg.clone())
        .search_slice(&hay, &mut plain)
        .expect("search");
    assert_eq!(filtered.matched.len(), 3);
    assert_eq!(plain.matched.len(), 3, "the skip changed the count");

    // `-q`: the answer is a boolean and a skipped buffer cannot flip it.
    let mut quiet = QuitOnMatch(Recorded::default());
    Searcher::with_candidates(&re, &re, cfg)
        .search_slice(&hay, &mut quiet)
        .expect("search");
    assert_eq!(quiet.0.matched.len(), 1, "-q stops at the first match");
}

/// The line counter is the trap that does not look like one. Every line of a
/// file is still printed and every number is right up to the gap — so an
/// off-by-N in the skip's line count is invisible to a line-COUNT check and
/// is a wrong answer all the same.
#[test]
fn line_numbers_survive_a_skipped_reader_buffer() {
    let hay = sparse(4000, &[3000, 3001]);
    let cfg = Config {
        line_numbers: true,
        ..cfg_default()
    };
    let (rec, skipped) = run_reader_counted(b"needle", &hay, cfg, 64 * 1024);
    assert!(
        skipped >= 1,
        "the fixture must produce at least one skippable buffer"
    );
    assert_eq!(
        rec.line_numbers,
        vec![Some(3001), Some(3002)],
        "the two needles are on lines 3001 and 3002 whatever was skipped"
    );
}

/// A slice is ONE buffer, so the early exit there is all-or-nothing: it takes
/// the whole file or none of it. That is worth 118 ms -> 5 ms on 235 MB for a
/// pattern that matches nothing, and exactly nothing for one that matches
/// once -- the per-64 KiB granularity only exists on the reader path.
#[test]
fn a_slice_is_skipped_whole_or_not_at_all() {
    let empty = sparse(4000, &[]);
    let (rec, skipped) = run_counted(
        b"needle",
        &empty,
        Config {
            line_numbers: true,
            ..cfg_default()
        },
    );
    assert!(rec.matched_lines().is_empty());
    assert_eq!(skipped, 1, "one buffer, no candidate, skipped whole");

    // The same file with one needle anywhere in it is not skipped at all, and
    // still reports that needle with its own line number.
    let one = sparse(4000, &[3000]);
    let (rec, skipped) = run_counted(
        b"needle",
        &one,
        Config {
            line_numbers: true,
            ..cfg_default()
        },
    );
    assert_eq!(skipped, 0, "one buffer, one candidate, walked");
    assert_eq!(rec.line_numbers, vec![Some(3001)]);
}

/// A final line with no terminator is a line, and a skipped buffer ending in
/// one has to count it — the `+1` in `count_lines`, which is exactly the
/// branch a "count the terminators" shortcut drops.
#[test]
fn a_skipped_buffer_with_no_final_newline_still_counts_its_last_line() {
    // A final line with no terminator is a line, and a skipped buffer ending
    // in one has to count it -- the `+1` in `count_lines`, which is exactly
    // the branch a "count the terminators" shortcut drops.
    let mut hay = Vec::new();
    for i in 0..2999 {
        hay.extend_from_slice(format!("ordinary line {i}\n").as_bytes());
    }
    assert_eq!(hay.iter().filter(|&&b| b == b'\n').count(), 2999);
    // Everything above is terminators, so the haystack is one skippable
    // buffer; the needle then lands on a 3000th line that has no terminator.
    hay.extend_from_slice(b"needle at the end");
    let cfg = Config {
        line_numbers: true,
        ..cfg_default()
    };
    let (rec, _) = run_counted(b"needle", &hay, cfg);
    assert_eq!(rec.matched_lines(), vec!["needle at the end"]);
    assert_eq!(rec.line_numbers, vec![Some(3000)]);
}

#[test]
fn an_empty_file_is_skipped_and_reports_nothing() {
    let (rec, skipped) = run_counted(b"needle", b"", cfg_default());
    assert!(rec.matched_lines().is_empty());
    // An empty buffer has no candidates, so the skip fires; the assertion that
    // matters is that nothing was reported and nothing panicked.
    assert_eq!(skipped, 1);
}

#[test]
fn a_one_byte_file_is_handled_either_way() {
    // The most degenerate buffer there is. It must not be skipped when it
    // holds the needle, and skipping it when it does not must be equally
    // uneventful.
    let (rec, skipped) = run_counted(b"needle", b"n", cfg_default());
    assert!(rec.matched_lines().is_empty());
    assert_eq!(skipped, 1);

    let (rec, skipped) = run_counted(b"n", b"n", cfg_default());
    assert_eq!(rec.matched_lines(), vec!["n"]);
    assert_eq!(skipped, 0, "a buffer holding the needle is never skipped");
}

/// The last byte of a buffer is where an off-by-one in the range would show
/// up as a match that is never offered to the confirm.
///
/// The one-byte needles get their own haystacks: `n` and `e` are everywhere in
/// English text, so a fixture built of words would match on the filler and the
/// assertion would be about the filler rather than about the boundary.
#[test]
fn a_match_on_the_last_byte_of_a_buffer_is_found() {
    for (pat, hay) in [
        (&b"needle"[..], &b"ordinary text needle"[..]),
        (b"ee", b"ordinary text needle"),
        (b"dle", b"ordinary text needle"),
        (b"n", b"qqqqqqqqqqqqn"),
        (b"e", b"qqqqqqqqqqqqe"),
    ] {
        let (rec, skipped) = run_counted(pat, hay, cfg_default());
        assert_eq!(
            rec.matched_lines(),
            vec![String::from_utf8_lossy(hay)],
            "pat={:?}",
            String::from_utf8_lossy(pat)
        );
        assert_eq!(skipped, 0, "pat={:?}", String::from_utf8_lossy(pat));
    }
    // And on the last line of a buffer whose lines are terminated.
    for pat in [&b"needle"[..], b"ee", b"dle"] {
        let (rec, skipped) = run_counted(pat, b"ordinary text\nneedle\n", cfg_default());
        assert_eq!(rec.matched_lines(), vec!["needle\n"]);
        assert_eq!(skipped, 0);
    }
}

/// A match straddling the 64 KiB fill boundary is found, and the fill before
/// it — which holds no part of the needle — is still skipped.
///
/// The fixture is built so the needle crosses offset 65536 while staying
/// INSIDE one line, which is the case that matters: a needle split across two
/// lines is not a match at all, so a fixture that does that proves nothing.
/// Forty-byte lines put the boundary in the middle of line 1638, and the
/// needle is written so its middle is the boundary.
#[test]
fn a_match_across_the_64_kib_fill_boundary_is_found() {
    let mut hay: Vec<u8> = Vec::new();
    let mut i = 0u32;
    // Forty-byte lines, so the 64 KiB fill boundary lands in the middle of a
    // line rather than cleanly between two.
    while hay.len() + 40 <= 65_534 {
        hay.extend_from_slice(format!("{i:0>39}\n").as_bytes());
        i += 1;
    }
    // Pad to 65534, which is 65536 - 2: the needle's THIRD byte is the first
    // byte of the next fill, and all six of it stay inside one line.
    let pad = 65_534 - hay.len();
    assert!((8..=39).contains(&pad), "the fixture drifted: pad={pad}");
    hay.resize(65_534, b'0');
    assert_eq!(hay.len(), 65_534);
    hay.extend_from_slice(b"needle\n");
    for _ in 0..5 {
        hay.extend_from_slice(b"trailing ordinary line\n");
    }

    let (rec, skipped) = run_reader_counted(b"needle", &hay, cfg_default(), 64 * 1024);
    assert_eq!(rec.matched.len(), 1, "the straddling needle was found");
    assert!(
        rec.matched[0].windows(6).any(|w| w == b"needle"),
        "the whole match is inside the reported line: {:?}",
        String::from_utf8_lossy(&rec.matched[0])
    );
    assert!(
        skipped >= 1,
        "the fill that ends before the needle holds none of it and is skipped"
    );
}

/// Before-context reaching back into a buffer that was skipped. The skipped
/// buffer's lines were never SUNK, so they are still owed, and this is the one
/// place where "nothing was reported here" has to mean "nothing has been
/// reported here YET" rather than "these lines are accounted for".
#[test]
fn before_context_reaches_back_into_a_skipped_buffer() {
    let mut hay = Vec::new();
    for i in 0..3000 {
        hay.extend_from_slice(format!("ordinary line {i}\n").as_bytes());
    }
    hay.extend_from_slice(b"needle here\n");
    let cfg = Config {
        before: 2,
        line_numbers: true,
        ..cfg_default()
    };
    let (rec, _) = run_reader_counted(b"needle", &hay, cfg, 64 * 1024);
    let before: Vec<String> = rec
        .context
        .iter()
        .map(|b| String::from_utf8_lossy(b).to_string())
        .collect();
    assert_eq!(
        before,
        vec!["ordinary line 2998\n", "ordinary line 2999\n"],
        "the two lines before the match, from the buffer that was skipped"
    );
    assert_eq!(rec.line_numbers, vec![Some(3001)]);
}

/// `--json` emits `begin`/`end` per FILE and its `end` carries the byte count.
/// A skipped buffer contributes no `match` event and must still advance the
/// count, which is the one thing about the mode the skip could break without
/// changing a single line of output.
#[test]
fn the_byte_count_covers_skipped_buffers() {
    let hay = sparse(4000, &[]);
    let re = ByteRegex::new(b"needle").unwrap();
    let s = Searcher::with_candidates(&re, &re, cfg_default());
    let mut rec = ByteCount(0);
    s.search_slice(&hay, &mut rec).expect("search");
    assert_eq!(rec.0, hay.len() as u64, "every byte is accounted for");
    assert_eq!(s.skipped_buffers(), 1);
}

/// A sink that only wants the total, which is what a `--json` `end` event and
/// a `--stats` line read.
struct ByteCount(u64);

impl Sink for ByteCount {
    type Error = fmt::Error;
    fn matched(&mut self, _: &SinkMatch<'_>) -> Result<bool, fmt::Error> {
        Ok(true)
    }
    fn context(&mut self, _: &SinkContext<'_>) -> Result<bool, fmt::Error> {
        Ok(true)
    }
    fn finish(&mut self, fin: &SinkFinish<'_>) -> Result<(), fmt::Error> {
        self.0 = fin.byte_count;
        Ok(())
    }
}

/// The end-to-end shape, on the reader: sparse needles, many fills, a skip on
/// most of them, and every needle still found with its own line number.
#[test]
fn a_sparse_reader_search_finds_every_needle_with_the_skip_active() {
    // One needle every 5000 lines over 40 000 of them: ~1.1 MB, so ~17 fills,
    // of which about half hold no needle at all.
    let at: Vec<usize> = (0..40_000).step_by(5000).collect();
    let hay = sparse(40_000, &at);
    let cfg = Config {
        line_numbers: true,
        ..cfg_default()
    };
    let (rec, skipped) = run_reader_counted(b"needle", &hay, cfg, 64 * 1024);
    assert_eq!(rec.matched.len(), at.len());
    for (i, line) in at.iter().enumerate() {
        assert_eq!(
            rec.line_numbers[i],
            Some(*line as u64 + 1),
            "needle #{i} on line {}",
            line + 1
        );
    }
    assert!(skipped >= 1, "the optimisation must actually have run");
}

// --- the per-candidate jump ---
//
// `grep-searcher` iterates CANDIDATES and locates the line each one sits in,
// so a line holding no candidate is never looked at. The jump makes the line
// walk do the same: ask the stream for the next candidate, move `pos` to that
// candidate's line, and popcount the lines in between. The line loop below the
// jump is unchanged, so a landed line is processed exactly as a walked-to line
// is, and the jump itself only ever moves `pos` forward to a line that holds a
// candidate.
//
// **The tests below come in two halves and the second half is the point.** A
// differential suite compares a jumped search against grep and reports nothing
// when the jump is merely ABSENT, because absent is correct. So each of these
// also asserts that the jump actually fired, through [`Searcher::jumped_gaps`]
// -- without which a jump that never ran would pass every one of them.

/// The same search twice over the same bytes: once with a candidate stream,
/// which is what turns the jump on, and once without one, which is the line
/// walk with no anchor to consult at all. Equal output is the contract; the
/// two counts are the jumped run's, for the caller to assert on.
fn jumped_and_walked(
    pattern: &[u8],
    hay: &[u8],
    config: Config,
    chunk: usize,
) -> (Recorded, u64, u64) {
    let re = ByteRegex::new(pattern).expect("the fixture patterns compile");
    let s = Searcher::with_candidates(&re, &re, config.clone());
    let mut jumped = Recorded::default();
    let mut lb = LineBuffer::new(&config);
    let mut src = Chunks { data: hay, chunk };
    let mut read = |b: &mut [u8]| src.read(b);
    s.search_reader(&mut read, &mut jumped, &mut lb)
        .expect("search");

    // `Searcher::new` has no candidate source, so `map_run` hands the line
    // loop `Candidates::every`, `has_anchor` is false, and the matcher is
    // asked at every line. That is the pre-jump searcher exactly.
    let plain = Searcher::new(&re, config.clone());
    let mut walked = Recorded::default();
    let mut lb = LineBuffer::new(&config);
    let mut src = Chunks { data: hay, chunk };
    let mut read = |b: &mut [u8]| src.read(b);
    plain
        .search_reader(&mut read, &mut walked, &mut lb)
        .expect("search");

    assert_eq!(
        jumped,
        walked,
        "the jump changed the answer for {:?}",
        String::from_utf8_lossy(pattern)
    );
    (jumped, s.jumped_gaps(), s.jumped_lines())
}

/// A fixture of `lines` numbered lines with exactly two needles on them. The
/// needles are what the jump lands on; the thousands of plain lines between
/// them are what it steps over.
fn two_needles(lines: usize, at: &[usize]) -> Vec<u8> {
    let mut hay = Vec::with_capacity(lines * 31);
    for i in 0..lines {
        if at.contains(&i) {
            hay.extend_from_slice(format!("line {i:0>24} needle\n").as_bytes());
        } else {
            hay.extend_from_slice(format!("line {i:0>24} plain \n").as_bytes());
        }
    }
    hay
}

#[test]
fn the_jump_agrees_with_the_line_walk_and_actually_fires() {
    // Both needles inside ONE 64 KiB fill. That is the case the per-BUFFER skip
    // cannot see -- the buffer holds a candidate, so it is walked in full -- and
    // it is why the fixture is 1700 lines of 37 bytes (62 900 B) rather than a
    // bigger file whose needles would land in different fills and be covered by
    // the older optimisation instead.
    let hay = two_needles(1700, &[10, 1600]);
    let cfg = Config {
        line_numbers: true,
        ..cfg_default()
    };
    let (rec, gaps, lines) = jumped_and_walked(b"needle", &hay, cfg, 64 * 1024);
    assert_eq!(rec.matched.len(), 2, "both needles survive the jump");
    assert_eq!(rec.line_numbers, vec![Some(11), Some(1601)]);
    assert!(gaps >= 1, "the jump must have fired: gaps={gaps}");
    assert!(
        lines > 1500,
        "two needles in one fill of 1700 lines means most were stepped over, got {lines}"
    );
}

#[test]
fn the_jump_fires_on_slice_searches() {
    let hay = two_needles(1700, &[10, 1600]);
    let cfg = Config {
        line_numbers: true,
        ..cfg_default()
    };
    let re = ByteRegex::new(b"needle").expect("pattern compiles");
    let s = Searcher::with_candidates(&re, &re, cfg);
    let mut jumped = Recorded::default();
    s.search_slice(&hay, &mut jumped).expect("search");
    assert_eq!(jumped.matched.len(), 2);
    assert_eq!(jumped.line_numbers, vec![Some(11), Some(1601)]);
    assert!(
        s.jumped_gaps() >= 1,
        "the jump must have fired on slice: gaps={}",
        s.jumped_gaps()
    );
    assert!(
        s.jumped_lines() > 1500,
        "two needles in 1700 lines means slice stepped over most lines, got {}",
        s.jumped_lines()
    );
}

#[test]
fn a_match_is_never_lost_or_duplicated_across_a_jump() {
    // Adjacent needles, so the jump fires between landings with an EMPTY gap:
    // the case where a jump that required a gap to make progress would sit
    // still, and one that reported a gap's lines would double them.
    let hay = two_needles(4000, &[0, 1, 2, 3, 3997, 3998, 3999]);
    let cfg = Config {
        line_numbers: true,
        ..cfg_default()
    };
    let (rec, gaps, _) = jumped_and_walked(b"needle", &hay, cfg, 64 * 1024);
    assert_eq!(rec.matched.len(), 7);
    assert_eq!(
        rec.line_numbers,
        vec![
            Some(1),
            Some(2),
            Some(3),
            Some(4),
            Some(3998),
            Some(3999),
            Some(4000)
        ]
    );
    assert!(gaps >= 1, "adjacent matches must still go through the jump");
}

/// The regression the differential found, kept as its own test because it is
/// the narrowest statement of the whole bug: a jumped-over line whose
/// terminator sits ABOVE the region being counted.
///
/// `count_lines` used to take `&buf[pos..]` and count the map from 0, which is
/// the right answer only while `pos` is 0. The jump calls it with `pos > 0` on
/// every gap, and the third line of a three-line file came back as the second:
/// every line present, every line right, the number wrong. The differential
/// caught it; this pins the shape so the next reader of `count_lines` does not
/// put it back.
#[test]
fn a_jumped_line_is_numbered_from_its_own_offset_not_the_buffers() {
    let hay = b"pub fn\npub f\npub fn";
    for chunk in [3usize, 6, 7, 12, 13, 19, 64] {
        let cfg = Config {
            line_numbers: true,
            ..cfg_default()
        };
        let re = ByteRegex::new(b"pub fn").unwrap();
        let s = Searcher::with_candidates(&re, &re, cfg.clone());
        let mut rec = Recorded::default();
        let mut lb = LineBuffer::new(&cfg);
        let mut src = Chunks { data: hay, chunk };
        let mut read = |b: &mut [u8]| src.read(b);
        s.search_reader(&mut read, &mut rec, &mut lb)
            .expect("search");
        assert_eq!(
            rec.line_numbers,
            vec![Some(1), Some(3)],
            "chunk={chunk}: the jumped line's number came from the wrong offset"
        );
    }
}

#[test]
fn before_and_after_context_survive_a_jump() {
    // The context machine keeps state that advances line by line, and the jump
    // is the one thing in this searcher that does not. `-A` in particular is
    // owed BY a match that already happened, so the jump stands down while any
    // of it is owed -- and the fixture puts the two matches far enough apart
    // that the second one's before-context reaches back over a jumped gap.
    for (before, after) in [(0usize, 0usize), (1, 0), (0, 1), (2, 2), (3, 1)] {
        let hay = two_needles(6000, &[100, 5000]);
        let cfg = Config {
            before,
            after,
            line_numbers: true,
            ..cfg_default()
        };
        let (rec, gaps, _) = jumped_and_walked(b"needle", &hay, cfg, 64 * 1024);
        assert_eq!(rec.matched.len(), 2, "before={before} after={after}");
        assert_eq!(
            rec.line_numbers,
            vec![Some(101), Some(5001)],
            "before={before} after={after}"
        );
        assert_eq!(
            rec.context.len(),
            2 * (before + after),
            "before={before} after={after}: a context run is the wrong length"
        );
        assert!(
            gaps >= 1,
            "before={before} after={after}: the jump never fired"
        );
    }
}

#[test]
fn context_around_a_jumped_gap_is_the_right_lines() {
    // Not just the right COUNT. The before-context of the second match is
    // reached by walking back over lines the jump stepped over, and those lines
    // were never SUNK, so they are still owed. A jump that advanced
    // `reported_upto` over its gap would print nothing here; one that advanced
    // it too little would print them twice.
    let hay = two_needles(3000, &[50, 2500]);
    let cfg = Config {
        before: 2,
        line_numbers: true,
        ..cfg_default()
    };
    let (rec, gaps, _) = jumped_and_walked(b"needle", &hay, cfg, 64 * 1024);
    assert!(gaps >= 1, "the jump must have fired");
    assert_eq!(rec.matched.len(), 2);
    let ctx: Vec<String> = rec.context_lines();
    assert_eq!(ctx.len(), 4, "two runs of two, oldest first: {ctx:?}");
    assert!(ctx[0].contains("48"), "line 49, not 49: {ctx:?}");
    assert!(ctx[1].contains("49"), "{ctx:?}");
    assert!(ctx[2].contains("2498"), "{ctx:?}");
    assert!(ctx[3].contains("2499"), "{ctx:?}");
}

#[test]
fn an_inverted_search_never_jumps_and_still_prints_everything() {
    // Under `-v` the NON-matching lines are the output, so a line with no
    // candidate is exactly the line that must be printed. This is the case
    // the per-BUFFER skip had to fix, and a jump that skipped
    // lines here would reintroduce it at a finer granularity: a silently short
    // `-v` that no line-count gate would catch, because every line it does
    // print is a line `grep` prints.
    for (before, after) in [(0usize, 0usize), (2, 0), (0, 2), (1, 1)] {
        let hay = two_needles(3000, &[10, 20, 2500]);
        let cfg = Config {
            invert: true,
            before,
            after,
            line_numbers: true,
            ..cfg_default()
        };
        let (rec, gaps, _) = jumped_and_walked(b"needle", &hay, cfg, 64 * 1024);
        assert_eq!(gaps, 0, "-v must never jump: before={before} after={after}");
        assert_eq!(rec.matched.len(), 2997, "before={before} after={after}");
        assert!(
            !rec.matched
                .iter()
                .any(|l| l.windows(6).any(|w| w == b"needle")),
            "-v printed a line that matches: {:?}",
            String::from_utf8_lossy(&rec.matched[0])
        );
    }
}

/// A pattern with NO required literal has no anchor, and the jump is not "less
/// useful" there: it does not exist. [`Candidates::has_anchor`] is what says
/// so, and this pins the answer and the reason together -- the walk still
/// reports every match, and the jump counter stays at zero.
#[test]
fn a_pattern_with_no_required_literal_is_explicitly_out_of_reach() {
    // `w*z` has nothing every match must contain, so there is no anchor to be
    // absent and there is nothing to jump TO. A fixture with an `x` and a `z`
    // far apart, so the pattern matches every line and the "found nothing"
    // answer cannot be mistaken for the "has no anchor" answer.
    let mut hay = Vec::new();
    for i in 0..2000 {
        hay.extend_from_slice(format!("row {i:0>8} quiet zone\n").as_bytes());
    }
    assert!(
        !ByteRegex::new(b"w*z").unwrap().has_prefilter(),
        "the fixture's premise: `w*z` requires nothing"
    );
    let (rec, gaps, jumped_lines) = jumped_and_walked(b"w*z", &hay, cfg_default(), 64 * 1024);
    assert_eq!(
        gaps, 0,
        "no anchor means no jump, not a jump that finds nothing"
    );
    assert_eq!(jumped_lines, 0);
    assert_eq!(
        rec.matched.len(),
        2000,
        "the walk still has to find them all, got {}",
        rec.matched.len()
    );
    // The contrast, so the assertions above are about this pattern and not
    // about a jump that is broken for everything. `needle` is a literal, so
    // it has an anchor, and a fixture with two of them in one fill leaves a
    // gap for the jump to step over.
    let sparse = two_needles(1700, &[10, 1600]);
    let (rec, gaps, _) = jumped_and_walked(b"needle", &sparse, cfg_default(), 64 * 1024);
    assert_eq!(rec.matched.len(), 2);
    assert!(gaps >= 1, "`needle` has an anchor and must jump");
}

#[test]
fn a_nullable_pattern_is_explicitly_out_of_reach() {
    // A zero-length line has no byte offsets at all, so no candidate can ever
    // point at it -- and every nullable pattern matches one. A jump would step
    // over exactly the lines the answer depends on, and the lines it would step
    // over here are the blank ones a fixture full of numbered text never has.
    let mut hay = two_needles(2000, &[5, 1500]);
    // Fifty blank lines, because a blank line is the only line with no byte
    // offsets in it and therefore the only line a jump could step over by
    // accident. A fixture of numbered text has none, and would pass a broken
    // jump for the wrong reason.
    for i in 0..50 {
        hay.extend_from_slice(format!("blank filler {i}\n\n").as_bytes());
    }
    for pat in [&b"^"[..], b".*", b"a?", b"(a|)"] {
        let cfg = Config {
            line_numbers: true,
            ..cfg_default()
        };
        let (rec, gaps, _) = jumped_and_walked(pat, &hay, cfg, 64 * 1024);
        assert_eq!(
            gaps,
            0,
            "{:?} must never jump",
            String::from_utf8_lossy(pat)
        );
        // Every line, blank ones included, is a match for every one of these.
        assert_eq!(
            rec.matched.len(),
            2100,
            "{:?}",
            String::from_utf8_lossy(pat)
        );
        assert!(
            rec.matched.iter().any(|l| l == b"\n"),
            "{:?} lost the blank lines",
            String::from_utf8_lossy(pat)
        );
    }
}

#[test]
fn a_file_with_no_final_newline_is_numbered_through_its_last_line() {
    let mut hay = two_needles(3000, &[1, 2999]);
    // Strip the terminator: the last line is now a line with no terminator,
    // which is the branch a "count the terminators" shortcut drops.
    let last = hay.len() - 1;
    assert_eq!(hay[last], b'\n');
    // The last line is reported WITHOUT a terminator, because there is none:
    // that is the whole shape of the case.
    let tail = hay[last - 36..last].to_vec();
    hay.truncate(last);
    let cfg = Config {
        line_numbers: true,
        ..cfg_default()
    };
    let (rec, gaps, _) = jumped_and_walked(b"needle", &hay, cfg, 64 * 1024);
    assert!(gaps >= 1, "the jump must have fired");
    assert_eq!(rec.matched.len(), 2);
    assert_eq!(rec.line_numbers, vec![Some(2), Some(3000)]);
    assert_eq!(
        rec.matched[1], tail,
        "the final unterminated line is reported whole"
    );
}

#[test]
fn an_empty_file_and_a_one_byte_file_are_both_uneventful() {
    for (hay, expect) in [
        (&b""[..], 0usize),
        (b"n", 0),
        (b"needle", 1),
        (b"\n", 0),
        (b"\n\n", 0),
    ] {
        let cfg = Config {
            line_numbers: true,
            ..cfg_default()
        };
        let (rec, _, _) = jumped_and_walked(b"needle", hay, cfg, 64 * 1024);
        assert_eq!(rec.matched.len(), expect, "hay={hay:?}");
    }
    // A one-byte file whose single byte IS the needle: the jump has a
    // candidate at offset 0 and no line after it, so it has nothing to step
    // over and must still report the line.
    let cfg = Config {
        line_numbers: true,
        ..cfg_default()
    };
    let (rec, gaps, _) = jumped_and_walked(b"n", b"n", cfg, 64 * 1024);
    assert_eq!(rec.matched, vec![b"n".to_vec()]);
    assert_eq!(rec.line_numbers, vec![Some(1)]);
    assert_eq!(gaps, 0, "there is no line to step over");
}

#[test]
fn a_match_on_the_last_byte_of_the_buffer_is_found() {
    // The candidate sits at the final byte, so there is no terminator above it
    // and the line ends at the buffer's end with none. A range check written
    // `< limit` rather than `<= limit` drops this match, silently.
    for (pat, hay) in [
        (&b"needle"[..], &b"ordinary text needle"[..]),
        (b"ee", b"ordinary text needle"),
        (b"dle", b"ordinary text needle"),
        (b"n", b"qqqqqqqqqqqqn"),
        (b"e", b"qqqqqqqqqqqqe"),
    ] {
        let cfg = Config {
            line_numbers: true,
            ..cfg_default()
        };
        let (rec, _, _) = jumped_and_walked(pat, hay, cfg, 64 * 1024);
        assert_eq!(
            rec.matched,
            vec![hay.to_vec()],
            "pat={:?}",
            String::from_utf8_lossy(pat)
        );
        assert_eq!(rec.line_numbers, vec![Some(1)]);
    }
}

#[test]
fn a_match_across_the_64_kib_fill_boundary_is_found_by_the_jump() {
    // Forty-byte lines, so the boundary lands in the middle of a line, and the
    // needle is written so its middle IS the boundary -- all six bytes inside
    // one line, because a needle split across two lines is not a match at all
    // and a fixture that did that would prove nothing.
    let mut hay: Vec<u8> = Vec::new();
    let mut i = 0u32;
    while hay.len() + 40 <= 65_534 {
        hay.extend_from_slice(format!("{i:0>39}\n").as_bytes());
        i += 1;
    }
    let pad = 65_534 - hay.len();
    assert!((8..=39).contains(&pad), "the fixture drifted: pad={pad}");
    hay.resize(65_534, b'0');
    hay.extend_from_slice(b"needle\n");
    for i in 0..8 {
        hay.extend_from_slice(format!("trailing ordinary line {i:0>8}\n").as_bytes());
    }
    // A second needle well after the boundary, so the fill holding the
    // straddling one has a GAP in it and the jump fires there. Without it the
    // first fill holds no candidate at all and is covered by the per-BUFFER
    // skip, which is a different optimisation and would leave this test
    // asserting nothing about the jump.
    hay.extend_from_slice(b"needle\n");
    for i in 0..8 {
        hay.extend_from_slice(format!("more ordinary line {i:0>10}\n").as_bytes());
    }
    let cfg = Config {
        line_numbers: true,
        ..cfg_default()
    };
    let (rec, gaps, _) = jumped_and_walked(b"needle", &hay, cfg, 64 * 1024);
    assert_eq!(rec.matched.len(), 2, "both needles are found");
    assert!(
        rec.matched[0].windows(6).any(|w| w == b"needle"),
        "the whole match is inside the reported line: {:?}",
        String::from_utf8_lossy(&rec.matched[0])
    );
    assert!(gaps >= 1, "the jump must have fired somewhere in this file");
}

#[test]
fn before_context_reaches_back_across_a_jumped_gap() {
    // The lines a jump stepped over were never SUNK, so a later match's
    // before-context walk still owes them. The gap here is the whole file
    // between the first fill and the needle.
    let mut hay = two_needles(4000, &[]);
    hay.extend_from_slice(b"needle at the end\n");
    let cfg = Config {
        before: 2,
        line_numbers: true,
        ..cfg_default()
    };
    let (rec, gaps, _) = jumped_and_walked(b"needle", &hay, cfg, 64 * 1024);
    assert!(gaps >= 1, "the jump must have fired");
    let ctx = rec.context_lines();
    assert_eq!(ctx.len(), 2, "the two lines before the match: {ctx:?}");
    assert!(ctx[0].contains("3998"), "the wrong line: {ctx:?}");
    assert!(ctx[1].contains("3999"), "the wrong line: {ctx:?}");
    assert_eq!(rec.line_numbers, vec![Some(4001)]);
}

#[test]
fn the_byte_count_covers_jumped_regions() {
    // `byte_count` is what a `--json` `end` event carries. A jump steps over
    // bytes it never reports, and the count has to include them: in that mode it
    // is the only number the optimisation could change without changing a
    // single line of output.
    let hay = two_needles(5000, &[0, 2500, 4999]);
    for chunk in [31usize, 512, 4096, 64 * 1024] {
        let re = ByteRegex::new(b"needle").unwrap();
        let cfg = cfg_default();
        let s = Searcher::with_candidates(&re, &re, cfg.clone());
        let mut bc = ByteCount(0);
        let mut lb = LineBuffer::new(&cfg);
        let mut src = Chunks { data: &hay, chunk };
        let mut read = |b: &mut [u8]| src.read(b);
        s.search_reader(&mut read, &mut bc, &mut lb)
            .expect("search");
        assert_eq!(bc.0, hay.len() as u64, "chunk={chunk}");
    }
}

#[test]
fn counting_is_unaffected_by_the_jump() {
    // `-c`: a stepped-over line contributes zero, which is the whole content of
    // the answer, so the count is the number of LANDED matches and nothing
    // else. The comparison is against the walk, which is the definition here.
    let hay = two_needles(6000, &[1000, 1001, 4000]);
    let cfg = Config {
        count: true,
        line_numbers: true,
        ..cfg_default()
    };
    let re = ByteRegex::new(b"needle").unwrap();

    let s = Searcher::with_candidates(&re, &re, cfg.clone());
    let mut rec = Recorded::default();
    let mut lb = LineBuffer::new(&cfg);
    let mut src = Chunks {
        data: &hay,
        chunk: 64 * 1024,
    };
    let mut read = |b: &mut [u8]| src.read(b);
    s.search_reader(&mut read, &mut rec, &mut lb)
        .expect("search");
    assert_eq!(rec.matched.len(), 0, "-c suppresses matched()");
    assert!(s.jumped_gaps() >= 1, "the jump must have fired");
    assert!(
        s.jumped_lines() > 0,
        "and it must have stepped over something"
    );

    // The byte count is the one number a jump can change without changing a
    // line of output, so it is compared against the walk rather than asserted
    // against a constant.
    let plain = Searcher::new(&re, cfg.clone());
    let mut bc = ByteCount(0);
    let mut lb = LineBuffer::new(&cfg);
    let mut src = Chunks {
        data: &hay,
        chunk: 64 * 1024,
    };
    let mut read = |b: &mut [u8]| src.read(b);
    plain
        .search_reader(&mut read, &mut bc, &mut lb)
        .expect("search");
    assert_eq!(
        bc.0,
        hay.len() as u64,
        "the walk counted the whole file and the jump must agree"
    );
}

/// **A match mask answers the line from its bits, and nothing else does.**
///
/// The matcher here says no to everything: `any_match_in` is the confirm the
/// shortcut replaces, and it is hard-wired to `false`. So every line this
/// reports was settled from the map alone, and every line it does not report
/// had no bit it was allowed to read -- which is the claim in one test. The
/// three shapes that make it bite are the three the cut has to get right:
///
/// - `pub `, four bytes ending a line, which the mask does NOT report: the
///   letter it needs is the terminator's position and the terminator is not a
///   letter;
/// - `fn x`, four bytes ending a line, which it DOES, and which a cut at the
///   mask's widest branch (five) would lose -- the differential has a fixture
///   for exactly that line;
/// - `pub x` and `xfn x`, where the match starts one byte in, so a cut
///   measured from the START of the line rather than from its end would lose
///   them.
struct DeafMatcher(ByteRegex);

impl crate::matcher::Matcher for DeafMatcher {
    fn find_at(&self, hay: &[u8], at: usize) -> Option<usize> {
        self.0.find_at(hay, at)
    }
    fn find_span_at(&self, hay: &[u8], at: usize) -> Option<core::ops::Range<usize>> {
        self.0.find_span_at(hay, at)
    }
    fn is_match_at(&self, hay: &[u8], at: usize) -> bool {
        self.0.is_match_at(hay, at)
    }
    /// The line this test is about: a confirm that always says no.
    fn any_match_in(&self, _line: &[u8], _cands: LineCandidates<'_>, _origin: Origin) -> bool {
        false
    }
}

impl CandidateSource for DeafMatcher {
    fn candidates<'b>(&'b self, hay: &'b [u8], out: &'b mut Vec<usize>) -> Candidates<'b> {
        self.0.candidates(hay, out)
    }
    fn map_candidates(&self, hay: &[u8], out: &mut crate::scan::BitMap) -> Option<Origin> {
        self.0.map_candidates(hay, out)
    }
    fn map_is_match_mask(&self, hay: &[u8]) -> Option<(usize, usize)> {
        self.0.map_is_match_mask(hay)
    }
}

#[test]
fn a_match_mask_settles_a_line_from_its_bits_with_no_confirm() {
    let hay = b"pub \nfn x\npub y\nfn\nxpub \nfn  x\npub x\nxfn x\nfn x\n";
    let re = ByteRegex::new(b"(pub|fn) [a-z]+").unwrap();
    let m = DeafMatcher(re);
    // The premise, stated so a failure below says which half broke: this mask
    // is CUTTABLE and is four wide, and the searcher is therefore entitled to
    // answer from the bits rather than from the confirm.
    assert_eq!(
        m.map_is_match_mask(hay),
        Some((4, 5)),
        "the source has to offer the cut (4, the `fn ` branch) and the span \
         (5, the `pub ` branch) for this test to mean anything"
    );
    // The READER path, which is the one that fills the two maps. The slice
    // path takes the candidate LIST and never asks.
    let cfg = cfg_default();
    let mut rec = Recorded::default();
    let mut lb = LineBuffer::new(&cfg);
    let mut src = Chunks {
        data: hay,
        chunk: 64 * 1024,
    };
    let mut read = |b: &mut [u8]| src.read(b);
    Searcher::with_candidates(&m, &m, cfg)
        .search_reader(&mut read, &mut rec, &mut lb)
        .expect("search");
    assert_eq!(
        rec.matched_lines(),
        vec!["fn x\n", "pub y\n", "pub x\n", "xfn x\n", "fn x\n"],
        "only lines holding a bit that a whole match fits in"
    );
}

#[test]
fn a_line_shorter_than_the_mask_offers_nothing_and_one_exactly_its_width_offers_one_bit() {
    // A hand-built map rather than a mask's: the point is what the STREAM does
    // with a bit that is in the disputed band, and a mask this engine builds
    // never puts one there (that is the argument `line_cut` makes), so the case
    // has to be made by hand or not at all.
    let hay = b"xxxxxxx\nxxxxxxx\n";
    let mut bits = crate::scan::BitMap::new();
    crate::scan::byte_bits(b"xxx", 1, hay, &mut bits);
    assert!(bits.any_set(0, 4), "the map is a bit set at every `x`");

    let mut c = Candidates::of_mask(&bits, 4, 4);
    assert!(c.decides(), "a cuttable mask settles its lines");
    assert_eq!(c.mask_width(), 4);
    // A line exactly the mask's width: the bits in its last three bytes could
    // hold a match that runs into the terminator, so the only one that can is
    // the first, and it is offered.
    assert_eq!(c.in_line(0, 4).collect::<Vec<_>>(), vec![0]);
    // Three bytes is one short of the width, so the line cannot match and the
    // stream says so with an empty range rather than a backward one.
    assert_eq!(c.in_line(0, 3).collect::<Vec<_>>(), vec![]);
    // A blank line, which is `start == end` and the shape that made this
    // worth a `max`.
    assert_eq!(c.in_line(0, 0).collect::<Vec<_>>(), vec![]);
    // A seven-byte line keeps every bit but the last three, and the offsets
    // are relative to the line: the searcher confirms against the line's own
    // bytes.
    assert_eq!(c.in_line(0, 7).collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    // And the cursor moved on, so the second line -- the same shape -- is
    // answered from its own bits rather than from the first line's.
    assert_eq!(c.in_line(8, 15).collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    // A stream with no mask is untouched by any of this.
    let mut plain = Candidates::of_bits(&bits);
    assert!(!plain.decides());
    assert_eq!(plain.in_line(0, 4).collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    assert_eq!(plain.in_line(0, 0).collect::<Vec<_>>(), vec![]);
}

/// A terminator map too short for the range being counted must not be read
/// out of bounds — and this is a regression test for a real segfault, not a
/// shape check.
///
/// `count_set_in` reaches an AVX2 body loop that indexes the word slice
/// through a raw pointer, so its caller has to prove the range is covered.
/// The scalar sibling cannot prove that need, because `get(..).unwrap_or(0)`
/// turns an out-of-range index into a zero and keeps going; the vector path
/// dereferences and dies. That gap let the reader path's lazy per-buffer skip
/// pass `Some(&[])` — an empty map standing in for "no map" — for any buffer
/// over `MAX_BITMAP_INPUT`, and counting a 327 KB region against a
/// zero-length slice is an access violation on every byte index past the end.
///
/// What this holds down is the invariant, not the number: an under-length map
/// must produce the SAME answer as having no map at all, which is the
/// `scan::count_byte` fallback over the same region.
#[test]
fn a_terminator_map_too_short_to_cover_the_region_falls_back_instead_of_reading_past_it() {
    let term = b'\n';

    // A region with a known number of terminators: 512 bytes, 32 of them.
    let mut buf = vec![b'x'; 512];
    for i in 0..32 {
        buf[i * 16] = term;
    }

    // The correct answer, from the no-map path.
    let expected = Core::count_lines(&buf, 0, buf.len(), term, None);
    assert_eq!(
        expected, 33,
        "32 terminators plus the trailing unterminated line"
    );

    // A REAL map over the same bytes, built the way the searcher builds it.
    // It has to be a real map and not a zero-filled buffer of the right
    // length: a zero map says "no terminators anywhere", which is a
    // different claim about the data and would disagree for the right reason.
    let mut bm = crate::scan::BitMap::new();
    crate::scan::term_bits(term, &buf, &mut bm);
    let full = bm.words();
    assert_eq!(
        full.len(),
        buf.len().div_ceil(64),
        "the map covers the buffer"
    );
    assert_eq!(
        Core::count_lines(&buf, 0, buf.len(), term, Some(full)),
        expected,
        "a map long enough must agree with the no-map path"
    );

    // Maps that do NOT cover it must not be indexed, and must still agree.
    // Empty is the case that crashed; the short ones are the same bug waiting
    // for a different region length.
    for len in [0usize, 1, 2, 4, 7] {
        let short = alloc::vec![0u64; len];
        assert_eq!(
            Core::count_lines(&buf, 0, buf.len(), term, Some(&short)),
            expected,
            "a {len}-word map must not be read past its end and must agree \
             with the no-map path"
        );
    }

    // And the same for an offset region, which is the per-candidate jump's
    // shape and the one that actually crashed (`from > 0`).
    for len in [0usize, 1, 3, 6] {
        let short = alloc::vec![0u64; len];
        assert_eq!(
            Core::count_lines(&buf, 256, buf.len(), term, Some(&short)),
            Core::count_lines(&buf, 256, buf.len(), term, None),
            "an offset region over a {len}-word map must agree with no map"
        );
    }
}

/// `drop` is an AMOUNT DROPPED, so with no `Core` nothing is owed and
/// everything is dropped. Spelling that as `0` retained the whole buffer --
/// every fill rolled the entire prior buffer forward and appended to it, and
/// a file with no early match grew to `LineBuffer::MAX_BUF` and lost both bit
/// maps on every later fill. The `None` arm is the one with no visible
/// symptom until a file crosses `MAX_BITMAP_INPUT`, which is why it is
/// asserted directly rather than only through a search.
#[test]
fn no_core_drops_the_whole_buffer_rather_than_retaining_it() {
    let buf: Vec<u8> = alloc::vec![b'x'; 4096];
    // The invariant: retained = seen.len() - drop, and with no Core the
    // retained region must be ZERO.
    let drop = drop_before_next_fill(None, &buf, 0);
    assert_eq!(
        drop,
        buf.len(),
        "with no Core nothing is owed, so the whole buffer must be dropped; \
         retained = seen.len() - drop would otherwise be the whole buffer"
    );
    assert_eq!(
        buf.len() - drop,
        0,
        "nothing may be retained before the first match"
    );
    // An empty buffer is fine and must stay exact.
    assert_eq!(drop_before_next_fill(None, &[], 0), 0);
    // Any max_context value is irrelevant without a Core: there is no
    // before-context window to honour yet.
    for ctx in [0usize, 1, 4, 64] {
        assert_eq!(
            drop_before_next_fill(None, &buf, ctx),
            buf.len(),
            "max_context={ctx} must not change the no-Core answer"
        );
    }
}

/// Codepoint length from a lead byte. A stray byte counts as one codepoint,
/// which is how `grep` treats invalid UTF-8.
fn utf8_len(b: u8) -> usize {
    match b {
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

/// A [`UnicodeMatcher`] with grep's codepoint semantics for `e.{2}`, holding
/// a counter borrowed from the test.
///
/// The contract under test is a ROUTING contract -- a mask bit is the byte
/// engine's answer and a non-ASCII line must still reach the delegate -- so
/// the test asserts the delegate was ASKED, not only what it answered. A
/// mock that only scripted its answers would pass even if the settle spoke
/// for the line and the delegate were never called.
struct AskedDelegate<'a> {
    asked: &'a core::sync::atomic::AtomicUsize,
}

impl crate::hybrid::UnicodeMatcher for AskedDelegate<'_> {
    /// The leftmost match at or after `at` of `e` followed by two codepoints.
    fn find_span(&self, line: &[u8], at: usize) -> Option<core::ops::Range<usize>> {
        self.asked
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let mut i = at;
        while i < line.len() {
            if line[i] == b'e' {
                let mut j = i + 1;
                let mut whole = true;
                for _ in 0..2 {
                    if j >= line.len() {
                        whole = false;
                        break;
                    }
                    let n = utf8_len(line[j]);
                    if j + n > line.len() {
                        whole = false;
                        break;
                    }
                    j += n;
                }
                if whole {
                    return Some(i..j);
                }
            }
            i += 1;
        }
        None
    }
}

/// A mask bit must never settle a line the byte engine may not decide.
///
/// The witness is `.`-counting over a two-byte codepoint: the byte engine
/// matches `e` + any TWO bytes, so `eé` (65 C3 A9) leaves a mask bit, while
/// the delegate counts `é` as one codepoint and sees two codepoints on a line
/// where `e.{2}` needs three. The ASCII line settles from its bit without
/// the delegate; the non-ASCII lines must be asked of the delegate -- one to
/// be REJECTED despite its bit, one to be ACCEPTED on the delegate's word.
#[test]
fn a_mask_bit_does_not_settle_a_line_the_byte_engine_may_not_decide() {
    use crate::hybrid::HybridMatcher;
    use core::sync::atomic::{AtomicUsize, Ordering};

    let re = ByteRegex::new(b"e.{2}").unwrap();
    let asked = AtomicUsize::new(0);
    let hyb = HybridMatcher::new(&re, AskedDelegate { asked: &asked });
    // "zz":   ASCII with NO bit, and BEFORE the bit-bearing lines -- the
    //         walk's empty-tail early-exit hides such a line when it comes
    //         last, and a settle that returned `true` for every clean line
    //         reported 827k of these on the 246 MB row.
    // "eab": ASCII, a bit, settles without the delegate.
    // "eé":   a bit the byte engine owes to two high bytes; the delegate
    //         sees `e` + one codepoint and must reject it.
    // "eéa":  three codepoints behind `e`; the delegate must accept it.
    // "xa":   no bit, no question asked of anyone.
    let hay = "zz\neab\ne\u{e9}\ne\u{e9}a\nxa\n".as_bytes();
    // If the settle path is not lit the test degenerates into the confirm
    // path and proves nothing about the veto.
    assert!(
        CandidateSource::map_is_match_mask(&hyb, hay).is_some(),
        "the mask settle must be engaged on this fixture"
    );
    let mut rec = Recorded::default();
    Searcher::with_candidates(&hyb, &hyb, cfg_default())
        .search_slice(hay, &mut rec)
        .unwrap();
    assert_eq!(
        rec.matched_lines(),
        alloc::vec!["eab\n".to_string(), "e\u{e9}a\n".to_string()],
        "the delegate owns both non-ASCII lines: its reject must win over \
         the byte engine's bit and its accept must survive it"
    );
    assert_eq!(
        asked.load(Ordering::Relaxed),
        2,
        "exactly the two non-ASCII lines may reach the delegate"
    );
}

/// A clean line WITHOUT a candidate is not a match.
///
/// In a dense region the walk visits every line, including one that has no
/// candidate at all. A composed shortcut tried on top of the window rule
/// settled `true` for every clean line and reported those as matches -- 827k
/// of them on the 246 MB row, caught by the A/B's count gate. A sparse
/// fixture hides that bug class completely: its no-bit lines are jumped
/// over by the candidate walk and never reach any per-line logic, so the
/// pin needs the dense shape. The shortcut was measured and reverted
/// (`benchmark/findings.md` §17); the invariant it broke is what stays.
#[test]
fn a_clean_line_without_a_candidate_is_not_a_match() {
    use crate::hybrid::HybridMatcher;
    use core::sync::atomic::AtomicUsize;

    let re = ByteRegex::new(b"e.{2}").unwrap();
    let asked = AtomicUsize::new(0);
    let hyb = HybridMatcher::new(&re, AskedDelegate { asked: &asked });
    let mut hay: Vec<u8> = Vec::new();
    for i in 0..200 {
        if i == 100 {
            hay.extend_from_slice(b"zz\n");
        } else {
            hay.extend_from_slice(b"eab\n");
        }
    }
    let mut rec = Recorded::default();
    Searcher::with_candidates(&hyb, &hyb, cfg_default())
        .search_slice(&hay, &mut rec)
        .unwrap();
    let matched = rec.matched_lines();
    assert_eq!(matched.len(), 199, "every `eab` and not the `zz` line");
    assert!(
        !matched.iter().any(|l| l == "zz\n"),
        "a line with no candidate and no bit must not settle as a match"
    );
}

/// The window rule settles a non-ASCII line when some bit's window is pure
/// ASCII, without asking the delegate at all.
///
/// `eé eab` carries two mask bits: the one at 0 has a dirty window (its
/// span reaches into the `é`) and the one at 3 sits on `eab`, which both
/// engines match identically. The rule is per WINDOW, not per line: the
/// clean window proves the line matches in both engines, so the delegate
/// has nothing left to decide and must not be asked.
#[test]
fn a_clean_match_window_settles_a_non_ascii_line_without_the_delegate() {
    use crate::hybrid::HybridMatcher;
    use core::sync::atomic::{AtomicUsize, Ordering};

    let re = ByteRegex::new(b"e.{2}").unwrap();
    let asked = AtomicUsize::new(0);
    let hyb = HybridMatcher::new(&re, AskedDelegate { asked: &asked });
    // Two bits on one non-ASCII line: 0 (dirty window) and 3 (`eab`, clean).
    let hay = "e\u{e9}eab\n".as_bytes();
    let mut rec = Recorded::default();
    Searcher::with_candidates(&hyb, &hyb, cfg_default())
        .search_slice(hay, &mut rec)
        .unwrap();
    assert_eq!(
        rec.matched_lines(),
        alloc::vec!["e\u{e9}eab\n".to_string()],
        "the clean window at `eab` proves the line matches in both engines"
    );
    assert_eq!(
        asked.load(Ordering::Relaxed),
        0,
        "a line with a clean match window never reaches the delegate"
    );
}
