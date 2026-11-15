// SPDX-License-Identifier: Apache-2.0

//! The RANGED pre-confirm, and the substring anchor beside it.
//!
//! **What lives here and why it is not in `differential.rs`.** The ranged
//! check's correctness claim is the same law every other prefilter is held
//! to — a byte every match contains, at an offset that may be a range — and
//! the proof of that is `required.rs`'s property test over the trap grid.
//! What is here is the other half: that the check is BUILT, that it is built
//! for the right range, and that the shapes it must decline are declined on
//! purpose. None of that is observable in a differential, because a check
//! that rejects nothing returns the same answers as one that rejects
//! correctly.

use super::*;

/// The prefilter of `pat`, kept alive by the caller.
///
/// A `&FastLiteral` cannot be handed out on its own because it borrows the
/// `ByteRegex` that owns it, and building the regex inside the helper would
/// return a reference into a local. So the helper takes the regex, which the
/// tests build once and keep for the length of their body.
fn fast(re: &ByteRegex) -> &FastLiteral {
    assert!(
        re.fast.is_some(),
        "the pattern has no prefilter at all, so there is nothing to test"
    );
    re.fast.as_ref().expect("checked above")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// **The optimisation is present, and this fails when it is taken out.**
///
/// The count is the only thing in the file that can say a speedup happened.
/// Every other assertion — the differential rows, the parity checks, the
/// answers themselves — is satisfied just as well by a confirm that runs the
/// VM on every candidate, because a check that rejects nothing is not a wrong
/// answer. So the ranged vector is asserted to be non-empty for the pattern it
/// was built for, at the range it was built for, and this test fails on the
/// build where `required::min_runs` is not consulted.
#[test]
fn a_variable_length_prefix_builds_a_ranged_check() {
    let re = ByteRegex::new(b"(pub|fn) [a-z]+").expect("compiles");
    let rs = &fast(&re).ranged;
    assert_eq!(
        rs.len(),
        1,
        "the space after the alternation is the one ranged entry there is"
    );
    assert_eq!(
        (rs[0].lo, rs[0].hi),
        (2, 3),
        "`fn ` puts the space at offset 2 and `pub ` at offset 3, and the \
         range has to be both"
    );
    assert_eq!(
        rs[0].bits[usize::from(b' ' >> 6)] >> (b' ' & 63) & 1,
        1,
        "and it is a space"
    );
}

/// The refusal is EXPLICIT, and this is what pins it. Each row is a different
/// line of [`RangedCheck::new`], and a pattern arriving at the VM with an
/// empty `ranged` is not a bug — it is the shape the optimisation declines.
/// The point of the test is that the decline is a decision the code states
/// rather than one it arrives at.
///
/// | pattern | why there is no ranged check |
/// |---|---|
/// | `e[0-9]` | every entry is at one exact offset, so `lo == hi` and the skeleton already has it |
/// | `foo.*bar` | `bar`'s range is `3..=infinity`, which is `bounded() == None` |
/// | `a*bc` | the `b` is at offset 0 or later, with nothing bounding the later |
/// | `pub fn` | a whole-pattern literal is its own confirm |
#[test]
fn a_pattern_with_nothing_to_range_over_gets_no_ranged_check() {
    for (pat, why) in [
        (&b"e[0-9]"[..], "exact offsets only"),
        (b"foo.*bar", "`bar` is at 3 or later and `.*` never ends"),
        (b"\\w+", "no required byte at an unknown offset"),
        (b"a*bc", "the `b` is at 0 or later, unbounded"),
        (b"^a.*b$", "same, and behind an assertion"),
        (b"pub fn", "a whole-pattern literal is its own confirm"),
    ] {
        let re = ByteRegex::new(pat).expect("compiles");
        let got = re.fast.as_ref().map_or(0, |f| f.ranged.len());
        assert_eq!(
            got,
            0,
            "{:?} should build no ranged check ({why})",
            text(pat)
        );
    }
}

/// A check is a REJECTOR and never a decider, so it may only ever throw away
/// a position the VM also throws away. This walks every start offset of every
/// line built to put a space inside `2..=3` and nowhere else, and asserts the
/// direction that costs an engine when it is wrong: the check rejecting
/// something the VM accepts.
///
/// A check that is too WIDE loses nothing — it rejects fewer — and a check
/// one offset out of place loses a match silently, which is the whole reason
/// this is exhaustive over positions rather than a handful of fixtures.
#[test]
fn a_ranged_check_never_rejects_a_position_the_vm_accepts() {
    let re = ByteRegex::new(b"(pub|fn) [a-z]+").expect("compiles");
    let f = re.fast.as_ref().expect("has a prefilter");
    let r = &f.ranged[0];
    let mut line = Vec::new();
    let mut checked = 0usize;
    for head in [
        "", "p", "pu", "pub", "pubb", "f", "fn", "zz", "fn(", "pub(", "fn x", "pub  y",
    ] {
        for tail in ["", " ", "x ", "  ", "x  ", "xy ", " x", "  y"] {
            line.clear();
            line.extend_from_slice(head.as_bytes());
            line.extend_from_slice(tail.as_bytes());
            line.extend_from_slice(b"abcd");
            for s in 0..=line.len() {
                let held = r.holds(&line, s);
                if !held {
                    assert!(
                        !vm::matches_at(&re.prog, &line, s),
                        "the check rejected a real match at {s} of {:?}",
                        text(&line)
                    );
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 500, "the fixture has to actually cover positions");
}

/// The bounds check, on the case that costs a whole engine when it is wrong.
///
/// `RangedCheck::holds` answers `false` for a window that runs past the end
/// of the line rather than reading past it, and `false` is the right answer
/// because a match has to lie entirely inside the line. The lengths sweep is
/// the part that would panic rather than merely answer wrongly.
#[test]
fn a_ranged_check_never_reads_past_the_end_of_a_line() {
    let re = ByteRegex::new(b"(pub|fn) [a-z]+").expect("compiles");
    let r = &fast(&re).ranged[0];
    // Every length across the range, with a byte that is not the space, so
    // the answer is `false` for all of them and the only thing under test is
    // that nothing panics and nothing reads out of bounds.
    for len in 0..12usize {
        let line = vec![b'a'; len];
        for s in 0..=line.len() {
            assert!(
                !r.holds(&line, s),
                "a line of {len} `a`s held the space check at {s}"
            );
        }
    }
    // Zero bytes and one byte, the two lengths a range can never fit in.
    assert!(!r.holds(b"", 0));
    assert!(!r.holds(b"f", 0));
    // A line whose range reaches PAST its last byte. `fn` is two bytes and
    // the range is 2..=3, so offset 3 does not exist and `get` answers `None`
    // rather than reading it. `pub` is three bytes and the range ends exactly
    // at the last byte, which is the other edge.
    assert!(!r.holds(b"fn", 0), "offset 3 is past the end of `fn`");
    assert!(!r.holds(b"pub", 0), "offset 3 is past the end of `pub`");
    // One byte more and the space is really there: the range's upper end is
    // inside the line, which is the case a clamped implementation would get
    // right for the wrong reason.
    assert!(r.holds(b"fn ", 0), "the space is at 2, inside the line");
    assert!(r.holds(b"pub ", 0), "and at 3");
    assert!(
        r.holds(b"pub z", 0),
        "with a match at the last byte of the line"
    );
}

/// The substring anchor is only taken when its offset is KNOWN, and a
/// pattern that already has one is not offered a second.
///
/// `foo.*bar` used to carry THREE anchors for two literals: the packed mask
/// over `foo`, the known substring over `foo` (offset 0), and
/// [`super::required::anywhere`]'s copy of the same needle with `known` set to
/// false. The third is strictly worse than the second -- the same offsets and
/// a confirm that has to consider the whole line instead of an anchored run --
/// so it bought nothing and cost a second 512-byte sample every time `plan`
/// measured. This says it is not built, and says the surviving one is known.
///
/// The unknown arm itself is what `\d+xx` still needs, and
/// `an_overlapping_literal_behind_an_unknown_offset_is_still_a_candidate` is
/// the test that holds it in place.
#[test]
fn a_substring_anchor_is_only_built_once_and_only_known_when_its_offset_is() {
    let re = ByteRegex::new(b"foo.*bar").expect("compiles");
    let f = fast(&re);
    let subs: alloc::vec::Vec<(usize, bool, alloc::vec::Vec<u8>)> = f
        .anchors
        .iter()
        .filter_map(|a| match &a.scan {
            FastScan::Sub { needle } => Some((a.at, a.known, needle.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(subs.len(), 1, "one literal, one substring anchor");
    assert!(subs[0].1, "and it is the known one");
    assert_eq!(subs[0].0, 0, "sitting at offset 0");
    assert_eq!(subs[0].2, b"foo".to_vec());

    // A pattern whose required literal is at an UNKNOWN offset keeps its
    // unknown anchor, and nothing turns it into a known one.
    let re2 = ByteRegex::new(br"\d+xx").expect("compiles");
    let f2 = fast(&re2);
    let subs2: alloc::vec::Vec<(bool, alloc::vec::Vec<u8>)> = f2
        .anchors
        .iter()
        .filter_map(|a| match &a.scan {
            FastScan::Sub { needle } => Some((a.known, needle.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(subs2.len(), 1);
    assert!(
        !subs2[0].0,
        "an unknown-offset literal stays unknown; reading it as known is the \
         false negative the guard in `search` exists for"
    );
    assert_eq!(subs2[0].1, b"xx".to_vec());
}

/// The caseless refusal, on the arm that has the case.
///
/// `FastScan::Sub` is a case-SENSITIVE substring search, because
/// `crate::memchr::memmem` has no caseless searcher. A known-offset `Sub` built for
/// a folded literal would find `pub fn` and not `PUB FN`, which is a wrong
/// answer rather than a slow one, so the build refuses it and this is the
/// refusal.
#[test]
fn a_caseless_literal_never_becomes_a_known_substring_anchor() {
    for pat in [
        &b"(?i)pub fn"[..],
        b"(?i)foo.bar",
        b"(?i)Er.",
        b"(?i)[ab]cd",
        b"(?i)needle",
    ] {
        let re = ByteRegex::new(pat).expect("compiles");
        let Some(f) = re.fast.as_ref() else { continue };
        let known_sub = f
            .anchors
            .iter()
            .any(|a| a.known && matches!(a.scan, FastScan::Sub { .. }));
        assert!(
            !(known_sub && re.is_case_insensitive()),
            "{:?} built a known-offset `Sub` while case folding, which would \
             find one spelling of the literal and not the other",
            text(pat)
        );
    }
}

/// **The superset law, on the shape that broke it.**
///
/// `CandidateSource` may over-report and may never under-report, and a
/// `Sub` anchor's offsets are the positions of a literal that every match
/// contains. `crate::memchr::memmem`'s `find_iter` is documented to return
/// *non-overlapping* occurrences, so `xx` in `xxx` yields one offset where
/// there are two, and the missing one is a match start nobody is ever asked
/// about. The step is `p + 1` rather than `p + needle.len()` and this is what
/// says so, at every needle length from one to eight, over haystacks built
/// out of nothing but runs of the needle — the only shape where the overlap
/// actually happens.
///
/// It is the test that fails without the fix, and it fails with a MISSING
/// MATCH rather than a wrong one, which is why it has to be a property over
/// lengths rather than one fixture.
#[test]
fn a_substring_scan_reports_every_occurrence_including_overlapping_ones() {
    for len in 1..=8usize {
        let needle: alloc::vec::Vec<u8> = (0..len).map(|i| b'a' + (i % 3) as u8).collect();
        for repeats in 1..=4usize {
            // Nothing but the needle, repeated: the densest possible overlap.
            let hay: alloc::vec::Vec<u8> = needle.repeat(repeats);
            let mut want: alloc::vec::Vec<usize> = Vec::new();
            for p in 0..=hay.len().saturating_sub(len) {
                if hay[p..p + len] == needle[..] {
                    want.push(p);
                }
            }
            assert!(
                want.len() >= repeats,
                "the fixture must produce overlapping occurrences for len={len} \
                 repeats={repeats}, got {want:?}"
            );
            let got: alloc::vec::Vec<usize> = sub_offsets(&hay, &needle).collect();
            assert_eq!(
                got, want,
                "len={len} repeats={repeats}: a lost occurrence is a lost match"
            );
            // And the same with the needle surrounded by noise, so the
            // overlapping pair is not the first thing in the haystack.
            let mut padded: alloc::vec::Vec<u8> = b"zz".to_vec();
            padded.extend_from_slice(&hay);
            padded.extend_from_slice(b"zz");
            let want2: alloc::vec::Vec<usize> = (0..=padded.len() - len)
                .filter(|&p| padded[p..p + len] == needle[..])
                .collect();
            let got2: alloc::vec::Vec<usize> = sub_offsets(&padded, &needle).collect();
            assert_eq!(got2, want2, "len={len} repeats={repeats}, padded");
        }
    }
}

/// The same law on the pattern that actually broke: `xx[0-9]zz`, a two-byte
/// required literal and therefore a two-byte needle, on a haystack full of
/// `xxx`.
///
/// The break reached the engine through
/// `fixed::tests::a_match_across_the_fill_boundary_agrees_with_the_vm`, whose
/// haystack happens to put the chosen anchor on the substring scan. That is
/// not something a fixture here can force, and the reason is worth stating:
/// `plan` prices the substring at 0.03 ns/byte and the byte-set run over
/// `xx?z` at 0.05, so the substring wins only where the two admit the SAME
/// offsets -- and manufacturing an overlap is precisely what makes them
/// differ, because an overlapping `xx` raises the substring's density above
/// the run's. Which is to say the cost model is RIGHT to prefer the mask
/// here, and the bug was never the choice. It was the scan underneath it
/// reporting half of what it had found.
///
/// So this asserts the law the engine actually owes -- every match start is
/// a candidate -- and, when the chosen anchor IS the substring, that its
/// offsets are every occurrence of the needle. The second half is the one
/// that bites, and it is written to bite whether or not the first does.
#[test]
fn an_overlapping_required_literal_is_still_a_candidate() {
    use crate::matcher::Matcher as _;
    let re = ByteRegex::new(b"xx[0-9]zz").expect("compiles");
    let parsed = crate::syntax::parse(b"xx[0-9]zz").expect("parses");
    let prog = crate::nfa::compile(&parsed.ast, parsed.groups);
    // 8 KiB of `xxx7zz`: one `xx` overlap per six bytes, so the two `xx` of
    // every `xxx` are both occurrences and a non-overlapping scan finds one.
    let mut hay: alloc::vec::Vec<u8> = Vec::new();
    while hay.len() < 8 * 1024 + 6 {
        hay.extend_from_slice(b"xxx7zz");
    }
    let mut out: Vec<usize> = Vec::new();
    re.fast_candidates(&hay, &mut out);

    // The law, anchor-agnostic.
    let mut starts = 0usize;
    for at in 0..hay.len() {
        if vm::matches_at(&prog, &hay, at) {
            starts += 1;
            assert!(
                out.binary_search(&at).is_ok(),
                "the match at {at} is not a candidate, so nothing will \
                 confirm it"
            );
        }
    }
    assert!(
        starts > 1000,
        "the fixture must contain matches, got {starts}"
    );

    // And the scan's own superset, when the scan is the substring one.
    let chosen = re.chosen_anchor(&hay).expect("has an anchor");
    let want: Vec<usize> = (0..=hay.len() - 2)
        .filter(|&p| &hay[p..p + 2] == b"xx")
        .collect();
    let overlapping = want.windows(2).filter(|w| w[1] == w[0] + 1).count();
    assert!(
        overlapping > 1000,
        "the fixture must produce overlapping occurrences, got {overlapping}"
    );
    if chosen.kind == "sub" {
        assert_eq!(
            out, want,
            "every `xx` is a candidate, including the second `xx` of a `xxx`"
        );
    }
    // The engine agrees with the VM at every position either way.
    for at in 0..hay.len() {
        assert_eq!(
            re.is_match_at(&hay, at),
            vm::matches_at(&prog, &hay, at),
            "at {at}"
        );
    }
}

/// The same law for a literal behind an UNKNOWN offset, which is the arm that
/// has always used this scan and the one no differential case reached.
///
/// `\d+xx` over a run of `1xxx` puts `xx` at offsets 1 and 2 -- overlapping
/// -- and again at 5 and 6. A non-overlapping scan reports 1 and 5 and drops
/// the other two, and because the confirm for an unknown origin is a
/// whole-line search the loss is invisible: the line is still confirmed, from
/// the candidate that survived, so the search returns the right answer having
/// done the wrong work and with no way to say so.
///
/// The needle is `xx` and not `em`, and that is the whole of what makes the
/// case possible: a needle can only overlap itself if it has a non-empty
/// border, and `em` has none -- `e` and `m` differ, so no occurrence of `em`
/// can start inside another. `em` would have been a fixture that could never
/// fail.
#[test]
fn an_overlapping_literal_behind_an_unknown_offset_is_still_a_candidate() {
    let re = ByteRegex::new(br"\d+xx").expect("compiles");
    let mut hay: alloc::vec::Vec<u8> = Vec::new();
    while hay.len() < 8 * 1024 + 4 {
        hay.extend_from_slice(b"1xxx");
    }
    let chosen = re.chosen_anchor(&hay).expect("has an anchor");
    assert_eq!(
        chosen.kind,
        "sub",
        "this fixture exists to put the engine on the unknown-offset \
         substring scan, and it did not; anchors were {:?}",
        re.anchor_info()
    );
    assert!(
        !chosen.known,
        "and it has to be the UNKNOWN one -- a known offset would confirm \
         anchored and the whole-line confirm would not be in play"
    );
    let mut out: Vec<usize> = Vec::new();
    re.fast_candidates(&hay, &mut out);
    let want: Vec<usize> = (0..=hay.len() - 2)
        .filter(|&p| &hay[p..p + 2] == b"xx")
        .collect();
    assert_eq!(
        out, want,
        "every `xx` is a candidate, including the two that overlap"
    );
    let overlapping = want.windows(2).filter(|w| w[1] == w[0] + 1).count();
    assert!(
        overlapping > 1000,
        "the fixture must produce overlapping occurrences, got {overlapping}"
    );
}

///
/// `\w+` and `a?b` are the two shapes: one has a required byte at offset 0
/// and nothing at an unknown one, the other has an optional prefix. Both must
/// reach the VM with an empty `ranged` — a check over "the whole line" is a
/// scan, and `CHECK_SPAN` is what says so — and both must still answer every
/// position correctly, because the refusal is a refusal to OPTIMISE and not a
/// refusal to match.
#[test]
fn a_pattern_with_no_ranged_path_still_answers_every_position() {
    use crate::matcher::Matcher as _;
    // (pattern, haystack, the positions a match begins at)
    let cases: &[(&[u8], &[u8], &[usize])] = &[
        (b"\\w+", b"ab", &[0, 1]),
        (b"\\w+", b"a b", &[0, 2]),
        (b"\\w+", b"", &[]),
        (b"a?b", b"ab", &[0, 1]),
        (b"a?b", b"b", &[0]),
        (b"a?b", b"zzb", &[2]),
        (b"a?b", b"", &[]),
        (b"a*b", b"aaab", &[0, 1, 2, 3]),
        (b"a*b", b"b", &[0]),
        (b"a*b", b"", &[]),
        // A match at the last byte, and a match that would run past it.
        (b"a*b", b"aaa", &[]),
        (b".", b"a", &[0]),
        (b".", b"", &[]),
    ];
    for (pat, hay, starts) in cases {
        let re = ByteRegex::new(pat).expect("compiles");
        assert_eq!(
            re.fast.as_ref().map_or(0, |f| f.ranged.len()),
            0,
            "{:?} must not use the ranged path",
            text(pat)
        );
        let got: alloc::vec::Vec<usize> = (0..=hay.len())
            .filter(|&at| re.is_match_at(hay, at))
            .collect();
        assert_eq!(&got[..], *starts, "{:?} over {:?}", text(pat), text(hay));
    }
}

/// The anchor the model picks at confirm price `p`, over rows already
/// measured by [`ByteRegex::anchor_costs_sampled`].
///
/// **A self-priced anchor is identified by its SCAN and not by its price.**
/// `CONFIRM_NS` and `MASK_CONFIRM_NS` are both 8.0, so a caller that asks
/// "is this anchor charged the pattern's price?" by comparing the two
/// numbers gets `true` for every anchor, and then sweeps a match mask's
/// confirm with a price it is not charged -- which silently changes the
/// comparison this test exists to make. The engine gets this right in
/// `Anchor::effective_confirm`, which matches on the scan; every caller
/// outside it has to as well.
fn argmin_rows(rows: &[AnchorCost], p: f64) -> &'static str {
    let mut best = 0usize;
    let mut best_score = f64::INFINITY;
    for (i, r) in rows.iter().enumerate() {
        let swept = !matches!(r.info.kind, "matchmask" | "premask");
        // The swept cost is `cost` with its own price term replaced, NOT
        // `cost` recomputed from the terms: `Anchor::cost` short-circuits a
        // one-byte deciding mask to its scan rate and an unknown-origin
        // anchor to a flat penalty, and re-deriving the arithmetic here
        // would drop both and order the anchors differently from the engine.
        let score = if swept {
            r.cost - r.density * r.confirm_ns + r.density * p
        } else {
            r.cost
        };
        if score < best_score {
            best_score = score;
            best = i;
        }
    }
    rows[best].info.kind
}

/// **The cost model's decisions, pinned, and the price at which each one
/// moves.** `benchmark/status.md` §4 item 1 records a confirm price that was
/// written, measured, and reverted because it moved `e[0-9]` by 92 ms in a
/// pattern it should not have touched. This test exists so that the next
/// attempt cannot do that silently: it asserts the anchor each of these
/// patterns ends up on, over a haystack shaped like the corpus, and it finds
/// the price at which that answer would change, which is the number the
/// reverter needed and did not have.
///
/// **The reverter's diagnosis was half right and the fix is the price
/// anyway.** The 92 ms was blamed on this constant and was not caused by it:
/// it was the second [`crate::regex::FastLiteral::plan`] measurement, whose
/// buffer is a 540,676-byte hex table in which `e[0-9]` is 13x denser than
/// the file and `(pub|fn) [a-z]+` is 13x sparser, pooled at half weight with
/// the first fill. `examples/density_probe.rs` measures both and no shape of
/// sample separates them — the two patterns need opposite answers from the
/// same bytes. The price fix makes the comparison insensitive to the poisoned
/// density; see the note on `CONFIRM_NS`.
///
/// **That number is the deliverable, and the floors below are it.** The price
/// is a common scale factor over every anchor that takes it, so it cancels out
/// of every comparison between two of those, and the only thing it decides is
/// its ratio against `MASK_CONFIRM_NS`, which a mask does not scale. So the
/// question a change to it must answer is not "is this the right price" but
/// "which prices move which patterns, and by how much" — and that has a closed
/// form: `cost_i(p) = n_i + d_i * p` for a swept anchor and a line of slope
/// zero for one carrying its own price, so two anchors meet once and the model
/// can be walked down from the shipped price until its argmin is a different
/// anchor.
///
/// The floors are measured on THIS haystack and are close to but not the same
/// as the numbers `examples/cost_sensitivity.rs` prints for the 235 MB corpus
/// (8.94 ns for `e.`, 0.56 for `e[0-9]`, 57.3 for `(pub|fn) [a-z]+`) — the
/// crossovers are a function of the densities and a synthetic corpus has
/// different ones. The corpus numbers are the ones worth quoting; these are
/// here to fail loudly if a constant moves across one.
///
/// **The walk scores the same rows `measure` did.** It used to score a
/// whole-haystack sample and compare that argmin with a decision taken on
/// an 8 KiB one, which agree except at a crossover -- where a fact about
/// the corpus, not a failure, was being reported as one. And it identified
/// a self-priced anchor by comparing its price against the pattern's, which
/// stopped working the moment `CONFIRM_NS` and `MASK_CONFIRM_NS` became the
/// same number: every anchor then looked swept, and the sweep charged a
/// match mask a confirm it is not charged. Both are in
/// [`argmin_rows`], which is the engine's arithmetic and not a copy of it.
///
/// **These are not correctness tests.** Nothing here can produce a wrong
/// answer — every anchor is sound, which is the module's law — so no oracle
/// can see any of it. What this pins is a DECISION, and a decision that moves
/// is a performance change to be argued for in a benchmark rather than
/// discovered in a test failure.
#[test]
fn the_confirm_price_moves_exactly_the_anchors_it_is_supposed_to() {
    /// Rust-ish source with the byte frequencies of the 235 MB corpus: `e` at
    /// about 5%, digits at about 7%, and one `e` followed by a digit per
    /// ~400 bytes so the two-position scans have something to find.
    fn corpus() -> alloc::vec::Vec<u8> {
        let mut s = String::new();
        let mut i = 0usize;
        while s.len() < 200_000 {
            i += 1;
            s.push_str("pub fn ");
            s.push_str(&alloc::format!("{i}"));
            s.push_str("(&self, value: Option<u32>) -> Result<u32, Error> {\n");
            s.push_str("    let mut total = 0u32; // compute every value\n");
            s.push_str("    Err(Error { code: 7 })\n}\n");
            s.push_str("the quick brown fox jumps over the lazy dog\n");
        }
        s.into_bytes()
    }
    let hay = corpus();

    // (pattern, the anchor `measure` must choose, and the price below which
    // it stops choosing it -- measured by the walk below on THIS haystack).
    let cases: &[(&[u8], &str, f64)] = &[
        // A one-byte pattern never samples: there is nothing to choose
        // between, so no price at all can move it. 0.0 is the sentinel for
        // "the price cannot reach this one at any value".
        (b"e", "byte", 0.0),
        (b"fn main", "sub", 0.0),
        (b"pub fn", "sub", 0.0),
        (b"let mut", "sub", 0.0),
        // `e.` is the one `benchmark/status.md` §4 item 1 called 12x wrong, and it
        // now says so in the other direction: the mask is bought at 8.94 ns
        // on the 235 MB corpus and the byte anchor is 12% FASTER there
        // (120.2 ms against 137.3, each build pinned to one anchor). On this
        // synthetic haystack `e` is 6.4% and the mask costs 0.07 + 8d against
        // the byte scan's 0.02 + 8.6d, so the byte anchor wins at EVERY
        // price and the walk finds no crossing at all.
        (b"e.", "byte", 0.0),
        // `a|b|c`'s two anchors have the same density, so the confirm term
        // cancels and the comparison is a 0.005 ns/byte scan-rate gap. It is
        // the one case the model has no opinion about, and the measurement
        // agrees: byte3 at 125.8 ms against 128.5 for the mask is 2.1%, at
        // the harness floor.
        (b"a|b|c", "matchmask", 0.10),
        // `e[0-9]` is the one the reverted price moved, and its two-position
        // anchors are three orders of magnitude below any price here, so no
        // confirm price reaches them. It moved anyway, and the reason is
        // [`MATERIALISE_NS`] plus the second measurement `plan` takes; see the
        // notes on those two constants.
        (b"e[0-9]", "mask2", 0.46),
        // `foo.*bar` is decided by SCAN RATE and not by the price at all:
        // its two anchors have the same density, so the confirm term cancels
        // exactly and `sub` wins on `memmem` being faster than the nibble
        // mask. No price moves it.
        (b"foo.*bar", "sub", 0.0),
        // The tailed price, and the only pattern with a tail among these. Its
        // floor is low because this synthetic corpus is dense in the pattern;
        // on the 235 MB corpus the same crossover is 57.3 ns.
        (b"(pub|fn) [a-z]+", "matchmask", 12.02),
    ];

    for &(pat, want, floor) in cases {
        let re = ByteRegex::new(pat).expect("compiles");
        let chosen = re
            .chosen_anchor(&hay)
            .unwrap_or_else(|| panic!("{:?} has no anchor", text(pat)));
        assert_eq!(
            chosen.kind,
            want,
            "{:?} chose {} -- if the price constants moved, this is the \
             failure that says so",
            text(pat),
            chosen.kind
        );

        // **How far the price can be lowered before this choice moves.**
        //
        // The question the reverter needed answered and did not have is not
        // "is the price right" but "which prices would change the answer",
        // and it has a closed form: an anchor swept at price `p` costs
        // `n + d*p`, an anchor carrying its own price is a line of slope zero,
        // and the two cross once. So the price at which the choice flips is
        // found by walking down from the shipped price until the model's
        // argmin is a different anchor, and that number IS the tripwire:
        // a change to any confirm constant that leaves it above `floor` has
        // not touched this pattern, and one that drops it below `floor` has,
        // and the test says which.
        let shipped = re.confirm_price();
        assert!(
            shipped > floor,
            "{:?}: the price assertion is vacuous",
            text(pat)
        );
        // **The same measurement basis as the decision, or the test is
        // comparing two different things.** `chosen_anchor` scored the
        // SAMPLE `measure` takes; scoring the whole haystack instead gives
        // slightly different densities, and at a crossover the two can land
        // on different anchors -- which is a fact about the corpus, not a
        // failure, and the floor below would then be measuring nothing.
        let rows = re.anchor_costs_sampled(&hay, Sampling::Spread16);
        assert_eq!(
            argmin_rows(&rows, shipped),
            want,
            "{:?}: the model and the measurement disagree at the shipped              price, so the floor below is measuring a different decision",
            text(pat)
        );
        let argmin_at = |p: f64| argmin_rows(&rows, p);
        let mut moves_at = f64::NEG_INFINITY;
        let mut p = shipped;
        while p > 0.0 {
            p -= 0.01;
            if argmin_at(p) != want {
                moves_at = p + 0.01;
                break;
            }
        }
        assert!(
            moves_at <= floor + 0.011,
            "{:?}: lowering the price to {moves_at:.2} ns moves it off {want} -- \
             this test says the floor is {floor:.2} ns, and the shipped price \
             is {shipped:.1} ns",
            text(pat),
        );
    }
}

/// **The plan is a pure function of the bytes, on the buffer it measured.**
///
/// [`FastLiteral::plan`] remembers its verdict and re-measures only when a
/// buffer [`REPLAN`] times bigger arrives. The claim under test is the one
/// the strictly-less rule in [`FastLiteral::measure`] exists for -- "the same
/// bytes always produce the same plan" -- and it is checked by measuring the
/// SAME bytes twice and through the cache.
#[test]
fn the_remembered_plan_is_the_measured_plan() {
    let hay: alloc::vec::Vec<u8> = std::iter::repeat_n(
        b"pub fn e7 x1 the quick brown fox jumps over the lazy dog\n".as_slice(),
        2000,
    )
    .flatten()
    .copied()
    .collect();
    for pat in [&b"e."[..], b"e[0-9]", b"foo.*bar", b"(pub|fn) [a-z]+"] {
        let re = ByteRegex::new(pat).expect("compiles");
        // Force the cold half, then ask again on the same bytes: the answer
        // must be the remembered one, not a second opinion.
        let first = re.chosen_anchor(&hay).expect("an anchor");
        let second = re.chosen_anchor(&hay).expect("an anchor");
        assert_eq!(first.kind, second.kind, "{:?}", text(pat));
        // And a fresh compile must reach the same verdict, which is what
        // "the choice is a pure function of the buffer" means across the
        // two threads that may each plan one.
        let other = ByteRegex::new(pat).expect("compiles");
        assert_eq!(
            other.chosen_anchor(&hay).expect("an anchor").kind,
            first.kind,
            "{:?} is not reproducible from the bytes",
            text(pat)
        );
    }
}

/// **`e[0-9]`'s two candidates have the SAME density, so the estimator is
/// not what chooses between them -- the prices are.**
///
/// This is the invariant the whole `CONFIRM_NS` change rests on, and it is a
/// property of the PATTERN rather than of a corpus, so it can be checked at
/// any size. `e[0-9]` has two ways to be rare: the two-position mask tests
/// `e` and a digit at adjacent offsets, and the match mask evaluates the
/// same two bytes as a branch set. Over the 235 MB corpus the first fires
/// 60,232 times and the second 60,230 -- a difference of two, which is the
/// two `e[0-9]` occurrences that the class admits and the byte test does not.
/// A sample that estimates one of them at four times its rate and the other
/// at a quarter has not found a different anchor; it has found a different
/// ORDER on a tie that was never a tie.
///
/// Which means the decision is
///
/// ```text
///   ns_per_byte(mask2) + d * (CONFIRM_NS + MATERIALISE_NS)
///       <  ns_per_byte(matchmask) + d * MASK_CONFIRM_NS
/// ```
///
/// and `d` appears on BOTH sides, so it divides out: the estimator's error
/// cancels, and the only thing that decides `e[0-9]` is the two price sums.
/// At the old 30 the left was `0.05 + 34d` and the right `0.07 + 8d`, which
/// cross at 7.7e-4 -- and the 540,676-byte hex-table fill the second
/// [`crate::regex::FastLiteral::plan`] measurement lands on is 13x denser
/// than the file, so its pooled density crosses. At 8 the crossing is
/// 5.0e-3 and nothing in the pool reaches it.
///
/// A test that builds a fixture with a realistic density would be testing
/// the corpus, not this, and a 200 KB synthetic haystack cannot hold one:
/// `e[0-9]` at the corpus rate is one occurrence per 4,100 bytes, which is
/// 0.1 hits in a fixture big enough for `LineBuffer` to double. So the
/// claim is checked as what it is -- an identity between two measured hit
/// counts, and the crossover it implies.
#[test]
fn e_09_candidates_are_a_tie_the_prices_break() {
    let line = b"pub fn e7 x1 the quick brown fox jumps over the lazy dog\n";
    let mut code: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(line.len() * 2000);
    for _ in 0..2000 {
        code.extend_from_slice(line);
    }
    let re = ByteRegex::new(b"e[0-9]").expect("compiles");
    let rows = re.anchor_costs_sampled(&code, Sampling::Whole);
    let hits = re.anchor_hits(&code);
    let (mask2, mmask) = (
        rows.iter().position(|r| r.info.kind == "mask2"),
        rows.iter().position(|r| r.info.kind == "matchmask"),
    );
    let (Some(m2), Some(mm)) = (mask2, mmask) else {
        panic!("e[0-9] no longer offers both a two-position mask and a match mask");
    };

    // The tie, within the two occurrences the class admits and the byte test
    // does not. This is what makes the estimator's error cancel, so it is the
    // thing to assert, and it has a real bound: the two scans test the same
    // two bytes at the same offsets, so neither can miss what the other
    // finds, and the two can differ only on the boundary of the class.
    assert!(
        hits[m2].abs_diff(hits[mm]) <= 4,
        "e[0-9]'s two-position mask fires {} times and its match mask {} --          they test the same two bytes, and a larger gap means one of them is          no longer the anchor this claim is about",
        hits[m2],
        hits[mm]
    );
    assert_eq!(rows[m2].density, rows[mm].density, "the tie is not exact");

    // And the crossover it implies, against the shipped prices. The density
    // cancels out of the comparison, so this is the SAME number for every
    // haystack, which is the point: it is a property of the constants.
    let (n2, n1) = (rows[m2].ns_per_byte, rows[mm].ns_per_byte);
    let (p2, p1) = (rows[m2].confirm_ns, rows[mm].confirm_ns);
    let m2m = rows[m2].materialise_ns;
    // The two densities are equal (asserted above), so d cancels and the
    // comparison is `n2 + (p2 + m2m) * d  <  n1 + p1 * d` iff
    // `d < (n1 - n2) / (p2 + m2m - p1)`.
    let denom = (p2 + m2m - p1).max(1e-9);
    let crossing = (n1 - n2) / denom;
    assert!(
        crossing > 0.0,
        "the two anchors cannot be separated by density at all:          ns/byte {n2} vs {n1}, price {p2} + materialise {m2m} vs {p1}"
    );
    // The real corpus measures 2.44e-4 and the hex-table fill 3.21e-3, so
    // the crossing has to sit above the corpus and above the outlier. This
    // is the number the old price failed.
    assert!(
        crossing > 3.21e-3,
        "the crossover is {crossing:.2e}, which the hex-table fill's own          3.21e-3 density crosses -- the plan will follow the outlier"
    );
    // And the crossing is where the model's argmin actually flips, asked
    // through the engine's own arithmetic rather than through a hand copy of
    // it. This synthetic haystack is 72x denser in `e[0-9]` than the corpus
    // is, so it sits ABOVE the crossing and the match mask is the right
    // answer for it -- which is the other half of the claim: the decision is
    // a function of the density and of nothing else, so the same two prices
    // that pick the two-position mask on a 235 MB corpus pick the match mask
    // here, and both are correct.
    let pick_at = |d: f64| {
        re.anchor_costs_at(&[0.0, d, d])
            .iter()
            .enumerate()
            .filter(|(_, r)| r.info.kind == "mask2" || r.info.kind == "matchmask")
            .min_by(|a, b| a.1.cost.total_cmp(&b.1.cost))
            .map(|(i, _)| re.anchor_info()[i].kind)
            .unwrap_or_default()
    };
    assert_eq!(
        alloc::string::ToString::to_string(&pick_at(crossing * 0.5)),
        "mask2",
        "below the crossing the two-position mask must win"
    );
    assert_eq!(
        alloc::string::ToString::to_string(&pick_at(crossing * 4.0)),
        "matchmask",
        "above the crossing the match mask must win -- and this haystack, at          {:.2e}, is above it",
        rows[m2].density
    );
    assert!(
        rows[mm].cost < rows[m2].cost,
        "this haystack is at {:.2e}, above the {:.2e} crossing, so the match          mask is the cheaper of the two here and the test's premise is          wrong rather than the model",
        rows[m2].density,
        crossing
    );
}

/// **A fill of unrepresentative bytes must not overturn the plan.**
///
/// The 235 MB corpus holds a 540,676-byte hex-table line -- `    0x3c00,
/// 0x3c00, ...` -- and `LineBuffer` has to keep doubling until a whole line
/// fits, so the fill carrying it is eight times the first. `plan` measured
/// on it a second time, and the line holds not one `pub ` or `fn `, so the
/// density the second measurement REPLACED the first with fell below the
/// crossover and the plan flipped to the fingerprint anchor, whose confirm
/// is a Pike VM per candidate, for the remaining 98 MB of the file: 178.2 ms
/// over the corpus against 94.8 for the plan the first fill chose. The
/// densities are now POOLED ([`FastLiteral::evidence`]), and this test is
/// the shape of that on buffers small enough to reason about.
#[test]
fn an_unrepresentative_fill_pools_rather_than_replaces() {
    let code: alloc::vec::Vec<u8> = std::iter::repeat_n(
        b"pub fn e7 x1 the quick brown fox jumps over the lazy dog\n".as_slice(),
        2000,
    )
    .flatten()
    .copied()
    .collect();
    let mut table: alloc::vec::Vec<u8> = Vec::new();
    while table.len() < code.len() * REPLAN {
        table.extend_from_slice(b"    0x3c00, 0x3c00, 0x0000, 0x1e00, 0x3c00, 0x0e07,\r");
    }
    // A fresh plan on the table ALONE must reject the match mask, or the
    // fixture has stopped being adversarial and the rest of this test is
    // vacuous: the whole point is that one empty sample cannot outvote a
    // full one, and an empty sample that would have agreed proves nothing.
    let alone = ByteRegex::new(b"(pub|fn) [a-z]+").expect("compiles");
    assert_eq!(
        alone.chosen_anchor(&table).expect("an anchor").kind,
        "masked",
        "the hex-table fill is no longer adversarial; make it barer"
    );
    // The representative fill chooses the mask: two `pub`/`fn` hits per
    // 57 bytes against a confirm priced at a Pike VM run.
    let re = ByteRegex::new(b"(pub|fn) [a-z]+").expect("compiles");
    let first = re.chosen_anchor(&code).expect("an anchor");
    assert_eq!(first.kind, "matchmask");
    // The table fill is REPLAN times bigger, so `plan` measures again on
    // it -- and the pooled density keeps the mask where a replaced one
    // flipped off it.
    let second = re.chosen_anchor(&table).expect("an anchor");
    assert_eq!(
        second.kind, "matchmask",
        "the hex-table fill overturned a plan made on representative bytes"
    );
}

/// **`(?-u)` is the glob translator's prefix, and a byte engine is
/// already in that mode.** The walker compiles a `.gitignore` line by
/// translating it to `(?-u)^...$` -- `(?-u)` being how the `regex` crate
/// spells "bytes, not codepoints" -- and every such pattern used to be
/// rejected with "unknown flag `u`". Both spellings parse; neither turns
/// anything on or off, because there is no mode to turn off.
#[test]
fn unicode_mode_flags_parse_as_no_ops() {
    for pat in [
        &b"(?-u)^src/.*\\.rs$"[..],
        b"(?u)^a$",
        b"(?-u)(?i)^Abc$",
        b"(?-u:a)b",
    ] {
        ByteRegex::new(pat).unwrap_or_else(|e| panic!("{pat:?} must compile: {e:?}"));
    }
    // And it is a no-op, not a silent mode switch: `(?-u)` must not make
    // the pattern match MORE than the same pattern without it.
    let re = ByteRegex::new(b"(?-u)^.$").expect("compiles");
    assert!(re.search(b"x", 0).is_some());
    assert!(
        re.search(b"\xe2", 0).is_some(),
        "a byte engine matches one byte"
    );
    let plain = ByteRegex::new(b"^.$").expect("compiles");
    assert_eq!(
        re.search(b"\xe2", 0).map(|m| (m.start, m.end)),
        plain.search(b"\xe2", 0).map(|m| (m.start, m.end)),
    );
}

/// **A translated glob is a pattern this engine can run**, not just
/// parse. The fixtures are exactly what `walk.rs` emits, byte for byte:
/// `(?-u)`, the anchored body, `[^/]` classes, `(?:/?|.*/)` for `**/`,
/// and `\xNN` escapes for every non-alphanumeric literal byte. Each one
/// is checked against the `regex` crate as the oracle, in the byte mode
/// the prefix selects.
#[test]
fn translated_globs_run_against_the_oracle() {
    for (pat, hit, miss) in [
        (b"(?-u)^src/.*$" as &[u8], &b"src/main.rs"[..], &b"src"[..]),
        (
            b"(?-u)^(?:/?|.*/)Cargo\\.toml$",
            b"a/b/Cargo.toml",
            b"a/b/CargoXtoml",
        ),
        (b"(?-u)^[^/]*\\.rs$", b"main.rs", b"dir/main.rs"),
        (b"(?-u)^(?:a|b)\\.txt$", b"b.txt", b"c.txt"),
        (
            b"(?-u)^(?:/|/.*/)node_modules$",
            b"/x/y/node_modules",
            b"x/node_modules",
        ),
    ] {
        let ours = ByteRegex::new(pat).unwrap_or_else(|e| panic!("{pat:?}: {e:?}"));
        let theirs =
            regex::bytes::Regex::new(core::str::from_utf8(pat).expect("glob patterns are ASCII"))
                .expect("the oracle accepts what the translator emits");
        {
            let h = hit;
            let got = ours.is_match_at(h, 0);
            assert!(got, "{pat:?} should match {h:?}");
            assert_eq!(
                got,
                theirs.is_match(h),
                "{pat:?} on {h:?}: oracle disagrees"
            );
        }
        {
            let m = miss;
            let got = ours.is_match_at(m, 0);
            assert!(!got, "{pat:?} should NOT match {m:?}");
            assert_eq!(
                got,
                theirs.is_match(m),
                "{pat:?} on {m:?}: oracle disagrees"
            );
        }
    }
}

/// **`escape` is what a fixed-string search goes through, so it has to
/// be exact: the escaped pattern matches the input, and nothing that
/// merely resembles it.** Every metacharacter, a lone backslash, control
/// bytes, and a DEL all round-trip; a clean word is left alone.
#[test]
fn escape_round_trips_the_literal_bytes() {
    for input in [
        &b"plain word_42"[..],
        b"a.b",
        b"a*b+c?d(e)f|g",
        b"^$[]{}-",
        b"back\\slash",
        b"tab\there",
        b"\x00\x1b\x7f",
        b"a[0-9]{2}(b|c)+$",
    ] {
        let quoted = super::escape(input);
        let re = ByteRegex::new(&quoted)
            .unwrap_or_else(|e| panic!("escape({input:?}) = {quoted:?} must compile: {e:?}"));
        assert!(
            re.is_match_at(input, 0),
            "escape({input:?}) = {quoted:?} must match the input"
        );
        // A pattern that matches only the input: a metacharacter replaced
        // by another literal must not be found, and a prefix of the input
        // must not be taken as the whole of it.
        if input.len() > 1 {
            let mut almost = input.to_vec();
            almost[0] = if almost[0] == b'a' { b'b' } else { b'a' };
            assert!(
                !re.is_match_at(&almost, 0),
                "escape({input:?}) = {quoted:?} also matched {almost:?}"
            );
        }
    }
    // Nothing to quote, nothing quoted.
    assert_eq!(super::escape(b"abc123"), b"abc123");
}

/// **A replacement template means what it means in ripgrep, byte for
/// byte** -- the gate the in-house `-r` swap stands on, and the gate that
/// found the defect it was first parked on.
///
/// # The rule
///
/// `$$` is a literal `$`; `${...}` is the braced spelling of a group by
/// number or by name; a bare `$` takes the WHOLE alphanumeric run that
/// follows as a name, and that name is a group number only when every
/// byte of it is a digit. So `X$1X` is `X` plus a reference to a group
/// named `1X` -- absent, so nothing -- and `${1}X` is group 1. A reference
/// to a group that did not participate, or to one the pattern has not
/// got, expands to nothing. **The `regex` crate's `expand` stops the run
/// at the digits** and answers `Xrgx_coreX` where ripgrep answers `X`;
/// the old `-r` went through the crate, so this is a shape where rgx and
/// rg already differed, and `scripts/compare-rg.ps1` now carries the case.
///
/// # The defect this gate found
///
/// The first fixture below is the defect's minimal form. `ByteRegex::search`
/// used to take its match-mask fast path for `(?<key>\w+)=(?<val>\w+)` with
/// the mask lowered to `\w@0`, `=@1`, `\w@2` -- the `=` placed at the
/// MINIMUM width of the `\w+` before it, because a repeat reports "its steps
/// fit a mask" and `lower_concat` reads that as "the next sibling's offset is
/// known". A group passed the repeat's claim straight up, so the `(\w+)` in
/// the group announced a fixed length it does not have:
///
/// ```text
/// pattern (\w+)=(\w+)   over "a=1 bb=22"   from 3
/// oracle   (4, 9)  key="bb" val="22"
/// before   (5, 9)  key="b"  val="22"      <- a mask bit at 4 was impossible
/// after    (4, 9)
/// ```
///
/// The fix is the boundary in [`super::required::lower`]'s group arm: a
/// group wrapping a repetition of non-fixed length keeps its steps (they
/// are required of every match) and declines to say its length is known,
/// which turns the mask from "the match starts here" into a prefilter
/// whose candidates are confirmed.
#[test]
fn replacement_templates_expand_like_rg() {
    fn expand_all(pat: &str, hay: &str, tmpl: &str) -> String {
        let re = ByteRegex::new(pat.as_bytes()).expect("compiles");
        let bytes = hay.as_bytes();
        let mut out: Vec<u8> = Vec::new();
        let mut at = 0usize;
        for m in re.captures_iter(bytes) {
            out.extend_from_slice(&bytes[at..m.start]);
            re.expand(&m, tmpl.as_bytes(), bytes, &mut out);
            at = m.end;
        }
        out.extend_from_slice(&bytes[at..]);
        String::from_utf8(out).expect("utf8 in, utf8 out")
    }
    for (pat, hay, tmpl, want) in [
        // Numbered groups, the braced spelling, and the whole match.
        (r"(\w+)=(\w+)", "a=1 bb=22", "$2=$1;", "1=a; 22=bb;"),
        (
            r"(?<key>\w+)=(?<val>\w+)",
            "a=1 bb=22",
            "[$val=$key]",
            "[1=a] [22=bb]",
        ),
        (
            r"(?<key>\w+)=(?<val>\w+)",
            "a=1 bb=22",
            "$2 -> $1;",
            "1 -> a; 22 -> bb;",
        ),
        (r"(\w+)", "abc", "<$0>${1}<$1>", "<abc>abc<abc>"),
        // `$$`, a group that does not exist, the whole match, a `$` with
        // nothing referable after it.
        (
            r"(\w+)",
            "abc",
            "cost: $$5 ${0} $ end",
            "cost: $5 abc $ end",
        ),
        (r"(a)?b", "b", "x${1}y", "xy"),
        (r"(a)(z)?", "a", "${2}|${1}|$3|${99}", "|a||"),
        // Names, and the run rule: `X$1X` is the name "1X", `${1}X` is the
        // group. The crate says "XabcX" for the first; ripgrep says "X".
        (r"(?<w>\w+)-(?<n>\d+)", "id-42", "$n/$w", "42/id"),
        (r"(\w+)", "abc", "X$1X", "X"),
        (r"(\w+)", "abc", "X${1}Y", "XabcY"),
        (r"(\w+)\s*=\s*(\w+)", "a=1", "$1$2$3", "a1"),
        (r"\b\w+\b", "one two", "$0 ", "one  two "),
    ] {
        let got = expand_all(pat, hay, tmpl);
        assert_eq!(got, want, "{pat} over {hay:?} with template {tmpl:?}");
    }
}

/// **The leftmost-first answer, on the shape the group boundary is for.**
/// A `+` behind a capture group: the required `=` is at offset 1 for the
/// shortest key and at 2 for a longer one, and a mask built at the minimum
/// has no bit at the start of a match with a longer key. The differential
/// template test above is the same fact seen through `-r`; this is the fact
/// itself, and it is short.
#[test]
fn a_grouped_repetition_does_not_pin_what_follows_it() {
    let hay = b"a=1 bb=22";
    let re = ByteRegex::new(b"(\\w+)=(\\w+)").expect("compiles");
    let m = re.search(hay, 3).expect("a match at or after 3");
    assert_eq!(
        (m.start, m.end),
        (4, 9),
        "the leftmost match is `bb=22` at 4, not `b=22` at 5"
    );
    assert_eq!(m.groups, vec![Some((4, 6)), Some((7, 9))]);
    // And the mask, which is what went wrong, is a prefilter here rather
    // than an oracle: it must not DECIDE.
    for c in re.anchor_costs(hay) {
        assert_ne!(
            c.info.kind, "matchmask",
            "a mask that places a byte at a repetition's minimum width cannot decide"
        );
    }
}

/// **The fix does not cost the pattern the mask was built for.**
/// `(pub|fn) [a-z]+` has a variable TAIL, and its space sits at the same
/// offset in both branches, so its mask is exact and DECIDES -- that bit is
/// the whole reason the pattern is 15% faster on the reader path. A group
/// boundary that took the tail with it would show here first.
#[test]
fn the_flagship_mask_still_decides() {
    let re = ByteRegex::new(b"(pub|fn) [a-z]+").expect("compiles");
    let costs = re.anchor_costs(b"pub fn helper");
    assert!(
        costs.iter().any(|c| c.info.kind == "matchmask"),
        "the match mask is gone from (pub|fn) [a-z]+: {:?}",
        costs.iter().map(|c| c.info.kind).collect::<Vec<_>>()
    );
}

/// **`captures_iter` yields the same non-overlapping stream the
/// template loop assumes** -- a second match starts where the first
/// ended, and an empty match steps one byte so the iteration ends.
#[test]
fn captures_iter_is_non_overlapping() {
    let re = ByteRegex::new(b"a+").expect("compiles");
    let spans: Vec<(usize, usize)> = re
        .captures_iter(b"baaa")
        .map(|m| (m.start, m.end))
        .collect();
    assert_eq!(spans, vec![(1, 4)], "one greedy match then the end");

    let re = ByteRegex::new(b"a*").expect("compiles");
    let spans: Vec<(usize, usize)> = re.captures_iter(b"baa").map(|m| (m.start, m.end)).collect();
    assert_eq!(
        spans,
        vec![(0, 0), (1, 3)],
        "an empty match, then the run -- and then it stops"
    );
}

/// **Direct confirmation and candidate quenching for `foo.*bar` shapes.**
///
/// Ensures `DirectConfirm` is compiled for `foo.*bar` patterns and can answer
/// queries without running the Pike VM, and that `suffix_checks` quenches false
/// candidates when `bar` does not follow `foo`.
#[test]
fn foo_dot_star_bar_direct_confirmation_and_quenching() {
    let re = ByteRegex::new(b"foo.*bar").expect("compiles");
    assert!(re.direct.is_some(), "foo.*bar must compile a DirectConfirm");
    let dc = re.direct.as_ref().unwrap();
    assert_eq!(dc.prefix, b"foo");
    assert_eq!(dc.suffix, b"bar");
    assert_eq!(dc.min_gap, 0);
    assert!(!dc.dot_all);

    // Direct confirmation on single lines
    assert!(re.line_matches(b"foo bar"));
    assert!(re.line_matches(b"123 foo middle text bar 456"));
    assert!(re.line_matches(b"foo___bar"));
    assert!(!re.line_matches(b"foo only"));
    assert!(!re.line_matches(b"bar only"));
    assert!(!re.line_matches(b"bar precedes foo"));
    assert!(!re.line_matches(b"foo\nbar"));

    // Matcher trait methods
    assert!(re.is_match_at(b"foobar", 0));
    assert!(!re.is_match_at(b"foobar", 1));
    assert!(re.is_match_at(b"xxxfoobar", 3));

    // Suffix check present in prefilter
    let fl = fast(&re);
    assert!(
        !fl.suffix_checks.is_empty(),
        "foo.*bar prefilter must populate suffix_checks"
    );
    assert_eq!(fl.suffix_checks[0].needle, b"bar");
    assert_eq!(fl.suffix_checks[0].min_offset, 3);
    assert!(!fl.suffix_checks[0].dot_all);

    // Admits quenches candidate at 'foo' when 'bar' does not follow
    assert!(!fl.admits(b"bar foo baz", 4));
    assert!(fl.admits(b"foo bar", 0));

    // Caseless variant
    let re_ci = ByteRegex::new_flags(b"(?i)foo.*bar", true).expect("compiles");
    assert!(re_ci.direct.is_some());
    assert!(re_ci.line_matches(b"FOO 123 BAR"));
    assert!(re_ci.line_matches(b"Foo middle Bar"));
    assert!(!re_ci.line_matches(b"Bar middle Foo"));
}

#[test]
fn two_byte_literal_maps_candidates() {
    use crate::searcher::CandidateSource;
    let re = ByteRegex::new(b"fn").expect("compiles");
    let hay = b"pub fn main() {\n    let x = 1;\n    fn helper() {}\n}\n";
    let mut bm = crate::scan::BitMap::new();
    let orig = re.map_candidates(hay, &mut bm);
    assert!(
        orig.is_some(),
        "2-byte literal must produce a candidate map"
    );
    assert!(bm.any_set(0, 10));
    assert!(bm.any_set(30, 45));
    assert!(!bm.any_set(15, 30));
}
