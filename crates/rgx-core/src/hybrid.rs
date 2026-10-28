// SPDX-License-Identifier: Apache-2.0

//! Deciding per LINE rather than per FILE.
//!
//! `rgx-core` has no `char` in the byte engine, whereas a codepoint-aware
//! regex matcher disagrees on character classes as soon as a window holds a
//! byte above `0x7f`. On a window that is entirely ASCII they agree: every
//! codepoint class is a byte class. [`HybridMatcher`] runs [`ByteRegex`] over
//! ASCII windows and hands the rest to a [`UnicodeMatcher`] delegate supplied
//! by the caller (the standalone `rgx` binary instantiates [`ByteRegex`]
//! directly; [`HybridMatcher`] is the library seam for callers that bring a
//! Unicode engine).
//!
//! The delegate sees one line's content, never a terminator, and its
//! `^`/`$` must be the line's. A multi-line Unicode regex engine is
//! exactly that, which is why the seam is a trait: `rgx-core` is `no_std`
//! and carries no external regex dependency.
//!
//! A UTF-16 file searched as the interleaving that encodes it is not a
//! slower search but a different one; see
//! `searcher::Config::bom_sniffing`.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::matcher::Matcher;
use super::regex::ByteRegex;
use super::searcher::{CandidateSource, Candidates, LineCandidates, Origin};

/// A line-oriented matcher with `grep`'s Unicode semantics.
///
/// One required method, because the other two follow from it under
/// leftmost-first semantics: a match begins at `at` exactly when the leftmost
/// match at or after `at` starts at `at`.
pub trait UnicodeMatcher: Send + Sync {
    /// The extent of the leftmost match at or after `at` in one line's
    /// content, or `None`.
    ///
    /// `line` is a line's content with the line terminator already cut off,
    /// so `^` is offset 0 and `$` is `line.len()`.
    fn find_span(&self, line: &[u8], at: usize) -> Option<core::ops::Range<usize>>;

    /// Whether a match begins exactly at `at`.
    fn is_match_at(&self, line: &[u8], at: usize) -> bool {
        matches!(self.find_span(line, at), Some(s) if s.start == at)
    }

    /// Whether the pattern can match at all.
    fn can_match(&self) -> bool {
        true
    }
}

/// Whether every byte is below `0x80`.
///
/// The one predicate the whole design turns on: it is a byte test, not a
/// UTF-8 test. Invalid UTF-8 fails it, as a valid `é` does, and that is
/// correct because neither is something the byte engine may decide.
#[inline]
pub fn is_ascii(bytes: &[u8]) -> bool {
    // `<[u8]>::is_ascii` lowers to a single `_mm256_movemask_epi8` (or
    // the NEON equivalent) on x86-64 / aarch64.
    bytes.is_ascii()
}

/// The byte engine over ASCII lines, a [`UnicodeMatcher`] over the rest.
///
/// The byte engine is borrowed rather than owned so a caller can build one of
/// these per search: the pattern is compiled once and the hybrid is a stack
/// value over it, not a second compilation per file.
pub struct HybridMatcher<'a, D> {
    byte: &'a ByteRegex,
    unicode: D,
    /// Caseless and the pattern is non-ASCII, so Unicode folding can put a
    /// match on an ASCII line the byte engine would miss. Every line goes to
    /// the delegate while this holds.
    fold_risky: bool,
    /// The pattern is a case-sensitive literal, and there is no line on which
    /// the two engines can answer differently.
    ///
    /// This is what keeps the design free where it matters. A literal is
    /// matched as bytes by both sides, and a case-SENSITIVE one has no
    /// codepoint semantics at all: no class to expand, no `.` to count, no
    /// fold. So the ASCII test is not merely cheap here, it is unnecessary,
    /// and neither the per-line test nor the whole-buffer one is paid. The
    /// caseless case cannot say that -- `grep -i kelvin` matches U+212A for
    /// `k` -- which is why the flag is on the case-sensitive half of the
    /// fast-literal path and not on the whole of it.
    byte_always_decides: bool,
    /// Whether the buffer the last [`CandidateSource::candidates`] call was
    /// given held nothing but ASCII.
    ///
    /// The searcher builds the stream from the buffer it is about to walk, and
    /// every line is a sub-slice of that buffer, so one whole-buffer test
    /// settles every line in it and the per-line test is only reached when a
    /// caller supplied no stream. It is never set without having been
    /// observed, so a stale `true` cannot be read: only `candidates` writes
    /// it, and only for a buffer it has just cleared.
    buffer_ascii: AtomicBool,
}

impl<'a, D: UnicodeMatcher> HybridMatcher<'a, D> {
    /// Pair the two engines. `unicode` is asked about every line that
    /// `byte` may not decide.
    pub fn new(byte: &'a ByteRegex, unicode: D) -> Self {
        let fold_risky = byte.is_case_insensitive() && !byte.as_bytes().is_ascii();
        // A fast literal is the WHOLE pattern, metacharacters and all:
        // the two engines are the same function. It is deliberately
        // NOT `has_prefilter`: a required literal skips lines but
        // `e.` is not enough to decide one -- the byte engine reads
        // `é` as two bytes and `grep` as one codepoint.
        let byte_always_decides =
            (byte.has_fast_literal() || byte.is_pure_ascii()) && !byte.is_case_insensitive();
        HybridMatcher {
            byte,
            unicode,
            fold_risky,
            byte_always_decides,
            buffer_ascii: AtomicBool::new(false),
        }
    }

    /// Whether `hay` is a line the byte engine may decide.
    ///
    /// The whole slice is tested, not the tail from `at`: the byte engine
    /// anchors `^` to the start of what it is given.
    #[inline]
    fn byte_decides(&self, hay: &[u8]) -> bool {
        if self.byte_always_decides {
            return true;
        }
        !self.fold_risky && (self.buffer_ascii.load(Ordering::Relaxed) || is_ascii(hay))
    }
}

impl<'a, D: UnicodeMatcher> Matcher for HybridMatcher<'a, D> {
    #[inline]
    fn find_at(&self, hay: &[u8], at: usize) -> Option<usize> {
        if self.byte_decides(hay) {
            self.byte.find_at(hay, at)
        } else {
            self.unicode.find_span(hay, at).map(|s| s.start)
        }
    }

    #[inline]
    fn find_span_at(&self, hay: &[u8], at: usize) -> Option<core::ops::Range<usize>> {
        if self.byte_decides(hay) {
            self.byte.find_span_at(hay, at)
        } else {
            self.unicode.find_span(hay, at)
        }
    }

    #[inline]
    fn is_match_at(&self, hay: &[u8], at: usize) -> bool {
        if self.byte_decides(hay) {
            self.byte.is_match_at(hay, at)
        } else {
            self.unicode.is_match_at(hay, at)
        }
    }

    /// A line the byte engine may not decide is scanned whole.
    ///
    /// The candidates were built for the byte engine's prefilter, and a
    /// delegated line was not part of that plan -- [`Self::candidates`] adds
    /// every offset of such a line precisely so that this method is reached at
    /// all, and once here the candidates carry no information the delegate
    /// could use. Ignoring them is what makes them a liveness device rather
    /// than a filter.
    #[inline]
    fn any_match_in(&self, line: &[u8], cands: LineCandidates<'_>, origin: Origin) -> bool {
        if self.byte_decides(line) {
            self.byte.any_match_in(line, cands, origin)
        } else {
            self.unicode.find_span(line, 0).is_some()
        }
    }

    /// The byte engine's answer, and only ever consulted on a line it decides.
    ///
    /// The default is `false`, which is the whole line scanned; a hybrid that
    /// inherited it would leave every `^`-anchored pattern on the slow confirm
    /// even though the byte engine underneath could have taken the anchored
    /// one. The non-ASCII branch of [`any_match_in`](Matcher::any_match_in)
    /// goes to the delegate with the line and asks it where to look, so it
    /// does not consult this.
    fn line_anchored(&self) -> bool {
        self.byte.line_anchored()
    }

    fn can_match(&self) -> bool {
        self.byte.can_match() && self.unicode.can_match()
    }

    /// The window rule (maintainer-approved, `benchmark/findings.md` §13):
    /// a mask match whose widest window is pure ASCII is a match in both
    /// engines -- on ASCII bytes a codepoint is a byte -- so it settles the
    /// line; the delegate is asked only when every window is refused. The
    /// searcher offers the whole line first (one map lookup settles a clean
    /// line outright) and each bit's window only on a dirty line.
    fn decides_window(&self, _window: &[u8], window_ascii: bool) -> bool {
        self.byte_always_decides || (!self.fold_risky && window_ascii)
    }

    fn may_decline_lines(&self) -> bool {
        !self.byte_always_decides && !self.fold_risky
    }
}

impl<'a, D: UnicodeMatcher> CandidateSource for HybridMatcher<'a, D> {
    /// The literal prefilter over the ASCII lines, widened to every offset of
    /// every line the delegate will have to decide.
    ///
    /// The searcher skips a line outright when its stream is empty for
    /// that line, so a line the byte engine may not decide has to carry
    /// at least one offset. The offsets are read but not used: such a
    /// line is scanned whole.
    fn candidates<'b>(&'b self, hay: &'b [u8], out: &'b mut Vec<usize>) -> Candidates<'b> {
        // No literal to widen means every offset is already a candidate,
        // which also covers a delegated line.
        if self.fold_risky || !self.byte.has_prefilter() {
            return Candidates::every(hay.len());
        }
        // The DENSE arm: a one-byte case-sensitive literal hits roughly
        // 5% of real source, so its offsets would be ~13 million
        // `usize` per 235 MB and the allocation + extra pass are not
        // worth it — `memchr` already finds them in the same pass.
        if self.byte_always_decides {
            if let Some(c) = self.byte.fast_candidates_lazy(hay) {
                return c;
            }
            // The masked arm. A byte-set anchor (e.g. `[0-9]` in `e[0-9]`) is a
            // scan the searcher cannot pull on demand, so the offsets are
            // written out and the offset they must be reduced by travels
            // with the stream.
            let anchor = self.byte.anchor_for(hay);
            out.clear();
            self.byte.fast_candidates(hay, out);
            return Candidates::of(out).with_origin(anchor);
        }
        // Whether a buffer holds a non-ASCII line is settled FIRST, and
        // that is what makes the dense arm safe to take on the way. When
        // the pattern requires an ASCII prefilter, any line without that
        // prefilter cannot match in Unicode either.
        let needs_widening = !self.byte.has_pure_ascii_prefilter();
        let all_ascii = is_ascii(hay);
        self.buffer_ascii.store(all_ascii, Ordering::Relaxed);
        if all_ascii || !needs_widening {
            if let Some(c) = self.byte.fast_candidates_lazy(hay) {
                return c;
            }
            let anchor = self.byte.anchor_for(hay);
            out.clear();
            self.byte.fast_candidates(hay, out);
            return Candidates::of(out).with_origin(anchor);
        }
        let anchor = self.byte.anchor_for(hay);
        out.clear();
        self.byte.fast_candidates(hay, out);
        // The walk is skipped on an all-ASCII buffer, which must not pay.
        widen_to_non_ascii_lines(hay, out);
        Candidates::of(out).with_origin(anchor)
    }

    /// The map form, and it may only answer `Some` where [`Self::candidates`]
    /// would have answered with a stream that needed no widening.
    ///
    /// The same three declining cases apply: taking the map on a buffer
    /// that needs widening would silently drop the delegate's lines.
    fn map_candidates(
        &self,
        hay: &[u8],
        out: &mut crate::scan::BitMap,
    ) -> Option<super::searcher::Origin> {
        // Caseless and non-ASCII, or no prefilter: `candidates` returns
        // `every`, which is not a byte scan and cannot be mapped.
        if self.fold_risky || !self.byte.has_prefilter() {
            return None;
        }
        let needs_widening = !self.byte.has_pure_ascii_prefilter();
        if !self.byte_always_decides {
            // Settle the buffer's ASCII-ness FIRST and store the answer,
            // so the per-line `byte_decides` test is not re-run per line
            // and agrees with the whole-buffer decision.
            let all_ascii = is_ascii(hay);
            self.buffer_ascii
                .store(all_ascii, core::sync::atomic::Ordering::Relaxed);
            if !all_ascii && needs_widening {
                return None;
            }
        }
        self.byte.map_candidates(hay, out)
    }

    /// The `(cut, span)` widths of the match mask the byte engine just
    /// filled, or `None`.
    ///
    /// Forwarded for the same reason as [`Self::map_candidates`]: the two
    /// declining cases there (no prefilter to map, a mixed buffer that needs
    /// widening) decline before this is reached at all, and a mask behind one
    /// of them would settle a line the delegate still has to decide.
    ///
    /// The old whole-buffer `buffer_ascii` gate is gone: the searcher's line
    /// loop takes the window rule instead (see [`Matcher::decides_window`]),
    /// so a bit whose match window is pure ASCII settles its line and the
    /// delegate is asked only about the windows that touch a high byte. The
    /// buffer gate was correct but paid for the whole fill -- one `é` in a
    /// 64 KiB source window put every line of it back on the confirm chain,
    /// which on the 247 MB single-file row is most of the walk (`e.`:
    /// 291.6 -> 100.2 ms with the settle forced, which also skips the report
    /// tail; benchmark/findings.md §13 decomposes it).
    fn map_is_match_mask(&self, hay: &[u8]) -> Option<(usize, usize)> {
        if self.fold_risky || !self.byte.has_prefilter() {
            return None;
        }
        self.byte.map_is_match_mask(hay)
    }
}

/// Merge every offset of every non-ASCII line into an ascending,
/// deduplicated candidate stream. A no-op on an all-ASCII hay.
///
/// `Candidates::in_line` advances a single cursor and rebases each
/// offset against the line it hands out, so the merge has to stay
/// ascending — an out-of-order offset becomes a subtraction that
/// underflows.
fn widen_to_non_ascii_lines(hay: &[u8], out: &mut Vec<usize>) {
    let mut extra: Vec<usize> = Vec::new();
    let mut start = 0usize;
    while start < hay.len() {
        let end = match crate::memchr::memchr(b'\n', &hay[start..]) {
            Some(i) => start + i,
            None => hay.len(),
        };
        if !is_ascii(&hay[start..end]) {
            extra.extend(start..end);
        }
        start = end + 1;
    }
    if extra.is_empty() {
        return;
    }
    let mut merged = Vec::with_capacity(out.len() + extra.len());
    let (mut i, mut j) = (0usize, 0usize);
    while i < out.len() || j < extra.len() {
        let take = match (out.get(i), extra.get(j)) {
            (Some(&a), Some(&b)) if a < b => {
                i += 1;
                a
            }
            (Some(&a), Some(&b)) if a > b => {
                j += 1;
                b
            }
            (Some(&a), Some(_)) => {
                i += 1;
                j += 1;
                a
            }
            (Some(&a), None) => {
                i += 1;
                a
            }
            (None, Some(&b)) => {
                j += 1;
                b
            }
            (None, None) => break,
        };
        merged.push(take);
    }
    *out = merged;
}

#[cfg(test)]
mod tests {
    use super::is_ascii;
    use alloc::vec::Vec;

    /// Every length across word and tail boundaries, with the high byte at
    /// every position: the tail is covered by an overlapping read, where an
    /// off-by-one would hide.
    #[test]
    fn is_ascii_agrees_with_a_byte_test_at_every_length() {
        for len in 0..200usize {
            let clean = alloc::vec![b'a'; len];
            assert!(is_ascii(&clean), "len {len}");
            for at in 0..len {
                let mut dirty = clean.clone();
                dirty[at] = 0xC3;
                assert!(!is_ascii(&dirty), "len {len} high byte at {at}");
            }
        }
        assert!(is_ascii(b""));
        assert!(!is_ascii(b"\x80"));
        assert!(!is_ascii(b"\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x80"));
    }

    /// The widened stream must stay ascending for buffers that mix literal
    /// hits with delegated lines in both orders.
    #[test]
    fn widening_keeps_the_stream_ascending() {
        use super::widen_to_non_ascii_lines;
        let cases: &[&[u8]] = &[
            b"plain\n",
            "caf\u{e9}\nplain\n".as_bytes(),
            "plain\ncaf\u{e9}\n".as_bytes(),
            "needle\ncaf\u{e9} needle\nneedle\n".as_bytes(),
            "caf\u{e9} needle\nplain needle\n".as_bytes(),
        ];
        for hay in cases {
            for lit in [0usize, 2, 5, 7] {
                let mut out: Vec<usize> = (0..lit).map(|i| i * 3).collect();
                out.sort_unstable();
                out.retain(|&o| o < hay.len());
                let before = out.clone();
                widen_to_non_ascii_lines(hay, &mut out);
                for w in out.windows(2) {
                    assert!(w[0] < w[1], "not ascending: {out:?} for {hay:?}");
                }
                for o in &before {
                    assert!(out.contains(o), "lost literal candidate {o}");
                }
            }
        }
    }
}
