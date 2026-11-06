// SPDX-License-Identifier: Apache-2.0

//! Exact k-edit-distance literal search as a bounded relaxation.
//!
//! Finds every start position whose best window is within `k` unit-cost
//! insertions, deletions and substitutions of a literal pattern. The
//! computation is a bounded relaxation over the alignment lattice: states are
//! (pattern position, text position), arcs cost 0 on a match and 1 on an
//! edit, and the budget `k` bounds the label. States whose edit count would
//! exceed `k` are discarded before they are computed -- a discard-only cut
//! with zero false negatives, because arc costs are non-negative and a label
//! above the budget can only grow.
//!
//! One match is reported per start: the window with the smallest edit count,
//! ties broken by the smallest window. A window consumes at least one byte;
//! zero-width matches are refused, and an empty pattern matches nothing (the
//! searcher's convention for empty literals). What this is NOT: not a regex
//! engine (literal bytes only), not a q-gram prefilter (`k > 0` stands the
//! exact prefilter down -- see [`exact_prefilter_stands_down`]), and not
//! wired into the `rgx` CLI (its sink surface is typed on `ByteRegex`; that
//! plumbing is a separate change). Worst-case cost is one band sweep per
//! start, `O((m + k) * k)` cells, so `O(n * m * k)` per slice.

use alloc::vec::Vec;
use core::ops::Range;

use super::matcher::Matcher;

/// One approximate occurrence: the window and its edit count.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FuzzyMatch {
    /// Byte offset of the window's first byte.
    pub start: usize,
    /// Byte offset one past the window's last byte.
    pub end: usize,
    /// Unit-cost edit distance between the pattern and `hay[start..end]`.
    pub edits: u32,
}

/// What the relaxation did, so the band's work is observable.
///
/// A discard-only tier that removes nothing is indistinguishable from one
/// that is not wired up; `cells_quenched` is the number that says it fired.
#[derive(Clone, Copy, Default, Debug)]
pub struct FuzzyStats {
    /// Start positions whose band sweep ran.
    pub starts_scanned: u64,
    /// Lattice cells computed (inside the band, under the budget).
    pub cells_admitted: u64,
    /// Lattice cells the band or the budget cut without computing them.
    pub cells_quenched: u64,
}

/// Whether the exact-literal prefilter may prune for `k` edit budget.
///
/// The n-gram/nibble-mask tier prunes on the pattern's bytes occurring
/// exactly, which is a necessary condition only at `k == 0`: one substitution
/// removes every exact occurrence, so consulting the mask at `k > 0` would
/// drop true matches. The rule is stand-down, not "no candidates" -- a filter
/// that declines must say so and let the confirm see the whole line. A
/// k-aware q-gram bound (a window within `k` edits must still share most of
/// the pattern's q-grams) is the future path to pruning at `k > 0`; until it
/// exists and is proven zero-false-negative, the answer is `true`.
pub fn exact_prefilter_stands_down(k: u32) -> bool {
    k > 0
}

/// The two rolling rows of one band sweep, reused across starts.
#[derive(Default)]
struct Rows {
    prev: Vec<u32>,
    cur: Vec<u32>,
}

const DEAD: u32 = u32::MAX;

impl Rows {
    /// Ensure both rows hold `width` cells. `prev` becomes row 0 of a fresh
    /// sweep (`0, 1, 2, ...` -- the empty pattern against each text prefix);
    /// `cur` is scratch, filled before it is read.
    fn reset(&mut self, width: usize) {
        self.prev.clear();
        self.prev.resize(width, DEAD);
        for (i, cell) in self.prev.iter_mut().enumerate() {
            *cell = i as u32;
        }
        self.cur.clear();
        self.cur.resize(width, DEAD);
    }
}

/// The band sweep for one start: the best window of `hay[s..]` within `k`
/// edits of `pat`, or `None` when no window at this start qualifies.
///
/// `rows` is scratch; the sweep reuses it. `stats.cells_admitted` counts the
/// cells that survived, and the rest of the lattice rectangle is added to
/// `cells_quenched` at the end, so `admitted + quenched` is every cell.
fn best_at_start(
    pat: &[u8],
    hay: &[u8],
    s: usize,
    k: u32,
    stats: &mut FuzzyStats,
    rows: &mut Rows,
) -> Option<FuzzyMatch> {
    let m = pat.len();
    // The pattern is empty only in the refusal case; the callers handle it.
    debug_assert!(m > 0);
    let ku = k as usize;
    // No window can exceed m + k bytes (more text is more than k deletions)
    // or fall short of m - k (more pattern is more than k insertions).
    let max_l = m.saturating_add(ku);
    let cap = core::cmp::min(hay.len() - s, max_l);
    let min_l = m.saturating_sub(ku).max(1); // a window consumes >= 1 byte
    if min_l > cap {
        return None;
    }

    rows.reset(cap + 1);
    stats.starts_scanned += 1;
    let admitted_before = stats.cells_admitted;

    for j in 1..=m {
        // Band for row j: |i - j| <= k. A cell outside it cannot reach the
        // budget (each indel shifts the diagonal by one), and a cell above
        // the budget cannot come back down (arc costs are non-negative), so
        // both are cut before admission -- the discard-only step.
        let lo = j.saturating_sub(ku);
        let hi = core::cmp::min(cap, j + ku);
        if lo > hi {
            // The row is entirely out of band; so is every row after it.
            for cell in rows.cur.iter_mut() {
                *cell = DEAD;
            }
        } else {
            for i in lo..=hi {
                let v = if i == 0 {
                    // No text consumed: the pattern's j chars against
                    // nothing is j edits. Inside the band this is <= k.
                    j as u32
                } else {
                    let cost = u32::from(pat[j - 1] != hay[s + i - 1]);
                    let sub = rows.prev[i - 1].saturating_add(cost);
                    let del = rows.prev[i].saturating_add(1);
                    // cur[i-1] is this row's left neighbour, written by the
                    // previous step -- except at the band's left edge, where
                    // the neighbour is outside the band and therefore dead.
                    let ins = if i > lo {
                        rows.cur[i - 1].saturating_add(1)
                    } else {
                        DEAD
                    };
                    sub.min(del).min(ins)
                };
                rows.cur[i] = if v > k { DEAD } else { v };
                if v <= k {
                    stats.cells_admitted += 1;
                }
            }
        }
        // `prev` becomes row j. Values left stale outside the band are never
        // read: every read above stays inside the previous row's band.
        core::mem::swap(&mut rows.prev, &mut rows.cur);
    }

    // Acceptance row (row m, in `prev` after the last swap): a match is a
    // window length L in [min_l, cap] under the budget. Best edits first,
    // then the smallest window -- the reporting convention.
    let mut best: Option<(u32, usize)> = None;
    for (l, &e) in rows.prev.iter().enumerate().take(cap + 1).skip(min_l) {
        if e == DEAD {
            continue;
        }
        match best {
            Some((be, bl)) if (be, bl) <= (e, l) => {}
            _ => best = Some((e, l)),
        }
    }

    // Everything the sweep did not admit is quenched, in-band or not.
    let total = (m + 1) * (cap + 1);
    let admitted = (stats.cells_admitted - admitted_before) as usize;
    stats.cells_quenched += (total - admitted) as u64;

    best.map(|(edits, l)| FuzzyMatch {
        start: s,
        end: s + l,
        edits,
    })
}

/// Best window for every start at or after `at`, scanning starts left to
/// right and returning the first that qualifies.
pub fn find_from(pat: &[u8], hay: &[u8], at: usize, k: u32) -> Option<FuzzyMatch> {
    if pat.is_empty() {
        return None;
    }
    let mut stats = FuzzyStats::default();
    find_from_counted(pat, hay, at, k, &mut stats)
}

/// [`find_from`] with the sweep's counters exposed.
pub fn find_from_counted(
    pat: &[u8],
    hay: &[u8],
    at: usize,
    k: u32,
    stats: &mut FuzzyStats,
) -> Option<FuzzyMatch> {
    if pat.is_empty() {
        return None;
    }
    let mut rows = Rows::default();
    for s in at..hay.len() {
        if let Some(hit) = best_at_start(pat, hay, s, k, stats, &mut rows) {
            return Some(hit);
        }
    }
    None
}

/// Every start's best window within `k` edits, plus the sweep's counters.
pub fn find_all(pat: &[u8], hay: &[u8], k: u32) -> (Vec<FuzzyMatch>, FuzzyStats) {
    let mut out = Vec::new();
    let mut stats = FuzzyStats::default();
    if pat.is_empty() {
        return (out, stats);
    }
    let mut rows = Rows::default();
    for s in 0..hay.len() {
        if let Some(hit) = best_at_start(pat, hay, s, k, &mut stats, &mut rows) {
            out.push(hit);
        }
    }
    (out, stats)
}

/// A literal pattern matched within `k` unit-cost edits.
///
/// Implements [`Matcher`] so the line searcher can consume it. The candidate
/// tier stands down with it: build the searcher with
/// [`crate::searcher::Searcher::new`] and never
/// [`crate::searcher::Searcher::with_candidates`], because the exact-literal
/// prefilter cannot prune at `k > 0` ([`exact_prefilter_stands_down`]). The
/// confirm then runs the band sweep on the whole line, which is what
/// `any_match_in`'s contract asks of a matcher without candidates.
pub struct FuzzyMatcher {
    pat: Vec<u8>,
    k: u32,
}

impl FuzzyMatcher {
    /// A matcher for `pat` within `k` unit-cost edits. An empty pattern is
    /// accepted and matches nothing ([`Matcher::can_match`]).
    pub fn new(pat: &[u8], k: u32) -> Self {
        Self {
            pat: pat.to_vec(),
            k,
        }
    }

    /// The edit budget this matcher was built with.
    pub fn max_edits(&self) -> u32 {
        self.k
    }

    /// Best window at this exact start, or `None`.
    pub fn best_at(&self, hay: &[u8], at: usize) -> Option<FuzzyMatch> {
        if self.pat.is_empty() || at >= hay.len() {
            return None;
        }
        let mut stats = FuzzyStats::default();
        let mut rows = Rows::default();
        best_at_start(&self.pat, hay, at, self.k, &mut stats, &mut rows)
    }

    /// Best window at or after `at`, or `None`.
    pub fn find_from(&self, hay: &[u8], at: usize) -> Option<FuzzyMatch> {
        find_from(&self.pat, hay, at, self.k)
    }
}

impl Matcher for FuzzyMatcher {
    fn find_at(&self, hay: &[u8], at: usize) -> Option<usize> {
        self.find_from(hay, at).map(|m| m.start)
    }

    fn find_span_at(&self, hay: &[u8], at: usize) -> Option<Range<usize>> {
        self.find_from(hay, at).map(|m| m.start..m.end)
    }

    fn is_match_at(&self, hay: &[u8], at: usize) -> bool {
        self.best_at(hay, at).is_some()
    }

    fn can_match(&self) -> bool {
        !self.pat.is_empty()
    }

    // Everything else is the trait's default, deliberately: the band sweep is
    // the deciding engine (decides_window stays true -- this matcher has no
    // delegate to defer to), any_match_in's default scans the whole line,
    // which is exactly the stood-down confirm, and no candidate source is
    // attached at the searcher.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzkit::Rng;
    use crate::literal::NibbleMask;
    use crate::prefilter::Prefilter;
    use crate::searcher::{Config, Searcher, Sink, SinkContext, SinkFinish, SinkMatch};

    // ---- the reference: full matrix, no band, same conventions ----------
    //
    // Same reporting convention as the engine (best edits then smallest
    // window; window consumes at least one byte), so parity is about the
    // relaxation and not about the definition.

    fn reference_best_at_start(pat: &[u8], hay: &[u8], s: usize, k: u32) -> Option<FuzzyMatch> {
        let m = pat.len();
        let ku = k as usize;
        let max_l = m.saturating_add(ku);
        let cap = core::cmp::min(hay.len() - s, max_l);
        let min_l = m.saturating_sub(ku).max(1);
        if min_l > cap {
            return None;
        }
        // Full (m+1) x (cap+1) matrix, every cell computed.
        let mut prev: Vec<u32> = (0..=cap as u32).collect();
        let mut cur = vec![0u32; cap + 1];
        for j in 1..=m {
            cur[0] = j as u32;
            for i in 1..=cap {
                let sub = prev[i - 1] + u32::from(pat[j - 1] != hay[s + i - 1]);
                let del = prev[i] + 1;
                let ins = cur[i - 1] + 1;
                cur[i] = sub.min(del).min(ins);
            }
            core::mem::swap(&mut prev, &mut cur);
        }
        let mut best: Option<(u32, usize)> = None;
        for (l, &e) in prev.iter().enumerate().take(cap + 1).skip(min_l) {
            if e > k {
                continue; // the budget: the band cuts the same cells
            }
            match best {
                Some((be, bl)) if (be, bl) <= (e, l) => {}
                _ => best = Some((e, l)),
            }
        }
        best.map(|(edits, l)| FuzzyMatch {
            start: s,
            end: s + l,
            edits,
        })
    }

    fn reference_find_all(pat: &[u8], hay: &[u8], k: u32) -> Vec<FuzzyMatch> {
        if pat.is_empty() {
            return Vec::new();
        }
        (0..hay.len())
            .filter_map(|s| reference_best_at_start(pat, hay, s, k))
            .collect()
    }

    /// Mismatch count between two match lists. The parity gate asserts zero;
    /// the negative control asserts non-zero on a corrupted copy, which is
    /// how the gate proves it can fail instead of trusting that it would.
    fn mismatch_count(a: &[FuzzyMatch], b: &[FuzzyMatch]) -> usize {
        let mut bad = a.len().abs_diff(b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            if x != y {
                bad += 1;
            }
        }
        bad
    }

    fn assert_parity(pat: &[u8], hay: &[u8], k: u32) {
        let (got, _stats) = find_all(pat, hay, k);
        let want = reference_find_all(pat, hay, k);
        assert_eq!(
            mismatch_count(&got, &want),
            0,
            "parity broke for pat={pat:?} hay={hay:?} k={k}: got {got:?} want {want:?}"
        );
    }

    // ---- parity --------------------------------------------------------

    #[test]
    fn parity_on_handcrafted_shapes() {
        let cases: &[(&[u8], &[u8], u32)] = &[
            (b"abc", b"abc", 0),
            (b"abc", b"abc", 1),
            (b"abc", b"abd", 1),
            (b"abc", b"abd", 0),
            (b"abc", b"ab", 1),
            (b"abc", b"ab", 2),
            (b"abc", b"", 3),
            (b"abc", b"", 2),
            (b"a", b"aaaa", 0),
            (b"a", b"bbbb", 1),
            (b"abc", b"abXabc", 1),
            (b"needle", b"the neddle is here", 1),
            (b"needle", b"the neddle is here", 0),
            (b"aaaa", b"aaaaaaaaaa", 2),
            (b"xyz", b"xy", 3),
            (b"ab", b"ba", 1),
            (b"ab", b"ba", 0),
            (b"abc", b"abbc", 1),
            (b"abc", b"aabc", 1),
            (b"abc", b"aXbXc", 2),
            (b"abc", b"aXbXc", 1),
        ];
        for &(pat, hay, k) in cases {
            assert_parity(pat, hay, k);
        }
    }

    #[test]
    fn parity_on_deterministic_random_slices() {
        // The crate's own deterministic RNG: no new PRNG, and every run
        // sees the same corpus. Small alphabets force byte collisions,
        // which is where band and full matrix can disagree.
        let mut rng = Rng::new(0x5EED_1234);
        for round in 0..200 {
            let alphabet: &[u8] = if round % 2 == 0 { b"ab" } else { b"abcX" };
            let m = 1 + rng.below(7);
            let n = rng.below(18);
            let k = (rng.below(4)) as u32;
            let pat: Vec<u8> = (0..m)
                .map(|_| alphabet[rng.below(alphabet.len())])
                .collect();
            let hay: Vec<u8> = (0..n)
                .map(|_| alphabet[rng.below(alphabet.len())])
                .collect();
            assert_parity(&pat, &hay, k);
        }
    }

    // ---- the gate can fail ---------------------------------------------

    #[test]
    fn negative_control_corruption_is_caught() {
        let (mut got, _) = find_all(b"abc", b"abXabc", 1);
        let want = reference_find_all(b"abc", b"abXabc", 1);
        assert_eq!(mismatch_count(&got, &want), 0);
        // Corrupt one field of one entry: the comparator must notice. A
        // comparator that cannot report a difference is indistinguishable
        // from one that passes.
        got[0].edits += 1;
        assert!(
            mismatch_count(&got, &want) > 0,
            "the parity comparator cannot fail"
        );
    }

    // ---- the band is live ----------------------------------------------

    #[test]
    fn band_prunes_cells() {
        let pat: Vec<u8> = (0..24u8).collect();
        let hay: Vec<u8> = (0..200u8).map(|i| i.wrapping_mul(7)).collect();
        let (_hits, stats) = find_all(&pat, &hay, 1);
        assert!(
            stats.cells_quenched > 0,
            "the band quenched nothing -- the discard-only cut is not wired up"
        );
        assert!(
            stats.cells_admitted > 0,
            "the sweep computed no cells at all"
        );
        // The band must actually be smaller than the full rectangle: for
        // k = 1 the admitted cells sit in a 3-wide diagonal.
        assert!(
            stats.cells_admitted < stats.cells_quenched,
            "admitted {} quenched {}: the band is not pruning",
            stats.cells_admitted,
            stats.cells_quenched
        );
    }

    // ---- the stand-down is required ------------------------------------

    #[test]
    fn exact_prefilter_would_drop_a_one_edit_match() {
        // One substitution defeats every exact occurrence: the literal
        // "abcd" occurs nowhere in this line, so the exact tier finds
        // nothing while the band finds the window within one edit.
        let hay = b"zzabXdzz";
        let fm = FuzzyMatcher::new(b"abcd", 1);
        let hit = fm
            .find_from(hay, 0)
            .expect("the band must find the one-edit window");
        assert_eq!(&hay[hit.start..hit.end], b"abXd");
        assert_eq!(hit.edits, 1);

        // The exact tier, built the way the engine builds it (a mask carries
        // at most MAX_FINGERPRINT = 4 bytes), finds nothing here.
        let mut mask = NibbleMask::new();
        assert!(mask.add(0, b"abcd", false));
        let pre = Prefilter::new(&mask).expect("a non-empty mask yields a prefilter");
        assert_eq!(
            pre.find(hay, 0),
            None,
            "the exact prefilter fired on a line it would have had to prune"
        );

        // And the contract says so out loud, at k > 0 only.
        assert!(exact_prefilter_stands_down(1));
        assert!(exact_prefilter_stands_down(2));
        assert!(!exact_prefilter_stands_down(0));
    }

    // ---- the Matcher contract ------------------------------------------

    #[test]
    fn matcher_methods_agree() {
        let fm = FuzzyMatcher::new(b"abc", 1);
        let hay = b"abXabc";
        for at in 0..=hay.len() {
            let found = fm.find_at(hay, at);
            assert_eq!(
                fm.is_match_at(hay, at),
                found == Some(at),
                "is_match_at disagreed with find_at at {at}"
            );
            if let (Some(s), Some(span)) = (found, fm.find_span_at(hay, at)) {
                assert_eq!(span.start, s, "span start disagreed with find_at at {at}");
                assert!(fm.best_at(hay, s).is_some());
            }
        }
        // An empty pattern is refused, not matched everywhere.
        let empty = FuzzyMatcher::new(b"", 3);
        assert!(!empty.can_match());
        assert!(empty.find_from(b"anything", 0).is_none());
    }

    #[test]
    fn zero_width_windows_are_refused() {
        // A window consumes >= 1 byte, so an empty haystack has no window at
        // all; matches_empty must say false and mean it (the trait derives
        // it from find_span_at, so the two cannot disagree).
        let fm = FuzzyMatcher::new(b"abc", 3);
        assert!(fm.find_from(b"", 0).is_none());
    }

    // ---- the searcher seam, with the candidate tier stood down ----------

    #[derive(Default)]
    struct LineSink {
        lines: Vec<Vec<u8>>,
    }

    impl Sink for LineSink {
        type Error = core::convert::Infallible;

        fn matched(&mut self, mat: &SinkMatch<'_>) -> Result<bool, Self::Error> {
            self.lines.push(mat.bytes.to_vec());
            Ok(true)
        }

        fn context(&mut self, _ctx: &SinkContext<'_>) -> Result<bool, Self::Error> {
            Ok(true)
        }

        fn finish(&mut self, _fin: &SinkFinish<'_>) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn searcher_consumes_the_matcher_without_a_candidate_tier() {
        let fm = FuzzyMatcher::new(b"abcdef", 1);
        let searcher = Searcher::new(&fm, Config::default());
        let mut sink = LineSink::default();
        let hay = b"plain line\nzzabcXefzz\nanother line\n";
        let stopped = searcher
            .search_slice(hay, &mut sink)
            .expect("infallible sink");
        assert!(stopped, "the search ran to completion");
        assert_eq!(sink.lines.len(), 1, "exactly the one-edit line matched");
        assert!(
            sink.lines[0].starts_with(b"zzabcXefzz"),
            "wrong line matched: {:?}",
            sink.lines[0]
        );
    }
}
