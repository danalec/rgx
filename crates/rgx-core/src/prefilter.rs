// SPDX-License-Identifier: Apache-2.0

//! The scan that consumes a [`NibbleMask`].
//!
//! `literal.rs` decides whether a pattern can match; this produces the
//! positions where a literal could start, and `ByteRegex` confirms them.
//! Keeping the two apart is what lets this be tested against a reference
//! instead of against the whole engine.
//!
//! The confirm is a `u64` compare and not a `memcmp`: a fingerprint is at
//! most 8 bytes, so the whole needle fits in one register, and comparing
//! folded keys is a subtract — the difference between ~20 cycles and ~6
//! per candidate.

use alloc::vec::Vec;

use super::literal::{ascii_flip, NibbleMask};

/// One confirmed hit: the offset of the literal, and which bucket it was.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Hit {
    /// Byte offset of the start of the literal in the haystack.
    pub at: usize,
    /// The bucket whose literal matched.
    pub bucket: usize,
}

/// A prefilter over a haystack, built once and reused across haystacks.
///
/// Holds the mask plus a flattened copy of the confirm keys, so the hot loop
/// reads two fixed-size arrays and touches no allocation.
pub struct Prefilter<'a> {
    mask: &'a NibbleMask,
    /// `keys[b]` is the folded confirm key for bucket `b`, or `None` if that
    /// bucket's fingerprint was too long for a `u64` (and must be confirmed by
    /// comparison instead).
    keys: Vec<Option<u64>>,
    /// `lengths[b]` is the fingerprint length for bucket `b`.
    lengths: Vec<usize>,
    /// Whether bucket `b`'s key was folded, so the window folds to match.
    caseless: Vec<bool>,
    /// The fingerprint bytes per bucket, for the `None` case.
    prints: Vec<&'a [u8]>,
    /// Total bytes of every fingerprint, for the cost estimate.
    print_bytes: usize,
}

impl<'a> Prefilter<'a> {
    /// Build a prefilter from a mask, or `None` if the mask has nothing in it.
    ///
    /// A mask that is empty would return no candidates, which is a *safe*
    /// answer for an empty literal set and a catastrophically wrong one for a
    /// non-empty set, so it is refused here rather than producing a prefilter
    /// that never fires.
    pub fn new(mask: &'a NibbleMask) -> Option<Self> {
        if mask.is_empty() {
            return None;
        }
        let mut keys = Vec::new();
        let mut lengths = Vec::new();
        let mut prints = Vec::new();
        let mut caseless = Vec::new();
        let mut print_bytes = 0;
        for b in 0..super::literal::MAX_BUCKETS {
            let bucket = mask.bucket_of(b).unwrap_or(&[]);
            let is_caseless = mask.is_caseless_bucket(b);
            if bucket.is_empty() {
                keys.push(None);
                lengths.push(0);
                prints.push(&[][..]);
                caseless.push(false);
                continue;
            }
            // One literal per bucket is what build_mask produces. A bucket
            // holding several is not representable in a single u64 key, so
            // fall back to a byte compare for it rather than silently
            // confirming only the first.
            let first = &bucket[0];
            let key = if bucket.len() == 1 {
                NibbleMask::confirm_key(first, is_caseless)
            } else {
                None
            };
            keys.push(key);
            lengths.push(first.len());
            prints.push(first);
            caseless.push(is_caseless);
            print_bytes += first.len();
        }
        Some(Self {
            mask,
            keys,
            lengths,
            prints,
            caseless,
            print_bytes,
        })
    }

    /// The total number of fingerprint bytes the prefilter tests per
    /// candidate-bearing position, which is the numerator of the cost model.
    #[must_use]
    pub fn print_bytes(&self) -> usize {
        self.print_bytes
    }

    /// Every candidate position: an offset and the bucket that fired.
    ///
    /// The scalar reference. The SIMD scan produces a bitmap and then walks
    /// the set bits, so the two agree on the set of hits, not the order.
    #[must_use]
    pub fn candidates(&self, hay: &[u8]) -> Vec<Hit> {
        let mut out = Vec::new();
        // The mask is per-position, so a candidate is a run of positions.
        // `scan::candidates` yields the offset where the run starts, which
        // is the offset the confirm reads from.
        let stats = super::maskstats::enabled();
        let mut confirms = 0u64;
        // `used_buckets` is a bitmask of the buckets that hold a literal.
        // Walking all `MAX_BUCKETS` cost a confirm per EMPTY bucket per
        // candidate, and `confirm` on an empty bucket can only answer false.
        let used = self.mask.used_buckets();
        for start in super::scan::candidates(self.mask, hay) {
            for bucket in 0..super::literal::MAX_BUCKETS {
                if used & (1u16 << bucket) == 0 {
                    continue;
                }
                if self.confirm(hay, start, bucket) {
                    out.push(Hit { at: start, bucket });
                }
                // Per candidate-bucket pair, which is the unit Hyperscan's
                // `verify_bucket` uses.
                confirms += 1;
            }
        }
        if stats {
            super::maskstats::flush(&super::maskstats::ScanDelta {
                bytes: 0,
                blocks: 0,
                candidates: 0,
                confirms,
                hits: out.len() as u64,
            });
        }
        out
    }
    /// The offset of the first confirmed hit at or after `at`, if any.
    ///
    /// The early-exit here is over confirmed hits: a caller wanting a true
    /// early exit should use [`Self::candidates`] and stop iterating, or
    /// the engine's own line-by-line search, which is what rgx does.
    #[must_use]
    pub fn find(&self, hay: &[u8], at: usize) -> Option<usize> {
        if at >= hay.len() {
            return None;
        }
        let stats = super::maskstats::enabled();
        let mut confirms = 0u64;
        // Scan only the suffix past `at`. The mask is per-position, so
        // trimming the input is enough. `start` is therefore RELATIVE TO
        // `at`, and the confirm has to read `hay[at + start]` -- confirming
        // at `hay[start]` reads the wrong byte whenever `at > 0`, which is
        // exactly the case `find` exists for. `find_agrees_with_candidates`
        // passed only because its fixture haystack began with a literal, so
        // `at` was 0 and the two coincided.
        let used = self.mask.used_buckets();
        for start in super::scan::candidates(self.mask, &hay[at..]) {
            for bucket in 0..super::literal::MAX_BUCKETS {
                if used & (1u16 << bucket) == 0 {
                    continue;
                }
                if self.confirm(hay, at + start, bucket) {
                    if stats {
                        super::maskstats::flush(&super::maskstats::ScanDelta {
                            bytes: 0,
                            blocks: 0,
                            candidates: 0,
                            confirms: confirms + 1,
                            hits: 1,
                        });
                    }
                    return Some(start + at);
                }
                confirms += 1;
            }
        }
        if stats {
            super::maskstats::flush(&super::maskstats::ScanDelta {
                bytes: 0,
                blocks: 0,
                candidates: 0,
                confirms,
                hits: 0,
            });
        }
        None
    }
    /// Whether bucket `bucket`'s literal is confirmed at `at`.
    ///
    /// Two cases: a register compare when the folded key is available,
    /// and a byte compare for a fingerprint too long to hold in a `u64`.
    /// The caseless question does not arise here — the key is already
    /// folded, so the window is folded the same way.
    #[inline]
    fn confirm(&self, hay: &[u8], at: usize, bucket: usize) -> bool {
        let n = self.lengths[bucket];
        if n == 0 {
            return false;
        }
        // `at` comes from a scan over `hay`; bounds are re-checked rather
        // than assumed: panicking on a short haystack is worse than
        // returning nothing.
        let Some(window) = hay.get(at..at.saturating_add(n)) else {
            return false;
        };
        match self.keys[bucket] {
            Some(key) => {
                // Fold only the `n` bytes the literal covers, so the key's
                // own zero padding is not clobbered by window bytes beyond
                // the fingerprint. The fold must match the one the key was
                // built with.
                let mut got = 0u64;
                for (i, &b) in window.iter().enumerate() {
                    let b = if self.caseless[bucket] {
                        b.to_ascii_lowercase()
                    } else {
                        b
                    };
                    got |= u64::from(b) << (8 * i);
                }
                got == key
            }
            None => {
                let print = self.prints[bucket];
                print.len() == n
                    && window
                        .iter()
                        .zip(print.iter())
                        .all(|(&a, &b)| a == b || ascii_flip(a) == ascii_flip(b))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::literal::{Literal, LiteralSet, MAX_FINGERPRINT};
    use super::*;
    use alloc::vec;

    fn prefilter_for(set: &LiteralSet) -> Option<NibbleMask> {
        super::super::literal::build_mask(set, MAX_FINGERPRINT)
    }

    /// The counters see real work, not just synthetic deltas.
    ///
    /// `maskstats` exists to measure the first stage's yield and the
    /// confirm's cost on this crate's own corpus. Asserting the shape
    /// here (blocks counted, candidates found, one confirm per
    /// candidate-bucket pair) is what stops it from silently becoming a
    /// no-op.
    ///
    /// The counters are process-global, so this is the only test that
    /// moves them.
    #[test]
    fn mask_counters_see_a_real_scan() {
        let set = LiteralSet::exact(vec![Literal::new(b"error")]);
        let mask = prefilter_for(&set).unwrap();
        let pf = Prefilter::new(&mask).unwrap();
        let hay = b"an error here, and an error there, and one more error";

        super::super::maskstats::begin_local();

        let hits = pf.candidates(hay);
        let after = super::super::maskstats::end_local();

        assert_eq!(hits.len(), 3, "the fixture has three occurrences");
        assert!(after.scans >= 1, "a scan must have been counted");
        assert!(after.bytes >= hay.len() as u64, "bytes must be counted");
        assert!(after.blocks >= 1, "vector blocks must be counted");
        assert_eq!(
            after.candidates,
            hits.len() as u64,
            "every admitted candidate is counted"
        );
        assert_eq!(
            after.hits,
            hits.len() as u64,
            "every confirmed hit is counted"
        );
        assert!(
            after.confirms >= after.candidates,
            "each candidate fans out over buckets, so confirms >= candidates"
        );
        // The confirm loop skips buckets the mask never used -- `confirm`
        // on an empty bucket can only answer false -- so a confirm happens
        // per candidate-USED-bucket pair, not per candidate-bucket pair.
        // One bucket of eight holds the literal here.
        assert_eq!(
            after.confirms, after.candidates,
            "one confirm per candidate per used bucket, and one of eight is used"
        );
        assert!(
            (after.hit_rate() - 1.0).abs() < 1e-12,
            "every confirm is against the one bucket that holds the literal, \
             so every confirm hits"
        );
    }

    /// The property that matters most: a prefilter must never miss a
    /// position the literal actually occupies. Anything else is a wrong
    /// answer; extra candidates are only slower.
    ///
    /// The needle set here is case-*sensitive*, so the case-differing
    /// spellings are deliberately not expected: a case-sensitive prefilter
    /// that matched `ERROR` would be a false positive, and that is covered by
    /// `caseless_finds_every_variant_and_nothing_else`'s converse below.
    #[test]
    fn every_literal_occurrence_is_reported() {
        let set = LiteralSet::exact(vec![Literal::new(b"error")]);
        let mask = prefilter_for(&set).unwrap();
        let pf = Prefilter::new(&mask).unwrap();
        let hay = b"an error here, and an error there, and one more error";
        let hits: Vec<usize> = pf.candidates(hay).iter().map(|h| h.at).collect();
        let mut from = 0;
        let mut expected = Vec::new();
        while let Some(p) = find_plain(hay, b"error", from) {
            expected.push(p);
            from = p + 1;
        }
        assert!(!expected.is_empty(), "the fixture must contain the literal");
        assert_eq!(expected, hits, "every occurrence, and only those");
    }

    /// A case-sensitive prefilter must NOT match a case-differing spelling.
    /// The converse of the caseless test, and the bug that
    /// `confirm_key_folds_letters_only` in `literal.rs` was written for.
    #[test]
    fn case_sensitive_does_not_match_a_variant() {
        let set = LiteralSet::exact(vec![Literal::new(b"error")]);
        let mask = prefilter_for(&set).unwrap();
        let pf = Prefilter::new(&mask).unwrap();
        for variant in [&b"ERROR"[..], b"Error", b"eRRoR"] {
            assert_eq!(
                None,
                pf.find(variant, 0),
                "{variant:?} must not match a case-sensitive literal"
            );
        }
        // And the exact spelling still does.
        assert_eq!(Some(0), pf.find(b"error", 0));
    }

    /// A plain substring search, so the test above compares against something
    /// that is not the code under test.
    fn find_plain(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
        if needle.is_empty() || hay.len() < needle.len() {
            return None;
        }
        (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
    }

    /// A caseless prefilter must find every case variant, and must not find a
    /// byte string that is not a variant.
    #[test]
    fn caseless_finds_every_variant_and_nothing_else() {
        let set = LiteralSet::exact(vec![Literal::caseless(b"error")]);
        let mask = prefilter_for(&set).unwrap();
        let pf = Prefilter::new(&mask).unwrap();
        let hay = b"error ERROR Error eRrOr Errors";
        for at in [0usize, 6, 12, 18] {
            assert!(
                pf.candidates(hay).iter().any(|h| h.at == at),
                "variant at {at} missed"
            );
        }
        // `Errors` starts with a variant, so it is a hit at 24; what must not
        // happen is a hit somewhere unrelated.
        for h in pf.candidates(hay) {
            assert!(h.at % 6 == 0, "spurious candidate at {}", h.at);
        }
    }

    /// An empty mask must be refused rather than producing a prefilter that
    /// silently never fires.
    #[test]
    fn an_empty_mask_yields_no_prefilter() {
        assert!(Prefilter::new(&NibbleMask::new()).is_none());
    }

    /// A haystack shorter than the fingerprint must not panic, whatever the
    /// candidate offset. Found by adversarial review as a class of bug in this
    /// codebase's other scanners.
    #[test]
    fn a_short_haystack_never_panics() {
        let set = LiteralSet::exact(vec![Literal::new(b"function")]);
        let mask = prefilter_for(&set).unwrap();
        let pf = Prefilter::new(&mask).unwrap();
        for n in 0..12usize {
            let hay = vec![b'f'; n];
            let _ = pf.candidates(&hay);
            let _ = pf.find(&hay, 0);
            let _ = pf.find(&hay, n);
            let _ = pf.find(&hay, n + 100);
        }
    }

    /// `candidates` and `find` must agree: the second is the first with an
    /// early exit, and a divergence would mean one of them is lying.
    #[test]
    fn find_agrees_with_candidates() {
        let set = LiteralSet::inexact(vec![
            Literal::new(b"alpha"),
            Literal::new(b"beta"),
            Literal::caseless(b"gamma"),
        ]);
        let mask = prefilter_for(&set).unwrap();
        let pf = Prefilter::new(&mask).unwrap();
        let hay = b"alpha beta GAMMA delta alphabeta gamma";
        let all = pf.candidates(hay);
        assert_eq!(all.first().map(|h| h.at), pf.find(hay, 0));
        for h in &all {
            assert_eq!(Some(h.at), pf.find(hay, h.at), "find lost {}", h.at);
        }
        // A start past the last hit must return None.
        assert_eq!(None, pf.find(hay, hay.len()));
    }

    /// A needle that cannot fit a u64 confirm key must still work, by the
    /// byte-compare path. `build_mask` cannot produce one, so this constructs
    /// it directly.
    #[test]
    fn a_long_fingerprint_falls_back_to_byte_compare() {
        let mut mask = NibbleMask::new();
        let long = b"abcdefghij";
        assert!(mask.add(0, long, false));
        // Register it directly so the key is None, as a >8-byte print would be.
        let mut pf = Prefilter::new(&mask).unwrap();
        pf.keys[0] = None;
        pf.lengths[0] = long.len();
        pf.prints[0] = long;
        let hay = b"xxabcdefghijyy";
        let hits = pf.candidates(hay);
        assert!(hits.iter().any(|h| h.at == 2), "long literal missed");
        assert!(pf.find(hay, 0).is_some());
    }

    // ---------------------------------------------------------------------
    // The frequency criterion, and the law it has to keep.
    //
    // `super::super::frequency` picks a needle's fingerprint window by a
    // background byte-frequency table instead of taking the leading bytes.
    // A window choice changes what a CANDIDATE is, and never what a match
    // is, so the only way it can break the engine is by dropping a
    // candidate. These two tests are the two halves of that claim: over the
    // needles the mask is actually built from today the two criteria are
    // the same prefilter, bit for bit; and where they part company it is
    // because the confirm is reading the WINDOW, which is a caller's
    // obligation to carry the offset and not this module's to absorb.
    // ---------------------------------------------------------------------

    /// Every literal of 2..=`MAX_FINGERPRINT` bytes, in every mixture of
    /// case over a small alphabet, in buckets of 1, 2 and 3 — which is the
    /// whole space `NibbleMask` sees today, because a fingerprint is capped
    /// at [`MAX_FINGERPRINT`] and `build_mask` truncates to it.
    ///
    /// For each, the prefilter built by the current criterion and by the
    /// frequency criterion must produce **exactly** the same hits, and the
    /// total across the corpus must be exactly equal. Not "no false
    /// negatives" — equal, entry for entry, because a byte-selection
    /// criterion has no business changing what this type reports.
    ///
    /// The equality is not a coincidence and it must not become one: the
    /// frequency window is a no-op for any needle that fits, and the first
    /// assertion says so directly. If a future table or a future
    /// `MAX_FINGERPRINT` ever moves a short needle's window, this test fails
    /// with a count mismatch rather than the engine quietly losing matches.
    #[test]
    fn a_frequency_chosen_window_is_the_same_prefilter_over_a_pattern_corpus() {
        use super::super::frequency;
        use super::super::literal::MAX_FINGERPRINT;

        let alphabet = b"ab_ ";
        let mut needles: Vec<Vec<u8>> = Vec::new();
        for len in 2..=MAX_FINGERPRINT {
            let mut idx = vec![0usize; len];
            loop {
                needles.push(idx.iter().map(|&i| alphabet[i]).collect());
                let mut p = len;
                loop {
                    if p == 0 {
                        break;
                    }
                    p -= 1;
                    idx[p] += 1;
                    if idx[p] < alphabet.len() {
                        break;
                    }
                    idx[p] = 0;
                    if p == 0 {
                        break;
                    }
                }
                if idx.iter().all(|&i| i == 0) {
                    break;
                }
            }
        }
        assert!(
            needles.len() > 100,
            "the corpus must be a corpus, got {}",
            needles.len()
        );

        let hay = b"aa ab a_ a b_  ab_ b__ _a __ aabbabaab ab_a_a bb aaabba";
        let mut total_current = 0usize;
        let mut total_frequency = 0usize;
        let mut moved = 0usize;

        for width in [1usize, 2, 3] {
            for caseless in [false, true] {
                for chunk in needles.chunks(width) {
                    let lits: Vec<Literal> = chunk
                        .iter()
                        .map(|n| {
                            if caseless {
                                Literal::caseless(n)
                            } else {
                                Literal::new(n)
                            }
                        })
                        .collect();

                    // The current criterion: the leading `max` bytes, which
                    // for every needle here is all of it.
                    let current = LiteralSet::inexact(lits.clone());
                    let cm = prefilter_for(&current).unwrap();
                    let cur_hits = Prefilter::new(&cm).unwrap().candidates(hay);

                    // The frequency criterion, applied the way a caller is
                    // meant to: the same literal, registered at the window
                    // the table picks. Every window here is the whole needle
                    // at offset 0, so the frequency mask is the current mask
                    // -- and the assert below is what earns that, rather than
                    // assuming it.
                    let windows: Vec<Literal> = chunk
                        .iter()
                        .map(|lit| {
                            let w = frequency::fingerprint(lit, MAX_FINGERPRINT).unwrap();
                            if w.at != 0 {
                                moved += 1;
                            }
                            assert!(
                                w.at == 0,
                                "a {}-byte needle must not move: {:?} picked {w:?}",
                                lit.len(),
                                lit,
                            );
                            let win = &lit[w.at..w.at + w.width];
                            if caseless {
                                Literal::caseless(win)
                            } else {
                                Literal::new(win)
                            }
                        })
                        .collect();
                    let fm = prefilter_for(&LiteralSet::inexact(windows)).unwrap();
                    assert_eq!(cm, fm, "the two criteria built different masks");
                    let freq_hits = Prefilter::new(&fm).unwrap().candidates(hay);

                    assert_eq!(cur_hits, freq_hits, "criteria disagree on {chunk:?}");
                    total_current += cur_hits.len();
                    total_frequency += freq_hits.len();
                }
            }
        }
        assert_eq!(moved, 0, "no short needle has anything to choose");
        assert_eq!(
            total_current, total_frequency,
            "the entry totals must be exactly equal"
        );
        assert!(
            total_current > 0,
            "the corpus must actually hit, got {total_current}"
        );
    }

    /// Where the two criteria part company, and why that is a caller's
    /// problem.
    ///
    /// `pub fn` is 6 bytes and a mask tests 4, so the table moves the window
    /// from `pub ` to `ub f`. Registering that window and confirming against
    /// it does not lose a match — it reports one the needle does not
    /// support, at an offset that is not where a match starts. That is the
    /// whole of the false-negative law stated in its other direction: a
    /// window choice is sound only if the caller carries
    /// [`frequency::Window::at`] to the confirm, and the only thing that
    /// makes it unsound is not carrying it.
    #[test]
    fn a_moved_window_changes_what_a_candidate_means_until_the_offset_is_carried() {
        use super::super::frequency;

        let needle = b"pub fn";
        let w = frequency::fingerprint(needle, MAX_FINGERPRINT).unwrap();
        assert_eq!(
            w.at, 1,
            "the table must move this one, or the test is vacuous"
        );
        let window = &needle[w.at..w.at + w.width];
        assert_eq!(window, b"ub f");

        // The haystack carries the WINDOW at 3 and nothing else.
        let hay = b"zzxub fyzz";
        let at = 3;
        assert_eq!(&hay[at..at + w.width], window);

        // Built the way a caller that forgot the offset would build it: the
        // window as the print. The prefilter reports offset 3, and offset 3
        // is not a `pub fn` -- so the set of hits grew to include something
        // that is not a match, which is the shape of the mistake.
        let set = LiteralSet::exact(vec![Literal::new(window)]);
        let moved_mask = prefilter_for(&set).unwrap();
        let pf = Prefilter::new(&moved_mask).unwrap();
        let hits = pf.candidates(hay);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].at, at);
        assert_ne!(
            hay.get(at..at + needle.len()),
            Some(&needle[..]),
            "offset {at} must not be a `pub fn`, or the test proves nothing"
        );

        // The current criterion on the same haystack reports nothing, which
        // is the answer it has to keep giving.
        let cur = LiteralSet::exact(vec![Literal::new(needle)]);
        let cur_mask = prefilter_for(&cur).unwrap();
        let cur_hits = Prefilter::new(&cur_mask).unwrap().candidates(hay);
        assert!(
            cur_hits.is_empty(),
            "`pub fn` does not occur in {hay:?}, so the current prefilter must say so"
        );

        // And the needle itself is never lost: a caller that registers the
        // window AND carries `at` re-anchors the confirm at `hit.at - at`,
        // and lands exactly on the needle. `pub fn` starts at 3 here and its
        // window `ub f` at 4, so the subtraction is what recovers the match
        // start -- which is why the offset has to travel with the window
        // rather than being an implementation detail of the selection.
        let real = b"aa pub fn zz";
        let set = LiteralSet::exact(vec![Literal::new(window)]);
        let real_mask = prefilter_for(&set).unwrap();
        let hits = Prefilter::new(&real_mask).unwrap().candidates(real);
        assert!(
            hits.iter().any(|h| h.at == 4 && h.at - w.at == 3),
            "the window at 4 must re-anchor to the needle at 3, got {hits:?}"
        );
        assert_eq!(&real[3..3 + needle.len()], &needle[..]);
    }
}
