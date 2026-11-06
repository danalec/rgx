// SPDX-License-Identifier: Apache-2.0

//! Background byte frequency: which bytes a prefilter should look for.
//!
//! **Provenance — read this before quoting any number from this file.** Every
//! value in [`RANK`] is copied from the `memchr` crate this workspace already
//! links, `memchr-2.8.3/src/arch/all/packedpair/default_rank.rs`, and the
//! two-byte selection in [`rarest_pair`] is `memchr`'s
//! `packedpair::Pair::with_ranker` reproduced step for step. It is **not** a
//! distribution measured on this repository's corpora, and it is not a claim
//! about them. `memchr` describes its own table as an assumption:
//!
//! > instead of always choosing the first and last bytes in the needle, we
//! > choose two bytes that we believe are 'rare' according to a background
//! > frequency distribution of bytes. That is, we assume that bytes like Z
//! > are far less common than bytes like a.
//!
//! That is the whole of the content, and it is enough: a *background*
//! distribution is a prior over haystacks in general, not a model of one
//! corpus. The objection to the alternative — Gen-DBA,
//! [arXiv:2601.16409](https://arxiv.org/abs/2601.16409), that a per-corpus
//! learned table is non-portable by construction — is accepted here, and the
//! blind spot measured below is the price of accepting it.
//!
//! **And it has a measured blind spot, which is the honest reason not to
//! measure one instead.** Over this project's 235 MB Rust corpus the table's
//! ordering is right at both ends of the range it claims: space (255), `e`
//! (253), `t` (251) and `\n` (242) are the four commonest bytes, and the
//! twelve bytes it ranks rarest all measure below 0.004% — the claim holds.
//! But the 64 bytes of `0xC0..=0xFF` are tied at 255, "the table declines to
//! order what it cannot separate", and on a corpus carrying accented source
//! that block is the **rarest** thing in the file: `0xc6`, `0xcd`, `0xdb`,
//! `0xca`, `0xd5` are five of the twelve rarest bytes measured, and the
//! table calls all of them common. A table measured on this corpus would fix
//! that and lose portability, which is the trade `BEYOND-SOTA.md` §7 says not
//! to take. Nothing here has to be re-learned to be honest about it: the
//! correct statement is that the table is a prior, and this is where the
//! prior is wrong.
//!
//! **What it is for.** A prefilter is charged for every candidate it admits.
//! Two structures can spend that charge differently. `memchr::memmem` has a
//! *fixed* kernel — a packed pair of byte compares per 32-byte block — so it
//! must decide which two of the needle's bytes to test, and the answer is
//! "the two the background says are rarest". A packed nibble mask has a
//! kernel of `n` per-position table lookups and `n` ANDs per block, so it
//! tests *every* position of a window instead of choosing between them, and
//! its only freedom is **where the window starts**. [`fingerprint`] is that
//! freedom, and it is a no-op whenever the needle is no longer than the
//! window.
//!
//! **Measured, and it is a no-op for every literal this engine masks.** The
//! two patterns of the nine that route through a `NibbleMask` at all —
//! `foo.*bar` and `(pub|fn) [a-z]+` — have literals of 3 and 4 bytes, and a
//! 4-byte window on a 4-byte needle has one position to start at. The three
//! literals long enough to have a choice (`pub fn`, `fn main`, `let mut`)
//! are the three the cost model does **not** send through the mask, because
//! `FastScan::Sub` is priced below it. So on this corpus the table changes
//! the mask for nothing, and where it would change something the mask is not
//! being used. That is a measurement, and it is why the only integration
//! point this module has is [`fingerprint`]: a decision a caller has to opt
//! into, not one wired in by default.
//!
//! **The rank is an order, not a probability.** [`RANK`] says `e` is commoner
//! than `Z`; it does not say by how much, and the table has 64 bytes tied at
//! 255. So [`cost`] multiplies ranks where a yield model would multiply
//! frequencies, which preserves the ordering (any window with a rarer byte is
//! cheaper, and the product is monotone in every argument) and loses the
//! magnitude. For choosing between windows of one needle that is enough; for
//! predicting a candidate count it is not, and nothing here should be read as
//! predicting one.

use core::mem;

/// The heuristic background frequency of every byte value.
///
/// **Lower is rarer.** Copied verbatim from `memchr-2.8.3`,
/// `src/arch/all/packedpair/default_rank.rs`; see the module docs for what
/// that assumption is and is not.
///
/// The shape of it is the argument in one line. Control bytes sit at the
/// bottom (`\x1f` is 27, the rarest byte in the table) because text is
/// mostly letters; `\n` is 242, the commonest byte that carries meaning,
/// because every line has one; space and every byte of `0xC0..=0xFF` tie
/// at 255 because the table declines to order what it cannot separate —
/// which on an accented corpus is a block of rarest bytes called common.
pub const RANK: [u8; 256] = [
    55, 52, 51, 50, 49, 48, 47, 46, 45, 103, 242, 66, 67, 229, 44, 43, 42, 41, 40, 39, 38, 37, 36,
    35, 34, 33, 56, 32, 31, 30, 29, 28, 255, 148, 164, 149, 136, 160, 155, 173, 221, 222, 134, 122,
    232, 202, 215, 224, 208, 220, 204, 187, 183, 179, 177, 168, 178, 200, 226, 195, 154, 184, 174,
    126, 120, 191, 157, 194, 170, 189, 162, 161, 150, 193, 142, 137, 171, 176, 185, 167, 186, 112,
    175, 192, 188, 156, 140, 143, 123, 133, 128, 147, 138, 146, 114, 223, 151, 249, 216, 238, 236,
    253, 227, 218, 230, 247, 135, 180, 241, 233, 246, 244, 231, 139, 245, 243, 251, 235, 201, 196,
    240, 214, 152, 182, 205, 181, 127, 27, 212, 211, 210, 213, 228, 197, 169, 159, 131, 172, 105,
    80, 98, 96, 97, 81, 207, 145, 116, 115, 144, 130, 153, 121, 107, 132, 109, 110, 124, 111, 82,
    108, 118, 141, 113, 129, 119, 125, 165, 117, 92, 106, 83, 72, 99, 93, 65, 79, 166, 237, 163,
    199, 190, 225, 209, 203, 198, 217, 219, 206, 234, 248, 158, 239, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255,
];

/// The heuristic background frequency of `b`. Lower is rarer.
///
/// The one function everything else is written over, and the whole reason
/// this module exists: it is a byte-to-`u8` load with no state, so a
/// selection made from it costs nothing at search time.
#[must_use]
pub const fn rank(b: u8) -> u8 {
    RANK[b as usize]
}

/// The two rarest bytes of a needle, and where in it they sit.
///
/// `memchr`'s `packedpair::Pair`, which is what its packed-pair kernel and
/// the `Pre` it hands to Two-Way both prefilter on. The two offsets are
/// distinct by construction; the two **bytes** need not be, because a needle
/// that repeats itself has no rarer second choice.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RarePair {
    /// Offset of the rarest byte.
    pub first: usize,
    /// Offset of the second-rarest byte, distinct from [`Self::first`].
    pub second: usize,
}

/// The two rarest bytes of `needle`, or `None` if it is too short to hold
/// two offsets.
///
/// Ties go to the **earlier** offset, which is the same tie-break `memchr`
/// makes and for the same reason: a choice that depends on the byte *value*
/// is arbitrary, and a choice that depends on the needle's order is at least
/// reproducible.
#[must_use]
pub fn rarest_pair(needle: &[u8]) -> Option<RarePair> {
    if needle.len() <= 1 {
        return None;
    }
    // A port of `memchr-2.8.3/src/arch/all/packedpair/mod.rs`,
    // `Pair::with_ranker` with the default ranker, including its ordering:
    // scan from index 2 keeping the best two, demoting the old best rather
    // than re-sorting.
    let (mut rare1, mut index1) = (needle[0], 0);
    let (mut rare2, mut index2) = (needle[1], 1);
    if rank(rare2) < rank(rare1) {
        mem::swap(&mut rare1, &mut rare2);
        mem::swap(&mut index1, &mut index2);
    }
    for (i, &b) in needle.iter().enumerate().take(usize::from(u8::MAX)).skip(2) {
        if rank(b) < rank(rare1) {
            rare2 = rare1;
            index2 = index1;
            rare1 = b;
            index1 = i;
        } else if b != rare1 && rank(b) < rank(rare2) {
            rare2 = b;
            index2 = i;
        }
    }
    Some(RarePair {
        first: index1,
        second: index2,
    })
}

/// A window of consecutive bytes and where it starts in the needle it came
/// from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Window {
    /// Offset of the window's first byte within the needle.
    pub at: usize,
    /// How many bytes the window covers. Never zero.
    pub width: usize,
}

/// The background-frequency cost of a byte range. **Lower is rarer.**
///
/// The product of [`rank`]s, saturating at `u64::MAX`. A yield model would
/// multiply *frequencies* here; the table only carries an order, so this
/// multiplies the order. That keeps the property the selection needs — a
/// window is cheaper exactly when it is rarer, and never cheaper because of
/// an accident of width — and drops the magnitude, so two windows that
/// differ by a factor this cannot see are a tie here.
#[must_use]
pub fn cost(bytes: &[u8]) -> u64 {
    let mut c = 1u64;
    for &b in bytes {
        c = c.saturating_mul(u64::from(rank(b)));
    }
    c
}

/// The background-frequency cost of a byte SET. **Lower is rarer.** `0` for
/// the empty set, so a set with no members is not silently the cheapest
/// thing in a run.
///
/// The **sum** of the members' ranks, where a byte range's [`cost`] is their
/// product, and the asymmetry is the whole point: a position of a pattern is
/// satisfied by *any* member of its class, so the chance a haystack byte
/// lands there is the chance it is any one of them — a sum, not a product
/// and emphatically not a mean. `e[0-9]` is the case that shows it: `e` is
/// rank 253 and the ten digits score 1904 between them, so the digit
/// position is the rarer of the two by everything the table can see, and the
/// real corpus agrees with the direction — 0.00014% of its bytes against
/// 5.31%. The table is not entitled to that factor of 39,000; it is entitled
/// to the ordering, and the ordering is all a choice between two candidates
/// needs.
///
/// The approximation is the same one [`cost`] makes: ranks stand in for
/// frequencies, which preserves the ordering between two sets of the same
/// size and not much else.
#[must_use]
pub fn set_cost(set: &[u8]) -> u32 {
    set.iter().map(|&b| u32::from(rank(b))).sum()
}

/// The `width`-wide run of consecutive byte-SETS with the lowest total
/// [`set_cost`], and where it starts.
///
/// The set-shaped twin of [`rarest_window`], for the one caller that has
/// sets rather than a needle: `regex.rs::run_mask` takes a run of required
/// byte-classes — `e` at one offset, a digit at the next — and truncates it
/// to [`MAX_FINGERPRINT`](super::literal::MAX_FINGERPRINT) from the front.
/// This picks the same width from wherever the background says is rarest.
///
/// Same refusal as [`rarest_window`]: a run that cannot be filled is not a
/// run, and a zero width constrains nothing.
#[must_use]
pub fn rarest_run(sets: &[&[u8]], width: usize) -> Option<Window> {
    if width == 0 || sets.len() < width {
        return None;
    }
    let mut best_at = 0;
    let mut best = u32::MAX;
    for at in 0..=sets.len() - width {
        let c: u32 = sets[at..at + width].iter().map(|s| set_cost(s)).sum();
        if c < best {
            best = c;
            best_at = at;
        }
    }
    Some(Window { at: best_at, width })
}

/// The `width`-byte window of `needle` the background says is rarest.
///
/// The only question `memchr`'s pair answers is "which two bytes"; a packed
/// mask asks "which *contiguous* run", because a mask position is the byte
/// at `at + j` and nothing else, so a non-contiguous choice is not
/// representable. Restricting [`rarest_pair`]'s idea to windows is what
/// makes it usable here, and it is why the answer is usually not
/// [`rarest_pair`]'s.
///
/// `None` when `needle` is shorter than `width`, or when `width` is zero —
/// a window that cannot be filled is not a window, and returning one would
/// hand a caller an empty fingerprint that matches everywhere.
#[must_use]
pub fn rarest_window(needle: &[u8], width: usize) -> Option<Window> {
    if width == 0 || needle.len() < width {
        return None;
    }
    // Sliding window of `width` ranks, cheapest of the `len - width + 1`
    // windows, ties going to the earliest — again for reproducibility.
    let mut best_at = 0;
    let mut best = u64::MAX;
    for at in 0..=needle.len() - width {
        let c = cost(&needle[at..at + width]);
        if c < best {
            best = c;
            best_at = at;
        }
    }
    Some(Window { at: best_at, width })
}

/// The fingerprint a packed mask should test for `needle`, and where it sits.
///
/// **This is the whole of the API, and it is a no-op for every needle that
/// fits.** When `needle.len() <= max` the window is the whole needle at
/// offset 0 — which is what [`super::literal::Literal::fingerprint`] already
/// returns, so every mask built from a 4-byte-or-shorter literal is
/// bit-for-bit what it was before this module existed. Only a needle longer
/// than `max` moves, and then only as far as its rarest `max`-byte run.
///
/// A caller that registers the window must remember [`Window::at`]: the mask
/// reports the window's first byte, which is the match start only when `at`
/// is 0. That is the constraint that makes this a decision for a caller
/// rather than a change to `build_mask`, and the reason is the one
/// `STATUS.md` §4 item 2 states for the same reason — an offset a match may
/// sit at does not recover a match start from a candidate.
#[must_use]
pub fn fingerprint(needle: &[u8], max: usize) -> Option<Window> {
    if needle.is_empty() {
        return None;
    }
    let width = if needle.len() < max {
        needle.len()
    } else {
        max
    };
    rarest_window(needle, width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// The table is a copy, so the copy is checked against what it claims
    /// to be: 256 entries, lower meaning rarer for the pairs the argument
    /// in the docs is made of, and nothing below it.
    #[test]
    fn the_table_is_a_total_order_on_the_bytes_the_docs_name() {
        assert_eq!(RANK.len(), 256);
        assert!(rank(b'e') > rank(b'Z'), "e is commoner than Z");
        assert!(rank(b' ') > rank(b'Z'), "space is commoner than Z");
        assert!(rank(b'\n') > rank(b'0'), "newline is commoner than a digit");
        assert!(rank(b'a') > rank(b'q'), "a is commoner than q");
        let lo = RANK.iter().copied().min().unwrap();
        assert!(lo > 0, "a zero rank would zero every cost product");
    }

    /// Every byte is a fixed point of the table, and `RANK[i] == rank(i)`.
    #[test]
    fn rank_agrees_with_the_table_at_every_byte() {
        for b in 0..=255u8 {
            assert_eq!(rank(b), RANK[usize::from(b)], "byte {b:#04x}");
        }
    }

    /// The behaviour `memchr` documents, on the two needles it is easiest to
    /// reason about: the rarest byte is not the first one, and a repeated
    /// byte cannot be its own second choice.
    #[test]
    fn rarest_pair_picks_the_two_rarest_offsets() {
        // `pub fn`: space is the commonest byte in the table and it is the
        // third byte, so the pair must skip it.
        let p = rarest_pair(b"pub fn").unwrap();
        assert_eq!(p.first, 2, "b is the rarest of `pub fn`");
        assert_eq!(p.second, 4, "f is the next");
        assert_ne!(p.first, p.second);
    }

    /// A needle shorter than two bytes has no pair, and a needle whose bytes
    /// are all the same value still gets two DISTINCT offsets out — the
    /// offsets are what must differ, because a repeated byte is a genuine
    /// second choice and not a second copy of the first.
    #[test]
    fn rarest_pair_needs_two_offsets_not_two_bytes() {
        assert!(rarest_pair(b"").is_none());
        assert!(rarest_pair(b"a").is_none());
        let p = rarest_pair(b"aaaa").unwrap();
        assert_eq!(p.first, 0);
        assert_eq!(p.second, 1);
    }

    /// The tie-break is the earliest offset, so the same needle always
    /// produces the same pair. A prefilter that chose differently on two
    /// runs of the same bytes would be a reproducibility bug of the kind
    /// `FastLiteral::plan` already documents about itself.
    #[test]
    fn rarest_pair_breaks_ties_towards_the_earlier_offset() {
        for n in 2..12usize {
            let needle = vec![b'q'; n]; // one rank, n offsets
            let p = rarest_pair(&needle).unwrap();
            assert_eq!((p.first, p.second), (0, 1), "n = {n}");
        }
        // ` ` and 0xC0 are both 255 -- the table declines to order the bytes
        // it cannot separate, so the needle below has a real tie at offsets
        // 1 and 2, and the earlier one must win it.
        assert_eq!(rank(b' '), rank(0xC0));
        let p = rarest_pair(b"q \xC0").unwrap();
        assert_eq!((p.first, p.second), (0, 1));
    }

    /// A window shorter than the needle, and the one this module exists for:
    /// `pub fn` is 7 bytes and a mask tests 4, and the rarest 4-run is NOT
    /// the first four -- it is `ub f`, because `u` (235) is rarer than the
    /// `n` (246) that displacing the space's left-hand neighbour would
    /// bring in. That is the whole difference from truncating.
    #[test]
    fn rarest_window_moves_off_the_prefix_when_it_can() {
        let w = rarest_window(b"pub fn", 4).unwrap();
        assert_eq!(w.width, 4);
        assert_eq!(w.at, 1, "`ub f` is rarer than `pub `");
        assert_eq!(&b"pub fn"[w.at..w.at + w.width], b"ub f");
        assert!(cost(&b"pub fn"[w.at..w.at + w.width]) < cost(b"pub "));
    }

    /// The prefix stays the prefix when nothing better exists. `abcdefgh` is
    /// strictly increasing in rank, so the last window is the rarest and
    /// this is the assertion in the other direction.
    #[test]
    fn rarest_window_follows_the_table() {
        let needle = b"abcdefgh";
        let w = rarest_window(needle, 4).unwrap();
        assert_eq!(&needle[w.at..w.at + w.width], b"efgh");
    }

    /// A window that cannot be filled is refused, and zero width is refused
    /// too: both would hand back a fingerprint that constrains nothing.
    #[test]
    fn a_window_that_does_not_fit_is_refused() {
        assert!(rarest_window(b"ab", 3).is_none());
        assert!(rarest_window(b"", 1).is_none());
        assert!(rarest_window(b"abcd", 0).is_none());
    }

    /// The compatibility property, stated as a test rather than as prose:
    /// for every needle that FITS the window, `fingerprint` returns offset 0
    /// and the whole needle. That is what makes this a no-op for every
    /// literal of `MAX_FINGERPRINT` bytes or fewer, and it is the reason the
    /// mask a caller builds is bit-for-bit the one it built before.
    #[test]
    fn fingerprint_is_the_prefix_verbatim_whenever_the_needle_fits() {
        for max in 1..=8usize {
            for n in 1..=max {
                let needle: Vec<u8> = (0..n).map(|i| b"pub fnxyz"[i]).collect();
                let w = fingerprint(&needle, max).unwrap();
                assert_eq!(w.width, n);
                assert_eq!(
                    w.at, 0,
                    "a {n}-byte needle that fits a {max}-byte window must not move"
                );
            }
        }
        assert!(fingerprint(b"", 4).is_none());
    }

    /// And the one case where it does move, spelled out: the prefix of a
    /// needle longer than the window. Note what does NOT move -- a needle of
    /// `max` bytes or fewer -- which is every literal in every mask this
    /// crate builds today, because `MAX_FINGERPRINT` is 4 and a literal of 4
    /// bytes or fewer has nothing to choose between.
    #[test]
    fn fingerprint_moves_only_for_a_needle_longer_than_the_window() {
        let w = fingerprint(b"pub fn", 4).unwrap();
        assert_eq!((w.at, w.width), (1, 4));
        let w = fingerprint(b"pub fnx", 4).unwrap();
        assert_eq!(w.width, 4);
        assert_eq!(&b"pub fnx"[w.at..w.at + w.width], b"ub f");
    }

    /// `cost` is monotone in each byte and saturates rather than wrapping.
    #[test]
    fn cost_is_a_product_that_saturates() {
        assert_eq!(cost(b""), 1);
        assert_eq!(
            cost(b"abc"),
            u64::from(rank(b'a')) * u64::from(rank(b'b')) * u64::from(rank(b'c'))
        );
        assert_eq!(cost(&[0u8; 64]), u64::MAX, "must saturate, not wrap");
    }

    /// A set is scored by the SUM and a range by the PRODUCT, and the
    /// difference is not cosmetic: `e` is rank 253 and the ten digits score
    /// 1904 between them, so a run of required classes that contains a digit
    /// position is scored as the rarer of the two even though every one of
    /// its ten members is commoner than the `e`. A mean would have called
    /// them near-equal, and the whole of `e[0-9]`'s anchor choice is that
    /// they are not.
    #[test]
    fn a_set_is_scored_by_the_sum_of_its_members() {
        assert_eq!(set_cost(b""), 0);
        assert_eq!(set_cost(b"e"), 253);
        let digits = b"0123456789";
        assert_eq!(set_cost(digits), 1904);
        assert!(set_cost(digits) > set_cost(b"e"));
        // Count matters, which is what a mean would have thrown away.
        assert!(set_cost(b"eZ") > set_cost(b"e"));
    }

    /// `rarest_run` is `rarest_window` over sets, with the same refusals and
    /// the same earliest-wins tie-break. The corpus it is built for is a run
    /// of required byte-classes, and a run of two has one position to start
    /// at — the same no-op property `fingerprint` has.
    #[test]
    fn rarest_run_picks_the_cheapest_run_of_classes() {
        let e: &[u8] = b"e";
        let digits: &[u8] = b"0123456789";
        let space: &[u8] = b" ";
        let word: &[u8] = b"word";

        // A two-set run: both positions fit, so it must not move.
        assert_eq!(rarest_run(&[e, digits], 2).unwrap().at, 0);
        // A three-set run into a two-wide window, and it moves: the tail
        // `{space, e}` scores 508 against the head's `{word, space}` at
        // 1176, so two common bytes beat one common byte and four rare
        // ones. `word` is rare at every position and `e` is the second
        // commonest byte in the table, and the sum is what decides it.
        let w = rarest_run(&[word, space, e], 2).unwrap();
        assert_eq!((w.at, w.width), (1, 2));

        assert!(rarest_run(&[e], 2).is_none());
        assert!(rarest_run(&[e, space], 0).is_none());
    }
}
