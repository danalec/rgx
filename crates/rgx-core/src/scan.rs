// SPDX-License-Identifier: Apache-2.0

//! The SIMD scan over a [`NibbleMask`].
//!
//! **Provenance.** Written here first, at full scope, and copied into rgx
//! with `alloc::` rewritten to `std::`.
//!
//! **This is the only `unsafe` in the prefilter, and it is the only part that
//! needed to be.** `literal.rs` builds the mask and `prefilter.rs` confirms
//! candidates, and both are safe and exhaustively tested. This file is the
//! one that trades safety for width, and it is split out so that split is
//! visible rather than smeared through the module.
//!
//! **What is being computed.** One `pshufb` lookup pair per mask position,
//! 32 haystack bytes at a time, ANDed into an accumulator that requires
//! `positions` **consecutive** bytes to agree. See `scan_body` for how the
//! positions are lined up against the chunk without shifting.
//!
//! **Correctness argument.** `simd_candidates` returns exactly the offsets
//! `scalar_candidates` returns. The tests compare the two on random and
//! document-shaped input rather than trusting the argument, and
//! `examples/vec_probe.rs` additionally sweeps a needle across every offset of
//! a controlled haystack -- the harness that found, and then verified the fix
//! for, three distinct lane-alignment defects this function carried across
//! its first three drafts. The distinction that mattered: a probe whose
//! filler shares bytes with the needle measures the filler, and a checker
//! that cannot show its hits can pass while finding nothing.

use alloc::vec;
use alloc::vec::Vec;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::literal::NibbleMask;
#[cfg(target_arch = "x86_64")]
use super::literal::MAX_FINGERPRINT;

/// The number of bytes one AVX2 iteration consumes.
#[cfg(target_arch = "x86_64")]
const LANES: usize = 32;

/// Every offset where a fingerprint **could start**.
///
/// This is the entry point a caller should use, gated at compile time the way
/// the rest of the crate's SIMD is (`b02/simd/mod.rs`): the vector path
/// exists only when the build targets a CPU that has AVX2. rgx's copy
/// dispatches at runtime instead, because it ships one binary to arbitrary
/// machines -- the two conventions differ deliberately and both copies say so.
#[must_use]
pub fn candidates(mask: &NibbleMask, hay: &[u8]) -> Vec<usize> {
    // Counting lives at this one choke point rather than in each path, so the
    // SIMD and scalar scans cannot drift apart in what they report, and it is
    // the only place that knows the haystack length without being told.
    let stats = super::maskstats::enabled();
    let record = |out: &Vec<usize>| {
        if stats {
            super::maskstats::flush(&super::maskstats::ScanDelta {
                bytes: hay.len() as u64,
                blocks: (hay.len() / block_width()) as u64,
                candidates: out.len() as u64,
                confirms: 0,
                hits: 0,
            });
        }
    };
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            // SAFETY: guarded by the runtime feature check above, which
            // is `simd_candidates`'s documented precondition.
            let out = unsafe { simd_candidates(mask, hay) };
            record(&out);
            return out;
        }
    }
    let out = scalar_candidates(mask, hay);
    record(&out);
    out
}

/// Count candidates without materialising them. [`crate::regex::FastScan::count_in`]
/// asks for a yield, not a list, and the list form allocated a `Vec` per call
/// just to take its length. The scalar scan is used deliberately: the only
/// caller samples a few hundred bytes in `measure()`, where the SIMD scan's
/// setup is more than the work it saves.
#[must_use]
pub fn candidates_count(mask: &NibbleMask, hay: &[u8]) -> usize {
    scalar_candidates_count(mask, hay)
}

/// Zero-alloc variant of [`candidates`]: writes into the caller's
/// `out` instead of returning a fresh `Vec`. The caller is expected to
/// reuse `out` across calls so the underlying allocation is paid once
/// per thread. Used by the prefilter where every search over every
/// file was previously allocating a new Vec for the candidate offsets.
///
/// On a 235 MB / 7.8 M-line corpus and a single-byte literal, the
/// candidate list across all fills is roughly 2.5 M entries; the old
/// path allocated a fresh Vec per fill (~30 000 of them in the worst
/// case), and the allocator never sees them again. With a reused
/// scratch, the prefilter drops to one allocation per thread.
/// Append candidate offsets for `mask` in `hay` to `out`.
pub fn candidates_append(mask: &NibbleMask, hay: &[u8], out: &mut Vec<usize>) {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            // SAFETY: feature check above is the documented precondition.
            unsafe { simd_candidates_into(mask, hay, out) };
            record_stats(mask, hay, out);
            return;
        }
    }
    scalar_candidates_into(mask, hay, out);
    record_stats(mask, hay, out);
}

pub fn candidates_into(mask: &NibbleMask, hay: &[u8], out: &mut Vec<usize>) {
    out.clear();
    candidates_append(mask, hay, out);
}

fn record_stats(mask: &NibbleMask, hay: &[u8], out: &[usize]) {
    if super::maskstats::enabled() {
        super::maskstats::flush(&super::maskstats::ScanDelta {
            bytes: hay.len() as u64,
            blocks: (hay.len() / block_width()) as u64,
            candidates: out.len() as u64,
            confirms: 0,
            hits: 0,
        });
    }
    let _ = mask;
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn simd_candidates_into(mask: &NibbleMask, hay: &[u8], out: &mut Vec<usize>) {
    let positions = mask.positions();
    // A haystack SHORTER than the window is not an empty answer: a short
    // bucket padded with don't-care positions is still a candidate there, and
    // `accumulate_at` folds the window off the end for exactly that. Bailing on
    // `hay.len() < positions` is what made `rgx 'ab|cde'` miss `ab` -- the
    // 2-byte `ab` bucket in a 3-byte window was never considered at all.
    if positions == 0 || hay.is_empty() {
        return;
    }
    if positions > MAX_FINGERPRINT {
        scalar_candidates_into(mask, hay, out);
        return;
    }

    let mut tables = [(_mm256_setzero_si256(), _mm256_setzero_si256()); MAX_FINGERPRINT];
    for (j, slot) in tables.iter_mut().enumerate().take(positions) {
        *slot = (
            nibble_table(mask.low_nibbles_at(j)),
            nibble_table(mask.high_nibbles_at(j)),
        );
    }

    let i = match positions {
        1 => scan_body::<1>(hay, &[tables[0]], out),
        2 => scan_body::<2>(hay, &[tables[0], tables[1]], out),
        3 => scan_body::<3>(hay, &[tables[0], tables[1], tables[2]], out),
        _ => scan_body::<4>(hay, &tables, out),
    };

    let mut state = [0u16; MAX_FINGERPRINT];
    let mut prevs = [0u16; MAX_FINGERPRINT];
    let (state, prevs) = (&mut state[..positions], &mut prevs[..positions]);
    let mut at = i;
    while at < hay.len() {
        if accumulate_at(mask, hay, at, state, prevs) {
            out.push(at);
        }
        at += 1;
    }
}

/// Bytes one first first stage iteration consumes.
///
/// 32 where AVX2 is in play, 1 for the scalar path. "Candidates per block"
/// only means something against the block size that actually produced them.
pub fn block_width() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            return LANES;
        }
    }
    1
}

/// The AVX2 path.
///
/// # Safety
///
/// The caller must have established that the CPU supports AVX2. Calling this
/// without it is undefined behaviour, not a wrong answer.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn simd_candidates(mask: &NibbleMask, hay: &[u8]) -> Vec<usize> {
    let positions = mask.positions();
    let mut out = Vec::new();
    // As in `simd_candidates_into`: a short haystack is evaluated with the
    // window folded off its end, not refused.
    if positions == 0 || hay.is_empty() {
        return out;
    }
    // `build_mask` caps the fingerprint at MAX_FINGERPRINT, so the const
    // generics below cover every mask that can reach here. Anything else
    // takes the scalar path, which is the definition rather than an
    // approximation of it.
    if positions > MAX_FINGERPRINT {
        return scalar_candidates(mask, hay);
    }

    let mut tables = [(_mm256_setzero_si256(), _mm256_setzero_si256()); MAX_FINGERPRINT];
    for (j, slot) in tables.iter_mut().enumerate().take(positions) {
        *slot = (
            nibble_table(mask.low_nibbles_at(j)),
            nibble_table(mask.high_nibbles_at(j)),
        );
    }

    let i = match positions {
        1 => scan_body::<1>(hay, &[tables[0]], &mut out),
        2 => scan_body::<2>(hay, &[tables[0], tables[1]], &mut out),
        3 => scan_body::<3>(hay, &[tables[0], tables[1], tables[2]], &mut out),
        _ => scan_body::<4>(hay, &tables, &mut out),
    };

    // The SIMD loop covered starts `0..i` outright -- it never emits a start
    // it could not fully load -- so the tail is under `span` bytes.
    let mut state = [0u16; MAX_FINGERPRINT];
    let mut prevs = [0u16; MAX_FINGERPRINT];
    let (state, prevs) = (&mut state[..positions], &mut prevs[..positions]);
    let mut at = i;
    while at < hay.len() {
        if accumulate_at(mask, hay, at, state, prevs) {
            out.push(at);
        }
        at += 1;
    }
    out
}

/// The chunk loop, with the fingerprint length fixed at `P` so every index
/// into `tables` and every load offset is a constant the unroller can fold.
///
/// One 32-byte load **per position**, all unaligned and overlapping, and no
/// shifting: lane `m` of load `j` is `hay[i+j+m]`, so position `j` is tested
/// against the bytes it would occupy for a match starting at `i+m`. Testing
/// positions as *ends* instead needs each mask shifted left by a different
/// amount and filled from the previous chunk -- a `permute2x128` per position
/// on the accumulator's own dependency chain. The overlapping loads cost `P`
/// loads per LANES bytes, all L1 hits after the first, and leave nothing on
/// that chain.
///
/// # Safety
///
/// The caller must have established that the CPU supports AVX2, and
/// `tables` must hold the mask's `P` broadcast table pairs.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_body<const P: usize>(
    hay: &[u8],
    tables: &[(__m256i, __m256i); P],
    out: &mut Vec<usize>,
) -> usize {
    let k0f = _mm256_set1_epi8(0x0F);
    let span = LANES + P - 1;
    let len = hay.len();
    let mut i = 0usize;

    // A 2x unroll measured slower (17-18 ms against 15-16 on a 235 MB corpus):
    // the second block's eight table registers push the tables out of the file.
    while i + span <= len {
        debug_assert!(i + span <= len, "a load window ran off the end");
        // SAFETY: `i + span <= len`, as the loop condition shows.
        let p = unsafe { hay.as_ptr().add(i) };
        let m = block::<P>(p, tables, k0f);
        if m != 0 {
            emit(m, i, out);
        }
        i += LANES;
    }
    i
}

/// One 32-byte block: the AND of every position's `pshufb` pair, as a bitmask
/// of candidate starts.
///
/// `pshufb` indexes its table with the low four bits of each byte and zeroes
/// the lane if bit 7 is set, so masking the index to 0x0F is what keeps the
/// lookup defined.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn block<const P: usize>(
    p: *const u8,
    tables: &[(__m256i, __m256i); P],
    k0f: __m256i,
) -> u32 {
    let (tl0, th0) = tables[0];
    let c0 = unsafe { _mm256_loadu_si256(p as *const __m256i) };
    let lo0 = _mm256_and_si256(c0, k0f);
    let hi0 = _mm256_and_si256(_mm256_srli_epi16(c0, 4), k0f);
    let mut acc = _mm256_and_si256(_mm256_shuffle_epi8(tl0, lo0), _mm256_shuffle_epi8(th0, hi0));
    if _mm256_testz_si256(acc, acc) == 1 {
        return 0;
    }
    if P > 1 {
        for (j, &(tl, th)) in tables[1..].iter().enumerate() {
            let c = unsafe { _mm256_loadu_si256(p.add(j + 1) as *const __m256i) };
            let lo = _mm256_and_si256(c, k0f);
            let hi = _mm256_and_si256(_mm256_srli_epi16(c, 4), k0f);
            acc = _mm256_and_si256(
                acc,
                _mm256_and_si256(_mm256_shuffle_epi8(tl, lo), _mm256_shuffle_epi8(th, hi)),
            );
            if j + 2 < P && _mm256_testz_si256(acc, acc) == 1 {
                return 0;
            }
        }
    }
    // Inverted from the sign bits: a set bit is a lane no bucket survived in.
    !(_mm256_movemask_epi8(_mm256_cmpeq_epi8(acc, _mm256_setzero_si256())) as u32)
}

/// Append every start in `cand`, whose bit `k` is a candidate at `base + k`.
#[cfg(target_arch = "x86_64")]
#[inline]
fn emit(mut cand: u32, base: usize, out: &mut Vec<usize>) {
    if (cand & (cand - 1)) == 0 {
        out.push(base + cand.trailing_zeros() as usize);
        return;
    }
    while cand != 0 {
        out.push(base + cand.trailing_zeros() as usize);
        cand &= cand - 1;
    }
}

/// Broadcast a 16-entry table of `u16` into the two 32-byte `pshufb` lanes,
/// narrowed to one byte per entry.
///
/// Narrowing is only correct because a bucket bitmask never exceeds
/// [`super::literal::MAX_BUCKETS`] = 8 bits, so the high byte of every `u16`
/// is zero. The assertion below is what stops that from silently becoming
/// wrong if the bucket count ever grows past 8.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
fn nibble_table(src: &[u16; 16]) -> __m256i {
    let mut bytes = [0u8; 32];
    for (i, &v) in src.iter().enumerate() {
        debug_assert_eq!(v >> 8, 0, "bucket mask exceeds 8 bits");
        bytes[i] = v as u8;
    }
    // Both lanes get the same 16-byte table because `pshufb` is lane-local:
    // the high lane of the haystack chunk must index the same table, not
    // zeroes.
    unsafe { _mm256_broadcastsi128_si256(_mm_loadu_si128(bytes.as_ptr() as *const __m128i)) }
}

/// Whether a run of `positions` consecutive bytes ending at `at` matches
/// some bucket's fingerprint, evaluated one position at a time.
///
/// This is the definition [`simd_candidates`] implements in vector form, and
/// the tests hold the two to it. `state[j]` is a bucket bitmask: bucket `k`
/// survives at position `j` only if it was present at position `j - 1` one
/// byte back **and** its byte at `j` matches. There is no bit shift anywhere
/// in it — a shift would move *bucket bits*, and the thing that needs
/// moving is *positions*, which is what the `prev` snapshot does.
#[must_use]
pub fn scalar_candidates(mask: &NibbleMask, hay: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    scalar_candidates_into(mask, hay, &mut out);
    out
}

/// Zero-alloc variant of [`scalar_candidates`]. The state and prev
/// scratch buffers are still allocated per call (they are small, the
/// length of the fingerprint, and `accumulate_at` takes them by
/// `&mut`); the candidate `Vec` is the one the prefilter was paying
/// for per buffer. The caller owns `out` and reuses it.
fn scalar_candidates_into(mask: &NibbleMask, hay: &[u8], out: &mut Vec<usize>) {
    // The common mask is at most `MAX_FINGERPRINT` (4) positions wide, so
    // the two accumulators live on the stack and the AVX2 fallback allocates
    // nothing but the caller's `out`. `add_padded` can build a wider one --
    // `a_long_fingerprint_falls_back_to_byte_compare` does exactly that at
    // 10 -- so a wider mask falls back to the heap rather than to a fixed
    // array that would panic. Threading a caller-owned scratch was the other
    // option; it widens `CandidateSource` and every impl for a case that is
    // already rare, and this keeps the API where it is.
    let n = mask.positions();
    if n <= crate::literal::MAX_FINGERPRINT {
        let mut state = [0u16; crate::literal::MAX_FINGERPRINT];
        let mut prev = [0u16; crate::literal::MAX_FINGERPRINT];
        for at in 0..hay.len() {
            if accumulate_at(mask, hay, at, &mut state[..n], &mut prev[..n]) {
                out.push(at);
            }
        }
    } else {
        let mut state = vec![0u16; n];
        let mut prev = vec![0u16; n];
        for at in 0..hay.len() {
            if accumulate_at(mask, hay, at, &mut state, &mut prev) {
                out.push(at);
            }
        }
    }
}

/// Count the candidates [`scalar_candidates_into`] would push, without
/// materialising them. [`crate::regex::FastScan::count_in`] asks for a
/// yield, not a list, and the list form allocated a `Vec` per call just to
/// take its length. The scalar scan is used deliberately: the only caller
/// samples a few hundred bytes in `measure()`, where the SIMD scan's setup
/// is more than the work it saves.
#[must_use]
fn scalar_candidates_count(mask: &NibbleMask, hay: &[u8]) -> usize {
    let n = mask.positions();
    if n <= crate::literal::MAX_FINGERPRINT {
        let mut state = [0u16; crate::literal::MAX_FINGERPRINT];
        let mut prev = [0u16; crate::literal::MAX_FINGERPRINT];
        let mut count = 0usize;
        for at in 0..hay.len() {
            if accumulate_at(mask, hay, at, &mut state[..n], &mut prev[..n]) {
                count += 1;
            }
        }
        count
    } else {
        let mut state = vec![0u16; n];
        let mut prev = vec![0u16; n];
        let mut count = 0usize;
        for at in 0..hay.len() {
            if accumulate_at(mask, hay, at, &mut state, &mut prev) {
                count += 1;
            }
        }
        count
    }
}

/// Whether a run of `positions` consecutive bytes starting at `at` matches
/// some bucket's fingerprint, accumulating through caller-owned scratch.
///
/// This is the definition [`simd_candidates`] implements in vector form, and
/// the tests hold the two to it. `state[j]` is a bucket bitmask: bucket `k`
/// survives at position `j` only if it was present at position `j - 1` one
/// byte back **and** its byte at `j` matches. There is no bit shift anywhere
/// in it — a shift would move *bucket bits*, and the thing that needs moving
/// is *positions*, which is what the `prev` snapshot does.
#[must_use]
fn accumulate_at(
    mask: &NibbleMask,
    hay: &[u8],
    at: usize,
    state: &mut [u16],
    prev: &mut [u16],
) -> bool {
    let positions = state.len();
    if positions == 0 || at >= hay.len() {
        return false;
    }
    // How much of the window the haystack can actually supply.
    let readable = core::cmp::min(positions, hay.len() - at);
    for &b in &hay[at..at + readable] {
        prev.copy_from_slice(state);
        for j in 1..positions {
            state[j] = prev[j - 1] & mask.bucket_at(j, b);
        }
        state[0] = mask.bucket_at(0, b);
    }
    // **Fold the window positions the haystack ran out on.**
    //
    // A bucket whose fingerprint is shorter than the window has no opinion
    // about the positions past its print, so it survives them and is still a
    // candidate. A bucket with a real byte there does not: it cannot be
    // satisfied, and treating the missing byte as a match would admit `cd` for
    // `cde`. Folding blindly keeps both alive; folding against the record of
    // which buckets actually had an opinion there is what separates them.
    if readable < positions {
        let dontcare = mask.dontcare_at();
        let mut live = state[readable - 1];
        for j in readable..positions {
            live &= dontcare.get(j).copied().unwrap_or(0);
        }
        return live != 0;
    }
    state[positions - 1] != 0
}

/// [`scalar_candidates`] for a single offset, with its own scratch. Convenient
/// and correct; do not call it per byte in a hot loop.
#[must_use]
pub fn scalar_candidate_at(mask: &NibbleMask, hay: &[u8], at: usize) -> bool {
    let mut state = vec![0u16; mask.positions()];
    let mut prev = vec![0u16; mask.positions()];
    accumulate_at(mask, hay, at, &mut state, &mut prev)
}

// ---------------------------------------------------------------------------
// The bit maps
// ---------------------------------------------------------------------------

/// One bit per byte of the haystack it was filled from.
///
/// **Why this exists.** Measured on a 235 MB single file, the per-line loop's
/// two SIMD calls -- `memchr('\n')` over each 31-byte line, and `memchr` over
/// each line's remainder for the prefilter -- cost 61 ms and 62 ms. Together
/// that was 123 ms of a 143 ms replication of the whole search, and 56% of the
/// 218 ms the binary takes on that corpus. Nothing about that cost is the
/// bytes: `memchr_iter` over the whole buffer for the same needle runs at
/// 50 GB/s, which is 5 ms. The cost is that a CALL costs ~7 ns whether the
/// range is 31 bytes or 31 KB -- one dispatch, one setup, one tail -- so a
/// per-line loop pays it 7.8 million times, and then once per candidate on top.
///
/// Materialising the offsets instead does not help and measurably hurts: the
/// `memchr` iterator's `next()` is not its specialised `count()`, and
/// collecting 13 million of them measured 216 ms against the 62 ms the
/// per-line calls cost. So neither "one call per line" nor "one iterator per
/// hit" is affordable, and the only shape left is ONE call per BUFFER whose
/// output is cheap to consume.
///
/// That is what a [`BitMap`] is: one bit per byte, filled by a single SIMD
/// pass and then read with `trailing_zeros` on words already in L1. A 64 KiB
/// buffer is 8 KiB of map, so both maps together are 16 KiB and stay resident
/// while 7.8 million boundaries and 13 million candidates are pulled out of
/// them by shifts rather than by calls.
///
/// **Bounded per BUFFER, not per file.** A map is `len / 8` bytes, so the
/// searcher holds two of them for one reader fill and only while that fill is
/// being walked. A caller declines to build one above
/// [`MAX_BITMAP_INPUT`] rather than mapping a whole file.
pub struct BitMap {
    words: Vec<u64>,
    len: usize,
}

/// The largest haystack a [`BitMap`] is built for. The map is `len/8` bytes,
/// so this bounds one map at 8 MB; above it a haystack is walked per line,
/// which is slower and still correct -- a map is an accelerator, never a
/// correctness requirement.
///
/// **The 256 KiB cap was measured and lost, and that measurement was taken on
/// a buffer that never shrank** (`LineBuffer` held one long line for every
/// later fill, so 125 of 129 fills were oversized and a raise built maps on
/// fills that had previously declined cheaply). The drop fix emptied the
/// buffer between fills, and re-measuring on `main` over 20 MiB
/// corpora turns the result around:
///
/// ```text
///   shape                      cap 256 KiB        cap 64 MiB
///   one 20 MiB line            12.65 ms (off)     10.22 ms (on)   -19%
///   40 x 512 KiB lines          4.35 ms (off)      4.41 ms (on)   overlap
///   800k short lines            9.68 ms (on)       9.71 ms (on)   overlap
/// ```
///
/// Only the single-long-line shape moves, and it moves a lot: that is
/// minified JS, a JSON dump, a base64 blob -- real files where the buffer IS
/// the line. The shape the old number was taken on is now indistinguishable,
/// so the loss it recorded is not reproducible.
///
/// **The decline this constant guards is now unreachable.** A reader fill is
/// bounded by `LineBuffer::MAX_BUF` (8 MiB) and a slice by `BUFFER_PATH_MAX`
/// (16 MiB); both sit under this cap, so every fill and every slice gets its
/// maps and a windowed map has no window left to cut. It stays as a bound on
/// the allocation rather than as `usize::MAX` because the map is `len/8` and
/// a caller that hands in a whole unmapped region should still meet a ceiling.
pub const MAX_BITMAP_INPUT: usize = 64 * 1024 * 1024;

impl BitMap {
    /// An empty map. Nothing is allocated until a [`BitMap::clear`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            words: Vec::new(),
            len: 0,
        }
    }

    /// The haystack length this map covers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the map covers no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Prepare for a haystack of `len` bytes, zeroed.
    ///
    /// Zeroing is the whole cost of reuse, and it is `len / 8` bytes of stores
    /// -- which is precisely why the map is worth having: the alternative is
    /// not "no clearing" but a function call per element.
    ///
    /// Exactly as many words as the haystack needs and no more: a 32-aligned
    /// 32-byte chunk never crosses a 64-byte boundary, so the vector fill
    /// writes only bits describing bytes that exist, and the padding bits above
    /// the haystack are never set.
    pub fn clear(&mut self, len: usize) {
        self.len = len;
        let needed = len.div_ceil(64);
        if self.words.len() >= needed {
            self.words.truncate(needed);
            self.words.fill(0);
        } else {
            self.words.fill(0);
            self.words.resize(needed, 0);
        }
    }

    /// Word `i`, or 0 past the end. The padding bits above the haystack are
    /// never written, so a caller cannot be handed an offset beyond it.
    #[must_use]
    fn word(&self, i: usize) -> u64 {
        self.words.get(i).copied().unwrap_or(0)
    }

    /// Set the bit for byte `at`.
    #[inline]
    fn set(&mut self, at: usize) {
        self.words[at / 64] |= 1u64 << (at % 64);
    }

    /// OR a 32-lane mask in at `base`, which the chunk loop keeps a multiple of
    /// 32.
    ///
    /// One word, never two: a 32-byte chunk at a 32-aligned base covers
    /// `[base, base + 32)`, and both ends are inside the same 64-byte word
    /// because `base % 64` is 0 or 32 and adding 31 reaches at most 63 within
    /// it. The version that split the mask across `lo` and `lo + 1` put the
    /// high half at offsets `base + 64 ..` -- bytes the haystack does not have
    /// -- and every test that compared against the scalar definition found it.
    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn push32(&mut self, base: usize, lanes: u32) {
        if lanes == 0 {
            return;
        }
        debug_assert!(base.is_multiple_of(32), "chunk base is not 32-aligned");
        debug_assert!(base + LANES <= self.len, "chunk runs past the haystack");
        self.words[base / 64] |= u64::from(lanes) << (base % 64);
    }

    /// OR a 64-bit lane mask in at `base`, which the mask fill keeps a
    /// multiple of 64.
    ///
    /// One word, never two, for the reason [`Self::push32`] gives: a 64-byte
    /// chunk at a 64-aligned base covers `[base, base + 64)`, which is exactly
    /// the word, so there is no straddle to get wrong.
    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn push64(&mut self, base: usize, bits: u64) {
        if bits == 0 {
            return;
        }
        debug_assert!(base.is_multiple_of(64), "chunk base is not 64-aligned");
        debug_assert!(base + 64 <= self.len, "chunk runs past the haystack");
        self.words[base / 64] |= bits;
    }

    /// The map's words, for a caller that walks them itself.
    ///
    /// **Why a caller would.** Going through [`BitMap::next_set`] from a hot
    /// loop costs about 11 ns per call -- the reload of the word, the variable
    /// shift and the bounds check -- which is the SAME cost as the `memchr`
    /// over a 31-byte line that the map exists to remove, and then the search
    /// pays the fill as well. The walk has to be INLINE in the consumer's loop
    /// to be a win, and that means the consumer holding the words themselves.
    #[must_use]
    pub fn words(&self) -> &[u64] {
        &self.words
    }

    /// Mutable view of the map's words, for a caller that wants to `|=` or
    /// assign into `words[word_idx]` directly along the same induction
    /// variable as `base` rather than going through `push64`.
    ///
    /// Direct assignment skips the bounds check and the `base / 64` division
    /// `push64` carries on its hot path: the caller already has the word
    /// index from its own stride, and the caller's contract -- that
    /// `word_idx * 64 < self.len + 64` and that `base.is_multiple_of(64)` --
    /// is the same contract `push64` enforces at runtime.
    #[must_use]
    pub fn words_mut(&mut self) -> &mut [u64] {
        &mut self.words
    }

    /// The word containing offset `at`, with every bit BELOW `at` cleared.
    ///
    /// What the candidate iterator walks with: it turns "give me the rest of
    /// the map from here" into one load and one shift, with no branch on
    /// whether `at` is word-aligned.
    #[must_use]
    pub fn word_from(&self, at: usize) -> u64 {
        self.word(at / 64) & (u64::MAX << (at % 64))
    }

    /// How many bits are set in `from..to`.
    ///
    /// The early exit needs this because a skipped buffer still has to hand
    /// its line count to the sink's line numbering, and a `popcount` over
    /// words already in L1 is the difference between one pass over 8 KiB and
    /// a `memchr` per line. The same range semantics as [`BitMap::any_set`]:
    /// a set bit past `to` is never counted, and neither is one at or below
    /// `from`.
    #[must_use]
    pub fn count_set(&self, from: usize, to: usize) -> u64 {
        let to = to.min(self.len);
        if from >= to {
            return 0;
        }
        let first = from / 64;
        let last = (to - 1) / 64;
        let mask_from = !0u64 << (from % 64);
        let mask_to = !0u64 >> (63 - ((to - 1) % 64));
        if first == last {
            let w = self.word(first) & mask_from & mask_to;
            return w.count_ones() as u64;
        }
        let mut n = (self.word(first) & mask_from).count_ones() as u64;
        if last > first + 1 {
            let mid = &self.words[first + 1..last];
            let (chunks, remainder) = mid.as_chunks::<4>();
            for chunk in chunks {
                n += (chunk[0].count_ones()
                    + chunk[1].count_ones()
                    + chunk[2].count_ones()
                    + chunk[3].count_ones()) as u64;
            }
            for &w in remainder {
                n += w.count_ones() as u64;
            }
        }
        n + (self.word(last) & mask_to).count_ones() as u64
    }

    /// The first offset at or after `from` whose bit is set, or `None`.
    ///
    /// The walk is over words, not bytes: a sparse map is skipped 64 bytes at
    /// a time and a dense one costs one `trailing_zeros`. A caller asking the
    /// "nothing at all" answer pays for the words it crossed, which is the same
    /// order as the bytes it did not read.
    #[must_use]
    pub fn next_set(&self, from: usize) -> Option<usize> {
        if from >= self.len {
            return None;
        }
        let words = &self.words;
        let mut i = from / 64;
        if i >= words.len() {
            return None;
        }
        let w = words[i] & (u64::MAX << (from % 64));
        if w != 0 {
            let pos = i * 64 + (w.trailing_zeros() as usize);
            return if pos < self.len { Some(pos) } else { None };
        }
        i += 1;
        while i + 4 <= words.len() {
            let w0 = words[i];
            let w1 = words[i + 1];
            let w2 = words[i + 2];
            let w3 = words[i + 3];
            if (w0 | w1 | w2 | w3) != 0 {
                let (w_nz, offset) = if w0 != 0 {
                    (w0, 0)
                } else if w1 != 0 {
                    (w1, 1)
                } else if w2 != 0 {
                    (w2, 2)
                } else {
                    (w3, 3)
                };
                let pos = (i + offset) * 64 + (w_nz.trailing_zeros() as usize);
                return if pos < self.len { Some(pos) } else { None };
            }
            i += 4;
        }
        while i < words.len() {
            let cur = words[i];
            if cur != 0 {
                let pos = i * 64 + (cur.trailing_zeros() as usize);
                return if pos < self.len { Some(pos) } else { None };
            }
            i += 1;
        }
        None
    }

    /// Call `f` with each offset whose bit is set, in ascending order.
    #[inline]
    pub fn for_each_set(&self, mut f: impl FnMut(usize)) {
        for (i, &word) in self.words.iter().enumerate() {
            let mut w = word;
            let base = i * 64;
            while w != 0 {
                let bit = w.trailing_zeros() as usize;
                let pos = base + bit;
                if pos >= self.len {
                    return;
                }
                f(pos);
                w &= w - 1;
            }
        }
    }

    /// Append all set bit offsets to `out`.
    #[inline]
    pub fn append_offsets(&self, out: &mut Vec<usize>) {
        self.for_each_set(|pos| out.push(pos));
    }

    /// Whether any bit in `from..to` is set.
    #[must_use]
    pub fn any_set(&self, from: usize, to: usize) -> bool {
        let to = to.min(self.len);
        if from >= to {
            return false;
        }
        let first = from / 64;
        let last = (to - 1) / 64;
        let mask_from = !0u64 << (from % 64);
        let mask_to = !0u64 >> (63 - ((to - 1) % 64));
        if first == last {
            return (self.word(first) & mask_from & mask_to) != 0;
        }
        if (self.word(first) & mask_from) != 0 {
            return true;
        }
        if last > first + 1 {
            let mid = &self.words[first + 1..last];
            let (chunks, remainder) = mid.as_chunks::<4>();
            for chunk in chunks {
                if (chunk[0] | chunk[1] | chunk[2] | chunk[3]) != 0 {
                    return true;
                }
            }
            for &w in remainder {
                if w != 0 {
                    return true;
                }
            }
        }
        (self.word(last) & mask_to) != 0
    }
}

impl Default for BitMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Fill `out` with a bit at every offset of `hay` holding the line terminator.
///
/// This is [`memchr`]'s job done into a map instead of an iterator, and the
/// difference is the point: the consumer reads the result with shifts rather
/// than calling anything per line.
pub fn term_bits(term: u8, hay: &[u8], out: &mut BitMap) {
    out.clear(hay.len());
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx512bw() {
            unsafe { avx512_bits(&[term, 0, 0], 1, hay, out) };
            return;
        }
        if crate::detect::avx2() {
            unsafe { avx2_bits(&[term, 0, 0], 1, hay, out) };
            return;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { neon_bits(&[term, 0, 0], 1, hay, out) };
    }
    // The scalar path is the fallback for the targets with no SIMD path, and
    // on aarch64 the NEON path above has already answered: the line is
    // unreachable there, and unreachable code is an error under the gate's
    // `-D warnings`.
    #[cfg(not(target_arch = "aarch64"))]
    {
        scalar_bits(&[term, 0, 0], 1, hay, out);
    }
}

/// Fill `out` with a bit at every offset of `hay` holding one of the first
/// `count` bytes of `needles`.
///
/// `count` is 1, 2 or 3 because that is what `memchr`, `memchr2` and
/// `memchr3` cover between them, and this is the map form of exactly those
/// three. A fourth needle is the packed mask's job, and that path materialises
/// a short candidate list instead of a map. For a set of FOUR OR MORE
/// one-byte needles use [`byte_bits_many`], which ORs these kernels over
/// groups of three.
pub fn byte_bits(needles: &[u8; 3], count: usize, hay: &[u8], out: &mut BitMap) {
    out.clear(hay.len());
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx512bw() {
            unsafe { avx512_bits(needles, count, hay, out) };
            return;
        }
        if crate::detect::avx2() {
            unsafe { avx2_bits(needles, count, hay, out) };
            return;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { neon_bits(needles, count, hay, out) };
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        scalar_bits(needles, count, hay, out);
    }
}

/// Fill `out` with a bit at every offset of `hay` holding any byte of `needles`,
/// for a set of any length -- the map form of "one of these bytes" that
/// [`byte_bits`] cannot express past three.
///
/// The kernels below cover one to three needles, so a longer set is filled by
/// ORing them over groups of three. That is `ceil(n/3)` SIMD passes over the
/// haystack instead of one, and for the four-to-eight case this serves that is
/// two or three passes -- still far cheaper than the Pike VM per line this map
/// exists to avoid. The set is small and fixed at compile time, so the
/// grouping is a loop over a stack array and no allocation happens.
///
/// `out` is cleared first, the way [`byte_bits`] and [`pair_bits`] clear --
/// `map_candidates` hands the same map back on every fill, and a kernel that
/// ORed into it as it stood would keep the previous fill's bits. The group
/// passes inside this function are what the OR is for.
pub fn byte_bits_many(needles: &[u8], hay: &[u8], out: &mut BitMap) {
    out.clear(hay.len());
    if needles.is_empty() || hay.is_empty() {
        return;
    }
    for chunk in needles.chunks(3) {
        let mut pad = [0u8; 3];
        pad[..chunk.len()].copy_from_slice(chunk);
        #[cfg(target_arch = "x86_64")]
        {
            if crate::detect::avx512bw() {
                unsafe { avx512_bits(&pad, chunk.len(), hay, out) };
                continue;
            }
            if crate::detect::avx2() {
                unsafe { avx2_bits(&pad, chunk.len(), hay, out) };
                continue;
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            unsafe { neon_bits(&pad, chunk.len(), hay, out) };
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            scalar_bits(&pad, chunk.len(), hay, out);
        }
    }
}

/// One pass, two maps: terminator bits and high-byte (`>= 0x80`) bits.
///
/// The two fills over the same haystack used to be two passes -- the term
/// scan and [`high_bits`] -- and the second one cost the composed settle
/// its whole lead over the window rule on the flagship row. Fused: one
/// load per chunk feeds both masks (`pcmpeqb`+`pmovmskb` for the
/// terminator, bare `pmovmskb` for the high bytes).
pub fn term_high_bits(term: u8, hay: &[u8], terms: &mut BitMap, high: &mut BitMap) {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx512bw() {
            unsafe { avx512_term_high_bits(term, hay, terms, high) };
            return;
        }
        if crate::detect::avx2() {
            unsafe { avx2_term_high_bits(term, hay, terms, high) };
            return;
        }
    }
    // Two SIMD passes beat one scalar pass everywhere the fused kernel is
    // not written (a NEON kernel would fuse the same way). `high_bits`
    // clears on entry, so the order is free.
    term_bits(term, hay, terms);
    high_bits(hay, high);
}

/// AVX-512BW fused fill. The masks come back as `__mmask64` -- bit j is
/// byte j -- which is the map word layout already, so there is no
/// `pmovmsask` extraction and no merge: one load, two stores per 64 bytes.
/// This is the kernel the two-pass baseline was already running twice.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw")]
unsafe fn avx512_term_high_bits(term: u8, hay: &[u8], terms: &mut BitMap, high: &mut BitMap) {
    use core::arch::x86_64::*;
    terms.clear(hay.len());
    high.clear(hay.len());
    let mut i = 0usize;
    let t_words = terms.words_mut();
    let h_words = high.words_mut();
    let mut word_idx = 0usize;
    let n0 = _mm512_set1_epi8(term as i8);
    while i + 64 <= hay.len() {
        let v = _mm512_loadu_si512(hay.as_ptr().add(i) as *const _);
        let tm = _mm512_cmpeq_epi8_mask(v, n0) as u64;
        let hm = _mm512_movepi8_mask(v) as u64;
        // UNCONDITIONAL assignment: `clear` zeroed the words and this walk
        // owns the map, so a zero mask is a correct (if redundant) write --
        // and branchless is the point. The high-byte mask is true for about
        // half the words on real source, which made the conditional store a
        // mispredict per iteration.
        t_words[word_idx] = tm;
        h_words[word_idx] = hm;
        i += 64;
        word_idx += 1;
    }
    for (k, &b) in hay[i..].iter().enumerate() {
        if b == term {
            terms.set(i + k);
        }
        if b >= 0x80 {
            high.set(i + k);
        }
    }
}

/// AVX-2 fallback fused fill: `pmovmskb` of the raw register IS the
/// high-byte mask, and the term mask is one compare more. The broadcast is
/// hoisted and the word stores are unconditional -- the mask pairs are
/// what the iteration is for, and branches there cost more than the writes.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_term_high_bits(term: u8, hay: &[u8], terms: &mut BitMap, high: &mut BitMap) {
    use core::arch::x86_64::*;
    terms.clear(hay.len());
    high.clear(hay.len());
    if hay.is_empty() {
        return;
    }
    let t = _mm256_set1_epi8(term as i8);
    let t_words = terms.words_mut();
    let h_words = high.words_mut();
    let mut i = 0usize;
    let mut word_idx = 0usize;
    while i + 64 <= hay.len() {
        let v0 = _mm256_loadu_si256(hay.as_ptr().add(i) as *const __m256i);
        let v1 = _mm256_loadu_si256(hay.as_ptr().add(i + 32) as *const __m256i);
        let t0 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v0, t)) as u32;
        let t1 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, t)) as u32;
        let h0 = _mm256_movemask_epi8(v0) as u32;
        let h1 = _mm256_movemask_epi8(v1) as u32;
        t_words[word_idx] |= (t0 as u64) | ((t1 as u64) << 32);
        h_words[word_idx] |= (h0 as u64) | ((h1 as u64) << 32);
        i += 64;
        word_idx += 1;
    }
    if i + LANES <= hay.len() {
        let v = _mm256_loadu_si256(hay.as_ptr().add(i) as *const __m256i);
        let tb = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, t)) as u32;
        let hb = _mm256_movemask_epi8(v) as u32;
        if tb != 0 {
            terms.push32(i, tb);
        }
        if hb != 0 {
            high.push32(i, hb);
        }
        i += LANES;
    }
    for (k, &b) in hay[i..].iter().enumerate() {
        if b == term {
            terms.set(i + k);
        }
        if b >= 0x80 {
            high.set(i + k);
        }
    }
}
/// Fill `out` with a bit at every offset of `hay` holding a byte `>= 0x80`.
///
/// The complement of `hybrid::is_ascii` as a map: the searcher's line loop
/// asks "is this line's range free of high bytes" once per line, and a
/// per-line `is_ascii` rescan costs 66 ms on the flagship row (see
/// `benchmark/findings.md` §13). `pmovmskb` of a raw chunk IS this
/// predicate -- no compare -- so the SIMD fill is one load and one
/// instruction per 32 bytes. `out` is cleared first, for the reason
/// [`byte_bits_many`] clears.
pub fn high_bits(hay: &[u8], out: &mut BitMap) {
    out.clear(hay.len());
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx512bw() {
            unsafe { avx512_high_bits(hay, out) };
            return;
        }
        if crate::detect::avx2() {
            unsafe { avx2_high_bits(hay, out) };
            return;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { neon_high_bits(hay, out) };
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        scalar_high_bits(hay, 0, out);
    }
}

/// AVX-2 fill of [`high_bits`]: `_mm256_movemask_epi8` of the raw register
/// is the `>= 0x80` mask, so the compare the other kernels need is absent.
#[cfg(target_arch = "x86_64")]
unsafe fn avx2_high_bits(hay: &[u8], out: &mut BitMap) {
    use core::arch::x86_64::*;
    if hay.is_empty() {
        return;
    }
    let mut i = 0usize;
    let out_words = out.words_mut();
    let mut word_idx = 0usize;
    while i + 64 <= hay.len() {
        let v0 = _mm256_loadu_si256(hay.as_ptr().add(i) as *const __m256i);
        let v1 = _mm256_loadu_si256(hay.as_ptr().add(i + 32) as *const __m256i);
        let b0 = _mm256_movemask_epi8(v0) as u32;
        let b1 = _mm256_movemask_epi8(v1) as u32;
        let word = (b0 as u64) | ((b1 as u64) << 32);
        if word != 0 {
            out_words[word_idx] |= word;
        }
        i += 64;
        word_idx += 1;
    }
    if i + LANES <= hay.len() {
        let v = _mm256_loadu_si256(hay.as_ptr().add(i) as *const __m256i);
        let bits = _mm256_movemask_epi8(v) as u32;
        if bits != 0 {
            out.push32(i, bits);
        }
        i += LANES;
    }
    scalar_high_bits(&hay[i..], i, out);
}

/// AVX-512BW fill of [`high_bits`]: `vpmovb2m` is the mask itself, one
/// 64-byte chunk to one map word with no compare and no merge.
#[cfg(target_arch = "x86_64")]
unsafe fn avx512_high_bits(hay: &[u8], out: &mut BitMap) {
    use core::arch::x86_64::*;
    if hay.is_empty() {
        return;
    }
    let mut i = 0usize;
    let out_words = out.words_mut();
    let mut word_idx = 0usize;
    while i + 64 <= hay.len() {
        let v = _mm512_loadu_si512(hay.as_ptr().add(i) as *const _);
        let bits = _mm512_movepi8_mask(v) as u64;
        if bits != 0 {
            out_words[word_idx] |= bits;
        }
        i += 64;
        word_idx += 1;
    }
    scalar_high_bits(&hay[i..], i, out);
}

/// NEON fill of [`high_bits`]: the chunk's maximum has its high bit set
/// exactly when some byte does, which is the whole predicate.
#[cfg(target_arch = "aarch64")]
unsafe fn neon_high_bits(hay: &[u8], out: &mut BitMap) {
    use core::arch::aarch64::*;
    if hay.is_empty() {
        return;
    }
    let mut i = 0usize;
    while i + 16 <= hay.len() {
        let v = vld1q_u8(hay.as_ptr().add(i));
        if vmaxvq_u8(v) >= 0x80 {
            for j in 0..16 {
                if hay[i + j] >= 0x80 {
                    out.set(i + j);
                }
            }
        }
        i += 16;
    }
    scalar_high_bits(&hay[i..], i, out);
}

/// Portable fill of [`high_bits`], and the tail every kernel above falls to.
/// Bits land at `base + at`, so a kernel's tail keeps absolute offsets.
fn scalar_high_bits(hay: &[u8], base: usize, out: &mut BitMap) {
    for (at, &b) in hay.iter().enumerate() {
        if b >= 0x80 {
            out.set(base + at);
        }
    }
}
/// Count occurrences of a single byte in `data`.
///
/// Uses AVX-512 (64 bytes/cycle) or AVX2 (32 bytes/cycle) on x86_64,
/// ARM NEON (16 bytes/cycle) on aarch64, and falls back to scalar counting.
pub fn count_byte(target: u8, data: &[u8]) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx512bw() {
            return unsafe { avx512_count_byte(target, data) };
        }
        if crate::detect::avx2() {
            return unsafe { avx2_count_byte(target, data) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { neon_count_byte(target, data) }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        scalar_count_byte(target, data)
    }
}

// The scalar path is the oracle the tests hold the vector path to, so it
// stays compiled on every target: on aarch64 the NEON path answers and
// nothing in a build without the test harness calls this. The warning
// would stand where the function is the thing that is correct.
#[allow(dead_code)]
#[inline]
fn scalar_count_byte(target: u8, data: &[u8]) -> u64 {
    let mut count = 0u64;
    for &b in data {
        if b == target {
            count += 1;
        }
    }
    count
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_count_byte(target: u8, data: &[u8]) -> u64 {
    let mut count = 0u64;
    let len = data.len();
    let mut i = 0;
    let target_vec = _mm256_set1_epi8(target as i8);

    while i + 128 <= len {
        let p = data.as_ptr().add(i);
        let c0 = _mm256_loadu_si256(p as *const __m256i);
        let c1 = _mm256_loadu_si256(p.add(32) as *const __m256i);
        let c2 = _mm256_loadu_si256(p.add(64) as *const __m256i);
        let c3 = _mm256_loadu_si256(p.add(96) as *const __m256i);
        let m0 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c0, target_vec)) as u32;
        let m1 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c1, target_vec)) as u32;
        let m2 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c2, target_vec)) as u32;
        let m3 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c3, target_vec)) as u32;
        let m01 = (m0 as u64) | ((m1 as u64) << 32);
        let m23 = (m2 as u64) | ((m3 as u64) << 32);
        count += (m01.count_ones() + m23.count_ones()) as u64;
        i += 128;
    }

    while i + 64 <= len {
        let p = data.as_ptr().add(i);
        let c0 = _mm256_loadu_si256(p as *const __m256i);
        let c1 = _mm256_loadu_si256(p.add(32) as *const __m256i);
        let m0 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c0, target_vec)) as u32;
        let m1 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c1, target_vec)) as u32;
        let m01 = (m0 as u64) | ((m1 as u64) << 32);
        count += m01.count_ones() as u64;
        i += 64;
    }

    while i + 32 <= len {
        let chunk = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);
        let eq = _mm256_cmpeq_epi8(chunk, target_vec);
        let mask = _mm256_movemask_epi8(eq) as u32;
        count += mask.count_ones() as u64;
        i += 32;
    }

    while i < len {
        if *data.get_unchecked(i) == target {
            count += 1;
        }
        i += 1;
    }

    count
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw")]
unsafe fn avx512_count_byte(target: u8, data: &[u8]) -> u64 {
    let mut count = 0u64;
    let len = data.len();
    let mut i = 0;
    let target_vec = _mm512_set1_epi8(target as i8);

    while i + 256 <= len {
        let p = data.as_ptr().add(i);
        let c0 = _mm512_loadu_si512(p as *const _);
        let c1 = _mm512_loadu_si512(p.add(64) as *const _);
        let c2 = _mm512_loadu_si512(p.add(128) as *const _);
        let c3 = _mm512_loadu_si512(p.add(192) as *const _);
        let m0 = _mm512_cmpeq_epi8_mask(c0, target_vec);
        let m1 = _mm512_cmpeq_epi8_mask(c1, target_vec);
        let m2 = _mm512_cmpeq_epi8_mask(c2, target_vec);
        let m3 = _mm512_cmpeq_epi8_mask(c3, target_vec);
        count += (m0.count_ones() + m1.count_ones() + m2.count_ones() + m3.count_ones()) as u64;
        i += 256;
    }

    while i + 64 <= len {
        let chunk = _mm512_loadu_si512(data.as_ptr().add(i) as *const _);
        let mask = _mm512_cmpeq_epi8_mask(chunk, target_vec);
        count += mask.count_ones() as u64;
        i += 64;
    }

    while i < len {
        if *data.get_unchecked(i) == target {
            count += 1;
        }
        i += 1;
    }

    count
}

#[cfg(target_arch = "aarch64")]
unsafe fn neon_count_byte(target: u8, data: &[u8]) -> u64 {
    use core::arch::aarch64::*;
    let mut count = 0u64;
    let len = data.len();
    let mut i = 0;
    let target_vec = vdupq_n_u8(target);

    while i + 16 <= len {
        let chunk = vld1q_u8(data.as_ptr().add(i));
        let eq = vceqq_u8(chunk, target_vec);
        let ones = vandq_u8(eq, vdupq_n_u8(1));
        count += vaddvq_u8(ones) as u64;
        i += 16;
    }

    while i < len {
        if *data.get_unchecked(i) == target {
            count += 1;
        }
        i += 1;
    }

    count
}

/// AVX-512 vector fill: 64 bytes per iteration directly into a 64-bit mask.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw")]
unsafe fn avx512_bits(needles: &[u8; 3], count: usize, hay: &[u8], out: &mut BitMap) {
    if hay.is_empty() {
        return;
    }
    let n0 = _mm512_set1_epi8(needles[0] as i8);
    let mut i = 0usize;
    // Direct assignment into `BitMap::words[word_idx]` along the same
    // induction variable as `i`: `push64` does the bounds check and the
    // `base / 64` divide on every non-zero chunk, and both are gone when
    // the caller carries its own `word_idx`.
    let out_words = out.words_mut();
    match count {
        1 => {
            let mut word_idx = 0usize;
            while i + 64 <= hay.len() {
                let v = _mm512_loadu_si512(hay.as_ptr().add(i) as *const _);
                let m = _mm512_cmpeq_epi8_mask(v, n0);
                if m != 0 {
                    out_words[word_idx] |= m;
                }
                i += 64;
                word_idx += 1;
            }
        }
        2 => {
            let n1 = _mm512_set1_epi8(needles[1] as i8);
            let mut word_idx = 0usize;
            while i + 64 <= hay.len() {
                let v = _mm512_loadu_si512(hay.as_ptr().add(i) as *const _);
                let m = _mm512_cmpeq_epi8_mask(v, n0) | _mm512_cmpeq_epi8_mask(v, n1);
                if m != 0 {
                    out_words[word_idx] |= m;
                }
                i += 64;
                word_idx += 1;
            }
        }
        _ => {
            let n1 = _mm512_set1_epi8(needles[1] as i8);
            let n2 = _mm512_set1_epi8(needles[2] as i8);
            let mut word_idx = 0usize;
            while i + 64 <= hay.len() {
                let v = _mm512_loadu_si512(hay.as_ptr().add(i) as *const _);
                let m = _mm512_cmpeq_epi8_mask(v, n0)
                    | _mm512_cmpeq_epi8_mask(v, n1)
                    | _mm512_cmpeq_epi8_mask(v, n2);
                if m != 0 {
                    out_words[word_idx] |= m;
                }
                i += 64;
                word_idx += 1;
            }
        }
    }
    for (k, &b) in hay[i..].iter().enumerate() {
        if needles[..count].contains(&b) {
            out.set(i + k);
        }
    }
}

/// The vector fill: one `cmpeq` per needle, ORed, `movemask`ed, ORed into the
/// map -- 64 bytes per iteration and no per-match work at all.
///
/// # Safety
///
/// The caller must have established that the CPU supports AVX2.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_bits(needles: &[u8; 3], count: usize, hay: &[u8], out: &mut BitMap) {
    if hay.is_empty() {
        return;
    }
    let n0 = _mm256_set1_epi8(needles[0] as i8);
    let mut i = 0usize;
    // Direct assignment into `BitMap::words[word_idx]`, with `word_idx`
    // walking the same `+1` induction as `i += 64`. `push64` divides by
    // 64 and bounds-checks on every non-zero chunk; the caller has
    // both numbers already, so the cost folds away.
    let out_words = out.words_mut();
    match count {
        1 => {
            let mut word_idx = 0usize;
            while i + 64 <= hay.len() {
                let v0 = _mm256_loadu_si256(hay.as_ptr().add(i) as *const __m256i);
                let v1 = _mm256_loadu_si256(hay.as_ptr().add(i + 32) as *const __m256i);
                let m0 = _mm256_cmpeq_epi8(v0, n0);
                let m1 = _mm256_cmpeq_epi8(v1, n0);
                let b0 = _mm256_movemask_epi8(m0) as u32;
                let b1 = _mm256_movemask_epi8(m1) as u32;
                let word = (b0 as u64) | ((b1 as u64) << 32);
                if word != 0 {
                    out_words[word_idx] |= word;
                }
                i += 64;
                word_idx += 1;
            }
            if i + LANES <= hay.len() {
                let v = _mm256_loadu_si256(hay.as_ptr().add(i) as *const __m256i);
                let m = _mm256_cmpeq_epi8(v, n0);
                let bits = _mm256_movemask_epi8(m) as u32;
                if bits != 0 {
                    out.push32(i, bits);
                }
                i += LANES;
            }
        }
        2 => {
            let n1 = _mm256_set1_epi8(needles[1] as i8);
            let mut word_idx = 0usize;
            while i + 64 <= hay.len() {
                let v0 = _mm256_loadu_si256(hay.as_ptr().add(i) as *const __m256i);
                let v1 = _mm256_loadu_si256(hay.as_ptr().add(i + 32) as *const __m256i);
                let m0 = _mm256_or_si256(_mm256_cmpeq_epi8(v0, n0), _mm256_cmpeq_epi8(v0, n1));
                let m1 = _mm256_or_si256(_mm256_cmpeq_epi8(v1, n0), _mm256_cmpeq_epi8(v1, n1));
                let b0 = _mm256_movemask_epi8(m0) as u32;
                let b1 = _mm256_movemask_epi8(m1) as u32;
                let word = (b0 as u64) | ((b1 as u64) << 32);
                if word != 0 {
                    out_words[word_idx] |= word;
                }
                i += 64;
                word_idx += 1;
            }
            if i + LANES <= hay.len() {
                let v = _mm256_loadu_si256(hay.as_ptr().add(i) as *const __m256i);
                let m = _mm256_or_si256(_mm256_cmpeq_epi8(v, n0), _mm256_cmpeq_epi8(v, n1));
                let bits = _mm256_movemask_epi8(m) as u32;
                if bits != 0 {
                    out.push32(i, bits);
                }
                i += LANES;
            }
        }
        _ => {
            let n1 = _mm256_set1_epi8(needles[1] as i8);
            let n2 = _mm256_set1_epi8(needles[2] as i8);
            let mut word_idx = 0usize;
            while i + 64 <= hay.len() {
                let v0 = _mm256_loadu_si256(hay.as_ptr().add(i) as *const __m256i);
                let v1 = _mm256_loadu_si256(hay.as_ptr().add(i + 32) as *const __m256i);
                let m0 = _mm256_or_si256(
                    _mm256_or_si256(_mm256_cmpeq_epi8(v0, n0), _mm256_cmpeq_epi8(v0, n1)),
                    _mm256_cmpeq_epi8(v0, n2),
                );
                let m1 = _mm256_or_si256(
                    _mm256_or_si256(_mm256_cmpeq_epi8(v1, n0), _mm256_cmpeq_epi8(v1, n1)),
                    _mm256_cmpeq_epi8(v1, n2),
                );
                let b0 = _mm256_movemask_epi8(m0) as u32;
                let b1 = _mm256_movemask_epi8(m1) as u32;
                let word = (b0 as u64) | ((b1 as u64) << 32);
                if word != 0 {
                    out_words[word_idx] |= word;
                }
                i += 64;
                word_idx += 1;
            }
            if i + LANES <= hay.len() {
                let v = _mm256_loadu_si256(hay.as_ptr().add(i) as *const __m256i);
                let m = _mm256_or_si256(
                    _mm256_or_si256(_mm256_cmpeq_epi8(v, n0), _mm256_cmpeq_epi8(v, n1)),
                    _mm256_cmpeq_epi8(v, n2),
                );
                let bits = _mm256_movemask_epi8(m) as u32;
                if bits != 0 {
                    out.push32(i, bits);
                }
                i += LANES;
            }
        }
    }
    for (k, &b) in hay[i..].iter().enumerate() {
        if needles[..count].contains(&b) {
            out.set(i + k);
        }
    }
}

/// ARM NEON vector fill: 16 bytes per iteration.
#[cfg(target_arch = "aarch64")]
unsafe fn neon_bits(needles: &[u8; 3], count: usize, hay: &[u8], out: &mut BitMap) {
    use core::arch::aarch64::*;
    if hay.is_empty() {
        return;
    }
    let n0 = vdupq_n_u8(needles[0]);
    let n1 = vdupq_n_u8(needles[1]);
    let n2 = vdupq_n_u8(needles[2]);
    let mut i = 0usize;
    while i + 16 <= hay.len() {
        let v = vld1q_u8(hay.as_ptr().add(i));
        let mut m = vceqq_u8(v, n0);
        if count >= 2 {
            m = vorrq_u8(m, vceqq_u8(v, n1));
        }
        if count >= 3 {
            m = vorrq_u8(m, vceqq_u8(v, n2));
        }
        if vmaxvq_u8(m) != 0 {
            for j in 0..16 {
                if needles[..count].contains(&hay[i + j]) {
                    out.set(i + j);
                }
            }
        }
        i += 16;
    }
    for (k, &b) in hay[i..].iter().enumerate() {
        if needles[..count].contains(&b) {
            out.set(i + k);
        }
    }
}

/// Pick the second byte offset `k` in `1..needle.len()` for paired SIMD scanning.
#[inline]
pub fn k_for_pair(needle: &[u8]) -> usize {
    if needle.len() <= 2 {
        return 1;
    }
    let limit = (needle.len() - 1).min(15);
    let mut best_k = 1;
    let mut best_rank = super::frequency::rank(needle[1]);
    for (k, &b) in needle.iter().enumerate().take(limit + 1).skip(2) {
        let r = super::frequency::rank(b);
        if r < best_rank {
            best_rank = r;
            best_k = k;
        }
    }
    best_k
}

/// Multi-byte paired-byte SIMD candidate/match offset scanner.
///
/// Tests two bytes simultaneously (offset 0 and rarest offset `k`) in 32-byte chunks
/// (or 64 bytes with AVX-512), pruning over 99.9% of blocks in a single instruction.
pub fn pair_offsets(needle: &[u8], hay: &[u8], out: &mut Vec<usize>) {
    if needle.len() < 2 || hay.len() < needle.len() {
        return;
    }
    let k = k_for_pair(needle);
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx512bw() {
            unsafe { avx512_pair_offsets(needle, k, hay, out) };
            return;
        }
        if crate::detect::avx2() {
            unsafe { avx2_pair_offsets(needle, k, hay, out) };
            return;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { neon_pair_offsets(needle, k, hay, out) };
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        scalar_pair_offsets(needle, k, hay, out);
    }
}

/// Multi-byte paired-byte SIMD bit scanner into [`BitMap`].
pub fn pair_bits(needle: &[u8], hay: &[u8], out: &mut BitMap) {
    out.clear(hay.len());
    if needle.len() < 2 || hay.len() < needle.len() {
        return;
    }
    let k = k_for_pair(needle);
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx512bw() {
            unsafe { avx512_pair_bits(needle, k, hay, out) };
            return;
        }
        if crate::detect::avx2() {
            unsafe { avx2_pair_bits(needle, k, hay, out) };
            return;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { neon_pair_bits(needle, k, hay, out) };
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        scalar_pair_bits(needle, k, hay, out);
    }
}

/// The first match of `needle` in `hay`, by the paired-byte scanner.
///
/// **This is the early-exit twin of [`pair_offsets`].** The
/// offset-collecting scanner walks the whole haystack, because a caller
/// that wants every match cannot stop at the first one; a caller that wants
/// the first one can, and stopping is the difference between a scan that
/// ends at the hit and a scan that ends at the end of the file.
///
/// **The pair is the needle's two rarest bytes, not its first byte and its
/// rarest.** [`pair_offsets`] pairs the first byte with the rarest one,
/// which is the right pair when the first byte is rare and a poor one when
/// it is not: `needle12345` starts with an `n`, and every `n` in the
/// haystack is a candidate that has to be confirmed and thrown away. The
/// pair here is [`frequency::rarest_pair`]'s -- the same two offsets
/// `memchr`'s own packed-pair kernel uses -- so the candidates are the rare
/// ones whichever byte they sit at.
///
/// **The pair may be any two offsets, so the loads are not at the block's
/// start.** The block at `s` loads the bytes at `s + i` and `s + j`, and
/// the candidate is `s` itself: the needle starts at the candidate, and
/// the two rare bytes sit at `i` and `j` inside it.
pub fn pair_find(needle: &[u8], hay: &[u8]) -> Option<usize> {
    if needle.len() < 2 || hay.len() < needle.len() {
        return None;
    }
    let pair = super::frequency::rarest_pair(needle)?;
    #[cfg(target_arch = "x86_64")]
    {
        // AVX-512 first, and the reason is measured rather than assumed.
        //
        // **The AVX2 kernel's speed depends on where the linker puts it.**
        // The two builds of this crate differ by a few kilobytes of code,
        // which moves the kernel to a different address, and the kernel's
        // hot path then either straddles a 64-byte window or does not.
        // Straddling costs the front end a cycle per block -- the same
        // instructions measured 103 us in one build and 154 us in the
        // other, reproducibly, with the machine code byte for byte the
        // same. The AVX-512 kernel is not sensitive to it: 113 us, 112 us
        // and 112 us in three builds whose layouts differ.
        //
        // So the forwards scan takes the 512-bit path where the CPU has
        // it, and the AVX2 kernel below stays as the path for the CPUs
        // that have AVX2 without AVX-512BW. The backwards scan already
        // preferred AVX-512, and for a different and better reason: its
        // AVX2 kernel is the one that runs out of registers, and the
        // k-mask is what saves it (98 us against 139 us).
        if crate::detect::avx512bw() {
            return unsafe { avx512_pair_find(needle, pair, hay) };
        }
        if crate::detect::avx2() {
            return unsafe { avx2_pair_find(needle, pair, hay) };
        }
    }
    scalar_pair_find(needle, pair, hay)
}

/// The last match of `needle` in `hay`, by the paired-byte scanner.
///
/// The twin of [`pair_find`] that walks the haystack from its end. The
/// blocks are the same 32 candidates wide and the pair is the same two
/// rarest bytes; what differs is the order the blocks and the bits inside
/// them are visited, because a backwards search wants the *highest*
/// candidate first and a forwards one wants the lowest.
pub fn pair_rfind(needle: &[u8], hay: &[u8]) -> Option<usize> {
    if needle.len() < 2 || hay.len() < needle.len() {
        return None;
    }
    let pair = super::frequency::rarest_pair(needle)?;
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx512bw() {
            return unsafe { avx512_pair_rfind(needle, pair, hay) };
        }
        if crate::detect::avx2() {
            return unsafe { avx2_pair_rfind(needle, pair, hay) };
        }
    }
    scalar_pair_rfind(needle, pair, hay)
}

/// Whether the needle sits at the haystack's `hay`.
///
/// **This compares through raw pointers and never calls `memcmp`, and that
/// is the whole point.** A call inside the scanner's loop clobbers every
/// vector register, so the two broadcast vectors have to be spilled and
/// reloaded on every block and the loop becomes load-bound: the same
/// kernel measured 167 us with the call in it and 103 us without it.
///
/// **A bounds check is just as bad, for a different reason.** The panic
/// path a bounds check drags in keeps the needle's pointer and length
/// alive across the block, and the register pressure that follows is what
/// makes the compiler hand the `movemask` result the very register the
/// haystack's base pointer was living in -- a copy out of the loop and a
/// copy back into it, on every block. The raw pointers below have no
/// panic path to keep alive, and the block that uses them measures the
/// same 103 us the upstream crate's own packed-pair kernel measures.
///
/// The comparison is on the candidate path, which is the rare one, so the
/// byte at a time costs nothing that matters.
///
/// # Safety
///
/// `needle` and `hay` must each be valid for reads of `len` bytes.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn needle_at(needle: *const u8, hay: *const u8, len: usize) -> bool {
    let mut k = 0usize;
    while k < len {
        if *needle.add(k) != *hay.add(k) {
            return false;
        }
        k += 1;
    }
    true
}

/// AVX2 paired-byte scan, forwards.
///
/// **The block walks the haystack with one induction variable -- the
/// block's own address -- and the candidate's offset is computed from it
/// only when there is a candidate to confirm.** A loop that carries the
/// block's start as an index *and* the haystack's base as a pointer needs
/// both, plus the two offsets of the pair's bytes, plus the mask; that is
/// one register too many, and the compiler answers the shortage by
/// handing the `movemask` result the register the base pointer was in.
/// The block then copies the base out and back on every iteration. The
/// single-pointer shape has nothing to copy: the same scan measured 154 us
/// with the index loop and 103 us with this one, and the upstream crate's
/// own packed-pair kernel -- the shape this follows -- measures the same
/// 103 us.
///
/// The pair is the needle's two rarest bytes, so the candidates are the
/// rare ones; [`pair_find`] says why that is not the needle's first byte
/// and its rarest.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_pair_find(
    needle: &[u8],
    pair: super::frequency::RarePair,
    hay: &[u8],
) -> Option<usize> {
    let len = needle.len();
    let (i, j) = (pair.first, pair.second);
    let vi = _mm256_set1_epi8(needle[i] as i8);
    let vj = _mm256_set1_epi8(needle[j] as i8);
    let limit = hay.len() - len;
    let hi = i.max(j);

    let start = hay.as_ptr();
    let mut cur = start;
    // The block at `cur` reads 32 bytes at `cur + i` and 32 bytes at
    // `cur + j`, so it fits while `cur + hi + 32` is inside the haystack.
    // When even the first block does not fit there is nothing to scan
    // with vectors and the tail below does the whole haystack.
    if let Some(fit) = hay.len().checked_sub(hi + 32) {
        let max = start.add(fit + 1);
        while cur < max {
            let ci = _mm256_loadu_si256(cur.add(i) as *const __m256i);
            let cj = _mm256_loadu_si256(cur.add(j) as *const __m256i);
            let mut mask = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(ci, vi),
                _mm256_cmpeq_epi8(cj, vj),
            )) as u32;

            while mask != 0 {
                let bit = mask.trailing_zeros() as usize;
                let cand = cur.offset_from(start) as usize + bit;
                if cand <= limit && needle_at(needle.as_ptr(), cur.add(bit), len) {
                    return Some(cand);
                }
                mask &= mask - 1;
            }
            cur = cur.add(32);
        }
    }

    // The candidates the blocks did not cover.
    //
    // **The tail reads the needle through raw pointers, and that is not a
    // detail.** A tail that reads `needle[i]` has a bounds check, and the
    // panic path behind it keeps the needle's *length* alive across the
    // vector loop; the tail that reads `needle[j]` keeps the needle's
    // *byte* alive across it. Either one is a value the loop has to carry
    // in a register it does not have, and the compiler answers the
    // shortage by spilling it and reloading it on every block -- the
    // reload lands in the loop's latch, where it costs a cycle per block,
    // and the scan measured 155 us with it and 103 us without it.
    let nptr = needle.as_ptr();
    let hptr = hay.as_ptr();
    let mut s = cur.offset_from(start) as usize;
    while s <= limit {
        if *nptr.add(i) == *hptr.add(s + i)
            && *nptr.add(j) == *hptr.add(s + j)
            && needle_at(nptr, hptr.add(s), len)
        {
            return Some(s);
        }
        s += 1;
    }
    None
}

/// AVX2 paired-byte scan, backwards.
///
/// The twin of [`avx2_pair_find`] that walks the haystack from its end.
/// The blocks are the same 32 candidates wide and the pair is the same two
/// rarest bytes; what differs is the order the blocks and the bits inside
/// them are visited, because a backwards search wants the *highest*
/// candidate first and a forwards one wants the lowest.
///
/// **The block that covers the highest candidate starts at `limit - 31`,
/// and its loads reach `limit + hi + 1`.** That is inside the haystack
/// because `hi` is inside the needle: `limit` is the last start a needle
/// of this length can have, so `limit + hi + 1` is the needle's own end
/// plus one at worst. Every block below it fits for the same reason.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_pair_rfind(
    needle: &[u8],
    pair: super::frequency::RarePair,
    hay: &[u8],
) -> Option<usize> {
    let len = needle.len();
    let (i, j) = (pair.first, pair.second);
    let vi = _mm256_set1_epi8(needle[i] as i8);
    let vj = _mm256_set1_epi8(needle[j] as i8);
    let limit = hay.len() - len;

    let start = hay.as_ptr();
    // One past the highest candidate the blocks have covered.
    let mut top = limit + 1;
    while top >= 32 {
        let b = top - 32;
        let p = start.add(b);
        let ci = _mm256_loadu_si256(p.add(i) as *const __m256i);
        let cj = _mm256_loadu_si256(p.add(j) as *const __m256i);
        let mut mask = _mm256_movemask_epi8(_mm256_and_si256(
            _mm256_cmpeq_epi8(ci, vi),
            _mm256_cmpeq_epi8(cj, vj),
        )) as u32;

        while mask != 0 {
            // The highest set bit first: a backwards search wants the
            // last match, and the block is visited from its top.
            let bit = 31 - mask.leading_zeros() as usize;
            let cand = b + bit;
            if cand <= limit && needle_at(needle.as_ptr(), p.add(bit), len) {
                return Some(cand);
            }
            mask &= !(1u32 << bit);
        }
        top = b;
    }

    // The candidates the blocks did not cover, from the top down.
    let nptr = needle.as_ptr();
    let hptr = hay.as_ptr();
    let mut cand = top;
    while cand > 0 {
        cand -= 1;
        if *nptr.add(i) == *hptr.add(cand + i)
            && *nptr.add(j) == *hptr.add(cand + j)
            && needle_at(nptr, hptr.add(cand), len)
        {
            return Some(cand);
        }
    }
    None
}

/// AVX-512 paired-byte scan, forwards.
///
/// The twin of [`avx2_pair_find`] with 64 candidates to a block. The
/// mask is a `k` register here, so the block never round-trips through a
/// general-purpose register the way the AVX2 one does.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw")]
unsafe fn avx512_pair_find(
    needle: &[u8],
    pair: super::frequency::RarePair,
    hay: &[u8],
) -> Option<usize> {
    let len = needle.len();
    let (i, j) = (pair.first, pair.second);
    let vi = _mm512_set1_epi8(needle[i] as i8);
    let vj = _mm512_set1_epi8(needle[j] as i8);
    let limit = hay.len() - len;
    let hi = i.max(j);

    let start = hay.as_ptr();
    let mut cur = start;
    if let Some(fit) = hay.len().checked_sub(hi + 64) {
        let max = start.add(fit + 1);
        while cur < max {
            let ci = _mm512_loadu_si512(cur.add(i) as *const _);
            let cj = _mm512_loadu_si512(cur.add(j) as *const _);
            let mut mask = _mm512_cmpeq_epi8_mask(ci, vi) & _mm512_cmpeq_epi8_mask(cj, vj);

            while mask != 0 {
                let bit = mask.trailing_zeros() as usize;
                let cand = cur.offset_from(start) as usize + bit;
                if cand <= limit && needle_at(needle.as_ptr(), cur.add(bit), len) {
                    return Some(cand);
                }
                mask &= mask - 1;
            }
            cur = cur.add(64);
        }
    }

    let mut s = cur.offset_from(start) as usize;
    let nptr = needle.as_ptr();
    let hptr = hay.as_ptr();
    while s <= limit {
        if *nptr.add(i) == *hptr.add(s + i)
            && *nptr.add(j) == *hptr.add(s + j)
            && needle_at(nptr, hptr.add(s), len)
        {
            return Some(s);
        }
        s += 1;
    }
    None
}

/// AVX-512 paired-byte scan, backwards.
///
/// The twin of [`avx512_pair_find`] that walks the haystack from its end,
/// with the same 64 candidates to a block and the same reason the highest
/// block fits: the candidate `limit` is the needle's last start, so the
/// block that covers it reads no further than the needle's own end.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw")]
unsafe fn avx512_pair_rfind(
    needle: &[u8],
    pair: super::frequency::RarePair,
    hay: &[u8],
) -> Option<usize> {
    let len = needle.len();
    let (i, j) = (pair.first, pair.second);
    let vi = _mm512_set1_epi8(needle[i] as i8);
    let vj = _mm512_set1_epi8(needle[j] as i8);
    let limit = hay.len() - len;

    let start = hay.as_ptr();
    let mut top = limit + 1;
    while top >= 64 {
        let b = top - 64;
        let p = start.add(b);
        let ci = _mm512_loadu_si512(p.add(i) as *const _);
        let cj = _mm512_loadu_si512(p.add(j) as *const _);
        let mut mask = _mm512_cmpeq_epi8_mask(ci, vi) & _mm512_cmpeq_epi8_mask(cj, vj);

        while mask != 0 {
            let bit = 63 - mask.leading_zeros() as usize;
            let cand = b + bit;
            if cand <= limit && needle_at(needle.as_ptr(), p.add(bit), len) {
                return Some(cand);
            }
            mask &= !(1u64 << bit);
        }
        top = b;
    }

    let mut cand = top;
    let nptr = needle.as_ptr();
    let hptr = hay.as_ptr();
    while cand > 0 {
        cand -= 1;
        if *nptr.add(i) == *hptr.add(cand + i)
            && *nptr.add(j) == *hptr.add(cand + j)
            && needle_at(nptr, hptr.add(cand), len)
        {
            return Some(cand);
        }
    }
    None
}

// The oracle of the paired-byte paths, for the reason `scalar_pair_offsets`
// carries: it stays compiled on every target, and a build without the
// test harness calls nothing here.
#[allow(dead_code)]
fn scalar_pair_find(needle: &[u8], pair: super::frequency::RarePair, hay: &[u8]) -> Option<usize> {
    let len = needle.len();
    let (i, j) = (pair.first, pair.second);
    let limit = hay.len() - len;
    for s in 0..=limit {
        if hay[s + i] == needle[i] && hay[s + j] == needle[j] && &hay[s..s + len] == needle {
            return Some(s);
        }
    }
    None
}

// The oracle of the paired-byte paths, for the reason `scalar_pair_offsets`
// carries: it stays compiled on every target, and a build without the
// test harness calls nothing here.
#[allow(dead_code)]
fn scalar_pair_rfind(needle: &[u8], pair: super::frequency::RarePair, hay: &[u8]) -> Option<usize> {
    let len = needle.len();
    let (i, j) = (pair.first, pair.second);
    let limit = hay.len() - len;
    for s in (0..=limit).rev() {
        if hay[s + i] == needle[i] && hay[s + j] == needle[j] && &hay[s..s + len] == needle {
            return Some(s);
        }
    }
    None
}

/// Fill `cands` and `terms` in one haystack pass — the pair scan and the
/// terminator scan share their loads.
///
/// Measured `both maps /64K` in `scan_floor.rs` is 13.5 ms where the two
/// kernels separately are 7.7 + 7.3; one fused pass over the same bytes is
/// the only way to remove the second scan's memory traffic. The maps stay
/// separate — this fuses the *scan*, not the *answers*.
pub fn pair_term_bits(needle: &[u8], term: u8, hay: &[u8], cands: &mut BitMap, terms: &mut BitMap) {
    cands.clear(hay.len());
    terms.clear(hay.len());
    if hay.is_empty() {
        return;
    }
    // A haystack shorter than the needle has no pair match. Fill terms
    // and leave cands empty -- same contract as \pair_bits\.
    if needle.len() < 2 || hay.len() < needle.len() {
        term_bits_into(term, hay, terms);
        return;
    }
    let k = k_for_pair(needle);
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            unsafe { avx2_pair_term_bits(needle, k, term, hay, cands, terms) };
            return;
        }
    }
    scalar_pair_term_bits(needle, k, term, hay, cands, terms);
}

/// Fill only `terms` from a pre-cleared map (the pair scan was skipped).
fn term_bits_into(term: u8, hay: &[u8], terms: &mut BitMap) {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx512bw() {
            unsafe { avx512_bits(&[term, 0, 0], 1, hay, terms) };
            return;
        }
        if crate::detect::avx2() {
            unsafe { avx2_bits(&[term, 0, 0], 1, hay, terms) };
            return;
        }
    }
    scalar_bits(&[term, 0, 0], 1, hay, terms);
}

/// AVX2 fused pair + terminator scan.
///
/// The pair comparison needs loads at `i` and `i+k`; the terminator
/// comparison needs a load at `i`. The pair's `i` load is shared with the
/// term comparison — that is the whole saving. Six loads become four per
/// 64-byte chunk, and two `movemask`+store rounds happen from one pass
/// instead of two.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_pair_term_bits(
    needle: &[u8],
    k: usize,
    term: u8,
    hay: &[u8],
    cands: &mut BitMap,
    terms: &mut BitMap,
) {
    let len = needle.len();
    let b0 = needle[0];
    let b1 = needle[k];
    let v0 = _mm256_set1_epi8(b0 as i8);
    let v1 = _mm256_set1_epi8(b1 as i8);
    let vt = _mm256_set1_epi8(term as i8);
    let limit = hay.len().saturating_sub(len);
    let cands_words = cands.words_mut();
    let terms_words = terms.words_mut();
    let mut i = 0usize;

    if len == 2 {
        let mut word_idx = 0usize;
        // 64-byte chunks: two 32-byte halves, both maps from one pass.
        while i + 64 + k <= hay.len() {
            let p0 = hay.as_ptr().add(i);
            let c0_0 = _mm256_loadu_si256(p0 as *const __m256i);
            let c1_0 = _mm256_loadu_si256(p0.add(k) as *const __m256i);
            let p1 = p0.add(32);
            let c0_1 = _mm256_loadu_si256(p1 as *const __m256i);
            let c1_1 = _mm256_loadu_si256(p1.add(k) as *const __m256i);

            let pm0 = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(c0_0, v0),
                _mm256_cmpeq_epi8(c1_0, v1),
            )) as u32;
            let pm1 = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(c0_1, v0),
                _mm256_cmpeq_epi8(c1_1, v1),
            )) as u32;
            let pair_word = u64::from(pm0) | (u64::from(pm1) << 32);

            // Term mask reuses c0_0 / c0_1 — no extra load.
            let tm0 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c0_0, vt)) as u32;
            let tm1 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c0_1, vt)) as u32;
            let term_word = u64::from(tm0) | (u64::from(tm1) << 32);

            if pair_word != 0 {
                cands_words[word_idx] |= pair_word;
            }
            if term_word != 0 {
                terms_words[word_idx] |= term_word;
            }
            i += 64;
            word_idx += 1;
        }
        // 32-byte tail chunk.
        while i + 32 + k <= hay.len() {
            let p0 = hay.as_ptr().add(i);
            let c0 = _mm256_loadu_si256(p0 as *const __m256i);
            let c1 = _mm256_loadu_si256(p0.add(k) as *const __m256i);
            let pm = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(c0, v0),
                _mm256_cmpeq_epi8(c1, v1),
            )) as u32;
            let tm = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c0, vt)) as u32;
            if pm != 0 {
                cands.push32(i, pm);
            }
            if tm != 0 {
                terms.push32(i, tm);
            }
            i += 32;
        }
    } else {
        // 3+-byte needle: pair is a prefilter, each hit needs verification.
        let mut word_idx = 0usize;
        while i + 64 + k <= hay.len() {
            let p0 = hay.as_ptr().add(i);
            let c0_0 = _mm256_loadu_si256(p0 as *const __m256i);
            let c1_0 = _mm256_loadu_si256(p0.add(k) as *const __m256i);
            let p1 = p0.add(32);
            let c0_1 = _mm256_loadu_si256(p1 as *const __m256i);
            let c1_1 = _mm256_loadu_si256(p1.add(k) as *const __m256i);

            let pm0 = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(c0_0, v0),
                _mm256_cmpeq_epi8(c1_0, v1),
            )) as u32;
            let pm1 = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(c0_1, v0),
                _mm256_cmpeq_epi8(c1_1, v1),
            )) as u32;

            let tm0 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c0_0, vt)) as u32;
            let tm1 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c0_1, vt)) as u32;
            let term_word = u64::from(tm0) | (u64::from(tm1) << 32);

            if (pm0 | pm1) != 0 {
                let mut conf0 = 0u32;
                let mut m0 = pm0;
                while m0 != 0 {
                    let bit = m0.trailing_zeros() as usize;
                    let cand = i + bit;
                    if cand <= limit && &hay[cand..cand + len] == needle {
                        conf0 |= 1u32 << bit;
                    }
                    m0 &= m0 - 1;
                }
                let mut conf1 = 0u32;
                let mut m1 = pm1;
                while m1 != 0 {
                    let bit = m1.trailing_zeros() as usize;
                    let cand = i + 32 + bit;
                    if cand <= limit && &hay[cand..cand + len] == needle {
                        conf1 |= 1u32 << bit;
                    }
                    m1 &= m1 - 1;
                }
                let pair_word = u64::from(conf0) | (u64::from(conf1) << 32);
                if pair_word != 0 {
                    cands_words[word_idx] |= pair_word;
                }
            }
            if term_word != 0 {
                terms_words[word_idx] |= term_word;
            }
            i += 64;
            word_idx += 1;
        }
        while i + 32 + k <= hay.len() {
            let p0 = hay.as_ptr().add(i);
            let c0 = _mm256_loadu_si256(p0 as *const __m256i);
            let c1 = _mm256_loadu_si256(p0.add(k) as *const __m256i);
            let pm = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(c0, v0),
                _mm256_cmpeq_epi8(c1, v1),
            )) as u32;
            let tm = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c0, vt)) as u32;
            if pm != 0 {
                let mut conf = 0u32;
                let mut m = pm;
                while m != 0 {
                    let bit = m.trailing_zeros() as usize;
                    let cand = i + bit;
                    if cand <= limit && &hay[cand..cand + len] == needle {
                        conf |= 1u32 << bit;
                    }
                    m &= m - 1;
                }
                if conf != 0 {
                    cands.push32(i, conf);
                }
            }
            if tm != 0 {
                terms.push32(i, tm);
            }
            i += 32;
        }
    }
    // Scalar tail for both maps.
    for (at, &b) in hay[i..].iter().enumerate() {
        let pos = i + at;
        if b == term {
            terms.set(pos);
        }
        if pos <= limit {
            if len == 2 {
                if hay[pos] == b0 && hay[pos + 1] == b1 {
                    cands.set(pos);
                }
            } else if hay[pos] == b0 && hay[pos + k] == b1 && &hay[pos..pos + len] == needle {
                cands.set(pos);
            }
        }
    }
}

/// Scalar fused pair + terminator scan. Same answers as the AVX2 path.
fn scalar_pair_term_bits(
    needle: &[u8],
    k: usize,
    term: u8,
    hay: &[u8],
    cands: &mut BitMap,
    terms: &mut BitMap,
) {
    let len = needle.len();
    let b0 = needle[0];
    let b1 = needle[k];
    let limit = hay.len().saturating_sub(len);
    for (at, &b) in hay.iter().enumerate() {
        if b == term {
            terms.set(at);
        }
        if at <= limit {
            if len == 2 {
                if b == b0 && hay[at + 1] == b1 {
                    cands.set(at);
                }
            } else if b == b0 && hay[at + k] == b1 && &hay[at..at + len] == needle {
                cands.set(at);
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw")]
unsafe fn avx512_pair_offsets(needle: &[u8], k: usize, hay: &[u8], out: &mut Vec<usize>) {
    let len = needle.len();
    let b0 = needle[0];
    let b1 = needle[k];
    let v0 = _mm512_set1_epi8(b0 as i8);
    let v1 = _mm512_set1_epi8(b1 as i8);
    let limit = hay.len() - len;
    let mut i = 0usize;

    if len == 2 {
        // 2-byte literals (`pub`, `fn`, `let`) cannot false-match: every set
        // bit IS a candidate. Hoist the per-bit branch out of the chunk
        // loop and let the comparison against `hay[cand..cand+2]` collapse
        // away entirely.
        while i + 64 + k <= hay.len() {
            let p0 = hay.as_ptr().add(i);
            let c0 = _mm512_loadu_si512(p0 as *const _);
            let c1 = _mm512_loadu_si512(p0.add(k) as *const _);
            let mut mask = _mm512_cmpeq_epi8_mask(c0, v0) & _mm512_cmpeq_epi8_mask(c1, v1);

            while mask != 0 {
                let bit = mask.trailing_zeros() as usize;
                out.push(i + bit);
                mask &= mask - 1;
            }
            i += 64;
        }

        while i <= limit {
            if hay[i] == b0 && hay[i + 1] == b1 {
                out.push(i);
            }
            i += 1;
        }
    } else {
        // 3+-byte literals need a candidate verification. The compare stays
        // inside the inner loop, but the per-call `if len == 2` test folds
        // away for the common 2-byte case above and is hoisted by the
        // outer branch for the rare 3+ case here.
        while i + 64 + k <= hay.len() {
            let p0 = hay.as_ptr().add(i);
            let c0 = _mm512_loadu_si512(p0 as *const _);
            let c1 = _mm512_loadu_si512(p0.add(k) as *const _);
            let mut mask = _mm512_cmpeq_epi8_mask(c0, v0) & _mm512_cmpeq_epi8_mask(c1, v1);

            while mask != 0 {
                let bit = mask.trailing_zeros() as usize;
                let cand = i + bit;
                if cand <= limit && &hay[cand..cand + len] == needle {
                    out.push(cand);
                }
                mask &= mask - 1;
            }
            i += 64;
        }

        while i <= limit {
            if hay[i] == b0 && hay[i + k] == b1 && &hay[i..i + len] == needle {
                out.push(i);
            }
            i += 1;
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw")]
unsafe fn avx512_pair_bits(needle: &[u8], k: usize, hay: &[u8], out: &mut BitMap) {
    let len = needle.len();
    let b0 = needle[0];
    let b1 = needle[k];
    let v0 = _mm512_set1_epi8(b0 as i8);
    let v1 = _mm512_set1_epi8(b1 as i8);
    let limit = hay.len() - len;
    let mut i = 0usize;
    let out_words = out.words_mut();

    if len == 2 {
        // 2-byte literals: every set bit is a confirmed match. Direct store
        // of the mask into the BitMap word, with `word_idx = i / 64`
        // walking the same arithmetic the chunk stride does.
        let mut word_idx = 0usize;
        while i + 64 + k <= hay.len() {
            let p0 = hay.as_ptr().add(i);
            let c0 = _mm512_loadu_si512(p0 as *const _);
            let c1 = _mm512_loadu_si512(p0.add(k) as *const _);
            let mask = _mm512_cmpeq_epi8_mask(c0, v0) & _mm512_cmpeq_epi8_mask(c1, v1);

            if mask != 0 {
                out_words[word_idx] |= mask;
            }
            i += 64;
            word_idx += 1;
        }

        while i <= limit {
            if hay[i] == b0 && hay[i + 1] == b1 {
                out.set(i);
            }
            i += 1;
        }
    } else {
        // 3+-byte literals: confirm every candidate against
        // `hay[cand..cand + len]` and accumulate the survivors.
        while i + 64 + k <= hay.len() {
            let p0 = hay.as_ptr().add(i);
            let c0 = _mm512_loadu_si512(p0 as *const _);
            let c1 = _mm512_loadu_si512(p0.add(k) as *const _);
            let mut mask = _mm512_cmpeq_epi8_mask(c0, v0) & _mm512_cmpeq_epi8_mask(c1, v1);

            if mask != 0 {
                let mut conf: u64 = 0;
                while mask != 0 {
                    let bit = mask.trailing_zeros() as usize;
                    let cand = i + bit;
                    if cand <= limit && &hay[cand..cand + len] == needle {
                        conf |= 1u64 << bit;
                    }
                    mask &= mask - 1;
                }
                if conf != 0 {
                    out.push64(i, conf);
                }
            }
            i += 64;
        }

        while i <= limit {
            if hay[i] == b0 && hay[i + k] == b1 && &hay[i..i + len] == needle {
                out.set(i);
            }
            i += 1;
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_pair_offsets(needle: &[u8], k: usize, hay: &[u8], out: &mut Vec<usize>) {
    let len = needle.len();
    let b0 = needle[0];
    let b1 = needle[k];
    let v0 = _mm256_set1_epi8(b0 as i8);
    let v1 = _mm256_set1_epi8(b1 as i8);
    let limit = hay.len() - len;
    let mut i = 0usize;

    if len == 2 {
        // 2-byte literals cannot false-match: every set bit IS a candidate.
        // The per-bit `len == 2` branch and the `cand <= limit &&
        // &hay[cand..cand + len] == needle` confirmation fold away at
        // compile time, so the inner loop is just the `trailing_zeros`
        // walk.
        while i + 32 + k <= hay.len() {
            let p0 = hay.as_ptr().add(i);
            let c0 = _mm256_loadu_si256(p0 as *const __m256i);
            let c1 = _mm256_loadu_si256(p0.add(k) as *const __m256i);
            let mut mask = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(c0, v0),
                _mm256_cmpeq_epi8(c1, v1),
            )) as u32;

            while mask != 0 {
                let bit = mask.trailing_zeros() as usize;
                out.push(i + bit);
                mask &= mask - 1;
            }
            i += 32;
        }

        while i <= limit {
            if hay[i] == b0 && hay[i + 1] == b1 {
                out.push(i);
            }
            i += 1;
        }
    } else {
        // 3+-byte literals need a candidate verification; the compare
        // sits inside the inner loop, but the per-iteration `if len == 2`
        // is gone, and the outer branch above keeps the hot 2-byte case
        // off the long-code path entirely.
        while i + 32 + k <= hay.len() {
            let p0 = hay.as_ptr().add(i);
            let c0 = _mm256_loadu_si256(p0 as *const __m256i);
            let c1 = _mm256_loadu_si256(p0.add(k) as *const __m256i);
            let mut mask = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(c0, v0),
                _mm256_cmpeq_epi8(c1, v1),
            )) as u32;

            while mask != 0 {
                let bit = mask.trailing_zeros() as usize;
                let cand = i + bit;
                if cand <= limit && &hay[cand..cand + len] == needle {
                    out.push(cand);
                }
                mask &= mask - 1;
            }
            i += 32;
        }

        while i <= limit {
            if hay[i] == b0 && hay[i + k] == b1 && &hay[i..i + len] == needle {
                out.push(i);
            }
            i += 1;
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_pair_bits(needle: &[u8], k: usize, hay: &[u8], out: &mut BitMap) {
    let len = needle.len();
    let b0 = needle[0];
    let b1 = needle[k];
    let v0 = _mm256_set1_epi8(b0 as i8);
    let v1 = _mm256_set1_epi8(b1 as i8);
    let limit = hay.len() - len;
    let mut i = 0usize;
    let out_words = out.words_mut();

    if len == 2 {
        // 2-byte literals: every set bit IS a match. The inner chunk loop
        // walks 64 bytes per iteration with two 32-byte halves, ORed into
        // a single 64-bit word; the inner `if len == 2` branch and the
        // per-candidate compare collapse away at compile time.
        let mut word_idx = 0usize;
        while i + 64 + k <= hay.len() {
            let p0 = hay.as_ptr().add(i);
            let c0_0 = _mm256_loadu_si256(p0 as *const __m256i);
            let c1_0 = _mm256_loadu_si256(p0.add(k) as *const __m256i);
            let p1 = p0.add(32);
            let c0_1 = _mm256_loadu_si256(p1 as *const __m256i);
            let c1_1 = _mm256_loadu_si256(p1.add(k) as *const __m256i);

            let mask0 = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(c0_0, v0),
                _mm256_cmpeq_epi8(c1_0, v1),
            )) as u32;
            let mask1 = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(c0_1, v0),
                _mm256_cmpeq_epi8(c1_1, v1),
            )) as u32;
            let res = u64::from(mask0) | (u64::from(mask1) << 32);

            if res != 0 {
                out_words[word_idx] |= res;
            }
            i += 64;
            word_idx += 1;
        }

        while i + 32 + k <= hay.len() {
            let p0 = hay.as_ptr().add(i);
            let c0 = _mm256_loadu_si256(p0 as *const __m256i);
            let c1 = _mm256_loadu_si256(p0.add(k) as *const __m256i);
            let mask = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(c0, v0),
                _mm256_cmpeq_epi8(c1, v1),
            )) as u32;

            if mask != 0 {
                out.push32(i, mask);
            }
            i += 32;
        }

        while i <= limit {
            if hay[i] == b0 && hay[i + 1] == b1 {
                out.set(i);
            }
            i += 1;
        }
    } else {
        // 3+-byte literals: verify each candidate against the haystack;
        // 64-bit and 32-bit chunk loops below keep the `len == 2` branch
        // out of the inner code, and the outer branch above puts the hot
        // 2-byte case on its own path.
        while i + 64 + k <= hay.len() {
            let p0 = hay.as_ptr().add(i);
            let c0_0 = _mm256_loadu_si256(p0 as *const __m256i);
            let c1_0 = _mm256_loadu_si256(p0.add(k) as *const __m256i);
            let p1 = p0.add(32);
            let c0_1 = _mm256_loadu_si256(p1 as *const __m256i);
            let c1_1 = _mm256_loadu_si256(p1.add(k) as *const __m256i);

            let mask0 = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(c0_0, v0),
                _mm256_cmpeq_epi8(c1_0, v1),
            )) as u32;
            let mask1 = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(c0_1, v0),
                _mm256_cmpeq_epi8(c1_1, v1),
            )) as u32;

            if (mask0 | mask1) != 0 {
                let mut conf0 = 0u32;
                let mut m0 = mask0;
                while m0 != 0 {
                    let bit = m0.trailing_zeros() as usize;
                    let cand = i + bit;
                    if cand <= limit && &hay[cand..cand + len] == needle {
                        conf0 |= 1u32 << bit;
                    }
                    m0 &= m0 - 1;
                }

                let mut conf1 = 0u32;
                let mut m1 = mask1;
                while m1 != 0 {
                    let bit = m1.trailing_zeros() as usize;
                    let cand = i + 32 + bit;
                    if cand <= limit && &hay[cand..cand + len] == needle {
                        conf1 |= 1u32 << bit;
                    }
                    m1 &= m1 - 1;
                }

                let res = u64::from(conf0) | (u64::from(conf1) << 32);
                if res != 0 {
                    out.push64(i, res);
                }
            }
            i += 64;
        }

        while i + 32 + k <= hay.len() {
            let p0 = hay.as_ptr().add(i);
            let c0 = _mm256_loadu_si256(p0 as *const __m256i);
            let c1 = _mm256_loadu_si256(p0.add(k) as *const __m256i);
            let mut mask = _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_cmpeq_epi8(c0, v0),
                _mm256_cmpeq_epi8(c1, v1),
            )) as u32;

            if mask != 0 {
                let mut conf = 0u32;
                while mask != 0 {
                    let bit = mask.trailing_zeros() as usize;
                    let cand = i + bit;
                    if cand <= limit && &hay[cand..cand + len] == needle {
                        conf |= 1u32 << bit;
                    }
                    mask &= mask - 1;
                }
                if conf != 0 {
                    out.push32(i, conf);
                }
            }
            i += 32;
        }

        while i <= limit {
            if hay[i] == b0 && hay[i + k] == b1 && &hay[i..i + len] == needle {
                out.set(i);
            }
            i += 1;
        }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn neon_pair_offsets(needle: &[u8], k: usize, hay: &[u8], out: &mut Vec<usize>) {
    use core::arch::aarch64::*;
    let len = needle.len();
    let b0 = needle[0];
    let b1 = needle[k];
    let v0 = vdupq_n_u8(b0);
    let v1 = vdupq_n_u8(b1);
    let limit = hay.len() - len;
    let mut i = 0usize;

    while i + 16 + k <= hay.len() {
        let p0 = hay.as_ptr().add(i);
        let c0 = vld1q_u8(p0);
        let c1 = vld1q_u8(p0.add(k));
        let m = vandq_u8(vceqq_u8(c0, v0), vceqq_u8(c1, v1));
        if vmaxvq_u8(m) != 0 {
            for j in 0..16 {
                let cand = i + j;
                if cand <= limit
                    && hay[cand] == b0
                    && hay[cand + k] == b1
                    && (len == 2 || &hay[cand..cand + len] == needle)
                {
                    out.push(cand);
                }
            }
        }
        i += 16;
    }

    while i <= limit {
        if hay[i] == b0 && hay[i + k] == b1 && (len == 2 || &hay[i..i + len] == needle) {
            out.push(i);
        }
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn neon_pair_bits(needle: &[u8], k: usize, hay: &[u8], out: &mut BitMap) {
    use core::arch::aarch64::*;
    let len = needle.len();
    let b0 = needle[0];
    let b1 = needle[k];
    let v0 = vdupq_n_u8(b0);
    let v1 = vdupq_n_u8(b1);
    let limit = hay.len() - len;
    let mut i = 0usize;

    while i + 16 + k <= hay.len() {
        let p0 = hay.as_ptr().add(i);
        let c0 = vld1q_u8(p0);
        let c1 = vld1q_u8(p0.add(k));
        let m = vandq_u8(vceqq_u8(c0, v0), vceqq_u8(c1, v1));
        if vmaxvq_u8(m) != 0 {
            for j in 0..16 {
                let cand = i + j;
                if cand <= limit
                    && hay[cand] == b0
                    && hay[cand + k] == b1
                    && (len == 2 || &hay[cand..cand + len] == needle)
                {
                    out.set(cand);
                }
            }
        }
        i += 16;
    }

    while i <= limit {
        if hay[i] == b0 && hay[i + k] == b1 && (len == 2 || &hay[i..i + len] == needle) {
            out.set(i);
        }
        i += 1;
    }
}

// The oracle of the paired-byte paths, for the reason `scalar_count_byte`
// carries: it stays compiled on every target, and a build without the
// test harness calls nothing here.
#[allow(dead_code)]
fn scalar_pair_offsets(needle: &[u8], k: usize, hay: &[u8], out: &mut Vec<usize>) {
    let len = needle.len();
    let b0 = needle[0];
    let b1 = needle[k];
    let limit = hay.len() - len;
    if len == 2 {
        for i in 0..=limit {
            if hay[i] == b0 && hay[i + 1] == b1 {
                out.push(i);
            }
        }
    } else {
        for i in 0..=limit {
            if hay[i] == b0 && hay[i + k] == b1 && &hay[i..i + len] == needle {
                out.push(i);
            }
        }
    }
}

// The oracle of the paired-byte paths, for the reason `scalar_count_byte`
// carries: it stays compiled on every target, and a build without the
// test harness calls nothing here.
#[allow(dead_code)]
fn scalar_pair_bits(needle: &[u8], k: usize, hay: &[u8], out: &mut BitMap) {
    let len = needle.len();
    let b0 = needle[0];
    let b1 = needle[k];
    let limit = hay.len() - len;
    if len == 2 {
        for i in 0..=limit {
            if hay[i] == b0 && hay[i + 1] == b1 {
                out.set(i);
            }
        }
    } else {
        for i in 0..=limit {
            if hay[i] == b0 && hay[i + k] == b1 && &hay[i..i + len] == needle {
                out.set(i);
            }
        }
    }
}

/// The definition [`avx2_bits`] implements in vector form. The tests hold the
/// two to it on every input, and it is what runs when AVX2 is absent.
fn scalar_bits(needles: &[u8; 3], count: usize, hay: &[u8], out: &mut BitMap) {
    for (at, &b) in hay.iter().enumerate() {
        if needles[..count].contains(&b) {
            out.set(at);
        }
    }
}

/// A set of byte values, in the form the mask producer wants them.
///
/// 256 bits, one per byte value, and nothing else: the set is what a class
/// and a one-byte literal are both made of, and a producer that accepts
/// needles and refuses intervals is a producer that cannot say "a lowercase
/// letter" -- which is the set `(pub|fn) [a-z]+` is mostly made of.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ByteClass {
    words: [u64; 4],
}

impl ByteClass {
    /// The class of exactly `b`.
    #[must_use]
    pub fn single(b: u8) -> Self {
        let mut c = Self::default();
        c.insert(b);
        c
    }

    /// The class of no bytes at all, which matches nothing and is not the same
    /// answer as a class of every byte.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The class of every byte.
    #[must_use]
    pub fn any() -> Self {
        Self {
            words: [u64::MAX; 4],
        }
    }

    /// The class of every byte except `b`.
    #[must_use]
    pub fn any_except(b: u8) -> Self {
        let mut c = Self::any();
        c.remove(b);
        c
    }

    /// Add `b`.
    pub fn insert(&mut self, b: u8) {
        self.words[usize::from(b >> 6)] |= 1u64 << (b & 63);
    }

    /// Drop `b`.
    pub fn remove(&mut self, b: u8) {
        self.words[usize::from(b >> 6)] &= !(1u64 << (b & 63));
    }

    /// Whether `b` is a member.
    #[inline]
    pub fn contains(&self, b: u8) -> bool {
        (self.words[usize::from(b >> 6)] & (1u64 << (b & 63))) != 0
    }

    /// Whether the class is a single byte, and which.
    #[must_use]
    pub fn sole(&self) -> Option<u8> {
        let mut found = None;
        for (i, &w) in self.words.iter().enumerate() {
            let mut w = w;
            while w != 0 {
                if found.is_some() {
                    return None;
                }
                found = Some((i as u8) * 64 + w.trailing_zeros() as u8);
                w &= w - 1;
            }
        }
        found
    }

    /// How many bytes the class accepts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Whether the class accepts nothing, which would make every AND through
    /// it zero and the mask a prefilter that filters everything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    /// Union of two classes.
    #[must_use]
    pub fn union(mut self, other: &Self) -> Self {
        for (a, b) in self.words.iter_mut().zip(&other.words) {
            *a |= *b;
        }
        self
    }

    /// The two `pshufb` lookup tables, as `[lo, hi]`, or `None` if the class
    /// cannot be partitioned into 8 or fewer distinct low-nibble masks.
    ///
    /// Each distinct non-empty low-nibble mask across the 16 high nibbles is
    /// assigned a unique bit in `0..8`. High nibble `h` sets this bit in
    /// `hi[h]`, and each member low nibble `l` sets this bit in `lo[l]`.
    /// Then `lo[l] & hi[h] != 0` is true if and only if `(h << 4) | l` is
    /// strictly a member of the class, eliminating false positives from the
    /// Cartesian product of high and low nibbles.
    #[must_use]
    pub fn tables(&self) -> Option<[[u8; 32]; 2]> {
        let (mut lo, mut hi) = ([0u8; 16], [0u8; 16]);
        let mut distinct_masks = [0u16; 8];
        let mut num_distinct = 0usize;

        for (h, hi_slot) in hi.iter_mut().enumerate() {
            let mut l_mask = 0u16;
            for l in 0..16usize {
                if self.contains((h * 16 + l) as u8) {
                    l_mask |= 1 << l;
                }
            }
            if l_mask == 0 {
                continue;
            }
            let bit_idx = if let Some(pos) = distinct_masks[..num_distinct]
                .iter()
                .position(|&m| m == l_mask)
            {
                pos
            } else {
                if num_distinct >= 8 {
                    return None;
                }
                distinct_masks[num_distinct] = l_mask;
                let idx = num_distinct;
                num_distinct += 1;
                idx
            };
            let bit = 1u8 << bit_idx;
            *hi_slot |= bit;
            for (l, lo_slot) in lo.iter_mut().enumerate() {
                if (l_mask & (1 << l)) != 0 {
                    *lo_slot |= bit;
                }
            }
        }

        let mut out = [[0u8; 32]; 2];
        out[0][..16].copy_from_slice(&lo);
        out[0][16..].copy_from_slice(&lo);
        out[1][..16].copy_from_slice(&hi);
        out[1][16..].copy_from_slice(&hi);
        Some(out)
    }
}

/// The most distinct byte classes one [`MatchMask`] will hold.
///
/// Sixteen is a register budget, not a taste: the fill keeps one `pshufb`
/// table pair per class live in a `__m256i` and there are sixteen of those.
/// A pattern that needs more falls back to the scalar producer, which is the
/// definition rather than an approximation of it, so the cap can only cost
/// speed.
pub const MAX_MASK_CLASSES: usize = 16;

/// The most AND terms one [`MatchMask`] will hold, over every branch.
///
/// The terms are extracted once per 64 bytes and held in a `u64` each, so the
/// cap is how many will sit in L1 beside the accumulator without a reload in
/// the inner loop. The same fallback applies.
pub const MAX_MASK_TERMS: usize = 24;

/// The most branches one [`MatchMask`] will hold.
pub const MAX_MASK_BRANCHES: usize = 8;

/// One AND term: this class, this many bytes after the start of a match.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MaskTerm {
    /// The class the byte at `shift` has to be a member of.
    pub class: ByteClass,
    /// How far past the start of the match the byte sits.
    pub shift: usize,
}

/// One way a match can start: every term holds, at its own offset.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MaskBranch {
    /// The terms, in any order. Two branches with the same terms are one
    /// branch, and the constructor merges them.
    pub terms: Vec<MaskTerm>,
}

/// The set of offsets where a match can start, as an AND of shifted byte
/// classes.
///
/// **The shape.** A pattern's required bytes are the AND of one byte-class
/// test per position, and a bitmap is one bit per byte, so the AND is a
/// word-level operation over data already in L1 rather than a call per
/// candidate:
///
/// ```text
///   M_pub = P & (U>>1) & (B>>2) & (S>>3) & (L>>4)
///   M_fn  = F & (N>>1) & (S>>2) & (L>>3)
///   M     = M_pub | M_fn
/// ```
///
/// The shift is not a shift in the emitted code. A term at `shift` is
/// evaluated by *loading* the haystack `shift` bytes further along, so lane `m`
/// of that load is byte `base + shift + m` and already sits where the answer
/// belongs; a `u64 >> shift` would move it twice.
///
/// **What a set bit means.** Whatever the caller built it from. A mask built
/// from terms that are *necessary* is a prefilter and its set bits are
/// candidates; a mask built from a branch set that is also *sufficient* --
/// the pattern lowered to exactly those bytes and no other way to start --
/// has set bits that are matches, and the searcher can then answer a line
/// without calling the engine at all. The two are the same object and the
/// difference is a claim about the pattern, so it is carried as
/// [`Self::decides`] rather than inferred by the consumer.
///
/// **Why the OR over branches.** `(pub|fn) [a-z]+` is two ways to start, and
/// an AND cannot express a choice. Each branch is one way, and the union of
/// the branches' sets is the pattern's set of starts. Branches with the same
/// shape are merged by unioning their classes, because `AND` distributes over
/// `OR` — which is what turns `a|b|c` from three branches into one class.
///
/// **Why a flat list and not indices into a shared term table.** The first
/// version of the fill extracted every term of every branch into a `u64` each
/// and then ANDed them per branch, which needs the branch's list to say WHICH
/// term — a `u16` load and then a dependent `u64` load, per term, with the AND
/// chain waiting on the second. Seven terms of that measured 5.6 GB/s against
/// 16 for the same work written as one pass. Sharing a term between two
/// branches saves one extraction and costs the indirection on all of them, and
/// `(pub|fn) [a-z]+` shared nothing anyway: its two branches read the space
/// and the letter class at *different* offsets, so no `(class, offset)` pair
/// ever repeated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Op {
    /// How far past the start of the block to read.
    shift: u8,
    /// The class to test, or [`Op::SINGLE`] for the `byte` below.
    class: u8,
    /// The byte, when `class` is [`Op::SINGLE`].
    byte: u8,
}

impl Op {
    /// The marker in [`Self::class`] for a one-byte test.
    const SINGLE: u8 = 0xFF;
}

/// One branch: a run of [`Op`]s, and where the single-byte ones stop.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Branch {
    start: u32,
    /// How many of this branch's `len` ops name a single byte. They come
    /// first, so the fill is two straight loops rather than a branch per op.
    split: u8,
    len: u8,
}

#[derive(Clone, Debug)]
pub struct MatchMask {
    /// The distinct classes that need a `pshufb` pair each.
    classes: Vec<ByteClass>,
    /// Two 32-byte broadcast tables per class, flattened.
    tables: Vec<[u8; 32]>,
    /// Every branch's ops, concatenated.
    ops: Vec<Op>,
    branches: Vec<Branch>,
    /// The offset of the last byte a term reads, plus one: the span past a
    /// block the reads reach.
    width: usize,
    /// Whether a set bit is a match rather than a candidate.
    decides: bool,
    /// How many bytes of a line a match has to have left for a bit in it to be
    /// a match OF THAT LINE. See [`Self::line_cut`].
    line_cut: Option<usize>,
}

/// The width a consumer must leave at the end of a line for a bit in it to
/// settle the line, or `None` when this mask's shape does not allow one.
///
/// **This is the arithmetic that makes a mask answer for a line instead of
/// being confirmed against one, and it is per BRANCH while the consumer gets
/// one number.** The fill has one bit per offset and cannot say which branch
/// set it, so the consumer has to cut far enough that every branch still fits
/// and not so far that a branch that does fit is dropped:
/// `(pub|fn) [a-z]+`'s two branches want a cut at five (`pub ` and a letter)
/// and at four (`fn ` and a letter), a cut at five drops every `fn x` that
/// ends a line, and a cut at four lets a five-byte branch's bit through on a
/// three-byte line.
///
/// **The four is right here, and the reason is what a bit at `content_end - 4`
/// is.** With the cut at four the only lines still in question carry bits in
/// their last four bytes, and every one of those bits has to have been set by
/// a branch reading at least one byte PAST the line -- which is where this
/// mask says no. Every branch is gap-free (`fn ` names offsets 0, 1, 2, 3),
/// so for an offset `o` in the disputed band the branch has a term exactly at
/// shift `e - o`, and that term reads `buf[e]`, which is the LINE TERMINATOR.
/// A class that accepts the terminator would let the bit through; `[a-z]`,
/// `f`, `n` and the space all reject it, so no branch can have set such a bit
/// and every bit the consumer keeps is a branch that fits inside the line.
///
/// **So the condition is checked, not assumed**, and a mask that fails it
/// gets `None` and takes the confirm it takes today:
///
/// - every branch names a term at EVERY offset `0..len` -- a gap would leave a
///   shift with no term to land on the terminator, and the bit could then be
///   set by bytes of the NEXT line with nothing to reject it;
/// - no class contains `b'\n'`, for the same reason.
///
/// The answer is the NARROWEST branch, because that is the one whose bits the
/// others can be mistaken for, and `decides` has to be set as well: the claim
/// is that a bit is a match, and only a deciding mask has claimed it.
///
/// `b'\n'` is the line terminator of every search this crate runs;
/// [`super::searcher::LineTerminator`] has no other value.
fn line_cut(branches: &[Vec<(usize, ByteClass)>], decides: bool) -> Option<usize> {
    if !decides || branches.is_empty() {
        return None;
    }
    let mut narrowest = usize::MAX;
    for v in branches {
        for (want, (shift, class)) in v.iter().enumerate() {
            if *shift != want || class.contains(b'\n') {
                return None;
            }
        }
        narrowest = core::cmp::min(narrowest, v.len());
    }
    Some(narrowest)
}

impl MatchMask {
    /// Build a mask from `branches`, or `None` when the shape is out of
    /// budget or a class is empty.
    ///
    /// **An empty class is refused rather than carried.** A term nothing can
    /// satisfy is a mask that matches nothing, and a mask that matches
    /// nothing is a prefilter that drops every match. The caller that built
    /// one has a bug, and refusing here is what keeps that bug from reaching a
    /// line count.
    ///
    /// **Two terms at one offset are refused for the same reason.** A match
    /// has exactly one byte at an offset, so two requirements there are a
    /// contradiction, not a union -- and a contradiction ANDed into the mask
    /// is a mask that matches nothing.
    ///
    /// **A one-byte class becomes a `cmpeq`, not a `pshufb` pair.** See
    /// `Op`: the two-lookup form costs one `vpshufb` per 32 bytes and this
    /// machine retires one per cycle, while a single byte is one `vpcmpeqb`
    /// out of four. `(pub|fn) [a-z]+` is six one-byte terms against one
    /// class, so the split is most of the fill.
    #[must_use]
    pub fn new(branches: Vec<MaskBranch>, decides: bool) -> Option<Self> {
        if branches.is_empty() || branches.len() > MAX_MASK_BRANCHES {
            return None;
        }
        // Each branch as an offset-sorted `(offset, class)` list, which is the
        // only form the merge and the fill need.
        let mut ordered: Vec<Vec<(usize, ByteClass)>> = Vec::with_capacity(branches.len());
        for b in &branches {
            let mut v: Vec<(usize, ByteClass)> =
                b.terms.iter().map(|t| (t.shift, t.class)).collect();
            if v.iter().any(|(s, c)| c.is_empty() || *s > u8::MAX as usize) {
                return None;
            }
            v.sort_unstable_by_key(|(s, _)| *s);
            if v.windows(2).any(|w| w[0].0 == w[1].0) {
                return None;
            }
            ordered.push(v);
        }
        // Merge branches that ask for the same bytes at the same offsets.
        // `a|b|c` is three branches of one offset and becomes one class; the
        // merge is the distributive law, and it is the reason an alternation of
        // one-byte literals costs one class rather than three.
        let mut merged: Vec<Vec<(usize, ByteClass)>> = Vec::new();
        for v in ordered {
            match merged
                .iter_mut()
                .find(|m| m.len() == v.len() && m.iter().zip(&v).all(|(a, b)| a.0 == b.0))
            {
                Some(m) => {
                    for (a, (_, b)) in m.iter_mut().zip(&v) {
                        a.1 = a.1.union(b);
                    }
                }
                None => merged.push(v),
            }
        }
        let mut mask = Self {
            classes: Vec::new(),
            tables: Vec::new(),
            ops: Vec::new(),
            branches: Vec::with_capacity(merged.len()),
            width: 0,
            decides,
            line_cut: line_cut(&merged, decides),
        };
        for v in &merged {
            if mask.ops.len() + v.len() > MAX_MASK_TERMS {
                return None;
            }
            let start = mask.ops.len() as u32;
            // The single-byte terms first, so the fill walks them as one run
            // and the class terms as another, with no branch per op.
            let mut split = 0u8;
            for want_single in [true, false] {
                for (shift, class) in v {
                    let sole = class.sole();
                    if sole.is_some() != want_single {
                        continue;
                    }
                    let op = match sole {
                        Some(b) => Op {
                            shift: *shift as u8,
                            class: Op::SINGLE,
                            byte: b,
                        },
                        None => {
                            let ci = match mask.classes.iter().position(|k| k == class) {
                                Some(i) => i,
                                None => {
                                    if mask.classes.len() >= MAX_MASK_CLASSES {
                                        return None;
                                    }
                                    let tables = class.tables()?;
                                    mask.classes.push(*class);
                                    mask.tables.extend_from_slice(&tables);
                                    mask.classes.len() - 1
                                }
                            };
                            Op {
                                shift: *shift as u8,
                                class: u8::try_from(ci).ok()?,
                                byte: 0,
                            }
                        }
                    };
                    if want_single {
                        split += 1;
                    }
                    mask.ops.push(op);
                    mask.width = core::cmp::max(mask.width, shift + 1);
                }
            }
            let len = mask.ops.len() - start as usize;
            mask.branches.push(Branch {
                start,
                split,
                len: u8::try_from(len).ok()?,
            });
        }
        Some(mask)
    }

    /// The branches as `(offset, class)` pairs, for a caller that wants to
    /// describe the mask rather than run it. Test and reporting only: the fill
    /// reads the packed form.
    #[must_use]
    pub fn branches(&self) -> Vec<Vec<(usize, ByteClass)>> {
        self.branches
            .iter()
            .map(|b| {
                self.ops[b.start as usize..b.start as usize + b.len as usize]
                    .iter()
                    .map(|o| {
                        let c = if o.class == Op::SINGLE {
                            ByteClass::single(o.byte)
                        } else {
                            self.classes[usize::from(o.class)]
                        };
                        (o.shift as usize, c)
                    })
                    .collect()
            })
            .collect()
    }

    /// The offset of the last byte a term reads, plus one.
    ///
    /// **This is a property of the FILL and not of a line.** It is how far
    /// past a block the reads reach, which is what bounds the vector loop, and
    /// it is the WIDEST branch: a consumer deciding a LINE wants
    /// [`Self::line_cut`], which is the narrowest branch and a different
    /// number whenever a mask's branches disagree.
    #[must_use]
    pub fn width(&self) -> usize {
        self.width
    }

    /// The bytes a consumer must leave at the end of a line for a bit inside
    /// it to be a match OF THAT LINE, or `None` when this mask cannot say.
    ///
    /// **`None` is the whole of the previous behaviour** and is always
    /// correct: the consumer asks the matcher, and the matcher re-runs the
    /// mask against the line's own bytes. `Some(w)` replaces that question
    /// with a range check, and the claim it makes is exactly:
    ///
    /// ```text
    ///   a line [s, e) matches  <=>  a bit is set at some o in [s, e - w]
    /// ```
    ///
    /// so a line shorter than `w` cannot match, a bit at exactly `e - w` does
    /// match -- the window fits whole -- and a bit past it does not, whatever
    /// bytes are there. [`Self::width`] is NOT that number: it is the widest
    /// branch, which is what the FILL needs to know how far past a block its
    /// reads reach, and using it as a cut drops `fn x` at the end of a line.
    /// See the module's `line_cut` for why the narrowest branch is the answer.
    #[must_use]
    pub fn line_cut(&self) -> Option<usize> {
        self.line_cut
    }

    /// How many terms the fill extracts per 64 bytes, over every branch.
    #[must_use]
    pub fn term_count(&self) -> usize {
        self.ops.len()
    }

    /// Whether a set bit is a match rather than a candidate. See the type.
    #[must_use]
    pub fn decides(&self) -> bool {
        self.decides
    }

    /// Whether a match can start at `at`. The definition every vector path in
    /// this file implements in another shape.
    #[must_use]
    pub fn holds(&self, hay: &[u8], at: usize) -> bool {
        self.branches.iter().any(|b| {
            self.ops[b.start as usize..b.start as usize + b.len as usize]
                .iter()
                .all(|o| {
                    hay.get(at + o.shift as usize).is_some_and(|&x| {
                        if o.class == Op::SINGLE {
                            x == o.byte
                        } else {
                            self.classes[usize::from(o.class)].contains(x)
                        }
                    })
                })
        })
    }

    /// Fill `out` with a bit at every offset of `hay` where a match can start.
    pub fn match_bits(&self, hay: &[u8], out: &mut BitMap) {
        #[cfg(target_arch = "x86_64")]
        {
            if crate::detect::avx512bw() {
                // SAFETY: guarded by the runtime feature check above.
                unsafe { avx512_match_bits(self, hay, out) };
                return;
            }
            if crate::detect::avx2() {
                // SAFETY: guarded by the runtime feature check above, which is
                // `avx2_match_bits`'s documented precondition.
                unsafe { avx2_match_bits(self, hay, out) };
                return;
            }
        }
        scalar_match_bits(self, hay, out);
    }
}

/// The definition [`avx2_match_bits`] implements in vector form, and what runs
/// when AVX2 is absent. One byte at a time, because a reference which cannot
/// be measured is not a reference.
fn scalar_match_bits(plan: &MatchMask, hay: &[u8], out: &mut BitMap) {
    out.clear(hay.len());
    for at in 0..hay.len() {
        if plan.holds(hay, at) {
            out.set(at);
        }
    }
}

/// The vector fill: 64 bytes per iteration, one `pshufb` pair per term, the
/// `movemask`es ANDed per branch and ORed together, one `u64` stored.
///
/// **Why 64 and not 32.** A term at offset `shift` is read by LOADING the
/// haystack `shift` bytes on, so lane `m` of that load is byte
/// `base + shift + m` and is already at the position the answer belongs to --
/// there is no shift in the emitted code, and a `u64 >> shift` would move the
/// bit twice. A 32-byte block would have to be stitched across blocks to cover
/// the 31 positions a shifted term reaches back over; a `u64` per 64 bytes
/// covers all 64 with one load pair per term and one store.
///
/// **The tail is the scalar definition.** The last `width + 62` bytes of a
/// buffer have no whole block behind them, and that is a hundred bytes once per
/// 64 KiB fill, which is not worth a second specialisation.
///
/// # Safety
///
/// The caller must have established that the CPU supports AVX2.
/// The vector fill for AVX-512BW: 64 bytes per iteration directly into a 64-bit mask.
/// Single-byte ops evaluate in a single `_mm512_cmpeq_epi8_mask` instruction, short-circuiting
/// branch evaluation immediately when the accumulator is zero.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,avx512bw")]
unsafe fn avx512_match_bits(plan: &MatchMask, hay: &[u8], out: &mut BitMap) {
    out.clear(hay.len());
    if plan.ops.is_empty() || hay.is_empty() {
        return;
    }
    let k0f = _mm256_set1_epi8(0x0F);
    let zero = _mm256_setzero_si256();
    let mut tables = [(_mm256_setzero_si256(), _mm256_setzero_si256()); MAX_MASK_CLASSES];
    for op in &plan.ops {
        if op.class == Op::SINGLE {
            continue;
        }
        let ci = usize::from(op.class);
        tables[ci] = (
            broadcast(&plan.tables[2 * ci]),
            broadcast(&plan.tables[2 * ci + 1]),
        );
    }
    let mut single_vecs = [_mm512_setzero_si512(); MAX_MASK_TERMS];
    for (i, op) in plan.ops.iter().enumerate() {
        if op.class == Op::SINGLE {
            single_vecs[i] = _mm512_set1_epi8(op.byte as i8);
        }
    }
    let mut base = 0usize;
    while base + 63 + plan.width <= hay.len() {
        let mut res: u64 = 0;
        for b in &plan.branches {
            let ops = &plan.ops[b.start as usize..b.start as usize + b.len as usize];
            let mut acc: u64 = !0u64;

            for (idx, o) in ops[..b.split as usize].iter().enumerate() {
                let p = hay.as_ptr().add(base + o.shift as usize);
                let v = single_vecs[b.start as usize + idx];
                let a = _mm512_loadu_si512(p as *const _);
                let eq = _mm512_cmpeq_epi8_mask(a, v);
                if idx == 0 {
                    acc = eq;
                } else {
                    acc &= eq;
                }
                if acc == 0 {
                    break;
                }
            }

            if acc != 0 && (b.split as usize) < ops.len() {
                let mut acc_lo = _mm256_set1_epi8(-1);
                let mut acc_hi = _mm256_set1_epi8(-1);
                for (c_idx, o) in ops[b.split as usize..].iter().enumerate() {
                    let p = hay.as_ptr().add(base + o.shift as usize);
                    let (tl, th) = tables[usize::from(o.class)];
                    let a = _mm256_loadu_si256(p as *const __m256i);
                    let b2 = _mm256_loadu_si256(p.add(32) as *const __m256i);
                    let m_a = lookup(a, tl, th, k0f);
                    let m_b = lookup(b2, tl, th, k0f);
                    acc_lo = _mm256_andnot_si256(_mm256_cmpeq_epi8(m_a, zero), acc_lo);
                    acc_hi = _mm256_andnot_si256(_mm256_cmpeq_epi8(m_b, zero), acc_hi);
                    if c_idx + 1 < ops.len() - (b.split as usize) {
                        let or_acc = _mm256_or_si256(acc_lo, acc_hi);
                        if _mm256_testz_si256(or_acc, or_acc) == 1 {
                            acc = 0;
                            break;
                        }
                    }
                }
                if acc != 0 {
                    let class_mask = lanes(acc_lo) | (lanes(acc_hi) << 32);
                    acc &= class_mask;
                }
            }

            res |= acc;
        }
        if res != 0 {
            out.push64(base, res);
        }
        base += 64;
    }
    for at in base..hay.len() {
        if plan.holds(hay, at) {
            out.set(at);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_match_bits(plan: &MatchMask, hay: &[u8], out: &mut BitMap) {
    out.clear(hay.len());
    if plan.ops.is_empty() || hay.is_empty() {
        return;
    }
    let k0f = _mm256_set1_epi8(0x0F);
    let zero = _mm256_setzero_si256();
    // Only the classes a GENERAL op names need a table, and a pattern with no
    // general op at all -- `pub fn`, `let mut` -- pays nothing for them.
    let mut tables = [(_mm256_setzero_si256(), _mm256_setzero_si256()); MAX_MASK_CLASSES];
    for op in &plan.ops {
        if op.class == Op::SINGLE {
            continue;
        }
        let ci = usize::from(op.class);
        tables[ci] = (
            broadcast(&plan.tables[2 * ci]),
            broadcast(&plan.tables[2 * ci + 1]),
        );
    }
    let mut single_vecs = [_mm256_setzero_si256(); MAX_MASK_TERMS];
    for (i, op) in plan.ops.iter().enumerate() {
        if op.class == Op::SINGLE {
            single_vecs[i] = _mm256_set1_epi8(op.byte as i8);
        }
    }
    let mut base = 0usize;
    // The highest byte any read touches is `base + shift + 63` for the largest
    // shift, `width - 1`, so this is the condition under which both loads of
    // every op are inside the haystack.
    while base + 63 + plan.width <= hay.len() {
        let mut res_lo = _mm256_setzero_si256();
        let mut res_hi = _mm256_setzero_si256();
        for b in &plan.branches {
            let ops = &plan.ops[b.start as usize..b.start as usize + b.len as usize];
            let mut acc_lo = _mm256_set1_epi8(-1);
            let mut acc_hi = _mm256_set1_epi8(-1);
            let mut dead = false;

            // The single-byte ops: one `cmpeq` against a broadcast, where a
            // class costs a `pshufb` pair and this machine retires one
            // `vpshufb` to four `vpcmpeqb`.
            for (idx, o) in ops[..b.split as usize].iter().enumerate() {
                // SAFETY: `base + o.shift + 63 < hay.len()` is the loop
                // condition and `o.shift <= width - 1`.
                let p = unsafe { hay.as_ptr().add(base + o.shift as usize) };
                let v = single_vecs[b.start as usize + idx];
                // SAFETY: as above.
                let a = unsafe { _mm256_loadu_si256(p as *const __m256i) };
                // SAFETY: as above.
                let b2 = unsafe { _mm256_loadu_si256(p.add(32) as *const __m256i) };
                let eq_lo = _mm256_cmpeq_epi8(a, v);
                let eq_hi = _mm256_cmpeq_epi8(b2, v);
                if idx == 0 {
                    acc_lo = eq_lo;
                    acc_hi = eq_hi;
                } else {
                    acc_lo = _mm256_and_si256(acc_lo, eq_lo);
                    acc_hi = _mm256_and_si256(acc_hi, eq_hi);
                }
                if idx + 1 < b.split as usize {
                    let or_acc = _mm256_or_si256(acc_lo, acc_hi);
                    if _mm256_testz_si256(or_acc, or_acc) == 1 {
                        dead = true;
                        break;
                    }
                }
            }

            // If the accumulator is already zero, skip the expensive class ops.
            if !dead && (b.split as usize) < ops.len() {
                let or_acc = _mm256_or_si256(acc_lo, acc_hi);
                if _mm256_testz_si256(or_acc, or_acc) == 1 {
                    dead = true;
                }
            }

            if !dead {
                // Then the class ops, which need the nibble pair.
                for (c_idx, o) in ops[b.split as usize..].iter().enumerate() {
                    // SAFETY: as above.
                    let p = unsafe { hay.as_ptr().add(base + o.shift as usize) };
                    let (tl, th) = tables[usize::from(o.class)];
                    // SAFETY: as above.
                    let a = unsafe { _mm256_loadu_si256(p as *const __m256i) };
                    // SAFETY: as above.
                    let b2 = unsafe { _mm256_loadu_si256(p.add(32) as *const __m256i) };
                    let m_a = lookup(a, tl, th, k0f);
                    let m_b = lookup(b2, tl, th, k0f);
                    acc_lo = _mm256_andnot_si256(_mm256_cmpeq_epi8(m_a, zero), acc_lo);
                    acc_hi = _mm256_andnot_si256(_mm256_cmpeq_epi8(m_b, zero), acc_hi);
                    if c_idx + 1 < ops.len() - (b.split as usize) {
                        let or_acc = _mm256_or_si256(acc_lo, acc_hi);
                        if _mm256_testz_si256(or_acc, or_acc) == 1 {
                            dead = true;
                            break;
                        }
                    }
                }
                if !dead {
                    res_lo = _mm256_or_si256(res_lo, acc_lo);
                    res_hi = _mm256_or_si256(res_hi, acc_hi);
                }
            }
        }
        let res = lanes(res_lo) | (lanes(res_hi) << 32);
        if res != 0 {
            out.push64(base, res);
        }
        base += 64;
    }
    for at in base..hay.len() {
        if plan.holds(hay, at) {
            out.set(at);
        }
    }
}

/// Broadcast one 16-byte table into both `pshufb` lanes.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
fn broadcast(src: &[u8; 32]) -> __m256i {
    // Both lanes carry the same table because `pshufb` is lane-local: the
    // high lane of a haystack chunk must index the same table, not zeroes.
    // SAFETY: `src` is a whole `[u8; 32]`, so the 16-byte load is in bounds.
    unsafe { _mm256_broadcastsi128_si256(_mm_loadu_si128(src.as_ptr() as *const __m128i)) }
}

/// The two `pshufb` lookups and their AND, with bit 7 set per member byte.
///
/// `pshufb` indexes its table with the low four bits of each byte and zeroes
/// the lane if bit 7 is set, so masking the index to `0x0F` is what keeps the
/// lookup defined for a byte above `0x8F`. The attribute is what makes the
/// intrinsics callable without an `unsafe` block: the caller of *this*
/// function has already established AVX2 and `#[target_feature]` carries that
/// into the body.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
fn lookup(v: __m256i, tl: __m256i, th: __m256i, k0f: __m256i) -> __m256i {
    let lo = _mm256_and_si256(v, k0f);
    let hi = _mm256_and_si256(_mm256_srli_epi16(v, 4), k0f);
    _mm256_and_si256(_mm256_shuffle_epi8(tl, lo), _mm256_shuffle_epi8(th, hi))
}

/// One 32-byte lane set as the low 32 bits of a `u64`, a set bit for every
/// byte whose sign bit came out of [`lookup`].
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
fn lanes(v: __m256i) -> u64 {
    u64::from(_mm256_movemask_epi8(v) as u32)
}

#[cfg(test)]
mod mask_tests {
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::{BitMap, ByteClass, MaskBranch, MaskTerm, MatchMask, MAX_MASK_TERMS};
    // The scalar definition is the oracle the vector path is held against, and
    // that comparison only exists on x86_64 -- so the *import* is gated with
    // the test that uses it and not with the function, which is compiled on
    // every target because it is also the fallback when AVX2 is absent.
    #[cfg(target_arch = "x86_64")]
    use super::scalar_match_bits;

    /// The offsets a map reports, which is a bitmap's whole contract.
    fn offsets(m: &BitMap) -> Vec<usize> {
        let mut out = Vec::new();
        m.append_offsets(&mut out);
        out
    }

    /// Every offset where the definition says a match can start.
    fn want(plan: &MatchMask, hay: &[u8]) -> Vec<usize> {
        (0..hay.len()).filter(|&i| plan.holds(hay, i)).collect()
    }

    fn cls(spec: &[u8]) -> ByteClass {
        let mut c = ByteClass::empty();
        for &b in spec {
            c.insert(b);
        }
        c
    }

    fn lower() -> ByteClass {
        cls(b"abcdefghijklmnopqrstuvwxyz")
    }

    /// The mask `benchmark/status.md` §4 item 1 spells out, term for term.
    fn pub_fn_branches() -> Vec<MaskBranch> {
        vec![
            MaskBranch {
                terms: vec![
                    MaskTerm {
                        class: cls(b"p"),
                        shift: 0,
                    },
                    MaskTerm {
                        class: cls(b"u"),
                        shift: 1,
                    },
                    MaskTerm {
                        class: cls(b"b"),
                        shift: 2,
                    },
                    MaskTerm {
                        class: cls(b" "),
                        shift: 3,
                    },
                    MaskTerm {
                        class: lower(),
                        shift: 4,
                    },
                ],
            },
            MaskBranch {
                terms: vec![
                    MaskTerm {
                        class: cls(b"f"),
                        shift: 0,
                    },
                    MaskTerm {
                        class: cls(b"n"),
                        shift: 1,
                    },
                    MaskTerm {
                        class: cls(b" "),
                        shift: 2,
                    },
                    MaskTerm {
                        class: lower(),
                        shift: 3,
                    },
                ],
            },
        ]
    }

    /// The mask `benchmark/status.md` §4 item 1 spells out, term for term.
    fn pub_fn_mask() -> MatchMask {
        MatchMask::new(pub_fn_branches(), true).expect("builds")
    }
    /// The high-byte fill must set exactly the bits the byte definition sets,
    /// at every length with a high byte at every position: the chunk
    /// boundaries and the word merges are where a bit goes missing or lands
    /// on the wrong offset, and a lost bit hands a non-ASCII line to the
    /// settle that the delegate owns.
    #[test]
    fn the_high_byte_fill_agrees_with_a_byte_test_at_every_length() {
        let mut lens: Vec<usize> = (0..130).collect();
        lens.extend([255, 256, 257, 511, 512, 513, 1023, 1024, 1025]);
        for len in lens {
            let mut hay = alloc::vec![b'a'; len];
            let mut out = BitMap::new();
            super::high_bits(&hay, &mut out);
            assert_eq!(out.count_set(0, len), 0, "clean len {len}");
            for at in 0..len {
                hay[at] = 0xC3;
                super::high_bits(&hay, &mut out);
                assert_eq!(out.count_set(0, len), 1, "one high byte at {at}/{len}");
                assert!(out.any_set(at, at + 1), "bit at {at}/{len}");
                assert!(!out.any_set(0, at), "no bit before {at}/{len}");
                hay[at] = b'a';
            }
        }
        // A dense fill of only high bytes, to exercise every merge.
        let hay: Vec<u8> = alloc::vec![0xFF; 300];
        let mut out = BitMap::new();
        super::high_bits(&hay, &mut out);
        assert_eq!(out.count_set(0, 300), 300, "dense high bytes");
    }
    /// The fused fill must set exactly the bits the two separate fills set,
    /// at every length with the term and a high byte at every position: it
    /// writes two maps from one load, and a mirrored or shifted bit there
    /// sends every line down the window walk (measured: +80 ms on `e.`).
    #[test]
    fn the_fused_fill_agrees_with_the_two_separate_fills() {
        let mut lens: Vec<usize> = (0..130).collect();
        lens.extend([255, 256, 257, 511, 512, 513, 1023, 1024, 1025]);
        for len in lens {
            for &term in b"a\nz" {
                let mut hay = alloc::vec![b'a'; len];
                // Term bytes and high bytes sprinkled at the edges of the
                // word and lane boundaries the kernels special-case.
                for at in [0usize, 1, 31, 32, 63, 64, 95, 96] {
                    if at < len {
                        hay[at] = 0xC3;
                    }
                }
                let (mut t1, mut h1) = (BitMap::new(), BitMap::new());
                let (mut t2, mut h2) = (BitMap::new(), BitMap::new());
                super::term_high_bits(term, &hay, &mut t1, &mut h1);
                super::term_bits(term, &hay, &mut t2);
                super::high_bits(&hay, &mut h2);
                for at in 0..len {
                    assert_eq!(
                        t1.any_set(at, at + 1),
                        t2.any_set(at, at + 1),
                        "term bit at {at}/{len} differs (term {term:#x})"
                    );
                    assert_eq!(
                        h1.any_set(at, at + 1),
                        h2.any_set(at, at + 1),
                        "high bit at {at}/{len} differs"
                    );
                }
            }
        }
    }

    /// The vector fill must set exactly the bits the definition sets, at every
    /// length around every 64-byte boundary. A bit lost in `push64`'s
    /// alignment is a MISSED MATCH and one set wrongly is a wrong line, so the
    /// grid is dense AND sparse and both are compared against the definition.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_vector_fill_agrees_with_the_definition_at_every_length() {
        if !crate::detect::avx2() {
            return;
        }
        let mut lens: Vec<usize> = (0..200).collect();
        lens.extend([255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 4096]);
        let mut plans: Vec<(&str, MatchMask)> = vec![("(pub|fn) [a-z]+", pub_fn_mask())];
        plans.push((
            "e[0-9]",
            MatchMask::new(
                vec![MaskBranch {
                    terms: vec![
                        MaskTerm {
                            class: cls(b"e"),
                            shift: 0,
                        },
                        MaskTerm {
                            class: cls(b"0123456789"),
                            shift: 1,
                        },
                    ],
                }],
                true,
            )
            .expect("builds"),
        ));
        plans.push((
            "a|b|c",
            MatchMask::new(
                vec![
                    MaskBranch {
                        terms: vec![MaskTerm {
                            class: cls(b"a"),
                            shift: 0,
                        }],
                    },
                    MaskBranch {
                        terms: vec![MaskTerm {
                            class: cls(b"b"),
                            shift: 0,
                        }],
                    },
                    MaskBranch {
                        terms: vec![MaskTerm {
                            class: cls(b"c"),
                            shift: 0,
                        }],
                    },
                ],
                true,
            )
            .expect("builds"),
        ));
        plans.push((
            "e.",
            MatchMask::new(
                vec![MaskBranch {
                    terms: vec![
                        MaskTerm {
                            class: cls(b"e"),
                            shift: 0,
                        },
                        MaskTerm {
                            class: ByteClass::any_except(b'\n'),
                            shift: 1,
                        },
                    ],
                }],
                true,
            )
            .expect("builds"),
        ));
        for (name, plan) in &plans {
            for len in lens.iter().copied() {
                // Sparse: hits every 71 bytes, so most words are zero and the
                // walk has to cross them.
                let sparse: Vec<u8> = (0..len)
                    .map(|i| {
                        if i % 71 == 0 {
                            b"pub fn e0 abcdef a\n"[i % 19]
                        } else {
                            b'.'
                        }
                    })
                    .collect();
                let mut got = BitMap::new();
                plan.match_bits(&sparse, &mut got);
                assert_eq!(
                    want(plan, &sparse),
                    offsets(&got),
                    "{name} sparse len={len}"
                );
                let mut scalar = BitMap::new();
                scalar_match_bits(plan, &sparse, &mut scalar);
                assert_eq!(offsets(&scalar), offsets(&got), "{name} scalar len={len}");
                // Dense: built out of the bytes the pattern actually names,
                // so a lane-alignment defect cannot pass by finding nothing.
                let dense: Vec<u8> = (0..len).map(|i| b"pub fn abc a.b|c\n"[i % 17]).collect();
                plan.match_bits(&dense, &mut got);
                assert_eq!(want(plan, &dense), offsets(&got), "{name} dense len={len}");
            }
        }
    }

    /// **The cut is the NARROWEST branch, and every case that could break it
    /// answers `None` rather than a number.** A number here is a promise about
    /// a LINE BOUNDARY, and the four shapes below are the ones where the
    /// promise cannot be kept:
    ///
    /// - a **gap** in a branch. The argument for the cut is that a branch with
    ///   terms at every offset `0..w` is forced to read `buf[e]` for any bit in
    ///   the disputed band, because its term at shift `e - o` is exactly there.
    ///   A branch with no term at that shift reads whatever the NEXT line has.
    /// - a **class that holds the terminator**, for the same reason: `\n` at
    ///   `buf[e]` would satisfy it and the bit would be set by bytes that are
    ///   not in the line.
    /// - a mask that does not DECIDE, where a bit is a candidate and the whole
    ///   claim is somebody else's.
    /// - and `pub_fn_mask`, whose answer is FOUR and not the five its widest
    ///   branch reads, which is the case the rest of this exists to get right.
    #[test]
    fn the_line_cut_is_the_narrowest_branch_or_nothing() {
        assert_eq!(
            pub_fn_mask().line_cut(),
            Some(4),
            "`(pub|fn) [a-z]+` is four wide in its `fn ` branch and five in its `pub ` branch"
        );
        assert_eq!(
            MatchMask::new(
                vec![MaskBranch {
                    terms: vec![MaskTerm {
                        class: cls(b"a|b|c"),
                        shift: 0
                    }],
                }],
                true,
            )
            .expect("builds")
            .line_cut(),
            Some(1),
        );
        assert_eq!(
            MatchMask::new(
                vec![MaskBranch {
                    terms: vec![
                        MaskTerm {
                            class: cls(b"e"),
                            shift: 0
                        },
                        MaskTerm {
                            class: cls(b"0123456789"),
                            shift: 1
                        },
                    ],
                }],
                true,
            )
            .expect("builds")
            .line_cut(),
            Some(2),
        );
        // The gap: `a` at 0 and `c` at 2, with nothing at 1.
        assert_eq!(
            MatchMask::new(
                vec![MaskBranch {
                    terms: vec![
                        MaskTerm {
                            class: cls(b"a"),
                            shift: 0
                        },
                        MaskTerm {
                            class: cls(b"c"),
                            shift: 2
                        },
                    ],
                }],
                true,
            )
            .expect("builds")
            .line_cut(),
            None,
            "a branch with no term at shift 1 has nothing to put on the terminator"
        );
        // The class that takes the terminator, which is the same hole with a
        // term in it: `e` then anything, and anything here includes `\n`.
        assert_eq!(
            MatchMask::new(
                vec![MaskBranch {
                    terms: vec![
                        MaskTerm {
                            class: cls(b"e"),
                            shift: 0
                        },
                        MaskTerm {
                            class: ByteClass::any(),
                            shift: 1
                        },
                    ],
                }],
                true,
            )
            .expect("builds")
            .line_cut(),
            None,
            "a class holding the terminator cannot be cut at"
        );
        // The prefilter. Same mask, no claim.
        assert_eq!(
            MatchMask::new(pub_fn_branches(), false)
                .expect("builds")
                .line_cut(),
            None
        );
    }

    /// **The cut is a claim about a line, so it is checked against one.** Every
    /// line of a hay is split out, the map is filled over the WHOLE hay -- which
    /// is the only way a mask is ever filled, and the reason a bit can be a
    /// match of the buffer and not of the line it sits in -- and the answer from
    /// the bits at or before `content_end - cut` is compared against the mask
    /// re-evaluated over that line's own bytes, which is what the confirm does
    /// today. The two have to be the same answer on every line of the grid,
    /// because the shortcut replaces the confirm rather than adding to it.
    #[test]
    fn the_line_cut_settles_every_line_exactly_as_the_confirm_does() {
        let cases: Vec<(&str, MatchMask)> = vec![
            ("(pub|fn) [a-z]+", pub_fn_mask()),
            (
                "e[0-9]",
                MatchMask::new(
                    vec![MaskBranch {
                        terms: vec![
                            MaskTerm {
                                class: cls(b"e"),
                                shift: 0,
                            },
                            MaskTerm {
                                class: cls(b"0123456789"),
                                shift: 1,
                            },
                        ],
                    }],
                    true,
                )
                .expect("builds"),
            ),
            (
                "a|b|c",
                MatchMask::new(
                    vec![
                        MaskBranch {
                            terms: vec![MaskTerm {
                                class: cls(b"a"),
                                shift: 0,
                            }],
                        },
                        MaskBranch {
                            terms: vec![MaskTerm {
                                class: cls(b"b"),
                                shift: 0,
                            }],
                        },
                        MaskBranch {
                            terms: vec![MaskTerm {
                                class: cls(b"c"),
                                shift: 0,
                            }],
                        },
                    ],
                    true,
                )
                .expect("builds"),
            ),
            (
                "e.",
                MatchMask::new(
                    vec![MaskBranch {
                        terms: vec![
                            MaskTerm {
                                class: cls(b"e"),
                                shift: 0,
                            },
                            MaskTerm {
                                class: ByteClass::any_except(b'\n'),
                                shift: 1,
                            },
                        ],
                    }],
                    true,
                )
                .expect("builds"),
            ),
        ];
        // Every three-byte window of this is a line, over a filler that makes
        // the surroundings useless: `pub ` and `fn x` at a line end, `pub` and
        // `fn` short of one, and the `x` of `pub x` landing where a term would
        // read past the line.
        let hay: Vec<u8> = b"\npub \nfn x\npub\nfn\nxpub \n\nfn  x\npub x\nfn x\nxe\n".to_vec();
        for (name, plan) in &cases {
            let cut = plan.line_cut().expect("this shape is cuttable");
            let mut bits = BitMap::new();
            plan.match_bits(&hay, &mut bits);
            let mut ls = 0usize;
            while ls < hay.len() {
                let le = match hay[ls..].iter().position(|&b| b == b'\n') {
                    Some(i) => ls + i,
                    None => hay.len(),
                };
                let line = &hay[ls..le];
                // What the searcher would answer from the bits it keeps: the
                // range is `[ls, le - cut]` inclusive, and a line too short for
                // one whole match keeps nothing at all.
                let upto = if le >= ls + cut { le - cut + 1 } else { 0 };
                let from_bits = bits.any_set(ls, upto);
                // What the confirm answers: the mask over the line's own bytes.
                let by_confirm = (0..line.len()).any(|at| plan.holds(line, at));
                assert_eq!(
                    from_bits,
                    by_confirm,
                    "{name}: {:?} settles differently from the confirm",
                    String::from_utf8_lossy(line),
                );
                ls = le + 1;
            }
        }
    }

    /// The fill must not read past the haystack, and the only way to see that
    /// from outside is to put a completing match in the bytes just after it.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_fill_does_not_read_past_the_haystack() {
        if !crate::detect::avx2() {
            return;
        }
        let plan = pub_fn_mask();
        for len in 60usize..=140 {
            let mut backing = vec![b'.'; len + 16];
            backing[len..len + 5].copy_from_slice(b"pub x");
            let hay = &backing[..len];
            let mut got = BitMap::new();
            plan.match_bits(hay, &mut got);
            assert_eq!(want(&plan, hay), offsets(&got), "len={len}");
            assert!(
                got.next_set(len).is_none(),
                "a bit past the haystack at len={len}"
            );
        }
    }

    /// The padding bits above the haystack must read as clear, for the same
    /// reason `push32`'s does: a reader that trusted them would hand the
    /// searcher an offset that is not in the buffer.
    #[test]
    fn the_padding_bits_are_clear() {
        let plan = pub_fn_mask();
        let mut m = BitMap::new();
        plan.match_bits(b"pub x", &mut m);
        assert_eq!(m.next_set(0), Some(0));
        assert!(m.next_set(5).is_none());
        let five = b"pub xpub xpub xpub xpub x";
        plan.match_bits(five, &mut m);
        assert_eq!(offsets(&m), vec![0, 5, 10, 15, 20]);
        assert!(m.next_set(five.len()).is_none());
        assert!(!m.any_set(five.len(), 128));
    }

    /// Reuse must not leak the previous fill, for the reason it does for
    /// `BitMap`: a map that grows without zeroing turns every match after the
    /// first fill into a false one.
    #[test]
    fn clear_removes_the_previous_fill() {
        let plan = pub_fn_mask();
        let mut m = BitMap::new();
        plan.match_bits(b"pub xpub xpub x", &mut m);
        assert_eq!(offsets(&m), vec![0, 5, 10]);
        // The same map, a SHORTER haystack: the words the longer one used must
        // be gone, or the map reports offsets past what it now describes.
        plan.match_bits(b"pub x", &mut m);
        assert_eq!(m.len(), 5);
        assert_eq!(offsets(&m), vec![0]);
        assert!(m.next_set(5).is_none());
    }

    /// Three branches of one offset are one class, and the merge is the
    /// distributive law rather than a special case: it is what stops `a|b|c`
    /// from costing three fills.
    #[test]
    fn same_shaped_branches_merge_into_one() {
        let one = |a: u8, b: u8, c: u8| {
            MatchMask::new(
                vec![
                    MaskBranch {
                        terms: vec![MaskTerm {
                            class: cls(&[a]),
                            shift: 0,
                        }],
                    },
                    MaskBranch {
                        terms: vec![MaskTerm {
                            class: cls(&[b]),
                            shift: 0,
                        }],
                    },
                    MaskBranch {
                        terms: vec![MaskTerm {
                            class: cls(&[c]),
                            shift: 0,
                        }],
                    },
                ],
                true,
            )
            .expect("builds")
        };
        let m = one(b'a', b'b', b'c');
        assert_eq!(
            m.term_count(),
            1,
            "three branches of one offset are one term"
        );
        let hay = b"abcabc";
        let mut got = BitMap::new();
        m.match_bits(hay, &mut got);
        assert_eq!(want(&m, hay), offsets(&got));
        assert_eq!(offsets(&got), (0..6).collect::<Vec<_>>());
    }

    /// Branches of DIFFERENT shapes stay apart, and the class table is shared
    /// where the (class, offset) pair repeats. `(pub|fn) [a-z]+` names the
    /// space twice and the letter class twice, at two offsets each.
    #[test]
    fn differently_shaped_branches_stay_apart_and_share_terms() {
        let m = pub_fn_mask();
        assert_eq!(m.branches.len(), 2);
        assert_eq!(
            m.term_count(),
            9,
            "p,u,b,sp@3,l@4 and f,n,sp@2,l@3: four shared, nine in all"
        );
        assert_eq!(m.width(), 5);
        assert!(m.decides());
        let hay = b"pub x\nfn y\npubfn\npub 1\nfn  z\n";
        let mut got = BitMap::new();
        m.match_bits(hay, &mut got);
        assert_eq!(want(&m, hay), offsets(&got));
        assert_eq!(offsets(&got), vec![0, 6]);
    }

    /// The shapes that would silently drop a match are refused, not carried.
    #[test]
    fn degenerate_shapes_are_refused() {
        // An empty class: nothing can satisfy it, so the mask would match
        // nothing and a prefilter that matches nothing drops every line.
        assert!(MatchMask::new(
            vec![MaskBranch {
                terms: vec![MaskTerm {
                    class: ByteClass::empty(),
                    shift: 0
                }]
            }],
            true,
        )
        .is_none());
        // Two requirements at one offset: a match has one byte there.
        assert!(MatchMask::new(
            vec![MaskBranch {
                terms: vec![
                    MaskTerm {
                        class: cls(b"a"),
                        shift: 0
                    },
                    MaskTerm {
                        class: cls(b"b"),
                        shift: 0
                    },
                ],
            }],
            true,
        )
        .is_none());
        // No branches at all.
        assert!(MatchMask::new(Vec::new(), true).is_none());
        // Past the term budget: the fill would have to spill, and the cap is
        // there so that it cannot.
        let long: Vec<MaskBranch> = (0..=MAX_MASK_TERMS as u8)
            .map(|i| MaskBranch {
                terms: vec![MaskTerm {
                    class: cls(b"a"),
                    shift: i as usize,
                }],
            })
            .collect();
        assert!(MatchMask::new(long, true).is_none());
    }

    /// The published shapes of the AND, read off the mask rather than off the
    /// pattern text: `M_pub` is five terms and `M_fn` four, the space at
    /// offsets 3 and 2, and the letter class at 4 and 3.
    #[test]
    fn the_published_mask_has_the_published_terms() {
        let m = pub_fn_mask();
        let named = |c: ByteClass| (0..=255u8).filter(|&b| c.contains(b)).collect::<Vec<u8>>();
        let got: Vec<Vec<(usize, Vec<u8>)>> = m
            .branches()
            .iter()
            .map(|b| b.iter().map(|&(s, c)| (s, named(c))).collect())
            .collect();
        assert_eq!(
            got,
            vec![
                vec![
                    (0, b"p".to_vec()),
                    (1, b"u".to_vec()),
                    (2, b"b".to_vec()),
                    (3, b" ".to_vec()),
                    (4, named(lower())),
                ],
                vec![
                    (0, b"f".to_vec()),
                    (1, b"n".to_vec()),
                    (2, b" ".to_vec()),
                    (3, named(lower())),
                ],
            ]
        );
    }

    /// **The price of the fill, per term count.**
    ///
    /// `regex.rs` prices a mask against a substring search and a `memchr`, and
    /// a constant that is wrong by 2x picks the wrong anchor for every
    /// literal of three bytes or more. This is where the constant comes from:
    /// the 235 MB corpus this engine is measured on, 64 KiB fills, the fill
    /// alone, minimum of five rounds.
    ///
    /// Run it with `cargo test --release -p rgx-core mask_fill_price -- --nocapture --ignored`.
    #[test]
    #[ignore = "a measurement, not a gate"]
    fn mask_fill_price() {
        use std::time::Instant;
        let path = format!(
            "{}/.rgx-bench/big235.rs",
            std::env::var("USERPROFILE").unwrap_or_default()
        );
        let hay = match std::fs::read(&path) {
            Ok(h) => h,
            Err(_) => {
                std::eprintln!("no corpus at {path}; skipping the price");
                return;
            }
        };
        std::eprintln!(
            "corpus {:.1} MiB, 64 KiB fills, min of 5",
            hay.len() as f64 / 1048576.0
        );
        let cases: Vec<(&str, MatchMask)> = vec![
            ("1 term  (a|b|c)", {
                MatchMask::new(
                    vec![
                        MaskBranch {
                            terms: vec![MaskTerm {
                                class: cls(b"a"),
                                shift: 0,
                            }],
                        },
                        MaskBranch {
                            terms: vec![MaskTerm {
                                class: cls(b"b"),
                                shift: 0,
                            }],
                        },
                        MaskBranch {
                            terms: vec![MaskTerm {
                                class: cls(b"c"),
                                shift: 0,
                            }],
                        },
                    ],
                    true,
                )
                .expect("builds")
            }),
            ("2 terms (e[0-9])", {
                MatchMask::new(
                    vec![MaskBranch {
                        terms: vec![
                            MaskTerm {
                                class: cls(b"e"),
                                shift: 0,
                            },
                            MaskTerm {
                                class: cls(b"0123456789"),
                                shift: 1,
                            },
                        ],
                    }],
                    true,
                )
                .expect("builds")
            }),
            ("7 terms (let mut)", {
                let b = b"let mut";
                MatchMask::new(
                    vec![MaskBranch {
                        terms: b
                            .iter()
                            .enumerate()
                            .map(|(i, &x)| MaskTerm {
                                class: cls(&[x]),
                                shift: i,
                            })
                            .collect(),
                    }],
                    true,
                )
                .expect("builds")
            }),
            ("9 terms ((pub|fn) [a-z]+)", pub_fn_mask()),
        ];
        let mut map = BitMap::new();
        for (name, m) in &cases {
            let mut best = f64::INFINITY;
            let mut bits = 0u64;
            for _ in 0..6 {
                let t = Instant::now();
                let mut n = 0u64;
                for blk in hay.chunks(64 * 1024) {
                    m.match_bits(blk, &mut map);
                    n += map.count_set(0, blk.len());
                }
                let ms = t.elapsed().as_secs_f64() * 1e3;
                best = best.min(ms);
                bits = n;
            }
            std::eprintln!(
                "  {name:26} {best:7.2} ms  {:5.2} GB/s  {:5.3} ns/byte  {bits} bits",
                hay.len() as f64 / 1e9 / (best / 1e3),
                best * 1e6 / hay.len() as f64
            );
        }
    }
}

#[cfg(test)]
mod bit_tests {
    use alloc::vec::Vec;

    use super::{byte_bits, byte_bits_many, term_bits, BitMap};
    // Same gate as the import above, and for the same reason: the scalar
    // definition is the oracle, the oracle is compared against the vector
    // path, and the vector path is x86_64.
    #[cfg(target_arch = "x86_64")]
    use super::scalar_bits;

    /// The set the map reports, as offsets. Every other test here compares
    /// this, because a bitmap's whole contract is which bits it sets.
    fn offsets(m: &BitMap) -> Vec<usize> {
        let mut out = Vec::new();
        m.append_offsets(&mut out);
        out
    }

    fn want(hay: &[u8], needles: &[u8]) -> Vec<usize> {
        (0..hay.len())
            .filter(|&i| needles.contains(&hay[i]))
            .collect()
    }

    /// The needle list padded to the three bytes the vector kernels take.
    /// x86_64 only, because the only caller is the vector/scalar comparison.
    #[cfg(target_arch = "x86_64")]
    fn pad3(needles: &[u8]) -> [u8; 3] {
        [
            needles[0],
            *needles.get(1).unwrap_or(&0),
            *needles.get(2).unwrap_or(&0),
        ]
    }

    /// The load-bearing test, and the reason this file has two paths at all:
    /// the vector fill must set exactly the bits the scalar definition sets,
    /// at every length around every 32-byte and 64-byte boundary, because a
    /// bit lost in `push32`'s straddle is a MISSED MATCH and one set wrongly is
    /// a wrong one.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_and_scalar_agree_at_every_boundary() {
        if !crate::detect::avx2() {
            return;
        }
        let mut lens: Vec<usize> = (0..200).collect();
        lens.extend([255, 256, 257, 511, 512, 513, 1023, 1024, 1025]);
        for len in lens {
            for needles in [&b"a"[..], &b"ab"[..], &b"abc"[..], &b"\n"[..], &b"\nz"[..]] {
                let p = pad3(needles);
                // A haystack that matches at EVERY offset, so a lane-alignment
                // defect cannot pass by finding nothing to find.
                let all: Vec<u8> = (0..len).map(|i| needles[i % needles.len()]).collect();
                let mut got = BitMap::new();
                byte_bits(&p, needles.len(), &all, &mut got);
                assert_eq!(
                    want(&all, needles),
                    offsets(&got),
                    "dense len={len} needles={needles:?}"
                );
                // The scalar definition on the SAME input, so the two paths can
                // never drift apart silently. It is the reference every
                // assertion above is really making. The kernels fill rather
                // than clear -- `byte_bits_many` ORs several passes into one
                // map -- so the reference clears first the way the public
                // entry points do.
                let mut scalar = BitMap::new();
                scalar.clear(all.len());
                scalar_bits(&p, needles.len(), &all, &mut scalar);
                assert_eq!(offsets(&scalar), offsets(&got), "scalar len={len}");
                // And a sparse haystack, where most words are zero and the walk
                // has to cross them.
                let sparse: Vec<u8> = (0..len)
                    .map(|i| if i % 71 == 0 { needles[0] } else { b'.' })
                    .collect();
                byte_bits(&p, needles.len(), &sparse, &mut got);
                assert_eq!(
                    want(&sparse, needles),
                    offsets(&got),
                    "sparse len={len} needles={needles:?}"
                );
            }
        }
    }

    /// The dispatching entry point is what a caller without AVX2 reaches, and
    /// it is what a caller WITH AVX2 reaches too -- so the entry point is the
    /// thing under test, not the vector body.
    #[test]
    fn the_entry_point_agrees_with_the_definition() {
        let hay: Vec<u8> = (0..1000u32)
            .map(|i| if i % 17 == 0 { b'e' } else { b'x' })
            .collect();
        let mut m = BitMap::new();
        byte_bits(&[b'e', 0, 0], 1, &hay, &mut m);
        assert_eq!(want(&hay, b"e"), offsets(&m));
        term_bits(b'\n', &hay, &mut m);
        assert_eq!(want(&hay, b"\n"), offsets(&m));
    }

    /// `next_set` is what the line loop and the candidate iterator are built
    /// on, so its three answers -- a hit, a miss, and a `from` past the end --
    /// are pinned at every offset of every length, including offsets inside
    /// the last partial word where a stray high bit would read past the map.
    #[test]
    fn next_set_is_exact_at_every_offset() {
        for len in 0..200usize {
            let hay: Vec<u8> = (0..len)
                .map(|i| if i % 13 == 0 { b'e' } else { b'.' })
                .collect();
            let mut m = BitMap::new();
            byte_bits(&[b'e', 0, 0], 1, &hay, &mut m);
            let all = want(&hay, b"e");
            for from in 0..=len {
                assert_eq!(
                    m.next_set(from),
                    all.iter().copied().find(|&i| i >= from),
                    "len={len} from={from}"
                );
            }
            assert_eq!(m.next_set(len + 100), None);
        }
    }

    /// `any_set` is the range query the candidate stream asks before it builds
    /// an iterator. Its edges are where an off-by-one reports a candidate one
    /// byte outside the line, so every sub-range of a small haystack is checked
    /// against the definition.
    #[test]
    fn any_set_is_exact_over_every_range() {
        for len in 0..140usize {
            let hay: Vec<u8> = (0..len)
                .map(|i| if i % 13 == 0 { b'e' } else { b'.' })
                .collect();
            let mut m = BitMap::new();
            byte_bits(&[b'e', 0, 0], 1, &hay, &mut m);
            let all = want(&hay, b"e");
            for from in 0..=len {
                for to in from..=len {
                    assert_eq!(
                        m.any_set(from, to),
                        all.iter().any(|&i| i >= from && i < to),
                        "len={len} range={from}..{to}"
                    );
                    // `count_set` is the early exit's line counter and answers
                    // the same range with a number, so it is held to the same
                    // definition rather than trusted because `any_set` is.
                    assert_eq!(
                        m.count_set(from, to),
                        all.iter().filter(|&&i| i >= from && i < to).count() as u64,
                        "len={len} range={from}..{to}"
                    );
                }
            }
            assert!(!m.any_set(len + 1, len + 50));
            assert_eq!(m.count_set(len + 1, len + 50), 0);
            assert!(!m.any_set(5, 5));
            assert_eq!(m.count_set(5, 5), 0);
        }
    }

    /// Reusing a map must not let the previous fill's bits leak into this one.
    /// The searcher clears once per fill and the fills are unrelated, so a map
    /// that grows without zeroing turns every match after the first fill into
    /// a false one.
    #[test]
    fn clear_removes_the_previous_fill() {
        let mut m = BitMap::new();
        let first = vec![b'e'; 200];
        byte_bits(&[b'e', 0, 0], 1, &first, &mut m);
        assert!(!offsets(&m).is_empty());
        let second = vec![b'.'; 200];
        byte_bits(&[b'.', 0, 0], 1, &second, &mut m);
        assert_eq!(offsets(&m), want(&second, b"."));
        // And a SHORTER fill: the words the longer one used must be gone, or
        // the map reports offsets past the haystack it now describes.
        let third = vec![b'e'; 40];
        byte_bits(&[b'e', 0, 0], 1, &third, &mut m);
        assert_eq!(m.len(), 40);
        assert_eq!(offsets(&m), want(&third, b"e"));
        assert_eq!(m.next_set(40), None);
    }

    /// The same contract for [`byte_bits_many`], which `map_candidates`'s
    /// `ByteN` arm calls on the searcher's reused map. A fill that ORed into
    /// the map as it stood would keep every previous fill's bits, and the
    /// reader path would emit false candidates from fill two onward.
    #[test]
    fn byte_bits_many_clears_the_previous_fill() {
        let set = b"+|-";
        let mut m = BitMap::new();
        let first: Vec<u8> = (0..300).map(|i| set[i % set.len()]).collect();
        byte_bits_many(set, &first, &mut m);
        assert_eq!(offsets(&m), want(&first, set));
        // A second fill with a DIFFERENT set over a haystack that holds none
        // of the first set's bytes: the map must read empty, not carry the
        // first fill forward.
        let second = vec![b'.'; 300];
        byte_bits_many(b":,;", &second, &mut m);
        assert_eq!(offsets(&m), Vec::<usize>::new());
        // And a shorter fill, so the words the longer one used are covered too.
        let third: Vec<u8> = (0..40).map(|i| set[i % set.len()]).collect();
        byte_bits_many(set, &third, &mut m);
        assert_eq!(m.len(), 40);
        assert_eq!(offsets(&m), want(&third, set));
        assert_eq!(m.next_set(40), None);
    }

    /// The padding bits above the haystack must read as clear. They are never
    /// written, and a reader that trusted them would hand the searcher an
    /// offset inside the padding -- which for the candidate stream is a
    /// subtraction past the end of a line.
    #[test]
    fn the_padding_bits_are_clear() {
        let mut m = BitMap::new();
        byte_bits(&[b'e', 0, 0], 1, b"eeeee", &mut m);
        assert_eq!(m.next_set(5), None);
        assert!(!m.any_set(5, 64));
        // One byte long: the padding is 63 bits, so all of them are exercised
        // at once.
        byte_bits(&[b'e', 0, 0], 1, b"e", &mut m);
        assert_eq!(m.next_set(1), None);
        assert!(m.any_set(0, 1));
        assert!(!m.any_set(1, 64));
    }

    /// An empty haystack must produce an empty map and must not index it, which
    /// a reader that walks words before checking the length would.
    #[test]
    fn an_empty_haystack_is_an_empty_map() {
        let mut m = BitMap::new();
        byte_bits(&[b'e', 0, 0], 1, b"", &mut m);
        term_bits(b'\n', b"", &mut m);
        assert!(m.is_empty());
        assert_eq!(m.next_set(0), None);
        assert!(!m.any_set(0, 10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::literal::{build_mask, Literal, LiteralSet, MAX_FINGERPRINT};

    fn mask_for(lits: &[&[u8]], caseless: bool) -> NibbleMask {
        let set = LiteralSet::exact(
            lits.iter()
                .map(|l| {
                    if caseless {
                        Literal::caseless(l)
                    } else {
                        Literal::new(l)
                    }
                })
                .collect(),
        );
        build_mask(&set, MAX_FINGERPRINT).expect("mask")
    }

    /// The load-bearing test: the vector path and the scalar path must agree
    /// on the *set* of candidates, for every input. A one-byte disagreement is
    /// a missed match, which is the one failure this whole module cannot have.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn simd_matches_scalar_on_random_input() {
        if !crate::detect::avx2() {
            return;
        }
        // A dependency-free xorshift, so the test does not need a crate and
        // the corpus is reproducible.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mask = mask_for(&[b"error", b"parse"], true);
        for len in [0usize, 1, 15, 31, 32, 33, 63, 64, 65, 100, 255, 1024] {
            for alphabet in [1u8, 4, 26, 255] {
                let hay: Vec<u8> = (0..len)
                    .map(|_| (next() % u64::from(alphabet)) as u8)
                    .collect();
                let want = scalar_candidates(&mask, &hay);
                // SAFETY: guarded by the feature check at the top.
                let got = unsafe { simd_candidates(&mask, &hay) };
                assert_eq!(want, got, "len={len} alphabet={alphabet}");
            }
        }
    }

    /// The same equality on input that looks like text, where the candidate
    /// positions are clustered rather than spread. Random bytes put a
    /// candidate every few hundred bytes; real text puts thousands in a
    /// line, and a bug that only shows up when `out` is being appended to
    /// rapidly would not appear above.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn simd_matches_scalar_on_document_shaped_input() {
        if !crate::detect::avx2() {
            return;
        }
        let mask = mask_for(&[b"error", b"parse"], true);
        let mut doc = Vec::new();
        for i in 0..2000 {
            doc.extend_from_slice(
                format!("line {i}: an error occurred while parsing the value\n").as_bytes(),
            );
        }
        let want = scalar_candidates(&mask, &doc);
        // SAFETY: guarded by the feature check at the top.
        let got = unsafe { simd_candidates(&mask, &doc) };
        assert_eq!(want, got);
        // And the fixture must actually be exercising the path.
        assert!(want.len() > 1000, "fixture is too sparse: {}", want.len());
    }

    /// A haystack that is all one byte must produce either zero candidates or
    /// every offset, and both paths must say the same thing. This is the
    /// "mask matches everything" degenerate case, where a lane-order bug would
    /// show up as a partial set.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_uniform_haystack_agrees() {
        if !crate::detect::avx2() {
            return;
        }
        let mask = mask_for(&[b"aa"], false);
        for byte in *b"ab" {
            for len in [32usize, 33, 64, 96] {
                let hay = vec![byte; len];
                // SAFETY: guarded by the feature check at the top.
                let got = unsafe { simd_candidates(&mask, &hay) };
                let want = scalar_candidates(&mask, &hay);
                assert_eq!(want, got, "byte={byte} len={len}");
            }
        }
    }

    /// The scan must not read one byte past the haystack, and the only way to
    /// see that from outside is to put a byte there that would complete a
    /// match. A haystack whose allocation continues with `d`, and whose last
    /// three bytes are `abc`, turns one byte read too far into a candidate at
    /// `len - 3` that the scalar reference cannot report -- the loop bound is
    /// `LANES + positions - 1` precisely so that block never runs.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_scan_does_not_read_past_the_haystack() {
        if !crate::detect::avx2() {
            return;
        }
        let mask = mask_for(&[b"abcd"], false);
        for len in 32usize..=40 {
            let mut backing = vec![b'.'; len + 1];
            backing[len - 3..len].copy_from_slice(b"abc");
            backing[len] = b'd';
            let hay = &backing[..len];
            // SAFETY: guarded by the feature check at the top.
            let got = unsafe { simd_candidates(&mask, hay) };
            assert_eq!(scalar_candidates(&mask, hay), got, "len={len}");
        }
    }

    /// The dispatching entry point must agree with the scalar path too, since
    /// that is what a caller actually reaches for.
    #[test]
    fn the_entry_point_agrees_with_scalar() {
        let mask = mask_for(&[b"error"], true);
        let doc = b"error\nparse\nno match here\nError again\n".to_vec();
        assert_eq!(scalar_candidates(&mask, &doc), candidates(&mask, &doc));
    }

    /// Every start offset, in a haystack sized to the loop's own arithmetic.
    ///
    /// `scan_body` loads `positions` overlapping 32-byte windows, so it may
    /// only run while `i + 32 + positions - 1 <= len`; a loop bounded by `len`
    /// alone reads past the haystack, and one bounded too tightly silently
    /// drops the last few starts. Placing a literal at *every* offset, at
    /// every length around those boundaries, is what tells the two apart --
    /// and the scalar reference is the definition, so the check is agreement
    /// rather than a hand-written expected set.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn every_start_is_found_at_every_length_around_the_chunk_boundary() {
        if !crate::detect::avx2() {
            return;
        }
        assert_eq!(
            block_width(),
            LANES,
            "the vector path is not the one running"
        );
        let needle = b"abcd";
        let mask = mask_for(&[needle], false);
        let span = LANES + mask.positions() - 1;
        let mut lens = vec![0usize, 1, needle.len()];
        lens.extend((span - 2)..=(span + 2));
        lens.extend((2 * LANES - 2)..=(2 * LANES + span + 2));
        for len in lens {
            if len < needle.len() {
                continue;
            }
            for start in 0..=len - needle.len() {
                let mut hay = vec![b'.'; len];
                hay[start..start + needle.len()].copy_from_slice(needle);
                // SAFETY: guarded by the feature check at the top.
                let got = unsafe { simd_candidates(&mask, &hay) };
                assert_eq!(
                    scalar_candidates(&mask, &hay),
                    got,
                    "len={len} start={start}"
                );
            }
        }
    }

    /// Each fingerprint depth gets its own instantiation of the chunk loop,
    /// and `build_mask` refuses anything under `MIN_FINGERPRINT`, so a
    /// one-position mask is only reachable through `add` directly.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn every_fingerprint_depth_agrees_with_scalar() {
        if !crate::detect::avx2() {
            return;
        }
        let doc = b"a ab abc abcd abcde abcd abc ab abcde aaa abcd abcd".to_vec();
        for depth in 1..=MAX_FINGERPRINT {
            let print = &b"abcd"[..depth];
            let mut mask = NibbleMask::new();
            assert!(mask.add(0, print, false));
            assert_eq!(mask.positions(), depth);
            // SAFETY: guarded by the feature check at the top.
            let got = unsafe { simd_candidates(&mask, &doc) };
            assert_eq!(scalar_candidates(&mask, &doc), got, "depth={depth}");
        }
    }

    /// A mask with no positions matches nothing, on both paths, rather than
    /// indexing an empty table pair.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn an_empty_mask_finds_nothing() {
        if !crate::detect::avx2() {
            return;
        }
        let mask = NibbleMask::new();
        let doc = vec![b'a'; 200];
        assert_eq!(scalar_candidates(&mask, &doc), Vec::<usize>::new());
        // SAFETY: guarded by the feature check at the top.
        assert_eq!(unsafe { simd_candidates(&mask, &doc) }, Vec::<usize>::new());
    }

    /// The result is used as a stream the line loop pulls from in order, so
    /// it has to come out strictly ascending with no repeats. The scan used
    /// to sort and dedup to guarantee that, which is what let a chunk emit
    /// the same start twice go unnoticed; with neither step, a duplicate is a
    /// visible failure.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_result_is_strictly_ascending() {
        if !crate::detect::avx2() {
            return;
        }
        let mask = mask_for(&[b"error", b"parse"], true);
        let mut doc = Vec::new();
        for i in 0..3000 {
            doc.extend_from_slice(
                format!("line {i}: an error occurred while parsing the value\n").as_bytes(),
            );
        }
        // SAFETY: guarded by the feature check at the top.
        let got = unsafe { simd_candidates(&mask, &doc) };
        assert!(got.len() > 1000, "fixture is too sparse: {}", got.len());
        assert!(
            got.windows(2).all(|w| w[0] < w[1]),
            "not strictly ascending around {:?}",
            got.windows(2).position(|w| w[0] >= w[1])
        );
    }

    /// The lane-broadcast is the subtle part: `pshufb` is lane-local, so if
    /// the high lane carried zeroes instead of the table, every candidate in
    /// bytes 16..32 of a chunk would vanish. A haystack of exactly one chunk
    /// with the literal starting past byte 16 is the smallest input that
    /// catches it.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_candidate_in_the_high_lane_is_not_lost() {
        if !crate::detect::avx2() {
            return;
        }
        let mask = mask_for(&[b"zq"], false);
        for start in [0usize, 15, 16, 17, 31, 32] {
            let mut hay = vec![b'x'; 64];
            hay[start] = b'z';
            hay[start + 1] = b'q';
            // SAFETY: guarded by the feature check at the top.
            let got = unsafe { simd_candidates(&mask, &hay) };
            assert!(
                got.contains(&start),
                "candidate at {start} was lost (got {got:?})"
            );
        }
    }

    #[test]
    fn pair_offsets_and_pair_bits_match_scalar_at_all_offsets() {
        let needles: &[&[u8]] = &[b"pub fn", b"fn", b"let mut", b"xyz123"];
        for &needle in needles {
            let mut hay = Vec::new();
            for i in 0..1000 {
                if i % 13 == 0 {
                    hay.extend_from_slice(needle);
                } else {
                    hay.extend_from_slice(b"some other text line padding\n");
                }
            }
            let mut got_offsets = Vec::new();
            pair_offsets(needle, &hay, &mut got_offsets);

            let mut want_offsets = Vec::new();
            scalar_pair_offsets(needle, k_for_pair(needle), &hay, &mut want_offsets);
            assert_eq!(
                got_offsets, want_offsets,
                "offsets mismatch for needle {:?}",
                needle
            );

            let mut got_bits = BitMap::new();
            pair_bits(needle, &hay, &mut got_bits);
            for &off in &want_offsets {
                assert!(got_bits.any_set(off, off + 1), "missing bit at {}", off);
            }
        }
    }

    #[test]
    fn count_byte_matches_scalar_at_all_lengths() {
        for len in [0, 1, 7, 15, 16, 31, 32, 63, 64, 127, 128, 255, 300, 1000] {
            let mut data = vec![b'a'; len];
            for i in (0..len).step_by(5) {
                data[i] = b'\n';
            }
            let want = scalar_count_byte(b'\n', &data);
            let got = count_byte(b'\n', &data);
            assert_eq!(got, want, "len={len}");
        }
    }
}
