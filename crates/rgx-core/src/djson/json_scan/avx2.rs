// SPDX-License-Identifier: Apache-2.0

//! The vector path: 64 bytes of input per iteration, one `u64` of output.
//!
//! **Every `unsafe` here is what the vector width requires.** [`super::scan_scalar`]
//! computes the identical predicate with none, and the tests compare the two
//! on a corpus built to break exactly this code. The discipline: each
//! `#[target_feature]` function states, in its safety documentation, which
//! runtime check lets its caller reach it.
//!
//! ## Shape of an iteration
//!
//! ```text
//! load 32 bytes -> 6 pshufb rectangles -> 2 planes (structural, quote)
//! load 32 bytes -> (same)               -> planes widened into a u64 each
//! plus one cmpeq for the backslash plane
//! 64 bytes of masks -> the block algebra in super::block_with
//!                  -> one u64 of structural output, one of quote
//! ```
//!
//! ## Two hazards a short input never shows
//!
//! `pshufb` is per-128-bit-lane, so every 16-byte table is broadcast into both
//! lanes of the `__m256i`. A table left in the high lane alone would make
//! bytes 16..32 of every chunk classify as OTHER — and since the tail bytes go
//! through `step` rather than through here, the *unit* tests over short
//! documents would all pass while the block loop was wrong for every input
//! over 64 bytes. The boundary sweeps are what catch it.
//!
//! The nibble indices are masked to four bits before use, both because
//! `pshufb` zeroes any lane whose index has bit 7 set and because the high
//! nibble of a byte `>= 0x80` is `>= 8`, where no rectangle has a row.

use core::arch::x86_64::*;

use super::{
    block_with, Builder, Classified16, RECT_BRACKET, RECT_COLON, RECT_COMMA, RECT_CTRL_WS,
    RECT_QUOTE, RECT_SPACE,
};

/// Bytes consumed per iteration: two 32-byte vectors folded into one 64-bit
/// output word.
const BLOCK: usize = 64;

/// Broadcast a 16-entry `pshufb` table into both 128-bit lanes.
///
/// `pshufb` zeroes a lane when bit 7 of its index is set — that is how the
/// instruction stays in bounds, and why the callers mask to `0x0F`. This is not
/// a bounds check; the tables hold `0x00`/`0xFF` only.
#[target_feature(enable = "avx2")]
unsafe fn broadcast(table: &[u8; 16]) -> __m256i {
    // SAFETY: `table` is a `&[u8; 16]`, so the 16-byte load is in bounds by
    // the type; the target feature is this function's contract.
    unsafe { _mm256_broadcastsi128_si256(_mm_loadu_si128(table.as_ptr() as *const __m128i)) }
}

/// One rectangle of the high-nibble × low-nibble grid, 32 bytes wide.
///
/// `pshufb(lo_table, lo) & pshufb(hi_table, hi)` is set exactly on the bytes
/// whose low nibble `lo_table` accepts *and* whose high nibble `hi_table`
/// accepts. `super` explains why the classification is a union of these rather
/// than a single pair.
#[inline(always)]
unsafe fn rect(lo_table: __m256i, hi_table: __m256i, lo: __m256i, hi: __m256i) -> __m256i {
    // SAFETY: reached only from a function whose contract established AVX2;
    // `lo` and `hi` are masked to `0x0F` by the caller, so no lane is zeroed
    // by `pshufb`'s high-bit rule and no table index exceeds 15.
    unsafe {
        _mm256_and_si256(
            _mm256_shuffle_epi8(lo_table, lo),
            _mm256_shuffle_epi8(hi_table, hi),
        )
    }
}

/// The broadcast tables, built once for a whole scan.
struct Tables {
    space: (__m256i, __m256i),
    ctrl_ws: (__m256i, __m256i),
    comma: (__m256i, __m256i),
    colon: (__m256i, __m256i),
    bracket: (__m256i, __m256i),
    quote: (__m256i, __m256i),
}

impl Tables {
    #[target_feature(enable = "avx2")]
    unsafe fn new() -> Self {
        // SAFETY: called from `scan_avx2`, whose contract established AVX2;
        // each `broadcast` requires no more than that.
        unsafe {
            Self {
                space: (broadcast(&RECT_SPACE.0), broadcast(&RECT_SPACE.1)),
                ctrl_ws: (broadcast(&RECT_CTRL_WS.0), broadcast(&RECT_CTRL_WS.1)),
                comma: (broadcast(&RECT_COMMA.0), broadcast(&RECT_COMMA.1)),
                colon: (broadcast(&RECT_COLON.0), broadcast(&RECT_COLON.1)),
                bracket: (broadcast(&RECT_BRACKET.0), broadcast(&RECT_BRACKET.1)),
                quote: (broadcast(&RECT_QUOTE.0), broadcast(&RECT_QUOTE.1)),
            }
        }
    }

    /// The three planes for 32 bytes, one bit per byte in a `u32`.
    ///
    /// # Safety
    ///
    /// `ptr` must be valid for a 32-byte read and AVX2 must be available.
    #[target_feature(enable = "avx2")]
    unsafe fn planes(&self, ptr: *const u8) -> (u32, u32, u32) {
        // SAFETY: the 32-byte load is in bounds because the caller checked
        // `at + 64 <= bytes.len()` before entering the loop. The target
        // feature is this function's contract.
        let v = unsafe { _mm256_loadu_si256(ptr as *const __m256i) };
        // `srli_epi16` shifts within 16-bit lanes, so byte 1's bits would land
        // in byte 0; the AND is what keeps the high nibble a nibble.
        let lo = _mm256_and_si256(v, _mm256_set1_epi8(0x0F));
        let hi = _mm256_and_si256(_mm256_srli_epi16(v, 4), _mm256_set1_epi8(0x0F));

        // SAFETY: in bounds of the tables by construction, and the indices
        // are `& 0x0F`.
        unsafe {
            let ws = _mm256_or_si256(
                rect(self.space.0, self.space.1, lo, hi),
                rect(self.ctrl_ws.0, self.ctrl_ws.1, lo, hi),
            );
            let punct = _mm256_or_si256(
                _mm256_or_si256(
                    rect(self.comma.0, self.comma.1, lo, hi),
                    rect(self.colon.0, self.colon.1, lo, hi),
                ),
                rect(self.bracket.0, self.bracket.1, lo, hi),
            );
            let structural = _mm256_or_si256(ws, punct);
            let quote = rect(self.quote.0, self.quote.1, lo, hi);
            // The backslash is the one class the two-bit code cannot carry;
            // `0x5C` is positive, so `_mm256_set1_epi8` is representable.
            let backslash = _mm256_cmpeq_epi8(v, _mm256_set1_epi8(b'\\' as i8));

            (
                _mm256_movemask_epi8(structural) as u32,
                _mm256_movemask_epi8(quote) as u32,
                _mm256_movemask_epi8(backslash) as u32,
            )
        }
    }
}

/// The 64-byte block, given the three planes of its first and second halves.
///
/// # Safety
///
/// Requires PCLMULQDQ, for [`prefix_xor_clmul`].
#[target_feature(enable = "avx2,pclmulqdq")]
unsafe fn block(lo: (u32, u32, u32), hi: (u32, u32, u32), carry: &mut super::Carry) -> (u64, u64) {
    let structural_raw = lo.0 as u64 | (hi.0 as u64) << 32;
    let quote = lo.1 as u64 | (hi.1 as u64) << 32;
    let backslash = lo.2 as u64 | (hi.2 as u64) << 32;
    // SAFETY: the target features are this function's contract, and the
    // closure's body is `prefix_xor_clmul` inlined under the same features.
    unsafe {
        block_with(structural_raw, quote, backslash, carry, |v| {
            prefix_xor_clmul(v)
        })
    }
}

/// Inclusive prefix-XOR of a 64-bit word: bit `i` of the result is the XOR of
/// bits `0..=i` of `x`.
///
/// `pclmulqdq` against an all-ones operand is the carry-less multiply by
/// `1 + x + x^2 + …`, which is exactly that sum. [`super::prefix_xor`] is the
/// same function as a shift chain, and the tests check the two agree word for
/// word — a carry-less multiply with the wrong operand, or reading the wrong
/// half of its result, is a silent one-bit-per-block corruption otherwise.
///
/// # Safety
///
/// Requires PCLMULQDQ.
#[target_feature(enable = "pclmulqdq")]
pub(super) unsafe fn prefix_xor_clmul(x: u64) -> u64 {
    let a = _mm_cvtsi64_si128(x as i64);
    // Only the low 64 bits of the operand reach the low half of the result:
    // any term using the high half has degree >= 64 and is shifted out.
    let ones = _mm_set1_epi64x(-1);
    // `0x00` selects the low 64 bits of each operand, and the target feature
    // is this function's contract.
    let r = _mm_clmulepi64_si128(a, ones, 0x00);
    _mm_cvtsi128_si64(r) as u64
}

/// Scan `bytes` with the AVX2 path.
///
/// # Safety
///
/// The caller must have established that the CPU supports both AVX2 and
/// PCLMULQDQ. [`super::scan`] does exactly that through
/// [`super::has_avx2_pclmulqdq`] before calling; reaching this without it is
/// undefined behaviour, not a wrong answer.
#[target_feature(enable = "avx2,pclmulqdq")]
pub unsafe fn scan_avx2(bytes: &[u8]) -> super::StructuralIndex {
    // SAFETY: this function's contract established AVX2, which is all
    // `Tables::new` requires.
    let tables = unsafe { Tables::new() };
    let mut builder = Builder::new(bytes.len());
    let mut at = 0usize;

    while at + BLOCK <= bytes.len() {
        // The loop bound is what makes the loads in bounds: the final
        // iteration that would read past `bytes` is never entered, and the
        // remaining `0..64` bytes go through `step`.
        //
        // SAFETY: `at + 64 <= bytes.len()`, so both 32-byte loads are wholly
        // within the slice. The target features are this function's contract.
        let lo = unsafe { tables.planes(bytes.as_ptr().add(at)) };
        let hi = unsafe { tables.planes(bytes.as_ptr().add(at + 32)) };
        // SAFETY: as above, for `block`.
        let (structural, quote) = unsafe { block(lo, hi, &mut builder.carry) };
        builder.push_word(structural, quote);
        at += BLOCK;
    }

    while at < bytes.len() {
        builder.step(at, bytes[at]);
        at += 1;
    }
    builder.finish()
}

/// The vector counterpart of [`super::classify16`].
///
/// # Safety
///
/// Requires AVX2.
#[target_feature(enable = "avx2")]
pub unsafe fn classify16_avx2_inner(bytes: &[u8; 16]) -> Classified16 {
    // SAFETY: `bytes` is `&[u8; 16]`, so the 16-byte load is in bounds by the
    // type. The target feature is this function's contract.
    unsafe {
        let v = _mm_loadu_si128(bytes.as_ptr() as *const __m128i);
        let lo = _mm_and_si128(v, _mm_set1_epi8(0x0F));
        let hi = _mm_and_si128(_mm_srli_epi16(v, 4), _mm_set1_epi8(0x0F));

        let ws = _mm_or_si128(rect128(&RECT_SPACE, lo, hi), rect128(&RECT_CTRL_WS, lo, hi));
        let punct = _mm_or_si128(
            _mm_or_si128(rect128(&RECT_COMMA, lo, hi), rect128(&RECT_COLON, lo, hi)),
            rect128(&RECT_BRACKET, lo, hi),
        );
        let structural = _mm_or_si128(ws, punct);
        let quote = rect128(&RECT_QUOTE, lo, hi);
        let backslash = _mm_cmpeq_epi8(v, _mm_set1_epi8(b'\\' as i8));

        let mb = _mm_movemask_epi8(backslash) as u32 & 0xFFFF;
        let mw = _mm_movemask_epi8(ws) as u32 & 0xFFFF;

        // Two bits per byte, byte `i` at bits `2i..2i+2`. `movemask` cannot do
        // this — it packs one bit per byte, which is a *different* layout, and
        // a version that returned it labelled as the code would agree with the
        // scalar path on every lane where the code was 0 or 1.
        //
        // The packing is two multiplies: pairs of code bytes fold into 16 bits
        // of code, then pairs of those into 32. What comes out is four dwords —
        // one per four input bytes — so a `pshufb` gathers their low bytes into
        // the first four. Both weight vectors are little-endian byte patterns,
        // `[1, 4]` and `[1, 16]`, written as the `u32` whose bytes they are.
        let code_bytes = _mm_or_si128(
            _mm_or_si128(
                _mm_and_si128(structural, _mm_set1_epi8(1)),
                _mm_and_si128(quote, _mm_set1_epi8(2)),
            ),
            _mm_and_si128(backslash, _mm_set1_epi8(3)),
        );
        let folded = _mm_maddubs_epi16(code_bytes, _mm_set1_epi32(0x0401_0401));
        let packed = _mm_madd_epi16(folded, _mm_set1_epi32(0x0010_0001));
        let compact = _mm_shuffle_epi8(
            packed,
            // Bytes 0, 4, 8, 12 of `packed` are the first bytes of its four
            // dwords. The rest of the control vector is 0x80, which `pshufb`
            // writes as zero, so the upper bytes come out clear.
            _mm_setr_epi8(0, 4, 8, 12, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1),
        );

        Classified16 {
            code: _mm_cvtsi128_si64(compact) as u32,
            whitespace: mw as u16,
            backslash: mb as u16,
        }
    }
}

/// One 128-bit rectangle: the SSE2 half of [`rect`].
#[inline(always)]
unsafe fn rect128(table: &([u8; 16], [u8; 16]), lo: __m128i, hi: __m128i) -> __m128i {
    // SAFETY: `table` is a pair of 16-byte arrays, so both loads are in
    // bounds by their types, and `lo`/`hi` are masked to `0x0F`.
    unsafe {
        let a = _mm_loadu_si128(table.0.as_ptr() as *const __m128i);
        let b = _mm_loadu_si128(table.1.as_ptr() as *const __m128i);
        _mm_and_si128(_mm_shuffle_epi8(a, lo), _mm_shuffle_epi8(b, hi))
    }
}
