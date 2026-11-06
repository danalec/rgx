// SPDX-License-Identifier: Apache-2.0

//! The Burrows-Wheeler transform and the two coders that follow it in the
//! bzip2 pipeline: move-to-front and zero-run coding.
//!
//! Independent implementations of the published algorithms, written from
//! the transform definition rather than from any implementation's source.
//! The forward transform sorts cyclic rotations; the inverse is the
//! last-column walk over the first-column occurrence map, which places
//! each recovered byte at its final index and so needs no reverse pass.
//! The move-to-front coder and the zero-run coder here are the standalone
//! forms the tests hold; the bzip2 bit-stream carries its own run coding
//! around these.

use alloc::vec;
use alloc::vec::Vec;

/// Burrows-Wheeler transform of cyclic rotations.
#[derive(Debug, Default)]
pub struct Bwt;

impl Bwt {
    /// A transform processor. Stateless; kept a struct so callers do not
    /// change shape if a transform ever needs scratch space.
    pub fn new() -> Self {
        Self
    }

    /// Forward transform: `(transformed, original_index)`, where
    /// `transformed[i]` is the byte preceding rotation `i` in sorted
    /// order and `original_index` is where the original string sits
    /// among those sorted rotations.
    pub fn transform(&mut self, data: &[u8]) -> (Vec<u8>, usize) {
        if data.is_empty() {
            return (Vec::new(), 0);
        }
        let n = data.len();
        let order = sorted_rotations(data);

        let mut original_index = 0;
        let mut output = Vec::with_capacity(n);
        for (i, &start) in order.iter().enumerate() {
            if start == 0 {
                original_index = i;
            }
            // The byte preceding rotation `start` is the last column entry
            // of row `i`.
            output.push(data[(start + n - 1) % n]);
        }
        (output, original_index)
    }

    /// Inverse transform of `data` (the last column) given where the
    /// original string sat in the sorted order. An `original_index` past
    /// the end cannot place the original string, and is answered with
    /// empty output rather than a panic: the index is caller-supplied and
    /// a malformed one must not be a crash.
    pub fn inverse(&mut self, data: &[u8], original_index: usize) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        let n = data.len();
        if original_index >= n {
            return Vec::new();
        }
        // bzip2 caps the BWT block at 900,000 bytes, so a u32 row index
        // covers every block this transform is ever handed and halves the
        // per-block heap against usize.
        debug_assert!(n <= u32::MAX as usize);

        // The first column is `data` sorted. `starts[b]` is where byte
        // `b`'s run begins there; `rank[i]` is which occurrence of
        // `data[i]` row `i` is in that run. The map `i ->
        // starts[data[i]] + rank[i]` is the LF mapping: one step from a
        // last-column position to the first-column position of the same
        // rotation.
        let mut starts = [0u32; 256];
        for &b in data {
            starts[b as usize] += 1;
        }
        let mut total = 0u32;
        for slot in starts.iter_mut() {
            let count = *slot;
            *slot = total;
            total += count;
        }
        let mut seen = [0u32; 256];
        let mut map = vec![0u32; n];
        for (i, &b) in data.iter().enumerate() {
            let b = b as usize;
            map[i] = starts[b] + seen[b];
            seen[b] += 1;
        }

        // Walk the map, writing each recovered byte at its final index:
        // the output is recovered back-to-front this way, so no separate
        // reverse pass is needed.
        let mut output = vec![0u8; n];
        let mut row = original_index as u32;
        let mut slot = n;
        while slot > 0 {
            slot -= 1;
            output[slot] = data[row as usize];
            row = map[row as usize];
        }
        output
    }
}

/// Order the cyclic rotations of `data` by their full rotation, by
/// prefix doubling: rotations are ranked on their first `k` bytes, and
/// the rank of a `2k`-prefix is the pair `(rank[i], rank[i+k])`. Each
/// refinement is two stable counting sorts — one per half of the pair —
/// so the whole sort stays O(n log n) even on the highly repetitive
/// inputs where a naive rotation comparison degenerates to O(n²).
fn sorted_rotations(data: &[u8]) -> Vec<usize> {
    let n = data.len();
    // Rank of a 1-prefix is the byte itself; order on it.
    let mut rank: Vec<u32> = data.iter().map(|&b| b as u32).collect();
    let mut order: Vec<usize> = (0..n).collect();
    count_sort_by(&mut order, |i| rank[i], 256);
    // Make the 1-prefix ranks dense before the first doubling step.
    rerank(&mut rank, &order, n);

    let mut k = 1usize;
    while k < n {
        if rank[order[n - 1]] == (n - 1) as u32 {
            break; // every rotation has a distinct rank
        }
        // Pair (rank[i], rank[i+k]) orders the 2k-prefix. The second
        // half sorts first so a stable sort on the first half leaves the
        // pairs ascending.
        count_sort_by(&mut order, |i| rank[(i + k) % n], n + 1);
        count_sort_by(&mut order, |i| rank[i], n + 1);
        rerank(&mut rank, &order, k);
        k *= 2;
    }
    order
}

/// Stable counting sort of `order` on `key(rotation)`.
fn count_sort_by(order: &mut [usize], key: impl Fn(usize) -> u32, range: usize) {
    let n = order.len();
    let mut counts = vec![0u32; range];
    for &i in order.iter() {
        counts[key(i) as usize] += 1;
    }
    let mut total = 0u32;
    for c in counts.iter_mut() {
        let count = *c;
        *c = total;
        total += count;
    }
    let mut sorted = vec![0usize; n];
    for &i in order.iter() {
        let slot = &mut counts[key(i) as usize];
        sorted[*slot as usize] = i;
        *slot += 1;
    }
    order.copy_from_slice(&sorted);
}

/// Re-rank the rotations in `order` on their `2*half`-prefixes, where
/// `rank` already ranks the `half`-prefixes. `half == n` compares only
/// `rank[i]` against itself and densifies the initial ranks. When all
/// prefixes are distinct the highest rank is `n - 1` and the caller stops.
fn rerank(rank: &mut Vec<u32>, order: &[usize], half: usize) {
    let n = order.len();
    let mut next = vec![0u32; n];
    next[order[0]] = 0;
    let mut level = 0u32;
    for w in order.windows(2) {
        let (a, b) = (w[0], w[1]);
        if rank[a] != rank[b] || rank[(a + half) % n] != rank[(b + half) % n] {
            level += 1;
        }
        next[b] = level;
    }
    *rank = next;
}

/// Move-to-front (MTF) encoding.
#[derive(Debug)]
pub struct MtfEncoder {
    /// Symbol table (initialized 0-255).
    table: [u8; 256],
}

impl Default for MtfEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl MtfEncoder {
    /// Create a new MTF encoder.
    pub fn new() -> Self {
        let mut table = [0u8; 256];
        for (i, slot) in table.iter_mut().enumerate() {
            *slot = i as u8;
        }
        Self { table }
    }

    /// Encode data using MTF: each byte becomes its index in the
    /// current table, then moves to the front of the table.
    pub fn encode(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for &b in data {
            let pos = self.table.iter().position(|&x| x == b).unwrap_or(0);
            self.move_to_front(pos);
            self.table[0] = b;
            out.push(pos as u8);
        }
        out
    }

    /// Decode MTF-encoded data: each index becomes the byte at that
    /// table position, which then moves to the front.
    pub fn decode(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for &pos in data {
            let b = self.table[pos as usize];
            self.move_to_front(pos as usize);
            self.table[0] = b;
            out.push(b);
        }
        out
    }

    /// Reset the symbol table.
    pub fn reset(&mut self) {
        for (i, slot) in self.table.iter_mut().enumerate() {
            *slot = i as u8;
        }
    }

    /// Shift `table[0..pos]` up one slot so `pos` can fall to the front.
    fn move_to_front(&mut self, pos: usize) {
        self.table.copy_within(0..pos, 1);
    }
}

/// Run-length encoding of zero runs, the coder bzip2 applies after MTF.
#[derive(Debug, Default)]
pub struct Rle;

impl Rle {
    /// Encode runs of zeros.
    ///
    /// A zero run uses values 0-254 (run length minus one); a non-zero
    /// byte is an escape (255) followed by the byte.
    pub fn encode(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            if data[i] == 0 {
                let mut count = 0usize;
                while i < data.len() && data[i] == 0 && count < 255 {
                    count += 1;
                    i += 1;
                }
                output.push((count - 1) as u8);
            } else {
                output.push(255);
                output.push(data[i]);
                i += 1;
            }
        }
        output
    }

    /// Decode runs of zeros. A trailing escape with nothing after it
    /// simply ends the stream.
    pub fn decode(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            if data[i] == 255 {
                i += 1;
                if i < data.len() {
                    output.push(data[i]);
                    i += 1;
                }
            } else {
                let count = (data[i] as usize) + 1;
                output.extend(core::iter::repeat_n(0, count));
                i += 1;
            }
        }
        output
    }
}

#[cfg(all(test, feature = "bwt"))]
mod tests {
    use super::*;

    #[test]
    fn test_bwt_simple() {
        let mut bwt = Bwt::new();
        let data = b"banana";
        let (transformed, idx) = bwt.transform(data);

        let inverse = bwt.inverse(&transformed, idx);
        assert_eq!(data.as_slice(), inverse.as_slice());
    }

    #[test]
    fn test_bwt_empty() {
        let mut bwt = Bwt::new();
        let (transformed, idx) = bwt.transform(b"");
        assert!(transformed.is_empty());
        assert_eq!(idx, 0);
    }

    #[test]
    fn test_bwt_single() {
        let mut bwt = Bwt::new();
        let (transformed, idx) = bwt.transform(b"a");
        assert_eq!(transformed, b"a");
        assert_eq!(idx, 0);

        let inverse = bwt.inverse(&transformed, idx);
        assert_eq!(inverse, b"a");
    }

    #[test]
    fn test_bwt_repeated() {
        let mut bwt = Bwt::new();
        let data = b"aaaa";
        let (transformed, idx) = bwt.transform(data);

        let inverse = bwt.inverse(&transformed, idx);
        assert_eq!(data.as_slice(), inverse.as_slice());
    }

    #[test]
    fn test_mtf_roundtrip() {
        let mut encoder = MtfEncoder::new();
        let data = b"banana";
        let encoded = encoder.encode(data);

        encoder.reset();
        let decoded = encoder.decode(&encoded);

        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_mtf_zeros() {
        let mut encoder = MtfEncoder::new();
        let data = b"\x00\x00\x00abc";
        let encoded = encoder.encode(data);

        // First zero is at position 0, subsequent zeros should produce small values
        assert_eq!(encoded[0], 0);

        encoder.reset();
        let decoded = encoder.decode(&encoded);
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_rle_encode() {
        let data = [0, 0, 0, 5, 6];
        let encoded = Rle::encode(&data);
        // 3 zeros -> 2, then escape + 5, escape + 6
        assert_eq!(encoded, [2, 255, 5, 255, 6]);
    }

    #[test]
    fn test_rle_decode() {
        let encoded = [2, 255, 5, 255, 6];
        let decoded = Rle::decode(&encoded);
        assert_eq!(decoded, [0, 0, 0, 5, 6]);
    }

    #[test]
    fn test_rle_roundtrip() {
        let data = [0, 0, 0, 5, 6, 0, 0, 7];
        let encoded = Rle::encode(&data);
        let decoded = Rle::decode(&encoded);
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_bwt_mtf_rle_pipeline() {
        // Test the full BZIP2 preprocessing pipeline
        let mut bwt = Bwt::new();
        let mut mtf = MtfEncoder::new();

        let data = b"banana banana banana";
        let (bwt_out, idx) = bwt.transform(data);
        let mtf_out = mtf.encode(&bwt_out);
        let rle_out = Rle::encode(&mtf_out);

        // Reverse
        let rle_in = Rle::decode(&rle_out);
        mtf.reset();
        let mtf_in = mtf.decode(&rle_in);
        let final_out = bwt.inverse(&mtf_in, idx);

        assert_eq!(data.as_slice(), final_out.as_slice());
    }

    /// The four-hundred-byte scale is where a doubling sort that
    /// re-ranked wrong still round-trips small inputs: the inverse is
    /// checking the transform's own permutation, not the sort's
    /// correctness, until the rotations outnumber the loop steps.
    #[test]
    fn transform_and_inverse_agree_at_pipeline_scale() {
        let mut bwt = Bwt::new();
        let mut data = Vec::new();
        for i in 0..200u32 {
            data.push((i % 7) as u8);
            data.extend_from_slice(b"abcabc");
            data.push((i % 251) as u8);
        }
        let (transformed, idx) = bwt.transform(&data);
        assert_eq!(transformed.len(), data.len());
        assert!(idx < data.len());
        let inverse = bwt.inverse(&transformed, idx);
        assert_eq!(data, inverse);
    }

    /// `inverse` takes a caller-supplied row index. One past the end is
    /// malformed input, not a crash: a pack reader that hands the
    /// transform a corrupt block index must not take the process down.
    #[test]
    fn inverse_refuses_a_row_index_past_the_end() {
        let mut bwt = Bwt::new();
        assert!(bwt.inverse(b"abc", 3).is_empty());
        assert!(bwt.inverse(b"abc", usize::MAX).is_empty());
        // In range, the transform still works.
        let (transformed, idx) = bwt.transform(b"abc");
        assert_eq!(bwt.inverse(&transformed, idx), b"abc".to_vec());
    }

    /// Decoders must survive arbitrary bytes: panic is the failure mode
    /// fuzzing is for, Err and empty output are fine.
    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: Vec<(&str, Vec<u8>)> = alloc::vec![
            ("empty", alloc::vec![]),
            ("one", alloc::vec![0]),
            ("escape_tail", alloc::vec![255]),
            ("mixed", alloc::vec![0, 0, 255, 65, 1, 255]),
            ("long", alloc::vec![0, 1, 255, 255, 0, 200]),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 2000, "bwt", |data| {
            let _ = Rle::decode(data);
            let mut mtf = MtfEncoder::new();
            let _ = mtf.decode(data);
            let mut bwt = Bwt::new();
            let idx = if data.is_empty() {
                0
            } else {
                data[0] as usize % (data.len() + 1)
            };
            let _ = bwt.inverse(data, idx);
            let _ = bwt.inverse(data, data.len());
        });
    }
}
