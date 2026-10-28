// SPDX-License-Identifier: Apache-2.0

//! Burrows-Wheeler transform and its two companions, move-to-front and
//! zero-run coding, the preprocessing chain the bzip2 codecs sit on.
//!
//! Independent implementations of the published algorithms. The forward
//! transform sorts cyclic shifts with prefix doubling (the standard
//! O(n log n) suffix-array construction); the inverse is the classic
//! last-column walk over the first-column occurrence map, placing each
//! recovered byte at its final index so no reverse pass is needed. The
//! move-to-front coder and the zero-run coder here are the standalone
//! forms the tests hold; the bzip2 bit-stream carries its own run
//! coding around these.

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
            // The byte preceding this rotation, cyclically.
            output.push(data[(start + n - 1) % n]);
        }
        (output, original_index)
    }

    /// Inverse transform: recover the original string from the last
    /// column `data` and the primary index `original_index`.
    ///
    /// Each occurrence of a byte in the last column maps to its slot in
    /// the sorted first column — the standard LF mapping. Walking that
    /// map from the primary index recovers the rotations in reverse
    /// order, so the bytes are placed from the end of the output
    /// forward instead of being pushed and reversed.
    pub fn inverse(&mut self, data: &[u8], original_index: usize) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        let n = data.len();

        // counts[b] = how often byte b occurs; cumsum[b] = its first
        // slot in the sorted first column.
        let mut counts = [0usize; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let mut cumsum = [0usize; 256];
        let mut total = 0;
        for (slot, &count) in counts.iter().enumerate() {
            cumsum[slot] = total;
            total += count;
        }

        // lf[i] = first-column slot of the occurrence that last-column
        // position i stands for.
        let mut seen = [0usize; 256];
        let mut lf = vec![0usize; n];
        for (i, &b) in data.iter().enumerate() {
            let b = b as usize;
            lf[i] = cumsum[b] + seen[b];
            seen[b] += 1;
        }

        // The walk visits rotations in reverse; fill from the back.
        let mut out = vec![0u8; n];
        let mut at = original_index;
        for slot in (0..n).rev() {
            out[slot] = data[at];
            at = lf[at];
        }
        out
    }
}

/// Order of the n cyclic rotations of `data`, by prefix doubling: sort
/// by the 2k-prefix `(rank[i], rank[i + k])` until every rotation has a
/// unique rank. Doubling keeps a highly repetitive input (where naive
/// rotation comparison degenerates to O(n²)) at O(n log n).
fn sorted_rotations(data: &[u8]) -> Vec<usize> {
    let n = data.len();
    let mut order: Vec<usize> = (0..n).collect();
    let mut rank: Vec<u32> = data.iter().map(|&b| u32::from(b)).collect();
    let mut scratch = vec![0u32; n];

    let mut span = 1usize;
    while span < n {
        order.sort_by_key(|&i| (rank[i], rank[(i + span) % n]));

        scratch[order[0]] = 0;
        let mut next = 0u32;
        for pair in 1..n {
            let (a, b) = (order[pair - 1], order[pair]);
            if rank[a] != rank[b] || rank[(a + span) % n] != rank[(b + span) % n] {
                next += 1;
            }
            scratch[b] = next;
        }
        core::mem::swap(&mut rank, &mut scratch);
        if next as usize == n - 1 {
            break;
        }
        span *= 2;
    }
    order
}

/// Move-to-front coding over the byte alphabet.
#[derive(Debug)]
pub struct MtfEncoder {
    /// Symbol list, most recently used first.
    table: [u8; 256],
}

impl Default for MtfEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl MtfEncoder {
    /// An encoder with the alphabet in natural order.
    pub fn new() -> Self {
        let mut table = [0u8; 256];
        for (i, slot) in table.iter_mut().enumerate() {
            *slot = i as u8;
        }
        Self { table }
    }

    /// Encode to the position of each byte in the current list.
    pub fn encode(&mut self, data: &[u8]) -> Vec<u8> {
        data.iter().map(|&b| self.push_front(b)).collect()
    }

    /// Decode positions back to bytes, given a list in the same state
    /// the encoder produced them in.
    pub fn decode(&mut self, data: &[u8]) -> Vec<u8> {
        data.iter().map(|&pos| self.pull_at(pos as usize)).collect()
    }

    /// Back to natural order.
    pub fn reset(&mut self) {
        for (i, slot) in self.table.iter_mut().enumerate() {
            *slot = i as u8;
        }
    }

    /// Emit the position of `b`, then make it the head.
    fn push_front(&mut self, b: u8) -> u8 {
        let at = self.table.iter().position(|&x| x == b).unwrap_or(0);
        self.table.copy_within(0..at, 1);
        self.table[0] = b;
        at as u8
    }

    /// Take the byte at position `at`, then make it the head.
    fn pull_at(&mut self, at: usize) -> u8 {
        let b = self.table[at];
        self.table.copy_within(0..at, 1);
        self.table[0] = b;
        b
    }
}

/// Zero-run coding of a symbol stream.
///
/// A run of `k` (1..=255) zeroes becomes the single byte `k - 1`; a
/// non-zero byte is the escape 255 followed by the byte itself. The
/// form is the standalone companion the tests hold — the bzip2
/// bit-stream carries its own run coding, not this one.
#[derive(Debug, Default)]
pub struct Rle;

impl Rle {
    /// Encode zero runs.
    pub fn encode(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            if data[i] != 0 {
                output.push(255);
                output.push(data[i]);
                i += 1;
                continue;
            }
            let start = i;
            while i < data.len() && data[i] == 0 && i - start < 255 {
                i += 1;
            }
            output.push((i - start - 1) as u8);
        }
        output
    }

    /// Decode zero runs.
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
                output.extend(core::iter::repeat_n(0, data[i] as usize + 1));
                i += 1;
            }
        }
        output
    }
}

#[cfg(test)]
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
}
