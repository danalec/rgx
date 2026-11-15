// SPDX-License-Identifier: Apache-2.0

//! Canonical Huffman coding primitives shared by the DEFLATE and BZIP2
//! codecs in this tree.
//!
//! Independent reimplementation of the published algorithms: canonical
//! code assignment follows RFC 1951 §3.2.2 (count codes per length, then
//! hand out consecutive values per length); the length-limited code
//! builder is the package-merge algorithm of Larmore & Hirschberg,
//! "A Fast Algorithm for Optimal Length-Limited Huffman Codes" (1990);
//! the bit I/O layer is the DEFLATE convention (LSB-first within bytes)
//! plus the MSB-first variant BZIP2 needs.
//!
//! # Code width
//!
//! Canonical code values for lengths up to 20 bits (the BZIP2 limit) can
//! reach 2^20 − 1, which overflows `u16`.  The code-value type is `u32`
//! throughout.  Any caller that narrows it to `u16` will silently wrap
//! and produce corrupt streams.

use alloc::boxed::Box;
use alloc::collections::BinaryHeap;
use alloc::vec::Vec;
use core::cmp::Ordering;

/// Maximum code length for DEFLATE (RFC 1951 §3.2.7).
pub const MAX_DEFLATE_CODE_LEN: usize = 15;

/// Maximum code length for BZIP2 (libbz2 1.0.8 `BZ_MAX_CODE_LEN`).
pub const MAX_BZIP2_CODE_LEN: usize = 20;

// ── Huffman tree ────────────────────────────────────────────────────────

/// A node in a Huffman tree.  Leaves carry a symbol; internal nodes carry
/// the sum of their children's frequencies.
#[derive(Debug, Clone)]
pub struct HuffmanNode {
    /// Symbol value; `None` for internal nodes.
    pub symbol: Option<u16>,
    /// Frequency / weight.
    pub freq: u64,
    /// Left child (bit 0).
    pub left: Option<Box<HuffmanNode>>,
    /// Right child (bit 1).
    pub right: Option<Box<HuffmanNode>>,
}

impl HuffmanNode {
    /// Create a leaf node.
    pub fn leaf(symbol: u16, freq: u64) -> Self {
        Self {
            symbol: Some(symbol),
            freq,
            left: None,
            right: None,
        }
    }

    /// Create an internal node from two children.
    pub fn internal(left: Box<HuffmanNode>, right: Box<HuffmanNode>) -> Self {
        Self {
            symbol: None,
            freq: left.freq + right.freq,
            left: Some(left),
            right: Some(right),
        }
    }

    /// Whether this is a leaf.
    pub fn is_leaf(&self) -> bool {
        self.symbol.is_some()
    }
}

// Reverse ordering so BinaryHeap acts as a min-heap on `freq`.
impl PartialEq for HuffmanNode {
    fn eq(&self, other: &Self) -> bool {
        self.freq == other.freq
    }
}
impl Eq for HuffmanNode {}
impl PartialOrd for HuffmanNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HuffmanNode {
    fn cmp(&self, other: &Self) -> Ordering {
        other.freq.cmp(&self.freq)
    }
}

/// Build a Huffman tree from per-symbol frequencies (index = symbol).
///
/// Symbols with zero frequency are skipped.  Returns `None` when every
/// frequency is zero.
pub fn build_huffman_tree(freqs: &[u64]) -> Option<Box<HuffmanNode>> {
    let mut heap: BinaryHeap<HuffmanNode> = BinaryHeap::new();
    for (symbol, &freq) in freqs.iter().enumerate() {
        if freq > 0 {
            heap.push(HuffmanNode::leaf(symbol as u16, freq));
        }
    }
    if heap.is_empty() {
        return None;
    }
    while heap.len() > 1 {
        let left = heap.pop()?;
        let right = heap.pop()?;
        heap.push(HuffmanNode::internal(Box::new(left), Box::new(right)));
    }
    heap.pop().map(Box::new)
}

// ── Canonical codes (RFC 1951 §3.2.2) ──────────────────────────────────

/// One entry in a canonical code table.
///
/// `code` is `u32` because a 20-bit canonical code can reach 2^20 − 1,
/// which overflows `u16`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CodeLength {
    /// Code length in bits (0 = unused symbol).
    pub bits: u8,
    /// Canonical code value (valid when `bits > 0`).
    pub code: u32,
}

/// Assign canonical Huffman codes from a code-length table.
///
/// The algorithm is RFC 1951 §3.2.2: count how many codes exist at each
/// length, derive the first code of each length, then hand out consecutive
/// values in symbol order.  `max_bits` bounds the length table; entries
/// longer than `max_bits` are treated as unused.
pub fn build_canonical_codes(lengths: &[u8], max_bits: usize) -> Vec<CodeLength> {
    let n = lengths.len();
    let mut codes = vec![CodeLength::default(); n];

    // Count codes per length.
    let mut bl_count = vec![0u32; max_bits + 1];
    for &len in lengths {
        if len > 0 && (len as usize) <= max_bits {
            bl_count[len as usize] += 1;
        }
    }

    // next_code[L] = smallest code value at length L.
    let mut next_code = vec![0u32; max_bits + 1];
    let mut code: u32 = 0;
    for bits in 1..=max_bits {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
    }

    // Hand out consecutive codes to each symbol.
    for (symbol, &len) in lengths.iter().enumerate() {
        if len > 0 && (len as usize) <= max_bits {
            codes[symbol].bits = len;
            codes[symbol].code = next_code[len as usize];
            next_code[len as usize] += 1;
        }
    }

    codes
}

// ── Bit reversal ───────────────────────────────────────────────────────

/// Reverse the low `len` bits of `code`.
///
/// DEFLATE packs Huffman codes LSB-first while canonical assignment is
/// MSB-first; reversing the code bridges the two.
///
/// Prose, not a runnable example: this module is crate-private, so a
/// doc-test cannot reach it.  The behaviour is asserted by the identical
/// public function in `rgx_core::compress::huffman`, whose doc-test runs.
///
/// ```
/// assert_eq!(rgx_core::compress::huffman::reverse_bits(0b10010001, 8), 0b10001001);
/// ```
pub fn reverse_bits(code: u32, len: u8) -> u32 {
    let mut result = 0u32;
    let mut val = code;
    for _ in 0..len {
        result = (result << 1) | (val & 1);
        val >>= 1;
    }
    result
}

// ── Table-driven decoder ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct DecoderEntry {
    symbol: u16,
    bits: u8,
    valid: bool,
}

/// Fast Huffman decoder using a bit-reversed lookup table.
///
/// Codes shorter than or equal to `table_bits` resolve in one table
/// lookup.  Longer codes fall back to a linear scan over the canonical
/// code table.
#[derive(Debug, Clone)]
pub struct HuffmanDecoder {
    table: Vec<DecoderEntry>,
    table_bits: u8,
    lengths: Vec<u8>,
    codes: Vec<CodeLength>,
}

impl HuffmanDecoder {
    /// Build a decoder from code lengths.
    ///
    /// The lookup table is indexed by the reversed code (LSB-first), so
    /// the prefix-free property holds for the low bits of the peeked
    /// value.  The encoder must write codes via
    /// `write_bits(reverse_bits(code, len), len)`.
    pub fn from_lengths(lengths: &[u8], max_bits: u8) -> Self {
        let table_bits = max_bits.min(12);
        let table_size = 1usize << table_bits;
        let mut table = vec![
            DecoderEntry {
                symbol: 0,
                bits: 0,
                valid: false,
            };
            table_size
        ];

        let codes = build_canonical_codes(lengths, max_bits as usize);

        for (symbol, code_len) in codes.iter().enumerate() {
            if code_len.bits == 0 {
                continue;
            }
            let len = code_len.bits;
            if len > table_bits {
                continue; // slow path only
            }
            let reversed = reverse_bits(code_len.code, len);
            let count = 1usize << (table_bits - len);
            for i in 0..count {
                let idx = (i << len) | (reversed as usize);
                if idx < table_size {
                    table[idx] = DecoderEntry {
                        symbol: symbol as u16,
                        bits: len,
                        valid: true,
                    };
                }
            }
        }

        Self {
            table,
            table_bits,
            lengths: lengths.to_vec(),
            codes,
        }
    }

    /// Decode one symbol from raw LSB-first stream bits.
    ///
    /// `bits` is the value returned by `peek_bits()`.  Returns
    /// `(symbol, bits_consumed)` or `None` when no code matches.
    pub fn decode(&self, bits: u32, available_bits: u8) -> Option<(u16, u8)> {
        // Fast path: primary lookup table.
        let lookup_bits = self.table_bits.min(available_bits);
        let mask = (1u32 << lookup_bits) - 1;
        let idx = (bits & mask) as usize;

        if idx < self.table.len() {
            let entry = &self.table[idx];
            if entry.valid && entry.bits <= available_bits {
                return Some((entry.symbol, entry.bits));
            }
        }

        // Slow path: codes longer than table_bits.  Un-reverse the peeked
        // bits and scan the canonical table.
        let max_check = available_bits.min(15);
        for len in (self.table_bits + 1)..=max_check {
            let mask = (1u32 << len) - 1;
            let stream_val = bits & mask;
            let canonical = reverse_bits(stream_val, len);
            for (symbol, code_info) in self.codes.iter().enumerate() {
                if code_info.bits == len && code_info.code == canonical {
                    return Some((symbol as u16, len));
                }
            }
        }

        None
    }

    /// Bits consumed by the primary lookup table.
    pub fn table_bits(&self) -> u8 {
        self.table_bits
    }
}

// ── Bit writer ─────────────────────────────────────────────────────────

/// Accumulates bits into a byte buffer.
///
/// `write_bits` packs LSB-first (DEFLATE); `write_bits_msb` packs
/// MSB-first (BZIP2).
#[derive(Debug, Clone, Default)]
pub struct BitWriter {
    buffer: Vec<u8>,
    current_byte: u8,
    bit_pos: u8,
}

impl BitWriter {
    /// Create an empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Write `num_bits` bits of `value`, least-significant bit first.
    pub fn write_bits(&mut self, value: u32, num_bits: u8) {
        for i in 0..num_bits {
            let bit = ((value >> i) & 1) as u8;
            self.current_byte |= bit << self.bit_pos;
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.buffer.push(self.current_byte);
                self.current_byte = 0;
                self.bit_pos = 0;
            }
        }
    }

    /// Write `num_bits` bits of `value`, most-significant bit first.
    pub fn write_bits_msb(&mut self, value: u64, num_bits: u8) {
        for i in (0..num_bits).rev() {
            let bit = ((value >> i) & 1) as u8;
            self.current_byte |= bit << self.bit_pos;
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.buffer.push(self.current_byte);
                self.current_byte = 0;
                self.bit_pos = 0;
            }
        }
    }

    /// Flush the partial byte (zero-padded) and return the buffer.
    pub fn finish(mut self) -> Vec<u8> {
        if self.bit_pos > 0 {
            self.buffer.push(self.current_byte);
        }
        self.buffer
    }

    /// Total number of bits written so far.
    pub fn bit_position(&self) -> usize {
        self.buffer.len() * 8 + self.bit_pos as usize
    }
}

// ── Bit reader ─────────────────────────────────────────────────────────

/// Reads bits from a byte slice.
///
/// Tracks position as `(byte_pos, bit_pos)` so nibble-oriented parsers
/// can re-synchronise without folding the two into one count.
#[derive(Debug, Clone)]
pub struct BitReader<'a> {
    data: &'a [u8],
    /// Current byte index.
    pub byte_pos: usize,
    /// Bits consumed in the current byte (0..8).
    pub bit_pos: u8,
}

impl<'a> BitReader<'a> {
    /// Create a reader at the start of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    /// Read `num_bits` bits LSB-first.  Returns `None` on underflow.
    pub fn read_bits(&mut self, num_bits: u8) -> Option<u32> {
        let mut result: u32 = 0;
        for i in 0..num_bits {
            if self.byte_pos >= self.data.len() {
                return None;
            }
            let bit = (self.data[self.byte_pos] >> self.bit_pos) & 1;
            result |= (bit as u32) << i;
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.byte_pos += 1;
                self.bit_pos = 0;
            }
        }
        Some(result)
    }

    /// Peek at `num_bits` bits LSB-first without consuming them.
    pub fn peek_bits(&self, num_bits: u8) -> Option<u32> {
        let mut result: u32 = 0;
        let mut byte_pos = self.byte_pos;
        let mut bit_pos = self.bit_pos;
        for i in 0..num_bits {
            if byte_pos >= self.data.len() {
                return None;
            }
            let bit = (self.data[byte_pos] >> bit_pos) & 1;
            result |= (bit as u32) << i;
            bit_pos += 1;
            if bit_pos == 8 {
                byte_pos += 1;
                bit_pos = 0;
            }
        }
        Some(result)
    }

    /// Advance past `num_bits` bits without returning them.
    pub fn skip_bits(&mut self, num_bits: u8) {
        for _ in 0..num_bits {
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.byte_pos += 1;
                self.bit_pos = 0;
            }
        }
    }

    /// Read `num_bits` bits MSB-first (BZIP2 convention).
    pub fn read_bits_msb(&mut self, num_bits: u8) -> Option<u32> {
        let mut result: u32 = 0;
        for i in (0..num_bits).rev() {
            if self.byte_pos >= self.data.len() {
                return None;
            }
            let bit = (self.data[self.byte_pos] >> self.bit_pos) & 1;
            result |= (bit as u32) << i;
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.byte_pos += 1;
                self.bit_pos = 0;
            }
        }
        Some(result)
    }

    /// Read up to 57 bits MSB-first into a `u64` (BZIP2 large values).
    pub fn read_bits_msb_64(&mut self, num_bits: u8) -> Option<u64> {
        let mut result: u64 = 0;
        for i in (0..num_bits).rev() {
            if self.byte_pos >= self.data.len() {
                return None;
            }
            let bit = (self.data[self.byte_pos] >> self.bit_pos) & 1;
            result |= (bit as u64) << i;
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.byte_pos += 1;
                self.bit_pos = 0;
            }
        }
        Some(result)
    }

    /// Advance to the next byte boundary.
    pub fn align(&mut self) {
        if self.bit_pos > 0 {
            self.byte_pos += 1;
            self.bit_pos = 0;
        }
    }

    /// Whether any unconsumed bytes remain.
    pub fn has_more(&self) -> bool {
        self.byte_pos < self.data.len()
    }

    /// Unconsumed bytes (partial current byte counts as one).
    pub fn remaining_bytes(&self) -> usize {
        self.data.len().saturating_sub(self.byte_pos)
    }

    /// Unconsumed bits including those in the partially-read byte.
    pub fn remaining_bits(&self) -> usize {
        self.remaining_bytes() * 8 - self.bit_pos as usize
    }
}

// ── Package-merge (Larmore & Hirschberg 1990) ─────────────────────────

/// Build optimal length-limited Huffman code lengths.
///
/// Minimises `sum(freq[i] * len[i])` subject to `len[i] <= max_bits`.
/// Uses the package-merge algorithm: `max_bits − 1` rounds of packaging
/// and merging, then a final selection of `2(n−1)` items whose symbol
/// multiplicity gives each code length.
///
/// The merge step must combine the packages with the **weight-sorted**
/// leaf list, not the symbol-index-ordered one.  If the leaves enter the
/// merge unsorted the resulting list is unsorted, `truncate` drops the
/// wrong coins, and the cost is no longer optimal.
pub fn package_merge_lengths(freqs: &[u64], max_bits: u8) -> Vec<u8> {
    let n = freqs.len();
    if n == 0 {
        return Vec::new();
    }

    // Active symbols (positive frequency).
    let symbols: Vec<usize> = (0..n).filter(|&i| freqs[i] > 0).collect();
    let num_active = symbols.len();

    if num_active == 0 {
        return vec![0u8; n];
    }
    if num_active == 1 {
        let mut lengths = vec![0u8; n];
        lengths[symbols[0]] = 1;
        return lengths;
    }
    if num_active == 2 {
        let mut lengths = vec![0u8; n];
        lengths[symbols[0]] = 1;
        lengths[symbols[1]] = 1;
        return lengths;
    }

    let max_bits = max_bits.max(2) as usize;

    #[derive(Clone)]
    struct Item {
        weight: u64,
        symbols: Vec<usize>,
    }

    // Leaves sorted by weight — the invariant the merge relies on.
    let mut leaves: Vec<Item> = symbols
        .iter()
        .map(|&s| Item {
            weight: freqs[s],
            symbols: alloc::vec![s],
        })
        .collect();
    leaves.sort_by_key(|item| item.weight);

    // Start with the sorted leaves.
    let mut list: Vec<Item> = leaves.clone();
    let keep = 2 * (num_active - 1);

    for _round in 1..max_bits {
        // Package: pair consecutive items of the (sorted) list.
        let mut packages: Vec<Item> = Vec::new();
        let mut i = 0;
        while i + 1 < list.len() {
            let mut syms = list[i].symbols.clone();
            syms.extend_from_slice(&list[i + 1].symbols);
            packages.push(Item {
                weight: list[i].weight + list[i + 1].weight,
                symbols: syms,
            });
            i += 2;
        }

        // Merge sorted leaves with sorted packages (both ascending).
        let mut merged = Vec::with_capacity(leaves.len() + packages.len());
        let (mut oi, mut pi) = (0usize, 0usize);
        while oi < leaves.len() && pi < packages.len() {
            if leaves[oi].weight <= packages[pi].weight {
                merged.push(leaves[oi].clone());
                oi += 1;
            } else {
                merged.push(packages[pi].clone());
                pi += 1;
            }
        }
        merged.extend_from_slice(&leaves[oi..]);
        merged.extend_from_slice(&packages[pi..]);

        merged.truncate(keep);
        list = merged;
    }

    // Final truncation (already at `keep` after the loop, but be explicit).
    list.truncate(keep);

    // Code length = number of final items containing the symbol.
    let mut lengths = vec![0u8; n];
    for item in &list {
        for &sym in &item.symbols {
            lengths[sym] += 1;
        }
    }

    // Safety net: if the Kraft sum exceeds 2^max_bits (a complete code
    // always has Kraft ≤ 1), clamp to the limit.
    let mut kraft = 0i64;
    for &l in &lengths {
        if l > 0 {
            kraft += 1i64 << (max_bits - l as usize);
        }
    }
    if kraft > (1i64 << max_bits) {
        for l in lengths.iter_mut() {
            if *l > max_bits as u8 {
                *l = max_bits as u8;
            }
        }
    }

    lengths
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_canonical_codes() {
        // RFC 1951 §3.2.2 worked example.
        let lengths = [3, 3, 3, 3, 3, 2, 4, 4];
        let codes = build_canonical_codes(&lengths, 15);

        assert_eq!(codes[0].bits, 3);
        assert_eq!(codes[0].code, 0b010);
        assert_eq!(codes[1].bits, 3);
        assert_eq!(codes[1].code, 0b011);
        assert_eq!(codes[5].bits, 2);
        assert_eq!(codes[5].code, 0b00);
        assert_eq!(codes[6].bits, 4);
        assert_eq!(codes[6].code, 0b1110);
    }

    #[test]
    fn test_bit_writer_reader() {
        let mut writer = BitWriter::new();
        writer.write_bits(0b101, 3);
        writer.write_bits(0b11011, 5);
        let data = writer.finish();

        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bits(3), Some(0b101));
        assert_eq!(reader.read_bits(5), Some(0b11011));
    }

    #[test]
    fn test_bit_writer_reader_msb() {
        let mut writer = BitWriter::new();
        writer.write_bits_msb(0b101, 3);
        writer.write_bits_msb(0b11011, 5);
        let data = writer.finish();

        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bits_msb(3), Some(0b101));
        assert_eq!(reader.read_bits_msb(5), Some(0b11011));
    }

    #[test]
    fn test_huffman_decoder() {
        let lengths = [2, 2, 2, 2, 0, 0, 0, 0];
        let codes = build_canonical_codes(&lengths, 2);
        let decoder = HuffmanDecoder::from_lengths(&lengths, 2);

        assert_eq!(codes[0].code, 0);
        assert_eq!(codes[1].code, 1);
        assert_eq!(codes[2].code, 2);
        assert_eq!(codes[3].code, 3);

        for sym in 0u16..4 {
            let code = codes[sym as usize].code;
            let bits = codes[sym as usize].bits;
            let rev = reverse_bits(code, bits);

            let mut writer = BitWriter::new();
            writer.write_bits(rev, bits);
            let data = writer.finish();

            let reader = BitReader::new(&data);
            let stream_bits = reader.peek_bits(bits).unwrap();
            assert_eq!(stream_bits, rev);

            let (decoded, consumed) = decoder
                .decode(stream_bits, bits)
                .unwrap_or_else(|| panic!("Failed to decode symbol {sym}"));
            assert_eq!(decoded, sym, "Symbol {sym} roundtrip failed");
            assert_eq!(consumed, bits);
        }
    }
}

#[cfg(test)]
mod package_merge_tests {
    use super::*;

    #[test]
    fn test_package_merge_basic() {
        let freqs = [10u64, 5, 3, 2];
        let lengths = package_merge_lengths(&freqs, 3);

        for &l in &lengths {
            assert!(l <= 3, "Code length {l} exceeds max 3");
        }
        let kraft: i64 = lengths
            .iter()
            .filter(|&&l| l > 0)
            .map(|&l| 1i64 << (3 - l as usize))
            .sum();
        assert!(kraft <= 8, "Kraft inequality violated: {kraft}");
    }

    #[test]
    fn test_package_merge_two_symbols() {
        let freqs = [100u64, 50];
        let lengths = package_merge_lengths(&freqs, 15);
        assert_eq!(lengths[0], 1);
        assert_eq!(lengths[1], 1);
    }

    #[test]
    fn test_package_merge_empty() {
        let lengths = package_merge_lengths(&[], 15);
        assert!(lengths.is_empty());
    }

    #[test]
    fn test_package_merge_single() {
        let freqs = [0u64, 0, 42, 0];
        let lengths = package_merge_lengths(&freqs, 11);
        assert_eq!(lengths[2], 1);
        assert_eq!(lengths[0], 0);
    }

    #[test]
    fn test_package_merge_better_than_clamping() {
        let freqs = [100u64, 50, 25, 12, 6, 3, 2, 1, 1];
        let lengths_pm = package_merge_lengths(&freqs, 4);

        for &l in &lengths_pm {
            assert!(l <= 4 && l > 0, "Invalid length {l}");
        }
        let kraft: i64 = lengths_pm
            .iter()
            .filter(|&&l| l > 0)
            .map(|&l| 1i64 << (4 - l as usize))
            .sum();
        assert!(kraft <= 16, "Kraft violated: {kraft}");

        let total_cost: u64 = freqs
            .iter()
            .zip(lengths_pm.iter())
            .map(|(&f, &l)| f * l as u64)
            .sum();
        assert!(total_cost < 800, "Cost {total_cost} too high");
    }
}

#[cfg(test)]
mod defect_tests {
    use super::*;

    /// Unsorted frequencies: symbol-index order is far from weight order.
    /// `keep = 2(n-1)` actually drops items once the merged list exceeds
    /// that bound.  Assert the three invariants the algorithm owes:
    /// max length, Kraft, and cost no worse than greedy clamp.
    #[test]
    fn package_merge_unsorted_freqs_respects_max_bits_and_cost() {
        let freqs = [
            1000u64, 1, 500, 2, 800, 3, 600, 4, 900, 5, 700, 6, 400, 7, 300, 8,
        ];
        let max_bits = 5u8;
        let lengths = package_merge_lengths(&freqs, max_bits);

        for (i, &f) in freqs.iter().enumerate() {
            assert!(lengths[i] > 0, "symbol {i} (freq {f}) got length 0");
            assert!(
                lengths[i] <= max_bits,
                "symbol {i} length {} exceeds max_bits {max_bits}",
                lengths[i]
            );
        }

        let kraft: u64 = lengths
            .iter()
            .map(|&l| 1u64 << (max_bits as usize - l as usize))
            .sum();
        assert!(
            kraft <= (1u64 << max_bits as usize),
            "Kraft sum {kraft} exceeds 2^{max_bits}"
        );

        let pm_cost: u64 = freqs
            .iter()
            .zip(lengths.iter())
            .map(|(&f, &l)| f * l as u64)
            .sum();
        let clamp_cost: u64 = freqs.iter().map(|&f| f * max_bits as u64).sum();
        assert!(
            pm_cost <= clamp_cost,
            "package-merge cost {pm_cost} worse than greedy clamp {clamp_cost}"
        );
    }

    /// A 20-bit canonical code can exceed u16::MAX.  One length-1 code
    /// plus 257 length-20 codes pushes `next_code[20]` to 2^19.
    #[test]
    fn canonical_codes_20bit_length_exceeds_u16() {
        let mut lengths = vec![0u8; 258];
        lengths[0] = 1;
        for l in lengths.iter_mut().skip(1) {
            *l = 20;
        }
        let codes = build_canonical_codes(&lengths, 20);
        assert_eq!(
            codes[1].code, 524288,
            "first length-20 code should be 524288, got {}",
            codes[1].code
        );
        for i in 2..258 {
            assert!(
                codes[i].code > codes[i - 1].code,
                "code[{i}]={} should be > code[{}]={}",
                codes[i].code,
                i - 1,
                codes[i - 1].code
            );
        }
        assert_eq!(
            codes[257].code, 524544,
            "last length-20 code should be 524544, got {}",
            codes[257].code
        );
    }

    /// Package-merge on unsorted frequencies must beat the greedy clamp
    /// and satisfy all three constraints even with 8 symbols and max_bits=4
    /// (the minimum where `keep = 2(n-1)` drops items).
    #[test]
    fn package_merge_eight_unsorted_symbols() {
        let freqs = [50u64, 1, 200, 3, 100, 2, 80, 4];
        let max_bits = 4u8;
        let lengths = package_merge_lengths(&freqs, max_bits);

        for (i, &f) in freqs.iter().enumerate() {
            assert!(lengths[i] > 0, "symbol {i} (freq {f}) got length 0");
            assert!(
                lengths[i] <= max_bits,
                "symbol {i} length {} exceeds max_bits {max_bits}",
                lengths[i]
            );
        }

        let kraft: u64 = lengths
            .iter()
            .map(|&l| 1u64 << (max_bits as usize - l as usize))
            .sum();
        assert!(
            kraft <= (1u64 << max_bits as usize),
            "Kraft sum {kraft} exceeds 2^{max_bits}"
        );

        let pm_cost: u64 = freqs
            .iter()
            .zip(lengths.iter())
            .map(|(&f, &l)| f * l as u64)
            .sum();
        let clamp_cost: u64 = freqs.iter().map(|&f| f * max_bits as u64).sum();
        assert!(
            pm_cost <= clamp_cost,
            "package-merge cost {pm_cost} worse than greedy clamp {clamp_cost}"
        );
    }
}
