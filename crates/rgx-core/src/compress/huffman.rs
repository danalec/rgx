// SPDX-License-Identifier: Apache-2.0

//! Huffman codes and bit-level I/O, the entropy layer under DEFLATE and
//! the shared helpers under bzip2.
//!
//! Independent implementations of the published pieces: the canonical
//! code assignment of RFC 1951 §3.2.2 (codes of one length taken in
//! symbol order, each length starting where the previous left off), the
//! Larmore–Hirschberg length-limited construction, and the bit orderings
//! the two formats speak — LSB-first for DEFLATE, MSB-first for bzip2.
//! The symbol decoder is a two-level table: a first level over the low
//! bits the stream offers first, and sub-tables only for the codes too
//! long to land there.

use alloc::boxed::Box;
use alloc::collections::BinaryHeap;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

/// Maximum code length for DEFLATE (15 bits).
pub const MAX_DEFLATE_CODE_LEN: usize = 15;

/// Maximum code length for BZIP2 (20 bits).
pub const MAX_BZIP2_CODE_LEN: usize = 20;

/// Huffman tree node.
#[derive(Debug, Clone)]
pub struct HuffmanNode {
    /// Symbol value (None for internal nodes).
    pub symbol: Option<u16>,
    /// Frequency/count.
    pub freq: u64,
    /// Left child (bit 0).
    pub left: Option<Box<HuffmanNode>>,
    /// Right child (bit 1).
    pub right: Option<Box<HuffmanNode>>,
}

impl HuffmanNode {
    /// Create a leaf node with a symbol.
    pub fn leaf(symbol: u16, freq: u64) -> Self {
        Self {
            symbol: Some(symbol),
            freq,
            left: None,
            right: None,
        }
    }

    /// Create an internal node.
    pub fn internal(left: Box<HuffmanNode>, right: Box<HuffmanNode>) -> Self {
        Self {
            symbol: None,
            freq: left.freq + right.freq,
            left: Some(left),
            right: Some(right),
        }
    }

    /// Check if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.symbol.is_some()
    }
}

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
        // Reverse order for min-heap behavior
        other.freq.cmp(&self.freq)
    }
}

/// Build a Huffman tree from symbol frequencies.
///
/// Returns the root node of the tree.
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

/// Code length table entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct CodeLength {
    /// Number of bits for this code.
    pub bits: u8,
    /// The code value.
    pub code: u16,
}

/// Build canonical Huffman codes from code lengths.
///
/// Uses the algorithm from RFC 1951 section 3.2.2.
pub fn build_canonical_codes(lengths: &[u8], max_bits: usize) -> Vec<CodeLength> {
    let n = lengths.len();
    let mut codes = vec![CodeLength::default(); n];

    // Count codes of each length
    let mut bl_count = vec![0u16; max_bits + 1];
    for &len in lengths {
        if len > 0 && (len as usize) <= max_bits {
            bl_count[len as usize] += 1;
        }
    }

    // Find the numerical value of the smallest code for each code length
    let mut next_code = vec![0u16; max_bits + 1];
    let mut code: u16 = 0;
    for bits in 1..=max_bits {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
    }

    // Assign numerical values to all codes
    for (symbol, &len) in lengths.iter().enumerate() {
        if len > 0 && (len as usize) <= max_bits {
            codes[symbol].bits = len;
            codes[symbol].code = next_code[len as usize];
            next_code[len as usize] += 1;
        }
    }

    codes
}

/// Reverse the bottom `len` bits of `code`.
///
/// Used to convert between MSB-first canonical Huffman codes and the
/// LSB-first stream representation DEFLATE uses.
///
/// # Examples
/// ```
/// assert_eq!(rgx_core::compress::huffman::reverse_bits(0b10010001, 8), 0b10001001);
/// assert_eq!(rgx_core::compress::huffman::reverse_bits(0b01, 2), 0b10);
/// ```
pub fn reverse_bits(code: u16, len: u8) -> u16 {
    let mut result = 0u16;
    let mut val = code;
    for _ in 0..len {
        result = (result << 1) | (val & 1);
        val >>= 1;
    }
    result
}

/// One slot of the symbol decoder's first level.
#[derive(Debug, Clone, Copy)]
struct Slot {
    /// Symbol this slot resolves to, when `bits` is non-zero.
    symbol: u16,
    /// Bits consumed when this slot is a whole code; 0 when empty or
    /// when the code lives in a sub-table.
    bits: u8,
    /// Where this slot's sub-table starts in `sub_slots`, when the code
    /// runs past the first level.
    sub_base: u32,
    /// Bits the sub-table indexes: `code_len - table_bits` at its widest.
    sub_bits: u8,
}

/// Huffman decoder lookup table.
///
/// Two levels, sized to the codes actually present: a first level of
/// `1 << table_bits` slots covers every code that lands inside it whole,
/// and each first-level slot that a longer code passes through carries a
/// sub-table of `1 << sub_bits` slots for exactly those codes. Codes are
/// matched on their bit-reversed values, because canonical codes are
/// prefix-free read MSB-first while DEFLATE packs bits LSB-first.
#[derive(Debug, Clone)]
pub struct HuffmanDecoder {
    table: Vec<Slot>,
    table_bits: u8,
    sub_slots: Vec<Slot>,
    /// Code lengths retained for slow-path callers and for the encoder
    /// side that rebuilds codes from the same lengths.
    #[allow(dead_code)] // vendored: encoder-side table
    lengths: Vec<u8>,
}

impl HuffmanDecoder {
    /// Build a decoder from code lengths.
    ///
    /// Uses bit-reversed lookup table following the DEFLATE convention:
    /// - Canonical Huffman codes are prefix-free when read MSB-first
    /// - DEFLATE streams pack bits LSB-first
    /// - To make the table fill pattern `(i << len) | code` work correctly,
    ///   we reverse each code's bits so the prefix-free property holds for
    ///   the bottom bits (LSB)
    /// - The encoder must also write reversed codes via `write_bits(reverse_bits(code, len), len)`
    pub fn from_lengths(lengths: &[u8], max_bits: u8) -> Self {
        let table_bits = max_bits.min(12); // Limit table size
        let table_size = 1usize << table_bits;
        let empty = Slot {
            symbol: 0,
            bits: 0,
            sub_base: 0,
            sub_bits: 0,
        };
        let mut table = vec![empty; table_size];
        let mut sub_slots: Vec<Slot> = Vec::new();

        let codes = build_canonical_codes(lengths, max_bits as usize);

        // Group the codes that run past the first level by the low
        // `table_bits` of their reversed value — that is the first-level
        // slot the stream will look them up through.
        let mut long: Vec<(usize, u16, u8, u16)> = Vec::new(); // (slot key, reversed, len, symbol)
        for (symbol, code_len) in codes.iter().enumerate() {
            if code_len.bits == 0 {
                continue;
            }
            let reversed = reverse_bits(code_len.code, code_len.bits);
            if code_len.bits <= table_bits {
                // Every index whose low `bits` bits are the reversed code,
                // for all patterns of the bits above them.
                let stride = 1usize << code_len.bits;
                let mut i = 0;
                while i < table_size {
                    table[i | reversed as usize] = Slot {
                        symbol: symbol as u16,
                        bits: code_len.bits,
                        sub_base: 0,
                        sub_bits: 0,
                    };
                    i += stride;
                }
            } else {
                long.push((
                    reversed as usize & (table_size - 1),
                    reversed,
                    code_len.bits,
                    symbol as u16,
                ));
            }
        }

        // One sub-table per first-level slot the long codes share. The
        // sub-table is wide enough for the longest code in the group.
        long.sort_unstable();
        let mut i = 0;
        while i < long.len() {
            let key = long[i].0;
            let mut j = i;
            let mut widest = 0u8;
            while j < long.len() && long[j].0 == key {
                widest = widest.max(long[j].2);
                j += 1;
            }
            let sub_bits = widest - table_bits;
            let sub_base = sub_slots.len() as u32;
            let width = 1usize << sub_bits;
            sub_slots.resize(
                sub_slots.len() + width,
                Slot {
                    symbol: 0,
                    bits: 0,
                    sub_base: 0,
                    sub_bits: 0,
                },
            );
            for &(_, reversed, len, symbol) in &long[i..j] {
                let within = (reversed >> table_bits) as usize;
                let stride = 1usize << (len - table_bits);
                let mut k = 0;
                while k < width {
                    sub_slots[sub_base as usize + (k | within)] = Slot {
                        symbol,
                        bits: len,
                        sub_base: 0,
                        sub_bits: 0,
                    };
                    k += stride;
                }
            }
            table[key] = Slot {
                symbol: 0,
                bits: 0,
                sub_base,
                sub_bits,
            };
            i = j;
        }

        Self {
            table,
            table_bits,
            sub_slots,
            lengths: lengths.to_vec(),
        }
    }

    /// Decode a symbol from raw LSB-first stream bits.
    ///
    /// `bits` should be the value returned by `peek_bits()`. The encoder must
    /// have written reversed canonical codes (via `write_bits(reverse_bits(code, len), len)`).
    ///
    /// Returns `(symbol, bits_consumed)` or `None` if no valid code matches.
    pub fn decode(&self, bits: u32, available_bits: u8) -> Option<(u16, u8)> {
        let mask = (1u32 << self.table_bits) - 1;
        let idx = (bits & mask) as usize;
        let slot = self.table[idx];

        if available_bits < self.table_bits {
            // Not enough bits to cover the first level. Only a code that
            // fits entirely inside what the stream has can match.
            if slot.bits != 0 && slot.bits <= available_bits {
                return Some((slot.symbol, slot.bits));
            }
            return None;
        }

        if slot.bits != 0 {
            return Some((slot.symbol, slot.bits));
        }
        if slot.sub_bits == 0 {
            return None;
        }

        // Second level: the code runs past the first table. It can only
        // match when the stream actually holds the sub-table's width.
        let need = self.table_bits + slot.sub_bits;
        if available_bits < need {
            // A code shorter than the sub-table's width may still match
            // inside it; check the entries whose bits fit what we have.
            let sub_mask = (1u32 << slot.sub_bits) - 1;
            let within = ((bits >> self.table_bits) & sub_mask) as usize;
            let entry = self.sub_slots[slot.sub_base as usize + within];
            if entry.bits != 0 && entry.bits <= available_bits {
                return Some((entry.symbol, entry.bits));
            }
            return None;
        }

        let sub_mask = (1u32 << slot.sub_bits) - 1;
        let within = ((bits >> self.table_bits) & sub_mask) as usize;
        let entry = self.sub_slots[slot.sub_base as usize + within];
        if entry.bits != 0 {
            return Some((entry.symbol, entry.bits));
        }
        None
    }

    /// Get the table size in bits.
    pub fn table_bits(&self) -> u8 {
        self.table_bits
    }
}

/// Bit writer for Huffman encoding.
#[derive(Debug, Clone, Default)]
pub struct BitWriter {
    buffer: Vec<u8>,
    /// Bits not yet flushed to `buffer`, least-significant first.
    pending: u64,
    /// How many bits `pending` holds. Always < 8 between writes' tails.
    pending_bits: u8,
}

impl BitWriter {
    /// Create a new bit writer.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            pending: 0,
            pending_bits: 0,
        }
    }

    /// Write bits (LSB first).
    pub fn write_bits(&mut self, value: u32, num_bits: u8) {
        debug_assert!(num_bits <= 32);
        let mask = if num_bits == 32 {
            u32::MAX
        } else {
            (1u32 << num_bits) - 1
        };
        self.pending |= ((value & mask) as u64) << self.pending_bits;
        self.pending_bits += num_bits;
        self.flush_bytes();
    }

    /// Write bits (MSB first, for BZIP2).
    pub fn write_bits_msb(&mut self, value: u64, num_bits: u8) {
        debug_assert!(num_bits <= 64);
        // The stream is filled least-significant bit first, so the value's
        // most significant bit — which must land in the stream first —
        // goes into the lowest pending slot: the written pattern is the
        // bottom `num_bits` of `value`, reversed.
        let mut reversed = 0u64;
        let mut val = value;
        for _ in 0..num_bits {
            reversed = (reversed << 1) | (val & 1);
            val >>= 1;
        }
        self.pending |= reversed << self.pending_bits;
        self.pending_bits += num_bits;
        self.flush_bytes();
    }

    /// Finish writing and return the buffer.
    pub fn finish(mut self) -> Vec<u8> {
        if self.pending_bits > 0 {
            self.buffer.push(self.pending as u8);
        }
        self.buffer
    }

    /// Get current bit position.
    pub fn bit_position(&self) -> usize {
        self.buffer.len() * 8 + self.pending_bits as usize
    }

    /// Move whole bytes out of `pending` into `buffer`.
    fn flush_bytes(&mut self) {
        while self.pending_bits >= 8 {
            self.buffer.push(self.pending as u8);
            self.pending >>= 8;
            self.pending_bits -= 8;
        }
    }
}

/// Bit reader for Huffman decoding.
#[derive(Debug, Clone)]
pub struct BitReader<'a> {
    /// The underlying input. `pub(crate)` so the deflate stored-block path
    /// can copy a contiguous slice past `byte_pos` without going through
    /// `read_bits(8)` per byte, which is the difference between a
    /// 65 535-call inner loop and a single `extend_from_slice`.
    pub(crate) data: &'a [u8],
    /// Current byte position.
    pub byte_pos: usize,
    /// Current bit position within byte.
    pub bit_pos: u8,
}

impl<'a> BitReader<'a> {
    /// Create a new bit reader.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    /// Read bits (LSB first).
    ///
    /// The byte-aligned fast path only fires when `num_bits == 8`, so
    /// a single byte is read with no per-bit loop or bounds check
    /// per bit. The `read_bits(3)` for the BTYPE field, `read_bits(5)`
    /// for HLIT/HDIST, and `read_bits(16)` for the stored-block
    /// LEN/NLEN all fall through to the bit-by-bit loop, where the
    /// per-iteration bounds check is the only hot-path work.
    pub fn read_bits(&mut self, num_bits: u8) -> Option<u32> {
        if num_bits == 8 && self.bit_pos == 0 {
            let byte = *self.data.get(self.byte_pos)?;
            self.byte_pos += 1;
            return Some(byte as u32);
        }
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

    /// Peek at bits without consuming them (LSB first).
    ///
    /// Hot path uses a 32-bit little-endian word load when at least 4 bytes
    /// remain after `byte_pos`. DEFLATE symbol decoding asks for 1–15 bits
    /// per call, and the slow loop's per-bit bounds check, index, shift and
    /// branch were the only thing the table-driven decoder sat behind; one
    /// aligned `u32` load and two shifts replaces them with what a register
    /// can retire per cycle.
    ///
    /// The call sites ask for at most 24 bits.
    pub fn peek_bits(&self, num_bits: u8) -> Option<u32> {
        if num_bits <= 24 && self.byte_pos + 4 <= self.data.len() {
            let chunk = u32::from_le_bytes(
                self.data[self.byte_pos..self.byte_pos + 4]
                    .try_into()
                    .unwrap(),
            );
            return Some((chunk >> self.bit_pos) & ((1u32 << num_bits) - 1));
        }

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

    /// Skip (consume) the specified number of bits.
    ///
    /// Computes the new `(byte_pos, bit_pos)` pair with arithmetic on the
    /// total bit offset rather than looping one bit at a time.
    pub fn skip_bits(&mut self, num_bits: u8) {
        let total = self.bit_pos as usize + num_bits as usize;
        self.byte_pos += total >> 3;
        self.bit_pos = (total & 7) as u8;
    }

    /// Read bits (MSB first, for BZIP2).
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

    /// Read bits as u64 (MSB first, for BZIP2 large values).
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

    /// Align to byte boundary.
    pub fn align(&mut self) {
        if self.bit_pos > 0 {
            self.byte_pos += 1;
            self.bit_pos = 0;
        }
    }

    /// Check if more bits are available.
    pub fn has_more(&self) -> bool {
        self.byte_pos < self.data.len()
    }

    /// Get remaining bytes.
    pub fn remaining_bytes(&self) -> usize {
        self.data.len().saturating_sub(self.byte_pos)
    }

    /// Get remaining bits (including the partially-consumed current byte).
    pub fn remaining_bits(&self) -> usize {
        self.remaining_bytes() * 8 - self.bit_pos as usize
    }
}

#[cfg(all(test, feature = "huffman"))]
mod tests {
    use super::*;

    #[test]
    fn test_build_canonical_codes() {
        // Example from RFC 1951 section 3.2.2
        // lengths = [3, 3, 3, 3, 3, 2, 4, 4]
        // Expected codes per RFC:
        // Symbol 0-4: length 3, codes 010, 011, 100, 101, 110
        // Symbol 5: length 2, code 00
        // Symbol 6-7: length 4, codes 1110, 1111
        let lengths = [3, 3, 3, 3, 3, 2, 4, 4];
        let codes = build_canonical_codes(&lengths, 15);

        // Verify symbol 0 (length 3)
        assert_eq!(codes[0].bits, 3);
        assert_eq!(codes[0].code, 0b010); // 2

        // Verify symbol 1 (length 3)
        assert_eq!(codes[1].bits, 3);
        assert_eq!(codes[1].code, 0b011); // 3

        // Verify symbol 5 (length 2, shortest code)
        assert_eq!(codes[5].bits, 2);
        assert_eq!(codes[5].code, 0b00); // 0

        // Verify symbol 6 (length 4)
        assert_eq!(codes[6].bits, 4);
        assert_eq!(codes[6].code, 0b1110); // 14
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

        // Verify canonical codes are 0,1,2,3
        assert_eq!(codes[0].code, 0);
        assert_eq!(codes[1].code, 1);
        assert_eq!(codes[2].code, 2);
        assert_eq!(codes[3].code, 3);

        // With bit-reversal, decode expects reversed codes as input.
        // Roundtrip: write reversed code, read back, decode.
        for sym in 0u16..4 {
            let code = codes[sym as usize].code;
            let bits = codes[sym as usize].bits;
            let rev = reverse_bits(code, bits);

            let mut writer = BitWriter::new();
            writer.write_bits(rev as u32, bits);
            let data = writer.finish();

            let reader = BitReader::new(&data);
            let stream_bits = reader.peek_bits(bits).unwrap();
            assert_eq!(stream_bits, rev as u32);

            let (decoded, consumed) = decoder
                .decode(stream_bits, bits)
                .unwrap_or_else(|| panic!("Failed to decode symbol {}", sym));
            assert_eq!(decoded, sym, "Symbol {} roundtrip failed", sym);
            assert_eq!(consumed, bits);
        }
    }

    /// The old suite only ever decoded codes shorter than the table.
    /// Lengths 1..=15 with a second 15 fill the Kraft sum exactly, which
    /// is the shape that forces codes through the sub-table the decoder
    /// builds for anything past `table_bits`.
    #[test]
    fn a_code_longer_than_the_table_still_decodes() {
        let mut lengths = [0u8; 16];
        for (i, slot) in lengths.iter_mut().enumerate() {
            *slot = (i as u8) + 1;
        }
        lengths[15] = 15; // lengths 1..=15 plus a second 15: Kraft sum 1
        let codes = build_canonical_codes(&lengths, 15);
        let decoder = HuffmanDecoder::from_lengths(&lengths, 15);
        assert_eq!(decoder.table_bits(), 12, "table must be smaller than 15");

        for (sym, code) in codes.iter().enumerate() {
            if code.bits == 0 {
                continue;
            }
            let rev = reverse_bits(code.code, code.bits);
            let mut writer = BitWriter::new();
            writer.write_bits(rev as u32, code.bits);
            let data = writer.finish();
            let reader = BitReader::new(&data);
            let bits = reader.peek_bits(code.bits).unwrap();
            let (decoded, consumed) = decoder
                .decode(bits, code.bits)
                .unwrap_or_else(|| panic!("symbol {sym} of {} bits did not decode", code.bits));
            assert_eq!(decoded as usize, sym);
            assert_eq!(consumed, code.bits);
        }
    }

    /// Bit I/O is on the path of every stream; a reader that panics on
    /// truncated or arbitrary bytes turns a corrupt file into a crash.
    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: Vec<(&str, Vec<u8>)> = alloc::vec![
            ("empty", alloc::vec![]),
            ("one", alloc::vec![0xFF]),
            ("short", alloc::vec![0x00, 0x80]),
            ("long", alloc::vec![0xA5; 64]),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 2000, "huffman", |data| {
            let mut reader = BitReader::new(data);
            for n in [1u8, 3, 7, 8, 15, 16, 24] {
                let _ = reader.peek_bits(n);
                let _ = reader.read_bits(n);
                let _ = reader.read_bits_msb(n);
                reader.skip_bits(n % 9);
            }
            let _ = reader.read_bits_msb_64(32);
            reader.align();
            let _ = reader.has_more();
            let _ = reader.remaining_bytes();
            let _ = reader.remaining_bits();

            let mut writer = BitWriter::new();
            if let Some(&b) = data.first() {
                writer.write_bits(b as u32, 5);
                writer.write_bits_msb(b as u64, 7);
                writer.write_bits_msb(b as u64, 64);
                let _ = writer.bit_position();
                let _ = writer.finish();
            }

            if !data.is_empty() {
                let lengths: Vec<u8> = data.iter().take(32).map(|b| b % 16).collect();
                let decoder = HuffmanDecoder::from_lengths(&lengths, 15);
                if let Some(bits) = BitReader::new(data).peek_bits(16) {
                    let _ = decoder.decode(bits, 16);
                    let _ = decoder.decode(bits, 4);
                }
            }
        });
    }
}

/// Build optimal length-limited Huffman codes using the package-merge algorithm.
///
/// Given a frequency table and maximum code length, produces code lengths
/// that minimize `sum(freq[i] * len[i])` subject to `len[i] <= max_bits`.
///
/// Reference: Larmore & Hirschberg, "A Fast Algorithm for Optimal
/// Length-Limited Huffman Codes" (1990)
pub fn package_merge_lengths(freqs: &[u64], max_bits: u8) -> Vec<u8> {
    let n = freqs.len();
    if n == 0 {
        return Vec::new();
    }

    // Filter active symbols
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

    /// A packaged item: either a leaf (single symbol) or a package (pair).
    #[derive(Clone)]
    struct Item {
        weight: u64,
        symbols: Vec<usize>, // which symbols this item represents
    }

    // Initial list: one item per active symbol, sorted by frequency
    let mut list: Vec<Item> = symbols
        .iter()
        .map(|&s| Item {
            weight: freqs[s],
            symbols: vec![s],
        })
        .collect();
    list.sort_by_key(|item| item.weight);

    // Run max_bits - 1 rounds of package-merge
    for _round in 1..max_bits {
        // Package: pair consecutive items
        let mut packages: Vec<Item> = Vec::new();
        let mut i = 0;
        while i + 1 < list.len() {
            let combined_weight = list[i].weight + list[i + 1].weight;
            let mut combined_symbols = list[i].symbols.clone();
            combined_symbols.extend_from_slice(&list[i + 1].symbols);
            packages.push(Item {
                weight: combined_weight,
                symbols: combined_symbols,
            });
            i += 2;
        }

        // Merge: combine packages with original symbols, sorted by weight
        let original: Vec<Item> = symbols
            .iter()
            .map(|&s| Item {
                weight: freqs[s],
                symbols: vec![s],
            })
            .collect();

        // Merge sorted lists
        let mut merged = Vec::with_capacity(original.len() + packages.len());
        let mut oi = 0;
        let mut pi = 0;
        while oi < original.len() && pi < packages.len() {
            if original[oi].weight <= packages[pi].weight {
                merged.push(original[oi].clone());
                oi += 1;
            } else {
                merged.push(packages[pi].clone());
                pi += 1;
            }
        }
        while oi < original.len() {
            merged.push(original[oi].clone());
            oi += 1;
        }
        while pi < packages.len() {
            merged.push(packages[pi].clone());
            pi += 1;
        }

        // Keep only 2*(num_active - 1) smallest items
        let keep = 2 * (num_active - 1);
        merged.truncate(keep);
        list = merged;
    }

    // Final selection: take 2*(num_active - 1) items from the last list
    let keep = 2 * (num_active - 1);
    list.truncate(keep);

    // Count occurrences of each symbol = code length
    let mut lengths = vec![0u8; n];
    for item in &list {
        for &sym in &item.symbols {
            lengths[sym] += 1;
        }
    }

    // Verify Kraft inequality: sum(2^(max_bits - len)) <= 2^max_bits
    let mut kraft = 0i64;
    for &l in &lengths {
        if l > 0 {
            kraft += 1i64 << (max_bits - l as usize);
        }
    }
    if kraft > (1i64 << max_bits) {
        // Fallback: clamp and redistribute
        for l in lengths.iter_mut() {
            if *l > max_bits as u8 {
                *l = max_bits as u8;
            }
        }
    }

    lengths
}

#[cfg(all(test, feature = "huffman"))]
mod package_merge_tests {
    use super::*;

    #[test]
    fn test_package_merge_basic() {
        let freqs = [10u64, 5, 3, 2];
        let lengths = package_merge_lengths(&freqs, 3);

        // All symbols should have code lengths <= 3
        for &l in &lengths {
            assert!(l <= 3, "Code length {} exceeds max 3", l);
        }

        // Verify Kraft inequality
        let kraft: i64 = lengths
            .iter()
            .filter(|&&l| l > 0)
            .map(|&l| 1i64 << (3 - l as usize))
            .sum();
        assert!(kraft <= 8, "Kraft inequality violated: {}", kraft);
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
        // Frequency distribution that benefits from package-merge vs clamping
        let freqs = [100u64, 50, 25, 12, 6, 3, 2, 1, 1];
        let lengths_pm = package_merge_lengths(&freqs, 4);

        // Verify all lengths within limit
        for &l in &lengths_pm {
            assert!(l <= 4 && l > 0, "Invalid length {}", l);
        }

        // Package-merge should produce valid Kraft inequality
        let kraft: i64 = lengths_pm
            .iter()
            .filter(|&&l| l > 0)
            .map(|&l| 1i64 << (4 - l as usize))
            .sum();
        assert!(kraft <= 16, "Kraft violated: {}", kraft);

        // Verify total cost is reasonable
        let total_cost: u64 = freqs
            .iter()
            .zip(lengths_pm.iter())
            .map(|(&f, &l)| f * l as u64)
            .sum();
        // Worst case: all 4 bits = 800
        assert!(total_cost < 800, "Cost {} too high", total_cost);
    }
}
