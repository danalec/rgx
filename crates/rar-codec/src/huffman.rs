// SPDX-License-Identifier: Apache-2.0

//! Canonical Huffman decode tables.
//!
//! Independent reimplementation of the code-length → symbol decoder the RAR
//! compression streams use. The construction is the standard canonical
//! Huffman assignment (count codes per length, assign increasing codes
//! within each length, in symbol order), so it can be written from the
//! algorithm alone. RAR packs codes **most-significant-bit first**, so the
//! lookup indexes the top bits of the peeked window — unlike DEFLATE, which
//! reverses them and indexes the bottom bits.
//!
//! # Throughput
//!
//! `decode` runs once per symbol, tens of thousands of times per member.
//! Three cuts, the same shape `rgx-core`'s own `compress::huffman` uses:
//!
//! - **one peek per symbol.** `decode` takes a 16-bit window from the
//!   reader once, indexes once, and consumes exactly the code length the
//!   entry reports. No bit-at-a-time tree walk, no second peek.
//! - **the table is capped at 12 bits (4096 entries).** A flat table of
//!   width `max_bits` would be 32768 entries for a 15-bit code and would
//!   evict the haystack from cache for no gain: in real tables almost every
//!   symbol's code is shorter than that.
//! - **codes longer than 12 bits fall back to a short overflow list.** They
//!   are rare, and a 4-entry linear scan beats widening the table for them.
//!
//! The width is `min(max_bits, 12)`, not a constant, so a block whose
//! longest code is 7 bits allocates 128 entries.

use alloc::vec;
use alloc::vec::Vec;

use crate::bitreader::BitReader;
use crate::{Error, Result};

/// Longest code the format allows. RAR's tables are built from 4-bit
/// length fields, so a code can never be longer than 15 bits.
const MAX_BITS: u8 = 15;

/// Table width cap. `1 << 12` = 4096 entries of 3 bytes is 12 KB — fits
/// comfortably in L1/L2 alongside the stream, while covering every code of
/// length 12 or less directly.
const TABLE_BITS: u8 = 12;

/// One decoded symbol: the value, and how many bits its code occupies.
#[derive(Debug, Clone, Copy)]
struct Entry {
    symbol: u16,
    bits: u8,
}

/// A code too long for the flat table. `code` is right-aligned (the number
/// a length-`bits` code stands for); the match compares the top `bits` of
/// the peeked window against `code << (16 - bits)`.
#[derive(Debug, Clone, Copy)]
struct LongCode {
    /// Left-aligned within 16 bits: the pattern to compare the window's top
    /// `bits` bits against.
    pattern: u16,
    bits: u8,
    symbol: u16,
}

/// A canonical Huffman lookup table with a short-code flat index.
#[derive(Debug, Clone)]
pub struct DecodeTable {
    /// `1 << table_bits` entries, indexed by the top `table_bits` bits of
    /// the peeked window, right-aligned.
    entries: Vec<Entry>,
    /// Codes longer than `table_bits`, matched in a linear scan. Empty for
    /// the overwhelmingly common case.
    long: Vec<LongCode>,
    table_bits: u8,
}

impl DecodeTable {
    /// Build a decode table from `size` code lengths.
    ///
    /// `bit_length[i]` is the length of symbol `i`'s code in bits; `0`
    /// means the symbol is unused. The usual canonical constraints apply:
    /// the code space must be exactly or under-subscribed (a Kraft sum
    /// above 1 means the codes cannot be uniquely decoded), and no code may
    /// exceed [`MAX_BITS`].
    pub fn build(bit_length: &[u8], size: usize) -> Result<DecodeTable> {
        let size = size.min(bit_length.len());
        if size == 0 {
            return Err(Error::Malformed("huffman table with no symbols"));
        }

        // 1. Count the codes of each length and reject anything illegal.
        let mut counts = [0u16; MAX_BITS as usize + 1];
        let mut max_bits = 0u8;
        for &len in &bit_length[..size] {
            if len > MAX_BITS {
                return Err(Error::Malformed("huffman code longer than 15 bits"));
            }
            if len > 0 {
                counts[len as usize] += 1;
                if len > max_bits {
                    max_bits = len;
                }
            }
        }
        if max_bits == 0 {
            // RAR 5.0 transmits an unused sub-table as an all-zero length
            // array: a block that never draws a low-distance code sends
            // `ldd` as sixteen zeros. That is a legal table with no codes,
            // not a malformed one — it must build so the rest of the block
            // can decode, and it must fail only when a code is drawn from
            // it. (WinRAR-oracle: 10 golden rows pass only with this.)
            return Ok(DecodeTable {
                entries: Vec::new(),
                long: Vec::new(),
                table_bits: 0,
            });
        }

        // 2. Kraft check: every level must leave room for the next. The
        // recurrence is the one DEFLATE uses. Over-subscription would make
        // a bit prefix mean two things, so it is refused rather than
        // silently decoding whichever symbol landed in the slot first.
        let mut left: i32 = 1;
        for &count in counts.iter().take(max_bits as usize + 1).skip(1) {
            left <<= 1;
            left -= i32::from(count);
            if left < 0 {
                return Err(Error::Malformed("huffman code space over-subscribed"));
            }
        }

        // 3. Assign canonical codes. Codes of length L occupy a contiguous
        // run in symbol order; `next_code[L]` is the first code of that
        // length, right-aligned.
        //
        // The index is the code *length*, and it addresses two arrays at
        // once with a one-level offset (`counts[len - 1]` feeding
        // `next_code[len]`). That is the recurrence, not a slice walk, so
        // the range loop is deliberate.
        #[allow(clippy::needless_range_loop)]
        let mut next_code = [0u16; MAX_BITS as usize + 1];
        let mut code = 0u16;
        for len in 1..=max_bits as usize {
            code = (code + counts[len - 1]) << 1;
            next_code[len] = code;
        }

        // 4. Split by length: short codes fill the flat table, long ones go
        // to the overflow list.
        let table_bits = max_bits.min(TABLE_BITS);
        let table_size = 1usize << table_bits;
        let mut entries = vec![Entry { symbol: 0, bits: 0 }; table_size];
        let mut long: Vec<LongCode> = Vec::new();

        for (sym, &len) in bit_length[..size].iter().enumerate() {
            if len == 0 {
                continue;
            }
            let len = len as usize;
            let c = next_code[len];
            next_code[len] = c + 1;

            if len <= table_bits as usize {
                // The code occupies the top `len` bits of the table index.
                // All `1 << (table_bits - len)` indices sharing those bits
                // get the same entry.
                let base = (c as usize) << (table_bits as usize - len);
                let span = 1usize << (table_bits as usize - len);
                for slot in &mut entries[base..base + span] {
                    // Only fill slots still unclaimed; over-subscription was
                    // rejected above, so this is a safety net.
                    if slot.bits == 0 {
                        *slot = Entry {
                            symbol: sym as u16,
                            bits: len as u8,
                        };
                    }
                }
            } else {
                // Left-align the code into 16 bits so the comparison is
                // against the same window `decode` peeks.
                let shift = 16 - len as u32;
                long.push(LongCode {
                    pattern: c << shift,
                    bits: len as u8,
                    symbol: sym as u16,
                });
            }
        }

        Ok(DecodeTable {
            entries,
            long,
            table_bits,
        })
    }

    /// Decode one symbol from `br` and consume exactly its code length.
    ///
    /// A code the table does not define (an unused symbol's bit pattern)
    /// yields `Malformed` rather than a wrong symbol.
    #[inline]
    pub fn decode(&self, br: &mut BitReader) -> Result<u16> {
        // A table built from all-zero lengths has no codes at all; every
        // bit pattern is undefined for it, and there is nothing to index.
        if self.entries.is_empty() {
            return Err(Error::Malformed("huffman code is not defined"));
        }
        let window = br.peek16()?;
        let e = self.entries[(window >> (16 - self.table_bits)) as usize];
        if e.bits != 0 {
            // A slot with `bits != 0` was filled from a short code whose
            // top `bits` bits match this window's top `bits` bits.
            br.skip(u32::from(e.bits));
            return Ok(e.symbol);
        }
        // No short code starts with this prefix. Either a long code does,
        // or the pattern is not a defined code at all.
        for lc in &self.long {
            let mask = if lc.bits == 16 {
                u16::MAX
            } else {
                // Top `lc.bits` of the 16-bit window.
                u16::MAX << (16 - lc.bits)
            };
            if window & mask == lc.pattern {
                br.skip(u32::from(lc.bits));
                return Ok(lc.symbol);
            }
        }
        Err(Error::Malformed("huffman code is not defined"))
    }

    /// Table width actually allocated. Exposed for tests and for callers
    /// that size a scratch buffer from it.
    #[cfg(test)]
    fn table_bits(&self) -> u8 {
        self.table_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn bits_of(code: u16, len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for i in (0..len).rev() {
            out.push(((code >> i) & 1) as u8);
        }
        out
    }

    fn reader_from_bits(bits: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut acc = 0u8;
        let mut n = 0;
        for &b in bits {
            acc = (acc << 1) | b;
            n += 1;
            if n == 8 {
                bytes.push(acc);
                acc = 0;
                n = 0;
            }
        }
        if n > 0 {
            bytes.push(acc << (8 - n));
        }
        bytes
    }

    /// A trivial one-symbol table: the only code is length 1, value 0.
    #[test]
    fn a_single_symbol_table_decodes_that_symbol() {
        let t = DecodeTable::build(&[1], 1).unwrap();
        let bytes = reader_from_bits(&[0]);
        let mut br = BitReader::new(&bytes);
        assert_eq!(t.decode(&mut br).unwrap(), 0);
    }

    /// Two symbols of length 1 fill the whole space and must build.
    #[test]
    fn two_symbols_of_length_one_build() {
        let t = DecodeTable::build(&[1, 1], 2).unwrap();
        let bytes = reader_from_bits(&[0, 1, 1, 0]);
        let mut br = BitReader::new(&bytes);
        assert_eq!(t.decode(&mut br).unwrap(), 0);
        assert_eq!(t.decode(&mut br).unwrap(), 1);
    }

    /// A mixed-length set round-trips in the order the codes appear.
    ///
    /// lengths 2,1,3,3: Kraft = 1/4+1/2+2/8 = 1. Canonical assignment
    /// (`next_code[L] = (next_code[L-1] + count[L-1]) << 1`):
    /// len 1 → symbol 1, code 0
    /// len 2 → symbol 0, code 10
    /// len 3 → symbols 2,3 → codes 110, 111
    #[test]
    fn mixed_code_lengths_round_trip() {
        let lengths = [2u8, 1, 3, 3];
        let t = DecodeTable::build(&lengths, 4).unwrap();
        let expected: &[(u16, &[u8])] =
            &[(1, &[0]), (0, &[1, 0]), (2, &[1, 1, 0]), (3, &[1, 1, 1])];
        let mut bits = Vec::new();
        for (_, b) in expected {
            bits.extend_from_slice(b);
        }
        let bytes = reader_from_bits(&bits);
        let mut br = BitReader::new(&bytes);
        for (sym, _) in expected {
            assert_eq!(t.decode(&mut br).unwrap(), *sym);
        }
    }

    /// Unused symbols must not steal table slots from used ones.
    #[test]
    fn a_zero_length_symbol_is_skipped() {
        let t = DecodeTable::build(&[0, 1, 1], 3).unwrap();
        let bytes = reader_from_bits(&[0, 1]);
        let mut br = BitReader::new(&bytes);
        assert_eq!(t.decode(&mut br).unwrap(), 1);
        assert_eq!(t.decode(&mut br).unwrap(), 2);
    }

    /// Over-subscribed code space is refused.
    #[test]
    fn an_over_subscribed_table_is_refused() {
        assert!(matches!(
            DecodeTable::build(&[1, 1, 1], 3),
            Err(Error::Malformed(_))
        ));
    }

    /// A code longer than the format allows is refused.
    #[test]
    fn a_code_longer_than_fifteen_bits_is_refused() {
        let mut lengths = vec![0u8; 20];
        lengths[0] = 16;
        assert!(matches!(
            DecodeTable::build(&lengths, 20),
            Err(Error::Malformed(_))
        ));
    }

    /// All-zero lengths are a legal table with no codes: RAR 5.0 sends an
    /// unused sub-table that way (a block that never draws a low-distance
    /// or repeat-distance code). It must build so the block parses, and
    /// every decode from it is a refusal — not an up-front error.
    #[test]
    fn an_all_zero_table_builds_and_refuses_every_decode() {
        let t = DecodeTable::build(&[0, 0, 0], 3).unwrap();
        let bytes = reader_from_bits(&[0, 0, 0, 0]);
        let mut br = BitReader::new(&bytes);
        assert!(matches!(t.decode(&mut br), Err(Error::Malformed(_))));
    }

    /// The table width is capped at 12 bits even for a 15-bit code, and the
    /// long code still decodes through the overflow list.
    #[test]
    fn a_code_longer_than_the_table_cap_still_decodes() {
        // One symbol at length 15, one at length 1: Kraft = 1/32768 + 1/2
        // is under-subscribed but buildable.
        //
        // length 1 gets code 0; length 15 gets the next code of length 15.
        let mut lengths = vec![0u8; 4];
        lengths[0] = 1;
        lengths[1] = 15;
        let t = DecodeTable::build(&lengths, 4).unwrap();
        assert_eq!(t.table_bits(), 12);

        // The length-15 code is next_code[15] after the length-1 code 0:
        // codes of length 15 start at 0x4000 (the run after 0 and 1 of the
        // shorter levels). Walk it: bits 0 then 14 more.
        //
        // Rather than compute the exact canonical value by hand here, emit
        // the symbol's own code by construction: symbols in length order.
        // symbol 0 = code 0 (1 bit). symbol 1 = the first length-15 code.
        // Canonical: after len 1, next_code[2]=(0+1)<<1=2 ... next_code[15]
        // = 2^(15-1) = 0x4000.
        let mut bits = bits_of(0x4000, 15);
        let bytes = reader_from_bits(&bits);
        let mut br = BitReader::new(&bytes);
        assert_eq!(t.decode(&mut br).unwrap(), 1);

        // And the short one still works.
        bits = vec![0];
        let bytes = reader_from_bits(&bits);
        let mut br = BitReader::new(&bytes);
        assert_eq!(t.decode(&mut br).unwrap(), 0);
    }

    /// The width tracks the longest code below the cap, not a constant.
    #[test]
    fn the_table_width_tracks_the_longest_code_below_the_cap() {
        let t = DecodeTable::build(&[1, 2, 2], 3).unwrap();
        assert_eq!(t.table_bits(), 2);
        assert_eq!(t.entries.len(), 4);
    }

    /// An undefined bit pattern must not decode to a wrong symbol.
    #[test]
    fn an_undefined_bit_pattern_is_malformed_not_a_lie() {
        let t = DecodeTable::build(&[2, 2, 0], 3).unwrap();
        // 11 is not a defined code.
        let bytes = reader_from_bits(&[1, 1, 0, 0]);
        let mut br = BitReader::new(&bytes);
        assert!(matches!(t.decode(&mut br), Err(Error::Malformed(_))));
    }

    /// The test helpers emit the bits they claim, so the tests above are
    /// not measuring their own fixtures.
    #[test]
    fn the_test_helpers_emit_the_bits_they_claim() {
        assert_eq!(bits_of(0b101, 3), vec![1, 0, 1]);
        assert_eq!(
            reader_from_bits(&[1, 0, 1, 0, 0, 0, 0, 0]),
            vec![0b1010_0000]
        );
    }
}
