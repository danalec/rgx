// SPDX-License-Identifier: Apache-2.0

//! Bit-level reader over a byte slice.
//!
//! Independent reimplementation, written from the bit-serial shape the RAR
//! compression streams require: codes are packed most-significant-bit first
//! into the byte stream, which is what a canonical Huffman decoder needs to
//! peek a fixed-width window and then consume exactly as many bits as the
//! matched code occupies.
//!
//! # Shape
//!
//! Position is two fields, not one offset: `pos` is the byte index and `bit`
//! is how many bits of that byte have already been consumed. That is the
//! layout a nibble-oriented table parser wants, because it can re-synchronise
//! the reader to "start of this nibble" without dividing a bit count back
//! out into (byte, bit). [`bit_pos`] folds them into one absolute count for
//! callers that compare against a limit.
//!
//! # Throughput
//!
//! Huffman decoding is one peek and one skip per symbol, tens of thousands
//! of times per member. The peek is a shift-and-mask over at most five
//! bytes and does not advance; the skip is an add on `bit` with a carry
//! into `pos`. Bounds are checked on every byte read: a compressed stream
//! that runs off the end is `Error::Truncated`, never a panic.

use crate::{Error, Result};

/// Reads bits most-significant-first out of `data`.
pub struct BitReader<'a> {
    data: &'a [u8],
    /// Byte index of the byte currently being consumed.
    pub(crate) pos: usize,
    /// Bits already consumed in `data[pos]`. Always 0..8.
    pub(crate) bit: u8,
}

impl<'a> BitReader<'a> {
    /// A reader positioned at bit 0.
    #[inline]
    pub fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            pos: 0,
            bit: 0,
        }
    }

    /// Absolute bit offset from the start of `data`. Used by callers that
    /// compare against a validity limit or need to know where a code ended.
    #[inline]
    pub fn bit_pos(&self) -> usize {
        self.pos * 8 + self.bit as usize
    }

    /// The next 16 bits without consuming them. Bit 15 of the result is the
    /// next bit to be read; the low bits are zero-padded where fewer than 16
    /// remain. This is the top 16 of the 32-bit window [`peek32`] builds.
    #[inline]
    pub fn peek16(&self) -> Result<u16> {
        Ok((self.peek32()? >> 16) as u16)
    }

    /// The next 32 bits without consuming them. Bit 31 is the next bit to be
    /// read.
    ///
    /// The window is assembled from five bytes — `bit` can be 7, so 32 bits
    /// can span 5 bytes — shifted in as one 40-bit accumulator, then
    /// shifted down so the next unread bit sits at bit 31. Bytes past the
    /// end contribute zeros, which is what a short tail should do: the bits
    /// after the stream are zero, not a special case. The first byte must
    /// exist, or there is nothing to read.
    #[inline]
    pub fn peek32(&self) -> Result<u32> {
        if self.data.get(self.pos).is_none() {
            return Err(Error::Truncated);
        }
        let mut acc: u64 = 0;
        for k in 0..5 {
            let b = self.data.get(self.pos + k).copied().unwrap_or(0);
            acc = (acc << 8) | u64::from(b);
        }
        // acc holds 40 bits, byte0 at 39..32. `bit` of byte0 are already
        // consumed, so the next unread bit is at index 39 - bit. Move it
        // to index 31: shift right by (39 - bit) - 31 = 8 - bit.
        Ok((acc >> (8 - u64::from(self.bit))) as u32)
    }

    /// Consume `n` bits. Skipping past the end is not an error here: the
    /// offset is not dereferenced, and the read that needs the bits will
    /// report `Truncated`.
    #[inline]
    pub fn skip(&mut self, n: u32) {
        let total = self.bit_pos() + n as usize;
        self.pos = total / 8;
        self.bit = (total % 8) as u8;
    }

    /// Read `n` bits (0..=32) and advance past them. Bit 0 of the result is
    /// the *last* bit read, so a 3-bit code `101` comes back as `0b101`.
    #[inline]
    pub fn take(&mut self, n: u32) -> Result<u32> {
        debug_assert!(n <= 32);
        if n == 0 {
            return Ok(0);
        }
        let window = self.peek32()?;
        // The n wanted bits are the top n of the 32-bit window.
        let got = window >> (32 - n);
        self.skip(n);
        Ok(got)
    }

    /// Raw byte at `idx` from the start of the buffer, independent of the
    /// bit cursor.
    ///
    /// The RAR 5.0 table-length preamble is nibble-aligned rather than
    /// bit-aligned, so it walks whole bytes before the bit reader is
    /// re-synchronised to where the next layer begins.
    #[inline]
    pub fn data_byte(&self, idx: usize) -> Option<&u8> {
        self.data.get(idx)
    }

    /// Re-synchronise the cursor to byte `pos`, `bit` bits already
    /// consumed within it. Same convention as the `pos`/`bit` fields.
    #[inline]
    pub fn seek_byte_bit(&mut self, pos: usize, bit: u8) {
        self.pos = pos;
        self.bit = bit & 7;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MSB-first: the top bit of the first byte is the first bit read.
    #[test]
    fn reads_most_significant_bit_first() {
        // 0b1011_0010: bits in stream order 1,0,1,1,0,0,1,0.
        let mut br = BitReader::new(&[0b1011_0010]);
        assert_eq!(br.take(1).unwrap(), 0b1);
        assert_eq!(br.take(1).unwrap(), 0b0);
        assert_eq!(br.take(2).unwrap(), 0b11);
        assert_eq!(br.take(4).unwrap(), 0b0010);
    }

    /// `take` returns the bits as a number, so a 3-bit code reads 0b101.
    #[test]
    fn a_multi_bit_take_is_a_number_not_a_stream() {
        let mut br = BitReader::new(&[0b1010_0000]);
        assert_eq!(br.take(3).unwrap(), 0b101);
        assert_eq!(br.bit_pos(), 3);
    }

    /// `peek` must not advance; `take` after a peek must see the same bits.
    #[test]
    fn peek_does_not_consume() {
        let mut br = BitReader::new(&[0b1100_1100, 0b0101_0101]);
        let first = br.peek16().unwrap();
        assert_eq!(br.bit_pos(), 0);
        assert_eq!(br.take(16).unwrap(), u32::from(first));
    }

    /// A peek from past the end truncates rather than wrapping or panicking.
    #[test]
    fn peek_past_the_end_is_truncated() {
        let mut br = BitReader::new(&[0xff]);
        br.skip(16);
        assert_eq!(br.peek16(), Err(Error::Truncated));
        assert_eq!(br.peek32(), Err(Error::Truncated));
    }

    /// `skip` moves the cursor without touching memory.
    #[test]
    fn skip_advances_the_cursor() {
        let mut br = BitReader::new(&[0xff, 0x00]);
        br.skip(9);
        assert_eq!(br.bit_pos(), 9);
        assert_eq!(br.take(7).unwrap(), 0);
    }

    /// Taking zero bits is a no-op, not an error — a zero-length field
    /// appears in variable-length formats.
    #[test]
    fn take_zero_is_a_no_op() {
        let mut br = BitReader::new(&[0xff]);
        assert_eq!(br.take(0).unwrap(), 0);
        assert_eq!(br.bit_pos(), 0);
    }

    /// Codes that straddle a byte boundary must reassemble correctly.
    #[test]
    fn a_code_spanning_a_byte_boundary_is_read_intact() {
        // bytes 0x0F 0xF0 → bits 0000 1111 1111 0000
        let mut br = BitReader::new(&[0x0F, 0xF0]);
        br.skip(2);
        // next 8 bits are 00 1111 11 = 0b0011_1111
        assert_eq!(br.take(8).unwrap(), 0b0011_1111);
    }

    /// A window larger than the remaining bits is zero-padded on a peek that
    /// still has its first bytes.
    #[test]
    fn peek_is_zero_padded_on_a_short_tail() {
        let br = BitReader::new(&[0b1000_0000]);
        let v = br.peek16().unwrap();
        assert_eq!(v, 0x8000);
    }

    /// The (byte, bit) fields are what a table parser re-synchronises
    /// against, so `bit` must mean "bits already consumed in `pos`".
    #[test]
    fn the_position_fields_mean_what_a_nibble_parser_expects() {
        let mut br = BitReader::new(&[0xff, 0x0f]);
        br.skip(4);
        assert_eq!(br.pos, 0);
        assert_eq!(br.bit, 4);
        br.skip(4);
        assert_eq!(br.pos, 1);
        assert_eq!(br.bit, 0);
    }

    /// Reading at an offset of 7 bits exercises the 5-byte window path.
    #[test]
    fn a_window_starting_at_bit_seven_reads_across_five_bytes() {
        // 5 bytes of 0xFF: whatever the alignment, 32 bits of 1 must come back.
        let mut br = BitReader::new(&[0xff, 0xff, 0xff, 0xff, 0xff]);
        br.skip(7);
        assert_eq!(br.take(32).unwrap(), u32::MAX);
    }
}
