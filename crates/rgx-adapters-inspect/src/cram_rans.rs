// SPDX-License-Identifier: Apache-2.0

//! The rANS 4x8 block codec of CRAM 3.0.
//!
//! The codec is the range-coder variant of Asymmetric Numeral Systems, in
//! the shape CRAM 3.0 gave it: the frame carries the compression order, the
//! compressed and uncompressed sizes, the symbol frequencies and the encoded
//! bytes. Four states are interleaved, and the order-1 variant keeps a
//! frequency table per context byte.
//!
//! The pseudocode this follows is the "CRAM codec specification" of the
//! hts-specs repository (sections 2 and 2.3), which is the document the
//! CRAM 3.0 and 3.1 specifications point at. The frames the tests carry were
//! written by the reference implementation of that codec, the htscodecs
//! library, and not by this reader.

use alloc::vec;
use alloc::vec::Vec;

/// The largest a decoded block may be.
///
/// The size comes from the frame itself, so a corrupt one could ask for a
/// gigabyte before it is refused. The ceiling is the same one the other
/// decompressors of this crate use.
const MAX_OUTPUT: usize = 32 << 20;

/// The number of the frequency slots of a table.
///
/// The specification normalises the frequencies of a table to add up to
/// 4095, and the reference implementation fills the range to 4096. A table
/// that adds up to neither is refused.
const TOTAL: u32 = 4096;

/// The frequency tables of a block, and their cumulative sums.
///
/// The tables are indexed by the context: for order 0 there is one table,
/// and for order 1 there is one per context byte, held at the slot of that
/// byte's value.
#[cfg(feature = "cram")]
struct RansTables {
    /// The frequency of each symbol, per context.
    freq: Vec<[u16; 256]>,
    /// The cumulative frequency of each symbol, per context. The last entry
    /// of a table is the total, so a table has one entry more than it has
    /// symbols.
    cum: Vec<[u16; 257]>,
    /// The last symbol of each table that has a frequency, per context.
    ///
    /// A table whose frequencies add up to 4095 leaves the value 4095
    /// outside its range, and the reference implementation answers for it
    /// with the last symbol of the table.
    last: Vec<u8>,
}

/// A byte reader over the block's bytes.
#[cfg(feature = "cram")]
struct RansReader<'a> {
    data: &'a [u8],
    at: usize,
}

#[cfg(feature = "cram")]
impl<'a> RansReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.data.get(self.at)?;
        self.at += 1;
        Some(b)
    }

    fn u32le(&mut self) -> Option<u32> {
        let bytes = self.data.get(self.at..self.at + 4)?;
        self.at += 4;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// The ITF-8 integer: the number of extra bytes is in the top bits of
    /// the first byte.
    fn itf8(&mut self) -> Option<u32> {
        let b = self.byte()?;
        Some(match b {
            0x80..=0xbf => (u32::from(b & 0x3f) << 8) | u32::from(self.byte()?),
            0xc0..=0xdf => {
                (u32::from(b & 0x1f) << 16)
                    | (u32::from(self.byte()?) << 8)
                    | u32::from(self.byte()?)
            }
            0xe0..=0xef => {
                (u32::from(b & 0x0f) << 24)
                    | (u32::from(self.byte()?) << 16)
                    | (u32::from(self.byte()?) << 8)
                    | u32::from(self.byte()?)
            }
            0xf0..=0xff => {
                (u32::from(b & 0x0f) << 28)
                    | (u32::from(self.byte()?) << 20)
                    | (u32::from(self.byte()?) << 12)
                    | (u32::from(self.byte()?) << 4)
                    | (u32::from(self.byte()?) >> 4)
            }
            _ => u32::from(b),
        })
    }
}

#[cfg(feature = "cram")]
impl RansTables {
    /// Read the frequency tables of the block.
    ///
    /// The order-0 table is a list of symbols and their frequencies, with
    /// the symbols run-length encoded: a counter after the second of two
    /// consecutive symbols says how many more symbols follow without
    /// being written.
    fn read(reader: &mut RansReader<'_>, order: u8) -> Option<RansTables> {
        if order == 0 {
            let mut freq = vec![[0u16; 256]; 1];
            let mut cum = vec![[0u16; 257]; 1];
            let mut last = vec![0u8; 1];
            Self::read_frequencies0(reader, &mut freq[0], &mut cum[0], &mut last[0])?;
            Some(RansTables { freq, cum, last })
        } else {
            // The order-1 tables are a list of contexts, each with its own
            // order-0 table, and the context is the byte itself, so the
            // table of a context is held at the slot of that byte's value.
            let mut sym = reader.byte()?;
            let mut last_sym = sym;
            let mut rle: u32 = 0;
            let mut freq: Vec<[u16; 256]> = vec![[0u16; 256]; 256];
            let mut cum: Vec<[u16; 257]> = vec![[0u16; 257]; 256];
            let mut last: Vec<u8> = vec![0u8; 256];
            loop {
                let mut f = [0u16; 256];
                let mut c = [0u16; 257];
                let mut l = 0u8;
                Self::read_frequencies0(reader, &mut f, &mut c, &mut l)?;
                freq[usize::from(sym)] = f;
                cum[usize::from(sym)] = c;
                last[usize::from(sym)] = l;
                if rle > 0 {
                    rle -= 1;
                    sym = sym.wrapping_add(1);
                } else {
                    sym = reader.byte()?;
                    if sym == last_sym.wrapping_add(1) {
                        rle = u32::from(reader.byte()?);
                    }
                }
                last_sym = sym;
                if sym == 0 {
                    break;
                }
            }
            Some(RansTables { freq, cum, last })
        }
    }

    /// Read one order-0 frequency table: the symbols and their
    /// frequencies, with the run-length encoded symbols.
    fn read_frequencies0(
        reader: &mut RansReader<'_>,
        freq: &mut [u16; 256],
        cum: &mut [u16; 257],
        last: &mut u8,
    ) -> Option<()> {
        let mut sym = reader.byte()?;
        let mut last_sym = sym;
        let mut rle: u32 = 0;
        loop {
            freq[usize::from(sym)] = u16::try_from(reader.itf8()?).ok()?;
            if rle > 0 {
                rle -= 1;
                sym = sym.wrapping_add(1);
            } else {
                sym = reader.byte()?;
                if sym == last_sym.wrapping_add(1) {
                    rle = u32::from(reader.byte()?);
                }
            }
            last_sym = sym;
            if sym == 0 {
                break;
            }
        }
        // The cumulative frequencies: the symbol of a cumulative frequency
        // c is the one with C[s] <= c < C[s+1].
        let mut total: u32 = 0;
        let mut high = 0u8;
        for s in 0..256 {
            cum[s] = u16::try_from(total).ok()?;
            if freq[s] != 0 {
                high = s as u8;
            }
            total += u32::from(freq[s]);
        }
        cum[256] = u16::try_from(total).ok()?;
        *last = high;
        // The frequencies of a table add up to 4095 or to 4096, and a table
        // that adds up to neither is not one this reader can decode: the
        // state would carry a value outside the range of the table.
        if !(TOTAL - 1..=TOTAL).contains(&total) {
            return None;
        }
        Some(())
    }

    /// The symbol a cumulative frequency belongs to.
    ///
    /// `None` when the frequency is outside the range of the table, which
    /// happens when the frame asks for a context it does not carry.
    fn symbol(&self, context: usize, c: u32) -> Option<u8> {
        let table = &self.cum[context];
        let total = u32::from(table[256]);
        if total == 0 {
            // The context has no table: the frame is short of it.
            return None;
        }
        if c >= total {
            // The reference implementation fills the slot past the end of
            // the range with the last symbol of the table, so a table whose
            // frequencies add up to 4095 still answers for the value 4095.
            return Some(self.last[context]);
        }
        // The frequencies are sorted, so a binary search finds the symbol.
        let mut lo = 0usize;
        let mut hi = 255usize;
        while lo < hi {
            let mid = (lo + hi) / 2;
            if u32::from(table[mid + 1]) <= c {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Some(lo as u8)
    }
}

/// Decode a rANS 4x8 block.
///
/// The block's bytes are the codec's own frame: the order, the compressed
/// and uncompressed sizes, the frequency tables and the encoded bytes.
///
/// `None` when the frame is not one this reader can decode: an order the
/// specification does not define, a size that does not match the frame, a
/// table whose frequencies do not add up, or a frame that ends before the
/// bytes it says it holds.
#[cfg(feature = "cram")]
pub(crate) fn decode(block: &[u8]) -> Option<Vec<u8>> {
    let mut reader = RansReader::new(block);
    let order = reader.byte()?;
    // The specification defines two orders and no others.
    if order > 1 {
        return None;
    }
    let compressed_size = reader.u32le()? as usize;
    let data_size = reader.u32le()? as usize;
    // The compressed size covers the frequency table and the encoded bytes,
    // so the frame is nine bytes longer than the size says.
    if compressed_size != block.len().saturating_sub(9) {
        return None;
    }
    // The order-1 variant is not defined for a stream of fewer than four
    // bytes: the four interleaved states would have nothing to decode.
    if order == 1 && data_size < 4 {
        return None;
    }
    if data_size > MAX_OUTPUT {
        return None;
    }
    let tables = RansTables::read(&mut reader, order)?;

    // Four interleaved states, each a 32-bit word read little-endian.
    let mut states = [0u32; 4];
    for state in states.iter_mut() {
        *state = reader.u32le()?;
    }

    let mut out = vec![0u8; data_size];
    if order == 0 {
        for (i, byte) in out.iter_mut().enumerate() {
            let j = i % 4;
            let c = states[j] & 0xfff;
            let s = tables.symbol(0, c)?;
            *byte = s;
            states[j] = advance(states[j], &tables, 0, s);
            states[j] = renorm(&mut reader, states[j])?;
        }
    } else {
        // The order-1 variant splits the data into four fragments, each
        // decoded by its own state, and the last state finishes the
        // remainder when the data is not a multiple of four.
        let mut last = [0u8; 4];
        let fragment = data_size / 4;
        let mut i = 0usize;
        while i < fragment {
            for j in 0..4 {
                let c = states[j] & 0xfff;
                let context = usize::from(last[j]);
                let s = tables.symbol(context, c)?;
                out[i + j * fragment] = s;
                states[j] = advance(states[j], &tables, context, s);
                states[j] = renorm(&mut reader, states[j])?;
                last[j] = s;
            }
            i += 1;
        }
        let mut k = fragment * 4;
        while k < data_size {
            let c = states[3] & 0xfff;
            let context = usize::from(last[3]);
            let s = tables.symbol(context, c)?;
            out[k] = s;
            states[3] = advance(states[3], &tables, context, s);
            states[3] = renorm(&mut reader, states[3])?;
            last[3] = s;
            k += 1;
        }
    }
    Some(out)
}

/// The next state, from the symbol and the state.
#[cfg(feature = "cram")]
fn advance(state: u32, tables: &RansTables, context: usize, symbol: u8) -> u32 {
    let s = usize::from(symbol);
    let f = u32::from(tables.freq[context][s]);
    let c = u32::from(tables.cum[context][s]);
    f * (state >> 12) + (state & 0xfff) - c
}

/// Renormalise the state, reading a byte for every byte the state is
/// short of.
#[cfg(feature = "cram")]
fn renorm(reader: &mut RansReader<'_>, mut state: u32) -> Option<u32> {
    while state < (1 << 23) {
        state = (state << 8) + u32::from(reader.byte()?);
    }
    Some(state)
}

/// The frame of "abracadabra" with order 0, written by the reference
/// implementation of the codec.
///
/// The frame is the nine bytes of the header, the frequency table, the
/// four states and the encoded bytes. The table is the one of the
/// specification's own example: the symbols 'a', 'b', 'c', 'd' and 'r'
/// with the frequencies 1863, 744, 372, 372 and 744, which add up to
/// 4095, and the run-length counter after 'b' says that 'c' and 'd'
/// follow without being written.
#[cfg(all(test, feature = "cram"))]
pub(crate) const ORDER0: &[u8] = &[
    0x00, 0x1f, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x61, 0x87, 0x47, 0x62, 0x02, 0x82, 0xe8,
    0x81, 0x74, 0x81, 0x74, 0x72, 0x82, 0xe8, 0x00, 0xd2, 0x02, 0xa4, 0x42, 0x0d, 0x3a, 0x52, 0x21,
    0xd0, 0xfe, 0xa1, 0x42, 0x40, 0xa6, 0x6a, 0x02,
];

/// The frame of "abracadabra" with order 1, written by the reference
/// implementation.
///
/// The order-1 frame carries a table per context: the context '\0' and
/// then the contexts 'a', 'b', 'c', 'd' and 'r', the last four of them
/// run-length encoded after 'b'.
#[cfg(all(test, feature = "cram"))]
pub(crate) const ORDER1: &[u8] = &[
    0x01, 0x3e, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x61, 0x83, 0xff, 0x63, 0x84, 0x00,
    0x64, 0x00, 0x84, 0x00, 0x72, 0x84, 0x00, 0x00, 0x61, 0x62, 0x89, 0x99, 0x63, 0x01, 0x83, 0x33,
    0x83, 0x33, 0x00, 0x62, 0x02, 0x72, 0x8f, 0xff, 0x00, 0x61, 0x8f, 0xff, 0x00, 0x61, 0x8f, 0xff,
    0x00, 0x72, 0x61, 0x8f, 0xff, 0x00, 0x00, 0xff, 0x52, 0x56, 0x03, 0xff, 0x2b, 0x00, 0x02, 0xff,
    0x23, 0x00, 0x02, 0x59, 0x19, 0x56, 0x03,
];

/// The frame of the specification's own order-1 example, written by the
/// reference implementation.
///
/// The data is 45 bytes, so it is not a multiple of four and the fourth
/// state finishes the remainder: the path the specification calls a
/// design oversight and defines anyway.
#[cfg(all(test, feature = "cram"))]
pub(crate) const ORDER1_REMAINDER: &[u8] = &[
    0x01, 0x37, 0x00, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x61, 0x8f, 0xff, 0x00, 0x61, 0x61,
    0x82, 0x66, 0x62, 0x02, 0x86, 0x66, 0x83, 0x33, 0x84, 0x00, 0x00, 0x62, 0x02, 0x72, 0x8f, 0xff,
    0x00, 0x61, 0x8f, 0xff, 0x00, 0x61, 0x8f, 0xff, 0x00, 0x72, 0x61, 0x8f, 0xff, 0x00, 0x00, 0xe2,
    0x40, 0xa6, 0x3e, 0xe2, 0x40, 0xa6, 0x3e, 0xe2, 0x40, 0xa6, 0x3e, 0xe9, 0xa2, 0xfa, 0x00, 0x27,
];

#[cfg(all(test, feature = "cram"))]
mod tests {
    use super::*;

    /// The frequency table of the specification's own example.
    ///
    /// The example in the codec specification is the string "abracadabra",
    /// whose frequencies normalise to 1863, 744, 372, 372 and 744, and the
    /// table is written with the run-length encoded symbols: after the
    /// second of two consecutive symbols a counter says how many more
    /// symbols follow without being written.
    #[test]
    fn the_frequency_table_of_the_specification_example_reads_back() {
        let bytes: &[u8] = &[
            0x61, 0x87, 0x47, // 'a' <1863>
            0x62, 0x02, 0x82, 0xe8, // 'b' <+2: c,d> <744>
            0x81, 0x74, // 'c' (implicit) <372>
            0x81, 0x74, // 'd' (implicit) <372>
            0x72, 0x82, 0xe8, // 'r' <744>
            0x00, // the end of the table
        ];
        let mut reader = RansReader::new(bytes);
        let mut freq = [0u16; 256];
        let mut cum = [0u16; 257];
        let mut last = 0u8;
        RansTables::read_frequencies0(&mut reader, &mut freq, &mut cum, &mut last).unwrap();
        assert_eq!(
            reader.at,
            bytes.len(),
            "the table did not end where it should"
        );
        assert_eq!(freq[b'a' as usize], 1863);
        assert_eq!(freq[b'b' as usize], 744);
        assert_eq!(freq[b'c' as usize], 372);
        assert_eq!(freq[b'd' as usize], 372);
        assert_eq!(freq[b'r' as usize], 744);
        assert_eq!(freq[b'e' as usize], 0, "'e' is not in the example");
        // The cumulative frequencies: the symbol of a cumulative frequency
        // c is the one with C[s] <= c < C[s+1].
        assert_eq!(cum[b'a' as usize], 0);
        assert_eq!(cum[b'b' as usize], 1863);
        assert_eq!(cum[b'c' as usize], 2607);
        assert_eq!(cum[b'd' as usize], 2979);
        assert_eq!(cum[b'r' as usize], 3351);
        assert_eq!(cum[256], 4095);
        assert_eq!(last, b'r');
    }

    /// The ITF-8 integer: the number of extra bytes is in the top bits of
    /// the first byte, and the value's bits fill the rest of the first byte
    /// and then the extra bytes.
    #[test]
    fn the_itf8_integer_reads_every_width() {
        let cases: &[(&[u8], u32)] = &[
            (&[0x00], 0),
            (&[0x7f], 127),
            (&[0x80, 0x01], 1),
            (&[0xbf, 0xff], 16383),
            (&[0xc0, 0x00, 0x40], 64),
            (&[0xe0, 0x00, 0x00, 0x40], 64),
            (&[0xf0, 0x00, 0x00, 0x00, 0x00], 0),
        ];
        for (bytes, want) in cases {
            let mut reader = RansReader::new(bytes);
            assert_eq!(reader.itf8(), Some(*want), "for {bytes:02x?}");
        }
    }

    /// The frame of the reference implementation decodes back to the bytes
    /// it was written from: order 0, where the four states take every
    /// fourth byte.
    #[test]
    fn the_order0_frame_of_the_reference_implementation_decodes() {
        assert_eq!(
            decode(ORDER0).as_deref(),
            Some(&b"abracadabra"[..]),
            "the order-0 frame is not decoded"
        );
    }

    /// The same frame with order 1: the four states take a quarter of the
    /// data each, and every byte is decoded in the context of the one
    /// before it.
    #[test]
    fn the_order1_frame_of_the_reference_implementation_decodes() {
        assert_eq!(
            decode(ORDER1).as_deref(),
            Some(&b"abracadabra"[..]),
            "the order-1 frame is not decoded"
        );
    }

    /// The order-1 frame whose data is not a multiple of four: the fourth
    /// state finishes the remainder.
    #[test]
    fn the_order1_frame_with_a_remainder_decodes() {
        let want = b"abracadabraabracadabraabracadabraabracadabrad";
        assert_eq!(want.len(), 45);
        assert_eq!(
            decode(ORDER1_REMAINDER).as_deref(),
            Some(&want[..]),
            "the order-1 frame with a remainder is not decoded"
        );
    }

    /// A frame this reader cannot decode is refused, not guessed at: an
    /// order the specification does not define, a compressed size that does
    /// not match the frame, a frame that ends early and a table whose
    /// frequencies do not add up.
    #[test]
    fn a_frame_that_is_not_one_this_reader_can_decode_is_refused() {
        // An order of 2: the specification defines two orders.
        let mut frame = ORDER0.to_vec();
        frame[0] = 2;
        assert!(decode(&frame).is_none(), "the order of 2 was not refused");

        // A compressed size that does not match the frame.
        let mut frame = ORDER0.to_vec();
        frame[1] = 0xff;
        assert!(
            decode(&frame).is_none(),
            "the wrong compressed size was not refused"
        );

        // A frame that ends before the bytes it says it holds.
        let frame = &ORDER0[..ORDER0.len() - 4];
        assert!(decode(frame).is_none(), "the short frame was not refused");

        // A table whose frequencies add up to less than the range.
        let mut frame = ORDER0.to_vec();
        frame[10] = 0x07;
        frame[11] = 0x47;
        assert!(
            decode(&frame).is_none(),
            "the table that does not add up was not refused"
        );

        // A frame that is too short to hold its own header.
        assert!(decode(&[0x00, 0x00]).is_none(), "the stub was not refused");
    }
}
