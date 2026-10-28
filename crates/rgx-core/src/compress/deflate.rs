// SPDX-License-Identifier: Apache-2.0

//! DEFLATE compression (RFC 1951).
//!
//! Independent reimplementation of the published block format: stored
//! blocks, the fixed Huffman tables the RFC spells out, dynamic Huffman
//! headers, and the length/distance code tables that map match shapes to
//! symbols. Written from the RFC's description of the bitstream rather
//! than from any implementation's source. The LZ77 stage lives in
//! [`super::lz77`]; this module turns its tokens into bits and back.
//!
//! The decoder is the half every .zip, .gz and PNG payload goes through,
//! so it treats its input as untrusted: a reserved block type is an
//! error, a length code outside the table is an error, and the output
//! ceiling is credited as bytes are emitted.

use super::cap::Bounded;
use super::error::{CompressError, CompressResult};
use super::huffman::{
    build_canonical_codes, reverse_bits, BitReader, BitWriter, HuffmanDecoder, MAX_DEFLATE_CODE_LEN,
};
use super::lz77::{Lz77Decoder, Lz77Encoder, Lz77Token};
use alloc::vec::Vec;

/// Compression level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressionLevel {
    /// No compression (store).
    None = 0,
    /// Fast compression (level 1-3).
    Fast = 3,
    /// Default compression (level 6).
    #[default]
    Default = 6,
    /// Best compression (level 9).
    Best = 9,
}

impl From<u8> for CompressionLevel {
    fn from(level: u8) -> Self {
        match level {
            0 => Self::None,
            1..=3 => Self::Fast,
            4..=7 => Self::Default,
            _ => Self::Best,
        }
    }
}

// Fixed Huffman code lengths for literals/lengths (RFC 1951 section 3.2.6)
const fn fixed_literal_lengths() -> [u8; 288] {
    let mut lengths = [0u8; 288];
    let mut i = 0;
    while i < 144 {
        lengths[i] = 8;
        i += 1;
    }
    while i < 256 {
        lengths[i] = 9;
        i += 1;
    }
    while i < 280 {
        lengths[i] = 7;
        i += 1;
    }
    while i < 288 {
        lengths[i] = 8;
        i += 1;
    }
    lengths
}

// Fixed Huffman code lengths for distances
const fn fixed_distance_lengths() -> [u8; 32] {
    [5u8; 32]
}

// Length code base values and extra bits (RFC 1951)
const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];

const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

// Distance code base values and extra bits
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];

const DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// How many blocks one stream may hold before the decoder calls it a
/// loop. A stream of empty non-final blocks is otherwise unbounded work
/// for zero output.
const MAX_BLOCKS: u32 = 100_000;

/// DEFLATE encoder.
#[derive(Debug)]
pub struct DeflateEncoder {
    /// Compression level.
    level: CompressionLevel,
    /// LZ77 encoder.
    lz77: Lz77Encoder,
}

impl DeflateEncoder {
    /// Create a new DEFLATE encoder with default compression.
    pub fn new() -> Self {
        Self::with_level(6)
    }

    /// Create a DEFLATE encoder with a specific level (0-9).
    pub fn with_level(level: u8) -> Self {
        Self {
            level: CompressionLevel::from(level),
            lz77: Lz77Encoder::with_level(level),
        }
    }

    /// Encode data using DEFLATE.
    pub fn encode(&mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            // Empty data: one final fixed block holding only EOB.
            let mut writer = BitWriter::new();
            writer.write_bits(1, 1); // BFINAL = 1
            writer.write_bits(1, 2); // BTYPE = 01 (fixed)
            let lit_codes = build_canonical_codes(&fixed_literal_lengths(), MAX_DEFLATE_CODE_LEN);
            write_symbol(&mut writer, &lit_codes[256]);
            return writer.finish();
        }

        if self.level == CompressionLevel::None {
            return self.encode_stored(data);
        }

        self.encode_fixed(data)
    }

    /// Encode with stored (uncompressed) blocks.
    ///
    /// Each stored block is byte-aligned by construction: the stream
    /// starts at a byte boundary and every block body is raw bytes, so
    /// the 3-bit header's remaining five bits are the padding an RFC 1951
    /// reader discards and can be written as zeros.
    fn encode_stored(&self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            let final_block = pos + 65535 >= data.len();
            result.push(if final_block { 0x01 } else { 0x00 });

            let len = (data.len() - pos).min(65535) as u16;
            result.extend_from_slice(&len.to_le_bytes());
            result.extend_from_slice(&(!len).to_le_bytes());

            let end = (pos + 65535).min(data.len());
            result.extend_from_slice(&data[pos..end]);
            pos = end;
        }

        result
    }

    /// Encode with the fixed Huffman codes of RFC 1951 section 3.2.6.
    fn encode_fixed(&mut self, data: &[u8]) -> Vec<u8> {
        let tokens = self.lz77.compress(data);
        let mut writer = BitWriter::new();

        writer.write_bits(1, 1); // BFINAL = 1
        writer.write_bits(1, 2); // BTYPE = 01 (fixed Huffman)

        let literal_codes = build_canonical_codes(&fixed_literal_lengths(), MAX_DEFLATE_CODE_LEN);
        let distance_codes = build_canonical_codes(&fixed_distance_lengths(), MAX_DEFLATE_CODE_LEN);

        for token in &tokens {
            match token {
                Lz77Token::Literal(byte) => {
                    write_symbol(&mut writer, &literal_codes[*byte as usize]);
                }
                Lz77Token::Match(m) => {
                    let (len_code, len_extra) = encode_length(m.length);
                    write_symbol(&mut writer, &literal_codes[len_code as usize]);
                    // Extra bits are plain values, not reversed codes.
                    if len_extra.1 > 0 {
                        writer.write_bits(len_extra.0 as u32, len_extra.1);
                    }

                    let (dist_code, dist_extra) = encode_distance(m.distance);
                    write_symbol(&mut writer, &distance_codes[dist_code as usize]);
                    if dist_extra.1 > 0 {
                        writer.write_bits(dist_extra.0 as u32, dist_extra.1);
                    }
                }
            }
        }

        write_symbol(&mut writer, &literal_codes[256]); // end of block
        writer.finish()
    }
}

impl Default for DeflateEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Write one canonical Huffman code onto an LSB-first stream: the code
/// bits are reversed, because the RFC's codes are assigned MSB-first.
fn write_symbol(writer: &mut BitWriter, code: &super::huffman::CodeLength) {
    writer.write_bits(reverse_bits(code.code, code.bits) as u32, code.bits);
}

/// DEFLATE decoder.
#[derive(Debug)]
pub struct DeflateDecoder {
    /// LZ77 decoder.
    lz77: Lz77Decoder,
    /// The RFC's fixed tables, built once per decoder. Held here rather
    /// than in a `static` so the module needs no `std` synchronisation
    /// primitive in a `no_std` build.
    fixed: Option<(HuffmanDecoder, HuffmanDecoder)>,
}

impl DeflateDecoder {
    /// Create a new DEFLATE decoder.
    pub fn new() -> Self {
        Self {
            lz77: Lz77Decoder::new(),
            fixed: None,
        }
    }

    /// Decode DEFLATE compressed data.
    ///
    /// Also reports how many input bytes the stream occupied. The count
    /// covers the byte the final block ends in (deflate is bit-oriented; the
    /// last block ends mid-byte and the remaining bits are padding).
    /// Container parsers that need to know where the payload stops — gzip,
    /// for one — use this instead of scanning for a byte value: a 0x00 byte
    /// is ordinary compressed data whenever the input contains any.
    pub fn decode_with_consumed(&mut self, data: &[u8]) -> CompressResult<(Vec<u8>, usize)> {
        self.decode_bounded_with_consumed(data, super::cap::UNLIMITED)
            .map(|(b, n)| (b.bytes, n))
    }

    /// Decode a deflate stream that may not expand past `limit` bytes,
    /// also reporting how many input bytes it occupied. A stream that
    /// would expand past the cap comes back short and flagged, not as an
    /// error: the caller still has the prefix, and still has to say the
    /// read was truncated.
    pub fn decode_bounded_with_consumed(
        &mut self,
        data: &[u8],
        limit: u64,
    ) -> CompressResult<(Bounded, usize)> {
        self.lz77.set_limit(limit);
        self.lz77.reset();
        let mut reader = BitReader::new(data);
        let mut blocks = 0u32;

        loop {
            blocks += 1;
            if blocks > MAX_BLOCKS {
                return Err(CompressError::CorruptedData(
                    "too many blocks - possible infinite loop",
                ));
            }

            // A missing 3-bit header is a truncated tail, not an error:
            // everything before it has already been emitted.
            if reader.peek_bits(3).is_none() {
                break;
            }

            let bfinal = reader.read_bits(1).ok_or(CompressError::UnexpectedEof)?;
            let btype = reader.read_bits(2).ok_or(CompressError::UnexpectedEof)?;

            match btype {
                0 => self.decode_stored_block(&mut reader)?,
                1 => self.decode_fixed_block(&mut reader)?,
                2 => self.decode_dynamic_block(&mut reader)?,
                _ => return Err(CompressError::InvalidFormat("reserved block type")),
            }
            if self.lz77.capped() {
                break;
            }

            if bfinal == 1 {
                break;
            }
        }

        let consumed = reader.byte_pos + usize::from(reader.bit_pos > 0);
        // Take the window rather than clone it: this is the last read of the
        // stream, the decoder was `reset()` at the top, and the clone was a
        // second full copy of everything just inflated.
        Ok((self.lz77.take_bounded(), consumed))
    }

    /// Decode a deflate stream to its end.
    pub fn decode(&mut self, data: &[u8]) -> CompressResult<Vec<u8>> {
        self.decode_with_consumed(data).map(|(out, _)| out)
    }

    /// Decode a deflate stream to its end, refusing to emit more than
    /// `limit` bytes.
    pub fn decode_bounded(&mut self, data: &[u8], limit: u64) -> CompressResult<Bounded> {
        self.decode_bounded_with_consumed(data, limit)
            .map(|(b, _)| b)
    }

    /// Decode a stored (uncompressed) block: discard the rest of the
    /// header byte, check LEN against its complement, and copy the body
    /// as raw bytes.
    fn decode_stored_block(&mut self, reader: &mut BitReader) -> CompressResult<()> {
        reader.align();

        let len = reader.read_bits(16).ok_or(CompressError::UnexpectedEof)? as usize;
        let nlen = reader.read_bits(16).ok_or(CompressError::UnexpectedEof)? as usize;

        if len != (!nlen & 0xFFFF) {
            return Err(CompressError::CorruptedData("stored block length mismatch"));
        }

        // The block is byte-aligned now, so the body is a contiguous
        // slice of the input: one `extend_from_slice` instead of `len`
        // single-byte reads, each with its own bounds check.
        if self.lz77.capped() {
            return Ok(());
        }
        let remaining = reader.data.len().saturating_sub(reader.byte_pos);
        if len > remaining {
            return Err(CompressError::UnexpectedEof);
        }
        let bytes = &reader.data[reader.byte_pos..reader.byte_pos + len];
        self.lz77.add_literal_slice(bytes);
        reader.byte_pos += len;

        Ok(())
    }

    /// Decode a fixed Huffman block against the RFC's constant tables.
    fn decode_fixed_block(&mut self, reader: &mut BitReader) -> CompressResult<()> {
        if self.fixed.is_none() {
            self.fixed = Some((
                HuffmanDecoder::from_lengths(&fixed_literal_lengths(), MAX_DEFLATE_CODE_LEN as u8),
                HuffmanDecoder::from_lengths(&fixed_distance_lengths(), MAX_DEFLATE_CODE_LEN as u8),
            ));
        }
        let (lit, dist) = self.fixed.take().unwrap();
        let result = self.decode_huffman_block(reader, &lit, &dist);
        self.fixed = Some((lit, dist));
        result
    }

    /// Decode a dynamic Huffman block: read the code-length code lengths,
    /// use them to read the literal and distance code lengths, then decode
    /// the block body against the two tables that describes.
    fn decode_dynamic_block(&mut self, reader: &mut BitReader) -> CompressResult<()> {
        let hlit = reader.read_bits(5).ok_or(CompressError::UnexpectedEof)? as usize + 257;
        let hdist = reader.read_bits(5).ok_or(CompressError::UnexpectedEof)? as usize + 1;
        let hclen = reader.read_bits(4).ok_or(CompressError::UnexpectedEof)? as usize + 4;

        // Code length code order
        const CODE_LENGTH_ORDER: [usize; 19] = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];

        let mut code_length_lengths = [0u8; 19];
        for i in 0..hclen {
            code_length_lengths[CODE_LENGTH_ORDER[i]] =
                reader.read_bits(3).ok_or(CompressError::UnexpectedEof)? as u8;
        }

        let cl_decoder = HuffmanDecoder::from_lengths(&code_length_lengths, 7);

        // Read literal/length and distance code lengths
        let mut all_lengths = Vec::with_capacity(hlit + hdist);

        while all_lengths.len() < hlit + hdist {
            // Peek at bits (don't consume yet) - code length codes use max 7 bits
            let bits = reader.peek_bits(7).ok_or(CompressError::UnexpectedEof)?;
            match cl_decoder.decode(bits, 7) {
                Some((symbol, consumed)) => {
                    // Consume only the bits we used
                    reader.skip_bits(consumed);

                    match symbol {
                        0..=15 => {
                            all_lengths.push(symbol as u8);
                        }
                        16 => {
                            let count = reader.read_bits(2).ok_or(CompressError::UnexpectedEof)?
                                as usize
                                + 3;
                            let prev = all_lengths.last().copied().unwrap_or(0);
                            for _ in 0..count {
                                all_lengths.push(prev);
                            }
                        }
                        17 => {
                            let count = reader.read_bits(3).ok_or(CompressError::UnexpectedEof)?
                                as usize
                                + 3;
                            all_lengths.extend(core::iter::repeat_n(0, count));
                        }
                        18 => {
                            let count = reader.read_bits(7).ok_or(CompressError::UnexpectedEof)?
                                as usize
                                + 11;
                            all_lengths.extend(core::iter::repeat_n(0, count));
                        }
                        _ => {
                            return Err(CompressError::InvalidFormat("invalid code length symbol"));
                        }
                    }
                }
                None => {
                    return Err(CompressError::InvalidFormat(
                        "invalid code length in dynamic header",
                    ));
                }
            }
        }

        let literal_lengths = &all_lengths[..hlit];
        let distance_lengths = &all_lengths[hlit..];

        let lit_decoder = HuffmanDecoder::from_lengths(literal_lengths, MAX_DEFLATE_CODE_LEN as u8);
        let dist_decoder =
            HuffmanDecoder::from_lengths(distance_lengths, MAX_DEFLATE_CODE_LEN as u8);

        self.decode_huffman_block(reader, &lit_decoder, &dist_decoder)
    }

    /// Decode a Huffman-coded block body until end-of-block or the cap.
    fn decode_huffman_block(
        &mut self,
        reader: &mut BitReader,
        lit_decoder: &HuffmanDecoder,
        dist_decoder: &HuffmanDecoder,
    ) -> CompressResult<()> {
        loop {
            if self.lz77.capped() {
                break;
            }
            // Peek only the bits that actually remain: near the end of a
            // stream fewer than 16 bits can still hold a valid code.
            let avail = core::cmp::min(16usize, reader.remaining_bits()) as u8;
            if avail == 0 {
                break;
            }
            let bits = reader.peek_bits(avail).unwrap_or(0);

            // Try to decode literal/length
            if let Some((symbol, consumed)) = lit_decoder.decode(bits, avail) {
                // Consume the bits we used
                reader.skip_bits(consumed);

                match symbol {
                    0..=255 => {
                        self.lz77.add_literal(symbol as u8);
                    }
                    256 => {
                        // End of block
                        break;
                    }
                    257..=285 => {
                        // Length code - read extra bits if needed
                        let len = decode_length(symbol as usize, reader)?;

                        // Read distance — peek only what remains; a valid
                        // distance code can fit in the tail bits.
                        let dist_avail = core::cmp::min(16usize, reader.remaining_bits()) as u8;
                        if dist_avail == 0 {
                            break;
                        }
                        let dist_bits = reader.peek_bits(dist_avail).unwrap_or(0);
                        match dist_decoder.decode(dist_bits, dist_avail) {
                            Some((dist_symbol, dist_consumed)) => {
                                reader.skip_bits(dist_consumed);
                                let distance = decode_distance(dist_symbol as usize, reader)?;
                                self.lz77.copy_match(distance as usize, len as usize);
                            }
                            None => {
                                return Err(CompressError::InvalidFormat("invalid distance code"));
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                // No more valid codes - end of stream
                break;
            }
        }

        Ok(())
    }
}

impl Default for DeflateDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode length to (code, (extra_value, extra_bits)).
fn encode_length(length: u16) -> (u16, (u16, u8)) {
    for (code, &base) in LENGTH_BASE.iter().enumerate() {
        if code + 1 < LENGTH_BASE.len() && length < LENGTH_BASE[code + 1] {
            let extra_bits = LENGTH_EXTRA[code];
            let extra_value = length - base;
            return (257 + code as u16, (extra_value, extra_bits));
        }
    }
    (285, (0, 0)) // Max length
}

/// Encode distance to (code, (extra_value, extra_bits)).
fn encode_distance(distance: u16) -> (u16, (u16, u8)) {
    for (code, &base) in DISTANCE_BASE.iter().enumerate() {
        if code + 1 < DISTANCE_BASE.len() && distance < DISTANCE_BASE[code + 1] {
            let extra_bits = DISTANCE_EXTRA[code];
            let extra_value = distance - base;
            return (code as u16, (extra_value, extra_bits));
        }
    }
    (29, (distance - DISTANCE_BASE[29], DISTANCE_EXTRA[29]))
}

/// Decode length code.
fn decode_length(code: usize, reader: &mut BitReader) -> CompressResult<u16> {
    if !(257..=285).contains(&code) {
        return Err(CompressError::CorruptedData("invalid length code"));
    }

    let idx = code - 257;
    let base = LENGTH_BASE[idx];
    let extra = LENGTH_EXTRA[idx];

    if extra > 0 {
        let extra_val = reader
            .read_bits(extra)
            .ok_or(CompressError::UnexpectedEof)?;
        Ok(base + extra_val as u16)
    } else {
        Ok(base)
    }
}

/// Decode distance code.
fn decode_distance(code: usize, reader: &mut BitReader) -> CompressResult<u16> {
    if code > 29 {
        return Err(CompressError::CorruptedData("invalid distance code"));
    }

    let base = DISTANCE_BASE[code];
    let extra = DISTANCE_EXTRA[code];

    if extra > 0 {
        let extra_val = reader
            .read_bits(extra)
            .ok_or(CompressError::UnexpectedEof)?;
        Ok(base + extra_val as u16)
    } else {
        Ok(base)
    }
}
#[cfg(all(test, feature = "deflate"))]
mod tests {
    use super::*;
    #[cfg(feature = "std")]
    use std::eprintln;

    #[test]
    fn test_deflate_empty() {
        let mut encoder = DeflateEncoder::new();
        let mut decoder = DeflateDecoder::new();

        let compressed = encoder.encode(b"");
        let decompressed = decoder.decode(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_deflate_fixed_codes() {
        // Test that fixed Huffman codes are generated correctly
        let literal_lengths = fixed_literal_lengths();
        let distance_lengths = fixed_distance_lengths();

        let literal_codes = build_canonical_codes(&literal_lengths, MAX_DEFLATE_CODE_LEN);
        let distance_codes = build_canonical_codes(&distance_lengths, MAX_DEFLATE_CODE_LEN);

        // Symbol 256 (EOB) should have 7 bits
        assert_eq!(literal_codes[256].bits, 7);
        // Symbol 257 (length 3) should have 7 bits
        assert_eq!(literal_codes[257].bits, 7);

        // All distance codes should have 5 bits
        for (i, code) in distance_codes.iter().enumerate() {
            assert_eq!(code.bits, 5, "Distance code {} should have 5 bits", i);
        }

        // Symbol 65 ('A') should have 8 or 9 bits depending on its position
        // 65 is in range 0-143, so it should have 8 bits
        assert_eq!(literal_codes[65].bits, 8);
    }

    #[test]
    fn test_deflate_match_encoding_debug() {
        // Test encoding of a simple match with debug output
        let mut writer = BitWriter::new();
        writer.write_bits(1, 1); // BFINAL
        writer.write_bits(1, 2); // BTYPE = fixed

        let literal_lengths = fixed_literal_lengths();
        let distance_lengths = fixed_distance_lengths();
        let literal_codes = build_canonical_codes(&literal_lengths, MAX_DEFLATE_CODE_LEN);
        let distance_codes = build_canonical_codes(&distance_lengths, MAX_DEFLATE_CODE_LEN);

        // Write literal 'a' (ASCII 97) — reversed for DEFLATE stream
        let lit_code = &literal_codes[97];
        writer.write_bits(
            reverse_bits(lit_code.code, lit_code.bits) as u32,
            lit_code.bits,
        );

        // Write length code 257 (length 3) — reversed
        let len_code = &literal_codes[257];
        writer.write_bits(
            reverse_bits(len_code.code, len_code.bits) as u32,
            len_code.bits,
        );

        // Write distance code 0 (distance 1) — reversed
        let dist_code = &distance_codes[0];
        writer.write_bits(
            reverse_bits(dist_code.code, dist_code.bits) as u32,
            dist_code.bits,
        );

        // Write EOB — reversed
        let eob = &literal_codes[256];
        writer.write_bits(reverse_bits(eob.code, eob.bits) as u32, eob.bits);

        let compressed = writer.finish();

        #[cfg(feature = "std")]
        {
            eprintln!("Compressed bytes: {:?}", compressed);
            eprintln!("Total bits: {}", compressed.len() * 8);
        }

        // Now manually decode to verify
        let mut reader = crate::compress::huffman::BitReader::new(&compressed);

        let bfinal = reader.read_bits(1).unwrap();
        let btype = reader.read_bits(2).unwrap();
        assert_eq!(bfinal, 1);
        assert_eq!(btype, 1);

        // Peek and decode literal 'a'
        let bits = reader.peek_bits(16).unwrap();
        #[cfg(feature = "std")]
        eprintln!("bits = {} (0x{:x})", bits, bits);
        let lit_decoder =
            HuffmanDecoder::from_lengths(&literal_lengths, MAX_DEFLATE_CODE_LEN as u8);
        #[cfg(feature = "std")]
        eprintln!(
            "literal_codes[97] = {{ code: {}, bits: {} }}",
            literal_codes[97].code, literal_codes[97].bits
        );
        let (symbol, consumed) = lit_decoder.decode(bits, 16).expect("Should decode literal");
        #[cfg(feature = "std")]
        eprintln!(
            "decode result: symbol = {}, consumed = {}",
            symbol, consumed
        );
        assert_eq!(symbol, 97, "Expected literal 'a', got {}", symbol);
        reader.skip_bits(consumed);

        // Peek and decode length code
        let bits = reader.peek_bits(16).unwrap();
        let (symbol2, consumed2) = lit_decoder
            .decode(bits, 16)
            .expect("Should decode length code");
        assert_eq!(symbol2, 257, "Expected length code 257, got {}", symbol2);
        reader.skip_bits(consumed2);

        // Peek and decode distance code
        let bits = reader.peek_bits(16).unwrap_or_else(|| {
            // May have fewer than 16 bits remaining; try smaller peek
            reader.peek_bits(8).unwrap_or(0)
        });
        let dist_decoder =
            HuffmanDecoder::from_lengths(&distance_lengths, MAX_DEFLATE_CODE_LEN as u8);
        let (dist_symbol, dist_consumed) = dist_decoder
            .decode(bits, 16)
            .expect("Should decode distance code");
        assert_eq!(
            dist_symbol, 0,
            "Expected distance code 0, got {}",
            dist_symbol
        );
        reader.skip_bits(dist_consumed);

        // Peek and decode EOB
        let bits = reader
            .peek_bits(16)
            .unwrap_or_else(|| reader.peek_bits(8).unwrap_or(0));
        let (eob_symbol, _) = lit_decoder.decode(bits, 16).expect("Should decode EOB");
        assert_eq!(eob_symbol, 256, "Expected EOB, got {}", eob_symbol);
    }

    #[test]
    fn test_deflate_match_encoding() {
        // Test encoding of a simple match
        use crate::compress::lz77::{Lz77Token, Match};

        let _tokens = [
            Lz77Token::Literal(b'a'),
            Lz77Token::Match(Match {
                distance: 1,
                length: 3,
            }),
        ];

        let mut writer = BitWriter::new();
        writer.write_bits(1, 1); // BFINAL
        writer.write_bits(1, 2); // BTYPE = fixed

        let literal_lengths = fixed_literal_lengths();
        let distance_lengths = fixed_distance_lengths();
        let literal_codes = build_canonical_codes(&literal_lengths, MAX_DEFLATE_CODE_LEN);
        let distance_codes = build_canonical_codes(&distance_lengths, MAX_DEFLATE_CODE_LEN);

        // Write literal 'a' (ASCII 97) — reversed for DEFLATE stream
        let lit_code = &literal_codes[97];
        writer.write_bits(
            reverse_bits(lit_code.code, lit_code.bits) as u32,
            lit_code.bits,
        );

        // Write length code 257 (length 3) — reversed
        let len_code = &literal_codes[257];
        writer.write_bits(
            reverse_bits(len_code.code, len_code.bits) as u32,
            len_code.bits,
        );

        // Write distance code 0 (distance 1) — reversed
        let dist_code = &distance_codes[0];
        writer.write_bits(
            reverse_bits(dist_code.code, dist_code.bits) as u32,
            dist_code.bits,
        );

        // Write EOB — reversed
        let eob = &literal_codes[256];
        writer.write_bits(reverse_bits(eob.code, eob.bits) as u32, eob.bits);

        let compressed = writer.finish();
        #[cfg(feature = "std")]
        eprintln!("compressed bytes: {:02x?}", compressed);

        // Decode
        let mut decoder = DeflateDecoder::new();
        let decompressed = decoder.decode(&compressed).unwrap();
        #[cfg(feature = "std")]
        eprintln!("decompressed: {:?}", decompressed);

        // Should decode to "aaaa" (literal 'a' + match of 3 'a's)
        assert_eq!(decompressed, b"aaaa");
    }

    #[test]
    fn test_deflate_single_byte() {
        let mut encoder = DeflateEncoder::new();
        let mut decoder = DeflateDecoder::new();

        let data = b"A"; // Single byte
        let compressed = encoder.encode(data);

        // Block should be: BFINAL=1, BTYPE=01 (fixed), literal A, EOB
        // That's 1 + 2 + 8 + 7 = 18 bits = 3 bytes (with padding)
        assert!(compressed.len() >= 3);

        let decompressed = decoder.decode(&compressed).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_deflate_simple() {
        let mut encoder = DeflateEncoder::new();
        let mut decoder = DeflateDecoder::new();

        let data = b"Hello, World!";
        let compressed = encoder.encode(data);

        let decompressed = decoder.decode(&compressed).unwrap();

        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_deflate_repeated() {
        let mut encoder = DeflateEncoder::new();
        let mut decoder = DeflateDecoder::new();

        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let compressed = encoder.encode(data);
        let decompressed = decoder.decode(&compressed).unwrap();

        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_deflate_stored() {
        let mut encoder = DeflateEncoder::with_level(0);
        let mut decoder = DeflateDecoder::new();

        let data = b"Hello, World!";
        let compressed = encoder.encode(data);
        let decompressed = decoder.decode(&compressed).unwrap();

        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_deflate_compression_ratio() {
        let mut encoder = DeflateEncoder::with_level(9);

        // Repeated data should compress well
        let data = b"Hello, World! ".repeat(100);
        let compressed = encoder.encode(&data);

        assert!(compressed.len() < data.len());
    }

    #[test]
    fn test_length_encoding() {
        assert_eq!(encode_length(3), (257, (0, 0)));
        assert_eq!(encode_length(10), (264, (0, 0)));
        assert_eq!(encode_length(11), (265, (0, 1)));
        assert_eq!(encode_length(258), (285, (0, 0)));
    }

    #[test]
    fn test_distance_encoding() {
        assert_eq!(encode_distance(1), (0, (0, 0)));
        assert_eq!(encode_distance(4), (3, (0, 0)));
        assert_eq!(encode_distance(5), (4, (0, 1)));
    }

    #[test]
    fn test_deflate_vector_match() {
        // Raw DEFLATE stream produced by CPython zlib (matches + literals).
        let compressed = include_bytes!("../../testdata/deflate_match.bin");
        let expected = include_bytes!("../../testdata/deflate_match.expected");
        let mut decoder = DeflateDecoder::new();
        let output = decoder.decode(compressed).expect("decode deflate_match");
        assert_eq!(output, expected);
    }

    #[test]
    fn test_deflate_vector_lit() {
        let compressed = include_bytes!("../../testdata/deflate_lit.bin");
        let expected = include_bytes!("../../testdata/deflate_lit.expected");
        let mut decoder = DeflateDecoder::new();
        let output = decoder.decode(compressed).expect("decode deflate_lit");
        assert_eq!(output, expected);
    }

    #[test]
    fn test_deflate_vector_big() {
        let compressed = include_bytes!("../../testdata/deflate_big.bin");
        let expected = include_bytes!("../../testdata/deflate_big.expected");
        let mut decoder = DeflateDecoder::new();
        let output = decoder.decode(compressed).expect("decode deflate_big");
        assert_eq!(output, expected);
    }

    /// Third-party vector sweep: raw deflate streams produced by CPython's
    /// zlib at levels 0 (stored), 1 (fixed), 6 (dynamic) and 9 over empty,
    /// text, repetitive and binary payloads.
    #[test]
    fn test_deflate_third_party_level_sweep() {
        macro_rules! case {
            ($name:literal, $level:literal) => {{
                let compressed = include_bytes!(concat!(
                    "../../testdata/deflate_",
                    $name,
                    "_",
                    $level,
                    ".bin"
                ));
                let expected = include_bytes!(concat!(
                    "../../testdata/deflate_",
                    $name,
                    "_",
                    $level,
                    ".expected"
                ));
                let mut decoder = DeflateDecoder::new();
                let output = decoder
                    .decode(compressed)
                    .expect(concat!("deflate_", $name, "_", $level));
                assert_eq!(output, expected, concat!("deflate_", $name, "_", $level));
            }};
        }
        case!("empty", "stored");
        case!("empty", "fixed");
        case!("empty", "dyn");
        case!("empty", "max");
        case!("text", "stored");
        case!("text", "fixed");
        case!("text", "dyn");
        case!("text", "max");
        case!("repeat", "stored");
        case!("repeat", "fixed");
        case!("repeat", "dyn");
        case!("repeat", "max");
        case!("binary", "stored");
        case!("binary", "fixed");
        case!("binary", "dyn");
        case!("binary", "max");
        case!("mixed", "stored");
        case!("mixed", "fixed");
        case!("mixed", "dyn");
        case!("mixed", "max");
    }
}

/// A corrupt or truncated stream is untrusted input: the decoder must
/// answer with an error or a short read, never a panic.
#[cfg(all(test, feature = "deflate"))]
mod fuzz {
    use super::*;

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: alloc::vec::Vec<(&str, alloc::vec::Vec<u8>)> = alloc::vec![
            ("empty", alloc::vec![]),
            ("header_only", alloc::vec![0x01]),
            ("stored_head", alloc::vec![0x01, 0x05, 0x00, 0xFA, 0xFF]),
            ("dyn_head", alloc::vec![0x05, 0x00, 0x00]),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 2000, "deflate", |data| {
            let mut decoder = DeflateDecoder::new();
            let _ = decoder.decode(data);
            let mut decoder = DeflateDecoder::new();
            let _ = decoder.decode_bounded(data, 4096);
            let mut decoder = DeflateDecoder::new();
            let _ = decoder.decode_with_consumed(data);
        });
    }
}
