// SPDX-License-Identifier: Apache-2.0

//! DEFLATE compression (RFC 1951).
//!
//! Independent reimplementation of the DEFLATE algorithm used in ZIP,
//! gzip, and PNG: LZ77 tokenisation followed by Huffman coding in three
//! block modes — stored (uncompressed), fixed (predefined codes), and
//! dynamic (per-block code-length tables).
//!
//! ## ISA-L Integration
//!
//! Behind the `isa-huffman` feature: [`DeflateEncoder::with_isal`] and
//! [`DeflateEncoder::encode_fast`], which route over 64 KiB through
//! [`super::isa_icf`]. **That module is a wrapper over this file's own
//! encoder, not Intel ISA-L** — see its header. The streams are valid
//! DEFLATE and decode through [`DeflateDecoder`]; they are not faster
//! than the standard path, and the feature's name is the vendored code's,
//! not a claim here.

use alloc::vec::Vec;

use super::error::{CompressError, CompressResult};
use super::huffman::{
    build_canonical_codes, reverse_bits, BitReader, BitWriter, HuffmanDecoder, MAX_DEFLATE_CODE_LEN,
};
use super::lz77::{Lz77Decoder, Lz77Encoder, Lz77Token};

#[cfg(feature = "isa-huffman")]
use super::isa_icf::IsalDeflateEncoder;

#[cfg(feature = "isa-huffman")]
use super::isa_huffman::CompressionLevel as IsalCompressionLevel;

/// Compression level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressionLevel {
    /// No compression (store).
    None = 0,
    /// Fast compression (level 1–3).
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

// ── Fixed Huffman code lengths (RFC 1951 §3.2.6) ──────────────────────

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

const fn fixed_distance_lengths() -> [u8; 32] {
    [5u8; 32]
}

// ── Length / distance code tables (RFC 1951 §3.2.5) ───────────────────

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];

const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];

const DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Code length alphabet order for dynamic blocks (RFC 1951 §3.2.7).
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

// ── Encoder ────────────────────────────────────────────────────────────

/// DEFLATE encoder.
#[derive(Debug)]
pub struct DeflateEncoder {
    level: CompressionLevel,
    lz77: Lz77Encoder,
    #[allow(dead_code)]
    fixed_literal_decoder: HuffmanDecoder,
    #[allow(dead_code)]
    fixed_distance_decoder: HuffmanDecoder,
}

impl DeflateEncoder {
    /// Create an encoder with default level 6.
    pub fn new() -> Self {
        Self::with_level(6)
    }

    /// Create an encoder for a specific level (0–9).
    pub fn with_level(level: u8) -> Self {
        let fixed_lit = fixed_literal_lengths();
        let fixed_dist = fixed_distance_lengths();

        Self {
            level: CompressionLevel::from(level),
            lz77: Lz77Encoder::with_level(level),
            fixed_literal_decoder: HuffmanDecoder::from_lengths(
                &fixed_lit,
                MAX_DEFLATE_CODE_LEN as u8,
            ),
            fixed_distance_decoder: HuffmanDecoder::from_lengths(
                &fixed_dist,
                MAX_DEFLATE_CODE_LEN as u8,
            ),
        }
    }

    /// Create an encoder with ISA-L acceleration (requires `isa-huffman`).
    #[cfg(feature = "isa-huffman")]
    pub fn with_isal() -> Self {
        Self::with_level(3)
    }

    /// Encode using the ISA-L pipeline for data over 64 KiB
    /// (requires `isa-huffman`).
    #[cfg(feature = "isa-huffman")]
    pub fn encode_fast(&mut self, data: &[u8]) -> Vec<u8> {
        const ISA_L_THRESHOLD: usize = 64 * 1024;
        if data.len() > ISA_L_THRESHOLD {
            let mut isal_encoder = IsalDeflateEncoder::with_level(1);
            isal_encoder.encode(data)
        } else {
            self.encode(data)
        }
    }

    /// Encode data to a DEFLATE stream.
    pub fn encode(&mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            let mut writer = BitWriter::new();
            writer.write_bits(1, 1); // BFINAL = 1
            writer.write_bits(1, 2); // BTYPE = 01 (fixed)
            let lit_lengths = fixed_literal_lengths();
            let lit_codes = build_canonical_codes(&lit_lengths, MAX_DEFLATE_CODE_LEN);
            let eob = &lit_codes[256];
            writer.write_bits(reverse_bits(eob.code, eob.bits), eob.bits);
            return writer.finish();
        }

        if self.level == CompressionLevel::None {
            return self.encode_stored(data);
        }

        self.encode_fixed(data)
    }

    /// Encode with stored (uncompressed) blocks.
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

    /// Encode with fixed Huffman codes (RFC 1951 §3.2.6).
    fn encode_fixed(&mut self, data: &[u8]) -> Vec<u8> {
        let tokens = self.lz77.compress(data);
        let mut writer = BitWriter::new();

        writer.write_bits(1, 1); // BFINAL = 1
        writer.write_bits(1, 2); // BTYPE = 01 (fixed Huffman)

        let literal_lengths = fixed_literal_lengths();
        let distance_lengths = fixed_distance_lengths();
        let literal_codes = build_canonical_codes(&literal_lengths, MAX_DEFLATE_CODE_LEN);
        let distance_codes = build_canonical_codes(&distance_lengths, MAX_DEFLATE_CODE_LEN);

        for token in &tokens {
            match token {
                Lz77Token::Literal(byte) => {
                    let code = &literal_codes[*byte as usize];
                    writer.write_bits(reverse_bits(code.code, code.bits), code.bits);
                }
                Lz77Token::Match(m) => {
                    let (len_code, len_extra) = encode_length(m.length);
                    let code = &literal_codes[len_code as usize];
                    writer.write_bits(reverse_bits(code.code, code.bits), code.bits);
                    if len_extra.1 > 0 {
                        writer.write_bits(len_extra.0 as u32, len_extra.1);
                    }

                    let (dist_code, dist_extra) = encode_distance(m.distance);
                    let code = &distance_codes[dist_code as usize];
                    writer.write_bits(reverse_bits(code.code, code.bits), code.bits);
                    if dist_extra.1 > 0 {
                        writer.write_bits(dist_extra.0 as u32, dist_extra.1);
                    }
                }
            }
        }

        // End-of-block (symbol 256).
        let eob = &literal_codes[256];
        writer.write_bits(reverse_bits(eob.code, eob.bits), eob.bits);

        writer.finish()
    }
}

impl Default for DeflateEncoder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Decoder ────────────────────────────────────────────────────────────

/// DEFLATE decoder.
#[derive(Debug)]
pub struct DeflateDecoder {
    lz77: Lz77Decoder,
}

impl DeflateDecoder {
    /// Create a new decoder.
    pub fn new() -> Self {
        Self {
            lz77: Lz77Decoder::new(),
        }
    }

    /// Decode a DEFLATE stream.
    pub fn decode(&mut self, data: &[u8]) -> CompressResult<Vec<u8>> {
        self.lz77.reset();
        let mut reader = BitReader::new(data);
        let mut block_count = 0u32;
        const MAX_BLOCKS: u32 = 100_000;

        loop {
            block_count += 1;
            if block_count > MAX_BLOCKS {
                return Err(CompressError::CorruptedData(
                    "too many blocks - possible infinite loop",
                ));
            }

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

            if bfinal == 1 {
                break;
            }
        }

        Ok(self.lz77.output().to_vec())
    }

    /// Decode a stored (uncompressed) block.
    fn decode_stored_block(&mut self, reader: &mut BitReader) -> CompressResult<()> {
        reader.align();
        let len = reader.read_bits(16).ok_or(CompressError::UnexpectedEof)? as usize;
        let nlen = reader.read_bits(16).ok_or(CompressError::UnexpectedEof)? as usize;

        if len != (!nlen & 0xFFFF) {
            return Err(CompressError::CorruptedData("stored block length mismatch"));
        }

        for _ in 0..len {
            let byte = reader.read_bits(8).ok_or(CompressError::UnexpectedEof)?;
            self.lz77.add_literal(byte as u8);
        }

        Ok(())
    }

    /// Decode a fixed Huffman block.
    fn decode_fixed_block(&mut self, reader: &mut BitReader) -> CompressResult<()> {
        let fixed_lit = fixed_literal_lengths();
        let fixed_dist = fixed_distance_lengths();
        let lit_decoder = HuffmanDecoder::from_lengths(&fixed_lit, MAX_DEFLATE_CODE_LEN as u8);
        let dist_decoder = HuffmanDecoder::from_lengths(&fixed_dist, MAX_DEFLATE_CODE_LEN as u8);
        self.decode_huffman_block(reader, &lit_decoder, &dist_decoder)
    }

    /// Decode a dynamic Huffman block (RFC 1951 §3.2.7).
    fn decode_dynamic_block(&mut self, reader: &mut BitReader) -> CompressResult<()> {
        let hlit = reader.read_bits(5).ok_or(CompressError::UnexpectedEof)? as usize + 257;
        let hdist = reader.read_bits(5).ok_or(CompressError::UnexpectedEof)? as usize + 1;
        let hclen = reader.read_bits(4).ok_or(CompressError::UnexpectedEof)? as usize + 4;

        let mut code_length_lengths = [0u8; 19];
        for i in 0..hclen {
            code_length_lengths[CODE_LENGTH_ORDER[i]] =
                reader.read_bits(3).ok_or(CompressError::UnexpectedEof)? as u8;
        }

        let cl_decoder = HuffmanDecoder::from_lengths(&code_length_lengths, 7);

        let mut all_lengths = Vec::with_capacity(hlit + hdist);

        while all_lengths.len() < hlit + hdist {
            let bits = reader.peek_bits(7).ok_or(CompressError::UnexpectedEof)?;
            match cl_decoder.decode(bits, 7) {
                Some((symbol, consumed)) => {
                    reader.skip_bits(consumed);
                    match symbol {
                        0..=15 => all_lengths.push(symbol as u8),
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

    /// Decode one Huffman-coded block body (literals, lengths, distances).
    fn decode_huffman_block(
        &mut self,
        reader: &mut BitReader,
        lit_decoder: &HuffmanDecoder,
        dist_decoder: &HuffmanDecoder,
    ) -> CompressResult<()> {
        loop {
            // Peek only the bits that remain: near the end of a stream
            // fewer than 16 bits can still hold a valid code.
            let avail = core::cmp::min(16usize, reader.remaining_bits()) as u8;
            if avail == 0 {
                break;
            }
            let bits = reader.peek_bits(avail).unwrap_or(0);

            if let Some((symbol, consumed)) = lit_decoder.decode(bits, avail) {
                reader.skip_bits(consumed);

                match symbol {
                    0..=255 => self.lz77.add_literal(symbol as u8),
                    256 => break, // end of block
                    257..=285 => {
                        let len = decode_length(symbol as usize, reader)?;

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

// ── Length / distance code helpers ─────────────────────────────────────

/// Encode a match length to `(code, (extra_value, extra_bits))`.
fn encode_length(length: u16) -> (u16, (u16, u8)) {
    for (code, &base) in LENGTH_BASE.iter().enumerate() {
        if code + 1 < LENGTH_BASE.len() && length < LENGTH_BASE[code + 1] {
            let extra_bits = LENGTH_EXTRA[code];
            let extra_value = length - base;
            return (257 + code as u16, (extra_value, extra_bits));
        }
    }
    (285, (0, 0))
}

/// Encode a match distance to `(code, (extra_value, extra_bits))`.
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

/// Decode a length code (symbols 257–285).
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

/// Decode a distance code (symbols 0–29).
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

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
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
        let literal_lengths = fixed_literal_lengths();
        let distance_lengths = fixed_distance_lengths();

        let literal_codes = build_canonical_codes(&literal_lengths, MAX_DEFLATE_CODE_LEN);
        let distance_codes = build_canonical_codes(&distance_lengths, MAX_DEFLATE_CODE_LEN);

        assert_eq!(literal_codes[256].bits, 7);
        assert_eq!(literal_codes[257].bits, 7);
        for (i, code) in distance_codes.iter().enumerate() {
            assert_eq!(code.bits, 5, "Distance code {i} should have 5 bits");
        }
        assert_eq!(literal_codes[65].bits, 8);
    }

    #[test]
    fn test_deflate_match_encoding_debug() {
        let mut writer = BitWriter::new();
        writer.write_bits(1, 1);
        writer.write_bits(1, 2);

        let literal_lengths = fixed_literal_lengths();
        let distance_lengths = fixed_distance_lengths();
        let literal_codes = build_canonical_codes(&literal_lengths, MAX_DEFLATE_CODE_LEN);
        let distance_codes = build_canonical_codes(&distance_lengths, MAX_DEFLATE_CODE_LEN);

        let lit_code = &literal_codes[97];
        writer.write_bits(reverse_bits(lit_code.code, lit_code.bits), lit_code.bits);

        let len_code = &literal_codes[257];
        writer.write_bits(reverse_bits(len_code.code, len_code.bits), len_code.bits);

        let dist_code = &distance_codes[0];
        writer.write_bits(reverse_bits(dist_code.code, dist_code.bits), dist_code.bits);

        let eob = &literal_codes[256];
        writer.write_bits(reverse_bits(eob.code, eob.bits), eob.bits);

        let compressed = writer.finish();

        #[cfg(feature = "std")]
        {
            eprintln!("Compressed bytes: {:?}", compressed);
            eprintln!("Total bits: {}", compressed.len() * 8);
        }

        let mut reader = crate::sevenz::huffman::BitReader::new(&compressed);

        let bfinal = reader.read_bits(1).unwrap();
        let btype = reader.read_bits(2).unwrap();
        assert_eq!(bfinal, 1);
        assert_eq!(btype, 1);

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
        assert_eq!(symbol, 97, "Expected literal 'a', got {symbol}");
        reader.skip_bits(consumed);

        let bits = reader.peek_bits(16).unwrap();
        let (symbol2, consumed2) = lit_decoder
            .decode(bits, 16)
            .expect("Should decode length code");
        assert_eq!(symbol2, 257, "Expected length code 257, got {symbol2}");
        reader.skip_bits(consumed2);

        let bits = reader
            .peek_bits(16)
            .unwrap_or_else(|| reader.peek_bits(8).unwrap_or(0));
        let dist_decoder =
            HuffmanDecoder::from_lengths(&distance_lengths, MAX_DEFLATE_CODE_LEN as u8);
        let (dist_symbol, dist_consumed) = dist_decoder
            .decode(bits, 16)
            .expect("Should decode distance code");
        assert_eq!(
            dist_symbol, 0,
            "Expected distance code 0, got {dist_symbol}"
        );
        reader.skip_bits(dist_consumed);

        let bits = reader
            .peek_bits(16)
            .unwrap_or_else(|| reader.peek_bits(8).unwrap_or(0));
        let (eob_symbol, _) = lit_decoder.decode(bits, 16).expect("Should decode EOB");
        assert_eq!(eob_symbol, 256, "Expected EOB, got {eob_symbol}");
    }

    #[test]
    fn test_deflate_match_encoding() {
        use crate::sevenz::lz77::{Lz77Token, Match};

        let _tokens = [
            Lz77Token::Literal(b'a'),
            Lz77Token::Match(Match {
                distance: 1,
                length: 3,
            }),
        ];

        let mut writer = BitWriter::new();
        writer.write_bits(1, 1);
        writer.write_bits(1, 2);

        let literal_lengths = fixed_literal_lengths();
        let distance_lengths = fixed_distance_lengths();
        let literal_codes = build_canonical_codes(&literal_lengths, MAX_DEFLATE_CODE_LEN);
        let distance_codes = build_canonical_codes(&distance_lengths, MAX_DEFLATE_CODE_LEN);

        let lit_code = &literal_codes[97];
        writer.write_bits(reverse_bits(lit_code.code, lit_code.bits), lit_code.bits);

        let len_code = &literal_codes[257];
        writer.write_bits(reverse_bits(len_code.code, len_code.bits), len_code.bits);

        let dist_code = &distance_codes[0];
        writer.write_bits(reverse_bits(dist_code.code, dist_code.bits), dist_code.bits);

        let eob = &literal_codes[256];
        writer.write_bits(reverse_bits(eob.code, eob.bits), eob.bits);

        let compressed = writer.finish();
        eprintln!("compressed bytes: {:02x?}", compressed);

        let mut decoder = DeflateDecoder::new();
        let decompressed = decoder.decode(&compressed).unwrap();
        eprintln!("decompressed: {:?}", decompressed);

        assert_eq!(decompressed, b"aaaa");
    }

    #[test]
    fn test_deflate_single_byte() {
        let mut encoder = DeflateEncoder::new();
        let mut decoder = DeflateDecoder::new();
        let data = b"A";
        let compressed = encoder.encode(data);
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

    /// `encode_fast` routes over 64 KiB to `isa_icf`, and the round-trip
    /// has to hold on that branch — it is the only place the feature's
    /// output is exercised.
    #[test]
    #[cfg(feature = "isa-huffman")]
    fn encode_fast_round_trips_over_the_threshold() {
        let mut decoder = DeflateDecoder::new();
        let mut encoder = DeflateEncoder::with_isal();

        let big = b"the quick brown fox jumps over the lazy dog. ".repeat(2_000);
        assert!(big.len() > 64 * 1024);
        assert_eq!(
            decoder.decode(&encoder.encode_fast(&big)).unwrap(),
            big.as_slice()
        );

        let small = b"the quick brown fox";
        assert_eq!(
            decoder.decode(&encoder.encode_fast(small)).unwrap(),
            small.as_slice()
        );
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
}
