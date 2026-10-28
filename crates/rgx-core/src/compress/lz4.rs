// SPDX-License-Identifier: Apache-2.0

//! LZ4 — the block format, decoding only.
//!
//! Written from the published block format: a run of sequences, each opening
//! with a token whose high nibble is the length of the literals that follow
//! and whose low nibble is the length of the match minus four. The literals
//! come next, then the two-byte little-endian distance of the match, and the
//! match copies that many bytes from that distance back. A length of fifteen
//! means the real length follows in extra bytes of 255 and a remainder.
//!
//! **The frame wrapper is not read here.** A `.lz4` file is a frame around
//! this, and the frame is read by the archive crate's own decoder — the one
//! that replaced `lz4_flex` for the search path. What is here is the block,
//! because the blosc frame is made of blocks and that frame *is*
//! interop-proven: the chunks zarr-python writes with the blosc codec are
//! read with it.
//!
//! Two properties of the format are worth naming, because each one is a way
//! to write a decoder that passes the easy cases and fails on real data:
//!
//! - **The distance is measured back from the write position**, not from the
//!   start of the output. Read as an absolute index, a stream decodes to the
//!   right length and the wrong bytes.
//! - **A match may overlap what it is producing.** That is the run-length
//!   case — one byte and then a copy of distance 1 — and a decoder that
//!   copies the source range in one go produces a short result instead of a
//!   repeated pattern.

use super::cap::{Bounded, OutputCap, UNLIMITED};
use super::error::{CompressError, CompressResult};
use alloc::vec::Vec;

/// LZ4 block decoder.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lz4Decoder {
    _priv: (),
}

impl Lz4Decoder {
    /// Create a decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { _priv: () }
    }

    /// Decode one block under an unlimited cap.
    pub fn decode(&self, data: &[u8]) -> CompressResult<Vec<u8>> {
        self.decode_bounded(data, UNLIMITED).map(|b| b.bytes)
    }

    /// Decode one block, stopping at `limit` emitted bytes.
    ///
    /// The block format declares no length: the sequences are the only thing
    /// that fills it, so the decode runs and is stopped by the cap as bytes
    /// leave it.
    pub fn decode_bounded(&self, data: &[u8], limit: u64) -> CompressResult<Bounded> {
        let mut cap = OutputCap::new(limit);
        self.decompress(data, &mut cap)
    }

    /// The decode itself, with a caller-supplied cap so a container can
    /// spend one budget across several blocks.
    pub fn decompress(&self, data: &[u8], cap: &mut OutputCap) -> CompressResult<Bounded> {
        let limit = cap.limit();
        let mut out: Vec<u8> = Vec::new();
        let mut p = 0usize;
        while p < data.len() {
            let token = data[p];
            p += 1;
            // The literals.
            let mut literals = usize::from(token >> 4);
            if literals == 15 {
                literals += extended_len(data, &mut p)?;
            }
            let end = p
                .checked_add(literals)
                .ok_or(CompressError::UnexpectedEof)?;
            let bytes = data.get(p..end).ok_or(CompressError::UnexpectedEof)?;
            p = end;
            if !cap.take(literals as u64) {
                return Ok(Bounded::stopped(out, None, limit));
            }
            out.extend_from_slice(bytes);
            // The last sequence of a block is literals only.
            if p >= data.len() {
                break;
            }
            // The match: the distance, then the length.
            let offset = le16(data, &mut p)?;
            let mut length = usize::from(token & 0x0f) + 4;
            if (token & 0x0f) == 15 {
                length += extended_len(data, &mut p)?;
            }
            if !emit_copy(&mut out, offset, length, cap)? {
                return Ok(Bounded::stopped(out, None, limit));
            }
        }
        Ok(Bounded::complete(out, None, limit))
    }
}

/// The extra bytes of a length that does not fit in the token: 255 and 255
/// and so on, and then the remainder.
fn extended_len(data: &[u8], p: &mut usize) -> CompressResult<usize> {
    let mut total = 0usize;
    loop {
        let byte = *data.get(*p).ok_or(CompressError::UnexpectedEof)?;
        *p += 1;
        total = total
            .checked_add(usize::from(byte))
            .ok_or(CompressError::CorruptedData(
                "the length of a sequence does not fit in a usize",
            ))?;
        if byte != 255 {
            return Ok(total);
        }
    }
}

/// A little-endian 16-bit number.
fn le16(data: &[u8], p: &mut usize) -> CompressResult<usize> {
    let end = p.checked_add(2).ok_or(CompressError::UnexpectedEof)?;
    let bytes = data.get(*p..end).ok_or(CompressError::UnexpectedEof)?;
    *p = end;
    Ok(usize::from(bytes[0]) | usize::from(bytes[1]) << 8)
}

/// One back-reference. `Ok(false)` means the cap stopped the decode.
///
/// The copy is applied a byte at a time because the ranges overlap by
/// design: a distance of 1 with a length of sixty is a run, and it reads
/// bytes this copy is still producing. Copying the source range in one go
/// would borrow the output immutably while extending it and could only copy
/// the bytes that existed when the copy began.
fn emit_copy(
    out: &mut Vec<u8>,
    off: usize,
    len: usize,
    cap: &mut OutputCap,
) -> CompressResult<bool> {
    // The distance runs back from the write position, so a distance past
    // what has been produced -- and zero, which would point at the byte
    // being written -- is a stream referencing bytes that are not there.
    // That is corruption, not a ceiling: reporting it as a cap would hand
    // the caller a short payload that reads like a whole one.
    if off == 0 || off > out.len() {
        return Err(CompressError::CorruptedData(
            "copy reaches before the start of the output",
        ));
    }
    if !cap.take(len as u64) {
        return Ok(false);
    }
    let start = out.len() - off;
    for i in 0..len {
        let byte = out[start + i];
        out.push(byte);
    }
    Ok(true)
}

#[cfg(all(test, feature = "lz4"))]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn literals_alone_decode_to_themselves() {
        // One token, three literals, and no match: the last sequence of a
        // block is literals only.
        let out = Lz4Decoder::new().decode(&[0x30, b'a', b'b', b'c']).unwrap();
        assert_eq!(out, b"abc");
    }

    #[test]
    fn a_run_of_one_byte_repeats() {
        // A literal and then a match of distance one and length four: the
        // run-length case, where the copy reads the bytes it is producing.
        let out = Lz4Decoder::new().decode(&[0x10, b'x', 0x01, 0x00]).unwrap();
        assert_eq!(out, b"xxxxx");
    }

    #[test]
    fn a_distance_past_the_output_is_corruption() {
        let err = Lz4Decoder::new()
            .decode(&[0x10, b'x', 0x40, 0x00])
            .unwrap_err();
        assert!(matches!(err, CompressError::CorruptedData(_)), "{err:?}");
    }

    #[test]
    fn the_cap_stops_the_decode() {
        let mut cap = OutputCap::new(2);
        let out = Lz4Decoder::new()
            .decompress(&[0x40, b'a', b'b', b'c', b'd'], &mut cap)
            .unwrap();
        assert!(out.capped);
        assert!(out.bytes.is_empty());
    }

    #[test]
    fn an_empty_block_is_empty() {
        let out = Lz4Decoder::new().decode(&[]).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn a_token_that_runs_off_the_end_is_an_error() {
        let err = Lz4Decoder::new().decode(&[0x50, b'a']).unwrap_err();
        assert!(matches!(err, CompressError::UnexpectedEof), "{err:?}");
    }

    #[test]
    fn the_extra_bytes_of_a_long_length_are_counted() {
        // A token that says fifteen literals, and then the extra bytes that
        // say there are two more.
        let mut data = vec![0xf0, 0x02];
        data.extend(core::iter::repeat_n(b'a', 17));
        let out = Lz4Decoder::new().decode(&data).unwrap();
        assert_eq!(out.len(), 17);
    }
}
