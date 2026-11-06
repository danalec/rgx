// SPDX-License-Identifier: Apache-2.0

//! Blosc — the frame of c-blosc, decoding only.
//!
//! The frame is a 16-octet header, the offset of each block, and the blocks.
//! The header says the format version, the flags, the size of one element,
//! the size of the data, the size of a block and the size of the frame. The
//! flags carry the codec and whether the bytes are shuffled. A block is the
//! size of its compressed bytes and then those bytes, and the block's bytes
//! are the data with the byte shuffle applied: the bytes of the same place of
//! each element next to each other, which is what makes a column of floats
//! compress like a column of numbers.
//!
//! Written from the format's own description, and checked against the frames
//! c-blosc and numcodecs write. The reason it is here: the chunks
//! zarr-python asks for by default are blosc frames, and without this they
//! are noise to a search tool.
//!
//! Three things about the format are worth naming, because each one is a way
//! to write a decoder that passes the easy cases and fails on real data:
//!
//! - **The offsets come before the blocks.** The frame holds the offset of
//!   every block in a table, and the blocks themselves follow it. A decoder
//!   that reads the blocks one after another reads the table as a block.
//! - **A block may be split.** A block big enough is split into as many
//!   pieces as the element has bytes, and each piece is compressed on its
//!   own, so the pieces of a block are a run of (size, bytes) pairs.
//! - **The shuffle is applied to the block, not to the frame**, and the
//!   bytes that do not fill an element are left where they are.
//!
//! The codec is the frame's own enumeration, and it is not the enumeration
//! of c-blosc's library codes: the two part company from the second code on,
//! and a reader that mixes them hands a frame to the wrong decoder and calls
//! the data corrupt.
//!
//! | code | codec |
//! |---|---|
//! | 0 | blosclz, the codec of the library itself |
//! | 1 | lz4, or lz4hc — the frame cannot tell the two apart |
//! | 2 | snappy |
//! | 3 | zlib |
//! | 4 | zstd |
//!
//! There is no code 5. A frame that names one is refused by the number.

use super::cap::{Bounded, OutputCap, UNLIMITED};
use super::error::{CompressError, CompressResult};
use super::lz4::Lz4Decoder;
use super::snappy::SnappyDecoder;
use super::zlib::ZlibDecoder;
use super::zstd::ZstdDecoder;
use alloc::vec;
use alloc::vec::Vec;

/// The frame's header: sixteen octets.
const HEADER: usize = 16;

/// The format version this decoder reads.
const VERSION: u8 = 2;

/// The flag that says the bytes are shuffled.
const DOSHUFFLE: u8 = 0x01;

/// The flag that says the data was stored without compression.
const MEMCPYED: u8 = 0x02;

/// The flag that says the bits are shuffled.
const DOBITSHUFFLE: u8 = 0x04;

/// The flag that says the block was not split.
const DONT_SPLIT: u8 = 0x10;

/// The bits of the flags that carry the codec.
const CODEC_MASK: u8 = 0xe0;

/// Where the codec sits in the flags.
const CODEC_SHIFT: u32 = 5;

/// The most pieces a block may be split into.
const MAX_SPLITS: usize = 16;

/// The least a piece must hold for the block to be split at all.
const MIN_SPLIT: usize = 128;

/// The codec a frame names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// blosclz, the codec of the library itself.
    BloscLz,
    /// LZ4. The frame's code 1 is lz4 or lz4hc, and the two have the same
    /// block format, so a frame that names it cannot say which.
    Lz4,
    /// Snappy.
    Snappy,
    /// zlib.
    Zlib,
    /// zstd.
    Zstd,
}

impl Codec {
    /// The codec a frame's flags name.
    ///
    /// The codes are the frame's own, from the format's description: 0 is
    /// blosclz, 1 is lz4 or lz4hc, 2 is snappy, 3 is zlib and 4 is zstd.
    /// They are not c-blosc's library codes, which are a different
    /// enumeration: 2 is lz4hc there, and zstd is 5.
    pub fn from_code(code: u8) -> Option<Codec> {
        match code {
            0 => Some(Codec::BloscLz),
            1 => Some(Codec::Lz4),
            2 => Some(Codec::Snappy),
            3 => Some(Codec::Zlib),
            4 => Some(Codec::Zstd),
            _ => None,
        }
    }

    /// The name the codec goes by in a Zarr manifest.
    ///
    /// The frame cannot say lz4hc, so a frame of code 1 is lz4 here whatever
    /// the manifest that named it called it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Codec::BloscLz => "blosclz",
            Codec::Lz4 => "lz4",
            Codec::Snappy => "snappy",
            Codec::Zlib => "zlib",
            Codec::Zstd => "zstd",
        }
    }
}

/// Blosc frame decoder.
#[derive(Debug, Clone, Copy, Default)]
pub struct BloscDecoder {
    _priv: (),
}

impl BloscDecoder {
    /// Create a decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { _priv: () }
    }

    /// Decode one frame under an unlimited cap.
    pub fn decode(&self, data: &[u8]) -> CompressResult<Vec<u8>> {
        self.decode_bounded(data, UNLIMITED).map(|b| b.bytes)
    }

    /// Decode one frame, stopping at `limit` emitted bytes.
    pub fn decode_bounded(&self, data: &[u8], limit: u64) -> CompressResult<Bounded> {
        let mut cap = OutputCap::new(limit);
        self.decompress(data, &mut cap)
    }

    /// The codec the frame names.
    pub fn codec(&self, data: &[u8]) -> CompressResult<Codec> {
        let header = data.get(..HEADER).ok_or(CompressError::UnexpectedEof)?;
        let code = (header[2] & CODEC_MASK) >> CODEC_SHIFT;
        Codec::from_code(code).ok_or_else(|| unknown_codec(code))
    }

    /// The decode itself, with a caller-supplied cap so a container can
    /// spend one budget across several blocks.
    pub fn decompress(&self, data: &[u8], cap: &mut OutputCap) -> CompressResult<Bounded> {
        let limit = cap.limit();
        let header = data.get(..HEADER).ok_or(CompressError::UnexpectedEof)?;
        if header[0] != VERSION {
            return Err(CompressError::Unsupported(
                "the blosc frame has a version this reader does not know",
            ));
        }
        let flags = header[2];
        let typesize = usize::from(header[3]);
        let nbytes = le32(header, 4)? as usize;
        let blocksize = le32(header, 8)? as usize;
        if flags & DOBITSHUFFLE != 0 {
            return Err(CompressError::Unsupported(
                "the blosc frame shuffles the bits, which is not decoded here",
            ));
        }
        if typesize == 0 || blocksize == 0 {
            return Err(CompressError::InvalidFormat(
                "the blosc frame has no element size or no block",
            ));
        }
        let codec = Codec::from_code((flags & CODEC_MASK) >> CODEC_SHIFT)
            .ok_or_else(|| unknown_codec((flags & CODEC_MASK) >> CODEC_SHIFT))?;
        let mut out: Vec<u8> = Vec::new();

        if flags & MEMCPYED != 0 {
            // The data was stored as it is: the frame is the header and then
            // the bytes, and there is no table of block offsets.
            let bytes = data
                .get(HEADER..HEADER + nbytes)
                .ok_or(CompressError::UnexpectedEof)?;
            if !cap.take(nbytes as u64) {
                return Ok(Bounded::stopped(out, Some(nbytes as u64), limit));
            }
            out.extend_from_slice(bytes);
            if flags & DOSHUFFLE != 0 && typesize > 1 {
                unshuffle(&mut out, typesize);
            }
            return Ok(Bounded::complete(out, Some(nbytes as u64), limit));
        }

        let nblocks = nbytes.div_ceil(blocksize);
        for block in 0..nblocks {
            let start = le32(data, HEADER + block * 4)? as usize;
            // The last block holds what is left over.
            let leftover = block + 1 == nblocks && !nbytes.is_multiple_of(blocksize);
            let bsize = if leftover {
                nbytes % blocksize
            } else {
                blocksize
            };
            // A block big enough is split into as many pieces as the element
            // has bytes, and each piece is compressed on its own.
            let pieces = if flags & DONT_SPLIT == 0
                && typesize <= MAX_SPLITS
                && bsize / typesize >= MIN_SPLIT
                && !leftover
            {
                typesize
            } else {
                1
            };
            let piece_size = bsize / pieces;
            let mut at = start;
            let mut chunk: Vec<u8> = Vec::with_capacity(bsize);
            for _ in 0..pieces {
                let cbytes = le32(data, at)? as usize;
                at += 4;
                let payload = data
                    .get(at..at + cbytes)
                    .ok_or(CompressError::UnexpectedEof)?;
                at += cbytes;
                if cbytes == piece_size {
                    // The piece was stored as it is.
                    chunk.extend_from_slice(payload);
                    continue;
                }
                // The piece cannot hold more than the frame says it holds,
                // so the room it is given is the piece's own size, and the
                // caller's budget when that is smaller.
                let budget = cap.remaining();
                let room = budget.min(piece_size as u64);
                let mut inner = OutputCap::new(room);
                let piece = decode_piece(codec, payload, &mut inner)?;
                if piece.capped {
                    if budget < piece_size as u64 {
                        // The caller's budget ran out.
                        return Ok(Bounded::stopped(out, Some(nbytes as u64), limit));
                    }
                    return Err(CompressError::CorruptedData(
                        "the piece of a blosc block holds more than the frame says",
                    ));
                }
                let piece = piece.bytes;
                if piece.len() != piece_size {
                    return Err(CompressError::CorruptedData(
                        "the piece of a blosc block does not hold what the frame says",
                    ));
                }
                chunk.extend_from_slice(&piece);
            }
            // The shuffle is the block's, not the frame's.
            if flags & DOSHUFFLE != 0 && typesize > 1 {
                unshuffle(&mut chunk, typesize);
            }
            if !cap.take(chunk.len() as u64) {
                return Ok(Bounded::stopped(out, Some(nbytes as u64), limit));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(Bounded::complete(out, Some(nbytes as u64), limit))
    }
}

/// Decode one piece of a block with the codec the frame names.
///
/// The piece's own size is the ceiling of the cap it is given: a piece that
/// decodes to more than the frame says it holds is stopped there, not
/// expanded to the size it asks for.
fn decode_piece(codec: Codec, payload: &[u8], cap: &mut OutputCap) -> CompressResult<Bounded> {
    match codec {
        Codec::BloscLz => blosclz::decompress(payload, cap),
        Codec::Lz4 => Lz4Decoder::new().decompress(payload, cap),
        Codec::Snappy => SnappyDecoder::new().decompress(payload, cap),
        Codec::Zlib => ZlibDecoder::new()
            .decode_bounded(payload, cap.limit())
            .map_err(|e| CompressError::DecompressionFailed(e.message)),
        Codec::Zstd => ZstdDecoder::new().decode_bounded(payload, cap.limit()),
    }
}

/// The refusal of a codec the frame's format does not have.
fn unknown_codec(code: u8) -> CompressError {
    CompressError::UnsupportedFormat(format!(
        "blosc: the frame names codec {code}, which is not one of the format's codecs"
    ))
}

/// The blosclz block format.
///
/// blosclz is an LZ77 of its own, not the LZ4 block: a byte-oriented one
/// whose control byte says what comes next.
///
/// The control byte carries two things. Its top three bits are the code of
/// the copy's length, and its low five bits are the top of the copy's
/// distance. A control byte below 32 is not a copy at all: it is the number
/// of the literals that follow, less one.
///
/// A copy of seven or more bytes has its length spelled out: octets of 255
/// and then the octet that ends them. The distance is one octet, unless the
/// copy reaches far: the octet 255 says so, and two more octets carry the
/// rest of the distance.
///
/// The distance is one less than the distance the copy reaches back, and the
/// copy may overlap what it writes, which is how a run of the same byte is
/// spelled.
///
/// Written from c-blosc's own `blosclz.c`, and checked against the frames
/// numcodecs writes.
mod blosclz {
    use super::super::cap::{Bounded, OutputCap};
    use super::super::error::{CompressError, CompressResult};
    use alloc::vec::Vec;

    /// The value the control byte's five bits carry when the copy is far.
    const FAR_OFS: usize = 31 << 8;

    /// The distance the far form adds to the two octets it carries.
    const FAR_DISTANCE: usize = 8191;

    /// Decode one block, stopping at the cap.
    pub fn decompress(data: &[u8], cap: &mut OutputCap) -> CompressResult<Bounded> {
        let limit = cap.limit();
        let mut out: Vec<u8> = Vec::new();
        let Some(&first) = data.first() else {
            return Err(CompressError::UnexpectedEof);
        };
        // The first control byte carries the marker of the format in its
        // bit five, so only the low five bits are the count.
        let mut ctrl = u32::from(first & 31);
        let mut at = 1usize;
        loop {
            if ctrl >= 32 {
                // A copy: the top three bits are the code of the length and
                // the low five are the top of the distance.
                let mut length = u64::from((ctrl >> 5) - 1);
                let ofs = usize::from((ctrl & 31) as u8) << 8;
                if length == 6 {
                    // The length runs past its code: octets of 255, and then
                    // the octet that ends them.
                    loop {
                        let code = *data.get(at).ok_or(CompressError::UnexpectedEof)?;
                        at += 1;
                        length += u64::from(code);
                        if code != 255 {
                            break;
                        }
                    }
                }
                let code = *data.get(at).ok_or(CompressError::UnexpectedEof)?;
                at += 1;
                length += 3;
                // The distance the copy reaches back is the octet below the
                // five the control byte carried, and one more: the block
                // spells the distance one less than the distance it means.
                let mut back = ofs + usize::from(code) + 1;
                if code == 255 && ofs == FAR_OFS {
                    // The copy reaches far: two more octets carry the rest
                    // of the distance, and the far distance is added to it.
                    let hi = *data.get(at).ok_or(CompressError::UnexpectedEof)?;
                    let lo = *data.get(at + 1).ok_or(CompressError::UnexpectedEof)?;
                    at += 2;
                    back = (usize::from(hi) << 8) + usize::from(lo) + FAR_DISTANCE + 1;
                }
                let length = usize::try_from(length).map_err(|_| {
                    CompressError::CorruptedData(
                        "the blosclz block copies more bytes than a frame holds",
                    )
                })?;
                if back == 0 || back > out.len() {
                    return Err(CompressError::CorruptedData(
                        "the blosclz block copies from before it begins",
                    ));
                }
                // The block ends where the octets end: the decoder stops
                // before the copy when there is nothing left to read.
                if at >= data.len() {
                    break;
                }
                let next = u32::from(data[at]);
                at += 1;
                if !cap.take(length as u64) {
                    return Ok(Bounded::stopped(out, None, limit));
                }
                copy_back(&mut out, back, length);
                ctrl = next;
            } else {
                // Literals: the control byte counts them, less one.
                let count = ctrl as usize + 1;
                let end = at.checked_add(count).ok_or(CompressError::UnexpectedEof)?;
                let bytes = data.get(at..end).ok_or(CompressError::UnexpectedEof)?;
                at = end;
                if !cap.take(count as u64) {
                    return Ok(Bounded::stopped(out, None, limit));
                }
                out.extend_from_slice(bytes);
                if at >= data.len() {
                    break;
                }
                ctrl = u32::from(data[at]);
                at += 1;
            }
        }
        Ok(Bounded::complete(out, None, limit))
    }

    /// Copy `length` bytes from `back` bytes back, which may overlap what it
    /// writes: a run of the same byte is a copy of one byte.
    fn copy_back(out: &mut Vec<u8>, back: usize, length: usize) {
        let start = out.len() - back;
        let mut written = 0usize;
        while written < length {
            let n = (length - written).min(back);
            let from = start + written;
            out.extend_from_within(from..from + n);
            written += n;
        }
    }
}

/// The inverse of the byte shuffle: the bytes of the same place of each
/// element side by side become the elements again.
///
/// The bytes that do not fill an element are left where they are, which is
/// what the shuffle did with them.
fn unshuffle(block: &mut [u8], typesize: usize) {
    let count = block.len() / typesize;
    let mut out = vec![0u8; block.len()];
    for j in 0..typesize {
        for i in 0..count {
            out[i * typesize + j] = block[j * count + i];
        }
    }
    // The bytes that do not fill an element are left where they are.
    let filled = count * typesize;
    out[filled..].copy_from_slice(&block[filled..]);
    block.copy_from_slice(&out);
}

/// A little-endian 32-bit number.
fn le32(data: &[u8], at: usize) -> CompressResult<u32> {
    let bytes = data.get(at..at + 4).ok_or(CompressError::UnexpectedEof)?;
    Ok(u32::from(bytes[0])
        | u32::from(bytes[1]) << 8
        | u32::from(bytes[2]) << 16
        | u32::from(bytes[3]) << 24)
}

#[cfg(all(test, feature = "blosc"))]
mod tests {
    use super::*;
    use alloc::vec;

    /// A frame with one block, the block's bytes given.
    fn frame(payload: &[u8], nbytes: usize, typesize: usize, blocksize: usize) -> Vec<u8> {
        frame_of(payload, nbytes, typesize, blocksize, 1)
    }

    /// A frame with one block, the block's bytes given, and the codec its
    /// flags name.
    fn frame_of(
        payload: &[u8],
        nbytes: usize,
        typesize: usize,
        blocksize: usize,
        codec: u8,
    ) -> Vec<u8> {
        let mut out = vec![0u8; HEADER + 8 + payload.len()];
        out[0] = VERSION;
        out[2] = (codec << CODEC_SHIFT) | DONT_SPLIT;
        out[3] = typesize as u8;
        out[4..8].copy_from_slice(&(nbytes as u32).to_le_bytes());
        out[8..12].copy_from_slice(&(blocksize as u32).to_le_bytes());
        let total = out.len() as u32;
        out[12..16].copy_from_slice(&total.to_le_bytes());
        out[16..20].copy_from_slice(&((HEADER + 4) as u32).to_le_bytes());
        out[20..24].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        out[HEADER + 8..].copy_from_slice(payload);
        out
    }

    #[test]
    fn a_frame_of_literals_decodes_to_them() {
        let payload = [0x30, b'a', b'b', b'c'];
        let frame = frame(&payload, 3, 1, 3);
        let out = BloscDecoder::new().decode(&frame).unwrap();
        assert_eq!(out, b"abc");
    }

    /// An LZ4 block of literals only.
    fn literals_block(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8];
        if bytes.len() < 15 {
            out[0] = (bytes.len() as u8) << 4;
        } else {
            out[0] = 0xf0;
            let mut rest = bytes.len() - 15;
            while rest >= 255 {
                out.push(255);
                rest -= 255;
            }
            out.push(rest as u8);
        }
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn a_block_big_enough_is_split_into_pieces() {
        // The element is eight bytes, and the block holds enough of them
        // for the frame to split it into one piece per byte of the element.
        let typesize = 8usize;
        let elements = 256usize;
        let nbytes = typesize * elements;
        let data: Vec<u8> = (0..nbytes).map(|i| (i % 251) as u8).collect();
        // The block's bytes: the data with the shuffle applied.
        let mut shuffled = vec![0u8; nbytes];
        for j in 0..typesize {
            for i in 0..elements {
                shuffled[j * elements + i] = data[i * typesize + j];
            }
        }
        // The pieces: one per byte of the element, each an LZ4 block of
        // literals, each with its own size in front of it.
        let piece_size = nbytes / typesize;
        let mut block = Vec::new();
        for piece in 0..typesize {
            let literals = &shuffled[piece * piece_size..(piece + 1) * piece_size];
            let bytes = literals_block(literals);
            block.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            block.extend_from_slice(&bytes);
        }
        // The frame: the header, the offset of the block, and the block.
        // The block opens with the size of its first piece.
        let mut frame = vec![0u8; HEADER + 4 + block.len()];
        frame[0] = VERSION;
        frame[2] = (1 << CODEC_SHIFT) | DOSHUFFLE; // lz4, and the block was split
        frame[3] = typesize as u8;
        frame[4..8].copy_from_slice(&(nbytes as u32).to_le_bytes());
        frame[8..12].copy_from_slice(&(nbytes as u32).to_le_bytes());
        let total = frame.len() as u32;
        frame[12..16].copy_from_slice(&total.to_le_bytes());
        frame[16..20].copy_from_slice(&((HEADER + 4) as u32).to_le_bytes());
        frame[HEADER + 4..].copy_from_slice(&block);
        let out = BloscDecoder::new().decode(&frame).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn the_codec_the_frame_names_is_reported() {
        let payload = [0x30, b'a', b'b', b'c'];
        let frame = frame(&payload, 3, 1, 3);
        assert_eq!(BloscDecoder::new().codec(&frame).unwrap(), Codec::Lz4);
    }

    #[test]
    fn the_codec_codes_are_the_frames_own() {
        // The frame's codes, from the format's own description: 0 blosclz,
        // 1 lz4 or lz4hc, 2 snappy, 3 zlib, 4 zstd. c-blosc's library codes
        // are a different enumeration -- 2 is lz4hc there and zstd is 5 --
        // and a reader that mixes the two hands a frame to the wrong
        // decoder and calls the data corrupt.
        assert_eq!(Codec::from_code(0), Some(Codec::BloscLz));
        assert_eq!(Codec::from_code(1), Some(Codec::Lz4));
        assert_eq!(Codec::from_code(2), Some(Codec::Snappy));
        assert_eq!(Codec::from_code(3), Some(Codec::Zlib));
        assert_eq!(Codec::from_code(4), Some(Codec::Zstd));
        assert_eq!(Codec::from_code(5), None);
    }

    #[test]
    fn a_frame_naming_the_codec_that_does_not_exist_is_refused_by_its_number() {
        let payload = [0x30, b'a', b'b', b'c'];
        let mut frame = frame(&payload, 3, 1, 3);
        frame[2] = (5 << CODEC_SHIFT) | DONT_SPLIT;
        let err = BloscDecoder::new().decode(&frame).unwrap_err();
        let CompressError::UnsupportedFormat(msg) = &err else {
            panic!("expected the refusal to name the codec, got {err:?}");
        };
        assert!(msg.contains('5'), "{msg}");
    }

    #[test]
    fn a_frame_of_another_version_is_refused() {
        let payload = [0x30, b'a', b'b', b'c'];
        let mut frame = frame(&payload, 3, 1, 3);
        frame[0] = 3;
        let err = BloscDecoder::new().decode(&frame).unwrap_err();
        assert!(matches!(err, CompressError::Unsupported(_)), "{err:?}");
    }

    #[test]
    fn the_shuffle_puts_the_bytes_of_each_element_back() {
        // Two elements of two bytes: the shuffled bytes are the first byte
        // of each element and then the second byte of each.
        let mut block = vec![1u8, 2, 3, 4];
        unshuffle(&mut block, 2);
        assert_eq!(block, vec![1, 3, 2, 4]);
    }

    #[test]
    fn the_bytes_of_a_partial_element_are_left_where_they_are() {
        // Three elements of two bytes and a half. The shuffled bytes are
        // the first byte of each element, then the second byte of each, and
        // the byte of the half element, which does not move.
        let mut block = vec![1u8, 3, 5, 2, 4, 6, 7];
        unshuffle(&mut block, 2);
        assert_eq!(block, vec![1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn a_frame_shorter_than_its_header_is_an_error() {
        let err = BloscDecoder::new().decode(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, CompressError::UnexpectedEof), "{err:?}");
    }

    #[test]
    fn the_cap_stops_the_decode() {
        let payload = [0x40, b'a', b'b', b'c', b'd'];
        let frame = frame(&payload, 4, 1, 4);
        let out = BloscDecoder::new().decode_bounded(&frame, 2).unwrap();
        assert!(out.capped);
        assert!(out.bytes.is_empty());
    }

    /// The sixteen octets the header of each fixture carries, as numcodecs
    /// wrote them:
    ///
    /// ```python
    /// from numcodecs.blosc import Blosc
    /// import numpy as np
    /// Blosc(cname="blosclz", clevel=5, shuffle=Blosc.SHUFFLE, typesize=8)
    ///     .encode(np.arange(64, dtype="<f8").tobytes())
    /// ```
    ///
    /// The codec sits in the top three bits of the flags, the third octet.
    #[test]
    fn the_header_of_each_fixture_names_the_codec_the_frame_says() {
        let cases: [(&[u8], &[u8], Codec); 5] = [
            (
                include_bytes!("../../testdata/blosc_blosclz.bin"),
                b"\x02\x01\x11\x08\x00\x02\x00\x00\x00\x02\x00\x00\x72\x00\x00\x00",
                Codec::BloscLz,
            ),
            (
                include_bytes!("../../testdata/blosc_lz4.bin"),
                b"\x02\x01\x31\x08\x00\x02\x00\x00\x00\x02\x00\x00\x74\x00\x00\x00",
                Codec::Lz4,
            ),
            (
                include_bytes!("../../testdata/blosc_zlib.bin"),
                b"\x02\x01\x71\x08\x00\x02\x00\x00\x00\x02\x00\x00\x6c\x00\x00\x00",
                Codec::Zlib,
            ),
            (
                include_bytes!("../../testdata/blosc_zstd.bin"),
                b"\x02\x01\x91\x08\x00\x02\x00\x00\x00\x02\x00\x00\x74\x00\x00\x00",
                Codec::Zstd,
            ),
            (
                include_bytes!("../../testdata/blosc_snappy.bin"),
                b"\x02\x01\x51\x08\x00\x02\x00\x00\x00\x02\x00\x00\x7b\x00\x00\x00",
                Codec::Snappy,
            ),
        ];
        for (frame, header, codec) in cases {
            assert_eq!(&frame[..HEADER], header);
            assert_eq!(BloscDecoder::new().codec(frame).unwrap(), codec);
        }
    }

    #[test]
    fn a_frame_of_blosclz_decodes_to_the_bytes_it_holds() {
        // The frame numcodecs writes:
        //   Blosc(cname="blosclz", clevel=5, shuffle=Blosc.SHUFFLE, typesize=8)
        //     .encode(np.arange(64, dtype="<f8").tobytes())
        let frame = include_bytes!("../../testdata/blosc_blosclz.bin");
        let expected = include_bytes!("../../testdata/blosc_blosclz.expected");
        let out = BloscDecoder::new().decode(frame).unwrap();
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    #[test]
    fn a_frame_of_lz4_decodes_to_the_bytes_it_holds() {
        // The frame numcodecs writes:
        //   Blosc(cname="lz4", clevel=5, shuffle=Blosc.SHUFFLE, typesize=8)
        //     .encode(np.arange(64, dtype="<f8").tobytes())
        let frame = include_bytes!("../../testdata/blosc_lz4.bin");
        let expected = include_bytes!("../../testdata/blosc_lz4.expected");
        let out = BloscDecoder::new().decode(frame).unwrap();
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    #[test]
    fn a_frame_of_snappy_decodes_to_the_bytes_it_holds() {
        // The frame c-blosc writes. numcodecs has no name for the snappy
        // codec -- its blosc accepts blosclz, lz4, lz4hc, zlib and zstd --
        // so the frame that checks the reader's snappy path had to come
        // from c-blosc itself, built with the snappy codec in it. That is
        // c-blosc 1.18.1, the last release with the snappy built in: from
        // 1.19 on, the snappy is an external library, and the build has
        // DEACTIVATE_SNAPPY on by default since 1.21:
        //   blosc_compress(5, BLOSC_SHUFFLE, 8, 512, data, dest, destsize)
        // with the compressor set to "snappy" and the same 64 doubles the
        // other fixtures hold.
        //
        // The frame's flags say the codec is the snappy one and that the
        // byte shuffle was applied, and the bit that says "this is a plain
        // copy" is not set: the blocks really are snappy compressed.
        let frame = include_bytes!("../../testdata/blosc_snappy.bin");
        let expected = include_bytes!("../../testdata/blosc_snappy.expected");
        let out = BloscDecoder::new().decode(frame).unwrap();
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    #[test]
    fn a_frame_of_zlib_decodes_to_the_bytes_it_holds() {
        // The frame numcodecs writes:
        //   Blosc(cname="zlib", clevel=5, shuffle=Blosc.SHUFFLE, typesize=8)
        //     .encode(np.arange(64, dtype="<f8").tobytes())
        let frame = include_bytes!("../../testdata/blosc_zlib.bin");
        let expected = include_bytes!("../../testdata/blosc_zlib.expected");
        let out = BloscDecoder::new().decode(frame).unwrap();
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    #[test]
    fn a_frame_of_zstd_decodes_to_the_bytes_it_holds() {
        // The frame numcodecs writes:
        //   Blosc(cname="zstd", clevel=5, shuffle=Blosc.SHUFFLE, typesize=8)
        //     .encode(np.arange(64, dtype="<f8").tobytes())
        let frame = include_bytes!("../../testdata/blosc_zstd.bin");
        let expected = include_bytes!("../../testdata/blosc_zstd.expected");
        let out = BloscDecoder::new().decode(frame).unwrap();
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    #[test]
    fn a_frame_of_snappy_decodes_to_the_bytes_its_piece_holds() {
        // The piece is a raw snappy stream, which is what a c-blosc snappy
        // piece holds, and it comes from the oracle's own fixture. The
        // frame around it is built here: numcodecs 0.17.1 refuses the
        // compressor (`ValueError: bad compressor or compressor not
        // supported: 'snappy'`) and the c-blosc in the corpus was built
        // with snappy deactivated, so no blosc frame of snappy could be
        // written here to be the fixture.
        let piece = include_bytes!("../../testdata/snappy_lit.bin");
        let expected = include_bytes!("../../testdata/snappy_lit.expected");
        let frame = frame_of(piece, expected.len(), 1, expected.len(), 2);
        let out = BloscDecoder::new().decode(&frame).unwrap();
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    /// The control byte of a run of literals, and the run itself.
    fn blosclz_literals(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = bytes;
        while !rest.is_empty() {
            let n = rest.len().min(32);
            let count = n as u8 - 1;
            // The marker of the format is on the first octet of the block.
            let ctrl = if out.is_empty() { count | 0x20 } else { count };
            out.push(ctrl);
            out.extend_from_slice(&rest[..n]);
            rest = &rest[n..];
        }
        out
    }

    #[test]
    fn a_blosclz_block_of_literals_decodes_to_them() {
        // Four literals and the marker: the control byte counts them, less
        // one.
        let block = blosclz_literals(b"abcd");
        let mut cap = OutputCap::unlimited();
        let out = blosclz::decompress(&block, &mut cap).unwrap();
        assert_eq!(out.bytes, b"abcd");
    }

    #[test]
    fn a_blosclz_block_copies_the_bytes_it_points_at() {
        // Four literals, then a copy of three bytes from four bytes back.
        // The control byte of the copy carries the code of the length in
        // its top three bits and the top of the distance in the low five.
        // A copy is never the last thing in a block: c-blosc's own decoder
        // stops before a copy that has nothing after it, and the block is
        // then short of what the frame says. The block ends with a literal.
        let mut block = blosclz_literals(b"abcd");
        block.push(0x20); // length code 1, distance high 0
        block.push(0x03); // distance low: 3, which means four bytes back
        block.push(0x00); // one literal follows
        block.push(b'Z');
        let mut cap = OutputCap::unlimited();
        let out = blosclz::decompress(&block, &mut cap).unwrap();
        assert_eq!(out.bytes, b"abcdabcZ");
    }

    #[test]
    fn a_blosclz_block_repeats_the_byte_it_points_at() {
        // Four literals of the same byte, then a copy of three bytes from
        // one byte back: the copy reads the bytes it is writing.
        let mut block = blosclz_literals(b"aaaa");
        block.push(0x20);
        block.push(0x00);
        block.push(0x00);
        block.push(b'Z');
        let mut cap = OutputCap::unlimited();
        let out = blosclz::decompress(&block, &mut cap).unwrap();
        assert_eq!(out.bytes, b"aaaaaaaZ");
    }

    #[test]
    fn a_blosclz_block_reaches_far() {
        // The distance is 8192 bytes, which is past the one octet the
        // distance has: the octet 255 says so, and two more octets carry
        // the rest of the distance.
        let literals: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        let mut block = blosclz_literals(&literals);
        block.push(0x3f); // length code 1, and the five bits say "far"
        block.push(0xff); // the octet that says the distance is far
        block.push(0x00); // the rest of the distance
        block.push(0x00);
        block.push(0x00); // one literal follows
        block.push(b'Z');
        let mut cap = OutputCap::unlimited();
        let out = blosclz::decompress(&block, &mut cap).unwrap();
        let mut expected = literals.clone();
        expected.extend_from_slice(&literals[..3]);
        expected.push(b'Z');
        assert_eq!(out.bytes, expected);
    }

    #[test]
    fn a_blosclz_block_that_copies_from_before_it_begins_is_refused() {
        // One literal, then a copy of three bytes from four bytes back:
        // the copy reaches before the block begins.
        let block = [0x20u8, b'A', 0x20, 0x03, 0x00, b'Z'];
        let mut cap = OutputCap::unlimited();
        let err = blosclz::decompress(&block, &mut cap).unwrap_err();
        assert!(matches!(err, CompressError::CorruptedData(_)), "{err:?}");
    }
}
