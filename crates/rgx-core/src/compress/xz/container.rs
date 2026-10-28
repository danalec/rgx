// SPDX-License-Identifier: Apache-2.0

//! The .xz container format: stream headers and footers, blocks with
//! optional declared sizes, padding, integrity checks, and the index the
//! footer points at.
//!
//! Independent reimplementation of the published container format
//! (stream/block/index/footer framing, the multibyte integer encoding,
//! and the four check types), written from the format description rather
//! than from any implementation's source. The compressed payload is
//! LZMA2, decoded by [`crate::compress::lzma`].
//!
//! The format's own caution governs the decode: §3.1.4 says the Block
//! Header and Index fields "may contain (intentionally or
//! unintentionally) invalid information", so the extent of the
//! Compressed Data is walked from the LZMA2 control bytes, a declared
//! Compressed Size is only trusted once it matches that walk (§3.1.3),
//! and the Index is checked against what the blocks *really* occupied
//! (§4.2/§4.3) rather than against what their headers claimed.

use crate::compress::crc32::crc32;
use crate::compress::error::{CompressError, CompressResult};
use crate::compress::lzma::LzmaDecoder;
use alloc::format;
use alloc::vec::Vec;

/// The six-byte stream magic (§2.1.1.1).
pub const XZ_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];

/// The two-byte stream footer magic (§2.1.2).
pub const FOOTER_MAGIC: [u8; 2] = *b"YZ";

/// Stream Header: magic + flags + CRC32 (§2.1.1).
const STREAM_HEADER_LEN: usize = 12;

/// Stream Footer: CRC32 + backward size + flags + magic (§2.1.2).
const STREAM_FOOTER_LEN: usize = 12;

/// The LZMA2 filter id (§5.3.1) — the only filter this decoder runs.
const FILTER_LZMA2: u64 = 0x21;

/// A Block Header larger than this is not something the format needs.
const MAX_BLOCK_HEADER: usize = 1024;

// Check types (§2.1.1.2 / §3.3).
const CHECK_NONE: u8 = 0x00;
const CHECK_CRC32: u8 = 0x01;
const CHECK_CRC64: u8 = 0x04;
const CHECK_SHA256: u8 = 0x0A;

fn invalid(msg: &'static str) -> CompressError {
    CompressError::InvalidFormat(msg)
}

/// Bytes the Check field occupies for a check id, or `None` when the id
/// is not one the format defines.
fn check_size(id: u8) -> Option<usize> {
    match id {
        CHECK_NONE => Some(0),
        CHECK_CRC32 => Some(4),
        CHECK_CRC64 => Some(8),
        CHECK_SHA256 => Some(32),
        _ => None,
    }
}

/// One multibyte integer (§1.2): seven data bits per byte, little-endian
/// groups, a continuation bit set on every byte but the last. The
/// encoding is canonical — no redundant trailing zero group — so a
/// non-canonical integer is an error, not a value.
fn read_vli(data: &[u8], pos: &mut usize) -> CompressResult<u64> {
    // At most 9 groups of 7 bits carry the 63-bit value space; anything
    // longer cannot be a well-formed integer no matter what the bits say.
    let mut groups: Vec<u8> = Vec::with_capacity(9);
    loop {
        let Some(&byte) = data.get(*pos) else {
            return Err(invalid("truncated multibyte integer"));
        };
        *pos += 1;
        groups.push(byte);
        if byte & 0x80 == 0 {
            break;
        }
        if groups.len() == 9 {
            return Err(invalid("multibyte integer too long"));
        }
    }
    let last = *groups.last().expect("loop always pushes one");
    // Canonical form: a multi-byte encoding must not end in 0x00.
    if groups.len() > 1 && last == 0x00 {
        return Err(invalid("non-canonical multibyte integer"));
    }
    let mut value: u64 = 0;
    for (i, &byte) in groups.iter().enumerate() {
        let piece = u64::from(byte & 0x7F);
        if i == 8 && piece > 1 {
            return Err(invalid("multibyte integer exceeds 63 bits"));
        }
        value |= piece << (7 * i);
    }
    Ok(value)
}

/// Everything a Block Header tells us that the decoder needs.
// `len` and `filter_id` are parsed and kept for completeness; the
// decoder advances by its own cursor and needs neither.
#[allow(dead_code)]
struct BlockHeader {
    /// Total header length including the size byte, flags, fields and CRC32.
    len: usize,
    /// Filter ID of the last filter in the chain.
    filter_id: u64,
    /// LZMA2 dictionary size, when the filter is LZMA2.
    dict_size: u32,
    /// Declared Compressed Size, when present in the flags.
    compressed_size: Option<u64>,
    /// Declared Uncompressed Size, when present in the flags.
    uncompressed_size: Option<u64>,
}

/// One filter's flags as the Block Header carries them (§3.1.5).
struct FilterFlags {
    id: u64,
    props: Vec<u8>,
}

/// Parse a Block Header at `data[*pos..]` (§3.1).
fn parse_block_header(data: &[u8], pos: &mut usize) -> CompressResult<BlockHeader> {
    let start = *pos;
    let first = *data
        .get(start)
        .ok_or_else(|| invalid("truncated block header"))?;
    let len = (first as usize + 1) * 4;
    let end = start
        .checked_add(len)
        .filter(|e| *e <= data.len())
        .ok_or_else(|| invalid("truncated block header"))?;
    if len > MAX_BLOCK_HEADER {
        return Err(invalid("block header too large"));
    }
    let header = &data[start..end];

    // §3.1.7: the CRC32 covers everything in the header except itself.
    let stored = u32::from_le_bytes([
        header[len - 4],
        header[len - 3],
        header[len - 2],
        header[len - 1],
    ]);
    if crc32(&header[..len - 4]) != stored {
        return Err(invalid("block header CRC32 mismatch"));
    }

    let mut fields_end = len - 4;
    let mut cursor = 2usize;
    let flags = *header
        .get(1)
        .ok_or_else(|| invalid("truncated block header"))?;
    if flags & 0x3C != 0 {
        return Err(invalid("reserved block flag bits set"));
    }
    let filter_count = (flags & 0x03) as usize + 1;
    let compressed_size = if flags & 0x40 != 0 {
        Some(read_vli(header, &mut cursor)?)
    } else {
        None
    };
    let uncompressed_size = if flags & 0x80 != 0 {
        Some(read_vli(header, &mut cursor)?)
    } else {
        None
    };

    let filters = read_filter_chain(header, &mut cursor, fields_end, filter_count)?;

    // §3.1.6: the remainder is padding and must be null.
    if header[cursor..fields_end].iter().any(|&b| b != 0) {
        return Err(invalid("block header padding is not null"));
    }

    // LZMA2 must be the last filter, so only the last one matters to us;
    // any earlier filter would have to run first and changes the data, so
    // a chain we do not implement is rejected rather than half-applied.
    let Some(last) = filters.last() else {
        return Err(invalid("block header declares no filters"));
    };
    if last.id != FILTER_LZMA2 {
        return Err(CompressError::UnsupportedFormat(format!(
            "xz: unsupported filter 0x{:x} (only LZMA2 is implemented)",
            last.id
        )));
    }
    if filters.len() > 1 {
        return Err(CompressError::UnsupportedFormat(
            "xz: multi-filter chains are not implemented".into(),
        ));
    }
    if last.props.len() != 1 {
        return Err(invalid("LZMA2 properties must be exactly one byte"));
    }
    let dict_size = lzma2_dict_size(last.props[0])?;

    fields_end = 0; // end of the field walk; `len` is what the caller advances by
    let _ = fields_end;
    *pos = end;
    Ok(BlockHeader {
        len,
        filter_id: last.id,
        dict_size,
        compressed_size,
        uncompressed_size,
    })
}

/// Read the Filter Flags list: each entry is an id, a properties length,
/// and that many property bytes (§3.1.5).
fn read_filter_chain(
    header: &[u8],
    cursor: &mut usize,
    fields_end: usize,
    count: usize,
) -> CompressResult<Vec<FilterFlags>> {
    let mut filters = Vec::with_capacity(count);
    for _ in 0..count {
        let id = read_vli(header, cursor)?;
        let props_len = read_vli(header, cursor)? as usize;
        let props_end = cursor
            .checked_add(props_len)
            .filter(|e| *e <= fields_end)
            .ok_or_else(|| invalid("filter properties run past the block header"))?;
        filters.push(FilterFlags {
            id,
            props: header[*cursor..props_end].to_vec(),
        });
        *cursor = props_end;
    }
    Ok(filters)
}

/// LZMA2 dictionary size from its one properties byte (§5.3.1).
///
/// One-bit mantissa, five-bit exponent: `(2 | (bits & 1)) << (bits / 2 + 11)`,
/// with raw value 40 meaning `u32::MAX`.
fn lzma2_dict_size(byte: u8) -> CompressResult<u32> {
    if byte & 0xC0 != 0 {
        return Err(invalid("reserved bits set in LZMA2 dictionary size"));
    }
    let bits = byte & 0x3F;
    if bits > 40 {
        return Err(invalid("LZMA2 dictionary size above 4 GiB"));
    }
    if bits == 40 {
        return Ok(u32::MAX);
    }
    let size = (2 | (bits as u32 & 1)) << (bits as u32 / 2 + 11);
    Ok(size)
}

/// Length of the LZMA2 chunk stream at the front of `data`.
///
/// The LZMA2 framing is self-delimiting, so this is how the extent of
/// Compressed Data is found when the Block Header does not declare a
/// Compressed Size — which is the common case for files from the `xz`
/// CLI.
fn lzma2_stream_len(data: &[u8]) -> CompressResult<usize> {
    let mut pos = 0usize;
    loop {
        let Some(&control) = data.get(pos) else {
            return Err(invalid("LZMA2 stream is not terminated"));
        };
        pos += 1;
        match classify_chunk(control)? {
            ChunkKind::End => return Ok(pos),
            ChunkKind::Uncompressed => {
                let size = read_be16(data, pos)? as usize + 1;
                pos += 2;
                pos = take_payload(data, pos, size)?;
            }
            ChunkKind::Lzma { has_props } => {
                let _unpacked = read_be16(data, pos)?;
                let packed = read_be16(data, pos + 2)? as usize;
                pos += 4;
                if has_props {
                    pos += 1;
                }
                pos = take_payload(data, pos, packed + 1)?;
            }
        }
    }
}

/// What an LZMA2 control byte says the next chunk is.
enum ChunkKind {
    End,
    Uncompressed,
    Lzma { has_props: bool },
}

fn classify_chunk(control: u8) -> CompressResult<ChunkKind> {
    match control {
        0x00 => Ok(ChunkKind::End),
        0x01 | 0x02 => Ok(ChunkKind::Uncompressed),
        0x80..=0xFF => Ok(ChunkKind::Lzma {
            has_props: control >= 0xC0,
        }),
        _ => Err(invalid("invalid LZMA2 control byte")),
    }
}

fn read_be16(data: &[u8], at: usize) -> CompressResult<u16> {
    let b0 = *data
        .get(at)
        .ok_or_else(|| invalid("truncated LZMA2 chunk header"))?;
    let b1 = *data
        .get(at + 1)
        .ok_or_else(|| invalid("truncated LZMA2 chunk header"))?;
    Ok(u16::from_be_bytes([b0, b1]))
}

fn take_payload(data: &[u8], pos: usize, size: usize) -> CompressResult<usize> {
    let end = pos
        .checked_add(size)
        .filter(|e| *e <= data.len())
        .ok_or_else(|| invalid("truncated LZMA2 chunk"))?;
    Ok(end)
}

/// XZ reader.
pub struct XzReader;

/// What one block contributed to the decode, kept for the Index check.
struct BlockExtent {
    /// Unpadded Size (§4.3.1): header + compressed data + check.
    unpadded: u64,
    /// Bytes the block actually produced.
    uncompressed: u64,
}

impl XzReader {
    /// Decompress a single `.xz` stream.
    pub fn decompress(data: &[u8]) -> CompressResult<Vec<u8>> {
        Self::decompress_bounded(data, crate::compress::cap::UNLIMITED).map(|b| b.bytes)
    }

    /// Decompress a single `.xz` stream without expanding it past `limit`
    /// bytes.
    ///
    /// §3.1.1.2 puts an optional Uncompressed Size in the Block Header, so
    /// a block that declares more than the limit is refused from the
    /// declaration, before its LZMA2 payload is walked. The field is
    /// optional and §3.1.4 says it "may contain (intentionally or
    /// unintentionally) invalid information", so it cannot be the only
    /// check: the LZMA2 pass is capped as well, and the Index verification
    /// §4.2/§4.3 does is skipped for a stream the cap cut short, because a
    /// partial decode has no business being compared against a full one.
    pub fn decompress_bounded(
        data: &[u8],
        limit: u64,
    ) -> CompressResult<crate::compress::cap::Bounded> {
        use crate::compress::cap::{Bounded, OutputCap};
        if data.len() < STREAM_HEADER_LEN + STREAM_FOOTER_LEN {
            return Err(invalid("file is too short to be an XZ stream"));
        }
        if data[..6] != XZ_MAGIC {
            return Err(invalid("bad magic bytes"));
        }
        let check_id = parse_stream_header(data)?;

        let mut out = Vec::new();
        let mut cap = OutputCap::new(limit);
        let mut pos = STREAM_HEADER_LEN;
        let mut extents: Vec<BlockExtent> = Vec::new();
        // Stop at the Index, which begins with a 0x00 byte where a Block
        // Header Size would be.
        while pos < data.len() && data[pos] != 0x00 {
            let before = pos;
            match decode_one_block(data, &mut pos, check_id, &mut cap)? {
                BlockOutcome::Done { bytes, extent } => {
                    extents.push(extent);
                    out.extend_from_slice(&bytes);
                }
                BlockOutcome::Capped { bytes, declared } => {
                    out.extend_from_slice(&bytes);
                    return Ok(Bounded::stopped(out, declared, limit));
                }
            }
            let _ = before;
            if pos > data.len() {
                return Err(invalid("truncated before the index"));
            }
        }

        let records = check_index_and_footer(data, pos, &extents)?;
        let _ = records;
        Ok(Bounded::complete(out, None, limit))
    }

    /// Decompress every stream in a possibly concatenated `.xz` file.
    ///
    /// Stream Padding is a run of null bytes between streams (§2.2), and
    /// the specification requires its size to be a multiple of four so
    /// that consecutive Streams stay four-byte aligned. `xz -t` rejects a
    /// file that pads by five; this did not, which meant a file that
    /// every other tool calls corrupt decoded here.
    pub fn decompress_all(data: &[u8]) -> CompressResult<Vec<u8>> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        // A standalone file is one or more Streams, with Stream Padding
        // only *between* or after them: the grammar cannot start with
        // padding, and "one or more" rules out a file that is nothing but
        // padding. liblzma gets this structurally, by only ever entering
        // its padding state from an already-parsed footer. Recognising
        // padding at offset 0 instead accepts files it calls corrupt.
        let mut saw_stream = false;
        while pos < data.len() {
            if data[pos] == 0x00 {
                if !saw_stream {
                    return Err(invalid("Stream Padding before the first Stream"));
                }
                let start = pos;
                while pos < data.len() && data[pos] == 0x00 {
                    pos += 1;
                }
                if !(pos - start).is_multiple_of(4) {
                    return Err(invalid("Stream Padding is not a multiple of four bytes"));
                }
                continue;
            }
            let start = pos;
            let stream = Self::decompress(&data[start..])?;
            out.extend_from_slice(&stream);
            pos = start + stream_span(&data[start..])?;
            saw_stream = true;
        }
        if !saw_stream {
            return Err(invalid("not an XZ file: no Stream"));
        }
        Ok(out)
    }
}

/// How one block turned out.
enum BlockOutcome {
    Done {
        bytes: Vec<u8>,
        extent: BlockExtent,
    },
    /// The cap stopped this block; the caller keeps the prefix. declared
    /// is the block's own Uncompressed Size claim, when it made one.
    Capped {
        bytes: Vec<u8>,
        declared: Option<u64>,
    },
}

/// Decode the block at `*pos`, advancing past its padding and Check.
fn decode_one_block(
    data: &[u8],
    pos: &mut usize,
    check_id: u8,
    cap: &mut crate::compress::cap::OutputCap,
) -> CompressResult<BlockOutcome> {
    let header_start = *pos;
    let header = parse_block_header(data, pos)?;
    let data_start = *pos;

    if let Some(declared) = header.uncompressed_size {
        if !cap.fits(declared) {
            return Ok(BlockOutcome::Capped {
                bytes: Vec::new(),
                declared: Some(declared),
            });
        }
    }
    // The real extent of the Compressed Data, walked from the LZMA2
    // control bytes. Section 3.1.4 says this is the only reliable way to
    // learn it: "the Block Header and Index fields may contain
    // (intentionally or unintentionally) invalid information".
    let real_len = lzma2_stream_len(&data[data_start..])?;
    if let Some(declared) = header.compressed_size {
        // §3.1.2: a declared Compressed Size of zero is invalid.
        if declared == 0 {
            return Err(invalid("Compressed Size must be non-zero"));
        }
        // §3.1.3: "If the Compressed Size doesn't match the size of
        // the Compressed Data field, the decoder MUST indicate an
        // error." Trusting the declared value instead let a file
        // that `xz -t` calls corrupt decode here, and it also made
        // the section 4.3 check below compare the Index against a
        // size that was itself never verified.
        if declared as usize != real_len {
            return Err(invalid(
                "Compressed Size does not match the Compressed Data",
            ));
        }
    }
    let compressed = data
        .get(data_start..data_start + real_len)
        .ok_or_else(|| invalid("compressed data out of range"))?;

    let decoded =
        LzmaDecoder::new().decode_lzma2_bounded(compressed, header.dict_size, cap.remaining())?;
    if decoded.capped {
        return Ok(BlockOutcome::Capped {
            bytes: decoded.bytes,
            declared: header.uncompressed_size,
        });
    }
    cap.take(decoded.bytes.len() as u64);
    if let Some(declared) = header.uncompressed_size {
        if declared != decoded.bytes.len() as u64 {
            return Err(invalid("Uncompressed Size does not match the decoded data"));
        }
    }
    // §3 orders a Block as Header, Compressed Data, Block Padding,
    // Check — the Check is NOT immediately after the Compressed
    // Data. §3.3 inserts 0-3 null bytes so that the Block is a
    // multiple of four, which (because the Block Header is itself
    // a multiple of four and starts four-byte aligned) means the
    // Check sits at the next four-byte boundary.
    let block_end = pad_to_four(data, data_start + real_len)?;
    let check_len = check_size_of(check_id);
    verify_check(data, block_end, check_id, &decoded.bytes)?;
    // Unpadded Size is the Block Header, the Compressed Data
    // and the Check -- and NOT the Block Padding, which sits
    // between the data and the Check and is the one thing this
    // field excludes.
    let extent = BlockExtent {
        unpadded: ((data_start - header_start) + real_len + check_len) as u64,
        uncompressed: decoded.bytes.len() as u64,
    };
    *pos = block_end + check_len;
    Ok(BlockOutcome::Done {
        bytes: decoded.bytes,
        extent,
    })
}

/// Parse the Index and Stream Footer (§3.4, §2.1.2) and return the
/// footer's Backward Size with the record list as `(unpadded size,
/// uncompressed size)` pairs. No comparison against the blocks happens
/// here; that is §4.3's job and lives in [`check_index_and_footer`].
fn parse_index_and_footer(
    data: &[u8],
    index_start: usize,
) -> CompressResult<(u64, Vec<(u64, u64)>)> {
    let mut p = index_start;
    // §3.4: the Index starts with a null indicator byte.
    if *data.get(p).ok_or_else(|| invalid("truncated index"))? != 0x00 {
        return Err(invalid("index indicator is not zero"));
    }
    p += 1;
    let count = read_vli(data, &mut p)?;
    let mut records = Vec::with_capacity(count.min(4096) as usize);
    for _ in 0..count {
        let unpadded = read_vli(data, &mut p)?;
        let uncompressed = read_vli(data, &mut p)?;
        records.push((unpadded, uncompressed));
    }
    let index_end = pad_to_four(data, p)?;
    let stored = read_le32(data, index_end, "truncated index CRC")?;
    if crc32(&data[index_start..index_end]) != stored {
        return Err(invalid("index CRC32 mismatch"));
    }
    let index_size = index_end + 4 - index_start;

    // Stream Footer (§2.1.2).
    let footer = data
        .get(index_end + 4..index_end + 4 + STREAM_FOOTER_LEN)
        .ok_or_else(|| invalid("truncated stream footer"))?;
    let backward_size = u32::from_le_bytes([footer[4], footer[5], footer[6], footer[7]]);
    // Backward Size counts the Index in four-byte units, minus one.
    if (backward_size as usize + 1) * 4 != index_size {
        return Err(invalid(
            "stream footer backward size does not match the index",
        ));
    }
    if footer[8..10] != data[6..8] {
        return Err(invalid("stream footer flags do not match the header"));
    }
    if footer[10..12] != FOOTER_MAGIC {
        return Err(invalid("bad stream footer magic"));
    }
    let fcrc = u32::from_le_bytes([footer[0], footer[1], footer[2], footer[3]]);
    if crc32(&footer[4..10]) != fcrc {
        return Err(invalid("stream footer CRC32 mismatch"));
    }
    Ok((u64::from(backward_size), records))
}

/// Parse the Index and Stream Footer and check both against what the
/// blocks really occupied (§3.4, §2.1.2, §4.2, §4.3).
fn check_index_and_footer(
    data: &[u8],
    index_start: usize,
    extents: &[BlockExtent],
) -> CompressResult<Vec<(u64, u64)>> {
    let (_, records) = parse_index_and_footer(data, index_start)?;

    // §4.2: the Number of Records is the number of Blocks, and a
    // decoder that has decoded them all and finds a different count
    // MUST error.
    if records.len() != extents.len() {
        return Err(invalid(
            "Index Record count does not match the number of Blocks",
        ));
    }
    // §4.3: the Records must match the real sizes of the Blocks they
    // describe. §3.1.4 is the reason it has to be the *real* sizes and
    // not the ones the Block Header claims.
    for (i, (unpadded, uncompressed)) in records.iter().enumerate() {
        let real = &extents[i];
        if *unpadded != real.unpadded {
            return Err(invalid(
                "Index Record Unpadded Size does not match the Block",
            ));
        }
        if *uncompressed != real.uncompressed {
            return Err(invalid(
                "Index Record Uncompressed Size does not match the Block",
            ));
        }
    }
    Ok(records)
}
/// Validate the Stream Header and return the Check ID (§2.1.1).
fn parse_stream_header(data: &[u8]) -> CompressResult<u8> {
    let flags = &data[6..8];
    // §2.1.1.2: the first byte is always null; the second is the Check ID
    // in its low four bits, with the rest reserved.
    if flags[0] != 0 || flags[1] & 0xF0 != 0 {
        return Err(invalid("reserved stream flag bits set"));
    }
    let check_id = flags[1] & 0x0F;
    if check_size(check_id).is_none() {
        return Err(invalid("unsupported check type"));
    }
    // §2.1.1.3: CRC32 of the two flag bytes.
    let stored = read_le32(data, 8, "truncated stream header")?;
    if crc32(flags) != stored {
        return Err(invalid("stream header CRC32 mismatch"));
    }
    Ok(check_id)
}

/// Verify the Check that follows a block's padding (§3.3).
fn verify_check(data: &[u8], at: usize, check_id: u8, decoded: &[u8]) -> CompressResult<()> {
    let size = check_size(check_id).unwrap_or(0);
    let stored = data
        .get(at..at + size)
        .ok_or_else(|| invalid("truncated block check"))?;
    let ok = match check_id {
        CHECK_NONE => true,
        CHECK_CRC32 => {
            u32::from_le_bytes([stored[0], stored[1], stored[2], stored[3]]) == crc32(decoded)
        }
        CHECK_CRC64 => {
            u64::from_le_bytes([
                stored[0], stored[1], stored[2], stored[3], stored[4], stored[5], stored[6],
                stored[7],
            ]) == super::crc64::crc64(decoded)
        }
        CHECK_SHA256 => crate::sha256::Sha256::hash(decoded) == stored[..],
        _ => return Err(invalid("unsupported check type")),
    };
    if ok {
        Ok(())
    } else {
        Err(invalid("block check mismatch"))
    }
}

/// Skip Block Padding: 0-3 null bytes up to the next four-byte boundary
/// (§3.3).
fn pad_to_four(data: &[u8], pos: usize) -> CompressResult<usize> {
    let mut p = pos;
    while !p.is_multiple_of(4) {
        if *data
            .get(p)
            .ok_or_else(|| invalid("truncated block padding"))?
            != 0
        {
            return Err(invalid("block padding is not null"));
        }
        p += 1;
    }
    Ok(p)
}

/// Total length of the stream at the front of `data`, padding included.
fn stream_span(data: &[u8]) -> CompressResult<usize> {
    let check_len = check_size_of(data[7] & 0x0F);
    let mut pos = STREAM_HEADER_LEN;
    while pos < data.len() && data[pos] != 0x00 {
        parse_block_header(data, &mut pos)?;
        let compressed = lzma2_stream_len(&data[pos..])?;
        pos = pad_to_four(data, pos + compressed)? + check_len;
    }
    let (backward_size, _) = parse_index_and_footer(data, pos)?;
    Ok(pos + (backward_size as usize + 1) * 4 + STREAM_FOOTER_LEN)
}

fn check_size_of(check_id: u8) -> usize {
    check_size(check_id).unwrap_or(0)
}

fn read_le32(data: &[u8], at: usize, what: &'static str) -> CompressResult<u32> {
    let b = data.get(at..at + 4).ok_or_else(|| invalid(what))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
#[cfg(all(test, feature = "xz"))]
mod tests {
    use super::*;
    // `use super::*` does not carry the parent's private `use alloc::vec::Vec`,
    // and this crate is no_std, so name it here.

    #[test]
    fn lzma2_dict_sizes_match_the_spec_table() {
        // Raw values 0, 1 and 40 from the table in §5.3.1.
        assert_eq!(lzma2_dict_size(0).unwrap(), 4096);
        assert_eq!(lzma2_dict_size(1).unwrap(), 6144);
        assert_eq!(lzma2_dict_size(2).unwrap(), 8192);
        assert_eq!(lzma2_dict_size(4).unwrap(), 16384);
        assert_eq!(lzma2_dict_size(40).unwrap(), u32::MAX);
        // Out of range and reserved bits.
        assert!(lzma2_dict_size(41).is_err());
        assert!(lzma2_dict_size(0x80).is_err());
    }

    #[test]
    fn multibyte_integers_round_trip() {
        let cases: &[&[u8]] = &[
            &[0x00],
            &[0x7F],
            &[0x80, 0x01], // 128
            &[0x80, 0x02], // 256
            &[0xFF, 0x7F], // 16383
        ];
        for c in cases {
            let mut pos = 0;
            assert!(read_vli(c, &mut pos).is_ok(), "{c:?}");
            assert_eq!(pos, c.len(), "{c:?}");
        }
    }

    #[test]
    fn multibyte_integers_reject_non_canonical_forms() {
        let mut pos = 0;
        // A continuation byte followed by 0x00 is not minimal.
        assert!(read_vli(&[0x80, 0x00], &mut pos).is_err());
        pos = 0;
        // Truncated.
        assert!(read_vli(&[0x80], &mut pos).is_err());
    }

    #[test]
    fn rejects_too_short_and_bad_magic() {
        assert!(XzReader::decompress(b"").is_err());
        assert!(XzReader::decompress(&[0u8; 40]).is_err());
        let mut f = vec![0u8; 32];
        f[..6].copy_from_slice(&XZ_MAGIC);
        // Stream header CRC32 will not match zeroed flags.
        assert!(XzReader::decompress(&f).is_err());
    }

    // ---- vectors produced by the XZ Utils reference implementation ----
    //
    // The fixtures below were written by Python's `lzma`, which is a binding
    // to the reference implementation. A test that encoded with our own
    // encoder and decoded back would be a matched pair and would prove
    // nothing about whether this parser understands the format.

    const TINY_CRC32: &[u8] = include_bytes!("testdata/tiny-crc32.xz");
    const TINY_CRC32_PLAIN: &[u8] = include_bytes!("testdata/tiny-crc32.plain");
    const TINY_CRC64: &[u8] = include_bytes!("testdata/tiny-crc64.xz");
    const TINY_CRC64_PLAIN: &[u8] = include_bytes!("testdata/tiny-crc64.plain");
    const TINY_CONCAT: &[u8] = include_bytes!("testdata/tiny-concat.xz");
    const TINY_CONCAT_PLAIN: &[u8] = include_bytes!("testdata/tiny-concat.plain");
    const TINY_L9E: &[u8] = include_bytes!("testdata/tiny-l9e.xz");
    const TINY_L9E_PLAIN: &[u8] = include_bytes!("testdata/tiny-l9e.plain");
    const TINY_SHA256: &[u8] = include_bytes!("testdata/tiny-sha256.xz");
    const TINY_SHA256_PLAIN: &[u8] = include_bytes!("testdata/tiny-sha256.plain");

    #[test]
    fn decodes_reference_streams() {
        // Single-chunk reference streams decode byte-for-byte, for both
        // verifiable check types.
        for (name, compressed, expected) in [
            ("crc32", TINY_CRC32, TINY_CRC32_PLAIN),
            ("crc64", TINY_CRC64, TINY_CRC64_PLAIN),
        ] {
            let got = XzReader::decompress(compressed).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(got, expected, "{name}");
        }
    }

    /// The bounded decode and the unbounded one must agree.
    ///
    /// The ceiling is what a bomb guard counts against, and a decode that
    /// stops early is a decode that cannot have checked the checksum that
    /// covers the bytes it did not see. A cap that is above the payload
    /// changes nothing, and this says so: the two decodes are the same
    /// bytes.
    #[test]
    fn the_bounded_decode_agrees_with_the_unbounded_one() {
        for limit in [u64::MAX, 32 << 20, 1 << 20, 4096, 256, 128, 64] {
            let bounded = XzReader::decompress_bounded(TINY_CRC32, limit)
                .unwrap_or_else(|e| panic!("limit {limit}: {e:?}"));
            assert_eq!(
                bounded.bytes, TINY_CRC32_PLAIN,
                "the bounded decode differs at the limit {limit}"
            );
            assert!(
                !bounded.capped,
                "the decode was capped at the limit {limit}"
            );
        }
    }

    /// A reference stream that needs a 64 MiB dictionary, and so declares
    /// its chunk sizes across the control byte's high five bits.
    ///
    /// This vector used to be pinned as a known failure — the LZMA2 layer
    /// read a chunk's uncompressed size as two bytes, so every chunk past
    /// 64 KiB desynced with "LZMA chunk size mismatch" whatever the
    /// dictionary size. It now decodes for real.
    #[test]
    fn decodes_the_large_dictionary_reference_stream() {
        let got = XzReader::decompress(TINY_L9E)
            .unwrap_or_else(|e| panic!("64 MiB dictionary vector: {e:?}"));
        assert_eq!(got, TINY_L9E_PLAIN);
    }

    #[test]
    fn block_header_is_parsed_from_a_reference_stream() {
        // The container is right about the 64 MiB case: filter is
        // LZMA2, the properties byte yields 64 MiB, and the reference
        // encoder declared no Compressed Size, so the extent comes from
        // walking LZMA2 chunks.
        let mut pos = STREAM_HEADER_LEN;
        let header = parse_block_header(TINY_L9E, &mut pos).unwrap();
        assert_eq!(header.filter_id, FILTER_LZMA2);
        assert_eq!(header.dict_size, 64 * 1024 * 1024);
        assert!(header.compressed_size.is_none());
        let len = lzma2_stream_len(&TINY_L9E[pos..]).unwrap();
        let block = &TINY_L9E[pos..pos + len];
        assert_eq!(*block.last().unwrap(), 0x00, "must end on the control byte");
        // and the Check that follows (after Block Padding) is where §3 says
        let check_at = pad_to_four(TINY_L9E, pos + len).unwrap();
        assert_eq!(&TINY_L9E[check_at..check_at + 4], &[0x99, 0x1e, 0xf1, 0xad]);
    }

    #[test]
    fn decodes_concatenated_streams_with_padding() {
        let got = XzReader::decompress_all(TINY_CONCAT).unwrap_or_else(|e| panic!("concat: {e:?}"));
        assert_eq!(got, TINY_CONCAT_PLAIN);
    }

    /// §3.1.3: a Compressed Size declared in the Block Header must match the
    /// real one, and the decoder MUST error when it does not.
    ///
    /// The reader used to take the declared value at its word, so a file
    /// whose header overstates the Compressed Data decoded here while
    /// `xz -t` called it corrupt -- and the section 4.3 cross-check then
    /// compared the Index against a size nothing had verified.
    #[test]
    fn a_declared_compressed_size_must_match_the_real_one() {
        // TINY_CRC32's Block Header is 12 bytes with no sizes declared:
        // size, flags, filter id 0x21, props size 1, props 0x16, two
        // padding bytes, CRC32. Adding the Compressed Size flag fills
        // exactly those two padding bytes, so the header keeps its size
        // and every offset after it stays valid.
        const HEADER: usize = 12;
        let mut p = STREAM_HEADER_LEN;
        parse_block_header(TINY_CRC32, &mut p).unwrap();
        let data_start = p;
        let real = lzma2_stream_len(&TINY_CRC32[data_start..]).unwrap();

        let rebuild = |declared: u64| -> Vec<u8> {
            let mut h = vec![0x02u8, 0x40, declared as u8, 0x21, 0x01, 0x16, 0x00, 0x00];
            let crc = crc32(&h);
            h.extend_from_slice(&crc.to_le_bytes());
            assert_eq!(h.len(), HEADER, "the header must keep its length");
            let mut out = TINY_CRC32[..STREAM_HEADER_LEN].to_vec();
            out.extend_from_slice(&h);
            out.extend_from_slice(&TINY_CRC32[data_start..]);
            out
        };

        // The control: the true size, declared, is a legal file.
        let ok = rebuild(real as u64);
        assert!(
            XzReader::decompress(&ok).is_ok(),
            "the real Compressed Size, declared, must decode"
        );

        for lie in [real as u64 + 3, real as u64 - 1] {
            let bad = rebuild(lie);
            assert!(
                XzReader::decompress(&bad).is_err(),
                "a declared Compressed Size of {lie} against a real {real} must be rejected"
            );
        }

        // Zero is invalid in its own right (§3.1.2).
        assert!(
            XzReader::decompress(&rebuild(0)).is_err(),
            "zero must be rejected"
        );
    }

    /// §2.2: Stream Padding keeps consecutive Streams four-byte aligned,
    /// so its size must be a multiple of four. `xz -t` rejects a file
    /// padded by five; without the rule this decoded it as clean.
    #[test]
    fn stream_padding_must_be_a_multiple_of_four() {
        let mut ok = TINY_CONCAT.to_vec();
        ok.extend_from_slice(&[0u8; 4]);
        assert_eq!(
            XzReader::decompress_all(&ok).unwrap_or_else(|e| panic!("four: {e:?}")),
            TINY_CONCAT_PLAIN
        );

        let mut bad = TINY_CONCAT.to_vec();
        bad.extend_from_slice(&[0u8; 5]);
        let err = XzReader::decompress_all(&bad).unwrap_err();
        assert!(
            format!("{err:?}").contains("multiple of four"),
            "five bytes of padding must be rejected, got {err:?}"
        );
    }

    /// Padding belongs *between* Streams, never before the first one.
    ///
    /// Section 2 spells a standalone file as one or more Streams with
    /// Stream Padding between or after them, so a file that opens with
    /// nulls -- or is nothing but nulls -- is not an .xz file. liblzma
    /// cannot reach that state by construction; a loop that treats any
    /// leading null run as padding can, and did.
    /// The Index Records must match the Blocks they describe.
    ///
    /// Section 4.3 makes it a MUST, and section 3.1.4 says why the *real*
    /// sizes are the ones to compare: the Block Header "may contain
    /// (intentionally or unintentionally) invalid information". Both
    /// were read and thrown away, so a file with a rewritten Index
    /// decoded here while `xz -t` called it corrupt.
    ///
    /// Each mutation below is rebuilt with the Index CRC32, the Footer
    /// CRC32 and the Backward Size recomputed, so the only thing wrong
    /// with the file is the thing under test.
    #[test]
    fn index_records_must_match_the_blocks() {
        fn rebuild(base: &[u8], index_start: usize, records: &[(u64, u64)]) -> Vec<u8> {
            fn push_vli(v: u64, out: &mut Vec<u8>) {
                let mut v = v;
                while v >= 0x80 {
                    out.push((v as u8 & 0x7F) | 0x80);
                    v >>= 7;
                }
                out.push(v as u8);
            }
            let mut body = Vec::new();
            for (unpadded, uncompressed) in records {
                push_vli(*unpadded, &mut body);
                push_vli(*uncompressed, &mut body);
            }

            let mut index = vec![0x00u8];
            index.push(records.len() as u8);
            index.extend_from_slice(&body);
            while index.len() % 4 != 0 {
                index.push(0x00);
            }
            let index_crc = crc32(&index);
            // The Backward Size is (real Index size / 4) - 1, and the
            // real Index size counts the CRC32 -- which is the 4 bytes
            // this line is about to append. Computing it before the
            // append is off by one slot, and the Footer CRC then fails
            // rather than the Index check, which is a worse answer.
            let backward = ((index.len() + 4) / 4 - 1) as u32;
            index.extend_from_slice(&index_crc.to_le_bytes());

            let mut out = base[..index_start].to_vec();
            out.extend_from_slice(&index);
            let mut flags = [0u8; 2];
            flags.copy_from_slice(&base[6..8]);
            // Section 2.1.2: the Stream Footer is CRC32, Backward Size,
            // Stream Flags, Footer Magic. The CRC comes first and covers
            // the two fields before the magic -- six bytes. liblzma
            // computes lzma_crc32(in + 4, 6, 0), and every fixture in
            // testdata agrees: storing the magic inside the CRC makes
            // the file unreadable.
            let mut covered = Vec::new();
            covered.extend_from_slice(&backward.to_le_bytes());
            covered.extend_from_slice(&flags);
            let mut footer = Vec::new();
            footer.extend_from_slice(&crc32(&covered).to_le_bytes());
            footer.extend_from_slice(&covered);
            footer.extend_from_slice(b"YZ");
            out.extend_from_slice(&footer);
            out
        }

        // One Stream, one block, one record. TINY_CONCAT is two Streams
        // and a rebuild from the first Index truncates the second, so the
        // control below would be measuring the wrong thing.
        let base = TINY_CRC32;
        let mut p = STREAM_HEADER_LEN;
        while p < base.len() && base[p] != 0x00 {
            parse_block_header(base, &mut p).unwrap();
            let data_start = p;
            let len = lzma2_stream_len(&base[data_start..]).unwrap();
            let block_end = pad_to_four(base, data_start + len).unwrap();
            p = block_end + check_size_of(CHECK_CRC32);
        }
        let index_start = p;

        // The control decodes.
        assert!(
            XzReader::decompress(base).is_ok(),
            "the unmodified file must decode"
        );

        // Read the real record out of the file, so the mutations below
        // are measured against it rather than against a guess -- and so
        // that rebuilding with the real values still decodes, which is
        // what makes the four failures mean what they claim to.
        let real_record = {
            let mut q = index_start + 1;
            let n = read_vli(base, &mut q).unwrap();
            assert_eq!(n, 1, "the fixture has a single block");
            let unpadded = read_vli(base, &mut q).unwrap();
            let uncompressed = read_vli(base, &mut q).unwrap();
            (unpadded, uncompressed)
        };
        let rebuilt_ok = rebuild(base, index_start, &[real_record]);
        assert!(
            XzReader::decompress(&rebuilt_ok).is_ok(),
            "a rebuilt Index with the real values must decode, or the four              rejections below prove nothing"
        );

        // Unpadded Size off by one.
        let bad = rebuild(base, index_start, &[(real_record.0 + 1, real_record.1)]);
        assert!(
            XzReader::decompress(&bad).is_err(),
            "an Index that lies about Unpadded Size must be rejected"
        );

        // Uncompressed Size off by twenty.
        let bad = rebuild(base, index_start, &[(real_record.0, real_record.1 - 20)]);
        assert!(
            XzReader::decompress(&bad).is_err(),
            "an Index that lies about Uncompressed Size must be rejected"
        );

        // Number of Records says two, the stream has one.
        let bad = rebuild(base, index_start, &[real_record, real_record]);
        assert!(
            XzReader::decompress(&bad).is_err(),
            "a Record count that is not the block count must be rejected"
        );

        // Unpadded Size of zero, which section 4.3.1 forbids outright.
        let bad = rebuild(base, index_start, &[(0, 43)]);
        assert!(
            XzReader::decompress(&bad).is_err(),
            "Unpadded Size zero must be rejected"
        );
    }

    #[test]
    fn padding_before_the_first_stream_is_not_an_xz_file() {
        let mut leading = vec![0u8; 4];
        leading.extend_from_slice(TINY_CONCAT);
        let err = XzReader::decompress_all(&leading).unwrap_err();
        assert!(
            format!("{err:?}").contains("before the first Stream"),
            "leading padding must be rejected, got {err:?}"
        );

        assert!(
            XzReader::decompress_all(&[0u8; 8]).is_err(),
            "a file of nothing but padding is not an .xz file"
        );
        assert!(
            XzReader::decompress_all(&[]).is_err(),
            "an empty file is not an .xz file"
        );

        // And the shape that must still work: padding *after* a stream.
        let mut trailing = TINY_CONCAT.to_vec();
        trailing.extend_from_slice(&[0u8; 4]);
        assert_eq!(
            XzReader::decompress_all(&trailing).unwrap(),
            TINY_CONCAT_PLAIN
        );
    }

    /// The one Check in the format that is not merely error-detecting.
    ///
    /// `xz --check=sha256` is what `xz(1)` recommends, so a decoder that
    /// refuses it refuses a large share of real files. This is a vector
    /// from XZ Utils 5.8.3, and the test also flips one byte of the
    /// plaintext-derived digest's source to prove the check is actually
    /// evaluated rather than accepted.
    #[test]
    fn verifies_the_sha256_check() {
        let got = XzReader::decompress(TINY_SHA256)
            .unwrap_or_else(|e| panic!("sha256-checked stream: {e:?}"));
        assert_eq!(got, TINY_SHA256_PLAIN);

        // Corrupt the stored digest, not the data: a decoder that skips
        // the check would still decode this and pass.
        let mut broken = TINY_SHA256.to_vec();
        let n = broken.len();
        broken[n - 40] ^= 0x01; // first byte of the 32-byte Check
        let err = XzReader::decompress(&broken).unwrap_err();
        assert!(
            format!("{err:?}").contains("check mismatch"),
            "a wrong SHA-256 must be rejected, got {err:?}"
        );

        // And corrupt the data instead: the digest is over the
        // uncompressed bytes, so this has to fail as well.
        let mut broken_data = TINY_SHA256.to_vec();
        let data_at = broken_data.len() - 40 - 20;
        broken_data[data_at] ^= 0x01;
        assert!(
            XzReader::decompress(&broken_data).is_err(),
            "corrupt data must not decode"
        );
    }

    /// `a_corrupt_check_is_rejected` above flips a byte in the compressed
    /// body, which fails in the LZMA2 layer -- so `verify_check` had no test
    /// at all. Only `verifies_the_sha256_check` touched a stored digest.
    ///
    /// This one corrupts the Check field itself. The offset is found by
    /// search rather than hardcoded, because the Check's position depends on
    /// the payload size, which changes whenever the fixture is regenerated --
    /// and a stale constant here would silently start testing the wrong
    /// bytes, which is what the previous version of this file did.
    ///
    /// The error is asserted by message rather than merely `is_err()`,
    /// because that is what distinguishes "the decoder noticed a bad
    /// Check" from "the decoder noticed something else first".
    #[test]
    fn a_corrupt_stored_check_is_rejected_by_the_check_verifier() {
        for (name, stream, plain, check_id) in [
            ("crc32", TINY_CRC32, TINY_CRC32_PLAIN, 1u8),
            ("crc64", TINY_CRC64, TINY_CRC64_PLAIN, 4u8),
        ] {
            let size = check_size_of(check_id);
            assert!(
                size > 0 && size <= 8,
                "{name}: implausible check size {size}"
            );
            // The intact stream must decode, or nothing below means anything.
            assert_eq!(
                XzReader::decompress(stream).expect("intact"),
                plain,
                "{name}: the fixture does not decode to begin with"
            );

            // The Check sits between the block data and the index, so it is
            // somewhere in the tail. Try every window of the right width and
            // require that the verifier rejects at least one of them. The
            // count is not asserted: the decoder locates the Check relative
            // to the block end, so more than one offset can land inside the
            // same field. What is being pinned is that `verify_check` is
            // reachable and says so, not how many windows overlap it.
            let mut found = 0usize;
            for at in 0..stream.len().saturating_sub(size) {
                let mut bad = stream.to_vec();
                bad[at] ^= 0xFF;
                let err = XzReader::decompress(&bad).expect_err("a corrupt Check must error");
                if format!("{err:?}").contains("check mismatch") {
                    found += 1;
                }
            }
            assert!(
                found >= 1,
                "{name}: corrupting the stored Check never reached \
                 verify_check; the check field may have moved"
            );
        }
    }

    #[test]
    fn a_corrupt_check_is_rejected() {
        // Flip a bit in the compressed body. The Check covers the decoded
        // bytes, so this must error rather than return wrong text — which
        // is the failure mode that matters for a search tool.
        let mut bad = TINY_CRC32.to_vec();
        let mid = bad.len() / 2;
        bad[mid] ^= 0xFF;
        assert!(
            XzReader::decompress(&bad).is_err(),
            "a corrupt body must not decode"
        );
    }

    #[test]
    fn a_corrupt_stream_header_is_rejected() {
        // Byte 7 is the Check ID, which is CRC32 of Stream Flags.
        let mut bad = TINY_CRC32.to_vec();
        bad[7] ^= 0xFF;
        assert!(XzReader::decompress(&bad).is_err());

        // Byte 6 is required to be null.
        let mut bad2 = TINY_CRC32.to_vec();
        bad2[6] = 0x01;
        assert!(XzReader::decompress(&bad2).is_err());
    }

    #[test]
    fn truncations_never_panic() {
        for frac in [1usize, 2, 3, 4, 6, 8, 12, 20, 40] {
            let n = TINY_CRC32.len() * frac / 8;
            if n == 0 || n >= TINY_CRC32.len() {
                continue;
            }
            // Must simply error; the point is that it does not panic.
            let _ = XzReader::decompress(&TINY_CRC32[..n]);
        }
    }

    #[test]
    fn lzma2_stream_len_matches_the_block_extent() {
        // The walker must terminate on the 0x00 end marker and not
        // overshoot; `decompress` relies on it when no Compressed Size is
        // declared, which is what the reference encoder emits.
        let mut pos = STREAM_HEADER_LEN;
        let header = parse_block_header(TINY_CRC32, &mut pos).unwrap();
        assert_eq!(header.filter_id, FILTER_LZMA2);
        assert!(
            header.compressed_size.is_none(),
            "reference omits Compressed Size"
        );
        let len = lzma2_stream_len(&TINY_CRC32[pos..]).unwrap();
        let block = &TINY_CRC32[pos..pos + len];
        assert_eq!(block[block.len() - 1], 0x00, "must end on the control byte");
        let decoded = LzmaDecoder::new()
            .decode_lzma2(block, header.dict_size)
            .unwrap();
        assert_eq!(decoded, TINY_CRC32_PLAIN);
    }

    /// A Block Header's optional Uncompressed Size (§3.1.1.2) is refused
    /// from: the LZMA2 payload is not walked at all, and nothing is
    /// emitted. xz also verifies the Index against what it decoded (§4.3),
    /// which a short decode has no business being compared against.
    ///
    /// `tiny-sha256` is liblzma's, and one of only two xz vectors in the
    /// tree whose encoder wrote that field at all.
    #[test]
    fn decompress_bounded_refuses_from_the_block_header() {
        let b = XzReader::decompress_bounded(TINY_SHA256, 16).expect("bounded");
        assert!(b.capped);
        assert!(b.bytes.is_empty(), "nothing was decoded");
        assert_eq!(
            b.declared,
            Some(TINY_SHA256_PLAIN.len() as u64),
            "the Block Header's Uncompressed Size is what said no"
        );

        let whole = XzReader::decompress_bounded(TINY_SHA256, TINY_SHA256_PLAIN.len() as u64)
            .expect("exact");
        assert!(!whole.capped);
        assert_eq!(whole.bytes, TINY_SHA256_PLAIN);
    }

    /// The other case: `tiny-l9e` omits the field, so the ceiling falls to
    /// the LZMA2 chunk, which states its own uncompressed size in its
    /// control byte and two size fields.
    #[test]
    fn decompress_bounded_stops_a_block_that_declares_no_size() {
        let b = XzReader::decompress_bounded(TINY_L9E, 1000).expect("bounded");
        assert!(b.capped);
        assert!(b.bytes.len() <= 1000, "emitted {} bytes", b.bytes.len());
        assert_eq!(
            b.bytes,
            &TINY_L9E_PLAIN[..b.bytes.len()],
            "not the real prefix"
        );
    }
}

/// The container framing is untrusted input: bad VLI encodings, a header
/// that declares a size nothing verifies, an index that disagrees with
/// the blocks. None of it may panic.
#[cfg(all(test, feature = "xz"))]
mod fuzz {
    use super::*;

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: alloc::vec::Vec<(&str, alloc::vec::Vec<u8>)> = alloc::vec![
            ("empty", alloc::vec![]),
            ("magic", XZ_MAGIC.to_vec()),
            ("header", {
                let mut v = XZ_MAGIC.to_vec();
                v.extend_from_slice(&[0, 4, 0, 0, 0, 0]);
                v
            }),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 2000, "xz", |data| {
            let _ = XzReader::decompress(data);
            let _ = XzReader::decompress_bounded(data, 4096);
            let _ = XzReader::decompress_all(data);
            let mut p = 0usize;
            let _ = read_vli(data, &mut p);
            let mut p = 0usize;
            let _ = parse_block_header(data, &mut p);
        });
    }
}
