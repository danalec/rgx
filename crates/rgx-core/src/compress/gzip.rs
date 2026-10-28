// SPDX-License-Identifier: Apache-2.0

//! The gzip file format (RFC 1952): a member header, a DEFLATE body, and
//! a CRC-32 + ISIZE trailer, with multi-member files as concatenated
//! members.
//!
//! Independent reimplementation of the published framing, written from
//! the RFC rather than from any implementation's source: the fixed
//! ten-byte header, the optional EXTRA/NAME/COMMENT/HCRC fields, the
//! reserved-FLG refusal, and the trailer. The body is decoded by
//! [`super::deflate`]; the checksum by [`super::crc32`].
//!
//! Two shapes the format makes unavoidable: the trailer sits *after* the
//! compressed data, so the only way to find it is to decode the stream;
//! and ISIZE is a size modulo 2^32, so it is a floor rather than a total
//! past 4 GiB.

use super::cap::{Bounded, OutputCap};
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GzipCompressionMethod {
    Deflate,
    Reserved,
    Unknown(u8),
}

impl From<u8> for GzipCompressionMethod {
    fn from(value: u8) -> Self {
        match value {
            8 => Self::Deflate,
            v => Self::Unknown(v),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GzipFlag {
    FText,
    FHCrc,
    FExtra,
    FName,
    FComment,
}

#[derive(Debug, Clone)]
pub struct GzipExtraField {
    pub subfield_id: [u8; 2],
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct GzipHeader {
    pub compression_method: GzipCompressionMethod,
    pub flags: u8,
    pub modification_time: u32,
    pub extra_flags: u8,
    pub operating_system: u8,
    pub original_filename: Option<String>,
    pub comment: Option<String>,
    pub extra_fields: Vec<GzipExtraField>,
    pub header_crc16: Option<u16>,
    pub header_size: usize,
}

impl GzipHeader {
    pub fn has_text(&self) -> bool {
        (self.flags & 0x01) != 0
    }

    pub fn has_crc16(&self) -> bool {
        (self.flags & 0x02) != 0
    }

    pub fn has_extra(&self) -> bool {
        (self.flags & 0x04) != 0
    }

    pub fn has_name(&self) -> bool {
        (self.flags & 0x08) != 0
    }

    pub fn has_comment(&self) -> bool {
        (self.flags & 0x10) != 0
    }

    pub fn modification_time_unix(&self) -> u32 {
        self.modification_time
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GzipOperatingSystem {
    Fat,
    Amiga,
    VMS,
    Unix,
    VMCMS,
    Atari,
    HPFS,
    Macintosh,
    ZSystem,
    CPM,
    TOPS20,
    NTFS,
    QDOS,
    AcornRISCOS,
    Unknown(u8),
}

impl From<u8> for GzipOperatingSystem {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Fat,
            1 => Self::Amiga,
            2 => Self::VMS,
            3 => Self::Unix,
            4 => Self::VMCMS,
            5 => Self::Atari,
            6 => Self::HPFS,
            7 => Self::Macintosh,
            8 => Self::ZSystem,
            9 => Self::CPM,
            10 => Self::TOPS20,
            11 => Self::NTFS,
            12 => Self::QDOS,
            13 => Self::AcornRISCOS,
            255 => Self::Unknown(255),
            v => Self::Unknown(v),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GzipMember {
    pub header: GzipHeader,
    pub compressed_data_offset: usize,
    pub compressed_data_size: usize,
    pub crc32: u32,
    pub original_size: u32,
}

impl GzipMember {
    pub fn compression_ratio(&self) -> f64 {
        if self.original_size == 0 {
            return 0.0;
        }
        self.compressed_data_size as f64 / self.original_size as f64
    }
}

#[derive(Debug, Clone)]
pub struct GzipFile {
    pub members: Vec<GzipMember>,
    pub total_compressed_size: usize,
    pub total_original_size: u64,
}

impl GzipFile {
    pub fn num_members(&self) -> usize {
        self.members.len()
    }

    pub fn is_multi_member(&self) -> bool {
        self.members.len() > 1
    }

    pub fn first_filename(&self) -> Option<&String> {
        self.members.first()?.header.original_filename.as_ref()
    }

    pub fn total_compression_ratio(&self) -> f64 {
        if self.total_original_size == 0 {
            return 0.0;
        }
        self.total_compressed_size as f64 / self.total_original_size as f64
    }
}

#[derive(Debug, Clone)]
pub enum GzipError {
    InvalidMagic,
    InvalidCompressionMethod,
    Truncated,
    InvalidExtra,
    /// FLG has a reserved bit set (RFC 1952 2.3.1.2).
    InvalidFlags,
    InvalidFilename,
    InvalidComment,
    MissingTrailer,
    CrcMismatch,
    DeflateFailed,
}

impl core::fmt::Display for GzipError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "Invalid GZIP magic number"),
            Self::InvalidCompressionMethod => write!(f, "Unsupported compression method"),
            Self::Truncated => write!(f, "Truncated GZIP file"),
            Self::InvalidExtra => write!(f, "Invalid extra field"),
            Self::InvalidFlags => write!(f, "GZIP FLG has a reserved bit set"),
            Self::InvalidFilename => write!(f, "Invalid filename"),
            Self::InvalidComment => write!(f, "Invalid comment"),
            Self::MissingTrailer => write!(f, "Missing GZIP trailer"),
            Self::CrcMismatch => write!(f, "CRC mismatch"),
            Self::DeflateFailed => write!(f, "Deflate stream decode failed"),
        }
    }
}

pub type GzipResult<T> = Result<T, GzipError>;

// Vendored std adaptation: the no_std source has no std::error::Error
// impl, which rgx_core::Error's blanket From<T: StdError> needs.
#[cfg(feature = "std")]
impl std::error::Error for GzipError {}

pub struct GzipReader;

/// Writer for a single-member gzip stream: 10-byte header, deflate
/// payload, CRC-32 + ISIZE trailer. Round-trips through
/// [`GzipReader::decode`] and through any third-party gunzip.
pub struct GzipWriter {
    level: u8,
    mtime: u32,
    os: u8,
}

impl Default for GzipWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl GzipWriter {
    pub fn new() -> Self {
        GzipWriter {
            level: 6,
            mtime: 0,
            os: 3, // Unix
        }
    }

    pub fn with_level(level: u8) -> Self {
        GzipWriter {
            level,
            ..Self::new()
        }
    }

    /// MTIME field (seconds since epoch, 0 = not set).
    pub fn with_mtime(mut self, mtime: u32) -> Self {
        self.mtime = mtime;
        self
    }

    /// Operating-system byte in the header (3 = Unix, 255 = unknown).
    pub fn with_os(mut self, os: u8) -> Self {
        self.os = os;
        self
    }

    /// RFC 1952 §2.3: ID1/ID2 magic, CM = 8, FLG = 0 (no optional
    /// fields), MTIME, XFL = 0, OS, then the body and the trailer.
    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        let payload = super::deflate::DeflateEncoder::with_level(self.level).encode(data);
        let mut out = Vec::with_capacity(payload.len() + 18);
        out.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00]);
        out.extend_from_slice(&self.mtime.to_le_bytes());
        out.extend_from_slice(&[0x00, self.os]);
        out.extend_from_slice(&payload);
        out.extend_from_slice(&super::crc32::crc32(data).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out
    }
}

impl GzipReader {
    pub fn is_gzip(data: &[u8]) -> bool {
        data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B
    }

    /// Decode the whole file: every member's deflate stream inflated,
    /// trailer CRC-32 and ISIZE verified, outputs concatenated.
    pub fn decode(data: &[u8]) -> GzipResult<Vec<u8>> {
        Self::decode_bounded(data, super::cap::UNLIMITED).map(|b| b.bytes)
    }

    /// Decode the whole file without expanding it past `limit` bytes.
    ///
    /// gzip cannot refuse early from a declaration: ISIZE is in the
    /// *trailer*, and the trailer's position is only known by decoding the
    /// member to find it. So the ceiling is the running one, in the deflate
    /// pass that has to happen anyway, and the ISIZE total is reported
    /// alongside for the wording of the notice. [`Self::decode`] walks every
    /// member's deflate stream twice for the same reason; this walks each
    /// once and keeps the prefix of the member that overran, which is what
    /// makes a truncated multi-member file still worth searching.
    pub fn decode_bounded(data: &[u8], limit: u64) -> GzipResult<Bounded> {
        let mut cap = OutputCap::new(limit);
        let mut out: Vec<u8> = Vec::new();
        let mut pos = 0usize;
        // ISIZE is in the trailer, so a member the cap stopped has none to
        // read: what is declared is only what was read before the cap.
        let mut declared: Option<u64> = None;

        while pos < data.len() && Self::is_gzip(&data[pos..]) {
            let (member, chunk) = Self::parse_member_bounded(data, pos, cap.remaining())?;
            let capped = chunk.capped;
            if !capped {
                // ISIZE is the size modulo 2^32 (RFC 1952 2.3.1.7), so it is
                // a floor, not a total, once a member passes 4 GiB.
                declared = Some(
                    declared
                        .unwrap_or(0)
                        .saturating_add(member.original_size as u64),
                );
            }
            out.extend_from_slice(&chunk.bytes);
            cap.take(chunk.bytes.len() as u64);
            if capped {
                return Ok(Bounded::stopped(out, declared, limit));
            }
            if chunk.bytes.len() as u64 != member.original_size as u64 {
                return Err(GzipError::CrcMismatch);
            }
            if super::crc32::crc32(&chunk.bytes) != member.crc32 {
                return Err(GzipError::CrcMismatch);
            }
            pos = member.compressed_data_offset + member.compressed_data_size + 8;
        }
        Ok(Bounded::complete(out, declared, limit))
    }

    pub fn parse(data: &[u8]) -> GzipResult<GzipFile> {
        let mut members = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            if !Self::is_gzip(&data[pos..]) {
                break;
            }

            let member = Self::parse_member(data, pos)?;
            members.push(member.clone());
            pos = member.compressed_data_offset + member.compressed_data_size + 8;
        }

        let total_compressed_size = members.iter().map(|m| m.compressed_data_size).sum();
        let total_original_size = members.iter().map(|m| m.original_size as u64).sum();

        Ok(GzipFile {
            members,
            total_compressed_size,
            total_original_size,
        })
    }

    fn parse_member(data: &[u8], start: usize) -> GzipResult<GzipMember> {
        Self::parse_member_bounded(data, start, super::cap::UNLIMITED).map(|(m, _)| m)
    }

    /// Parse one member and, in the same pass, decode its deflate stream
    /// under `limit`. The two cannot be separated: the trailer the parser
    /// needs sits after the compressed data, so the only way to find it is
    /// to decode the stream.
    fn parse_member_bounded(
        data: &[u8],
        start: usize,
        limit: u64,
    ) -> GzipResult<(GzipMember, Bounded)> {
        let (header, body_at) = parse_header(data, start)?;

        let (trailer_pos, decoded) = find_trailer_bounded(data, body_at, limit)?;
        let compressed_data_size = trailer_pos - body_at;

        // A capped member's trailer is past the bytes the cap allowed, so
        // there is nothing to read and nothing to check. The caller stops
        // on the flag and the zeroed fields below are never looked at.
        let (crc32, original_size) = if decoded.capped {
            (0, 0)
        } else {
            if trailer_pos + 8 > data.len() {
                return Err(GzipError::MissingTrailer);
            }
            (
                le32(&data[trailer_pos..trailer_pos + 4]),
                le32(&data[trailer_pos + 4..trailer_pos + 8]),
            )
        };

        Ok((
            GzipMember {
                header,
                compressed_data_offset: body_at,
                compressed_data_size,
                crc32,
                original_size,
            },
            decoded,
        ))
    }

    pub fn extract_compressed_data<'a>(data: &'a [u8], member: &GzipMember) -> Option<&'a [u8]> {
        let start = member.compressed_data_offset;
        let end = start + member.compressed_data_size;

        if end > data.len() {
            return None;
        }

        Some(&data[start..end])
    }
}

/// Walk one member header from `start`, returning it and the offset the
/// DEFLATE body begins at.
fn parse_header(data: &[u8], start: usize) -> GzipResult<(GzipHeader, usize)> {
    if start + 10 > data.len() {
        return Err(GzipError::Truncated);
    }

    if !GzipReader::is_gzip(&data[start..]) {
        return Err(GzipError::InvalidMagic);
    }

    let compression_method = GzipCompressionMethod::from(data[start + 2]);
    if compression_method != GzipCompressionMethod::Deflate {
        return Err(GzipError::InvalidCompressionMethod);
    }

    let flags = data[start + 3];
    // RFC 1952 §2.3.1.2: a compliant decompressor must error on any
    // reserved bit set. Bits 5, 6 and 7 are reserved, so 0xE0 is an
    // error. gzip(1) and ripgrep both refuse it.
    if (flags & 0xE0) != 0 {
        return Err(GzipError::InvalidFlags);
    }
    let modification_time = le32(&data[start + 4..start + 8]);
    let extra_flags = data[start + 8];
    let operating_system = data[start + 9];

    let mut pos = start + 10;

    let extra_fields = if (flags & 0x04) != 0 {
        if pos + 2 > data.len() {
            return Err(GzipError::Truncated);
        }
        let xlen = le16(&data[pos..pos + 2]) as usize;
        pos += 2;
        // A crafted header can claim an extra-field block far larger
        // than the file. Bounds-check before slicing.
        if pos + xlen > data.len() {
            return Err(GzipError::InvalidExtra);
        }

        let fields = parse_extra_fields(&data[pos..pos + xlen])?;
        pos += xlen;
        fields
    } else {
        Vec::new()
    };

    let original_filename = if (flags & 0x08) != 0 {
        let name_end = find_null(&data[pos..]).ok_or(GzipError::InvalidFilename)?;
        // RFC 1952 §2.3.1.3: the name is LATIN-1, NUL-terminated. LATIN-1
        // maps every byte to the codepoint of the same value, so the bytes
        // *are* the string.
        let name = latin1(&data[pos..pos + name_end]);
        pos += name_end + 1;
        Some(name)
    } else {
        None
    };

    let comment = if (flags & 0x10) != 0 {
        let comment_end = find_null(&data[pos..]).ok_or(GzipError::InvalidComment)?;
        // Same rule as FNAME: RFC 1952 2.3.1.5 requires LATIN-1.
        let text = latin1(&data[pos..pos + comment_end]);
        pos += comment_end + 1;
        Some(text)
    } else {
        None
    };

    let header_crc16 = if (flags & 0x02) != 0 {
        if pos + 2 > data.len() {
            return Err(GzipError::Truncated);
        }
        let crc = le16(&data[pos..pos + 2]);
        pos += 2;
        Some(crc)
    } else {
        None
    };

    let header_size = pos - start;

    Ok((
        GzipHeader {
            compression_method,
            flags,
            modification_time,
            extra_flags,
            operating_system,
            original_filename,
            comment,
            extra_fields,
            header_crc16,
            header_size,
        },
        pos,
    ))
}

/// Parse the EXTRA subfield sequence: SI1/SI2, a 16-bit length, that
/// many bytes, until the block is spent.
fn parse_extra_fields(data: &[u8]) -> GzipResult<Vec<GzipExtraField>> {
    let mut fields = Vec::new();
    let mut pos = 0;

    while pos + 4 <= data.len() {
        let subfield_id = [data[pos], data[pos + 1]];
        let len = le16(&data[pos + 2..pos + 4]) as usize;

        if pos + 4 + len > data.len() {
            return Err(GzipError::InvalidExtra);
        }

        let subfield_data = data[pos + 4..pos + 4 + len].to_vec();
        fields.push(GzipExtraField {
            subfield_id,
            data: subfield_data,
        });

        pos += 4 + len;
    }

    Ok(fields)
}

/// ISO 8859-1 as a `String`: byte value == codepoint, for every byte.
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

fn find_null(data: &[u8]) -> Option<usize> {
    data.iter().position(|&b| b == 0)
}

/// Locate the 8-byte trailer after the deflate stream starting at
/// `start`, under a ceiling on how far that stream may expand.
///
/// The deflate stream is bit-oriented and may contain 0x00 bytes as
/// ordinary compressed data, so its end is found by decoding it.
fn find_trailer_bounded(data: &[u8], start: usize, limit: u64) -> GzipResult<(usize, Bounded)> {
    use super::deflate::DeflateDecoder;
    let stream = &data[start..];
    let (decoded, consumed) = DeflateDecoder::new()
        .decode_bounded_with_consumed(stream, limit)
        .map_err(|_| GzipError::DeflateFailed)?;
    if decoded.capped {
        // The trailer is past the bytes the cap allowed, so there is no
        // trailer to find. The caller keeps the prefix and stops.
        return Ok((start + stream.len(), decoded));
    }
    let end = start + consumed;
    if end + 8 > data.len() {
        return Err(GzipError::MissingTrailer);
    }
    Ok((end, decoded))
}

fn le16(data: &[u8]) -> u16 {
    u16::from_le_bytes([data[0], data[1]])
}

fn le32(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}
#[cfg(all(test, feature = "gzip"))]
mod tests {
    use super::*;
    use crate::compress::crc32::crc32;

    /// RFC 1952 2.3.1.3 and 2.3.1.5: FNAME and FCOMMENT are LATIN-1, not
    /// UTF-8, and 2.3.1.2 makes a set reserved FLG bit an error.
    ///
    /// RFC 1952 §2.3.1.3 and §2.3.1.5: FNAME and FCOMMENT are LATIN-1, not
    /// UTF-8, and §2.3.1.2 makes a set reserved FLG bit an error. The OS
    /// byte 0xFF is "unknown" and must be accepted.
    #[test]
    fn header_fields_follow_rfc1952() {
        /// A deflate stream of stored (uncompressed) blocks, so the test
        /// needs no encoder. BTYPE 00 with LEN/NLEN, which the format
        /// defines for exactly this.
        fn deflate_stored(payload: &[u8]) -> Vec<u8> {
            let mut v = Vec::new();
            for (i, chunk) in payload.chunks(0xFFFF).enumerate() {
                let last = (i + 1) * 0xFFFF >= payload.len();
                v.push(u8::from(last));
                let n = chunk.len() as u16;
                v.extend_from_slice(&n.to_le_bytes());
                v.extend_from_slice(&(!n).to_le_bytes());
                v.extend_from_slice(chunk);
            }
            v
        }

        fn member(flg: u8, extra: &[u8], os: u8) -> Vec<u8> {
            let payload = b"needle one
two
";
            let body = deflate_stored(payload);
            let mut v = vec![0x1f, 0x8b, 0x08, flg];
            v.extend_from_slice(&[0, 0, 0, 0]);
            v.push(0x02);
            v.push(os);
            v.extend_from_slice(extra);
            v.extend_from_slice(&body);
            v.extend_from_slice(&crc32(payload).to_le_bytes());
            v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            v
        }

        // FNAME in LATIN-1: 0xE9 is 'e' with an acute accent, a valid
        // name, and not valid UTF-8 on its own.
        let name = member(0x08, b"caf\xe9.txt\x00", 0xFF);
        let out = GzipReader::decode(&name).expect("a LATIN-1 FNAME must decode");
        assert!(out.starts_with(b"needle one"));

        // Same for FCOMMENT.
        let comment = member(0x10, b"caf\xe9 comment\x00", 0xFF);
        let out = GzipReader::decode(&comment).expect("a LATIN-1 FCOMMENT must decode");
        assert!(out.starts_with(b"needle one"));

        // OS 0xFF is "unknown" and must be accepted, not rejected.
        let plain = member(0x00, b"", 0xFF);
        assert!(GzipReader::decode(&plain).is_ok(), "OS 0xFF is legal");

        // Reserved FLG bits 5, 6 and 7 (0xE0) must be an error.
        let reserved = member(0xE0, b"", 0xFF);
        assert!(
            GzipReader::decode(&reserved).is_err(),
            "a reserved FLG bit is a MUST-error per RFC 1952 2.3.1.2"
        );
    }

    #[test]
    fn test_is_gzip() {
        let valid_gzip = [0x1F, 0x8B, 0x08, 0x00];
        assert!(GzipReader::is_gzip(&valid_gzip));

        let not_gzip = [0x1F, 0x00, 0x08, 0x00];
        assert!(!GzipReader::is_gzip(&not_gzip));
    }

    #[test]
    fn test_compression_method() {
        assert_eq!(
            GzipCompressionMethod::from(8),
            GzipCompressionMethod::Deflate
        );
    }

    #[test]
    fn test_operating_system() {
        assert_eq!(GzipOperatingSystem::from(3), GzipOperatingSystem::Unix);
        assert_eq!(GzipOperatingSystem::from(11), GzipOperatingSystem::NTFS);
    }

    #[test]
    fn test_header_flags() {
        let header = GzipHeader {
            compression_method: GzipCompressionMethod::Deflate,
            flags: 0x08,
            modification_time: 0,
            extra_flags: 0,
            operating_system: 3,
            original_filename: Some(String::from("test.txt")),
            comment: None,
            extra_fields: Vec::new(),
            header_crc16: None,
            header_size: 20,
        };

        assert!(header.has_name());
        assert!(!header.has_comment());
        assert!(!header.has_extra());
    }

    /// Third-party vectors: gzip members produced by CPython's gzip module
    /// (levels 1-9, empty/text/repetitive/binary payloads, and a
    /// concatenated multi-member file).
    #[test]
    fn test_gzip_third_party_vectors() {
        macro_rules! case {
            ($name:literal) => {{
                let compressed = include_bytes!(concat!("../../testdata/gzip_", $name, ".bin"));
                let expected = include_bytes!(concat!("../../testdata/gzip_", $name, ".expected"));
                let out = GzipReader::decode(compressed).expect(concat!("gzip_", $name));
                assert_eq!(out, &expected[..], concat!("gzip_", $name));
            }};
        }
        case!("empty");
        case!("text");
        case!("repeat");
        case!("binary");
        case!("mixed");
        case!("multi");
    }

    /// Regression: a header claiming a 16940-byte extra field in a
    /// 27-byte file used to panic on the slice (found by rgx's fuzz kit).
    #[test]
    fn test_oversized_extra_field_is_rejected() {
        // FEXTRA alone, so the check under test is the bounds one and not
        // the reserved-bit one below. The original repro used FLG 0xff,
        // which now fails earlier for a different and equally correct
        // reason, so it was never reaching this code at all.
        let repro: &[u8] = &[
            0x1f, 0x8b, 0x08, 0x04, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x2c, 0x42, 0x07, 0x00, 0x00, 0x00,
        ];
        assert!(matches!(
            GzipReader::parse(repro),
            Err(GzipError::InvalidExtra)
        ));
    }

    /// The same 0xFF FLG the fuzz kit produced, now diagnosed for what it
    /// is: every reserved bit set. RFC 1952 2.3.1.2 makes that an error
    /// in its own right, and it is a better answer than a bounds failure
    /// several fields later.
    #[test]
    fn reserved_flag_bits_are_refused() {
        let repro: &[u8] = &[
            0x1f, 0x8b, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x15,
            0x6a, 0x2c, 0x42, 0x07, 0x00, 0x00, 0x00,
        ];
        assert!(matches!(
            GzipReader::parse(repro),
            Err(GzipError::InvalidFlags)
        ));
    }

    #[test]
    fn test_gzip_writer_roundtrip() {
        let data = b"the writer round-trips through its own reader".to_vec();
        for level in [0u8, 1, 6, 9] {
            let gz = GzipWriter::with_level(level)
                .with_mtime(1_700_000_000)
                .encode(&data);
            assert!(GzipReader::is_gzip(&gz));
            assert_eq!(
                GzipReader::decode(&gz).expect("decode"),
                data,
                "level {level}"
            );
        }
    }

    /// A stream is stopped at the cap rather than refused outright, and
    /// what comes back is a real prefix: the first bytes of a bomb are
    /// ordinary content, and the caller can only say so if it is given
    /// them. `gzip_repeat` is CPython's, so the prefix is compared against
    /// the same decode every other test in this file makes.
    ///
    /// A match is taken whole or not at all, so the prefix can land up to
    /// one maximum match short of the cap; it can never pass it.
    #[test]
    fn decode_bounded_stops_at_the_cap() {
        let gz = include_bytes!("../../testdata/gzip_repeat.bin");
        let full = GzipReader::decode(gz).expect("whole");
        let b = GzipReader::decode_bounded(gz, 64).expect("bounded");
        assert!(b.capped, "a {} byte stream under a 64 byte cap", full.len());
        let n = b.bytes.len();
        assert!(n <= 64, "emitted {n} bytes under a 64 byte cap");
        assert!(n + 258 >= 64, "emitted only {n} of 64 bytes");
        assert_eq!(b.bytes, full[..n], "the prefix is not the real prefix");
        // ISIZE sits in the trailer, past the cap, so there is nothing to
        // report. A cap that did fit the whole member reads it.
        assert_eq!(b.declared, None, "a capped member's ISIZE is not read");
        assert_eq!(b.limit, 64);

        // A cap that fits the whole stream is not a cap that truncated it.
        let whole = GzipReader::decode_bounded(gz, full.len() as u64).expect("exact");
        assert!(!whole.capped);
        assert_eq!(whole.bytes, full);
        assert_eq!(whole.declared, Some(full.len() as u64), "ISIZE is read");
    }

    /// Every member of a concatenated file, in one pass, bounded.
    #[test]
    fn decode_bounded_reads_every_member() {
        let gz = include_bytes!("../../testdata/gzip_multi.bin");
        let full = GzipReader::decode(gz).expect("whole");
        let b = GzipReader::decode_bounded(gz, crate::compress::cap::UNLIMITED).expect("bounded");
        assert!(!b.capped);
        assert_eq!(b.bytes, full);

        // Stop inside the second member: the first one still comes back.
        let cut = GzipReader::decode_bounded(gz, (full.len() / 2) as u64).expect("bounded");
        assert!(cut.capped);
        assert!(cut.bytes.len() < full.len());
        assert_eq!(&cut.bytes[..], &full[..cut.bytes.len()]);
    }
}

/// The parser walks untrusted bytes: magic, FLG, an extra block whose
/// length is declared by the file, NUL-terminated strings, and a trailer
/// it can only find by decoding. None of that may panic.
#[cfg(all(test, feature = "gzip"))]
mod fuzz {
    use super::*;

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: alloc::vec::Vec<(&str, alloc::vec::Vec<u8>)> = alloc::vec![
            ("empty", alloc::vec![]),
            ("magic", alloc::vec![0x1f, 0x8b]),
            (
                "fixed",
                alloc::vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 3]
            ),
            (
                "fextra",
                alloc::vec![0x1f, 0x8b, 0x08, 0x04, 0, 0, 0, 0, 0, 3, 0xff, 0xff]
            ),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 2000, "gzip", |data| {
            let _ = GzipReader::is_gzip(data);
            let _ = GzipReader::decode(data);
            let _ = GzipReader::decode_bounded(data, 256);
            let _ = GzipReader::parse(data);
        });
    }
}
