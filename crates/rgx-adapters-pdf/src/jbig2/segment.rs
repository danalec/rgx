// SPDX-License-Identifier: Apache-2.0

//! JBIG2 segment headers and segment types (ITU-T T.88 §7.2 and §7.3).
//!
//! Every JBIG2 stream — a standalone file, or the embedded stream a PDF's
//! `/JBIG2Decode` filter carries — is a sequence of segments, each one a
//! header followed by a data part. The header says what kind of segment this
//! is, which other segments it needs, which page it belongs to and how long
//! its data is.
//!
//! The header is variable length: the page association is one or four bytes,
//! and the referred-to segment count field is one byte or a run of bytes
//! depending on how many segments are referred to. Getting that length wrong
//! shifts every later segment, so the parser here reads the header as a
//! whole and reports the payload it actually found.

use alloc::vec::Vec;

/// Symbol dictionary (T.88 §7.3).
pub const SYMBOL_DICTIONARY: u8 = 0;
/// Intermediate text region.
pub const INTERMEDIATE_TEXT_REGION: u8 = 4;
/// Immediate text region.
pub const IMMEDIATE_TEXT_REGION: u8 = 6;
/// Immediate lossless text region.
pub const IMMEDIATE_LOSSLESS_TEXT_REGION: u8 = 7;
/// Pattern dictionary.
pub const PATTERN_DICTIONARY: u8 = 16;
/// Intermediate halftone region.
pub const INTERMEDIATE_HALFTONE_REGION: u8 = 20;
/// Immediate halftone region.
pub const IMMEDIATE_HALFTONE_REGION: u8 = 22;
/// Immediate lossless halftone region.
pub const IMMEDIATE_LOSSLESS_HALFTONE_REGION: u8 = 23;
/// Intermediate generic region.
pub const INTERMEDIATE_GENERIC_REGION: u8 = 36;
/// Immediate generic region.
pub const IMMEDIATE_GENERIC_REGION: u8 = 38;
/// Immediate lossless generic region.
pub const IMMEDIATE_LOSSLESS_GENERIC_REGION: u8 = 39;
/// Intermediate generic refinement region.
pub const INTERMEDIATE_REFINEMENT_REGION: u8 = 40;
/// Immediate generic refinement region.
pub const IMMEDIATE_REFINEMENT_REGION: u8 = 42;
/// Immediate lossless generic refinement region.
pub const IMMEDIATE_LOSSLESS_REFINEMENT_REGION: u8 = 43;
/// Page information.
pub const PAGE_INFORMATION: u8 = 48;
/// End of page.
pub const END_OF_PAGE: u8 = 49;
/// End of stripe.
pub const END_OF_STRIPE: u8 = 50;
/// End of file.
pub const END_OF_FILE: u8 = 51;
/// Profiles.
pub const PROFILES: u8 = 52;
/// Tables.
pub const TABLES: u8 = 53;
/// Extension.
pub const EXTENSION: u8 = 62;

/// The value a segment data length takes when the length is not known in
/// advance (T.88 §7.2.7).
pub const UNKNOWN_LENGTH: u32 = 0xFFFF_FFFF;

/// A parsed segment header.
pub struct SegmentHeader {
    /// The segment's own number (T.88 §7.2.2).
    pub number: u32,
    /// The segment type (T.88 §7.3).
    pub seg_type: u8,
    /// The "deferred non-retain" bit (T.88 §7.2.3).
    pub deferred: bool,
    /// The segments this one refers to (T.88 §7.2.5).
    pub referred: Vec<u32>,
    /// The page this segment belongs to; zero means none (T.88 §7.2.6).
    pub page: u32,
    /// The length of the data part, or [`UNKNOWN_LENGTH`].
    pub data_length: u32,
    /// Whether the data part ran past the end of the stream.
    ///
    /// A segment header that declares more data than the stream holds is a
    /// truncated stream, and a truncated stream is not a page: half a scan
    /// decodes into a plausible-looking page that is missing its marks, and
    /// handing that over as the page is worse than handing over nothing.
    pub truncated: bool,
    /// Whether the data part's length was unknown when it was written.
    ///
    /// T.88 §7.2.7 allows the "immediate generic region" to carry
    /// `0xFFFFFFFF` here, which means the data part's true end is found by
    /// looking at the data rather than at a length.
    pub unknown_length: bool,
}

/// A segment header and the data part that follows it.
pub struct Segment<'a> {
    pub header: SegmentHeader,
    pub data: &'a [u8],
}

/// Read one segment header at the start of `data`, returning the header and
/// the length of the header itself.
fn read_header(data: &[u8]) -> Option<(SegmentHeader, usize)> {
    // number (4) + flags (1) + referred-to flags (>= 1) + page (1 or 4) +
    // data length (4).
    if data.len() < 11 {
        return None;
    }
    let number = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let flags = data[4];
    let seg_type = flags & 0x3F;
    let page_assoc_size_4 = flags & 0x40 != 0;
    let deferred = flags & 0x80 != 0;

    // Referred-to segment count and retention flags (T.88 §7.2.4). The short
    // form is one byte with the count in the top three bits; the long form
    // starts with four bytes whose top three bits are 7 and whose low 29 bits
    // are the count.
    let mut pos = 5;
    let referred_flags = data[pos];
    pos += 1;
    let count = if referred_flags & 0xE0 == 0xE0 {
        if data.len() < pos + 4 {
            return None;
        }
        let long = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        // The retain bits follow the four-byte count, one byte per eight
        // referred-to segments, the first of which also carries this
        // segment's own retain bit.
        let retain_bytes = (long & 0x1FFF_FFFF) as usize / 8 + 1;
        if data.len() < pos + retain_bytes {
            return None;
        }
        pos += retain_bytes;
        (long & 0x1FFF_FFFF) as usize
    } else {
        (referred_flags >> 5) as usize
    };

    // Referred-to segment numbers (T.88 §7.2.5): one byte while the current
    // segment's number fits in a byte, two bytes up to 65536, else four.
    let number_len = if number <= 256 {
        1
    } else if number <= 65536 {
        2
    } else {
        4
    };
    if data.len() < pos + count * number_len {
        return None;
    }
    let mut referred = Vec::with_capacity(count);
    for _ in 0..count {
        let mut n: u32 = 0;
        for i in 0..number_len {
            n = (n << 8) | data[pos + i] as u32;
        }
        pos += number_len;
        referred.push(n);
    }

    // Segment page association (T.88 §7.2.6).
    let page_len = if page_assoc_size_4 { 4 } else { 1 };
    if data.len() < pos + page_len + 4 {
        return None;
    }
    let mut page: u32 = 0;
    for i in 0..page_len {
        page = (page << 8) | data[pos + i] as u32;
    }
    pos += page_len;

    // Segment data length (T.88 §7.2.7).
    let data_length = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    Some((
        SegmentHeader {
            number,
            seg_type,
            deferred,
            referred,
            page,
            data_length,
            truncated: false,
            unknown_length: data_length == UNKNOWN_LENGTH,
        },
        pos,
    ))
}

/// Split `data` into its segments.
///
/// A segment whose length is unknown ([`UNKNOWN_LENGTH`]) swallows the rest of
/// the stream, which is what T.88 §7.2.7 means by it.
pub fn split(data: &[u8]) -> Vec<Segment<'_>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < data.len() {
        let Some((header, header_len)) = read_header(&data[off..]) else {
            break;
        };
        let start = off + header_len;
        let unknown = header.data_length == UNKNOWN_LENGTH;
        let end = if unknown {
            data.len()
        } else {
            match start.checked_add(header.data_length as usize) {
                Some(e) if e <= data.len() => e,
                // A length that points past the end of the data is a lie, not
                // a truncation: take what is there and let the caller notice
                // that the segment did not decode.
                _ => {
                    let mut header = header;
                    header.truncated = true;
                    out.push(Segment {
                        header,
                        data: &data[start..],
                    });
                    break;
                }
            }
        };
        out.push(Segment {
            header,
            data: &data[start..end],
        });
        off = end;
        if unknown {
            break;
        }
    }
    out
}

#[cfg(all(test, feature = "pdf"))]
mod tests {
    use super::*;

    #[test]
    fn a_real_page_information_header_parses() {
        // The first segment of a real stream: segment number 1, type 48 (page
        // information), no referred-to segments, page 1, and a 19-byte data
        // part.
        let bytes = [
            0x00, 0x00, 0x00, 0x01, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13,
        ];
        let (header, len) = read_header(&bytes).expect("the header parses");
        assert_eq!(header.number, 1);
        assert_eq!(header.seg_type, PAGE_INFORMATION);
        assert!(!header.deferred);
        assert!(header.referred.is_empty());
        assert_eq!(header.page, 1);
        assert_eq!(header.data_length, 19);
        assert!(!header.unknown_length);
        assert_eq!(len, 11);
    }

    #[test]
    fn a_text_region_header_names_the_dictionary_it_refers_to() {
        // The text region of a real stream: segment number 3, type 6
        // (immediate text region), one referred-to segment — number 1, the
        // symbol dictionary — page 1, and a 141-byte data part.
        let bytes = [
            0x00, 0x00, 0x00, 0x03, 0x06, 0x20, 0x01, 0x01, 0x00, 0x00, 0x00, 0x8d,
        ];
        let (header, len) = read_header(&bytes).expect("the header parses");
        assert_eq!(header.number, 3);
        assert_eq!(header.seg_type, IMMEDIATE_TEXT_REGION);
        assert_eq!(header.referred, alloc::vec![1]);
        assert_eq!(header.page, 1);
        assert_eq!(header.data_length, 141);
        assert_eq!(len, 12);
    }

    #[test]
    fn a_truncated_header_is_refused_rather_than_read_past_the_end() {
        let bytes = [0x00, 0x00, 0x00, 0x20, 0x86, 0x6B, 0x02];
        assert!(read_header(&bytes).is_none());
    }
}
