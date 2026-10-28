// SPDX-License-Identifier: Apache-2.0

//! The zlib wrapper format (RFC 1950): a two-byte header, a DEFLATE
//! body, and a four-byte Adler-32 trailer.
//!
//! Independent reimplementation of the published framing, written from
//! the RFC rather than from any implementation's source: the CMF/FLG
//! header check (CM must be 8, the two bytes as a 16-bit value must be a
//! multiple of 31), the FDICT refusal, and the Adler-32 checksum the
//! trailer carries. The body is decoded by [`super::deflate`].

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::cap::Bounded;
use super::deflate::{CompressionLevel, DeflateDecoder, DeflateEncoder};
use super::error::CompressError;

/// Adler-32 of `data`, as RFC 1950 defines it: two running sums, `a`
/// over the bytes and `b` over `a`, both modulo 65521, with `a` seeded
/// to 1 so an empty input hashes to 1.
fn adler32(data: &[u8]) -> u32 {
    // 5552 is the largest run over which `b` cannot overflow u32 given
    // `a, b < 65521` on entry (255·n(n+1)/2 + (n+1)·65520 ≤ 2^32-1), so
    // the modulus only needs to run per chunk and over the tail — not
    // inside the per-byte loop.
    const CHUNK: usize = 5552;
    let mut a = 1u32;
    let mut b = 0u32;

    let mut rest = data;
    while rest.len() >= CHUNK {
        let (chunk, tail) = rest.split_at(CHUNK);
        rest = tail;
        for &byte in chunk {
            a = a.wrapping_add(byte as u32);
            b = b.wrapping_add(a);
        }
        a %= 65521;
        b %= 65521;
    }
    for &byte in rest {
        a = a.wrapping_add(byte as u32);
        b = b.wrapping_add(a);
    }
    a %= 65521;
    b %= 65521;

    (b << 16) | a
}

#[derive(Debug, Clone)]
pub struct ZlibError {
    pub message: String,
}

impl fmt::Display for ZlibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZLIB error: {}", self.message)
    }
}

impl From<CompressError> for ZlibError {
    fn from(e: CompressError) -> Self {
        ZlibError {
            message: format!("DEFLATE error: {:?}", e),
        }
    }
}

pub type ZlibResult<T> = Result<T, ZlibError>;

// Vendored std adaptation — see compress/gzip.rs.
#[cfg(feature = "std")]
impl std::error::Error for ZlibError {}

/// What the RFC 1950 header says. The decompressed size is not in there,
/// which is why the bounded decode has only a running ceiling to work
/// with.
#[derive(Debug, Clone, Copy)]
struct ZlibHeader {
    /// The FLEVEL field (bits 6-7 of FLG): a hint, not a constraint.
    #[allow(dead_code)]
    flevel: u8,
}

/// Parse and check CMF/FLG. Returns the header and the offset the
/// DEFLATE body starts at.
fn parse_header(data: &[u8]) -> ZlibResult<(ZlibHeader, usize)> {
    if data.len() < 2 {
        return Err(ZlibError {
            message: "Data too short for ZLIB".into(),
        });
    }
    let cmf = data[0];
    let flg = data[1];

    if cmf & 0x0F != 8 {
        return Err(ZlibError {
            message: format!("Unsupported compression method: {}", cmf & 0x0F),
        });
    }
    // FDICT set means a 4-byte dictionary id follows and the body is
    // compressed against a dictionary this decoder does not have.
    if flg & 0x20 != 0 {
        return Err(ZlibError {
            message: "ZLIB stream uses a preset dictionary".into(),
        });
    }
    if (u16::from(cmf) * 256 + u16::from(flg)) % 31 != 0 {
        return Err(ZlibError {
            message: "Invalid ZLIB header checksum".into(),
        });
    }

    Ok((ZlibHeader { flevel: flg >> 6 }, 2))
}

pub struct ZlibEncoder {
    level: CompressionLevel,
}

impl ZlibEncoder {
    pub fn new() -> Self {
        Self::with_level(CompressionLevel::Default)
    }

    pub fn with_level(level: CompressionLevel) -> Self {
        Self { level }
    }

    /// CMF/FLG as the RFC composes them: CM = 8 (deflate), CINFO = 7
    /// (32 KiB window), FLEVEL from the compression level, and FCHECK
    /// chosen so the two bytes read as a 16-bit value are a multiple of
    /// 31.
    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();

        let cmf: u8 = 0x78;
        let flevel: u8 = match self.level {
            CompressionLevel::None => 0,
            CompressionLevel::Fast => 1,
            CompressionLevel::Default => 2,
            CompressionLevel::Best => 3,
        };
        let flg_partial = (flevel << 6) as u16;
        let fcheck = (31 - ((cmf as u16 * 256 + flg_partial) % 31)) % 31;
        let flg: u8 = (flevel << 6) | (fcheck as u8);
        output.push(cmf);
        output.push(flg);

        let mut encoder = DeflateEncoder::with_level(self.level as u8);
        let compressed = encoder.encode(data);
        output.extend_from_slice(&compressed);

        let adler = adler32(data);
        output.extend_from_slice(&adler.to_be_bytes());

        output
    }
}

impl Default for ZlibEncoder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ZlibDecoder;

impl ZlibDecoder {
    pub fn new() -> Self {
        Self
    }

    pub fn decode(&self, data: &[u8]) -> ZlibResult<Vec<u8>> {
        self.decode_bounded(data, super::cap::UNLIMITED)
            .map(|b| b.bytes)
    }

    /// Decode without expanding past `limit` bytes.
    ///
    /// RFC 1950 declares no uncompressed size, so there is nothing to refuse
    /// early from and the ceiling is the running one, in the deflate pass.
    /// A stream the cap stops comes back short and flagged, and its ADLER32
    /// is not checked: the checksum covers bytes the decode never saw.
    pub fn decode_bounded_with_consumed(
        &self,
        data: &[u8],
        limit: u64,
    ) -> ZlibResult<(Bounded, usize)> {
        if data.len() < 6 {
            return Err(ZlibError {
                message: "Data too short for ZLIB".into(),
            });
        }

        let (_, body_at) = parse_header(data)?;
        let deflate_data = &data[body_at..];

        let mut decoder = DeflateDecoder::new();
        let (decompressed, consumed_deflate) = decoder
            .decode_bounded_with_consumed(deflate_data, limit)
            .map_err(ZlibError::from)?;

        let total_consumed = body_at + consumed_deflate + 4;
        if total_consumed > data.len() {
            return Err(ZlibError {
                message: "Unexpected EOF in ZLIB stream".into(),
            });
        }

        if decompressed.capped {
            return Ok((decompressed, total_consumed));
        }

        let trailer_offset = body_at + consumed_deflate;
        let expected_adler = u32::from_be_bytes([
            data[trailer_offset],
            data[trailer_offset + 1],
            data[trailer_offset + 2],
            data[trailer_offset + 3],
        ]);

        let actual_adler = adler32(&decompressed.bytes);
        if actual_adler != expected_adler {
            return Err(ZlibError {
                message: format!(
                    "ADLER32 mismatch: expected {}, got {}",
                    expected_adler, actual_adler
                ),
            });
        }

        Ok((decompressed, total_consumed))
    }

    /// Decode a buffer that holds exactly one zlib stream: header, body,
    /// and the trailer as its last four bytes.
    pub fn decode_bounded(&self, data: &[u8], limit: u64) -> ZlibResult<Bounded> {
        if data.len() < 6 {
            return Err(ZlibError {
                message: "Data too short for ZLIB".into(),
            });
        }

        let (_, body_at) = parse_header(data)?;
        let deflate_data = &data[body_at..data.len() - 4];

        let mut decoder = DeflateDecoder::new();
        let decompressed = decoder
            .decode_bounded(deflate_data, limit)
            .map_err(ZlibError::from)?;

        if decompressed.capped {
            return Ok(decompressed);
        }

        let trailer_offset = data.len() - 4;
        let expected_adler = u32::from_be_bytes([
            data[trailer_offset],
            data[trailer_offset + 1],
            data[trailer_offset + 2],
            data[trailer_offset + 3],
        ]);

        let actual_adler = adler32(&decompressed.bytes);
        if actual_adler != expected_adler {
            return Err(ZlibError {
                message: format!(
                    "ADLER32 mismatch: expected {}, got {}",
                    expected_adler, actual_adler
                ),
            });
        }

        Ok(decompressed)
    }
}

impl Default for ZlibDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "zlib"))]
mod tests {
    use super::*;

    #[test]
    fn test_zlib_empty() {
        let encoder = ZlibEncoder::new();
        let compressed = encoder.encode(b"");
        let decoder = ZlibDecoder::new();
        let decompressed = decoder.decode(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_zlib_simple() {
        let data = b"Hello, World!";
        let encoder = ZlibEncoder::new();
        let compressed = encoder.encode(data);
        let decoder = ZlibDecoder::new();
        let decompressed = decoder.decode(&compressed).unwrap();
        assert_eq!(decompressed, data.as_slice());
    }

    #[test]
    fn test_zlib_levels() {
        let data = b"This is a test string for compression with repeated patterns.";

        for level in [
            CompressionLevel::Fast,
            CompressionLevel::Default,
            CompressionLevel::Best,
        ] {
            let encoder = ZlibEncoder::with_level(level);
            let compressed = encoder.encode(data);
            let decoder = ZlibDecoder::new();
            let decompressed = decoder.decode(&compressed).unwrap();
            assert_eq!(decompressed, data.as_slice());
        }
    }

    #[test]
    fn test_adler32() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"a"), 0x00620062);
        assert_eq!(adler32(b"abc"), 0x024D0127);
        assert_eq!(adler32(b"Hello, World!"), 0x1F9E046A);
    }

    /// Third-party vectors: zlib streams produced by CPython's zlib
    /// (default level) over empty/text/repetitive/binary payloads.
    #[test]
    fn test_zlib_third_party_vectors() {
        macro_rules! case {
            ($name:literal) => {{
                let compressed = include_bytes!(concat!("../../testdata/zlib_", $name, ".bin"));
                let expected = include_bytes!(concat!("../../testdata/zlib_", $name, ".expected"));
                let out = ZlibDecoder::new()
                    .decode(compressed)
                    .expect(concat!("zlib_", $name));
                assert_eq!(out, &expected[..], concat!("zlib_", $name));
            }};
        }
        case!("empty");
        case!("text");
        case!("repeat");
        case!("binary");
        case!("mixed");
    }

    /// RFC 1950 has no uncompressed size in its header, so the ceiling is
    /// the running one. A stream the cap stops is not an error: the prefix
    /// comes back flagged, and its ADLER32 is not checked, because the
    /// checksum covers bytes the decode never saw.
    #[test]
    fn decode_bounded_stops_at_the_cap() {
        let compressed = include_bytes!("../../testdata/zlib_repeat.bin");
        let expected = include_bytes!("../../testdata/zlib_repeat.expected");
        let b = ZlibDecoder::new()
            .decode_bounded(compressed, 1000)
            .expect("bounded");
        assert!(b.capped);
        assert_eq!(b.declared, None);
        assert!(b.bytes.len() <= 1000, "emitted {} bytes", b.bytes.len());
        assert_eq!(b.bytes, &expected[..b.bytes.len()], "not the real prefix");

        let whole = ZlibDecoder::new()
            .decode_bounded(compressed, expected.len() as u64)
            .expect("exact");
        assert!(!whole.capped);
        assert_eq!(whole.bytes, expected);
    }

    /// FDICT set means the body is compressed against a dictionary the
    /// stream only names by id. Decoding it against nothing would produce
    /// bytes and then blame the Adler-32; the header refuses it instead.
    #[test]
    fn a_preset_dictionary_is_refused() {
        // CMF=0x78, FLG with FDICT set (bit 5) and a valid FCHECK so the
        // two bytes still pass the RFC's multiple-of-31 check.
        let cmf = 0x78u8;
        let fdict = 0x20u8;
        let base = u16::from(cmf) * 256 + u16::from(fdict);
        let fcheck = (31 - (base % 31)) % 31;
        let flg = fdict | fcheck as u8;
        assert_eq!((u16::from(cmf) * 256 + u16::from(flg)) % 31, 0);
        assert_ne!(flg & 0x20, 0, "FDICT must be set for this test");

        let mut stream = alloc::vec![cmf, flg];
        stream.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // DICTID
        stream.extend_from_slice(&[0x03, 0x00]); // a tiny deflate tail
        stream.extend_from_slice(&0u32.to_be_bytes());
        let err = ZlibDecoder::new().decode(&stream).unwrap_err();
        assert!(
            err.message.contains("dictionary"),
            "unexpected error: {}",
            err.message
        );
    }

    /// A corrupt zlib stream is untrusted input: wrong method, wrong
    /// check, truncated body, or garbage after a valid header — none may
    /// panic.
    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: alloc::vec::Vec<(&str, alloc::vec::Vec<u8>)> = alloc::vec![
            ("empty", alloc::vec![]),
            ("one", alloc::vec![0x78]),
            ("good_head", alloc::vec![0x78, 0x9C]),
            ("short", alloc::vec![0x78, 0x9C, 0x01]),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 2000, "zlib", |data| {
            let _ = ZlibDecoder::new().decode(data);
            let _ = ZlibDecoder::new().decode_bounded(data, 64);
            let _ = ZlibDecoder::new().decode_bounded_with_consumed(data, 64);
        });
    }
}
