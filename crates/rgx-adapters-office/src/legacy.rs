// SPDX-License-Identifier: Apache-2.0

//! Legacy office formats that are neither ZIP nor OLE2: AbiWord's gzipped
//! XML, Hangul Word Processor's raw record stream, and WordPerfect's
//! compound binary header.
//!
//! The ZIP-based members of the "legacy office" family — ODF's `.sxw`,
//! `.uot`, `.odi`, and UOF's package form — are already container members
//! once the archive adapter opens them, so claiming them again here would
//! only take the extension away from the reader that can actually read them.
//! `.hwp` is the interesting case because it has *two* shapes: the OLE2
//! wrapper (handled by the compound reader) and a raw record stream that
//! starts with its own signature.

#[cfg(any(feature = "hwp", feature = "wordperfect"))]
use alloc::string::String;
#[cfg(feature = "wordperfect")]
use alloc::string::ToString;
#[cfg(feature = "wordperfect")]
use alloc::vec::Vec;
#[cfg(any(feature = "hwp", feature = "wordperfect"))]
use core::fmt::Write as _;

use rgx_core::{decline, Adapter, Outcome, Result};

/// The raw HWP signature: the string repeated twice, 256 bytes apart.
#[cfg(feature = "hwp")]
const HWP_SIG: &[u8] = b"HWP Document File";

#[cfg(feature = "abiword")]
pub struct AbiWord;
#[cfg(feature = "abiword")]
impl Adapter for AbiWord {
    fn name(&self) -> &'static str {
        "abiword"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["abw"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // An `.abw` is gzip, and the plain-text fallback (`abw` saved as XML
        // without compression) exists too. Decompressing is what turns a
        // document ripgrep skips into one it reads.
        if data.len() < 2 || data[0] != 0x1f || data[1] != 0x8b {
            if data.starts_with(b"<?xml") || data.starts_with(b"<!DOCTYPE abw") {
                return Ok(Outcome::Text(data.to_vec()));
            }
            decline!("not an AbiWord file (no gzip header)");
        }
        let plain = rgx_core::compress::gzip::GzipReader::decode(data)
            .map_err(|e| rgx_core::anyhow!("gzip: {e}"))?;
        if plain.is_empty() {
            decline!("AbiWord file decompressed to nothing");
        }
        Ok(Outcome::Text(plain))
    }
}

/// Hangul Word Processor 5.0, raw record stream.
#[cfg(feature = "hwp")]
pub struct HwpRaw;
#[cfg(feature = "hwp")]
impl Adapter for HwpRaw {
    fn name(&self) -> &'static str {
        "hwp-raw"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["hwd"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // `.hwp` proper is OLE2 and belongs to the compound reader. The raw
        // form has its own signature and is a different container entirely,
        // so claiming it under its own extension keeps the two from
        // shadowing each other.
        if !data.starts_with(HWP_SIG) {
            decline!("not a raw HWP document (bad signature)");
        }
        let mut out = String::new();
        let _ = writeln!(out, "HWP document (raw record stream)");
        // A 32-byte, 256-byte-aligned header. The compressed section length
        // is at 0x1C and the inflated length at 0x20.
        let u32le = |o: usize| -> u64 {
            let b = data.get(o..o + 4);
            match b {
                Some(x) => u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as u64,
                None => 0,
            }
        };
        let compressed = u32le(0x1C);
        let plain_len = u32le(0x20);
        let encrypted = u32le(0x24) & 0x01 != 0;
        let _ = writeln!(
            out,
            "compressed {compressed} bytes, expands to {plain_len} bytes{}",
            if encrypted {
                ", encrypted (password-protected)"
            } else {
                ""
            }
        );
        if encrypted {
            // An encrypted body is Korean SEED-encrypted zlib. Decrypting it
            // needs the password, which rgx does not have; saying so beats
            // emitting the ciphertext as if it were text.
            let _ = writeln!(
                out,
                "body not decrypted: the document is password-protected"
            );
            return Ok(Outcome::Text(out.into_bytes()));
        }
        let end = 256usize.saturating_add(compressed as usize);
        if compressed == 0 {
            let _ = writeln!(out, "no body: the document carries no record stream");
            return Ok(Outcome::Text(out.into_bytes()));
        }
        let Some(body) = data.get(256..end) else {
            let _ = writeln!(out, "body is truncated");
            return Ok(Outcome::Text(out.into_bytes()));
        };
        let plain = rgx_core::compress::zlib::ZlibDecoder::new()
            .decode(body)
            .map_err(|e| rgx_core::anyhow!("zlib: {e}"))?;
        let n = records(&plain, &mut out);
        let _ = writeln!(out, "records: {n}");
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// The record stream is a sequence of `(uint32 tag, uint32 level, uint32 size,
/// payload)`. Tags below 0x10 are controls; HWPTAG_PARA_TEXT is 0x10 and the
/// text tags run to 0x1A. EUC-KR text is what a Korean HWP stores, so the
/// bytes are reported as Latin-1 rather than mangled through UTF-8.
#[cfg(feature = "hwp")]
fn records(plain: &[u8], out: &mut String) -> usize {
    let mut p = 0usize;
    let mut n = 0usize;
    let mut shown = 0usize;
    while p + 12 <= plain.len() {
        let rd = |o: usize| -> u32 {
            let b = plain.get(p + o..p + o + 4);
            match b {
                Some(x) => u32::from_le_bytes([x[0], x[1], x[2], x[3]]),
                None => 0,
            }
        };
        let tag = rd(0);
        let size = rd(8) as usize;
        let body = p + 12;
        if size > plain.len() - body {
            break;
        }
        n += 1;
        // 0x10..=0x1A are the paragraph text tags; their payload is EUC-KR.
        if (0x10..=0x1A).contains(&tag) && shown < 64 {
            let bytes = &plain[body..body + size];
            if bytes.iter().any(|b| (0x20..0x7f).contains(b)) {
                let text: String = bytes.iter().map(|b| *b as char).collect();
                let trimmed = text.trim();
                if trimmed.len() > 1 {
                    let _ = writeln!(out, "  {trimmed}");
                    shown += 1;
                }
            }
        }
        p = body + size;
        if n > 500_000 {
            break;
        }
    }
    n
}

/// WordPerfect 5.1/8: a compound binary whose header declares the product
/// type and the point size, and whose text is stored in a thesaurus-indexed
/// encoding that no short reader decodes.
#[cfg(feature = "wordperfect")]
pub struct WordPerfect;
#[cfg(feature = "wordperfect")]
impl Adapter for WordPerfect {
    fn name(&self) -> &'static str {
        "wordperfect"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["wpd", "wps", "wfb"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // `\xFFWPC` is the 5.x product code and sits in bytes 0..4, so the document
        // type is at byte 4 and the point size at 18. Version 11+ drops the
        // code and starts with the type as a little-endian u16. Reading the
        // type from offset 0 in the 5.x form yields 0x57FF — the letter 'W'.
        let old = data.starts_with(b"\xffWPC");
        let doc_type = if old {
            data.get(4).copied().unwrap_or(0) as u16
        } else {
            if data.len() < 16 {
                decline!("too small for a WordPerfect document");
            }
            u16::from_le_bytes([*data.first().unwrap_or(&0), *data.get(1).unwrap_or(&0)])
        };
        let known = matches!(
            doc_type,
            1 | 2 | 3 | 4 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16
        );
        if !old && !known {
            decline!("not a WordPerfect document (unknown document type {doc_type})");
        }
        let point_at = if old { 18 } else { 8 };
        let mut out = String::new();
        let name = match doc_type {
            1 => "document",
            2 => "worksheet",
            3 => "dictionary",
            4 => "macro",
            9 => "merge codes",
            10 => "data source",
            11 => "style",
            12 => "list",
            13 => "block",
            14 => "line",
            15 => "page",
            16 => "column",
            _ => "unknown",
        };
        let _ = writeln!(out, "WordPerfect {name} (type {doc_type})");
        if let Some(size) = data.get(point_at) {
            let _ = writeln!(out, "point size {size}");
        }
        // The character-thesaurus encoding is not decoded here, so what is
        // reported is the printable runs, and the report says so.
        let runs = runs(data, 6, 400);
        if runs.is_empty() {
            let _ = writeln!(out, "no printable runs; the body is thesaurus-encoded");
        } else {
            let _ = writeln!(out, "printable runs (the body is thesaurus-encoded):");
            for r in runs {
                let _ = writeln!(out, "  {r}");
            }
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(feature = "wordperfect")]
fn runs(data: &[u8], min: usize, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < data.len() && out.len() < max {
        let b = data[i];
        if (0x20..0x7f).contains(&b) || b == b'\t' {
            i += 1;
            continue;
        }
        if i - start >= min {
            let s = String::from_utf8_lossy(&data[start..i]).trim().to_string();
            if !s.is_empty() {
                out.push(s);
            }
        }
        start = i + 1;
        i += 1;
    }
    out
}

#[cfg(all(
    test,
    any(feature = "abiword", feature = "hwp", feature = "wordperfect")
))]
mod tests {
    use super::*;
    use alloc::string::String;

    // The abiword test builds a gzip member and the hwp test builds a
    // header buffer, and both name `Vec` outright.
    #[cfg(feature = "abiword")]
    use alloc::vec;
    #[cfg(any(feature = "abiword", feature = "hwp"))]
    use alloc::vec::Vec;

    fn text_of(r: Result<Outcome>) -> String {
        match r.expect("adapter") {
            Outcome::Text(t) => String::from_utf8_lossy(&t).into_owned(),
            _ => panic!("expected Text"),
        }
    }

    /// A gzip member built from stored (uncompressed) DEFLATE blocks, which is
    /// RFC 1951 valid and exercises the real decoder. Each block's LEN/NLEN
    /// must state *that* block's length: a fixed pair produces a stream that
    /// decodes to its first byte and then fails.
    #[cfg(feature = "abiword")]
    fn gzip(payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut rest = payload;
        loop {
            let take = rest.len().min(0xFFFF);
            let (chunk, tail) = rest.split_at(take);
            let last = tail.is_empty();
            body.push(if last { 1 } else { 0 });
            body.extend_from_slice(&(take as u16).to_le_bytes());
            body.extend_from_slice(&(!(take as u16)).to_le_bytes());
            body.extend_from_slice(chunk);
            if last {
                break;
            }
            rest = tail;
        }
        let mut out = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0x03];
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc32(payload).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out
    }

    #[cfg(feature = "abiword")]
    fn crc32(d: &[u8]) -> u32 {
        let mut table = [0u32; 256];
        for (i, e) in table.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *e = c;
        }
        let mut c = 0xFFFF_FFFFu32;
        for b in d {
            c = table[((c ^ *b as u32) & 0xFF) as usize] ^ (c >> 8);
        }
        c ^ 0xFFFF_FFFF
    }

    #[cfg(feature = "abiword")]
    #[test]
    fn an_abiword_file_becomes_its_xml() {
        let xml = b"<?xml version=\"1.0\"?><!DOCTYPE abw><abw:abw><abw:p>Contrato de aluguel</abw:p></abw:abw>";
        let out = text_of(AbiWord.extract(&gzip(xml), "x.abw"));
        assert!(out.contains("Contrato de aluguel"), "{out}");
    }

    #[cfg(feature = "hwp")]
    #[test]
    fn a_raw_hwp_document_reports_its_header_and_declines_to_invent_text() {
        let mut d = Vec::from(HWP_SIG);
        d.extend_from_slice(&[0u8; 256 - HWP_SIG.len()]);
        // compressed length 0 at 0x1C, inflated 0 at 0x20, not encrypted.
        d.extend_from_slice(&[0u8; 256]);
        let out = text_of(HwpRaw.extract(&d, "x.hwd"));
        assert!(out.contains("HWP document"), "{out}");
        assert!(HwpRaw.extract(b"not an hwp at all", "x.hwd").is_err());
    }

    #[cfg(feature = "hwp")]
    #[test]
    fn an_encrypted_hwp_says_so_instead_of_printing_ciphertext() {
        let mut d = Vec::from(HWP_SIG);
        d.extend_from_slice(&[0u8; 256 - HWP_SIG.len()]);
        d.extend_from_slice(&[0u8; 256]);
        d[0x24] = 0x01; // encrypted
        d[0x1C..0x20].copy_from_slice(&512u32.to_le_bytes());
        let out = text_of(HwpRaw.extract(&d, "x.hwd"));
        assert!(out.contains("password-protected"), "{out}");
        assert!(!out.contains("records:"), "{out}");
    }

    #[cfg(feature = "wordperfect")]
    #[test]
    fn a_wordperfect_header_names_the_document_type() {
        let mut d = b"\xffWPC".to_vec();
        d.push(1); // document type at offset 4
        d.push(0);
        d.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        d.push(12); // point size at offset 18
        d.extend_from_slice(b"some printable prose here");
        let out = text_of(WordPerfect.extract(&d, "x.wpd"));
        assert!(out.contains("WordPerfect document"), "{out}");
        assert!(out.contains("printable runs"), "{out}");
        assert!(WordPerfect.extract(b"\x00\x00\x00\x00", "x.wpd").is_err());
    }
}
