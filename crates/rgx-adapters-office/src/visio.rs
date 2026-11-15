// SPDX-License-Identifier: Apache-2.0

//! Binary Visio (.vsd, Visio 1.x-2010) text extraction.
//!
//! The file is an OLE CFB whose `VisioDocument` stream is a forest of
//! sub-streams addressed by absolute offset; each holds either a chunk
//! sequence or a single blob, optionally compressed with the Visio LZSS
//! variant (4096-byte window). Text lives in `VSD_TEXT` (0x0e) chunks:
//! an 8-byte prefix followed by UTF-16LE (format version 11) or ANSI
//! (versions 1-6) characters. The grammar — chunk headers with their
//! trailer rules, pointer records, per-version quirks — was read from
//! LibreOffice's `libvisio`, the reconstruction of the format that exists;
//! the code here is rgx's own. Only text is interpreted;
//! geometry/styles/stencils are walked past.
//!
//! A reduced port of the Visio reader of the `io` project by Dan Gohman,
//! whose work is used here under Apache-2.0. See `NOTICE`.

use alloc::borrow::Cow;
#[allow(unused_imports)]
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use rgx_core::cfb::Cfb;
use rgx_core::Outcome;
use rgx_core::{bail, decline, Context, Result};

/// Stream magic: `Visio (TM) Drawing\r\n\0`.
const MAGIC: &[u8; 21] = b"Visio (TM) Drawing\r\n\0";

const TYPE_TRAILER: u32 = 0x14;
const TYPE_TEXT: u32 = 0x0e;
const TYPE_COLORS: u32 = 0x16;

const MAX_POINTERS: usize = 4096;
const MAX_CHUNKS: usize = 1 << 16;
const MAX_DEPTH: usize = 64;
const MAX_TEXT: usize = 16 << 20;

pub struct Visio;

impl rgx_core::Adapter for Visio {
    fn name(&self) -> &'static str {
        "visio"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["vsd"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let text = extract_text(data)?;
        Ok(Outcome::Text(text.into_bytes()))
    }
}

pub fn extract_text(data: &[u8]) -> Result<String> {
    let cfb = Cfb::parse(data)?;
    let doc = cfb
        .stream("VisioDocument")
        .decline_context("no VisioDocument stream")?;
    let mut texts = extract_text_stream(&doc)?;
    if texts.is_empty() {
        decline!("no text chunks in VisioDocument stream");
    }
    if texts.len() > MAX_TEXT {
        texts.truncate(MAX_TEXT);
    }
    Ok(texts)
}

fn rd_u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd_u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd_i16le(b: &[u8], o: usize) -> i16 {
    i16::from_le_bytes([b[o], b[o + 1]])
}
fn rd_i32le(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn extract_text_stream(doc: &[u8]) -> Result<String> {
    if doc.len() < 0x36 || &doc[..21] != MAGIC {
        decline!("not a binary Visio document (bad magic)");
    }
    let version = doc[0x1A];
    if !(1..=6).contains(&version) && version != 11 {
        bail!("unsupported Visio format version {version}");
    }

    let trailer = Pointer::read(doc, 0x24, version)
        .context("truncated VisioDocument header (no trailer pointer)")?;
    if trailer.ptr_type != TYPE_TRAILER
        || trailer.offset as usize >= doc.len()
        || trailer.length as usize > doc.len() - trailer.offset as usize
    {
        bail!("invalid trailer stream pointer");
    }

    let mut walker = Walker {
        doc,
        version,
        texts: String::new(),
        text_bytes: 0,
        visited: Vec::new(),
    };
    let region = &doc[trailer.offset as usize..trailer.offset as usize + trailer.length as usize];
    let buf = if trailer.is_compressed() {
        decompress(region)
    } else {
        region.to_vec()
    };
    let shift = if trailer.is_compressed() { 4 } else { 0 };
    if shift >= buf.len() {
        bail!("empty trailer stream");
    }
    if version <= 5 {
        if let Some((ls, pc, pos)) = walker.pointer_info_v5(&buf, shift, TYPE_TRAILER) {
            walker.follow_pointers(&buf, ls, pc, pos, 0);
        }
    } else {
        walker.walk_streams(&buf, shift, 0);
    }
    if walker.texts.is_empty() {
        decline!("no text chunks reached from the trailer stream");
    }
    Ok(walker.texts)
}

#[derive(Debug, Clone, Copy)]
struct Pointer {
    ptr_type: u32,
    offset: u32,
    length: u32,
    format: u16,
}

impl Pointer {
    /// 18-byte record: type, pad, offset, length, format (all LE).
    fn read_v6(doc: &[u8], o: usize) -> Option<Pointer> {
        if o + 18 > doc.len() {
            return None;
        }
        Some(Pointer {
            ptr_type: rd_u32le(doc, o),
            offset: rd_u32le(doc, o + 8),
            length: rd_u32le(doc, o + 12),
            format: rd_u16le(doc, o + 16),
        })
    }
    /// 16-byte record: type u16&0xFF, format u16&0xFF, pad dword,
    /// offset, length (format versions 1-5).
    fn read_v5(doc: &[u8], o: usize) -> Option<Pointer> {
        if o + 16 > doc.len() {
            return None;
        }
        Some(Pointer {
            ptr_type: rd_u16le(doc, o) as u32 & 0xFF,
            offset: rd_u32le(doc, o + 8),
            length: rd_u32le(doc, o + 12),
            format: rd_u16le(doc, o + 2) & 0xFF,
        })
    }
    fn read(doc: &[u8], o: usize, version: u8) -> Option<Pointer> {
        if version <= 5 {
            Self::read_v5(doc, o)
        } else {
            Self::read_v6(doc, o)
        }
    }
    fn size(version: u8) -> usize {
        if version <= 5 {
            16
        } else {
            18
        }
    }
    fn is_compressed(&self) -> bool {
        self.format & 2 != 0
    }
}

struct Walker<'a> {
    doc: &'a [u8],
    version: u8,
    texts: String,
    text_bytes: usize,
    visited: Vec<u32>,
}

impl<'a> Walker<'a> {
    /// `handleStreams`: read the pointer list at the start of a stream
    /// buffer and follow every pointer into the raw document.
    fn walk_streams(&mut self, buf: &[u8], shift: usize, depth: usize) {
        if depth >= MAX_DEPTH {
            return;
        }
        let (list_size, pointer_count, pos) = match self.pointer_info(buf, shift) {
            Some(v) => v,
            None => return,
        };
        self.follow_pointers(buf, list_size, pointer_count, pos, depth);
    }

    fn follow_pointers(
        &mut self,
        buf: &[u8],
        list_size: u32,
        pointer_count: i32,
        mut pos: usize,
        depth: usize,
    ) {
        if depth >= MAX_DEPTH {
            return;
        }
        let pointer_count = pointer_count.clamp(0, MAX_POINTERS as i32) as usize;
        let stride = Pointer::size(self.version);
        let mut pointers: Vec<(usize, Pointer)> = Vec::new();
        for i in 0..pointer_count {
            match Pointer::read(buf, pos, self.version) {
                Some(p) => {
                    pos += stride;
                    if p.ptr_type != 0 {
                        pointers.push((i, p));
                    }
                }
                None => break,
            }
        }
        // Order: pointers named by the trailing order list first, the rest
        // in declaration order (matches libvisio's emission order).
        let mut order: Vec<usize> = Vec::new();
        if list_size > 1 {
            for _ in 0..list_size.min(MAX_POINTERS as u32) {
                if pos + 4 > buf.len() {
                    break;
                }
                order.push(rd_u32le(buf, pos) as usize);
                pos += 4;
            }
        }
        let mut ordered: Vec<(usize, Pointer)> = Vec::with_capacity(pointers.len());
        for idx in order {
            if let Some(p) = pointers.iter().find(|(i, _)| *i == idx) {
                if !ordered.iter().any(|(i, _)| *i == idx) {
                    ordered.push(*p);
                }
            }
        }
        for p in &pointers {
            if !ordered.iter().any(|(i, _)| *i == p.0) {
                ordered.push(*p);
            }
        }

        for (_, p) in ordered {
            self.walk_stream(p, depth);
        }
    }

    /// `readPointerInfo` for format versions 6 and 11.
    fn pointer_info(&self, buf: &[u8], shift: usize) -> Option<(u32, i32, usize)> {
        if shift + 4 > buf.len() {
            return None;
        }
        let offset = rd_u32le(buf, shift) as usize;
        let list_at = offset.checked_add(shift)?.checked_sub(4)?;
        if list_at + 8 > buf.len() {
            return None;
        }
        let list_size = rd_u32le(buf, list_at);
        let pointer_count = rd_i32le(buf, list_at + 4);
        // 4 bytes of padding follow, then the pointer records themselves.
        Some((list_size, pointer_count, list_at + 8 + 4))
    }

    /// `readPointerInfo` for format versions 1-5: the pointer count lives
    /// at a type-dependent fixed offset and pointers follow immediately.
    fn pointer_info_v5(
        &self,
        buf: &[u8],
        shift: usize,
        ptr_type: u32,
    ) -> Option<(u32, i32, usize)> {
        let skip = match ptr_type {
            TYPE_TRAILER => 0x82,
            0x15 => 0x42,        // VSD_PAGE
            0x18 => 0x2e,        // VSD_FONT_LIST
            0x1a => 0x12,        // VSD_STYLES
            0x1d | 0x4e => 0x1e, // VSD_STENCILS / VSD_SHAPE_FOREIGN
            0x1e => 0x36,        // VSD_STENCIL_PAGE
            t if t > 0x45 => 0x1e,
            _ => 0x0a,
        };
        let at = shift.checked_add(skip)?;
        if at + 2 > buf.len() {
            return None;
        }
        Some((0, rd_i16le(buf, at) as i32, at + 2))
    }

    /// `handleStream`: decompress the pointed-at region and dispatch on
    /// the pointer format's high nibble.
    fn walk_stream(&mut self, p: Pointer, depth: usize) {
        let off = p.offset as usize;
        let len = p.length as usize;
        if off >= self.doc.len() || len > self.doc.len() - off || len < 2 {
            return;
        }
        let raw = &self.doc[off..off + len];
        // Compressed streams need an owned decompression buffer;
        // uncompressed streams are read straight from `self.doc`. The
        // prior code cloned uncompressed streams into a fresh `Vec<u8>`
        // per pointer, which doubled memory traffic for the common
        // case (most Visio streams are not LZSS-compressed).
        let buf: Cow<[u8]> = if p.is_compressed() {
            Cow::Owned(decompress(raw))
        } else {
            Cow::Borrowed(raw)
        };
        let shift = if p.is_compressed() { 4 } else { 0 };
        if shift >= buf.len() {
            return;
        }
        match p.format >> 4 {
            0x0 | 0x4 | 0x5 => {
                // Blob: the whole buffer is one chunk payload.
                if p.ptr_type == TYPE_TEXT && buf.len() > shift + 8 {
                    self.push_text(&buf[shift + 8..]);
                }
                if p.format >> 4 == 0x5 && p.ptr_type != TYPE_COLORS {
                    // Each stream offset is expanded once, however many
                    // pointers reach it.
                    if !self.visited.contains(&p.offset) {
                        self.visited.push(p.offset);
                        if self.version <= 5 {
                            if let Some((ls, pc, pos)) =
                                self.pointer_info_v5(&buf, shift, p.ptr_type)
                            {
                                self.follow_pointers(&buf, ls, pc, pos, depth + 1);
                            }
                        } else {
                            self.walk_streams(&buf, shift, depth + 1);
                        }
                    }
                }
            }
            0x8 | 0xc | 0xd => {
                if self.version <= 5 {
                    self.walk_chunks_v5(&buf);
                } else {
                    self.walk_chunks(&buf);
                }
            }
            _ => {}
        }
    }

    /// `handleChunks` for format versions 6 and 11.
    fn walk_chunks(&mut self, buf: &[u8]) {
        let mut pos = 0usize;
        let mut chunks = 0usize;
        while pos + 19 <= buf.len() && chunks < MAX_CHUNKS {
            // Chunks are zero-padded to alignment: skip NUL bytes.
            while pos < buf.len() && buf[pos] == 0 {
                pos += 1;
            }
            if pos + 19 > buf.len() {
                break;
            }
            let chunk_type = rd_u32le(buf, pos);
            let list = rd_u32le(buf, pos + 8);
            let data_length = rd_u32le(buf, pos + 12) as usize;
            let level = rd_u16le(buf, pos + 16);
            let unknown = buf[pos + 18];
            let data_start = pos + 19;

            let trailer = if self.version == 6 {
                trailer_v6(chunk_type, list)
            } else {
                trailer_v11(chunk_type, list, level, unknown)
            };

            let data_end = data_start.saturating_add(data_length);
            if data_end > buf.len() || data_end <= pos {
                break; // malformed length; stop this stream
            }
            if chunk_type == TYPE_TEXT && data_length > 8 {
                self.push_text(&buf[data_start + 8..data_end]);
            }
            chunks += 1;
            pos = data_end + trailer;
        }
    }

    /// `handleChunks` for format versions 1-5 (different chunk header:
    /// s16 type, s16 id, level, unknown, s16 list, u32 dataLength).
    fn walk_chunks_v5(&mut self, buf: &[u8]) {
        let mut pos = 0usize;
        let mut chunks = 0usize;
        while pos + 12 <= buf.len() && chunks < MAX_CHUNKS {
            while pos < buf.len() && buf[pos] == 0 {
                pos += 1;
            }
            if pos + 12 > buf.len() {
                break;
            }
            let chunk_type = rd_i16le(buf, pos) as u16 as u32;
            let data_length = rd_u32le(buf, pos + 8) as usize;
            let data_start = pos + 12;
            let data_end = data_start.saturating_add(data_length);
            if data_end > buf.len() || data_end <= pos {
                break;
            }
            if chunk_type == TYPE_TEXT && data_length > 8 {
                self.push_text(&buf[data_start + 8..data_end]);
            }
            chunks += 1;
            pos = data_end; // v5 chunks carry no trailer
        }
    }

    fn push_text(&mut self, raw: &[u8]) {
        if self.text_bytes >= MAX_TEXT {
            return;
        }
        // Version 6 and older store text as 8-bit ANSI (the VSD5 parser
        // inherits the VSD6 reader); version 11 uses UTF-16LE.
        if self.version <= 6 {
            decode_ansi_into(raw, &mut self.texts);
        } else {
            decode_utf16_into(raw, &mut self.texts);
        }
        self.text_bytes = self.texts.len();
        self.texts.push('\n');
    }
}

/// Trailer size after a chunk payload, format version 11.
fn trailer_v11(chunk_type: u32, list: u32, level: u16, unknown: u8) -> usize {
    if matches!(chunk_type, 0x1f | 0xc9 | 0x2d | 0xd1) {
        return 0;
    }
    let mut trailer = 0usize;
    if list != 0
        || matches!(
            chunk_type,
            0x71 | 0x70 | 0x6b | 0x6a | 0x69 | 0x66 | 0x65 | 0x2c
        )
    {
        trailer += 8;
    }
    if list != 0
        || (level == 2 && unknown == 0x55)
        || (level == 2 && unknown == 0x54 && chunk_type == 0xaa)
        || (level == 3 && unknown != 0x50 && unknown != 0x54)
    {
        trailer += 4;
    }
    if matches!(
        chunk_type,
        0x64 | 0x65
            | 0x66
            | 0x69
            | 0x6a
            | 0x6b
            | 0x6f
            | 0x71
            | 0x92
            | 0xa9
            | 0xb4
            | 0xb6
            | 0xb9
            | 0xc7
    ) && trailer != 12
        && trailer != 4
    {
        trailer += 4;
    }
    trailer
}

/// Trailer size after a chunk payload, format version 6.
fn trailer_v6(chunk_type: u32, list: u32) -> usize {
    if matches!(chunk_type, 0x1f | 0xc9) {
        return 0;
    }
    if list != 0
        || matches!(
            chunk_type,
            0x76 | 0x73
                | 0x72
                | 0x71
                | 0x70
                | 0x6f
                | 0x6e
                | 0x6d
                | 0x6c
                | 0x6b
                | 0x6a
                | 0x69
                | 0x68
                | 0x67
                | 0x66
                | 0x65
                | 0x64
                | 0x2c
                | 0xd
        )
    {
        8
    } else {
        0
    }
}

/// Visio LZSS: 4096-byte circular window, flag byte steers 8 literals
/// (bit set) or back-references (bit clear).
fn decompress(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() * 4);
    let mut window = [0u8; 4096];
    let mut pos = 0usize; // window write position
    let mut offset = 0usize;
    while offset < raw.len() {
        let flag = raw[offset];
        offset += 1;
        let mut mask = 1u8;
        for _ in 0..8 {
            if offset >= raw.len() {
                break;
            }
            if flag & mask != 0 {
                window[pos & 4095] = raw[offset];
                out.push(raw[offset]);
                offset += 1;
                pos += 1;
            } else {
                if offset + 1 >= raw.len() {
                    break;
                }
                let addr1 = raw[offset] as usize;
                let addr2 = raw[offset + 1] as usize;
                offset += 2;
                let length = (addr2 & 0xF) + 3;
                let mut pointer = ((addr2 & 0xF0) << 4) | addr1;
                if pointer > 4078 {
                    pointer -= 4078;
                } else {
                    pointer += 18;
                }
                for j in 0..length {
                    let b = window[(pointer + j) & 4095];
                    window[(pos + j) & 4095] = b;
                    out.push(b);
                }
                pos += length;
            }
            mask <<= 1;
        }
        // Hard cap: decompressed streams are bounded.
        if out.len() > MAX_TEXT {
            break;
        }
    }
    out
}

/// Decode UTF-16LE text with C0 markers (field placeholders) dropped.
fn decode_utf16_into(raw: &[u8], out: &mut String) {
    for chunk in raw.as_chunks::<2>().0 {
        let u = u16::from_le_bytes([chunk[0], chunk[1]]);
        match u {
            0xFEFF => {}
            0x09 | 0x0A | 0x0D => out.push(u as u8 as char),
            u if u >= 0x20 => {
                if let Some(c) = char::from_u32(u as u32) {
                    out.push(c);
                }
            }
            _ => {} // field markers and other C0 controls
        }
    }
}

/// Decode 8-bit ANSI text as Windows-1252.
fn decode_ansi_into(raw: &[u8], out: &mut String) {
    const HIGH: [char; 32] = [
        '\u{20AC}', '\u{FFFD}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}',
        '\u{2021}', '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{FFFD}',
        '\u{017D}', '\u{FFFD}', '\u{FFFD}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}',
        '\u{2022}', '\u{2013}', '\u{2014}', '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}',
        '\u{0153}', '\u{FFFD}', '\u{017E}', '\u{0178}',
    ];
    for &b in raw {
        match b {
            0x09 | 0x0A | 0x0D => out.push(b as char),
            0x20..=0x7E => out.push(b as char),
            0x80..=0x9F => out.push(HIGH[(b - 0x80) as usize]),
            0xA0..=0xFF => out.push(b as char),
            _ => {} // field markers and other C0 controls
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc_with_pointers(version: u8, pointers: &[Vec<u8>], body: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; 0x36];
        d[..21].copy_from_slice(MAGIC);
        d[0x1A] = version;
        let mut t = vec![0u8; 16];
        t[0..4].copy_from_slice(&8u32.to_le_bytes()); // offset field
        t[4..8].copy_from_slice(&0u32.to_le_bytes()); // list size
        t[8..12].copy_from_slice(&(pointers.len() as i32).to_le_bytes());
        for p in pointers {
            t.extend_from_slice(p);
        }
        d[0x24..0x28].copy_from_slice(&TYPE_TRAILER.to_le_bytes());
        d[0x28..0x2C].copy_from_slice(&0u32.to_le_bytes()); // pad
        d[0x2C..0x30].copy_from_slice(&0x36u32.to_le_bytes()); // offset
        d[0x30..0x34].copy_from_slice(&((t.len() + body.len()) as u32).to_le_bytes());
        d[0x34..0x36].copy_from_slice(&0x0000u16.to_le_bytes()); // format
        d.extend_from_slice(&t);
        d.extend_from_slice(body);
        d
    }

    fn page_with_text(text: &[u8]) -> Vec<u8> {
        let data_len = 8 + text.len();
        let mut c = Vec::new();
        c.extend_from_slice(&TYPE_TEXT.to_le_bytes());
        c.extend_from_slice(&1u32.to_le_bytes()); // id
        c.extend_from_slice(&0u32.to_le_bytes()); // list
        c.extend_from_slice(&(data_len as u32).to_le_bytes());
        c.extend_from_slice(&1u16.to_le_bytes()); // level
        c.push(0x50); // unknown
        c.extend_from_slice(&[0u8; 8]); // text prefix
        c.extend_from_slice(text);
        c
    }

    fn pointer(ptr_type: u32, offset: u32, length: u32, format: u16) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&ptr_type.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        p.extend_from_slice(&offset.to_le_bytes());
        p.extend_from_slice(&length.to_le_bytes());
        p.extend_from_slice(&format.to_le_bytes());
        p
    }

    const BODY: u32 = 0x36 + 16 + 18;

    #[test]
    fn v11_utf16_text_via_chunk_stream() {
        let units: Vec<u8> = [b'H' as u16, b'i' as u16, 0x20ACu16]
            .iter()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let page = page_with_text(&units);
        let ptrs = vec![pointer(0x15, BODY, page.len() as u32, 0x00D0)];
        let doc = doc_with_pointers(11, &ptrs, &page);
        let t = extract_text_stream(&doc).unwrap();
        assert_eq!(t, "Hi\u{20AC}\n");
    }

    #[test]
    fn v6_ansi_text() {
        let page = page_with_text(b"Z:\x80raw");
        let ptrs = vec![pointer(0x15, BODY, page.len() as u32, 0x00D0)];
        let doc = doc_with_pointers(6, &ptrs, &page);
        let t = extract_text_stream(&doc).unwrap();
        assert_eq!(t, "Z:\u{20AC}raw\n");
    }

    #[test]
    fn compressed_page_stream_roundtrip() {
        let page = page_with_text(b"LZss");
        let mut comp = Vec::new();
        for chunk in page.chunks(8) {
            comp.push(if chunk.len() >= 8 {
                0xFF
            } else {
                (1u8 << chunk.len()) - 1
            });
            comp.extend_from_slice(chunk);
        }
        let ptrs = vec![pointer(0x15, BODY, comp.len() as u32, 0x00D2)];
        let doc = doc_with_pointers(6, &ptrs, &comp);
        let t = extract_text_stream(&doc).unwrap();
        assert_eq!(t, "LZss\n");
    }

    #[test]
    fn text_blob_stream() {
        let units: Vec<u8> = "plain blob"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let mut blob = vec![0u8; 8];
        blob.extend_from_slice(&units);
        let ptrs = vec![pointer(TYPE_TEXT, BODY, blob.len() as u32, 0x0040)];
        let doc = doc_with_pointers(11, &ptrs, &blob);
        let t = extract_text_stream(&doc).unwrap();
        assert_eq!(t, "plain blob\n");
    }

    #[test]
    fn rejects_bad_magic_and_version() {
        assert!(extract_text_stream(b"nope").is_err());
        let mut d = vec![0u8; 0x40];
        d[..21].copy_from_slice(MAGIC);
        d[0x1A] = 33;
        assert!(extract_text_stream(&d).is_err());
    }

    #[test]
    fn truncated_never_panics() {
        let page = page_with_text(b"xyz");
        let ptrs = vec![pointer(0x15, BODY, page.len() as u32, 0x00D0)];
        let doc = doc_with_pointers(11, &ptrs, &page);
        for cut in 0..doc.len() {
            let _ = extract_text_stream(&doc[..cut]);
        }
    }

    /// Corpus sweep over the libvisio test data (18 real .vsd files,
    /// format versions 5/6/11). Points the env var at the directory to
    /// enable; skipped otherwise. The utf8/ms1252 pair must extract
    /// identical text.
    #[test]
    fn libvisio_corpus() {
        let Ok(dir) = std::env::var("RGX_VSD_CORPUS") else {
            return;
        };
        let mut checked = 0;
        let mut texts = BTreeMap::new();
        for ent in std::fs::read_dir(&dir).unwrap() {
            let p = ent.unwrap().path();
            if p.extension().and_then(|e| e.to_str()) != Some("vsd") {
                continue;
            }
            let data = std::fs::read(&p).unwrap();
            // bitmaps*/dwg are image-only drawings: no text chunks exist.
            let stem = p.file_stem().unwrap().to_string_lossy().into_owned();
            let expect_text = !(stem.starts_with("bitmaps") || stem == "dwg");
            match extract_text(&data) {
                Ok(out) => {
                    assert!(
                        !expect_text || !out.trim().is_empty(),
                        "no text: {}",
                        p.display()
                    );
                    texts.insert(stem, out);
                }
                Err(e) => assert!(!expect_text, "{}: {e}", p.display()),
            }
            checked += 1;
        }
        assert!(checked >= 10, "corpus too small: {checked} files");
        let a = texts.get("fdo86729-utf8").expect("utf8 twin");
        let b = texts.get("fdo86729-ms1252").expect("ms1252 twin");
        assert_eq!(a.trim(), b.trim(), "encoding twins must match");
    }
}
