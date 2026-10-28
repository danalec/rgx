// SPDX-License-Identifier: Apache-2.0

//! Extra media adapters: font name tables (TTF/OTF/TTC) and MOBI/AZW
//! e-book metadata.
//!
//! Both are small fixed-layout binary formats — no dependencies, parse
//! straight off the byte slice.

#[cfg(feature = "font")]
use alloc::collections::BTreeMap;
#[cfg(any(feature = "font", feature = "woff", feature = "mobi"))]
use alloc::string::String;
#[cfg(any(feature = "font", feature = "woff"))]
use alloc::string::ToString;
#[cfg(any(feature = "font", feature = "woff", feature = "mobi"))]
use core::fmt::Write as _;
#[cfg(any(feature = "font", feature = "mobi"))]
use rgx_core::bail;
#[cfg(any(feature = "font", feature = "woff", feature = "mobi"))]
use rgx_core::decline;
#[cfg(any(feature = "font", feature = "woff", feature = "mobi"))]
use rgx_core::Adapter;
#[cfg(any(feature = "font", feature = "woff", feature = "mobi"))]
use rgx_core::Outcome;
#[cfg(any(feature = "font", feature = "woff", feature = "mobi"))]
use rgx_core::Result;

#[cfg(any(feature = "font", feature = "woff", feature = "mobi"))]
fn rd_u16be(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}
#[cfg(any(feature = "font", feature = "woff", feature = "mobi"))]
fn rd_u32be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

// ---------- TrueType / OpenType names ----------

/// Name IDs worth reporting (1=family, 2=subfamily, 4=full, 6=postscript,
/// 3=unique, 5=version, 13=license, 14=license URL, 0=copyright).
#[cfg(feature = "font")]
const NAME_IDS: &[(u16, &str)] = &[
    (0, "copyright"),
    (1, "family"),
    (2, "subfamily"),
    (3, "unique"),
    (4, "full-name"),
    (5, "version"),
    (6, "postscript"),
    (13, "license"),
    (14, "license-url"),
];

/// Parse one sfnt 'name' table starting at `base` in `data`.
#[cfg(feature = "font")]
fn font_names(data: &[u8], base: usize, out: &mut String) {
    // table: u16 format, u16 count, u16 stringOffset, then count records
    // of 12 bytes: platform, encoding, language, nameID, length, offset
    if base + 6 > data.len() {
        return;
    }
    let count = rd_u16be(data, base + 2) as usize;
    let _string_off = rd_u16be(data, base + 4) as usize;
    let strings = base + 6 + count * 12;
    // prefer Windows (platform 3) records, fall back to Macintosh (1)
    let mut picked: BTreeMap<u16, String> = BTreeMap::new();
    for i in 0..count.min(512) {
        let rec = base + 6 + i * 12;
        if rec + 12 > data.len() {
            break;
        }
        let platform = rd_u16be(data, rec);
        let name_id = rd_u16be(data, rec + 6);
        let len = rd_u16be(data, rec + 8) as usize;
        let off = rd_u16be(data, rec + 10) as usize;
        if strings + off + len > data.len() || len > 512 {
            continue;
        }
        let raw = &data[strings + off..strings + off + len];
        let decode = |utf16: bool| -> String {
            if utf16 {
                raw.as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .map(|u| char::from_u32(u as u32).unwrap_or('\u{FFFD}'))
                    .collect()
            } else {
                raw.iter().map(|&b| char::from(b)).collect()
            }
        };
        let text = match platform {
            3 => decode(true),
            1 => decode(false),
            _ => continue,
        };
        // Windows records win over Mac records for the same name id
        if platform == 3 || !picked.contains_key(&name_id) {
            picked.insert(name_id, text.trim().to_string());
        }
    }
    for &(id, label) in NAME_IDS {
        if let Some(v) = picked.get(&id) {
            if !v.is_empty() {
                let _ = writeln!(out, "{label}: {v}");
            }
        }
    }
}

/// sfnt container walk: find 'name' tables (one per font in collections).
#[cfg(feature = "font")]
fn walk_sfnt(data: &[u8], offset: usize, out: &mut String, depth: usize) -> Result<()> {
    if depth > 4 || offset + 12 > data.len() {
        bail!("truncated sfnt header");
    }
    let scaler = &data[offset..offset + 4];
    if scaler == b"ttcf" {
        // TrueType Collection: u32 tag, u32 version, u32 numFonts, offsets
        let n = rd_u32be(data, offset + 8) as usize;
        for i in 0..n.min(64) {
            // **Bound the READ, not just what it yields.** The offset table
            // entry is read before the guard below used to run, so a 12-byte
            // file -- `ttcf` plus a `numFonts` of 1 and nothing else -- indexed
            // `data[12..16]` on a 12-byte slice and aborted the process. The
            // header check above only proves `offset + 12 <= len`, which says
            // nothing about an offset TABLE, which starts where the header
            // ends.
            let at = offset + 12 + i * 4;
            if at + 4 > data.len() {
                break;
            }
            let off = rd_u32be(data, at) as usize;
            if off + 12 <= data.len() {
                let _ = writeln!(out, "--- font {} ---", i + 1);
                let _ = walk_sfnt(data, off, out, depth + 1);
            }
        }
        return Ok(());
    }
    let num_tables = rd_u16be(data, offset + 4) as usize;
    for i in 0..num_tables.min(256) {
        let rec = offset + 12 + i * 16;
        if rec + 16 > data.len() {
            break;
        }
        if &data[rec..rec + 4] == b"name" {
            let table_off = rd_u32be(data, rec + 8) as usize;
            font_names(data, table_off, out);
        }
    }
    Ok(())
}

/// TTF/OTF/TTC: extract the font's name table (family, subfamily, full
/// name, postscript name, version, license). What an agent needs to answer
/// "which font is this file" — never the glyph outlines.
#[cfg(feature = "font")]
pub struct FontNames;
#[cfg(feature = "font")]
impl Adapter for FontNames {
    fn name(&self) -> &'static str {
        "font"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ttf", "otf", "ttc", "otc"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 12 {
            decline!("too small for an sfnt container");
        }
        let scaler = &data[0..4];
        if scaler != b"ttcf"
            && scaler != b"\x00\x01\x00\x00"
            && scaler != b"OTTO"
            && scaler != b"true"
        {
            decline!("not an sfnt container (bad scaler type)");
        }
        let mut out = String::new();
        walk_sfnt(data, 0, &mut out, 0)?;
        if out.trim().is_empty() {
            decline!("no name table found");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

// ---------- WOFF / WOFF2 web fonts ----------

/// WOFF (1.0): sfnt tables zlib-compressed individually — without pulling
/// a deflate stack into this crate we index what identifies the font: the
/// table directory (tags + original sizes). WOFF 2.0: brotli-compressed
/// transforms; only the header and the known table-tag directory (flags
/// byte per entry, tags 0..=62 are registered) are readable without a
/// brotli decoder — that is still enough to answer "which font/which
/// tables does this webfont carry".
#[cfg(feature = "woff")]
pub struct Woff;
#[cfg(feature = "woff")]
impl Adapter for Woff {
    fn name(&self) -> &'static str {
        "woff"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["woff", "woff2"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 16 {
            decline!("too small for a woff container");
        }
        let flavor = &data[4..8];
        let flavor_name = match flavor {
            b"\x00\x01\x00\x00" => "TrueType",
            b"OTTO" => "CFF/OpenType",
            b"true" => "TrueType (Apple)",
            b"typ1" => "PostScript (Type1)",
            _ => "unknown",
        };
        let mut out = String::new();
        if &data[0..4] == b"wOFF" {
            let num_tables = rd_u16be(data, 12) as usize;
            let _ = writeln!(out, "woff v1 {flavor_name} tables: {num_tables}");
            for i in 0..num_tables.min(256) {
                let rec = 44 + i * 20; // header(44) + directory entries
                if rec + 20 > data.len() {
                    break;
                }
                let tag = String::from_utf8_lossy(&data[rec..rec + 4]).into_owned();
                let orig = rd_u32be(data, rec + 12);
                let _ = writeln!(out, "table: {tag} (orig {orig} bytes)");
            }
        } else if &data[0..4] == b"wOF2" {
            let num_tables = rd_u16be(data, 12) as usize;
            let _ = writeln!(out, "woff v2 {flavor_name} tables: {num_tables}");
            // variable-length directory: per entry a flags byte; tag id
            // 0..=62 maps to the registered tag table, 63 = 4 raw bytes.
            const TAGS: &[&str] = &[
                "cmap", "head", "hhea", "hmtx", "maxp", "name", "OS/2", "post", "cvt ", "fpgm",
                "glyf", "loca", "prep", "CFF ", "VORG", "EBDT", "EBLC", "gasp", "hdmx", "kern",
                "LTSH", "PCLT", "VDMX", "vhea", "vmtx", "BASE", "GDEF", "GPOS", "GSUB", "EBSC",
                "JSTF", "MATH", "CBDT", "CBLC", "COLR", "CPAL", "SVG ", "sbix", "acnt", "avar",
                "bdat", "bloc", "bsln", "cvar", "fdsc", "feat", "fmtx", "fvar", "gvar", "hsty",
                "just", "lcar", "mort", "morx", "opbd", "prop", "trak", "Zapf", "Silf", "Glat",
                "Gloc", "Feat", "Sill",
            ];
            let mut p = 48usize; // header is 48 bytes
            for _ in 0..num_tables.min(256) {
                let Some(&flags) = data.get(p) else { break };
                p += 1;
                let id = (flags & 0x3F) as usize;
                let tag: String = if id == 63 {
                    if p + 4 > data.len() {
                        break;
                    }
                    let t = String::from_utf8_lossy(&data[p..p + 4]).into_owned();
                    p += 4;
                    t
                } else {
                    TAGS.get(id).copied().unwrap_or("?").to_string()
                };
                // UIntBase128 original length: walk continuation bits
                let mut len: u64 = 0;
                let mut ok = false;
                for _ in 0..5 {
                    let Some(&b) = data.get(p) else { break };
                    p += 1;
                    len = (len << 7) | (b & 0x7F) as u64;
                    if b & 0x80 == 0 {
                        ok = true;
                        break;
                    }
                }
                if !ok {
                    break;
                }
                let _ = writeln!(out, "table: {tag} (orig {len} bytes)");
            }
        } else {
            decline!("not a woff container (bad magic)");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

// ---------- MOBI / AZW ----------

/// EXTH record types we name; everything else numeric.
#[cfg(feature = "mobi")]
fn exth_name(t: u32) -> &'static str {
    match t {
        100 => "author",
        101 => "publisher",
        102 => "imprint",
        103 => "description",
        104 => "isbn",
        105 => "subject",
        106 => "published",
        108 => "contributor",
        109 => "rights",
        110 => "subjectcode",
        112 => "source",
        113 => "asin",
        116 => "sample",
        129 => "kpf-conversion-options",
        // 503 is the *updated* title, not the title: the title itself is
        // the full name in the record-0 slot, and a book usually holds the
        // same string in both. Calling this one "title" printed the same
        // line twice, which reads like a bug in the adapter rather than
        // like two fields that happen to agree.
        503 => "updated title",
        524 => "language",
        525 => "paperback-isbn",
        531 => "periodical-type",
        534 => "categ-132",
        _ => "?",
    }
}

/// PalmDOC/MOBI metadata: PDB header, record 0 with the MOBI header and
/// EXTH record block (title, author, publisher, ...). The book's *text* is
/// never decompressed — like the model adapters, we extract metadata, not
/// payload.
#[cfg(feature = "mobi")]
pub struct Mobi;
#[cfg(feature = "mobi")]
impl Adapter for Mobi {
    fn name(&self) -> &'static str {
        "mobi"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["mobi", "azw", "azw3", "prc"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 78 + 16 {
            decline!("too small for a PDB file");
        }
        let num_records = rd_u16be(data, 76) as usize;
        if num_records == 0 || 78 + num_records * 8 > data.len() {
            bail!("bad PDB record list");
        }
        // record info entry 0: u32 data offset, u32 attributes
        let rec0 = rd_u32be(data, 78) as usize;
        let rec1 = if num_records > 1 {
            rd_u32be(data, 86) as usize
        } else {
            data.len()
        };
        if rec0 + 16 + 20 > rec1.min(data.len()) {
            bail!("record 0 out of range");
        }
        let r0 = &data[rec0..rec1.min(data.len())];
        // PalmDOC header (16 bytes) then MOBI header
        if &r0[16..20] != b"MOBI" {
            decline!("record 0 has no MOBI header (not a Mobi/AZW book)");
        }
        // header_len counts from the 'MOBI' magic (incl. magic + length)
        let mobi_header_len = rd_u32be(r0, 20) as usize;
        if 16 + mobi_header_len > r0.len() {
            bail!("truncated MOBI header");
        }
        // **The three reads below are at FIXED offsets, so the declared
        // header length does not cover them.** They sit at 0x54, 0x58 and
        // 0x80 of record 0, so the record needs 132 bytes before any of them
        // is in range. The guard above only asks whether `mobi_header_len`
        // fits, and `mobi_header_len` is a u32 straight out of the file with
        // no lower bound -- a ~94-byte crafted book sets it to 0, passes
        // that guard, and then indexes `r0[128..132]` on a 36-byte record.
        //
        // The spec's own minimum is far larger (a MOBI header is 232 bytes),
        // so this is not tightening anything real; it is stating the bound the
        // fixed-offset reads below have always needed.
        const MOBI_MIN_HEADER_END: usize = 132;
        if MOBI_MIN_HEADER_END > r0.len() {
            bail!("record 0 too short for the MOBI header fields it declares");
        }
        // **These offsets are relative to the START OF RECORD 0, not to the
        // 'MOBI' magic.** The MOBI header sits at record-0 offset 0x10, but
        // the MobileRead MOBI table numbers its fields from 0x10 upward and
        // puts Full Name Offset at 0x54 and the EXTH flags at 0x80 -- those
        // are record-0 addresses. KindleUnpack's `mobi_header.py` reads them
        // the same way (`self.header[0x54:0x5c]`, where `self.header` is
        // record 0) and applies the Full Name Offset *value* to record 0 as
        // well: "Offset in record 0 (not from start of file) of the full
        // name of the book".
        //
        // Reading them at 16+84 / 16+88 / 16+128 -- i.e. as if they were
        // relative to the magic -- lands 16 bytes late on real books: the
        // "offset" read is the Output Language field, the "length" read is
        // the Locale field, and the EXTH flags read lands in the 32 unknown
        // bytes after the real flags, so bit 0x40 is clear and the EXTH
        // block is never opened. A valid MOBI then yields no title and no
        // author at all.
        let flags = rd_u32be(r0, 128); // EXTH flags, record-0 0x80
        let full_name_off = rd_u32be(r0, 84) as usize; // 0x54
        let full_name_len = rd_u32be(r0, 88) as usize; // 0x58

        // decode values that are either UTF-8-ish bytes or UTF-16BE text
        let decode_text = |raw: &[u8]| -> String {
            if raw.len().is_multiple_of(2)
                && !raw.is_empty()
                && raw.as_chunks::<2>().0.iter().filter(|c| c[0] == 0).count() * 2 >= raw.len()
            {
                raw.as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .map(|u| char::from_u32(u as u32).unwrap_or('\u{FFFD}'))
                    .collect()
            } else {
                String::from_utf8_lossy(raw).into_owned()
            }
        };

        let mut out = String::new();
        if full_name_off + full_name_len <= r0.len() && full_name_len > 0 && full_name_len < 4096 {
            let name = decode_text(&r0[full_name_off..full_name_off + full_name_len]);
            let _ = writeln!(out, "title: {}", name.trim());
        }
        // EXTH block follows the MOBI header when flag 0x40 is set
        if flags & 0x40 != 0 {
            let exth = 16 + mobi_header_len;
            if exth + 12 <= r0.len() && &r0[exth..exth + 4] == b"EXTH" {
                let exth_len = rd_u32be(r0, exth + 4) as usize;
                let count = rd_u32be(r0, exth + 8) as usize;
                let mut p = exth + 12;
                for _ in 0..count.min(512) {
                    if p + 8 > exth + exth_len || p + 8 > r0.len() {
                        break;
                    }
                    let ty = rd_u32be(r0, p);
                    let len = rd_u32be(r0, p + 4) as usize;
                    if len < 8 || p + len > r0.len() {
                        break;
                    }
                    let val = &r0[p + 8..p + len];
                    let text = decode_text(val);
                    let text = text.trim();
                    if !text.is_empty() {
                        let _ = writeln!(out, "{}: {}", exth_name(ty), text);
                    }
                    p += len;
                }
            }
        }
        if out.trim().is_empty() {
            decline!("no MOBI metadata found");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// sfnt with a single 'name' table: one Windows record (family).
    #[cfg(feature = "font")]
    fn mini_ttf() -> Vec<u8> {
        let family = "ZIRCALOY Sans";
        let fam_utf16: Vec<u8> = family
            .encode_utf16()
            .flat_map(|u| u.to_be_bytes())
            .collect();
        let mut name_table = Vec::new();
        name_table.extend_from_slice(&0u16.to_be_bytes()); // format
        name_table.extend_from_slice(&1u16.to_le_bytes()); // count — BE!
                                                           // careful: name table uses big-endian
        name_table.clear();
        name_table.extend_from_slice(&0u16.to_be_bytes()); // format
        name_table.extend_from_slice(&1u16.to_be_bytes()); // count
        name_table.extend_from_slice(&18u16.to_be_bytes()); // stringOffset = 6+12
        name_table.extend_from_slice(&3u16.to_be_bytes()); // platform: windows
        name_table.extend_from_slice(&1u16.to_be_bytes()); // encoding
        name_table.extend_from_slice(&0x409u16.to_be_bytes()); // lang
        name_table.extend_from_slice(&1u16.to_be_bytes()); // nameID family
        name_table.extend_from_slice(&(fam_utf16.len() as u16).to_be_bytes());
        name_table.extend_from_slice(&0u16.to_be_bytes()); // offset
        name_table.extend_from_slice(&fam_utf16);

        let mut f = Vec::new();
        f.extend_from_slice(b"\0\x01\0\0"); // scaler
        f.extend_from_slice(&1u16.to_be_bytes()); // numTables
        f.extend_from_slice(&[0u8; 6]);
        // table record
        f.extend_from_slice(b"name");
        f.extend_from_slice(&0u32.to_be_bytes()); // checksum
        f.extend_from_slice(&28u32.to_be_bytes()); // offset (12+16)
        f.extend_from_slice(&(name_table.len() as u32).to_be_bytes());
        while f.len() < 28 {
            f.push(0);
        }
        f.extend_from_slice(&name_table);
        f
    }

    #[test]
    #[cfg(feature = "font")]
    fn ttf_family_name() {
        let out = FontNames.extract(&mini_ttf(), "a.ttf").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        assert!(String::from_utf8(t)
            .unwrap()
            .contains("family: ZIRCALOY Sans"));
    }

    #[test]
    #[cfg(feature = "font")]
    fn ttf_rejects_non_font() {
        assert!(FontNames.extract(b"whatever binary", "x.ttf").is_err());
    }

    #[cfg(feature = "mobi")]
    fn mini_mobi(title: &str, author: &str) -> Vec<u8> {
        let title_utf16: Vec<u8> = title.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
        let author_utf16: Vec<u8> = author
            .encode_utf16()
            .flat_map(|u| u.to_be_bytes())
            .collect();
        // EXTH records
        let mut exth = Vec::new();
        exth.extend_from_slice(b"EXTH");
        let mut body = Vec::new();
        for (ty, val) in [(503u32, &title_utf16[..]), (100u32, &author_utf16[..])] {
            body.extend_from_slice(&ty.to_be_bytes());
            body.extend_from_slice(&((8 + val.len()) as u32).to_be_bytes());
            body.extend_from_slice(val);
        }
        let exth_len = 12 + body.len();
        exth.extend_from_slice(&(exth_len as u32).to_be_bytes());
        exth.extend_from_slice(&2u32.to_be_bytes()); // count
        exth.extend_from_slice(&body);

        let mut r0 = vec![0u8; 16]; // PalmDOC header
        r0.extend_from_slice(b"MOBI");
        // MOBI header length: fixed region is 232 bytes total; we build a
        // compact but layout-faithful header (244 bytes covers full_name_off)
        r0.extend_from_slice(&232u32.to_be_bytes());
        r0.resize(16 + 232, 0);
        // Full Name Offset (0x54), Full Name Length (0x58) and the EXTH
        // flags (0x80) are at RECORD-0 offsets -- the 'MOBI' magic sits at
        // record-0 0x10, but these fields are not counted from it. The
        // Full Name Offset's value is likewise an offset into record 0.
        // Reading them at 16+84 / 16+88 / 16+128 lands 16 bytes late and
        // loses both the title and the whole EXTH block.
        let name_off = 16 + 232 + exth_len;
        r0[84..88].copy_from_slice(&(name_off as u32).to_be_bytes());
        r0[88..92].copy_from_slice(&(title.len() as u32).to_be_bytes());
        // EXTH flags at record-0 0x80 (0x40 = EXTH present, BE u32)
        r0[128 + 3] = 0x40;
        r0.extend_from_slice(&exth);
        r0.extend_from_slice(title.as_bytes());

        let mut d = vec![0u8; 78];
        d[76..78].copy_from_slice(&1u16.to_be_bytes()); // 1 record
        d.extend_from_slice(&86u32.to_be_bytes()); // record 0 offset (78 + 8)
        d.extend_from_slice(&0u32.to_be_bytes()); // attributes
        d.extend_from_slice(&r0);
        d
    }

    #[test]
    #[cfg(feature = "mobi")]
    fn mobi_title_and_author() {
        let d = mini_mobi("ZIRCALOY Field Guide", "Dana Leccia");
        let out = Mobi.extract(&d, "b.mobi").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("title: ZIRCALOY Field Guide"), "{s}");
        assert!(s.contains("author: Dana Leccia"), "{s}");
    }

    #[test]
    #[cfg(feature = "mobi")]
    fn mobi_rejects_non_pdb() {
        assert!(Mobi.extract(&[0u8; 200], "x.mobi").is_err());
    }

    /// The Full Name Offset/Length and the EXTH flags are at RECORD-0 offsets
    /// 0x54, 0x58 and 0x80 -- not at 0x64, 0x68 and 0x90, which is where
    /// counting them from the 'MOBI' magic (record-0 0x10) would put them.
    ///
    /// This test writes a *decoy* pair at record-0 0x64/0x68 -- the Output
    /// Language and Min Version fields, which is exactly what a reader
    /// using the magic-relative offsets would mistake for the name offset
    /// and length -- and asserts the title still comes out right. A reader
    /// with the 16-byte drift reads the decoy, lands somewhere else in the
    /// record, and either prints the wrong title or none.
    #[test]
    #[cfg(feature = "mobi")]
    fn mobi_name_offset_is_record0_relative_not_mobi_header_relative() {
        let mut d = mini_mobi("ZIRCALOY Field Guide", "Dana Leccia");
        // record 0 starts at 86; the decoy sits at record-0 0x64 and 0x68.
        let rec0 = 86usize;
        let decoy_off = 4096u32; // an offset no record of this size can hold
        d[rec0 + 0x64..rec0 + 0x68].copy_from_slice(&decoy_off.to_be_bytes());
        d[rec0 + 0x68..rec0 + 0x6c].copy_from_slice(&7u32.to_be_bytes());
        let out = Mobi.extract(&d, "b.mobi").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("title: ZIRCALOY Field Guide"), "{s}");
    }

    /// woff1: header + one directory entry for the 'name' table
    #[cfg(feature = "woff")]
    fn mini_woff1() -> Vec<u8> {
        let mut d = b"wOFF".to_vec();
        d.extend_from_slice(b"\x00\x01\x00\x00"); // TrueType flavor
        d.extend_from_slice(&104u32.to_be_bytes()); // length
        d.extend_from_slice(&1u16.to_be_bytes()); // numTables
        d.extend_from_slice(&0u16.to_be_bytes()); // reserved
        d.extend_from_slice(&0u32.to_be_bytes()); // totalSfntSize
        d.extend_from_slice(&2u16.to_be_bytes()); // majorVersion
        d.extend_from_slice(&1u16.to_be_bytes()); // minorVersion
        d.extend_from_slice(&0u32.to_be_bytes()); // metaOffset
        d.extend_from_slice(&0u32.to_be_bytes()); // metaLength
        d.extend_from_slice(&0u32.to_be_bytes()); // metaOrigLength
        d.extend_from_slice(&0u32.to_be_bytes()); // privOffset
        d.extend_from_slice(&0u32.to_be_bytes()); // privLength
        d.extend_from_slice(b"name");
        d.extend_from_slice(&44u32.to_be_bytes()); // offset
        d.extend_from_slice(&60u32.to_be_bytes()); // compLength
        d.extend_from_slice(&120u32.to_be_bytes()); // origLength
        d.extend_from_slice(&0u32.to_be_bytes()); // checksum
        d
    }

    /// woff2: header + one flags byte (tag id 5 = 'name') + base128 length
    #[cfg(feature = "woff")]
    fn mini_woff2() -> Vec<u8> {
        let mut d = b"wOF2".to_vec();
        d.extend_from_slice(b"OTTO"); // CFF flavor
        d.extend_from_slice(&49u32.to_be_bytes());
        d.extend_from_slice(&1u16.to_be_bytes()); // numTables
        d.extend_from_slice(&0u16.to_be_bytes());
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&5u8.to_be_bytes()); // flags: known tag id 5 = name
        d.extend_from_slice(&120u8.to_be_bytes()); // UIntBase128 length
        d
    }

    #[test]
    #[cfg(feature = "woff")]
    fn woff1_lists_tables() {
        let out = Woff.extract(&mini_woff1(), "f.woff").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8_lossy(&t);
        assert!(s.contains("woff v1 TrueType tables: 1"), "{s}");
        assert!(s.contains("table: name (orig 120 bytes)"), "{s}");
    }

    #[test]
    #[cfg(feature = "woff")]
    fn woff2_lists_known_tags() {
        let out = Woff.extract(&mini_woff2(), "f.woff2").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8_lossy(&t);
        assert!(s.contains("woff v2 CFF/OpenType tables: 1"), "{s}");
        assert!(
            s.contains("table: name (orig 120 bytes)"),
            "len={} s={s}",
            mini_woff2().len()
        );
    }

    mod fuzz {
        use super::*;

        #[test]
        #[cfg(feature = "mobi")]
        fn mobi_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("mobi", mini_mobi("ZIRCALOY Field Guide", "Dana Leccia")),
                    ("pdb-only", {
                        let mut d = vec![0u8; 78];
                        d[76..78].copy_from_slice(&1u16.to_be_bytes());
                        d
                    }),
                    ("empty", vec![]),
                ],
                1500,
                "mobi",
                |data| {
                    let _ = Mobi.extract(data, "fuzz.mobi");
                },
            );
        }

        #[test]
        #[cfg(feature = "font")]
        fn font_names_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("ttf", mini_ttf()),
                    ("sfnt-only", b"\0\x01\0\0".to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "font-names",
                |data| {
                    let _ = FontNames.extract(data, "fuzz.ttf");
                },
            );
        }

        #[test]
        #[cfg(feature = "woff")]
        fn woff_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("woff1", mini_woff1()),
                    ("woff2", mini_woff2()),
                    ("magic-only", b"wOFF".to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "woff",
                |data| {
                    let _ = Woff.extract(data, "fuzz.woff");
                },
            );
        }
    }
}

#[cfg(all(test, any(feature = "font", feature = "mobi")))]
#[path = "oob_regressions.rs"]
mod oob_regressions;
