// SPDX-License-Identifier: Apache-2.0

//! Windows Address Book (`.wab`).
//!
//! A WAB file is an OLE Compound File (CFB) holding a MAPI property storage
//! tree. The directory lists the streams; each contact lives in its own
//! `__SUBRECORD__<n>` stream, encoded as a MAPI property stream:
//!
//! * 4 bytes reserved
//! * 4 bytes version
//! * 4 bytes type
//! * 4 bytes count
//! * `count` records, each `(prop_tag:u32, flags:u32, value:?)`.
//!   In MAPI, the **low 16 bits** of `prop_tag` carry the property
//!   **type** (PT_STRING8 = 0x1E, PT_UNICODE = 0x1F, PT_BINARY = 0x102,
//!   …) and the **high 16 bits** carry the property **identifier**
//!   (PR_DISPLAY_NAME = 0x3001, PR_EMAIL_ADDRESS = 0x3003, …). The
//!   value's layout is dictated by the type.
//!
//! We read the CFB entirely in Rust — no C, no subprocess — by walking:
//!
//! 1. **Header** (512 bytes). Magic, sector size (9 = 512, 12 = 4096),
//!    FAT/DIFAT/mini-FAT locations.
//! 2. **DIFAT** in the header (109 u32 entries) plus any chained DIFAT
//!    sectors; each entry is a FAT sector number.
//! 3. **FAT chain**. Each u32 is `sector → next_sector` (or `ENDOFCHAIN`,
//!    `FREESECT`, `FATSECT`, `DIFSECT`). Streams and the directory are
//!    chains of sectors.
//! 4. **Directory**. A chain of 128-byte entries; each entry names a
//!    stream or storage and points to its sector chain (or to the
//!    mini-FAT if the stream is smaller than the mini-stream cutoff).
//! 5. **Mini-FAT** for small streams, mini-stream itself starting at
//!    the Root Entry's first sector.
//!
//! What we extract per contact: display name, given name, surname, email,
//! company, title, business/mobile/home phone, and a comment. The output
//! is one stanza per `__SUBRECORD__<n>` stream; a search for any of
//! these fields hits because the textual value is on its own line.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use rgx_core::{bail, decline};
use rgx_core::{Adapter, Outcome, Result};

// ----- OLE Compound File constants ----------------------------------------

const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const ENDOFCHAIN: u32 = 0xFFFFFFFE;
const FREESECT: u32 = 0xFFFFFFFF;
// `FATSECT` and `STG_ROOT` are documented OLE CFB sentinel values; the
// parser walks the FAT/DIFAT chains directly and the root entry's
// storage type is handled inline, so these constants only appear in the
// synthesised-fixture test below. Without the attribute, `cargo clippy
// --all-targets` flags them as dead in the lib-only build.
#[allow(dead_code)]
const FATSECT: u32 = 0xFFFFFFFD;
const STG_STREAM: u8 = 0x02;
#[allow(dead_code)]
const STG_ROOT: u8 = 0x05;

// ----- MAPI property tags we know how to read ------------------------------
//
// Layout: `(prop_id << 16) | prop_type`. The high 16 bits carry the
// MAPI property identifier (e.g. 0x3001 = PR_DISPLAY_NAME) and the low
// 16 bits carry the property **type** (PT_STRING8 = 0x1E, PT_UNICODE =
// 0x1F, …). We pick the PT_UNICODE form so the parser can store both
// spellings of the same property under one key.

const PR_DISPLAY_NAME: u32 = (0x3001 << 16) | 0x1F;
const PR_GIVEN_NAME: u32 = (0x3A11 << 16) | 0x1F;
const PR_SURNAME: u32 = (0x3A11 << 16) | 0x3F;
const PR_COMPANY_NAME: u32 = (0x3A16 << 16) | 0x1F;
const PR_TITLE: u32 = (0x3A17 << 16) | 0x1F;
const PR_EMAIL_ADDRESS: u32 = (0x3003 << 16) | 0x1F;
const PR_BUSINESS_TELEPHONE: u32 = (0x3A08 << 16) | 0x1F;
const PR_MOBILE_TELEPHONE: u32 = (0x3A1C << 16) | 0x1F;
const PR_HOME_TELEPHONE: u32 = (0x3A09 << 16) | 0x1F;
const PR_COMMENT: u32 = (0x3004 << 16) | 0x1F;

/// Windows Address Book — full CFB + MAPI walk in pure Rust.
pub struct Wab;
impl Adapter for Wab {
    fn name(&self) -> &'static str {
        "wab"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["wab"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 512 {
            decline!("too small for OLE Compound File");
        }
        if data[..8] != OLE_MAGIC {
            decline!("not an OLE Compound File (bad magic)");
        }
        let cfb = Cfb::parse(data)?;
        let contacts = extract_contacts(&cfb, data);
        let mut out = String::new();
        let _ = writeln!(out, "-- windows address book (OLE) --");
        let _ = writeln!(out, "sector size: {}", cfb.sector_size);
        let _ = writeln!(out, "directory entries: {}", cfb.directory.len());
        let _ = writeln!(out, "contact streams: {}", contacts.len());
        for (name, props) in &contacts {
            let _ = writeln!(out, "---");
            let _ = writeln!(out, "stream\t{name}");
            for (tag, key) in CANONICAL_TAGS {
                if let Some(v) = props.get(tag) {
                    let _ = writeln!(out, "  {key}\t{v}");
                }
            }
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// `(prop_tag, field_name)` pairs to print, in the order rgx emits
/// them. Tags are the canonical (PT_UNICODE) form; the parser
/// collapses the PT_STRING8 alternate into the same key.
const CANONICAL_TAGS: &[(u32, &str)] = &[
    (PR_DISPLAY_NAME, "display_name"),
    (PR_GIVEN_NAME, "given_name"),
    (PR_SURNAME, "surname"),
    (PR_EMAIL_ADDRESS, "email"),
    (PR_COMPANY_NAME, "company"),
    (PR_TITLE, "title"),
    (PR_BUSINESS_TELEPHONE, "phone_business"),
    (PR_MOBILE_TELEPHONE, "phone_mobile"),
    (PR_HOME_TELEPHONE, "phone_home"),
    (PR_COMMENT, "comment"),
];

// ----- OLE Compound File parser ------------------------------------------

struct Cfb {
    sector_size: usize,
    /// 0-based directory entries in stream order. Entry 0 is the Root.
    directory: Vec<DirEntry>,
    /// FAT chain: sector index → next sector.
    fat: Vec<u32>,
    /// Mini-FAT chain, used for streams smaller than the cutoff.
    mini_fat: Vec<u32>,
    /// First sector of the mini-stream (referenced by Root.start_sector).
    mini_stream_start: u32,
    /// Cutoff (in bytes) above which a stream lives in regular sectors
    /// rather than the mini-stream. The spec fixes it at 4096.
    mini_cutoff: u32,
}

#[derive(Clone, Debug)]
struct DirEntry {
    name: String,
    typ: u8,
    /// First sector of the entry's data. For a storage, the start of its
    /// directory sector chain; for a stream, the start of its data
    /// chain. For Root, the start of the mini-stream.
    start_sector: u32,
    /// Size in bytes. Zero for storages and the Root.
    size: u32,
}

impl Cfb {
    fn parse(data: &[u8]) -> Result<Self> {
        // ---- header -----------------------------------------------------
        // 0x1C: byte order (u16). Must be 0xFFFE (little-endian).
        // 0x1E: sector shift (u16). 9 = 512, 12 = 4096.
        // 0x20: mini sector shift (u16). Always 6 = 64.
        // 0x2C: number of FAT sectors (u32)
        // 0x30: first directory sector (u32)
        // 0x38: mini stream cutoff (u32, must be 0x00001000 = 4096)
        // 0x3C: first mini-FAT sector (u32)
        // 0x40: number of mini-FAT sectors (u32)
        // 0x44: first DIFAT sector (u32)
        // 0x48: number of DIFAT sectors (u32)
        // 0x4C..0x200: DIFAT (109 u32 entries)
        let byte_order = u16::from_le_bytes([data[0x1C], data[0x1D]]);
        if byte_order != 0xFFFE {
            decline!("CFB: only little-endian files are supported");
        }
        let sector_shift = u16::from_le_bytes([data[0x1E], data[0x1F]]) as usize;
        let sector_size: usize = match sector_shift {
            9 => 512,
            12 => 4096,
            _ => decline!("CFB: sector shift {sector_shift} not 9 or 12"),
        };
        let n_fat_sectors = u32::from_le_bytes([data[0x2C], data[0x2D], data[0x2E], data[0x2F]]);
        let first_dir_sector = u32::from_le_bytes([data[0x30], data[0x31], data[0x32], data[0x33]]);
        let mini_cutoff = u32::from_le_bytes([data[0x38], data[0x39], data[0x3A], data[0x3B]]);
        let first_minifat_sector =
            u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
        let n_minifat_sectors =
            u32::from_le_bytes([data[0x40], data[0x41], data[0x42], data[0x43]]);
        let first_difat_sector =
            u32::from_le_bytes([data[0x44], data[0x45], data[0x46], data[0x47]]);
        let n_difat_sectors = u32::from_le_bytes([data[0x48], data[0x49], data[0x4A], data[0x4B]]);
        let mut difat: Vec<u32> = Vec::with_capacity(109);
        for i in 0..109 {
            let off = 0x4C + i * 4;
            let v = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            if v != FREESECT {
                difat.push(v);
            }
        }
        if n_difat_sectors > 0 {
            let mut next = first_difat_sector;
            for _ in 0..n_difat_sectors {
                let off = sector_offset(next, sector_size, data.len())
                    .ok_or_else(|| rgx_core::anyhow!("CFB: DIFAT sector {next} out of range"))?;
                if off + sector_size > data.len() {
                    bail!("CFB: DIFAT sector {next} truncated");
                }
                let body = &data[off..off + sector_size];
                for i in 0..127 {
                    let v = u32::from_le_bytes([
                        body[i * 4],
                        body[i * 4 + 1],
                        body[i * 4 + 2],
                        body[i * 4 + 3],
                    ]);
                    if v != FREESECT {
                        difat.push(v);
                    }
                }
                next = u32::from_le_bytes([
                    body[127 * 4],
                    body[127 * 4 + 1],
                    body[127 * 4 + 2],
                    body[127 * 4 + 3],
                ]);
                if next == ENDOFCHAIN || next == FREESECT {
                    break;
                }
            }
        }
        // ---- FAT --------------------------------------------------------
        // The header's FAT-sector count is a claim, and the DIFAT can hold
        // fewer entries than it claims (109 header slots plus 127 per DIFAT
        // sector, and a truncated file stops early). Slicing to the claim
        // panicked on the gap; take what exists and say so if it is short.
        let want_fat = n_fat_sectors as usize;
        if want_fat > difat.len() {
            bail!(
                "CFB: header claims {want_fat} FAT sectors, DIFAT holds {}",
                difat.len()
            );
        }
        let mut fat: Vec<u32> = Vec::new();
        for &s in &difat[..want_fat] {
            let off = sector_offset(s, sector_size, data.len())
                .ok_or_else(|| rgx_core::anyhow!("CFB: FAT sector {s} out of range"))?;
            if off + sector_size > data.len() {
                bail!("CFB: FAT sector {s} truncated");
            }
            let body = &data[off..off + sector_size];
            for i in 0..(sector_size / 4) {
                fat.push(u32::from_le_bytes([
                    body[i * 4],
                    body[i * 4 + 1],
                    body[i * 4 + 2],
                    body[i * 4 + 3],
                ]));
            }
        }
        // ---- mini-FAT ----------------------------------------------------
        let mut mini_fat: Vec<u32> = Vec::new();
        let mut sec = first_minifat_sector;
        for _ in 0..n_minifat_sectors {
            if sec == ENDOFCHAIN || sec == FREESECT {
                break;
            }
            let off = sector_offset(sec, sector_size, data.len())
                .ok_or_else(|| rgx_core::anyhow!("CFB: mini-FAT sector {sec} out of range"))?;
            if off + sector_size > data.len() {
                bail!("CFB: mini-FAT sector {sec} truncated");
            }
            let body = &data[off..off + sector_size];
            for i in 0..(sector_size / 4) {
                mini_fat.push(u32::from_le_bytes([
                    body[i * 4],
                    body[i * 4 + 1],
                    body[i * 4 + 2],
                    body[i * 4 + 3],
                ]));
            }
            sec = if (sec as usize) < fat.len() {
                fat[sec as usize]
            } else {
                ENDOFCHAIN
            };
        }
        // ---- directory ---------------------------------------------------
        let mut directory: Vec<DirEntry> = Vec::new();
        let mut sec = first_dir_sector;
        // A FAT entry may point at itself or back at an ancestor, and the chain
        // is walked until ENDOFCHAIN. Without a visited set a self-referential
        // entry spins forever while `directory` grows; the sector index is the
        // bound, because a chain longer than the FAT has more sectors than
        // exist. `compound.rs` carries the same guard for the same reason.
        let mut visited = 0usize;
        loop {
            if sec == ENDOFCHAIN || sec == FREESECT {
                break;
            }
            visited += 1;
            if visited > fat.len().max(1) + 8 {
                bail!("CFB: directory chain does not terminate");
            }
            let off = sector_offset(sec, sector_size, data.len())
                .ok_or_else(|| rgx_core::anyhow!("CFB: directory sector {sec} out of range"))?;
            if off + sector_size > data.len() {
                bail!("CFB: directory sector {sec} truncated");
            }
            let body = &data[off..off + sector_size];
            for i in 0..(sector_size / 128) {
                let e = &body[i * 128..(i + 1) * 128];
                let typ = e[66];
                // Type 0 means the slot is unused; skip it. Real CFBs
                // leave the trailing slots of a directory sector zeroed
                // so this filters out the noise without an explicit
                // count field.
                if typ == 0 {
                    continue;
                }
                let name_len = u16::from_le_bytes([e[64], e[65]]) as usize;
                let read_len = if name_len >= 2 {
                    (name_len - 2).min(64)
                } else {
                    0
                };
                let name = decode_utf16_name(&e[..read_len]);
                let start = u32::from_le_bytes([e[0x74], e[0x75], e[0x76], e[0x77]]);
                let size = u32::from_le_bytes([e[0x78], e[0x79], e[0x7A], e[0x7B]]);
                directory.push(DirEntry {
                    name,
                    typ,
                    start_sector: start,
                    size,
                });
            }
            if (sec as usize) < fat.len() {
                sec = fat[sec as usize];
            } else {
                break;
            }
        }
        let mini_stream_start = if !directory.is_empty() {
            directory[0].start_sector
        } else {
            ENDOFCHAIN
        };
        Ok(Cfb {
            sector_size,
            directory,
            fat,
            mini_fat,
            mini_stream_start,
            mini_cutoff,
        })
    }

    /// Read a stream's bytes. For streams smaller than `mini_cutoff`
    /// the data lives in the mini-stream and is addressed via
    /// `mini_fat`; otherwise it lives in regular sectors via `fat`.
    fn read_stream(&self, data: &[u8], dir: &DirEntry) -> Result<Vec<u8>> {
        if dir.size == 0 {
            return Ok(Vec::new());
        }
        // `dir.size` is a raw u32 from the directory entry, so a ~1 KB file can
        // claim 4 GiB and `with_capacity` would try to commit all of it before
        // a single byte was validated. Cap the reservation at what the file
        // could possibly hold; the stream is truncated to `dir.size` anyway.
        let want = dir.size as usize;
        let cap = want.min(data.len()).max(1);
        if dir.size < self.mini_cutoff {
            let mut out = Vec::with_capacity(cap);
            let mut sec = dir.start_sector;
            let mut visited = 0usize;
            loop {
                if sec == ENDOFCHAIN || sec == FREESECT {
                    break;
                }
                visited += 1;
                if visited > self.mini_fat.len().max(1) + 8 {
                    bail!("CFB: mini stream chain does not terminate");
                }
                let off = mini_offset(self.mini_stream_start, sec, self.sector_size, data.len())
                    .ok_or_else(|| rgx_core::anyhow!("CFB: mini-sector {sec} out of range"))?;
                let n = (want - out.len()).min(64);
                // `mini_offset` only bounds the *start*; a partial final
                // sector made `off + n` run past the buffer.
                let Some(body) = data.get(off..off + n) else {
                    bail!("CFB: mini-sector {sec} truncated");
                };
                out.extend_from_slice(body);
                if (sec as usize) < self.mini_fat.len() {
                    sec = self.mini_fat[sec as usize];
                } else {
                    break;
                }
                if out.len() >= want {
                    break;
                }
            }
            out.truncate(want);
            Ok(out)
        } else {
            let mut out = Vec::with_capacity(cap);
            let mut sec = dir.start_sector;
            let mut visited = 0usize;
            loop {
                if sec == ENDOFCHAIN || sec == FREESECT {
                    break;
                }
                visited += 1;
                if visited > self.fat.len().max(1) + 8 {
                    bail!("CFB: stream chain does not terminate");
                }
                let off = sector_offset(sec, self.sector_size, data.len())
                    .ok_or_else(|| rgx_core::anyhow!("CFB: stream sector {sec} out of range"))?;
                let n = (want - out.len()).min(self.sector_size);
                let Some(body) = data.get(off..off + n) else {
                    bail!("CFB: stream sector {sec} truncated");
                };
                out.extend_from_slice(body);
                if (sec as usize) < self.fat.len() {
                    sec = self.fat[sec as usize];
                } else {
                    break;
                }
                if out.len() >= want {
                    break;
                }
            }
            out.truncate(want);
            Ok(out)
        }
    }
}

fn sector_offset(sector: u32, sector_size: usize, total: usize) -> Option<usize> {
    // CFB sectors are 0-based and start right after the 512-byte header.
    let off = 512 + sector as usize * sector_size;
    if off >= total {
        None
    } else {
        Some(off)
    }
}

fn mini_offset(
    mini_stream_start: u32,
    mini_sector: u32,
    sector_size: usize,
    total: usize,
) -> Option<usize> {
    // Mini-sectors are 64 bytes; the mini-stream itself is a regular
    // sector chain rooted at `mini_stream_start`.
    let sec = mini_stream_start as usize + mini_sector as usize * 64 / sector_size;
    let inner = mini_sector as usize * 64 % sector_size;
    sector_offset(sec as u32, sector_size, total).map(|o| o + inner)
}

fn decode_utf16_name(bytes: &[u8]) -> String {
    let mut s = String::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if u == 0 {
            break;
        }
        if let Some(c) = char::from_u32(u as u32) {
            s.push(c);
        }
        i += 2;
    }
    s
}

// ----- MAPI property extraction ------------------------------------------

/// Walk the directory, find `__SUBRECORD__<n>` streams, parse each as a
/// MAPI property stream, and collect the property map per contact.
fn extract_contacts(cfb: &Cfb, data: &[u8]) -> Vec<(String, BTreeMap<u32, String>)> {
    let mut out = Vec::new();
    for dir in &cfb.directory {
        if dir.typ != STG_STREAM || !dir.name.starts_with("__SUBRECORD__") {
            continue;
        }
        let bytes = match cfb.read_stream(data, dir) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let props = match parse_mapi_stream(&bytes) {
            Ok(p) => p,
            Err(_) => continue,
        };
        out.push((dir.name.clone(), props));
    }
    out
}

/// MAPI property stream: a 16-byte stream header followed by an array
/// of (prop_tag:u32, flags:u32, value:?).
///
/// The value's layout is dictated by the type half of `prop_tag`:
/// PT_STRING8 (0x1E) and PT_UNICODE (0x1F) are NUL-terminated, PT_BINARY
/// (0x102) is a u32 length followed by raw bytes, and the small
/// integer/boolean types are fixed-width.
///
/// We collapse the PT_STRING8 alternate of a property (e.g. `0x3A11_001E`
/// vs `0x3A11_001F`) to the same canonical key so the caller sees one
/// entry per property name; PT_UNICODE wins when both are present.
fn parse_mapi_stream(data: &[u8]) -> Result<BTreeMap<u32, String>> {
    if data.len() < 16 {
        return Ok(BTreeMap::new());
    }
    let count = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
    let mut pos = 16usize;
    let mut by_tag: BTreeMap<u32, String> = BTreeMap::new();
    for _ in 0..count {
        if pos + 8 > data.len() {
            break;
        }
        let prop_tag = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let _flags =
            u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        pos += 8;
        let prop_type = prop_tag & 0xFFFF;
        // Length first, slice once, check in between. Each arm used to return
        // `(len, &data[a..b])` in the same expression, so the guard below could
        // not protect the slice it was written to protect: PT_STRING8 on a
        // value with no NUL gives `end == len` and `pos + end + 1` runs one
        // past the buffer, PT_UNICODE two, and PT_BINARY trusts a u32 straight
        // from the file.
        let value_len: usize = match prop_type {
            0x0001 => 0, // PT_NULL
            0x0002 => 2, // PT_I2
            0x0003 => 4, // PT_LONG
            0x0004 => 4, // PT_R4
            0x0005 => 8, // PT_DOUBLE
            0x0006 => 4, // PT_BOOLEAN
            0x000A => 4, // PT_ERROR
            // PT_STRING8: NUL-terminated MBCS. `find_nul` returns the slice
            // length when there is none, hence the +1.
            0x001E => find_nul(&data[pos..]).saturating_add(1),
            // PT_UNICODE: NUL-terminated UTF-16LE; +2 for the whole code unit.
            0x001F => find_nul_u16(&data[pos..]).saturating_add(2),
            0x0040 => 8,  // PT_SYSTIME
            0x0048 => 16, // PT_CLSID
            0x0102 => {
                // PT_BINARY: u32 length prefix
                if pos + 4 > data.len() {
                    break;
                }
                u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as usize
            }
            _ => 0,
        };
        // Subtraction rather than `pos + value_len > len`, so a huge claim
        // cannot overflow the sum. A property that does not fit ends the walk:
        // `continue` without moving `pos` would re-read the same 8 bytes for
        // the remaining `count` iterations, and `count` is the file's own u32.
        if value_len == 0 || value_len > data.len() - pos {
            break;
        }
        let value_bytes = &data[pos..pos + value_len];
        pos += value_len;
        let text = match prop_type {
            0x001E => decode_string8(value_bytes),
            0x001F => decode_unicode(value_bytes),
            0x0002 => i16::from_le_bytes([value_bytes[0], value_bytes[1]]).to_string(),
            0x0003 | 0x000A => i32::from_le_bytes([
                value_bytes[0],
                value_bytes[1],
                value_bytes[2],
                value_bytes[3],
            ])
            .to_string(),
            0x0006 => (value_bytes[0] != 0).to_string(),
            0x0040 => String::new(), // FILETIME: skip textualisation
            0x0048 => format_guid(value_bytes),
            0x0102 => decode_binary_as_text(value_bytes),
            _ => continue,
        };
        by_tag.insert(prop_tag, text);
    }
    let mut result: BTreeMap<u32, String> = BTreeMap::new();
    for (tag, text) in &by_tag {
        let canonical = canonical_tag(*tag);
        match result.get(&canonical) {
            None => {
                result.insert(canonical, text.clone());
            }
            Some(existing) => {
                if existing.is_empty() && !text.is_empty() {
                    result.insert(canonical, text.clone());
                }
            }
        }
    }
    Ok(result)
}

/// Collapse the low-16-bit type half of a prop tag so that
/// `0x3001001E` (PT_STRING8) and `0x3001001F` (PT_UNICODE) map to the
/// same key. The high 16 bits carry the property identifier and stay
/// untouched; we rewrite the low byte to the PT_UNICODE bucket.
fn canonical_tag(tag: u32) -> u32 {
    let typ = tag & 0xFFFF;
    let id = tag & 0xFFFF0000;
    match typ {
        0x001E => id | 0x1F,
        0x003E => id | 0x3F,
        _ => tag,
    }
}

fn find_nul(b: &[u8]) -> usize {
    b.iter().position(|&c| c == 0).unwrap_or(b.len())
}

fn find_nul_u16(b: &[u8]) -> usize {
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == 0 && b[i + 1] == 0 {
            return i;
        }
        i += 2;
    }
    b.len()
}

fn decode_string8(b: &[u8]) -> String {
    // MAPI strings from older WAB builds are usually Windows-1252
    // encoded; we keep them as ISO-8859-1 so each byte round-trips and
    // no information is lost. A lossless reconstruction from a WAB
    // needs the original codepage, which the file does not record.
    let end = if b.last() == Some(&0) {
        b.len() - 1
    } else {
        b.len()
    };
    b[..end].iter().map(|&c| c as char).collect()
}

fn decode_unicode(b: &[u8]) -> String {
    let end = if b.len() >= 2 && b[b.len() - 2] == 0 && b[b.len() - 1] == 0 {
        b.len() - 2
    } else {
        b.len()
    };
    let mut s = String::new();
    let mut i = 0;
    while i + 1 < end {
        let u = u16::from_le_bytes([b[i], b[i + 1]]);
        if let Some(c) = char::from_u32(u as u32) {
            s.push(c);
        }
        i += 2;
    }
    s
}

fn decode_binary_as_text(b: &[u8]) -> String {
    // PT_BINARY often carries a property ID or an opaque blob; we emit
    // printable runs of >= 4 so a grep for an embedded value still hits.
    let mut s = String::new();
    let mut run: Vec<u8> = Vec::new();
    for &c in b {
        if (0x20..=0x7e).contains(&c) || c == b'\t' {
            run.push(c);
        } else {
            if run.len() >= 4 {
                s.push_str(core::str::from_utf8(&run).unwrap_or(""));
                s.push('\n');
            }
            run.clear();
        }
    }
    if run.len() >= 4 {
        s.push_str(core::str::from_utf8(&run).unwrap_or(""));
    }
    s
}

fn format_guid(b: &[u8]) -> String {
    if b.len() < 16 {
        return String::new();
    }
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn text_of(data: &[u8]) -> String {
        match Wab.extract(data, "a.wab").unwrap() {
            Outcome::Text(t) => String::from_utf8(t).unwrap(),
            _ => panic!("expected Outcome::Text"),
        }
    }

    /// Build a minimal CFB with one FAT sector, one directory sector,
    /// and one stream named "Properties". The directory sector's last
    /// 4 bytes carry the ENDOFCHAIN marker.
    fn build_minimal_cfb() -> Vec<u8> {
        let sector_size = 512usize;
        let mut buf = vec![0u8; 512 * 4];
        buf[..8].copy_from_slice(&OLE_MAGIC);
        // byte order LE
        buf[0x1C] = 0xFE;
        buf[0x1D] = 0xFF;
        // sector shift = 9
        buf[0x1E] = 0x09;
        buf[0x1F] = 0x00;
        // mini sector shift = 6
        buf[0x20] = 0x06;
        // n_fat_sectors = 1
        buf[0x2C] = 0x01;
        // first_dir_sector = 1
        buf[0x30] = 0x01;
        // mini cutoff 4096
        buf[0x38..0x3C].copy_from_slice(&4096u32.to_le_bytes());
        // DIFAT[0] = 0 (FAT sector)
        buf[0x4C] = 0x00;
        // FAT: sector 0 is the FAT itself, so slot 0 = FATSECT; sector
        // 1 is the directory and ends the chain there (ENDOFCHAIN);
        // the rest are FREESECT.
        let fat_off = 512;
        let fat = [
            FATSECT,    // sector 0: this is the FAT sector itself
            ENDOFCHAIN, // sector 1: directory, end of chain
        ];
        for (i, v) in fat.iter().enumerate() {
            buf[fat_off + i * 4..fat_off + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        for i in fat.len()..(sector_size / 4) {
            buf[fat_off + i * 4..fat_off + i * 4 + 4].copy_from_slice(&FREESECT.to_le_bytes());
        }
        // Directory (sector 1)
        let dir_off = 512 + sector_size;
        // Entry 0: Root
        write_utf16_name(&mut buf[dir_off..dir_off + 64], "Root Entry");
        buf[dir_off + 0x42] = STG_ROOT;
        buf[dir_off + 0x43] = 0x01;
        // Entry 1: stream "Properties"
        let e1 = dir_off + 128;
        write_utf16_name(&mut buf[e1..e1 + 64], "Properties");
        buf[e1 + 0x42] = STG_STREAM;
        buf[e1 + 0x43] = 0x01;
        // End-of-chain marker
        buf[dir_off + sector_size - 4..dir_off + sector_size]
            .copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        buf
    }

    fn write_utf16_name(dst: &mut [u8], name: &str) {
        // `dst` must be at least 66 bytes: 64 for the name, 2 for the
        // length field. We never write past `dst[65]`.
        let mut i = 0;
        for c in name.encode_utf16() {
            if i + 1 >= 64 {
                break;
            }
            dst[i..i + 2].copy_from_slice(&c.to_le_bytes());
            i += 2;
        }
        if i < 64 {
            dst[i..i + 2].copy_from_slice(&0u16.to_le_bytes());
        }
        let len = (i + 2) as u16;
        if dst.len() >= 66 {
            dst[64] = (len & 0xff) as u8;
            dst[65] = ((len >> 8) & 0xff) as u8;
        }
    }

    #[test]
    fn cfb_header_is_recognised() {
        let buf = build_minimal_cfb();
        let out = text_of(&buf);
        assert!(out.contains("sector size: 512"), "{out}");
        assert!(out.contains("directory entries: 2"), "{out}");
    }

    #[test]
    fn rejects_file_without_ole_magic() {
        let mut buf = vec![0u8; 1024];
        buf[0] = 0xAB;
        assert!(Wab.extract(&buf, "a.wab").is_err());
    }

    #[test]
    fn rejects_le_only() {
        // Big-endian byte-order marker: must bail.
        let mut buf = vec![0u8; 1024];
        buf[..8].copy_from_slice(&OLE_MAGIC);
        buf[0x1C] = 0xFF;
        buf[0x1D] = 0xFE;
        buf[0x1E] = 0x09;
        assert!(Wab.extract(&buf, "a.wab").is_err());
    }

    #[test]
    fn mapi_string8_is_decoded() {
        // Build a small MAPI property stream: 1 record, PR_DISPLAY_NAME
        // in PT_STRING8 (0x3001001E) = "Alice".
        let mut body = vec![0u8; 16];
        body[12..16].copy_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&0x3001_001Eu32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes()); // flags
        body.extend_from_slice(b"Alice\0");
        let props = parse_mapi_stream(&body).unwrap();
        let canon = canonical_tag(0x3001_001E);
        assert_eq!(props.get(&canon).map(String::as_str), Some("Alice"));
    }

    #[test]
    fn mapi_unicode_is_decoded() {
        let mut body = vec![0u8; 16];
        body[12..16].copy_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&PR_DISPLAY_NAME.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        // "Bob" in UTF-16LE + NUL
        body.extend_from_slice(&[0x42, 0x00, 0x6F, 0x00, 0x62, 0x00, 0x00, 0x00]);
        let props = parse_mapi_stream(&body).unwrap();
        assert_eq!(props.get(&PR_DISPLAY_NAME).map(String::as_str), Some("Bob"));
    }
}
