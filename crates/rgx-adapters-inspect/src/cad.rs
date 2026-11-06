// SPDX-License-Identifier: Apache-2.0

//! CAD/CAE containers: AutoCAD DWG, Parasolid XT, ACIS SAB, Autodesk Revit
//! (OLE compound file) and MicroStation DGN.
//!
//! The rule this file is built to: report what the format's own header can
//! honestly answer, and name the part it does not decode. A guessed offset is
//! worse than an admission — it produces a report that reads well and lies,
//! and nothing downstream can tell.
//!
//! **The text CAD formats are rendered, not answered.** DXF (ASCII),
//! IFC/STEP, IGES and the ASCII ACIS `.sat` are plain text that ripgrep
//! already reads, entities and all, so their adapters declare `Reach::Render`:
//! under the default `Policy::Source` the file's own bytes are the answer and
//! the renderer is not consulted at all, and under `Policy::Render` the
//! rendering is what gets searched. Each of the four lives in its own module —
//! `cad_dxf`, `cad_step`, `cad_iges`, `cad_sat`.
//!
//! They were left unclaimed here until the question was measured instead of
//! argued. The objection was that a renderer which drops what the file carries
//! is a subset of ripgrep — true of the markup family, whose arms drop
//! `<script>` bodies and LaTeX control words. It is false of a renderer that
//! only *joins* what the file already says, and a CAD entity is exactly that:
//! a DXF's group codes put the entity's name on one line and its coordinates
//! on another, and a STEP instance is one long line whose entity, attributes
//! and name are separated by commas with no space. A rendering that puts the
//! name beside the values holds a pattern the file's own bytes do not
//! contain, which is the test AGENTS.md §2 sets for a rendering worth
//! writing. STL is still not claimed: it was outside that batch, and the same
//! argument would admit it, so it is a known remainder and not a verdict.
//!
//! `.sab` *is* claimed and `.sat` is rendered, because the SAB is the same
//! model in a binary container: there the entity stream is not text, and this
//! file reports the container's version token instead.
//!
//! Sources the byte layouts below come from, all checked before the code was
//! written and all reproduced in the tests:
//!   * DWG version codes — LibreDWG `include/dwg.h`, the `dwg_version_type`
//!     enum. Only the six-byte code at offset 0 is decoded; the section
//!     locators and the object map are not, and the report says so.
//!   * OLE compound file — [MS-CFB] §2.2 (header), §2.6.1 (directory entry),
//!     §2.3 (FAT), §2.5 (special values).
//!   * DGN — GDAL's `dgnlib`/`dgnread` (`ogr/ogrsf_frmts/dgn`): the element
//!     header is `level|complex`, `deleted|type`, and a 16-bit word count that
//!     sizes the element as `words * 2 + 4`.
//!
//! [MS-CFB]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/

#[cfg(feature = "rvt")]
use alloc::format;
use alloc::string::String;
#[cfg(any(feature = "dgn", feature = "dwg"))]
use alloc::string::ToString;
#[cfg(any(feature = "dgn", feature = "rvt"))]
use alloc::vec::Vec;
use core::fmt::Write as _;
#[cfg(any(feature = "dgn", feature = "rvt"))]
use rgx_core::bail;
use rgx_core::{decline, Adapter, Outcome, Result};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Renders bytes taken out of a file, which are allowed to hold anything.
///
/// A NUL in the rendering is not cosmetic: `BinaryDetection::Quit` reports
/// nothing at all once a NUL sits in the first 64 KiB, so a report carrying
/// one silently drops the file it was supposed to describe — out of `-c`, out
/// of `-l`, out of the exit status, on a file `rg` had counted.
#[cfg(any(
    feature = "acis-sab",
    feature = "dgn",
    feature = "dwg",
    feature = "parasolid"
))]
fn sanitize(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' {
            out.push(b as char);
        } else {
            out.push('\u{fffd}');
        }
    }
    out
}

/// The leading run of printable ASCII, capped. Used to name a version token
/// that lives inside bytes this build does not otherwise decode, so the
/// report can show what is written there without claiming to have parsed it.
#[cfg(feature = "acis-sab")]
fn ascii_run(data: &[u8], max: usize) -> String {
    let take = data
        .iter()
        .take(max)
        .take_while(|b| b.is_ascii_graphic() || **b == b' ')
        .count();
    sanitize(data.get(..take).unwrap_or(&[]))
}

#[cfg(any(feature = "dgn", feature = "rvt"))]
fn le16(d: &[u8], at: usize) -> Option<u16> {
    let s = d.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[cfg(any(feature = "dgn", feature = "rvt"))]
fn le32(d: &[u8], at: usize) -> Option<u32> {
    let s = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[cfg(feature = "rvt")]
fn le64(d: &[u8], at: usize) -> Option<u64> {
    let s = d.get(at..at.checked_add(8)?)?;
    let mut b = [0u8; 8];
    b.copy_from_slice(s);
    Some(u64::from_le_bytes(b))
}

#[cfg(feature = "parasolid")]
fn find(data: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > data.len() {
        return None;
    }
    data.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// DWG — AutoCAD drawing
// ---------------------------------------------------------------------------

/// AutoCAD DWG. The six-byte `AC10nn` code at offset 0 names the release;
/// everything past it (section locators, handles, the object map and the
/// object section where the layer and text names live) is not decoded here.
#[cfg(feature = "dwg")]
pub struct Dwg;

#[cfg(feature = "dwg")]
impl Adapter for Dwg {
    fn name(&self) -> &'static str {
        "dwg"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["dwg"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(describe_dwg(data)?.into_bytes()))
    }
}

/// Version code to release, from LibreDWG's `dwg_version_type`. Several codes
/// name the same release (AC1016 is 2000i, AC1017 is 2002), which is why the
/// table is keyed on the code and not the other way round.
#[cfg(feature = "dwg")]
const DWG_RELEASES: &[(&str, &str)] = &[
    ("AC1032", "AutoCAD Release 2018-2021"),
    ("AC1027", "AutoCAD Release 2013-2017"),
    ("AC1024", "AutoCAD Release 2010-2012"),
    ("AC1021", "AutoCAD Release 2007-2009"),
    ("AC1018", "AutoCAD Release 2004-2006"),
    ("AC1017", "AutoCAD Release 2002"),
    ("AC1016", "AutoCAD Release 2000i"),
    ("AC1015", "AutoCAD Release 2000"),
    ("AC1014", "AutoCAD Release 14"),
    ("AC1012", "AutoCAD Release 13"),
    ("AC1009", "AutoCAD Release 11/12"),
    ("AC1006", "AutoCAD Release 10"),
    ("AC1004", "AutoCAD Release 9"),
];

#[cfg(feature = "dwg")]
fn describe_dwg(data: &[u8]) -> Result<String> {
    // The code is six ASCII bytes. Anything shorter, or not `AC` followed by
    // four alphanumerics, is not a DWG whatever the name says.
    let code = data
        .get(..6)
        .ok_or_else(|| rgx_core::anyhow!("dwg: file shorter than its 6-byte version code"))?;
    if &code[..2] != b"AC" || !code[2..].iter().all(|b| b.is_ascii_alphanumeric()) {
        decline!("dwg: no ACxxxx version code at offset 0");
    }
    let code_str = sanitize(code);
    let release = DWG_RELEASES
        .iter()
        .find(|(c, _)| *c == code_str.as_str())
        .map(|(_, r)| (*r).to_string());

    let mut out = String::with_capacity(384);
    writeln!(out, "dwg: AutoCAD drawing").unwrap();
    writeln!(out, "  version code: {code_str}").unwrap();
    match &release {
        Some(r) => writeln!(out, "  release:       {r}").unwrap(),
        None => writeln!(out, "  release:       unmapped code, reported as written").unwrap(),
    }
    writeln!(out, "  file size:     {} bytes", data.len()).unwrap();
    writeln!(
        out,
        "  decoded:       the 6-byte version code at offset 0 only"
    )
    .unwrap();
    writeln!(
        out,
        "  not decoded:   section headers, handles, object map and the object\n\
         \x20               section. Layer, block, linetype and text names are in\n\
         \x20               the object section, so this report cannot show them."
    )
    .unwrap();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Parasolid XT — text (.x_t) and binary (.x_b) transmit files
// ---------------------------------------------------------------------------

/// The marker every XT transmit file opens with, in both its text and its
/// binary form: the header block is ASCII in both.
#[cfg(feature = "parasolid")]
const XT_MARKER: &[u8] = b"**ABCDEFGHIJKLMNOPQRSTUVWXYZ";
#[cfg(feature = "parasolid")]
const XT_END: &[u8] = b"**END_OF_HEADER";
/// The XT header is a handful of short lines. A megabyte without the end
/// marker means the file is not XT, not that the marker is further in.
#[cfg(feature = "parasolid")]
const XT_HEADER_LIMIT: usize = 8192;

/// Parasolid XT. Reports the transmit header (which is ASCII in both the text
/// and the binary variant) and which variant the body is; the modelled entity
/// stream is not decoded.
#[cfg(feature = "parasolid")]
pub struct ParasolidXt;

#[cfg(feature = "parasolid")]
impl Adapter for ParasolidXt {
    fn name(&self) -> &'static str {
        "parasolid-xt"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["x_t", "x_b", "xt"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(describe_xt(data)?.into_bytes()))
    }
}

/// `MC=x86_64_win;OS=WINDOWS;FORMAT=txt;` — one `key=value;` pair out of the
/// header block. Field order inside a record is not documented here, so each
/// value is taken by key and never by position.
#[cfg(feature = "parasolid")]
fn xt_field(header: &[u8], key: &str) -> Option<String> {
    let at = find(header, key.as_bytes())?;
    let rest = header.get(at..)?;
    let end = rest
        .iter()
        .position(|b| *b == b';' || *b == b'\n' || *b == b'\r')
        .unwrap_or(0);
    Some(sanitize(rest.get(..end)?))
}

#[cfg(feature = "parasolid")]
fn describe_xt(data: &[u8]) -> Result<String> {
    let head = data.get(..XT_MARKER.len()).ok_or_else(|| {
        rgx_core::Error::decline("parasolid: shorter than its own 28-byte marker")
    })?;
    if head != XT_MARKER {
        decline!("parasolid: no **ABCDEFGH.. transmit marker at offset 0");
    }
    let window = data.get(..XT_HEADER_LIMIT.min(data.len())).unwrap_or(&[]);
    let end_at = find(window, XT_END).ok_or_else(|| {
        rgx_core::anyhow!("parasolid: no **END_OF_HEADER within the first {XT_HEADER_LIMIT} bytes")
    })?;
    let header = window.get(..end_at).unwrap_or(&[]);

    // The body encoding is what separates .x_t from .x_b; the header is
    // ASCII in both, so it has to be read from past the end marker.
    let body = data.get(end_at + XT_END.len()..).unwrap_or(&[]);
    // `get(..256)` would demand 256 bytes and yield nothing for the short
    // bodies a truncated file has; the cap is `min`, not a range end.
    let probe = body.get(..body.len().min(256)).unwrap_or(&[]);
    let binary = probe
        .iter()
        .filter(|b| !(**b).is_ascii_graphic() && **b != b' ' && **b != b'\n' && **b != b'\r')
        .count()
        > probe.len() / 8;

    let mut out = String::with_capacity(header.len() + 512);
    writeln!(out, "parasolid: XT transmit file").unwrap();
    writeln!(
        out,
        "  body:          {}",
        if binary {
            "binary (XT binary transmit)"
        } else {
            "text (XT text transmit)"
        }
    )
    .unwrap();
    for key in ["MC=", "OS=", "FORMAT=", "GUISE="] {
        if let Some(v) = xt_field(header, key) {
            if !v.is_empty() {
                writeln!(out, "  {v}").unwrap();
            }
        }
    }
    if find(header, b"**PART1;").is_some() {
        writeln!(out, "  schema:        PART1").unwrap();
    }
    // The FILE record names the originating document. Its field order is not
    // documented here, so it is quoted as written instead of being split.
    if let Some(at) = find(header, b"FILE;") {
        let rest = header.get(at..).unwrap_or(&[]);
        let end = rest
            .iter()
            .position(|b| *b == b'\n' || *b == b'\r')
            .unwrap_or(rest.len());
        writeln!(
            out,
            "  file record:   {}",
            sanitize(rest.get(..end).unwrap_or(&[]))
        )
        .unwrap();
    }
    writeln!(
        out,
        "  not decoded:   the modelled entity stream after the header"
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "  [transmit header]").unwrap();
    for line in header.split(|b| *b == b'\n') {
        writeln!(out, "  {}", sanitize(line)).unwrap();
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// ACIS SAB — binary B-rep
// ---------------------------------------------------------------------------

/// ACIS binary (`.sab`). The container signature and the version token that
/// follows it are ASCII; the entity stream behind them is a binary B-rep and
/// is not decoded.
#[cfg(feature = "acis-sab")]
pub struct AcisSab;

#[cfg(feature = "acis-sab")]
impl Adapter for AcisSab {
    fn name(&self) -> &'static str {
        "acis-sab"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["sab"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(describe_sab(data)?.into_bytes()))
    }
}

#[cfg(feature = "acis-sab")]
fn describe_sab(data: &[u8]) -> Result<String> {
    let head = data
        .get(..4)
        .ok_or_else(|| rgx_core::anyhow!("acis: shorter than its 4-byte signature"))?;
    if head != b"ACIS" {
        decline!("acis: no ACIS signature at offset 0");
    }
    let token = ascii_run(data.get(4..).unwrap_or(&[]), 24);

    let mut out = String::with_capacity(256);
    writeln!(out, "acis: binary model (SAB)").unwrap();
    writeln!(out, "  signature:     ACIS").unwrap();
    if token.is_empty() {
        writeln!(out, "  version token: not readable as text at offset 4").unwrap();
    } else {
        writeln!(out, "  version token: {token}").unwrap();
    }
    writeln!(out, "  file size:     {} bytes", data.len()).unwrap();
    writeln!(
        out,
        "  not decoded:   the B-rep entity stream. Body, lump, shell, face and\n\
         \x20               edge records are binary and are not read here."
    )
    .unwrap();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Revit / OLE compound file
// ---------------------------------------------------------------------------

/// OLE compound file, the container Autodesk Revit writes an `.rvt` into.
/// The directory is decoded in full — storages and streams, named and sized —
/// because those names (`BasicFileInfo`, `Contents`, `RevitPreview4.0`) are
/// what a user searches a Revit model for. Stream *contents* are not.
#[cfg(feature = "rvt")]
pub struct Rvt;

#[cfg(feature = "rvt")]
impl Adapter for Rvt {
    fn name(&self) -> &'static str {
        "rvt"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["rvt"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(describe_cfb(data)?.into_bytes()))
    }
}

#[cfg(feature = "rvt")]
const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
#[cfg(feature = "rvt")]
const FREESECT: u32 = 0xFFFF_FFFF;
#[cfg(feature = "rvt")]
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
#[cfg(feature = "rvt")]
const DIFSECT: u32 = 0xFFFF_FFFC;
#[cfg(feature = "rvt")]
const NOSTREAM: u32 = 0xFFFF_FFFF;
#[cfg(feature = "rvt")]
const DIR_ENTRY_LEN: usize = 128;
#[cfg(feature = "rvt")]
const HEADER_LEN: usize = 512;
/// A chain this long means the FAT is corrupt, and following it is how a
/// reader spends the whole file's worth of time and memory. The bound is
/// generous next to a real directory: 64K sectors is 8M entries.
#[cfg(feature = "rvt")]
const MAX_CHAIN: usize = 1 << 16;

#[cfg(feature = "rvt")]
struct DirEntry {
    name: String,
    kind: u8,
    left: u32,
    right: u32,
    child: u32,
    size: u64,
}

#[cfg(feature = "rvt")]
fn sector(data: &[u8], id: u32, shift: u32) -> Option<&[u8]> {
    // Sector 0 starts immediately after the 512-byte header, so the file
    // offset is `512 + id * sector_size` and not `id * sector_size`.
    let size = 1usize << shift;
    let start = HEADER_LEN.checked_add((id as usize).checked_mul(size)?)?;
    let end = start.checked_add(size)?;
    data.get(start..end)
}

/// The sectors holding the FAT, from the header's own DIFAT and then along the
/// DIFAT chain (MS-CFB §2.2, offsets 76 and 68).
#[cfg(feature = "rvt")]
fn fat_sector_ids(data: &[u8], shift: u32, mut first_difat: u32) -> Vec<u32> {
    let mut ids = Vec::new();
    let entries_per_difat = (1usize << shift) / 4 - 1;
    for i in 0..109 {
        if let Some(id) = le32(data, 76 + i * 4) {
            if id <= DIFSECT {
                ids.push(id);
            }
        }
    }
    let mut guard = 0;
    while first_difat != ENDOFCHAIN && first_difat != FREESECT && first_difat <= DIFSECT {
        guard += 1;
        if guard > MAX_CHAIN {
            break;
        }
        let Some(sec) = sector(data, first_difat, shift) else {
            break;
        };
        for i in 0..entries_per_difat {
            if let Some(id) = le32(sec, i * 4) {
                if id <= DIFSECT {
                    ids.push(id);
                }
            }
        }
        first_difat = le32(sec, entries_per_difat * 4).unwrap_or(FREESECT);
    }
    ids
}

#[cfg(feature = "rvt")]
fn fat_table(data: &[u8], shift: u32, first_difat: u32) -> Vec<u32> {
    let mut fat = Vec::new();
    for id in fat_sector_ids(data, shift, first_difat) {
        let Some(sec) = sector(data, id, shift) else {
            break;
        };
        for chunk in sec.as_chunks::<4>().0 {
            fat.push(u32::from_le_bytes(*chunk));
        }
        if fat.len() > MAX_CHAIN {
            break;
        }
    }
    fat
}

/// Sectors of one chain, stopping on the end marker, on a sector the FAT does
/// not cover, or when the chain has consumed `limit` sectors — a chain that
/// wants more sectors than the file has is a cycle, and following it is how a
/// reader turns a corrupt FAT into an unbounded allocation.
#[cfg(feature = "rvt")]
fn chain(fat: &[u32], start: u32, limit: usize) -> Vec<u32> {
    let mut out = Vec::new();
    let mut cur = start;
    while out.len() < limit.min(MAX_CHAIN)
        && cur != ENDOFCHAIN
        && cur != FREESECT
        && (cur as usize) < fat.len()
    {
        out.push(cur);
        cur = fat.get(cur as usize).copied().unwrap_or(ENDOFCHAIN);
    }
    out
}

#[cfg(feature = "rvt")]
fn utf16le_name(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() / 2);
    let mut units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c));
    while let Some(unit) = units.next() {
        if unit == 0 {
            break;
        }
        if (0xD800..0xDC00).contains(&unit) {
            let cp = match units.next() {
                Some(lo) if (0xDC00..0xE000).contains(&lo) => {
                    0x1_0000 + ((unit as u32 - 0xD800) << 10) + (lo as u32 - 0xDC00)
                }
                Some(lo) => {
                    out.push('\u{fffd}');
                    lo as u32
                }
                None => break,
            };
            out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
            continue;
        }
        let ch = char::from_u32(unit as u32).unwrap_or('\u{fffd}');
        out.push(if ch.is_control() { '\u{fffd}' } else { ch });
    }
    out
}

#[cfg(feature = "rvt")]
fn dir_entry(raw: &[u8]) -> Option<DirEntry> {
    let name_len = le16(raw, 64)? as usize;
    let name_bytes = raw.get(..name_len.min(64))?;
    Some(DirEntry {
        name: utf16le_name(name_bytes),
        // Object type: 0 unallocated, 1 storage, 2 stream, 5 root.
        kind: *raw.get(66)?,
        left: le32(raw, 68).unwrap_or(NOSTREAM),
        right: le32(raw, 72).unwrap_or(NOSTREAM),
        child: le32(raw, 76).unwrap_or(NOSTREAM),
        size: le64(raw, 120).unwrap_or(0),
    })
}

#[cfg(feature = "rvt")]
fn describe_cfb(data: &[u8]) -> Result<String> {
    if data.get(..8) != Some(&CFB_MAGIC[..]) {
        decline!("compound file: no D0CF11E0A1B11AE1 signature");
    }
    // Byte order and sector shift decide every offset below; a header that
    // says otherwise is not a layout this reader understands, and reading it
    // anyway would invent names out of unrelated bytes.
    if le16(data, 30) != Some(0xFFFE) {
        decline!("compound file: byte order mark is not 0xFFFE (little-endian)");
    }
    let shift = u32::from(le16(data, 32).unwrap_or(0));
    if shift != 9 && shift != 12 {
        decline!("compound file: sector shift {shift} is neither 512 nor 4096 bytes");
    }
    let major = le16(data, 28).unwrap_or(0);
    let first_dir = le32(data, 48).unwrap_or(ENDOFCHAIN);
    let first_difat = le32(data, 68).unwrap_or(ENDOFCHAIN);
    let fat = fat_table(data, shift, first_difat);

    let mut entries: Vec<DirEntry> = Vec::new();
    // A directory chain can name each sector of the file at most once; the
    // count of sectors the file holds is therefore its own hard limit.
    let sector_limit = data.len().saturating_sub(HEADER_LEN) / (1usize << shift);
    for id in chain(&fat, first_dir, sector_limit) {
        let Some(sec) = sector(data, id, shift) else {
            break;
        };
        for chunk in sec.as_chunks::<DIR_ENTRY_LEN>().0 {
            if let Some(entry) = dir_entry(chunk) {
                entries.push(entry);
            }
        }
    }
    if entries.is_empty() {
        bail!("compound file: directory chain resolved to no entries");
    }

    // Directory entry ids are 1-based (`id - 1` indexes the vector), so the
    // root's own index is off by one from its id.
    let root = entries
        .iter()
        .position(|e| e.kind == 5)
        .map(|i| i as u32 + 1)
        .unwrap_or(1);
    let mut out = String::with_capacity(1024);
    writeln!(out, "compound file: OLE2 container (Revit)").unwrap();
    writeln!(
        out,
        "  layout:        version {major}, {}-byte sectors, little-endian",
        1usize << shift
    )
    .unwrap();
    writeln!(
        out,
        "  directory:     {} entries",
        entries.iter().filter(|e| e.kind != 0).count()
    )
    .unwrap();

    let mut seen = vec![false; entries.len()];
    let mut written = 0usize;
    let mut printed = String::new();
    walk_dir(&mut printed, &entries, &mut seen, root, "", 0, &mut written);
    out.push_str(&printed);

    // Entries the red-black tree does not reach are still entries; a file
    // whose tree was corrupted should not silently lose half its names.
    let unreachable: Vec<&DirEntry> = entries
        .iter()
        .enumerate()
        .filter(|(i, e)| e.kind != 0 && !seen[*i])
        .map(|(_, e)| e)
        .collect();
    if !unreachable.is_empty() {
        writeln!(
            out,
            "  not reachable from the root directory tree: {} entries",
            unreachable.len()
        )
        .unwrap();
        for entry in unreachable.iter().take(32) {
            writeln!(out, "    entry        {}", entry.name).unwrap();
        }
    }
    writeln!(
        out,
        "  not decoded:   stream contents. BasicFileInfo and PartAtom hold the\n\
         \x20               model's own metadata and are not read here."
    )
    .unwrap();
    Ok(out)
}

/// Walks the sibling/child tree the directory entries form (MS-CFB §2.6.4),
/// printing each storage and stream under its full path. Depth and repeats are
/// bounded: the structure is a tree only if the file is not lying.
#[cfg(feature = "rvt")]
fn walk_dir(
    out: &mut String,
    entries: &[DirEntry],
    seen: &mut [bool],
    id: u32,
    prefix: &str,
    depth: usize,
    written: &mut usize,
) {
    if depth > 32 || *written > 4096 {
        return;
    }
    let Some(index) = (id as usize).checked_sub(1) else {
        return;
    };
    if id == NOSTREAM || index >= entries.len() || seen[index] {
        return;
    }
    seen[index] = true;
    let entry = &entries[index];
    let path = if prefix.is_empty() {
        entry.name.clone()
    } else {
        format!("{prefix}/{}", entry.name)
    };
    if entry.kind != 0 {
        let kind = match entry.kind {
            1 => "storage",
            2 => "stream",
            5 => "root",
            _ => "entry",
        };
        if entry.kind == 2 || entry.kind == 5 {
            writeln!(out, "  {kind:<7} {path}  {} bytes", entry.size).unwrap();
        } else {
            writeln!(out, "  {kind:<7} {path}").unwrap();
        }
        *written += 1;
    }
    walk_dir(out, entries, seen, entry.left, prefix, depth + 1, written);
    walk_dir(out, entries, seen, entry.right, prefix, depth + 1, written);
    if entry.kind == 1 || entry.kind == 5 {
        // The root's children are top level; a storage's children carry its
        // name, which is what makes a nested `Global/PartAtom` readable.
        let below = if entry.kind == 5 {
            String::new()
        } else {
            format!("{path}/")
        };
        walk_dir(out, entries, seen, entry.child, &below, depth + 1, written);
    }
}

// ---------------------------------------------------------------------------
// MicroStation DGN
// ---------------------------------------------------------------------------

/// MicroStation DGN, v8 (ISFF). The file opens with its TCB element, which
/// carries the drawing's units; the elements after it are walked for a type
/// histogram. Geometry and cell names are not decoded.
#[cfg(feature = "dgn")]
pub struct Dgn;

#[cfg(feature = "dgn")]
impl Adapter for Dgn {
    fn name(&self) -> &'static str {
        "dgn"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["dgn"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(describe_dgn(data)?.into_bytes()))
    }
}

#[cfg(feature = "dgn")]
const DGN_TCB_TYPE: u8 = 9;
#[cfg(feature = "dgn")]
const DGN_TCB_WORDS: u16 = 0x02FE;
#[cfg(feature = "dgn")]
const DGN_ELEMENT_MAX: usize = 1 << 20;

/// Element type numbers, from GDAL's `dgnlib.h`. Types not listed here are
/// printed by number rather than given a name this build cannot vouch for.
#[cfg(feature = "dgn")]
const DGN_TYPES: &[(u8, &str)] = &[
    (1, "CELL_LIBRARY"),
    (2, "CELL_HEADER"),
    (3, "LINE"),
    (4, "LINE_STRING"),
    (5, "GROUP_DATA"),
    (6, "SHAPE"),
    (7, "TEXT_NODE"),
    (8, "DIGITIZER_SETUP"),
    (9, "TCB"),
    (10, "LEVEL_SYMBOLOGY"),
    (11, "CURVE"),
    (12, "COMPLEX_CHAIN_HEADER"),
    (14, "COMPLEX_SHAPE_HEADER"),
    (15, "ELLIPSE"),
    (16, "ARC"),
    (17, "TEXT"),
    (18, "3DSURFACE_HEADER"),
    (19, "3DSOLID_HEADER"),
    (21, "BSPLINE_POLE"),
    (22, "POINT_STRING"),
    (23, "CONE"),
    (24, "BSPLINE_SURFACE_HEADER"),
    (25, "BSPLINE_SURFACE_BOUNDARY"),
    (26, "BSPLINE_KNOT"),
    (27, "BSPLINE_CURVE_HEADER"),
    (28, "BSPLINE_WEIGHT_FACTOR"),
    (34, "SHARED_CELL_DEFN"),
    (35, "SHARED_CELL_ELEM"),
    (37, "TAG_VALUE"),
    (66, "APPLICATION_ELEM"),
];

#[cfg(feature = "dgn")]
fn dgn_type_name(t: u8) -> String {
    DGN_TYPES
        .iter()
        .find(|(ty, _)| *ty == t)
        .map(|(_, n)| (*n).to_string())
        .unwrap_or_else(|| "UNKNOWN".to_string())
}

/// One element header: `level | complex`, `deleted | type`, then a 16-bit word
/// count sizing the whole element as `words * 2 + 4`.
#[cfg(feature = "dgn")]
fn dgn_element(data: &[u8], at: usize) -> Option<(u8, u8, usize)> {
    let head = data.get(at..at.checked_add(4)?)?;
    if head[0] == 0xFF && head[1] == 0xFF {
        return None; // end-of-file marker
    }
    let level = head[0] & 0x3F;
    let ty = head[1] & 0x7F;
    let words = le16(data, at + 2)? as usize;
    Some((ty, level, words.checked_mul(2)?.checked_add(4)?))
}

#[cfg(feature = "dgn")]
fn describe_dgn(data: &[u8]) -> Result<String> {
    let (first_type, _level, tcb_len) = dgn_element(data, 0)
        .ok_or_else(|| rgx_core::anyhow!("dgn: shorter than one element header"))?;
    if first_type != DGN_TCB_TYPE {
        decline!("dgn: first element is type {first_type}, not the TCB");
    }
    if le16(data, 2) != Some(DGN_TCB_WORDS) {
        bail!(
            "dgn: TCB is not the expected {} bytes",
            DGN_TCB_WORDS * 2 + 4
        );
    }

    let mut out = String::with_capacity(1024);
    writeln!(out, "dgn: MicroStation design file v8 (ISFF)").unwrap();
    // The TCB is the only element that states the drawing's units, and its
    // fields sit at fixed offsets inside an element that is usually present
    // in full. The bound is the bytes the file actually has, not the length
    // the element claims: a file that stops short of a field has not got it.
    if data.len() > 1215 {
        let three_d = data.get(1214).map(|b| b & 0x40 != 0).unwrap_or(false);
        writeln!(
            out,
            "  dimension:     {}",
            if three_d { "3D" } else { "2D" }
        )
        .unwrap();
    }
    if data.len() > 1124 {
        let subunits = le32(data, 1112).unwrap_or(0);
        let uor = le32(data, 1116).unwrap_or(0);
        let master = sanitize(data.get(1120..1122).unwrap_or(&[]));
        let sub = sanitize(data.get(1122..1124).unwrap_or(&[]));
        writeln!(out, "  master units:  {master}").unwrap();
        writeln!(out, "  sub units:     {sub}").unwrap();
        writeln!(
            out,
            "  resolution:    {uor} uor/subunit, {subunits} subunits/master"
        )
        .unwrap();
    }

    let mut counts = [0u32; 128];
    let mut levels = [false; 64];
    let mut total = 0u32;
    let mut deleted = 0u32;
    let mut at = tcb_len;
    let mut stop = "end of file";
    for _ in 0..DGN_ELEMENT_MAX {
        let Some((ty, level, len)) = dgn_element(data, at) else {
            break;
        };
        if len < 6 {
            stop = "element shorter than its own header";
            break;
        }
        let Some(next) = at.checked_add(len) else {
            stop = "element length overflowed the file";
            break;
        };
        if next > data.len() {
            stop = "element runs past the end of the file";
            break;
        }
        let index = usize::from(ty) & 0x7F;
        if let Some(slot) = counts.get_mut(index) {
            *slot = slot.saturating_add(1);
        }
        levels[usize::from(level) & 0x3F] = true;
        if data.get(at + 1).map(|b| b & 0x80 != 0).unwrap_or(false) {
            deleted += 1;
        }
        total += 1;
        at = next;
    }
    if total as usize == DGN_ELEMENT_MAX {
        stop = "element scan hit its bound";
    }

    writeln!(out, "  elements:      {total} ({deleted} deleted)").unwrap();
    for (ty, count) in counts.iter().enumerate() {
        if *count > 0 {
            let ty = ty as u8;
            writeln!(
                out,
                "    type {:<3}      {:<22} {count}",
                ty,
                dgn_type_name(ty)
            )
            .unwrap();
        }
    }
    let used: Vec<String> = levels
        .iter()
        .enumerate()
        .filter(|(_, seen)| **seen)
        .map(|(i, _)| (i + 1).to_string())
        .collect();
    writeln!(out, "  levels in use: {}", used.join(", ")).unwrap();
    writeln!(out, "  scan stopped:  {stop}").unwrap();
    writeln!(
        out,
        "  not decoded:   cell names are Rad50-encoded and are left as bytes;\n\
         \x20               geometry, levels' symbology and text strings are not read."
    )
    .unwrap();
    Ok(out)
}

#[cfg(test)]
#[cfg(any(
    feature = "acis-sab",
    feature = "dgn",
    feature = "dwg",
    feature = "parasolid",
    feature = "rvt"
))]
mod tests {
    //! What these tests are for: each adapter is exercised through the path a
    //! user takes — `Adapter::extract` on a hand-built file — and each one
    //! also gets an input that must `bail!` or degrade without panicking. A
    //! parser that only ever sees well-formed files proves nothing about the
    //! truncated one, which is what the corpus actually contains.

    use super::*;
    #[cfg(feature = "parasolid")]
    use alloc::vec::Vec;

    #[cfg(any(
        feature = "acis-sab",
        feature = "dgn",
        feature = "dwg",
        feature = "parasolid",
        feature = "rvt"
    ))]
    fn text_of(outcome: Outcome) -> String {
        match outcome {
            Outcome::Text(t) => String::from_utf8(t).expect("report must be UTF-8"),
            _ => panic!("expected text"),
        }
    }

    // -- DWG --------------------------------------------------------------

    #[test]
    #[cfg(feature = "dwg")]
    fn a_dwg_version_code_names_the_release_and_says_what_is_not_decoded() {
        let mut dwg = b"AC1032".to_vec();
        dwg.extend_from_slice(&[0u8; 512]);
        let report = text_of(Dwg.extract(&dwg, "plan.dwg").unwrap());
        assert!(report.contains("AC1032"), "{report}");
        assert!(report.contains("AutoCAD Release 2018-2021"), "{report}");
        assert!(report.contains("not decoded"), "{report}");
        // The one promise the file can keep: a report with no control bytes
        // in it, so the file stays countable (see `sanitize`).
        assert!(!report.contains('\0'), "{report:?}");
    }

    #[test]
    #[cfg(feature = "dwg")]
    fn a_dwg_code_this_build_cannot_map_is_reported_as_written() {
        let report = text_of(Dwg.extract(b"AC9999\0\0\0\0\0\0", "odd.dwg").unwrap());
        assert!(report.contains("AC9999"), "{report}");
        assert!(report.contains("unmapped"), "{report}");
    }

    /// The extension is not the question: a `.dwg` that does not open with an
    /// `AC` version code is some other format wearing the name.
    #[test]
    #[cfg(feature = "dwg")]
    fn a_file_named_dwg_without_the_version_code_is_not_claimed() {
        assert!(Dwg
            .extract(b"PK\x03\x04not a drawing at all", "fake.dwg")
            .is_err());
        assert!(Dwg.extract(b"AC10", "stub.dwg").is_err());
    }

    // -- Parasolid XT -----------------------------------------------------

    #[cfg(feature = "parasolid")]
    fn xt_file(body: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(XT_MARKER);
        f.extend_from_slice(b"*******************************\n");
        f.extend_from_slice(b"**PARASOLID !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\n");
        f.extend_from_slice(b"**PART1;\n");
        f.extend_from_slice(b"MC=x86_64_win;OS=WINDOWS;FORMAT=txt;GUISE=transmit;\n");
        f.extend_from_slice(b"FILE;bracket.sld;2024/01/01;10:00:00;USER;HOST;APP;\n");
        f.extend_from_slice(XT_END);
        f.extend_from_slice(b"\n");
        f.extend_from_slice(body);
        f
    }

    #[test]
    #[cfg(feature = "parasolid")]
    fn a_parasolid_header_is_surfaced_verbatim_with_its_fields() {
        let report = text_of(
            ParasolidXt
                .extract(&xt_file(b"**END_OF_DATA\n"), "b.x_t")
                .unwrap(),
        );
        assert!(report.contains("MC=x86_64_win"), "{report}");
        assert!(report.contains("FORMAT=txt"), "{report}");
        assert!(report.contains("PART1"), "{report}");
        assert!(report.contains("bracket.sld"), "{report}");
        assert!(report.contains("text (XT text transmit)"), "{report}");
        // The header is the payload: it has to be in the report verbatim.
        assert!(report.contains("GUISE=transmit;"), "{report}");
    }

    #[test]
    #[cfg(feature = "parasolid")]
    fn a_parasolid_binary_body_is_distinguished_from_a_text_one() {
        let binary = [0u8, 0xFF, 0x10, 0x80, 0u8, 1, 2, 3, 4, 5, 6, 7, 8];
        let report = text_of(ParasolidXt.extract(&xt_file(&binary), "b.x_b").unwrap());
        assert!(report.contains("binary (XT binary transmit)"), "{report}");
    }

    /// A file that opens with the XT marker and then stops is not an XT file
    /// this build can report on. It has to decline, not invent a header.
    #[test]
    #[cfg(feature = "parasolid")]
    fn a_parasolid_header_without_its_end_marker_is_not_claimed() {
        let mut f = xt_file(b"");
        let end = find(&f, XT_END).unwrap_or(0);
        f.truncate(end + 4);
        assert!(ParasolidXt.extract(&f, "cut.x_t").is_err());
        assert!(ParasolidXt.extract(XT_MARKER, "bare.x_t").is_err());
    }

    // -- ACIS SAB ---------------------------------------------------------

    #[test]
    #[cfg(feature = "acis-sab")]
    fn an_acis_sab_reports_its_version_token_and_not_its_entities() {
        let mut sab = b"ACIS 300".to_vec();
        sab.extend_from_slice(&[0x00, 0xFF, 0x10, 0x00]);
        sab.extend_from_slice(&[0u8; 64]);
        let report = text_of(AcisSab.extract(&sab, "part.sab").unwrap());
        assert!(report.contains("ACIS"), "{report}");
        assert!(report.contains("300"), "{report}");
        assert!(report.contains("not decoded"), "{report}");
    }

    #[test]
    #[cfg(feature = "acis-sab")]
    fn a_file_named_sab_without_the_acis_signature_is_not_claimed() {
        assert!(AcisSab
            .extract(b"\x00\x01\x02\x03binary junk", "x.sab")
            .is_err());
        assert!(AcisSab.extract(b"ACI", "x.sab").is_err());
    }

    // -- OLE compound file (Revit) ----------------------------------------

    #[cfg(feature = "rvt")]
    struct Cfb {
        bytes: Vec<u8>,
    }

    #[cfg(feature = "rvt")]
    impl Cfb {
        /// A minimal but well-formed compound file: one FAT sector, one
        /// directory sector and, when a stream claims bytes, the sector
        /// holding them. `dir` is filled with 128-byte entries by the caller.
        fn new(dir: Vec<u8>, stream_bytes: usize) -> Cfb {
            let per_sector = 128usize; // 512-byte sectors, 4-byte FAT entries
            let sectors = 2 + if stream_bytes > 0 { 1 } else { 0 };
            let mut bytes = vec![0u8; HEADER_LEN + sectors * 512];
            let fat: u32 = 0;
            let directory: u32 = 1;
            let stream: u32 = 2;
            // FAT: sector 0 is itself, sector 1 ends the directory chain,
            // sector 2 (when present) holds the stream and ends there.
            let put = |bytes: &mut Vec<u8>, sector: usize, entry: usize, value: u32| {
                let at = HEADER_LEN + sector * 512 + entry * 4;
                bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            };
            for e in 0..per_sector {
                let value = if e == 0 {
                    0xFFFF_FFFD
                } else if e as u32 == directory || e as u32 == stream {
                    ENDOFCHAIN
                } else {
                    FREESECT
                };
                put(&mut bytes, 0, e, value);
            }
            // Header.
            bytes[0..8].copy_from_slice(&CFB_MAGIC);
            bytes[30..32].copy_from_slice(&0xFFFEu16.to_le_bytes());
            bytes[32..34].copy_from_slice(&9u16.to_le_bytes()); // 512-byte sectors
            bytes[34..36].copy_from_slice(&6u16.to_le_bytes());
            bytes[28..30].copy_from_slice(&3u16.to_le_bytes()); // major version
            bytes[44..48].copy_from_slice(&1u32.to_le_bytes()); // FAT sector count
            bytes[48..52].copy_from_slice(&directory.to_le_bytes());
            bytes[56..60].copy_from_slice(&4096u32.to_le_bytes());
            bytes[68..72].copy_from_slice(&ENDOFCHAIN.to_le_bytes()); // DIFAT chain
            bytes[76..80].copy_from_slice(&fat.to_le_bytes());
            for e in 1..109 {
                let at = 76 + e * 4;
                bytes[at..at + 4].copy_from_slice(&FREESECT.to_le_bytes());
            }
            // Directory and stream data.
            let dir_at = HEADER_LEN + directory as usize * 512;
            let n = dir.len().min(512);
            bytes[dir_at..dir_at + n].copy_from_slice(dir.get(..n).unwrap_or(&[]));
            if stream_bytes > 0 {
                let at = HEADER_LEN + stream as usize * 512;
                let take = stream_bytes.min(512);
                bytes[at..at + take].fill(b'A');
            }
            Cfb { bytes }
        }
    }

    #[cfg(feature = "rvt")]
    fn dir_entry_bytes(
        name: &str,
        kind: u8,
        left: u32,
        right: u32,
        child: u32,
        size: u64,
    ) -> Vec<u8> {
        let mut e = vec![0u8; DIR_ENTRY_LEN];
        let mut utf16 = Vec::new();
        for unit in name.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        utf16.extend_from_slice(&[0, 0]); // terminating NUL, counted in the length
        utf16.truncate(64);
        e[0..utf16.len()].copy_from_slice(&utf16);
        e[64..66].copy_from_slice(&(utf16.len() as u16).to_le_bytes());
        e[66] = kind;
        e[68..72].copy_from_slice(&left.to_le_bytes());
        e[72..76].copy_from_slice(&right.to_le_bytes());
        e[76..80].copy_from_slice(&child.to_le_bytes());
        e[120..128].copy_from_slice(&size.to_le_bytes());
        e
    }

    /// The directory entry layout is the whole point of the adapter: Revit's
    /// metadata lives under exactly these names, so a reader that cannot
    /// recover them has recovered nothing. Entry ids are 1-based, so the
    /// root's child is 3 (entry 2) and the sibling link is 4 (entry 3).
    #[test]
    #[cfg(feature = "rvt")]
    fn a_compound_file_reports_the_storages_and_streams_it_holds() {
        let mut dir = Vec::new();
        dir.extend(dir_entry_bytes(
            "Root Entry",
            5,
            NOSTREAM,
            NOSTREAM,
            3,
            4096,
        ));
        dir.extend(dir_entry_bytes("", 0, NOSTREAM, NOSTREAM, NOSTREAM, 0));
        dir.extend(dir_entry_bytes(
            "BasicFileInfo",
            1,
            NOSTREAM,
            4,
            NOSTREAM,
            0,
        ));
        dir.extend(dir_entry_bytes(
            "RevitPreview4.0",
            2,
            NOSTREAM,
            NOSTREAM,
            NOSTREAM,
            512,
        ));
        let cfb = Cfb::new(dir, 512);
        let report = text_of(Rvt.extract(&cfb.bytes, "model.rvt").unwrap());
        assert!(report.contains("storage BasicFileInfo"), "{report}");
        assert!(
            report.contains("stream  RevitPreview4.0  512 bytes"),
            "{report}"
        );
        assert!(report.contains("512-byte sectors"), "{report}");
        assert!(report.contains("not decoded"), "{report}");
        // Both names came out of the sibling tree, not the safety net.
        assert!(!report.contains("not reachable"), "{report}");
    }

    #[test]
    #[cfg(feature = "rvt")]
    fn a_compound_file_name_is_read_from_utf16_and_carries_no_control_bytes() {
        let mut dir = Vec::new();
        dir.extend(dir_entry_bytes("Root Entry", 5, NOSTREAM, NOSTREAM, 3, 0));
        dir.extend(dir_entry_bytes("", 0, NOSTREAM, NOSTREAM, NOSTREAM, 0));
        // A name whose length field claims more bytes than the entry holds:
        // the reader must clip to the 64-byte name field, not run past it.
        let mut broken = dir_entry_bytes("Contents", 2, NOSTREAM, NOSTREAM, NOSTREAM, 8);
        broken[64..66].copy_from_slice(&4096u16.to_le_bytes());
        dir.extend(broken);
        let cfb = Cfb::new(dir, 0);
        let report = text_of(Rvt.extract(&cfb.bytes, "m.rvt").unwrap());
        assert!(report.contains("stream  Contents  8 bytes"), "{report}");
        assert!(!report.contains('\0'), "{report:?}");
    }

    /// A header that points past the end of the file is the common corrupt
    /// case. It must degrade to a report, never to a panic and never to
    /// invented names.
    #[test]
    #[cfg(feature = "rvt")]
    fn a_compound_file_whose_directory_is_past_the_end_degrades_without_panicking() {
        let mut dir = Vec::new();
        dir.extend(dir_entry_bytes("Root Entry", 5, NOSTREAM, NOSTREAM, 2, 0));
        dir.extend(dir_entry_bytes(
            "BasicFileInfo",
            2,
            NOSTREAM,
            NOSTREAM,
            NOSTREAM,
            16,
        ));
        let mut cfb = Cfb::new(dir, 0);
        // Point the directory chain at a sector that is not in the file.
        cfb.bytes[48..52].copy_from_slice(&99u32.to_le_bytes());
        assert!(Rvt.extract(&cfb.bytes, "broken.rvt").is_err());

        // And a file cut off mid-header.
        cfb.bytes.truncate(600);
        assert!(Rvt.extract(&cfb.bytes, "cut.rvt").is_err());
    }

    #[test]
    #[cfg(feature = "rvt")]
    fn a_cyclic_directory_chain_stops_instead_of_spinning() {
        let mut dir = Vec::new();
        dir.extend(dir_entry_bytes("Root Entry", 5, NOSTREAM, NOSTREAM, 2, 0));
        // Entry 2 is its own left sibling: the tree walk must refuse to
        // revisit an entry it has already printed.
        dir.extend(dir_entry_bytes("LoopStream", 2, 2, NOSTREAM, NOSTREAM, 0));
        let mut cfb = Cfb::new(dir, 0);
        // FAT[1] = 1: the directory sector chain is a loop.
        let at = HEADER_LEN + 4;
        cfb.bytes[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        let report = text_of(Rvt.extract(&cfb.bytes, "loop.rvt").unwrap());
        assert!(report.contains("stream  LoopStream"), "{report}");
        // The property is that the walk stops, not that a duplicate entry is
        // spelled a particular way: a chain that follows its own tail grows
        // the report without bound, one that gives up does not.
        assert!(
            report.len() < 4096,
            "a cyclic chain produced a {} byte report",
            report.len()
        );
    }

    #[test]
    #[cfg(feature = "rvt")]
    fn a_file_named_rvt_without_the_compound_file_signature_is_not_claimed() {
        assert!(Rvt
            .extract(b"%PDF-1.7 not a compound file", "x.rvt")
            .is_err());
        assert!(Rvt.extract(&CFB_MAGIC, "head.rvt").is_err());
    }

    // -- DGN --------------------------------------------------------------

    #[cfg(feature = "dgn")]
    fn dgn_tcb() -> Vec<u8> {
        let mut tcb = vec![0u8; DGN_TCB_WORDS as usize * 2 + 4];
        tcb[0] = 0x08; // level 8, not complex
        tcb[1] = DGN_TCB_TYPE;
        tcb[2..4].copy_from_slice(&DGN_TCB_WORDS.to_le_bytes());
        tcb[1112..1116].copy_from_slice(&1i32.to_le_bytes()); // subunits/master
        tcb[1116..1120].copy_from_slice(&1000i32.to_le_bytes()); // uor/subunit
        tcb[1120..1122].copy_from_slice(b"FT");
        tcb[1122..1124].copy_from_slice(b"SU");
        tcb[1214] = 0x40; // 3D
        tcb
    }

    #[cfg(feature = "dgn")]
    fn dgn_element(ty: u8, level: u8, words: u16) -> Vec<u8> {
        let mut e = vec![0u8; words as usize * 2 + 4];
        e[0] = level & 0x3F;
        e[1] = ty;
        e[2..4].copy_from_slice(&words.to_le_bytes());
        e
    }

    #[test]
    #[cfg(feature = "dgn")]
    fn a_dgn_reports_its_units_and_an_element_histogram() {
        let mut f = dgn_tcb();
        f.extend(dgn_element(3, 1, 20)); // LINE
        f.extend(dgn_element(3, 2, 20)); // LINE
        f.extend(dgn_element(17, 2, 16)); // TEXT
        f.extend([0xFF, 0xFF, 0, 0]); // end-of-file marker
        let report = text_of(Dgn.extract(&f, "site.dgn").unwrap());
        assert!(report.contains("3D"), "{report}");
        assert!(report.contains("FT"), "{report}");
        assert!(report.contains("SU"), "{report}");
        assert!(report.contains("1000 uor/subunit"), "{report}");
        assert!(report.contains("LINE"), "{report}");
        assert!(report.contains("TEXT"), "{report}");
        assert!(report.contains("elements:      3"), "{report}");
    }

    /// A 2D drawing and a 3D one share every byte above the dimension flag.
    /// Getting the flag wrong would call every model a 2D plan.
    #[test]
    #[cfg(feature = "dgn")]
    fn a_dgn_without_the_dimension_flag_is_two_dimensional() {
        let mut f = dgn_tcb();
        f[1214] = 0;
        let report = text_of(Dgn.extract(&f, "flat.dgn").unwrap());
        assert!(report.contains("2D"), "{report}");
    }

    /// A TCB cut short still identifies the file and its version. Refusing
    /// it would throw away the one answer we do have.
    #[test]
    #[cfg(feature = "dgn")]
    fn a_dgn_with_a_truncated_tcb_still_names_its_version() {
        let f = dgn_tcb()[..600].to_vec();
        let report = text_of(Dgn.extract(&f, "cut.dgn").unwrap());
        assert!(report.contains("MicroStation design file v8"), "{report}");
        assert!(!report.contains("master units"), "{report}");
    }

    #[test]
    #[cfg(feature = "dgn")]
    fn an_element_running_past_the_end_of_the_file_ends_the_scan_without_panicking() {
        let mut f = dgn_tcb();
        // The element header claims 4000 words; only 100 bytes of it are
        // there. A whole element would fit exactly and the scan would end at
        // end-of-file instead, which is a different case.
        let whole = dgn_element(3, 1, 4000);
        f.extend(whole.get(..100).unwrap_or(&[]).to_vec());
        let report = text_of(Dgn.extract(&f, "short.dgn").unwrap());
        assert!(report.contains("elements:      0"), "{report}");
        assert!(report.contains("past the end"), "{report}");
    }

    #[test]
    #[cfg(feature = "dgn")]
    fn a_file_named_dgn_that_is_not_a_v8_design_file_is_not_claimed() {
        assert!(Dgn.extract(b"not a design file at all", "x.dgn").is_err());
        // Right element header, wrong element type.
        let mut f = dgn_element(3, 1, 20);
        f.extend_from_slice(&[0u8; 2048]);
        assert!(Dgn.extract(&f, "x.dgn").is_err());
    }

    // -- the whole file through the fuzzer -------------------------------

    #[cfg(all(
        feature = "acis-sab",
        feature = "dgn",
        feature = "dwg",
        feature = "parasolid",
        feature = "rvt"
    ))]
    mod fuzz {
        use super::*;
        use rgx_core::fuzzkit::assert_never_panics;

        #[test]
        #[cfg(all(
            feature = "acis-sab",
            feature = "dgn",
            feature = "dwg",
            feature = "parasolid",
            feature = "rvt"
        ))]
        fn cad_adapters_never_panic_on_arbitrary_bytes() {
            let mut corpus: Vec<(&str, Vec<u8>)> = vec![
                ("dwg", b"AC1032".to_vec()),
                ("xt", xt_file(b"body")),
                ("sab", b"ACIS 300\x00\xff".to_vec()),
                (
                    "cfb",
                    Cfb::new(
                        dir_entry_bytes("Root Entry", 5, NOSTREAM, NOSTREAM, NOSTREAM, 0),
                        0,
                    )
                    .bytes,
                ),
                ("dgn", dgn_tcb()),
                ("empty", Vec::new()),
            ];
            corpus.push(("truncated-cfb", {
                let mut f = Cfb::new(dir_entry_bytes("Root Entry", 5, 0, 0, 0, 0), 0).bytes;
                f.truncate(700);
                f
            }));
            corpus.push(("truncated-dgn", dgn_tcb()[..500].to_vec()));

            assert_never_panics(corpus, 2000, "cad", |data| {
                let _ = Dwg.extract(data, "f.dwg");
                let _ = ParasolidXt.extract(data, "f.x_t");
                let _ = AcisSab.extract(data, "f.sab");
                let _ = Rvt.extract(data, "f.rvt");
                let _ = Dgn.extract(data, "f.dgn");
            });
        }
    }
}
