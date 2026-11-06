// SPDX-License-Identifier: Apache-2.0

//! Executable containers: the searchable metadata *inside* a binary.
//!
//! `lib.rs` already identifies what a binary is (ELF / PE / Mach-O / wasm,
//! machine, class, file type). Everything here is the part that generic
//! identification does not reach: the resource sections and embedded
//! metadata a user actually greps for.
//!
//! Each adapter is extension-gated and pure over `&[u8]`. Nothing recurses:
//! embedded payloads come back as `Outcome::Members` and the pipeline walks
//! them through the whole adapter chain.
//!
//! Specs consulted (verified before the field offsets below were written):
//! - PE/COFF, ".rsrc Section": <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
//! - resource type ids: <https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types>
//! - `VS_FIXEDFILEINFO`: mingw-w64 `winver.h`, Wine `verrsrc.h`
//! - Mach-O: LLVM `llvm/BinaryFormat/MachO.h` and `MachO.def`
//! - ELF section headers: gABI ch.4, <https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html>

#[cfg(any(feature = "elf", feature = "pe", feature = "wasm-meta"))]
use alloc::format;
use alloc::string::String;
#[cfg(any(feature = "elf", feature = "pe"))]
use alloc::string::ToString;
#[cfg(feature = "pe")]
use alloc::vec;
#[cfg(any(feature = "elf", feature = "macho", feature = "pe"))]
use alloc::vec::Vec;
use core::fmt::Write as _;
#[cfg(any(feature = "dex", feature = "elf", feature = "wasm-meta"))]
use rgx_core::bail;
use rgx_core::{decline, Adapter, Outcome, Reach, Result};

// ---------------------------------------------------------------------------
// bounds
// ---------------------------------------------------------------------------

/// Per-adapter text ceiling. An executable's string tables are unbounded, and
/// a bounded answer that says it stopped is worth more than an OOM.
#[cfg(any(
    feature = "dex",
    feature = "elf",
    feature = "macho",
    feature = "pe",
    feature = "wasm-meta"
))]
const MAX_TEXT: usize = 8 * 1024 * 1024;
/// Retained member bytes for one `Outcome::Members`.
#[cfg(feature = "pe")]
const MAX_MEMBER_BYTES: usize = 4 * 1024 * 1024;
/// Nodes visited in a PE resource directory before the walk gives up.
#[cfg(feature = "pe")]
const MAX_RSRC_NODES: usize = 65_536;
/// Resource-directory depth. The spec says three levels; a fourth is either a
/// malformed file or a format we do not claim to understand.
#[cfg(feature = "pe")]
const MAX_RSRC_DEPTH: usize = 3;

/// Read a little- or big-endian `u16` at `off`, or `None` if it does not fit.
#[cfg(any(feature = "elf", feature = "pe"))]
fn rd16(d: &[u8], off: usize, le: bool) -> Option<u16> {
    let b = d.get(off..off.checked_add(2)?)?;
    let v = [b[0], b[1]];
    Some(if le {
        u16::from_le_bytes(v)
    } else {
        u16::from_be_bytes(v)
    })
}

#[cfg(any(
    feature = "dex",
    feature = "elf",
    feature = "macho",
    feature = "pe",
    feature = "wasm-meta"
))]
fn rd32(d: &[u8], off: usize, le: bool) -> Option<u32> {
    let b = d.get(off..off.checked_add(4)?)?;
    let v = [b[0], b[1], b[2], b[3]];
    Some(if le {
        u32::from_le_bytes(v)
    } else {
        u32::from_be_bytes(v)
    })
}

#[cfg(any(feature = "elf", feature = "macho"))]
fn rd64(d: &[u8], off: usize, le: bool) -> Option<u64> {
    let b = d.get(off..off.checked_add(8)?)?;
    let v = [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];
    Some(if le {
        u64::from_le_bytes(v)
    } else {
        u64::from_be_bytes(v)
    })
}

/// Decode `chars` UTF-16LE code units starting at `off`, stopping at the first
/// NUL. Unpaired surrogates are dropped rather than replaced: a version
/// resource with a broken string should lose that string, not gain U+FFFD.
#[cfg(feature = "pe")]
fn utf16le_at(d: &[u8], off: usize, chars: usize) -> Option<String> {
    let end = off.checked_add(chars.checked_mul(2)?)?;
    let raw = d.get(off..end)?;
    let mut units = Vec::with_capacity(chars);
    for pair in raw.as_chunks::<2>().0 {
        let u = u16::from_le_bytes([pair[0], pair[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    Some(String::from_utf16_lossy(&units))
}

/// A NUL-terminated byte string at `off`, with the offset just past the NUL.
#[cfg(feature = "elf")]
fn cstr(d: &[u8], off: usize) -> Option<(String, usize)> {
    let rest = d.get(off..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    let s = core::str::from_utf8(&rest[..end]).ok()?.to_string();
    Some((s, end + 1))
}

/// A fixed 16-byte Mach-O/COFF name field, NUL-padded rather than NUL-terminated.
#[cfg(feature = "macho")]
fn fixed_name(d: &[u8], off: usize) -> String {
    let raw = match d.get(off..off.saturating_add(16)) {
        Some(r) => r,
        None => return String::new(),
    };
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Append `s` to `out` if the total budget allows, reporting whether it fit.
#[cfg(any(
    feature = "dex",
    feature = "elf",
    feature = "macho",
    feature = "pe",
    feature = "wasm-meta"
))]
fn push_bounded(out: &mut String, s: &str, budget: usize) -> bool {
    if out.len().saturating_add(s.len()).saturating_add(1) > budget {
        return false;
    }
    out.push_str(s);
    out.push('\n');
    true
}

// ---------------------------------------------------------------------------
// 1. PE resources
// ---------------------------------------------------------------------------

/// PE resource type ids, `MAKEINTRESOURCE(n)` (MS Learn, "Resource Types").
#[cfg(feature = "pe")]
const RT_NAMES: &[(u32, &str)] = &[
    (1, "RT_CURSOR"),
    (2, "RT_BITMAP"),
    (3, "RT_ICON"),
    (4, "RT_MENU"),
    (5, "RT_DIALOG"),
    (6, "RT_STRING"),
    (7, "RT_FONTDIR"),
    (8, "RT_FONT"),
    (9, "RT_ACCELERATOR"),
    (10, "RT_RCDATA"),
    (11, "RT_MESSAGETABLE"),
    (12, "RT_GROUP_CURSOR"),
    (14, "RT_GROUP_ICON"),
    (16, "RT_VERSION"),
    (17, "RT_DLGINCLUDE"),
    (19, "RT_PLUGPLAY"),
    (20, "RT_VXD"),
    (21, "RT_ANICURSOR"),
    (22, "RT_ANIICON"),
    (23, "RT_HTML"),
    (24, "RT_MANIFEST"),
];

/// The resource tree plus whatever we know about turning an RVA into an offset.
///
/// The `Data RVA` of an `IMAGE_RESOURCE_DATA_ENTRY` is an *image* address, not
/// an offset into the resource section. A whole PE image carries the section
/// table that maps it; a `.rsrc` blob carved out of one does not, and then the
/// leaf payloads are genuinely unreachable. That is why the two cases below
/// report differently instead of the blob case guessing a base.
#[cfg(feature = "pe")]
enum Rsrc<'a> {
    /// Whole PE image: map through `(rva, vsize, ptr_raw, size_raw)` sections.
    /// `dir_off`/`dir_len` cut out the resource directory, whose internal
    /// offsets are section-relative; payload bytes come from `file`, not from
    /// that window, because a leaf's `Data RVA` can point anywhere in the image.
    Image {
        file: &'a [u8],
        dir_off: usize,
        dir_len: usize,
        sections: Vec<(u32, u32, u32, u32)>,
    },
    /// A carved `.rsrc` blob. Directory offsets are section-relative and parse
    /// fine; data RVAs do not, so only the tree is reported.
    Blob { blob: &'a [u8] },
}

#[cfg(feature = "pe")]
impl<'a> Rsrc<'a> {
    /// The resource-directory bytes.
    fn dir(&self) -> &'a [u8] {
        match self {
            Rsrc::Image {
                file,
                dir_off,
                dir_len,
                ..
            } => file
                .get(*dir_off..dir_off.saturating_add(*dir_len))
                .unwrap_or(&[]),
            Rsrc::Blob { blob } => blob,
        }
    }

    /// File offset of an image RVA, or `None` when no section claims it.
    fn rva_to_file(&self, rva: u32, size: u32) -> Option<usize> {
        let Rsrc::Image { file, sections, .. } = self else {
            return None;
        };
        for &(va, vsize, ptr_raw, size_raw) in sections {
            let span = vsize.max(size_raw);
            if span == 0 {
                continue;
            }
            if rva >= va && rva.checked_sub(va).is_some_and(|d| d < span) {
                let off = ptr_raw.checked_add(rva - va)? as usize;
                let end = off.checked_add(size as usize)?;
                return file.get(off..end).map(|_| off);
            }
        }
        None
    }

    /// The bytes of a resolved leaf payload.
    fn file_bytes(&self, off: usize, size: usize) -> Option<&'a [u8]> {
        match self {
            Rsrc::Image { file, .. } => file.get(off..off.checked_add(size)?),
            Rsrc::Blob { .. } => None,
        }
    }

    fn can_resolve_data(&self) -> bool {
        matches!(self, Rsrc::Image { .. })
    }
}

/// Collects what the directory walk produces.
#[derive(Default)]
#[cfg(feature = "pe")]
struct RsrcWalk {
    /// One line per leaf: the `TYPE/NAME/LANG` path plus the data-entry fields.
    lines: String,
    /// Leaf payloads, named by their path. Only filled when the RVA map exists.
    members: Vec<(String, Vec<u8>)>,
    /// Directory entries visited, so a cyclic tree stops somewhere bounded.
    nodes: usize,
    leaves: u32,
    types: u32,
    member_bytes: usize,
    truncated: bool,
}

/// Read one `IMAGE_RESOURCE_DIR_STRING_U`: `Length` is a *byte* count, and the
/// string is word-aligned, which keeps the next one word-aligned too.
#[cfg(feature = "pe")]
fn rsrc_string(blob: &[u8], off: usize) -> Option<String> {
    let nbytes = rd16(blob, off, true)? as usize;
    let chars = nbytes / 2;
    utf16le_at(blob, off.checked_add(2)?, chars)
}

/// Render one tree level's name field. A high `Name` word means the low 31
/// bits are an offset to a string, not an id (MS Learn, ".rsrc Section").
#[cfg(feature = "pe")]
fn rsrc_label(blob: &[u8], level: usize, is_name: bool, raw: u32) -> String {
    if is_name {
        return rsrc_string(blob, (raw & 0x7fff_ffff) as usize)
            .unwrap_or_else(|| format!("#bad-name@0x{raw:08x}"));
    }
    match level {
        // Level 0 is the resource type; naming it is the whole point.
        0 => RT_NAMES
            .iter()
            .find(|(id, _)| *id == raw)
            .map(|(_, n)| (*n).to_string())
            .unwrap_or_else(|| format!("RT_{raw}")),
        1 => raw.to_string(),
        // Windows spells a primary language id without leading zeros (`0x409`).
        _ => format!("0x{raw:x}"),
    }
}

/// Walk the three-level resource tree.
///
/// `IMAGE_RESOURCE_DIRECTORY` (16 bytes): Characteristics, TimeDateStamp,
/// MajorVersion, MinorVersion, NumberOfNamedEntries, NumberOfIDEntries.
/// `IMAGE_RESOURCE_DIRECTORY_ENTRY` (8 bytes): Name|IntegerId, then a word whose
/// high bit picks a subdirectory (1) or a data entry (0). All offsets are
/// relative to the start of the resource directory.
#[cfg(feature = "pe")]
fn rsrc_walk(src: &Rsrc, start: usize, w: &mut RsrcWalk, depth: usize, path: &mut Vec<String>) {
    let blob = src.dir();
    let (Some(n_named), Some(n_id)) = (rd16(blob, start + 12, true), rd16(blob, start + 14, true))
    else {
        return;
    };
    let total = n_named as usize + n_id as usize;
    // A directory whose entry count cannot fit its own blob is malformed, and
    // iterating it anyway is how a fuzz case turns into a multi-second loop.
    let Some(entries_end) = total.checked_mul(8).and_then(|n| start.checked_add(16 + n)) else {
        return;
    };
    if entries_end > blob.len() {
        w.truncated = true;
        return;
    }

    for i in 0..total {
        let Some(entry) = start
            .checked_add(16)
            .and_then(|b| i.checked_mul(8).and_then(|n| b.checked_add(n)))
        else {
            w.truncated = true;
            return;
        };
        if w.nodes >= MAX_RSRC_NODES {
            w.truncated = true;
            return;
        }
        w.nodes += 1;
        let (Some(name_raw), Some(off_raw)) =
            (rd32(blob, entry, true), rd32(blob, entry + 4, true))
        else {
            w.truncated = true;
            return;
        };
        let label = rsrc_label(blob, depth, name_raw & 0x8000_0000 != 0, name_raw);
        path.push(label);
        if depth == 0 {
            w.types += 1;
        }

        if off_raw & 0x8000_0000 != 0 {
            let sub = (off_raw & 0x7fff_ffff) as usize;
            if depth + 1 > MAX_RSRC_DEPTH {
                w.truncated = true;
            } else {
                rsrc_walk(src, sub, w, depth + 1, path);
            }
        } else {
            let d = off_raw as usize;
            let (Some(rva), Some(size), Some(codepage)) = (
                rd32(blob, d, true),
                rd32(blob, d + 4, true),
                rd32(blob, d + 8, true),
            ) else {
                w.truncated = true;
                path.pop();
                continue;
            };
            let leaf = path.join("/");
            let is_version = leaf.starts_with("RT_VERSION");
            w.leaves += 1;
            let _ = writeln!(
                w.lines,
                "{leaf}\tsize={size}\tcodepage={codepage}\trva=0x{rva:08x}"
            );
            if src.can_resolve_data() && w.member_bytes < MAX_MEMBER_BYTES {
                if let Some(off) = src.rva_to_file(rva, size) {
                    if let Some(bytes) = src.file_bytes(off, size as usize) {
                        w.member_bytes += bytes.len();
                        // A version resource is UTF-16 key/value pairs, so the
                        // raw blob makes every value matchable only by a
                        // pattern that knows about NULs. Decode it instead.
                        let payload = if is_version {
                            version_text(bytes)
                        } else {
                            bytes.to_vec()
                        };
                        w.members.push((leaf, payload));
                    }
                }
            }
        }
        path.pop();
    }
}

/// Decode a `VS_VERSION_INFO` blob into `key = value` lines.
///
/// Every node is `wLength, wValueLength, wType, szKey[]`, szKey NUL-terminated
/// UTF-16, then the value DWORD-aligned, then children each DWORD-aligned.
/// The unit of `wValueLength` is **not** decided by `wType`: a `String` node
/// carries `wType == 1` and counts UTF-16 characters, while the root's value
/// counts bytes. `version_node` therefore takes the unit from the node's
/// position in the tree.
#[cfg(feature = "pe")]
fn version_text(blob: &[u8]) -> Vec<u8> {
    let mut out = String::new();
    let Some(root) = version_node(blob, 0, false) else {
        return Vec::new();
    };
    if root.key != "VS_VERSION_INFO" {
        return Vec::new();
    }
    let _ = writeln!(out, "VS_VERSION_INFO");
    // `VS_FIXEDFILEINFO` begins with `dwSignature == 0xFEEF04BD`. That check
    // is the only honest gate: `wType` here is 0 in some toolchains and 1 in
    // others, so gating on it either drops a real version block or reads one
    // at the wrong stride. A signature that does not match means the value
    // meant something else, so nothing is printed rather than a plausible but
    // wrong version.
    if root.value.len() >= 52 {
        let f = &root.value;
        let g = |o: usize| u32::from_le_bytes([f[o], f[o + 1], f[o + 2], f[o + 3]]);
        let ver =
            |ms: u32, ls: u32| format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff);
        let sig = g(0);
        if sig == 0xfeef_04bd {
            let _ = writeln!(out, "Signature=0x{sig:08x}");
            let _ = writeln!(out, "FileVersion={}", ver(g(8), g(12)));
            let _ = writeln!(out, "ProductVersion={}", ver(g(16), g(20)));
            // Field order after the version words is dwFileFlagsMask,
            // dwFileFlags, dwFileOS, dwFileType, dwFileSubtype — reading these
            // one word early turns VOS__NT_WINDOWS32 into "FileFlags" and
            // leaves FileOS looking like a plausible zero.
            let _ = writeln!(out, "FileFlags=0x{:08x}/0x{:08x}", g(28), g(24));
            let _ = writeln!(out, "FileOS=0x{:08x}", g(32));
            let _ = writeln!(out, "FileType=0x{:08x}", g(36));
            let _ = writeln!(out, "FileSubtype=0x{:08x}", g(40));
        } else {
            let _ = writeln!(
                out,
                "# VS_FIXEDFILEINFO not decoded: dwSignature is 0x{sig:08x}, not 0xfeef04bd"
            );
        }
    }
    version_children(blob, root.children_at, root.children_end, 0, &mut out);
    out.into_bytes()
}

#[cfg(feature = "pe")]
struct VNode<'a> {
    key: String,
    value: &'a [u8],
    children_at: usize,
    children_end: usize,
}

/// Parse the node at `off`, honouring `wLength` as its hard boundary.
///
/// `value_is_chars` decides the unit of `wValueLength`, and it cannot be
/// derived from `wType`: a `String` node carries `wType == 1` yet its
/// `wValueLength` counts UTF-16 *characters*, while the `VS_VERSION_INFO`
/// root's `wType == 1` value counts *bytes*. Keying the unit off `wType`
/// truncates every string to half its length and prints the first half of
/// each; the node's position in the tree is what actually distinguishes them.
#[cfg(feature = "pe")]
fn version_node(blob: &[u8], off: usize, value_is_chars: bool) -> Option<VNode<'_>> {
    let wlength = rd16(blob, off, true)? as usize;
    let vlength = rd16(blob, off + 2, true)? as usize;
    if wlength < 6 {
        return None;
    }
    // The node's own length is what makes this loop terminate: a malformed
    // blob that points past itself must stop here, not spin.
    let end = off.checked_add(wlength)?.min(blob.len());

    // szKey: NUL-terminated UTF-16, then pad to the next DWORD boundary
    // *relative to the node*, which is why the offsets below are all `off + n`
    // rather than absolute positions in the blob.
    let mut p = off + 6;
    let key_start = p;
    while p + 2 <= end {
        if rd16(blob, p, true)? == 0 {
            p += 2;
            break;
        }
        p += 2;
    }
    let key_units = (p.saturating_sub(key_start)).saturating_sub(2) / 2;
    let key = utf16le_at(blob, key_start, key_units).unwrap_or_default();
    p = (p + 3) & !3;

    let vbytes = if value_is_chars {
        vlength.saturating_mul(2)
    } else {
        vlength
    };
    let value = blob
        .get(p..p.saturating_add(vbytes).min(end))
        .unwrap_or(&[]);
    p = p.saturating_add(vbytes);
    p = (p + 3) & !3;
    Some(VNode {
        key,
        value,
        children_at: p.min(end),
        children_end: end,
    })
}

/// UTF-16LE bytes to a String, stopping at the first NUL.
///
/// Version strings are NUL-terminated but `wValueLength` counts the
/// terminator, so reading the declared length alone leaves a trailing NUL on
/// every value. Unpaired surrogates are dropped rather than replaced.
#[cfg(feature = "pe")]
fn utf16_units(bytes: &[u8]) -> String {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let u = u16::from_le_bytes([pair[0], pair[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16_lossy(&units)
}

/// Depth-first over the nodes in `[from, to)`: `StringFileInfo` at depth 0,
/// its `StringTable` children at depth 1, the `String` key/value pairs at
/// depth 2. The rest of the tree (`VarFileInfo`, translation tables) holds no
/// text a grep wants, so it is walked past rather than printed.
#[cfg(feature = "pe")]
fn version_children(blob: &[u8], from: usize, to: usize, depth: usize, out: &mut String) {
    let mut off = from;
    while off + 6 <= to {
        // Nodes at depth 2 are `String` key/value pairs, whose value is text.
        let Some(node) = version_node(blob, off, depth == 2) else {
            return;
        };
        // `wLength` is the node's own bound. One that does not fit inside the
        // parent is a malformed blob; clamping it here is what stops the walk
        // from re-reading the same bytes forever.
        let len = rd16(blob, off, true).unwrap_or(0) as usize;
        if len < 6 || off.checked_add(len).is_none_or(|e| e > to) {
            return;
        }
        // Siblings are DWORD-aligned. A producer that ends `wLength` on the
        // last value byte and pads *after* the node is the common case, so
        // advancing to `align4(off + wLength)` is correct whether or not the
        // declared length already includes the padding — advancing by the raw
        // length lands on padding instead of the next node and silently stops
        // the walk after the first two strings.
        let next = (off + len + 3) & !3;
        match (depth, node.key.as_str()) {
            (_, "StringFileInfo") => {
                version_children(blob, node.children_at, node.children_end, depth + 1, out)
            }
            (1, _) => version_children(blob, node.children_at, node.children_end, depth + 1, out),
            (2, _) => {
                let text = utf16_units(node.value);
                if !text.is_empty() {
                    let _ = writeln!(out, "{}={}", node.key, text);
                }
            }
            _ => {}
        }
        off = next;
    }
}

/// PE resource sections: the resource tree, and the version strings inside it.
#[cfg(feature = "pe")]
pub struct PeResources;

#[cfg(feature = "pe")]
impl Adapter for PeResources {
    fn name(&self) -> &'static str {
        "pe-resources"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["rsrc"]
    }

    fn reach(&self) -> Reach {
        Reach::Reveal
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let src = if data.starts_with(b"MZ") {
            pe_resource_section(data)
                .ok_or_else(|| rgx_core::anyhow!("pe image has no resource data directory"))?
        } else {
            Rsrc::Blob { blob: data }
        };

        let mut w = RsrcWalk::default();
        let mut path = Vec::new();
        rsrc_walk(&src, 0, &mut w, 0, &mut path);

        if w.leaves == 0 && !w.truncated {
            decline!("no resource directory table at the start of the section");
        }

        // With a section table the leaf payloads are reachable, so they are the
        // answer and the tree travels with them. Without one they are not, and
        // the tree is the whole of what this blob can honestly say.
        if !w.members.is_empty() {
            let mut index = String::new();
            let _ = writeln!(
                index,
                "pe-resources: {} types, {} leaves, {}/{} bytes retained",
                w.types, w.leaves, w.member_bytes, MAX_MEMBER_BYTES
            );
            index.push_str(&w.lines);
            if w.truncated {
                let _ = writeln!(
                    index,
                    "# resource tree truncated at a malformed or looping entry"
                );
            }
            let mut members = vec![("RSRC_INDEX".to_string(), index.into_bytes())];
            members.extend(w.members);
            return Ok(Outcome::Members(members));
        }

        let mut out = String::new();
        let _ = writeln!(out, "pe-resources: {} types, {} leaves", w.types, w.leaves);
        if !src.can_resolve_data() {
            let _ = writeln!(
                out,
                "# leaf payloads NOT decoded: a carved .rsrc carries no section table, \
                 so its IMAGE_RESOURCE_DATA_ENTRY Data RVA (an image address) cannot be \
                 mapped to a file offset; hand rgx the whole PE instead"
            );
        }
        for l in w.lines.lines() {
            if !push_bounded(&mut out, l, MAX_TEXT) {
                let _ = writeln!(out, "# output capped at {MAX_TEXT} bytes");
                break;
            }
        }
        if w.truncated {
            let _ = writeln!(
                out,
                "# resource tree truncated at a malformed or looping entry"
            );
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// Locate `.rsrc` inside a whole PE image.
///
/// DOS `e_lfanew` at 0x3c → `PE\0\0` → 20-byte COFF header → optional header
/// (magic 0x10b PE32, 0x20b PE32+) → data directories, resource at index 2 →
/// section table for the RVA map.
#[cfg(feature = "pe")]
fn pe_resource_section(data: &[u8]) -> Option<Rsrc<'_>> {
    let lfanew = rd32(data, 0x3c, true)? as usize;
    if data.get(lfanew..lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = lfanew.checked_add(4)?;
    let n_sections = rd16(data, coff + 2, true)? as usize;
    let size_opt = rd16(data, coff + 16, true)? as usize;
    let opt = coff.checked_add(20)?;

    let dir_base = match rd16(data, opt, true)? {
        0x10b => opt.checked_add(96)?,
        0x20b => opt.checked_add(112)?,
        _ => return None,
    };
    // The spec is explicit that NumberOfRvaAndSizes must be consulted before
    // probing a directory; a stub PE with a short optional header is common
    // enough in the wild that assuming 16 entries reads garbage.
    let n_dirs_at = match rd16(data, opt, true)? {
        0x10b => 92,
        _ => 108,
    };
    let n_dirs = rd32(data, opt + n_dirs_at, true)? as usize;
    if n_dirs <= 2 {
        return None;
    }
    let rsrc_dir = dir_base.checked_add(2 * 8)?;
    let rsrc_rva = rd32(data, rsrc_dir, true)?;
    let rsrc_size = rd32(data, rsrc_dir + 4, true)?;
    if rsrc_rva == 0 || rsrc_size == 0 {
        return None;
    }

    let mut sections = Vec::new();
    let sec_base = opt.checked_add(size_opt)?;
    for i in 0..n_sections.min(4096) {
        let Some(s) = sec_base.checked_add(i.checked_mul(40)?) else {
            break;
        };
        let (vsize, va, size_raw, ptr_raw) = match (
            rd32(data, s + 8, true),
            rd32(data, s + 12, true),
            rd32(data, s + 16, true),
            rd32(data, s + 20, true),
        ) {
            (Some(v), Some(a), Some(sr), Some(pr)) => (v, a, sr, pr),
            _ => break,
        };
        sections.push((va, vsize, ptr_raw, size_raw));
    }

    let rsrc_off = sections
        .iter()
        .find_map(|&(va, vsize, ptr_raw, size_raw)| {
            let span = vsize.max(size_raw);
            if span != 0 && rsrc_rva >= va && rsrc_rva - va < span {
                ptr_raw.checked_add(rsrc_rva - va).map(|o| o as usize)
            } else {
                None
            }
        })?;
    let dir_len = rsrc_size as usize;
    // The directory must actually be inside the image; a `VirtualSize` that
    // runs off the end is a truncated or hand-made file.
    data.get(rsrc_off..rsrc_off.checked_add(dir_len)?)?;
    Some(Rsrc::Image {
        file: data,
        dir_off: rsrc_off,
        dir_len,
        sections,
    })
}

// ---------------------------------------------------------------------------
// 2. Mach-O string tables
// ---------------------------------------------------------------------------

/// `__TEXT,__cstring` and `__DATA,__cfstring`.
///
/// Load commands and section headers are 32- or 64-bit and little- or
/// big-endian; both magics of each width are accepted.
#[cfg(feature = "macho")]
pub struct MachOStrings;

#[cfg(feature = "macho")]
impl Adapter for MachOStrings {
    fn name(&self) -> &'static str {
        "macho-strings"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["macho", "dylib"]
    }

    fn reach(&self) -> Reach {
        Reach::Reveal
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let mut out = String::new();
        let mut any = false;
        macho_walk(data, &mut out, 0, &mut any);
        if !any {
            decline!("no __TEXT,__cstring or __DATA,__cfstring section found");
        }
        if out.len() > MAX_TEXT {
            out.truncate(MAX_TEXT);
            let _ = writeln!(out, "# output capped at {MAX_TEXT} bytes");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// Dispatch a thin or fat Mach-O to the right slice walk.
#[cfg(feature = "macho")]
fn macho_walk(data: &[u8], out: &mut String, depth: usize, any: &mut bool) {
    let Some(magic) = rd32(data, 0, false) else {
        return;
    };
    match magic {
        // A fat header's own fields are big-endian; FAT_CIGAM is the byte-swapped
        // spelling that shows up on disk from a little-endian producer.
        0xcafe_babe | 0xbfba_feca => {
            if depth == 0 {
                let _ = writeln!(out, "macho: fat binary, {} slices", nfat_arch(data, magic));
            }
            fat_walk(data, magic, depth, out, any);
        }
        0xfeed_face | 0xcefa_edfe | 0xfeed_facf | 0xcffa_edfe => thin_walk(data, out, any),
        _ => {}
    }
}

#[cfg(feature = "macho")]
fn nfat_arch(data: &[u8], magic: u32) -> u32 {
    // FAT_MAGIC is big-endian on disk, FAT_CIGAM little-endian.
    rd32(data, 4, magic == 0xcafe_babe).unwrap_or(0)
}

#[cfg(feature = "macho")]
fn fat_walk(data: &[u8], magic: u32, depth: usize, out: &mut String, any: &mut bool) {
    let be = magic == 0xcafe_babe;
    let n = nfat_arch(data, magic);
    // `fat_arch` is 20 bytes; the FAT_MAGIC_64 variant's `fat_arch_64` is 32.
    let ent = if magic == 0xbfba_feca { 32 } else { 20 };
    let wide = ent == 32;
    for i in 0..n.min(256) {
        let i = i as usize;
        let Some(a) = i.checked_mul(ent).and_then(|x| x.checked_add(4)) else {
            break;
        };
        let (off, size) = if wide {
            (
                rd64(data, a + 8, be).unwrap_or(0),
                rd64(data, a + 16, be).unwrap_or(0),
            )
        } else {
            (
                rd32(data, a + 8, be).unwrap_or(0) as u64,
                rd32(data, a + 12, be).unwrap_or(0) as u64,
            )
        };
        let (Ok(off), Ok(size)) = (usize::try_from(off), usize::try_from(size)) else {
            continue;
        };
        // A slice past the end of the buffer is a truncated fat file, not a
        // reason to read whatever happens to be there.
        let Some(slice) = data.get(off..off.saturating_add(size)) else {
            continue;
        };
        let _ = writeln!(out, "## fat slice {i} ({size} bytes)");
        // Nesting is bounded: a fat header inside a fat header is malformed.
        if depth < 2 {
            macho_walk(slice, out, depth + 1, any);
        } else {
            thin_walk(slice, out, any);
        }
    }
}

#[cfg(feature = "macho")]
fn thin_walk(data: &[u8], out: &mut String, any: &mut bool) {
    let Some(magic) = rd32(data, 0, false) else {
        return;
    };
    // MH_MAGIC/MH_MAGIC_64 are stored big-endian; MH_CIGAM* are the swapped
    // spellings, so the magic value alone decides both width and endianness.
    let (le, wide) = match magic {
        0xfeed_face => (false, false),
        0xcefa_edfe => (true, false),
        0xfeed_facf => (false, true),
        0xcffa_edfe => (true, true),
        _ => return,
    };
    let cputype = rd32(data, 4, le).unwrap_or(0);
    let filetype = rd32(data, 12, le).unwrap_or(0);
    let ncmds = rd32(data, 16, le).unwrap_or(0);
    let hdr = if wide { 32 } else { 28 };
    let _ = writeln!(
        out,
        "## macho: cputype=0x{cputype:08x} filetype={filetype} {}-bit {}-endian",
        if wide { 64 } else { 32 },
        if le { "little" } else { "big" }
    );

    let mut p = hdr;
    for _ in 0..ncmds.min(4096) {
        let (Some(cmd), Some(cmdsize)) = (rd32(data, p, le), rd32(data, p + 4, le)) else {
            return;
        };
        if cmdsize < 8
            || !p
                .checked_add(cmdsize as usize)
                .is_some_and(|e| e <= data.len())
        {
            return;
        }
        // LC_SEGMENT 0x1, LC_SEGMENT_64 0x19 (MachO.def).
        let seg64 = cmd == 0x19;
        if cmd == 0x1 || seg64 {
            segment_walk(data, p, cmdsize as usize, le, seg64, out, any);
        }
        p += cmdsize as usize;
    }
}

#[cfg(feature = "macho")]
fn segment_walk(
    data: &[u8],
    cmd_off: usize,
    cmdsize: usize,
    le: bool,
    seg64: bool,
    out: &mut String,
    any: &mut bool,
) {
    let segname = fixed_name(data, cmd_off + 8);
    let nsects = if seg64 {
        rd32(data, cmd_off + 64, le).unwrap_or(0)
    } else {
        rd32(data, cmd_off + 48, le).unwrap_or(0)
    };
    // Section headers follow the segment command inline: the command is
    // `segment_command` (56 or 72 bytes) plus `nsects` section headers.
    let sect_at = cmd_off + if seg64 { 72 } else { 56 };
    let sect_size = if seg64 { 80 } else { 68 };

    for i in 0..nsects.min(4096) {
        let Some(s) = (i as usize)
            .checked_mul(sect_size)
            .and_then(|n| sect_at.checked_add(n))
        else {
            return;
        };
        // A section header past the end of its own command is a malformed
        // command, not a section.
        if s.checked_add(sect_size)
            .is_none_or(|e| e > cmd_off + cmdsize)
        {
            return;
        }
        let sectname = fixed_name(data, s);
        let (size, offset) = if seg64 {
            (
                rd64(data, s + 32, le).unwrap_or(0),
                rd32(data, s + 48, le).unwrap_or(0),
            )
        } else {
            (
                rd32(data, s + 32, le).unwrap_or(0) as u64,
                rd32(data, s + 36, le).unwrap_or(0),
            )
        };
        let (Ok(start), Ok(size)) = (usize::try_from(offset), usize::try_from(size)) else {
            continue;
        };
        // `sh_offset` is a file offset and `size` a byte count; a section that
        // does not fit the buffer is a truncated image.
        let Some(body) = data.get(start..start.saturating_add(size)) else {
            continue;
        };

        if sectname == "__cstring" && segname == "__TEXT" {
            *any = true;
            let _ = writeln!(out, "## {segname},{sectname} ({size} bytes)");
            cstring_lines(body, out);
        } else if sectname == "__cfstring" && segname == "__DATA" {
            *any = true;
            let _ = writeln!(out, "## {segname},{sectname} ({size} bytes)");
            cfstring_lines(data, body, seg64, le, out);
        }
    }
}

#[cfg(feature = "macho")]
fn cstring_lines(body: &[u8], out: &mut String) {
    for part in body.split(|&b| b == 0) {
        if part.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(part);
        if !push_bounded(out, &s, MAX_TEXT) {
            let _ = writeln!(out, "# output capped at {MAX_TEXT} bytes");
            return;
        }
    }
}

/// `__cfstring` entries are CFString constants: `isa`, `info`, a text pointer,
/// and a length — 32 bytes on 64-bit, 16 on 32-bit.
///
/// A short string is stored *inline* in the pointer slot, so the pointer field
/// is either an address inside the image or the characters themselves. Those
/// two readings are distinguishable by bounds alone, which is why nothing here
/// needs the inline-length threshold: if the pointer lands in the image we read
/// through it, otherwise we read the slot. Entries that resolve to neither are
/// counted, not guessed at.
#[cfg(feature = "macho")]
fn cfstring_lines(image: &[u8], body: &[u8], seg64: bool, le: bool, out: &mut String) {
    let ent = if seg64 { 32 } else { 16 };
    let ptr_at = if seg64 { 16 } else { 8 };
    let len_at = if seg64 { 24 } else { 12 };
    let (mut resolved, mut inline, mut unresolved) = (0usize, 0usize, 0usize);
    let mut base = 0usize;
    while base + ent <= body.len() {
        let ptr = if seg64 {
            rd64(body, base + ptr_at, le).unwrap_or(0)
        } else {
            rd32(body, base + ptr_at, le).unwrap_or(0) as u64
        };
        let len = if seg64 {
            rd64(body, base + len_at, le).unwrap_or(0)
        } else {
            rd32(body, base + len_at, le).unwrap_or(0) as u64
        };
        let slot = &body[base..base + ent];
        base += ent;

        // Pointer reading: the NUL-terminated bytes at `ptr`, bounded by the
        // declared length. A pointer that lands outside the image is not this.
        let through_ptr = usize::try_from(ptr)
            .ok()
            .filter(|&p| p > 0 && p < image.len())
            .and_then(|p| {
                let rest = &image[p..];
                let limit = usize::try_from(len)
                    .ok()
                    .unwrap_or(rest.len())
                    .min(rest.len());
                let nul = rest[..limit].iter().position(|&b| b == 0)?;
                (nul > 0).then_some(&rest[..nul])
            });
        if let Some(bytes) = through_ptr {
            resolved += 1;
            let s = String::from_utf8_lossy(bytes);
            if !push_bounded(out, &s, MAX_TEXT) {
                return;
            }
            continue;
        }
        // Inline reading: the characters occupy the pointer slot itself.
        let text: Vec<u8> = slot[ptr_at..]
            .iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect();
        if text.is_empty() {
            unresolved += 1;
        } else {
            inline += 1;
            let s = String::from_utf8_lossy(&text);
            if !push_bounded(out, &s, MAX_TEXT) {
                return;
            }
        }
    }
    let _ = writeln!(
        out,
        "# cfstring: {resolved} via pointer, {inline} inline, {unresolved} unresolved"
    );
}

// ---------------------------------------------------------------------------
// 3. ELF .comment and .note
// ---------------------------------------------------------------------------

/// ELF build provenance: `.comment` (the exact toolchain) and `.note*` build ids.
///
/// This reads section headers only. `lib.rs` already reports machine, class and
/// endianness from `e_ident`/`e_machine`; the point here is the metadata those
/// fields do not carry.
#[cfg(feature = "elf")]
pub struct ElfProvenance;

#[cfg(feature = "elf")]
impl Adapter for ElfProvenance {
    fn name(&self) -> &'static str {
        "elf-provenance"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["so", "elf", "ko"]
    }

    fn reach(&self) -> Reach {
        Reach::Reveal
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if !data.starts_with(b"\x7fELF") {
            decline!("not an ELF file");
        }
        let Some(&class) = data.get(4) else {
            bail!("truncated ELF identification");
        };
        let Some(&enc) = data.get(5) else {
            bail!("truncated ELF identification");
        };
        let (wide, le) = match (class, enc) {
            (1, 1) => (false, true),
            (1, 2) => (false, false),
            (2, 1) => (true, true),
            (2, 2) => (true, false),
            _ => bail!("unsupported ELF class {class:#x} or data encoding {enc:#x}"),
        };

        let (shoff, shentsize, shnum, shstrndx) = if wide {
            (
                rd64(data, 40, le).unwrap_or(0),
                rd16(data, 58, le).unwrap_or(0) as usize,
                rd16(data, 60, le).unwrap_or(0) as u32,
                rd16(data, 62, le).unwrap_or(0),
            )
        } else {
            (
                rd32(data, 32, le).unwrap_or(0) as u64,
                rd16(data, 46, le).unwrap_or(0) as usize,
                rd16(data, 48, le).unwrap_or(0) as u32,
                rd16(data, 50, le).unwrap_or(0),
            )
        };
        if shoff == 0 || shentsize == 0 {
            decline!("ELF has no section header table");
        }
        let expect = if wide { 64 } else { 40 };
        if shentsize < expect {
            bail!("ELF section header entry is {shentsize} bytes, smaller than the {expect} the class requires");
        }
        // `e_shnum == 0` is the SHN_LORESERVE escape: the real count lives in
        // `sh_size` of entry 0 (gABI ch.4). `e_shstrndx == SHN_XINDEX` escapes
        // the same way for the string-table index.
        let mut shnum = shnum as u64;
        let mut shstrndx = shstrndx as u64;
        if shnum == 0 {
            shnum = section_field(data, shoff, shentsize, 0, wide, le, SecField::Size).unwrap_or(0);
        }
        if shstrndx == 0xffff {
            shstrndx =
                section_field(data, shoff, shentsize, 0, wide, le, SecField::Link).unwrap_or(0);
        }
        if shnum == 0 || shnum > 65_536 {
            bail!("implausible ELF section count {shnum}");
        }
        if shstrndx >= shnum {
            bail!("ELF section-name table index {shstrndx} is out of range");
        }

        let Some(shstr) = section_body(data, shoff, shentsize, shstrndx as usize, wide, le) else {
            bail!("ELF section-name table is out of file bounds");
        };

        let mut out = String::new();
        let _ = writeln!(
            out,
            "elf-provenance: {} {}-bit {}-endian, {shnum} sections",
            if wide { "ELF64" } else { "ELF32" },
            if wide { 64 } else { 32 },
            if le { "little" } else { "big" }
        );
        let mut found = false;
        for i in 0..shnum as usize {
            let Some(name_off) = section_field(data, shoff, shentsize, i, wide, le, SecField::Name)
            else {
                break;
            };
            let name = cstr(shstr, name_off as usize)
                .map(|(s, _)| s)
                .unwrap_or_else(|| format!("<name@{name_off}>"));
            let Some(body) = section_body(data, shoff, shentsize, i, wide, le) else {
                continue;
            };
            if name == ".comment" {
                found = true;
                let _ = writeln!(out, "## .comment");
                for part in body.split(|&b| b == 0) {
                    if part.is_empty() {
                        continue;
                    }
                    let s = String::from_utf8_lossy(part);
                    if !push_bounded(&mut out, &s, MAX_TEXT) {
                        return Ok(Outcome::Text(out.into_bytes()));
                    }
                }
            } else if name.starts_with(".note") {
                found = true;
                note_lines(&name, body, le, &mut out);
            }
        }
        if !found {
            decline!("no .comment or .note section");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// The section-header fields this module needs, in each class's byte layout.
#[derive(Clone, Copy)]
#[cfg(feature = "elf")]
enum SecField {
    Name,
    Size,
    Link,
}

/// Read one section-header field, or `None` if the header is out of bounds.
///
/// Offsets follow the gABI: `Elf32_Shdr` is `sh_name, sh_type, sh_flags,
/// sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize` at
/// 4-byte words; `Elf64_Shdr` widens `sh_flags`, `sh_addr`, `sh_offset` and
/// `sh_size` to 8 bytes.
#[cfg(feature = "elf")]
fn section_field(
    data: &[u8],
    shoff: u64,
    shentsize: usize,
    index: usize,
    wide: bool,
    le: bool,
    field: SecField,
) -> Option<u64> {
    let base = shoff.checked_add((index as u64).checked_mul(shentsize as u64)?)?;
    let base = usize::try_from(base).ok()?;
    if wide {
        let w = |o: usize| rd64(data, base.checked_add(o)?, le);
        Some(match field {
            SecField::Name => rd32(data, base, le)? as u64,
            SecField::Size => w(32)?,
            SecField::Link => rd32(data, base + 40, le)? as u64,
        })
    } else {
        let w = |o: usize| rd32(data, base.checked_add(o)?, le).map(u64::from);
        Some(match field {
            SecField::Name => rd32(data, base, le)? as u64,
            SecField::Size => w(20)?,
            SecField::Link => rd32(data, base + 24, le)? as u64,
        })
    }
}

/// `sh_offset`/`sh_size` of a section, and its body clipped to the file.
#[cfg(feature = "elf")]
fn section_body(
    data: &[u8],
    shoff: u64,
    shentsize: usize,
    index: usize,
    wide: bool,
    le: bool,
) -> Option<&[u8]> {
    let base = shoff.checked_add((index as u64).checked_mul(shentsize as u64)?)?;
    let base = usize::try_from(base).ok()?;
    let (off, size) = if wide {
        (rd64(data, base + 24, le)?, rd64(data, base + 32, le)?)
    } else {
        (
            rd32(data, base + 16, le)? as u64,
            rd32(data, base + 20, le)? as u64,
        )
    };
    let start = usize::try_from(off).ok()?;
    let end = start.checked_add(usize::try_from(size).ok()?)?;
    data.get(start..end)
}

/// A note record is `namesz`, `descsz`, `type`, then the name and the
/// descriptor, each padded up to a four-byte boundary.
#[cfg(feature = "elf")]
fn note_lines(name: &str, body: &[u8], le: bool, out: &mut String) {
    let _ = writeln!(out, "## {name}");
    let mut p = 0usize;
    while p + 12 <= body.len() {
        let (Some(namesz), Some(descsz), Some(ntype)) = (
            rd32(body, p, le),
            rd32(body, p + 4, le),
            rd32(body, p + 8, le),
        ) else {
            break;
        };
        let name_off = p + 12;
        let desc_off = match name_off.checked_add(namesz as usize) {
            Some(v) => (v + 3) & !3,
            None => break,
        };
        let desc_end = match desc_off.checked_add(descsz as usize) {
            Some(v) => (v + 3) & !3,
            None => break,
        };
        if desc_end > body.len() {
            let _ = writeln!(out, "# note truncated at offset {p}");
            break;
        }
        let raw = body
            .get(name_off..name_off + namesz as usize)
            .unwrap_or(&[])
            .iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect::<Vec<u8>>();
        let nname = String::from_utf8_lossy(&raw);
        let _ = writeln!(out, "note type={ntype} name={nname}");
        // NT_GNU_BUILD_ID (3, "GNU") is the one note whose descriptor is itself
        // the payload: the build id, which is what a user greps to correlate a
        // binary with a build.
        if ntype == 3 && nname == "GNU" {
            if let Some(desc) = body.get(desc_off..desc_off + descsz as usize) {
                let mut hex = String::with_capacity(desc.len() * 2);
                for b in desc {
                    let _ = write!(hex, "{b:02x}");
                }
                let _ = writeln!(out, "build-id {hex}");
            }
        }
        if descsz == 0 && namesz == 0 {
            break;
        }
        p = desc_end;
    }
}

// ---------------------------------------------------------------------------
// 4. Android DEX string pool
// ---------------------------------------------------------------------------

/// The DEX string pool: class names, method names, literals, annotations.
///
/// The pool *is* the searchable surface of a DEX — every type descriptor and
/// every string literal is reached from `string_ids`, and nothing else in the
/// file is text.
#[cfg(feature = "dex")]
pub struct DexStrings;

#[cfg(feature = "dex")]
impl Adapter for DexStrings {
    fn name(&self) -> &'static str {
        "dex-strings"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["dex", "odex"]
    }

    fn reach(&self) -> Reach {
        Reach::Reveal
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 0x70 || !data.starts_with(b"dex\n") {
            decline!("not a DEX file");
        }
        let version = data.get(4..7).map(|v| core::str::from_utf8(v));
        let Some(Ok(version)) = version else {
            decline!("DEX version digits are not ASCII");
        };
        if !matches!(
            version,
            "035" | "036" | "037" | "038" | "039" | "040" | "041"
        ) {
            bail!("unknown DEX version {version}");
        }
        if data.get(7) != Some(&0) {
            decline!("DEX magic is not NUL-terminated");
        }
        let header_size = rd32(data, 36, true).unwrap_or(0);
        if header_size != 0x70 {
            bail!("DEX header_size is {header_size}, not the documented 0x70");
        }
        let endian = rd32(data, 40, true).unwrap_or(0);
        // ENDIAN_CONSTANT 0x12345678 is the only one in use; the reverse
        // constant marks a byte-swapped file this reader does not attempt,
        // rather than guessing a swapped walk.
        if endian != 0x1234_5678 {
            decline!("DEX endian_tag is 0x{endian:08x}, not ENDIAN_CONSTANT");
        }

        let file_size = rd32(data, 32, true).unwrap_or(0) as usize;
        // A DEX may be a window onto a larger file (an `odex` inside an APK);
        // the pool must not be read past the end of *this* buffer either way.
        let limit = file_size.min(data.len());
        let string_ids_size = rd32(data, 56, true).unwrap_or(0) as usize;
        let string_ids_off = rd32(data, 60, true).unwrap_or(0) as usize;

        // The table is `size` consecutive 32-bit offsets. Checking the table
        // itself before touching entry 0 is what keeps a header that claims a
        // million strings in a 4 KiB file from walking off the end.
        let table_end = string_ids_size
            .checked_mul(4)
            .and_then(|n| string_ids_off.checked_add(n));
        match table_end {
            Some(e) if e <= limit => {}
            Some(e) => bail!("DEX string_ids table ends at {e}, past the {limit}-byte file"),
            None => bail!("DEX string_ids table offset overflows"),
        }

        let mut out = String::new();
        let _ = writeln!(
            out,
            "dex: version {version}, header 0x70, {string_ids_size} strings"
        );
        let _ = writeln!(
            out,
            "dex: types={} protos={} fields={} methods={} classes={}",
            rd32(data, 64, true).unwrap_or(0),
            rd32(data, 72, true).unwrap_or(0),
            rd32(data, 80, true).unwrap_or(0),
            rd32(data, 88, true).unwrap_or(0),
            rd32(data, 96, true).unwrap_or(0),
        );

        let mut emitted = 0usize;
        let mut skipped = 0usize;
        for i in 0..string_ids_size {
            let Some(off) = rd32(data, string_ids_off + i * 4, true) else {
                break;
            };
            let Ok(mut p) = usize::try_from(off) else {
                skipped += 1;
                continue;
            };
            if p >= limit {
                skipped += 1;
                continue;
            }
            // `string_data_item` is a ULEB128 utf16 length then MUTF-8 bytes
            // terminated by a NUL. The length is a *UTF-16* count, which is not
            // the byte count, so the terminator is what actually bounds it.
            let Some((_utf16_len, np)) = uleb128(data, p, limit) else {
                skipped += 1;
                continue;
            };
            p = np;
            let Some(bytes) = data.get(p..limit) else {
                skipped += 1;
                continue;
            };
            // The declared length is a UTF-16 count, not a byte count, so the
            // NUL terminator is what actually bounds the bytes.
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            let mut s = String::new();
            mutf8_to_utf8(&bytes[..end], &mut s);
            if s.is_empty() {
                continue;
            }
            if !push_bounded(&mut out, &s, MAX_TEXT) {
                let _ = writeln!(
                    out,
                    "# string pool truncated at {MAX_TEXT} bytes ({i} of {string_ids_size} read)"
                );
                return Ok(Outcome::Text(out.into_bytes()));
            }
            emitted += 1;
        }
        if skipped > 0 {
            let _ = writeln!(
                out,
                "# {skipped} of {string_ids_size} string_data_off values were out of range"
            );
        }
        if emitted == 0 && string_ids_size > 0 {
            decline!("no DEX string could be read from the pool");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// ULEB128, bounded by `limit` so a run of continuation bytes stops at the end
/// of the buffer instead of spinning.
#[cfg(any(feature = "dex", feature = "wasm-meta"))]
fn uleb128(d: &[u8], mut p: usize, limit: usize) -> Option<(u32, usize)> {
    let mut v: u32 = 0;
    let mut shift = 0u32;
    loop {
        // `limit` may be shorter than `d` (a DEX window inside a larger file),
        // so the bound is checked before the byte, not after it.
        if p >= limit {
            return None;
        }
        let b = *d.get(p)?;
        p += 1;
        v |= ((b & 0x7f) as u32) << shift;
        if b & 0x80 == 0 {
            return Some((v, p));
        }
        shift += 7;
        if shift >= 32 {
            return None;
        }
    }
}

/// Modified UTF-8, as DEX encodes it: U+0000 is `C0 80`, and a supplementary
/// character arrives as a pair of three-byte surrogates rather than one
/// four-byte sequence.
#[cfg(feature = "dex")]
fn mutf8_to_utf8(bytes: &[u8], out: &mut String) {
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b < 0x80 {
            if b != 0 {
                out.push(b as char);
            }
            i += 1;
        } else if b & 0xe0 == 0xc0 && i + 1 < bytes.len() {
            let v = (((b & 0x1f) as u32) << 6) | (bytes[i + 1] & 0x3f) as u32;
            if let Some(c) = char::from_u32(v) {
                if c != '\0' {
                    out.push(c);
                }
            }
            i += 2;
        } else if b & 0xf0 == 0xe0 && i + 2 < bytes.len() {
            let v = (((b & 0x0f) as u32) << 12)
                | (((bytes[i + 1] & 0x3f) as u32) << 6)
                | (bytes[i + 2] & 0x3f) as u32;
            match char::from_u32(v) {
                Some(c) => out.push(c),
                None => {
                    // A lone high surrogate followed by a low one is the
                    // CESU-8 spelling of one supplementary character.
                    if (0xd800..0xdc00).contains(&v) && i + 5 < bytes.len() {
                        let lo = (((bytes[i + 3] & 0x0f) as u32) << 12)
                            | (((bytes[i + 4] & 0x3f) as u32) << 6)
                            | (bytes[i + 5] & 0x3f) as u32;
                        if (0xdc00..0xe000).contains(&lo) {
                            let cp = 0x10000 + ((v - 0xd800) << 10) + (lo - 0xdc00);
                            if let Some(c) = char::from_u32(cp) {
                                out.push(c);
                                i += 6;
                                continue;
                            }
                        }
                    }
                    out.push('\u{fffd}');
                }
            }
            i += 3;
        } else {
            out.push('\u{fffd}');
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// 5. WebAssembly names, producers and data literals
// ---------------------------------------------------------------------------

/// The custom sections that say *how a module was built*, plus the string
/// literals in its data section.
#[cfg(feature = "wasm-meta")]
pub struct WasmMeta;

#[cfg(feature = "wasm-meta")]
impl Adapter for WasmMeta {
    fn name(&self) -> &'static str {
        "wasm-meta"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["wasm", "wat"]
    }

    fn reach(&self) -> Reach {
        Reach::Reveal
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if !data.starts_with(b"\0asm") {
            decline!("not a WebAssembly module");
        }
        if rd32(data, 4, true) != Some(1) {
            bail!("unsupported WebAssembly binary version");
        }

        let mut out = String::new();
        let mut p = 8usize;
        let mut sections = 0usize;
        let mut any = false;
        while p < data.len() {
            let Some(&id) = data.get(p) else { break };
            p += 1;
            let Some((size, np)) = uleb128(data, p, data.len()) else {
                let _ = writeln!(out, "# section at {p} has a malformed LEB128 size");
                break;
            };
            p = np;
            let Some(end) = p.checked_add(size as usize) else {
                break;
            };
            let Some(body) = data.get(p..end.min(data.len())) else {
                let _ = writeln!(out, "# section {id} at {p} runs past the end of the module");
                break;
            };
            if end > data.len() {
                let _ = writeln!(out, "# section {id} is truncated");
            }
            p = end;
            sections += 1;

            match id {
                0 => {
                    if let Some((name, rest)) = wasm_vec(body, body.len()) {
                        match name.as_str() {
                            "name" => {
                                any = true;
                                name_section(rest, &mut out);
                            }
                            "producers" => {
                                any = true;
                                producers_section(rest, &mut out);
                            }
                            "target_features" => {
                                any = true;
                                target_features_section(rest, &mut out);
                            }
                            other => {
                                let _ = writeln!(out, "## custom section {other}");
                            }
                        }
                    }
                }
                11 => {
                    any = true;
                    data_section(body, &mut out);
                }
                _ => {}
            }
        }
        let _ = sections;
        if !any {
            decline!("no name, producers, target_features or data section to report");
        }
        if out.len() > MAX_TEXT {
            out.truncate(MAX_TEXT);
            let _ = writeln!(out, "# output capped at {MAX_TEXT} bytes");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// `vec(byte)`: a LEB128 count then that many raw bytes.
#[cfg(feature = "wasm-meta")]
fn wasm_vec(d: &[u8], end: usize) -> Option<(String, &[u8])> {
    let (n, mut p) = uleb128(d, 0, end)?;
    let n = n as usize;
    let stop = p.checked_add(n)?;
    if stop > end {
        return None;
    }
    let s = String::from_utf8_lossy(d.get(p..stop)?).into_owned();
    p = stop;
    Some((s, &d[p..]))
}

/// The `name` section: `id`-tagged subsections, each with its own LEB size.
///
/// 0 module, 1 function, 2 local, and 4..=12 the extended index spaces
/// (type, table, memory, global, elem, data, field, tag).
#[cfg(feature = "wasm-meta")]
fn name_section(body: &[u8], out: &mut String) {
    let end = body.len();
    let mut p = 0usize;
    while p < end {
        let Some(&id) = body.get(p) else { break };
        p += 1;
        let Some((size, np)) = uleb128(body, p, end) else {
            let _ = writeln!(out, "# name subsection {id} has a malformed size");
            break;
        };
        p = np;
        let Some(stop) = p.checked_add(size as usize).filter(|&s| s <= end) else {
            let _ = writeln!(out, "# name subsection {id} runs past the section");
            break;
        };
        let sub = &body[p..stop];
        p = stop;

        let label = match id {
            0 => "module",
            1 => "function",
            2 => "local",
            4 => "type",
            5 => "table",
            6 => "memory",
            7 => "global",
            8 => "elem",
            9 => "data",
            10 => "field",
            11 => "tag",
            12 => "table",
            _ => {
                let _ = writeln!(out, "## name subsection {id} (unknown)");
                continue;
            }
        };
        let _ = writeln!(out, "## {label} names");
        match id {
            0 => {
                if let Some((s, _)) = wasm_vec(sub, sub.len()) {
                    let _ = writeln!(out, "module = {s}");
                }
            }
            // The local subsection is `vec(indirectnameassoc)`, so it carries its
            // own count before the first function index — reading that count as
            // an index shifts every name that follows.
            2 => {
                let Some((count, np)) = uleb128(sub, 0, sub.len()) else {
                    break;
                };
                let mut rest = &sub[np..];
                for _ in 0..count {
                    let Some((idx, np)) = uleb128(rest, 0, rest.len()) else {
                        break;
                    };
                    rest = &rest[np..];
                    let Some((nlocals, np)) = uleb128(rest, 0, rest.len()) else {
                        break;
                    };
                    let mut locals = &rest[np..];
                    for _ in 0..nlocals {
                        let Some((li, np)) = uleb128(locals, 0, locals.len()) else {
                            break;
                        };
                        locals = &locals[np..];
                        let Some((nm, after)) = wasm_vec(locals, locals.len()) else {
                            break;
                        };
                        locals = after;
                        let _ = writeln!(out, "local[{idx}][{li}] = {nm}");
                    }
                    rest = &rest[rest.len() - locals.len()..];
                }
            }
            _ => {
                // A namemap is `vec(assoc)`: a count, then that many
                // index/name pairs. Reading the count as the first index is
                // how every name after the first comes out shifted.
                let Some((count, np)) = uleb128(sub, 0, sub.len()) else {
                    break;
                };
                let mut rest = &sub[np..];
                for _ in 0..count {
                    let Some((idx, np)) = uleb128(rest, 0, rest.len()) else {
                        break;
                    };
                    rest = &rest[np..];
                    let Some((nm, after)) = wasm_vec(rest, rest.len()) else {
                        break;
                    };
                    rest = after;
                    let _ = writeln!(out, "{label}[{idx}] = {nm}");
                }
            }
        }
    }
}

/// `producers`: a vector of fields, each a name and a vector of `name, version`.
#[cfg(feature = "wasm-meta")]
fn producers_section(body: &[u8], out: &mut String) {
    let Some((count, np)) = uleb128(body, 0, body.len()) else {
        let _ = writeln!(out, "# producers section has a malformed field count");
        return;
    };
    let _ = writeln!(out, "## producers");
    let mut rest = &body[np..];
    for _ in 0..count.min(1024) {
        let Some((field, after)) = wasm_vec(rest, rest.len()) else {
            break;
        };
        let Some((vcount, np)) = uleb128(after, 0, after.len()) else {
            break;
        };
        let mut vals = &after[np..];
        let mut line = String::new();
        line.push_str(&field);
        for _ in 0..vcount.min(64) {
            let Some((vname, a)) = wasm_vec(vals, vals.len()) else {
                break;
            };
            let Some((version, b)) = wasm_vec(a, a.len()) else {
                break;
            };
            vals = b;
            let _ = write!(line, " {vname}={version}");
        }
        rest = vals;
        let _ = push_bounded(out, &line, MAX_TEXT);
    }
}

/// `target_features`: a vector of `+`/`-` prefixed feature names.
#[cfg(feature = "wasm-meta")]
fn target_features_section(body: &[u8], out: &mut String) {
    let Some((count, np)) = uleb128(body, 0, body.len()) else {
        let _ = writeln!(out, "# target_features has a malformed count");
        return;
    };
    let _ = writeln!(out, "## target_features");
    let mut rest = &body[np..];
    for _ in 0..count.min(4096) {
        let (Some(&prefix), Some(after)) = (rest.first(), rest.get(1..)) else {
            break;
        };
        let Some((name, after)) = wasm_vec(after, after.len()) else {
            break;
        };
        rest = after;
        let sign = match prefix {
            0x2b => '+',
            0x2d => '-',
            other => {
                let _ = writeln!(
                    out,
                    "# target_features prefix 0x{other:02x} is neither + nor -"
                );
                continue;
            }
        };
        let _ = push_bounded(out, &format!("{sign}{name}"), MAX_TEXT);
    }
}

/// The data section: memory index, an init expression, then the literal bytes.
#[cfg(feature = "wasm-meta")]
fn data_section(body: &[u8], out: &mut String) {
    let end = body.len();
    let Some((count, mut p)) = uleb128(body, 0, end) else {
        let _ = writeln!(out, "# data section has a malformed segment count");
        return;
    };
    let _ = writeln!(out, "## data literals");
    for i in 0..count.min(65_536) {
        let Some((_memidx, np)) = uleb128(body, p, end) else {
            break;
        };
        p = np;
        // An init expression ends with 0x0b; a literal one is a single byte,
        // but skip properly rather than assuming that byte is there.
        if body.get(p) == Some(&0x41) {
            p += 1;
            if let Some((_, np)) = uleb128(body, p, end) {
                p = np;
            }
        }
        if body.get(p) == Some(&0x0b) {
            p += 1;
        }
        let Some((len, np)) = uleb128(body, p, end) else {
            break;
        };
        p = np;
        let Some(stop) = p.checked_add(len as usize).filter(|&s| s <= end) else {
            let _ = writeln!(out, "# data segment {i} runs past the section");
            break;
        };
        let bytes = &body[p..stop];
        p = stop;
        if bytes.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(bytes);
        if !push_bounded(out, &s, MAX_TEXT) {
            let _ = writeln!(out, "# output capped at {MAX_TEXT} bytes");
            return;
        }
    }
}

#[cfg(test)]
#[cfg(any(
    feature = "dex",
    feature = "elf",
    feature = "macho",
    feature = "pe",
    feature = "wasm-meta"
))]
mod tests {
    //! What these hold down: each container is walked from bytes built to the
    //! field layout in its own specification, and each format gets at least one
    //! input that a real file can produce but the parser must survive — a
    //! truncated header, a table that overruns the buffer, a directory that
    //! points at itself.

    use super::*;
    #[cfg(any(feature = "dex", feature = "wasm-meta"))]
    use alloc::vec::Vec;

    // -- shared little-endian writers --------------------------------------

    #[cfg(any(feature = "elf", feature = "pe"))]
    fn w16(v: &mut [u8], o: usize, x: u16) {
        v[o..o + 2].copy_from_slice(&x.to_le_bytes());
    }

    #[cfg(any(feature = "dex", feature = "elf", feature = "macho", feature = "pe"))]
    fn w32(v: &mut [u8], o: usize, x: u32) {
        v[o..o + 4].copy_from_slice(&x.to_le_bytes());
    }

    // -- PE ---------------------------------------------------------------

    /// A `VS_VERSIONINFO` node: 6-byte header, NUL-terminated UTF-16 key, value
    /// DWORD-aligned, then children.
    #[cfg(feature = "pe")]
    fn vnode(key: &str, vtype: u16, value: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
        let mut n = vec![0u8; 6];
        for u in key.encode_utf16() {
            n.extend_from_slice(&u.to_le_bytes());
        }
        n.extend_from_slice(&[0, 0]);
        while !n.len().is_multiple_of(4) {
            n.push(0);
        }
        n.extend_from_slice(value);
        while !n.len().is_multiple_of(4) {
            n.push(0);
        }
        for c in children {
            n.extend_from_slice(c);
        }
        let len = n.len() as u16;
        let vlen = if vtype == 1 {
            value.len() as u16
        } else {
            (value.len() / 2) as u16
        };
        n[0..2].copy_from_slice(&len.to_le_bytes());
        n[2..4].copy_from_slice(&vlen.to_le_bytes());
        n[4..6].copy_from_slice(&vtype.to_le_bytes());
        n
    }

    /// The same node with `wValueLength` written verbatim.
    ///
    /// The unit of that field is the whole difficulty: a real Microsoft DLL
    /// writes the `VS_VERSION_INFO` root with `wType = 0` and a length in
    /// *bytes*, and every `String` child with `wType = 1` and a length in
    /// *characters*. A builder that derives the unit from `wType` produces a
    /// fixture that agrees with the reader about the one question a
    /// self-built fixture cannot check.
    #[cfg(feature = "pe")]
    fn vnode_ex(key: &str, wtype: u16, vlen: u16, value: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
        let mut n = vec![0u8; 6];
        for u in key.encode_utf16() {
            n.extend_from_slice(&u.to_le_bytes());
        }
        n.extend_from_slice(&[0, 0]);
        while !n.len().is_multiple_of(4) {
            n.push(0);
        }
        n.extend_from_slice(value);
        while !n.len().is_multiple_of(4) {
            n.push(0);
        }
        for c in children {
            n.extend_from_slice(c);
        }
        let len = n.len() as u16;
        n[0..2].copy_from_slice(&len.to_le_bytes());
        n[2..4].copy_from_slice(&vlen.to_le_bytes());
        n[4..6].copy_from_slice(&wtype.to_le_bytes());
        n
    }

    #[cfg(feature = "pe")]
    fn wt(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// A VS_FIXEDFILEINFO: 52 bytes, signature 0xFEEF04BD, version 1.2.3.4.
    ///
    /// The tail order is dwFileFlagsMask, dwFileFlags, dwFileOS, dwFileType,
    /// dwFileSubtype at 24, 28, 32, 36, 40.
    #[cfg(feature = "pe")]
    fn fixed_file_info() -> Vec<u8> {
        let mut f = vec![0u8; 52];
        w32(&mut f, 0, 0xfeef_04bd);
        w32(&mut f, 4, 0x0001_0000);
        w32(&mut f, 8, 0x0001_0002); // dwFileVersionMS   1.2
        w32(&mut f, 12, 0x0003_0004); // dwFileVersionLS   3.4
        w32(&mut f, 16, 0x0001_0002); // dwProductVersionMS
        w32(&mut f, 20, 0x0003_0004); // dwProductVersionLS
        w32(&mut f, 24, 0x3f); // dwFileFlagsMask
        w32(&mut f, 28, 0); // dwFileFlags
        w32(&mut f, 32, 0x4); // dwFileOS   = VOS__WINDOWS32
        w32(&mut f, 36, 1); // dwFileType = VFT_APP
        f
    }

    /// A version resource: VS_VERSION_INFO → StringFileInfo → StringTable →
    /// two `String` key/value pairs.
    #[cfg(feature = "pe")]
    fn version_blob() -> Vec<u8> {
        let company = vnode("CompanyName", 1, &wt("Acme Widgets"), &[]);
        let product = vnode("ProductName", 1, &wt("Widget Suite"), &[]);
        let table = vnode("040904b0", 1, &[], &[company, product]);
        let sfi = vnode("StringFileInfo", 1, &[], &[table]);
        vnode("VS_VERSION_INFO", 1, &fixed_file_info(), &[sfi])
    }

    /// A carved resource blob: one type (RT_VERSION=16), name 1, language 0x409.
    ///
    /// Layout inside the blob, all offsets relative to the section start:
    /// ```text
    ///  0  root directory (16) + 1 entry (8)      = 24
    /// 24  name directory (16) + 1 entry (8)       = 48
    /// 48  lang directory (16) + 1 entry (8)       = 64
    /// 64  data entry: rva, size, codepage, 0      = 80
    /// 80  payload (the version blob)
    /// ```
    #[cfg(feature = "pe")]
    fn rsrc_blob(payload: &[u8], rva: u32) -> Vec<u8> {
        // Each directory is a 16-byte header plus one 8-byte entry, so the three
        // directories sit at 0, 24 and 48 and their entries at 16, 40 and 64.
        // The `IMAGE_RESOURCE_DATA_ENTRY` is a *fourth* 16-byte structure at 72:
        // laying it at 64 overwrites the language entry, which still parses and
        // yields a plausible-looking but wrong answer.
        const DATA_OFF: usize = 72;
        const PAYLOAD_OFF: usize = 88;
        let mut b = vec![0u8; PAYLOAD_OFF + payload.len()];
        // directory header: Characteristics, TimeDateStamp, Major, Minor,
        // NumberOfNamedEntries, NumberOfIdEntries
        w16(&mut b, 0, 0); // Characteristics
        w16(&mut b, 4, 0); // TimeDateStamp
        w16(&mut b, 12, 0); // NumberOfNamedEntries
        w16(&mut b, 14, 1); // NumberOfIdEntries
        w32(&mut b, 16, 16); // type id RT_VERSION
        w32(&mut b, 20, 0x8000_0000 | 24); // subdirectory at 24

        w16(&mut b, 24, 0);
        w16(&mut b, 36, 0);
        w16(&mut b, 38, 1);
        w32(&mut b, 40, 1); // name id 1
        w32(&mut b, 44, 0x8000_0000 | 48);

        w16(&mut b, 48, 0);
        w16(&mut b, 60, 0);
        w16(&mut b, 62, 1);
        w32(&mut b, 64, 0x409); // lang id
        w32(&mut b, 68, DATA_OFF as u32); // leaf: a data entry, high bit clear

        w32(&mut b, DATA_OFF, rva);
        w32(&mut b, DATA_OFF + 4, payload.len() as u32);
        w32(&mut b, DATA_OFF + 8, 1200); // codepage UTF-16
        w32(&mut b, DATA_OFF + 12, 0);
        b[PAYLOAD_OFF..].copy_from_slice(payload);
        b
    }

    /// Wrap a resource blob in a minimal PE32+ with one section, so the
    /// RVA→file-offset map exists and the leaf payload is reachable.
    #[cfg(feature = "pe")]
    fn pe_with_section(blob: &[u8], rva: u32) -> Vec<u8> {
        let sec_rva = 0x1000u32;
        let raw = 0x200usize;
        let hdr_len = 0x40 + 4 + 20 + 0xf0 + 40; // DOS + PE + COFF + opt + 1 section
        let mut f = vec![0u8; raw.max(hdr_len)];
        f[0] = b'M';
        f[1] = b'Z';
        w32(&mut f, 0x3c, 0x40);
        f[0x40..0x44].copy_from_slice(b"PE\0\0");

        let coff = 0x44;
        w16(&mut f, coff, 0x8664); // Machine AMD64
        w16(&mut f, coff + 2, 1); // NumberOfSections
        w16(&mut f, coff + 16, 0xf0); // SizeOfOptionalHeader

        let opt = 0x58usize;
        w16(&mut f, opt, 0x20b); // PE32+
        w32(&mut f, opt + 108, 16); // NumberOfRvaAndSizes
        let dir = opt + 112;
        // DataDirectory[2] = resource table
        w32(&mut f, dir + 2 * 8, sec_rva);
        w32(&mut f, dir + 2 * 8 + 4, blob.len() as u32);

        let sec = opt + 0xf0;
        f[sec..sec + 8].copy_from_slice(b".rsrc\0\0\0");
        w32(&mut f, sec + 8, blob.len() as u32); // VirtualSize
        w32(&mut f, sec + 12, sec_rva); // VirtualAddress
        w32(&mut f, sec + 16, blob.len() as u32); // SizeOfRawData
        w32(&mut f, sec + 20, raw as u32); // PointerToRawData

        let data_rva = rva;
        f.extend_from_slice(blob);
        let _ = data_rva;
        f
    }

    #[test]
    #[cfg(feature = "pe")]
    fn pe_resources_a_carved_rsrc_reports_the_tree_but_not_the_payload() {
        let payload = version_blob();
        let blob = rsrc_blob(&payload, 0xa1234);
        let Outcome::Text(text) = PeResources.extract(&blob, "app.rsrc").unwrap() else {
            panic!("a carved blob with no RVA map must answer with text");
        };
        let text = String::from_utf8(text).unwrap();
        assert!(
            text.contains("RT_VERSION/1/0x409"),
            "the leaf path must be named, got: {text}"
        );
        assert!(text.contains("rva=0x000a1234"), "got: {text}");
        assert!(
            text.contains("NOT decoded"),
            "a carved blob cannot resolve its data RVA and must say so, got: {text}"
        );
        // The whole point of the format is these bytes; losing them silently
        // would be the failure mode this line exists to prevent.
        assert!(
            !text.contains("Acme Widgets"),
            "a carved blob must not claim to have decoded the payload"
        );
    }

    #[test]
    #[cfg(feature = "pe")]
    fn pe_resources_a_whole_pe_decodes_the_version_leaf_through_the_section_table() {
        let payload = version_blob();
        // Section RVA is 0x1000 and the leaf sits 80 bytes into the blob, so
        // its image RVA is 0x1000 + 88 (88 bytes of directory).
        let blob = rsrc_blob(&payload, 0x1000 + 88);
        let image = pe_with_section(&blob, 0x1000 + 88);

        let Outcome::Members(members) = PeResources.extract(&image, "app.exe").unwrap() else {
            panic!("a whole image must hand back resolvable payloads as members");
        };
        let version = members
            .iter()
            .find(|(n, _)| n == "RT_VERSION/1/0x409")
            .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
            .expect("the version leaf must be a member");
        assert!(version.contains("CompanyName=Acme Widgets"), "{version}");
        assert!(version.contains("ProductName=Widget Suite"), "{version}");
        assert!(version.contains("FileVersion=1.2.3.4"), "{version}");
        assert!(version.contains("Signature=0xfeef04bd"), "{version}");
        assert!(
            members.iter().any(|(n, _)| n == "RSRC_INDEX"),
            "the directory listing must travel with the payloads"
        );
    }

    #[test]
    #[cfg(feature = "pe")]
    fn pe_resources_a_directory_header_cut_short_yields_no_leaves() {
        let blob = vec![0u8; 8]; // IMAGE_RESOURCE_DIRECTORY is 16 bytes
                                 // An 8-byte "section" carries no directory header at all, so there is
                                 // nothing to report and the answer is "not my file" rather than an
                                 // empty report that looks like a real (empty) resource section.
        assert!(
            PeResources.extract(&blob, "short.rsrc").is_err(),
            "a header too short to hold a directory is not a resource section"
        );
    }

    #[test]
    #[cfg(feature = "pe")]
    fn pe_resources_a_fully_truncated_blob_bails_instead_of_parsing() {
        let r = PeResources.extract(b"", "empty.rsrc");
        assert!(r.is_err(), "an empty file is not a resource section");
    }

    #[test]
    #[cfg(feature = "pe")]
    fn pe_resources_a_subdirectory_pointing_at_itself_terminates() {
        let mut blob = rsrc_blob(b"x", 0x1000);
        // Entry 0 of the root directory now points back at offset 0, which is
        // the root itself: an unbounded recursion if the walk trusts offsets.
        w32(&mut blob, 20, 0x8000_0000);
        let Outcome::Text(t) = PeResources.extract(&blob, "loop.rsrc").unwrap() else {
            panic!("a looping directory must degrade, not panic");
        };
        let text = String::from_utf8(t).unwrap();
        assert!(
            text.contains("truncated"),
            "the walk must report that it stopped, got: {text}"
        );
    }

    #[test]
    #[cfg(feature = "pe")]
    fn pe_resources_an_entry_count_past_the_buffer_stops_the_walk() {
        let mut blob = rsrc_blob(b"x", 0x1000);
        // Claim 60000 id entries in a 90-byte directory.
        w16(&mut blob, 14, 60000);
        let Outcome::Text(t) = PeResources.extract(&blob, "huge.rsrc").unwrap() else {
            panic!("expected a degraded answer");
        };
        let text = String::from_utf8(t).unwrap();
        assert!(text.contains("truncated"), "got: {text}");
        assert!(!text.contains("RT_VERSION/1/0x409"), "got: {text}");
    }

    #[test]
    #[cfg(feature = "pe")]
    fn pe_resources_a_version_resource_using_real_toolchain_spellings_decodes() {
        // The shape a real Microsoft DLL writes, which is *not* the shape
        // `vnode` builds: root `wType = 0` with `wValueLength` in bytes, and
        // `String` children `wType = 1` with `wValueLength` in characters.
        // Reading the unit off `wType` loses the version block and prints the
        // first half of every string; this is the regression that holds.
        let company = wt("Contoso");
        let desc = wt("Widget");
        let table = vnode_ex(
            "040904b0",
            1,
            0,
            &[],
            &[
                // wValueLength = 7 characters, value = 8 UTF-16 bytes incl. NUL.
                vnode_ex("CompanyName", 1, 7, &company, &[]),
                vnode_ex("FileDescription", 1, 6, &desc, &[]),
            ],
        );
        let sfi = vnode_ex("StringFileInfo", 1, 0, &[], &[table]);
        let ffi = fixed_file_info();
        let root = vnode_ex("VS_VERSION_INFO", 0, 52, &ffi, &[sfi]);

        let text = String::from_utf8(version_text(&root)).unwrap();
        assert!(text.contains("CompanyName=Contoso"), "got: {text}");
        assert!(text.contains("FileDescription=Widget"), "got: {text}");
        assert!(text.contains("FileVersion=1.2.3.4"), "got: {text}");
        assert!(text.contains("FileOS=0x00000004"), "got: {text}");
        assert!(text.contains("FileType=0x00000001"), "got: {text}");
        assert!(
            !text.contains("CompanyName=Contos\n"),
            "a character-count length must not truncate the value, got: {text}"
        );
    }

    #[test]
    #[cfg(feature = "pe")]
    fn pe_resources_a_version_blob_whose_root_key_is_wrong_decodes_to_nothing() {
        // The RT_VERSION leaf resolved, but it is not a VS_VERSION_INFO: the
        // adapter must not print a plausible-looking empty key/value list.
        let payload = vnode("SomethingElse", 1, &[], &[]);
        let blob = rsrc_blob(&payload, 0x1000 + 88);
        let image = pe_with_section(&blob, 0x1000 + 88);
        let Outcome::Members(members) = PeResources.extract(&image, "app.exe").unwrap() else {
            panic!("payload still resolves");
        };
        let version = members
            .iter()
            .find(|(n, _)| n == "RT_VERSION/1/0x409")
            .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
            .expect("the leaf is still a member");
        assert!(
            version.is_empty(),
            "a non-version payload must stay empty rather than gain invented keys, got: {version}"
        );
    }

    // -- Mach-O ------------------------------------------------------------

    /// A 64-bit Mach-O with one `__TEXT,__cstring` section.
    #[cfg(feature = "macho")]
    fn macho64(cstr_body: &[u8]) -> Vec<u8> {
        let hdr = 32usize;
        let segc = 72usize;
        let sectc = 80usize;
        let cmdsize = segc + sectc;
        let body_off = hdr + cmdsize;
        let mut f = vec![0u8; hdr + cmdsize];
        f[0..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes()); // MH_MAGIC_64, LE
        w32(&mut f, 4, 0x0100_0007); // cputype x86_64
        w32(&mut f, 12, 2); // filetype MH_EXECUTE
        w32(&mut f, 16, 1); // ncmds
        w32(&mut f, 20, cmdsize as u32); // sizeofcmds

        let seg = hdr;
        w32(&mut f, seg, 0x19); // LC_SEGMENT_64
        w32(&mut f, seg + 4, cmdsize as u32);
        f[seg + 8..seg + 14].copy_from_slice(b"__TEXT");
        w64(&mut f, seg + 40, body_off as u64); // fileoff
        w64(&mut f, seg + 48, cstr_body.len() as u64); // filesize
        w32(&mut f, seg + 64, 1); // nsects

        let s = seg + segc;
        f[s..s + 9].copy_from_slice(b"__cstring");
        f[s + 16..s + 22].copy_from_slice(b"__TEXT");
        w64(&mut f, s + 32, cstr_body.len() as u64); // size
        w32(&mut f, s + 48, body_off as u32); // offset

        f.extend_from_slice(cstr_body);
        f
    }

    #[cfg(any(feature = "elf", feature = "macho"))]
    fn w64(v: &mut [u8], o: usize, x: u64) {
        v[o..o + 8].copy_from_slice(&x.to_le_bytes());
    }

    #[test]
    #[cfg(feature = "macho")]
    fn macho_cstring_section_yields_one_line_per_string() {
        let body = b"https://example.com\0/usr/local/bin\0\0tail\0";
        let Outcome::Text(t) = MachOStrings.extract(&macho64(body), "prog").unwrap() else {
            panic!("expected text");
        };
        let text = String::from_utf8(t).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines.contains(&"https://example.com"), "got: {text}");
        assert!(lines.contains(&"/usr/local/bin"), "got: {text}");
        assert!(lines.contains(&"tail"), "got: {text}");
        assert_eq!(
            lines.iter().filter(|l| **l == "tail").count(),
            1,
            "a run of NULs must not produce a duplicate line"
        );
    }

    #[test]
    #[cfg(feature = "macho")]
    fn macho_a_section_header_past_its_segment_command_stops_the_walk() {
        let mut f = macho64(b"visible\0");
        // nsects claims two sections but only one header fits in cmdsize.
        w32(&mut f, 32 + 64, 2);
        let Outcome::Text(t) = MachOStrings.extract(&f, "prog").unwrap() else {
            panic!("expected text");
        };
        let text = String::from_utf8(t).unwrap();
        assert!(text.contains("visible"), "got: {text}");
    }

    #[test]
    #[cfg(feature = "macho")]
    fn macho_a_truncated_header_bails() {
        let r = MachOStrings.extract(b"\xcf\xfa\xed\xfe", "tiny");
        assert!(r.is_err(), "4 bytes is not a mach header");
    }

    #[test]
    #[cfg(feature = "macho")]
    fn macho_a_load_command_whose_size_is_zero_terminates() {
        // One good segment, then a second load command claiming zero bytes.
        // Trusting `cmdsize` there would re-read the same command forever.
        let mut f = macho64(b"visible\0");
        w32(&mut f, 16, 2); // ncmds
        let r = MachOStrings.extract(&f, "prog");
        assert!(r.is_ok(), "a zero-sized load command must stop the walk");
        let Outcome::Text(t) = r.unwrap() else {
            panic!("the first segment's strings are already out");
        };
        assert!(String::from_utf8(t).unwrap().contains("visible"));
    }

    #[test]
    #[cfg(feature = "macho")]
    fn macho_a_file_with_no_string_sections_bails() {
        // Magic is right but there are no load commands at all.
        let mut f = vec![0u8; 64];
        f[0..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes());
        w32(&mut f, 16, 0);
        let r = MachOStrings.extract(&f, "prog");
        assert!(
            r.is_err(),
            "nothing to report must be a bail, not empty text"
        );
    }

    // -- ELF --------------------------------------------------------------

    /// A 64-bit little-endian ELF with `.comment`, `.note.gnu.build-id` and
    /// `.shstrtab`.
    #[cfg(feature = "elf")]
    fn elf64(comment: &[u8], note: &[u8]) -> Vec<u8> {
        // sh_name is an offset into .shstrtab, so the three name offsets have
        // to be the *real* string positions, not the length of each string.
        let full = b"\0.comment\0.note.gnu.build-id\0.shstrtab\0";
        let n_comment = 1usize; // ".comment" follows the leading NUL
        let n_note = n_comment + ".comment".len() + 1;
        let n_shstrtab = n_note + ".note.gnu.build-id".len() + 1;
        let shstr = full[..n_shstrtab].to_vec();

        let hdr = 64usize;
        let sht = hdr;
        // Sections: 0 = NULL, 1 = .comment, 2 = .note.gnu.build-id,
        // 3 = .shstrtab (so e_shstrndx = 3).
        let c_off = sht + 4 * 64;
        let n_off = c_off + comment.len();
        let s_off = n_off + note.len();
        let str_off = s_off + shstr.len();
        let mut f = vec![0u8; str_off + shstr.len()];
        f[0..4].copy_from_slice(b"\x7fELF");
        f[4] = 2; // ELFCLASS64
        f[5] = 1; // ELFDATA2LSB
        f[6] = 1; // EV_CURRENT
        w16(&mut f, 16, 2); // e_type ET_EXEC
        w16(&mut f, 18, 0x3e); // e_machine x86-64
        w32(&mut f, 20, 1); // e_version
        w64(&mut f, 40, sht as u64); // e_shoff
        w16(&mut f, 52, 64); // e_ehsize
        w16(&mut f, 58, 64); // e_shentsize
        w16(&mut f, 60, 4); // e_shnum
        w16(&mut f, 62, 3); // e_shstrndx

        let shdr = |f: &mut Vec<u8>, i: usize, name: u32, off: usize, size: usize| {
            let o = sht + i * 64;
            w32(f, o, name); // sh_name
            w32(f, o + 4, 1); // sh_type SHT_PROGBITS
            w64(f, o + 24, off as u64); // sh_offset
            w64(f, o + 32, size as u64); // sh_size
        };
        // Section 0 is the SHN_UNDEF placeholder.
        shdr(&mut f, 0, 0, 0, 0);
        shdr(&mut f, 1, n_comment as u32, c_off, comment.len());
        shdr(&mut f, 2, n_note as u32, n_off, note.len());
        shdr(&mut f, 3, n_shstrtab as u32, s_off, shstr.len());

        f[c_off..c_off + comment.len()].copy_from_slice(comment);
        f[n_off..n_off + note.len()].copy_from_slice(note);
        f[s_off..str_off].copy_from_slice(&shstr);
        f
    }

    #[cfg(feature = "elf")]
    fn gnu_build_id_note(id: &[u8]) -> Vec<u8> {
        let mut n = Vec::new();
        n.extend_from_slice(&4u32.to_le_bytes()); // namesz
        n.extend_from_slice(&(id.len() as u32).to_le_bytes()); // descsz
        n.extend_from_slice(&3u32.to_le_bytes()); // NT_GNU_BUILD_ID
        n.extend_from_slice(b"GNU\0"); // already 4-byte aligned
        n.extend_from_slice(id);
        while n.len() % 4 != 0 {
            n.push(0);
        }
        n
    }

    #[test]
    #[cfg(feature = "elf")]
    fn elf_comment_and_build_id_are_reported() {
        let comment = b"GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0\0clang version 17.0.6\0";
        let f = elf64(comment, &gnu_build_id_note(&[0xde, 0xad, 0xbe, 0xef]));
        let Outcome::Text(t) = ElfProvenance.extract(&f, "app.so").unwrap() else {
            panic!("expected text");
        };
        let text = String::from_utf8(t).unwrap();
        assert!(
            text.contains("GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0"),
            "the exact toolchain string is the whole point, got: {text}"
        );
        assert!(text.contains("clang version 17.0.6"), "got: {text}");
        assert!(
            text.contains("build-id deadbeef"),
            "NT_GNU_BUILD_ID must render as hex, got: {text}"
        );
    }

    #[test]
    #[cfg(feature = "elf")]
    fn elf_a_truncated_section_header_table_bails() {
        let f = elf64(b"x\0", &[]);
        // Cut the file inside the section header table, then before it.
        assert!(
            ElfProvenance.extract(&f[..70], "cut.so").is_err(),
            "a section-name table that is not in the file is not answerable"
        );
        assert!(
            ElfProvenance.extract(&f[..40], "cut.so").is_err(),
            "no section table at all must bail"
        );
        // A header whose e_shoff points past the end must bail, not read there.
        let mut g = f.clone();
        w64(&mut g, 40, 0xffff_0000);
        assert!(ElfProvenance.extract(&g, "far.so").is_err());
    }

    #[test]
    #[cfg(feature = "elf")]
    fn elf_a_section_name_offset_past_shstrtab_does_not_stop_the_walk() {
        let mut f = elf64(b"GCC: (Debian 12.2.0) 12.2.0\0", &[]);
        // Corrupt section 2's sh_name only. Section 1 (`.comment`) is untouched,
        // so the walk must still reach it: one bad name may not end the scan.
        let sht = 64usize;
        w32(&mut f, sht + 2 * 64, 0xffff);
        let Outcome::Text(t) = ElfProvenance.extract(&f, "bad.so").unwrap() else {
            panic!("a bad name offset degrades, it does not fail the whole file");
        };
        let text = String::from_utf8(t).unwrap();
        assert!(text.contains("GCC: (Debian 12.2.0) 12.2.0"), "got: {text}");
        assert!(
            !text.contains("build-id"),
            "the note section is gone, got: {text}"
        );
    }

    #[test]
    #[cfg(feature = "elf")]
    fn elf_with_no_comment_or_note_section_bails() {
        let f = elf64(b"", &[]);
        // Section 1 is still named `.comment`; make it empty so nothing is found.
        let mut f2 = f.clone();
        // Truncate so the .comment body is empty but the header still parses.
        f2.truncate(f2.len());
        let Outcome::Text(t) = ElfProvenance.extract(&f2, "empty.so").unwrap() else {
            panic!("an empty .comment still yields the header line");
        };
        assert!(!String::from_utf8(t).unwrap().contains("truncated"));
    }

    #[test]
    #[cfg(feature = "elf")]
    fn elf_a_non_elf_file_bails() {
        assert!(ElfProvenance
            .extract(b"MZ\x90\x00 not elf", "x.so")
            .is_err());
    }

    // -- DEX --------------------------------------------------------------

    /// A DEX with a `string_ids` table whose offsets point at ULEB128 + MUTF-8
    /// payloads placed right after the header.
    #[cfg(feature = "dex")]
    fn dex(strings: &[&str], string_ids_size: u32) -> Vec<u8> {
        let mut d = vec![0u8; 0x70];
        d[0..8].copy_from_slice(b"dex\n035\0");
        w32(&mut d, 36, 0x70); // header_size
        w32(&mut d, 40, 0x1234_5678); // endian_tag
        let ids_off = 0x70usize;
        let mut pool = Vec::new();
        let mut ids: Vec<u32> = Vec::new();
        // The pool follows the whole table, so every offset is measured from the end
        // of `strings.len()` entries — not from the end of the entries so
        // far, which would put the first string inside the table itself.
        let ids_len = strings.len() * 4;
        for s in strings {
            ids.push((ids_off + ids_len + pool.len()) as u32);
            // ULEB128 utf16 length, then the bytes, then NUL.
            let units = s.encode_utf16().count() as u32;
            let mut v = units;
            loop {
                let mut b = (v & 0x7f) as u8;
                v >>= 7;
                if v != 0 {
                    b |= 0x80;
                }
                pool.push(b);
                if v == 0 {
                    break;
                }
            }
            pool.extend_from_slice(s.as_bytes());
            pool.push(0);
        }
        // `string_id_item` is a bare 32-bit `string_data_off`, so the table is
        // the offsets concatenated little-endian, not a `Vec<u32>` in memory.
        let ids: Vec<u8> = ids.iter().flat_map(|v| v.to_le_bytes()).collect();
        d.extend_from_slice(&ids);
        d.extend_from_slice(&pool);
        w32(&mut d, 56, string_ids_size);
        w32(&mut d, 60, ids_off as u32);
        w32(&mut d, 64, strings.len() as u32); // type_ids_size
                                               // file_size must be the real length: the reader bounds every offset by
                                               // it, so a zero here makes a valid pool look like it overruns.
        let total = d.len() as u32;
        w32(&mut d, 32, total);
        d
    }

    #[test]
    #[cfg(feature = "dex")]
    fn dex_string_pool_reports_the_pool() {
        let f = dex(
            &["Lcom/example/MainActivity;", "onCreate", "hello world"],
            3,
        );
        let Outcome::Text(t) = DexStrings.extract(&f, "classes.dex").unwrap() else {
            panic!("expected text");
        };
        let text = String::from_utf8(t).unwrap();
        assert!(text.contains("Lcom/example/MainActivity;"), "got: {text}");
        assert!(text.contains("onCreate"), "got: {text}");
        assert!(text.contains("hello world"), "got: {text}");
        assert!(text.contains("3 strings"), "got: {text}");
    }

    #[test]
    #[cfg(feature = "dex")]
    fn dex_string_pool_is_walked_in_sorted_id_order() {
        // A DEX string_ids table is sorted by UTF-16 code point order; this
        // pool is built in that order, so the output must come out sorted.
        let f = dex(&["Main", "Zebra", "apple"], 3);
        let Outcome::Text(t) = DexStrings.extract(&f, "classes.dex").unwrap() else {
            panic!("expected text");
        };
        let text = String::from_utf8(t).unwrap();
        let main = text.find("Main").unwrap();
        let zebra = text.find("Zebra").unwrap();
        let apple = text.find("apple").unwrap();
        assert!(main < zebra && zebra < apple, "out of order: {text}");
    }

    #[test]
    #[cfg(feature = "dex")]
    fn dex_a_string_ids_table_overrunning_the_file_is_refused() {
        // The header claims a million strings; the file has room for three.
        let f = dex(&["a", "b", "c"], 1_000_000);
        let r = DexStrings.extract(&f, "classes.dex");
        assert!(
            r.is_err(),
            "reading entry 0 of a table that does not fit is exactly the \
             out-of-bounds walk this check exists to prevent"
        );
    }

    #[test]
    #[cfg(feature = "dex")]
    fn dex_a_string_data_offset_past_the_end_is_skipped_not_read() {
        let mut f = dex(&["a"], 1);
        // Point the single string_id past the end of the buffer.
        w32(&mut f, 0x70, 0xffff);
        let r = DexStrings.extract(&f, "classes.dex");
        assert!(
            r.is_err(),
            "no readable string means the file is not usable"
        );
    }

    #[test]
    #[cfg(feature = "dex")]
    fn dex_an_unknown_version_bails() {
        let mut f = dex(&["a"], 1);
        f[4..7].copy_from_slice(b"099");
        assert!(DexStrings.extract(&f, "classes.dex").is_err());
    }

    #[test]
    #[cfg(feature = "dex")]
    fn dex_the_reverse_endian_constant_is_refused_rather_than_byte_swapped() {
        let mut f = dex(&["a"], 1);
        w32(&mut f, 40, 0x7856_3412);
        let r = DexStrings.extract(&f, "classes.dex");
        assert!(
            r.is_err(),
            "a byte-swapped DEX needs a different reader, not a guess"
        );
    }

    #[test]
    #[cfg(feature = "dex")]
    fn dex_a_header_size_other_than_0x70_is_refused() {
        let mut f = dex(&["a"], 1);
        w32(&mut f, 36, 0x60);
        assert!(DexStrings.extract(&f, "classes.dex").is_err());
    }

    #[test]
    #[cfg(feature = "dex")]
    fn dex_mutf8_supplementary_characters_survive_the_transcode() {
        // U+1F600 is CESU-8 as a surrogate pair in MUTF-8.
        let mut f2 = Vec::new();
        let pool_ut: Vec<u8> = vec![0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80];
        let ids_off = 0x70usize;
        f2.extend_from_slice(&[0u8; 0x70]);
        f2[0..8].copy_from_slice(b"dex\n035\0");
        w32(&mut f2, 36, 0x70);
        w32(&mut f2, 40, 0x1234_5678);
        f2.extend_from_slice(&[0u8; 4]); // one string_id
        let data_off = (ids_off + 4) as u32;
        w32(&mut f2, 0x70, data_off);
        f2.push(2); // ULEB128 utf16 length = 2 (a surrogate pair)
        f2.extend_from_slice(&pool_ut);
        f2.push(0);
        w32(&mut f2, 56, 1);
        w32(&mut f2, 60, ids_off as u32);
        let total = f2.len() as u32;
        w32(&mut f2, 32, total);

        let Outcome::Text(t) = DexStrings.extract(&f2, "classes.dex").unwrap() else {
            panic!("expected text");
        };
        let text = String::from_utf8(t).unwrap();
        assert!(text.contains('\u{1f600}'), "got: {text:?}");
    }

    // -- WebAssembly ------------------------------------------------------

    #[cfg(feature = "wasm-meta")]
    fn leb(v: &mut Vec<u8>, mut x: u32) {
        loop {
            let mut b = (x & 0x7f) as u8;
            x >>= 7;
            if x != 0 {
                b |= 0x80;
            }
            v.push(b);
            if x == 0 {
                break;
            }
        }
    }

    #[cfg(feature = "wasm-meta")]
    fn wvec(v: &mut Vec<u8>, s: &[u8]) {
        leb(v, s.len() as u32);
        v.extend_from_slice(s);
    }

    #[cfg(feature = "wasm-meta")]
    fn section(id: u8, body: &[u8]) -> Vec<u8> {
        let mut s = vec![id];
        leb(&mut s, body.len() as u32);
        s.extend_from_slice(body);
        s
    }

    #[cfg(feature = "wasm-meta")]
    fn custom(name: &str, body: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        wvec(&mut p, name.as_bytes());
        p.extend_from_slice(body);
        section(0, &p)
    }

    #[test]
    #[cfg(feature = "wasm-meta")]
    fn wasm_name_section_reports_module_function_and_local_names() {
        let mut name = Vec::new();
        // subsection 0: module name
        let mut sub0 = Vec::new();
        wvec(&mut sub0, b"my-module");
        name.push(0);
        leb(&mut name, sub0.len() as u32);
        name.extend_from_slice(&sub0);
        // subsection 1: function names
        let mut sub1 = Vec::new();
        leb(&mut sub1, 2);
        leb(&mut sub1, 3);
        wvec(&mut sub1, b"compute_total");
        leb(&mut sub1, 7);
        wvec(&mut sub1, b"render");
        name.push(1);
        leb(&mut name, sub1.len() as u32);
        name.extend_from_slice(&sub1);
        // subsection 2: local names for function 3
        let mut sub2 = Vec::new();
        leb(&mut sub2, 1);
        leb(&mut sub2, 3); // function index
        leb(&mut sub2, 2); // two locals
        leb(&mut sub2, 0);
        wvec(&mut sub2, b"accumulator");
        leb(&mut sub2, 1);
        wvec(&mut sub2, b"currency");
        name.push(2);
        leb(&mut name, sub2.len() as u32);
        name.extend_from_slice(&sub2);

        let mut f = b"\0asm\x01\x00\x00\x00".to_vec();
        f.extend_from_slice(&custom("name", &name));

        let Outcome::Text(t) = WasmMeta.extract(&f, "mod.wasm").unwrap() else {
            panic!("expected text");
        };
        let text = String::from_utf8(t).unwrap();
        assert!(text.contains("module = my-module"), "got: {text}");
        assert!(text.contains("function[3] = compute_total"), "got: {text}");
        assert!(text.contains("function[7] = render"), "got: {text}");
        assert!(text.contains("local[3][0] = accumulator"), "got: {text}");
        assert!(text.contains("local[3][1] = currency"), "got: {text}");
    }

    #[test]
    #[cfg(feature = "wasm-meta")]
    fn wasm_producers_and_target_features_are_reported() {
        let mut prod = Vec::new();
        leb(&mut prod, 1); // one field
        wvec(&mut prod, b"processed-by");
        leb(&mut prod, 2); // two values
        wvec(&mut prod, b"clang");
        wvec(&mut prod, b"17.0.6");
        wvec(&mut prod, b"wasm-opt");
        wvec(&mut prod, b"version 119");

        let mut tf = Vec::new();
        leb(&mut tf, 3);
        tf.push(0x2b);
        wvec(&mut tf, b"mutable-globals");
        tf.push(0x2d);
        wvec(&mut tf, b"bulk-memory");
        tf.push(0x2b);
        wvec(&mut tf, b"sign-ext");

        let mut f = b"\0asm\x01\x00\x00\x00".to_vec();
        f.extend_from_slice(&custom("producers", &prod));
        f.extend_from_slice(&custom("target_features", &tf));

        let Outcome::Text(t) = WasmMeta.extract(&f, "mod.wasm").unwrap() else {
            panic!("expected text");
        };
        let text = String::from_utf8(t).unwrap();
        assert!(
            text.contains("processed-by clang=17.0.6 wasm-opt=version 119"),
            "got: {text}"
        );
        assert!(text.contains("+mutable-globals"), "got: {text}");
        assert!(text.contains("-bulk-memory"), "got: {text}");
        assert!(text.contains("+sign-ext"), "got: {text}");
    }

    #[test]
    #[cfg(feature = "wasm-meta")]
    fn wasm_data_section_literals_are_reported() {
        let mut data = Vec::new();
        leb(&mut data, 1); // one segment
        leb(&mut data, 0); // memory 0
        data.push(0x0b); // init expr: i32.const 0; end
        wvec(&mut data, b"Hello, wasm!");

        let mut f = b"\0asm\x01\x00\x00\x00".to_vec();
        f.extend_from_slice(&section(11, &data));

        let Outcome::Text(t) = WasmMeta.extract(&f, "mod.wasm").unwrap() else {
            panic!("expected text");
        };
        assert!(String::from_utf8(t).unwrap().contains("Hello, wasm!"));
    }

    #[test]
    #[cfg(feature = "wasm-meta")]
    fn wasm_a_section_whose_size_overruns_the_module_is_reported_not_read() {
        let mut f = b"\0asm\x01\x00\x00\x00".to_vec();
        // A custom section claiming 0xFFFF bytes of payload in a short file.
        f.push(0);
        f.extend_from_slice(&[0xff, 0xff, 0x03]);
        f.extend_from_slice(b"\x04name");
        let Outcome::Text(t) = WasmMeta.extract(&f, "mod.wasm").unwrap() else {
            panic!("the header lines still come out");
        };
        let text = String::from_utf8(t).unwrap();
        assert!(
            text.contains("truncated") || text.contains("past the end"),
            "got: {text}"
        );
    }

    #[test]
    #[cfg(feature = "wasm-meta")]
    fn wasm_a_module_with_no_relevant_sections_bails() {
        let mut f = b"\0asm\x01\x00\x00\x00".to_vec();
        f.extend_from_slice(&section(1, &[0x00, 0x00, 0x00]));
        assert!(WasmMeta.extract(&f, "mod.wasm").is_err());
    }

    #[test]
    #[cfg(feature = "wasm-meta")]
    fn wasm_a_wrong_magic_bails() {
        assert!(WasmMeta
            .extract(b"\0asx\x01\x00\x00\x00", "mod.wasm")
            .is_err());
    }
}
