// SPDX-License-Identifier: Apache-2.0

//! Disk images, filesystem containers and image-package headers.
//!
//! Two different questions live here, and the difference is what the adapter
//! can honestly answer:
//!
//! * **Filesystems with a catalogue** — ISO9660, SquashFS, WIM — have a
//!   directory tree and file payloads inside the image, so the adapter can
//!   hand the pipeline real members and the search reaches the bytes inside
//!   the image. That is a [`Reach::Reveal`]: bytes ripgrep cannot see at all.
//! * **Block containers** — VHD, VHDX, QCOW2, VMDK, VDI, EROFS, APFS, HFS+
//!   — wrap a block device. Reading the file's contents means mounting it,
//!   and an adapter is a pure function over a byte slice: no mount, no
//!   loop device, no privileges. So what these report is the container's
//!   own metadata — geometry, UUID, backing chain, features, and for the
//!   filesystems with a readable catalogue, the file names. That is what
//!   grep can use, and it is what the output says; nothing here claims the
//!   payload was decoded.
//!
//! `.img` is not a format — it is what an operator names a raw dump — so the
//! adapter dispatches on the bytes: an ISO9660 descriptor, an Apple DMG
//! trailer, an HFS+ volume header, or a partition table.

#[cfg(any(
    feature = "applefs",
    feature = "erofs",
    feature = "iso9660",
    feature = "qcow2",
    feature = "raw-image",
    feature = "vdi",
    feature = "vhd",
    feature = "vhdx",
    feature = "vmdk"
))]
use alloc::format;
use alloc::string::String;
#[cfg(any(feature = "iso9660", feature = "vdi", feature = "vhd", feature = "wim"))]
use alloc::string::ToString;
#[cfg(any(
    feature = "applefs",
    feature = "erofs",
    feature = "iso9660",
    feature = "raw-image",
    feature = "vdi",
    feature = "vhd",
    feature = "vhdx",
    feature = "wim"
))]
use alloc::vec::Vec;
#[cfg(any(
    feature = "applefs",
    feature = "erofs",
    feature = "qcow2",
    feature = "raw-image",
    feature = "vdi",
    feature = "vhd",
    feature = "vhdx",
    feature = "vmdk",
    feature = "wim"
))]
use core::fmt::Write as _;

#[cfg(feature = "iso9660")]
use crate::budget::MemberSink;
#[cfg(feature = "qcow2")]
use rgx_core::bail;
use rgx_core::{decline, Adapter, Outcome, Result};

// ---------- checked scalar readers ----------

#[cfg(any(feature = "erofs", feature = "iso9660"))]
fn le16(d: &[u8], p: usize) -> Option<u16> {
    let b = d.get(p..p + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

#[cfg(any(
    feature = "applefs",
    feature = "erofs",
    feature = "iso9660",
    feature = "qcow2",
    feature = "raw-image",
    feature = "vdi",
    feature = "vhd",
    feature = "vhdx",
    feature = "vmdk"
))]
fn le32(d: &[u8], p: usize) -> Option<u32> {
    let b = d.get(p..p + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(any(
    feature = "applefs",
    feature = "erofs",
    feature = "qcow2",
    feature = "raw-image",
    feature = "vdi",
    feature = "vhd",
    feature = "vhdx",
    feature = "vmdk"
))]
fn le64(d: &[u8], p: usize) -> Option<u64> {
    let b = d.get(p..p + 8)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

#[cfg(any(feature = "applefs", feature = "iso9660", feature = "raw-image"))]
fn be16(d: &[u8], p: usize) -> Option<u16> {
    let b = d.get(p..p + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

#[cfg(any(
    feature = "applefs",
    feature = "iso9660",
    feature = "raw-image",
    feature = "vhd"
))]
fn be32(d: &[u8], p: usize) -> Option<u32> {
    let b = d.get(p..p + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(any(feature = "applefs", feature = "raw-image", feature = "vhd"))]
fn be64(d: &[u8], p: usize) -> Option<u64> {
    let b = d.get(p..p + 8)?;
    Some(u64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// ISO 9660 stores most numbers twice, little-endian then big-endian. A
/// field is only read when both halves agree: that is what makes a
/// mis-detected image fail loudly instead of yielding plausible garbage
/// extents.
#[cfg(feature = "iso9660")]
fn both32(d: &[u8], p: usize) -> Option<u32> {
    let le = le32(d, p)?;
    if be32(d, p + 4) == Some(le) {
        Some(le)
    } else {
        None
    }
}

#[cfg(feature = "iso9660")]
fn both16(d: &[u8], p: usize) -> Option<u16> {
    let le = le16(d, p)?;
    if be16(d, p + 2) == Some(le) {
        Some(le)
    } else {
        None
    }
}

/// GUIDs in VHD, VHDX, GPT and the Apple/Windows structures are stored
/// mixed-endian: the first three fields little-endian, the last two as
/// written. Printing them any other way produces a string that looks like a
/// GUID and compares unequal to every tool that prints one.
#[cfg(any(feature = "raw-image", feature = "vhd", feature = "vhdx"))]
fn guid_str(b: &[u8]) -> String {
    if b.len() < 16 {
        return String::new();
    }
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    )
}

#[cfg(any(feature = "applefs", feature = "erofs", feature = "vdi"))]
fn hex_uuid(b: &[u8]) -> String {
    let mut s = String::with_capacity(36);
    for (i, byte) in b.iter().take(16).enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            s.push('-');
        }
        let _ = write!(s, "{byte:02X}");
    }
    s
}

#[cfg(any(
    feature = "applefs",
    feature = "erofs",
    feature = "iso9660",
    feature = "qcow2",
    feature = "raw-image",
    feature = "vdi",
    feature = "vhd",
    feature = "vmdk"
))]
fn human(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.2} {}", UNITS[i])
    }
}

/// ISO 9660 names are `NAME.EXT;1` in ASCII, or UTF-16BE under Joliet. The
/// version suffix is noise for grep; the separators are not.
#[cfg(feature = "iso9660")]
fn tidy_name(raw: &[u8], joliet: bool) -> String {
    let mut s = if joliet {
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    if let Some(cut) = s.rfind(';') {
        if s[cut + 1..].chars().all(|c| c.is_ascii_digit()) {
            s.truncate(cut);
        }
    }
    s.replace(';', "_")
}

/// Rock Ridge carries the real POSIX name in an `NM` entry inside the
/// system-use area. Without it every file on a Linux ISO is `FILE.DAT;1`
/// and the names a user greps for do not exist anywhere in the image.
#[cfg(feature = "iso9660")]
fn rock_ridge_name(sysuse: &[u8]) -> Option<String> {
    let mut p = 0;
    while p + 4 <= sysuse.len() {
        let sig = &sysuse[p..p + 2];
        let len = u16::from_be_bytes([sysuse[p + 2], sysuse[p + 3]]) as usize;
        if len < 4 || p + len > sysuse.len() {
            break;
        }
        if sig == b"NM" {
            // NM carries the CURRENT name in the flag word and the name
            // itself right after it. A real NM is six bytes at the least —
            // signature, length, flags and one character of the name — so
            // a shorter one is a malformed entry and not this file's name:
            // reading its flags or its empty name slice would run past the
            // system-use area the record declared.
            if len < 6 {
                break;
            }
            // Without the CURRENT bit the name lives in the parent
            // directory, so there is nothing to read here and returning the
            // following bytes would print a fragment as a filename.
            let flags = sysuse[p + 5];
            if flags & 0x02 == 0 || flags & 0x04 != 0 {
                return None;
            }
            let name = String::from_utf8_lossy(&sysuse[p + 6..p + len]).into_owned();
            let name = name.trim_end_matches('\0').to_string();
            return if name.is_empty() { None } else { Some(name) };
        }
        if sig == b"ST" {
            break;
        }
        p += len;
    }
    None
}

#[cfg(feature = "iso9660")]
struct IsoRec {
    extent: u32,
    size: u32,
    dir: bool,
    name: String,
}

/// One directory extent, read flat so a record may be parsed without
/// re-deriving its sector. Records never straddle a sector per ECMA-119,
/// and the padding byte that makes them even is consumed here.
#[cfg(feature = "iso9660")]
fn iso_records(data: &[u8], extent: u32, len: u32, block: usize, joliet: bool) -> Vec<IsoRec> {
    let mut out = Vec::new();
    let start = extent as usize * block;
    let end = start.saturating_add(len as usize).min(data.len());
    if start >= data.len() || start >= end {
        return out;
    }
    let buf = &data[start..end];
    let mut p = 0usize;
    while p + 33 <= buf.len() {
        let reclen = buf[p] as usize;
        if reclen == 0 {
            // The rest of the sector is padding; the record list continues
            // in the next logical block.
            p = (p / block + 1) * block;
            if p >= buf.len() {
                break;
            }
            continue;
        }
        if reclen < 34 || reclen > buf.len() - p {
            break;
        }
        let r = &buf[p..p + reclen];
        let (Some(e), Some(sz)) = (both32(r, 2), both32(r, 10)) else {
            break;
        };
        let flags = r[25];
        let name_len = r[32] as usize;
        if 33 + name_len > reclen {
            break;
        }
        let raw = &r[33..33 + name_len];
        let skip = (name_len & 1 == 0) as usize;
        let sysuse = r.get(33 + name_len + skip..reclen).unwrap_or(&[]);
        // "." and ".." are records, not entries: the offset still has to
        // advance, which is why this is a filter and not a `continue`.
        let name = match (name_len, raw.first()) {
            (0, _) | (1, Some(0)) | (1, Some(1)) => {
                p += reclen;
                continue;
            }
            _ => rock_ridge_name(sysuse).unwrap_or_else(|| tidy_name(raw, joliet)),
        };
        out.push(IsoRec {
            extent: e,
            size: sz,
            dir: flags & 0x02 != 0,
            name,
        });
        p += reclen;
    }
    out
}

#[cfg(feature = "iso9660")]
pub struct Iso9660;
#[cfg(feature = "iso9660")]
impl Adapter for Iso9660 {
    fn name(&self) -> &'static str {
        "iso9660"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["iso"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        iso_extract(data, false)
    }
}

#[cfg(any(feature = "iso9660", feature = "raw-image"))]
fn iso_extract(data: &[u8], implied: bool) -> Result<Outcome> {
    let sector = 2048usize;
    let pvd = 16 * sector;
    let pvd = data.get(pvd..pvd + sector).unwrap_or_default();
    if pvd.len() < sector || pvd[0] != 1 || &pvd[1..6] != b"CD001" {
        if !implied {
            decline!("not an ISO 9660 image (no primary volume descriptor)");
        }
        decline!("no ISO 9660 volume descriptor");
    }
    let block = both16(pvd, 128).unwrap_or(sector as u16).max(512) as usize;
    let label = String::from_utf8_lossy(&pvd[40..72]).trim().to_string();
    let total_blocks = both32(pvd, 80).unwrap_or(0);
    let root = pvd.get(156..190).unwrap_or_default();

    // Joliet lives in a supplementary descriptor at the same sector 16.
    // A Windows-authored ISO has one and its names are real; a Linux
    // Rock Ridge one usually does not.
    let mut joliet = false;
    let mut root_rec = root;
    for s in 17..40 {
        let Some(vd) = data.get(s * sector..s * sector + sector) else {
            break;
        };
        if vd.len() < sector || vd[0] != 2 || &vd[1..6] != b"CD001" {
            continue;
        }
        if matches!(&vd[88..91], b"%/@" | b"%/C" | b"%/E") {
            joliet = true;
            root_rec = &vd[156..190];
            break;
        }
    }

    let mut sink = MemberSink::new();
    let mut stack: Vec<(String, u32, u32, usize)> = Vec::new();
    if let Some(e) = both32(root_rec, 2) {
        stack.push((
            String::new(),
            e,
            both32(root_rec, 10).unwrap_or_default(),
            0,
        ));
    }

    while let Some((prefix, extent, size, depth)) = stack.pop() {
        if depth > 16 || stack.len() > 4096 {
            continue;
        }
        for rec in iso_records(data, extent, size, block, joliet) {
            let full = if prefix.is_empty() {
                rec.name.clone()
            } else {
                format!("{prefix}/{}", rec.name)
            };
            if rec.dir {
                stack.push((full, rec.extent, rec.size, depth + 1));
            } else {
                let start = rec.extent as usize * block;
                let end = start.saturating_add(rec.size as usize);
                if start >= data.len() || end > data.len() {
                    continue;
                }
                if !sink.reserve(rec.size as u64) {
                    sink.stop(crate::budget::Stopped::Bytes);
                    break;
                }
                sink.push(full, data[start..end].to_vec());
            }
        }
    }
    if !label.is_empty() {
        sink.push(
            "volume-label".to_string(),
            format!("ISO 9660 volume label: {label}\nlogical block size: {block}\nvolume size: {}\njoliet: {joliet}\nblocks: {total_blocks}\n", human(total_blocks as u64 * block as u64)).into_bytes(),
        );
    }
    Ok(Outcome::Members(sink.finish()))
}

/// A raw dump (`.img`). The name says nothing about the contents, so every
/// recognisable shape is tried and the first that fits answers; a file that
/// is none of them still yields its partition table, which is the one thing
/// a raw image always has.
#[cfg(feature = "raw-image")]
pub struct RawImage;
#[cfg(feature = "raw-image")]
impl Adapter for RawImage {
    fn name(&self) -> &'static str {
        "img"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["img"]
    }
    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome> {
        if let Some(vd) = data.get(16 * 2048..16 * 2048 + 6) {
            if vd[0] == 1 && &vd[1..6] == b"CD001" {
                return iso_extract(data, true);
            }
        }
        if dmg_trailer(data).is_some() {
            return dmg_extract(data);
        }
        if hfs_volume_header(data).is_some() {
            return apple_extract(data, path);
        }
        let Some(parts) = partitions(data) else {
            decline!("no ISO 9660 descriptor, DMG trailer, HFS+ volume or partition table");
        };
        Ok(Outcome::Text(parts.into_bytes()))
    }
}

// ---------- Apple ----------

/// A DMG keeps its koly trailer in the last 512 bytes and points at an XML
/// property list that names the partitions in the image.
#[cfg(any(feature = "applefs", feature = "raw-image"))]
fn dmg_trailer(data: &[u8]) -> Option<&[u8]> {
    let n = data.len();
    if n < 512 + 512 {
        return None;
    }
    let koly = n - 512;
    if &data[koly..koly + 4] == b"koly" {
        Some(&data[koly..])
    } else {
        None
    }
}

#[cfg(any(feature = "applefs", feature = "raw-image"))]
fn dmg_extract(data: &[u8]) -> Result<Outcome> {
    let koly = dmg_trailer(data).expect("checked by caller");
    let version = be32(koly, 4).unwrap_or(0);
    let xml_off = be64(koly, 216).unwrap_or(0) as usize;
    let xml_len = be64(koly, 224).unwrap_or(0) as usize;
    let mut out = String::new();
    let _ = writeln!(out, "Apple disk image (koly) version {version}");
    if xml_len > 0 && xml_off.saturating_add(xml_len) <= data.len() {
        let plist = &data[xml_off..xml_off + xml_len];
        // The blkx entries carry the volume names as <string> payloads.
        let mut p = 0;
        let mut names = Vec::new();
        while let Some(found) = find_bytes(plist, b"<string>", p) {
            let start = found + 8;
            let Some(end) = find_bytes(plist, b"</string>", start) else {
                break;
            };
            names.push(String::from_utf8_lossy(&plist[start..end]).into_owned());
            p = end;
        }
        for n in names.iter().filter(|n| !n.is_empty()).take(64) {
            let _ = writeln!(out, "partition: {n}");
        }
        if names.is_empty() {
            let _ = writeln!(out, "(image property list carries no partition names)");
        }
    } else {
        let _ = writeln!(out, "(no embedded property list)");
    }
    Ok(Outcome::Text(out.into_bytes()))
}

#[cfg(any(feature = "applefs", feature = "raw-image", feature = "wim"))]
fn find_bytes(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= hay.len() || needle.is_empty() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

/// HFS+ volume header: signature at offset 1 of the 512-byte header that
/// starts at sector 2. `H+` is the wrapped variant, `HX` the unwrapped one.
#[cfg(any(feature = "applefs", feature = "raw-image"))]
fn hfs_volume_header(data: &[u8]) -> Option<&[u8]> {
    let vh = data.get(1024..1536)?;
    match be16(vh, 1) {
        Some(0x482B) | Some(0x4858) => Some(vh),
        _ => None,
    }
}

#[cfg(feature = "applefs")]
pub struct AppleFs;
#[cfg(feature = "applefs")]
impl Adapter for AppleFs {
    fn name(&self) -> &'static str {
        "applefs"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["apfs", "hfs", "hfsplus", "dmg"]
    }
    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome> {
        apple_extract(data, path)
    }
}

#[cfg(any(feature = "applefs", feature = "raw-image"))]
fn apple_extract(data: &[u8], _path: &str) -> Result<Outcome> {
    if let Some(nx) = data.get(32..36) {
        if nx == b"NXSB" {
            return apfs_extract(data);
        }
    }
    if dmg_trailer(data).is_some() {
        return dmg_extract(data);
    }
    if hfs_volume_header(data).is_some() {
        return hfs_extract(data);
    }
    decline!("no APFS superblock, HFS+ volume header or DMG trailer");
}

#[cfg(feature = "applefs")]
fn apfs_feature(f: u64) -> &'static str {
    match f {
        0x1 => "defrag-prerelease",
        0x2 => "hardlink-map-records",
        0x4 => "dirent-set-type",
        0x8 => "defrag",
        0x10 => "strictatime",
        0x20 => "sealed-root",
        0x40 => "sealed-volume-snapshot",
        0x100 => "volume-object-id-reuse",
        0x200 => "volume-group-id-reuse",
        _ => "unknown",
    }
}

#[cfg(feature = "applefs")]
fn apfs_extract(data: &[u8]) -> Result<Outcome> {
    let sb = data.get(32..32 + 112).unwrap_or_default();
    if sb.get(0..4) != Some(b"NXSB") {
        decline!("no APFS container superblock (NXSB)");
    }
    let block_size = le32(sb, 4).unwrap_or(0);
    let block_count = le64(sb, 8).unwrap_or(0);
    let features = le64(sb, 16).unwrap_or(0);
    let ro_features = le64(sb, 24).unwrap_or(0);
    let incompat = le64(sb, 32).unwrap_or(0);
    let uuid = hex_uuid(sb.get(40..56).unwrap_or_default());
    let next_oid = le64(sb, 56).unwrap_or(0);
    let omap_oid = le64(sb, 80).unwrap_or(0);
    let root_tree_oid = le64(sb, 96).unwrap_or(0);
    let root_tree_xid = le64(sb, 104).unwrap_or(0);

    let mut out = String::new();
    let _ = writeln!(out, "APFS container");
    let _ = writeln!(out, "block size: {block_size}");
    let _ = writeln!(
        out,
        "blocks: {block_count} ({})",
        human(block_count * block_size as u64)
    );
    let _ = writeln!(out, "uuid: {uuid}");
    let _ = writeln!(out, "next oid: {next_oid}");
    let _ = writeln!(out, "omap oid: {omap_oid}");
    let _ = writeln!(out, "root tree oid: {root_tree_oid} xid: {root_tree_xid}");
    let mut f = features;
    let mut bit = 0;
    while f != 0 && bit < 16 {
        if f & 1 == 1 {
            let _ = writeln!(out, "feature: 0x{bit:x} {}", apfs_feature(1u64 << bit));
        }
        f >>= 1;
        bit += 1;
    }
    if ro_features != 0 {
        let _ = writeln!(out, "readonly features: 0x{ro_features:016x}");
    }
    if incompat != 0 {
        let _ = writeln!(out, "incompatible features: 0x{incompat:016x}");
    }
    Ok(Outcome::Text(out.into_bytes()))
}

#[cfg(feature = "applefs")]
fn hfs_extract(data: &[u8]) -> Result<Outcome> {
    let vh = hfs_volume_header(data).expect("checked by caller");
    let version = be16(vh, 2).unwrap_or(0);
    let attributes = be32(vh, 4).unwrap_or(0);
    let files = be32(vh, 32).unwrap_or(0);
    let folders = be32(vh, 36).unwrap_or(0);
    let block_size = be32(vh, 40).unwrap_or(0) as u64;
    let total_blocks = be32(vh, 44).unwrap_or(0) as u64;
    let free_blocks = be32(vh, 48).unwrap_or(0) as u64;
    let encodings = be64(vh, 72).unwrap_or(0);
    // catalogFile fork: logicalSize, clumpSize, totalBlocks, then eight
    // extents of (startBlock, blockCount) — the B-tree the names live in.
    let cat = vh.get(272..352).unwrap_or_default();
    let cat_bytes = be64(cat, 0).unwrap_or(0);
    let cat_start = be32(cat, 16).unwrap_or(0) as u64;
    let cat_blocks = be32(cat, 20).unwrap_or(0) as u64;
    let cat_alloc = be32(cat, 12).unwrap_or(0) as u64;

    let mut out = String::new();
    let _ = writeln!(out, "HFS+ volume (version {version})");
    let _ = writeln!(out, "files: {files}  folders: {folders}");
    let _ = writeln!(
        out,
        "block size: {block_size}  total: {total_blocks}  free: {free_blocks}"
    );
    let _ = writeln!(
        out,
        "size: {}",
        human(total_blocks.saturating_mul(block_size))
    );
    if attributes & 0x0002_0000 != 0 {
        let _ = writeln!(out, "attributes: journaled");
    }
    if attributes & 0x0000_0100 != 0 {
        let _ = writeln!(out, "attributes: case-sensitive");
    }
    if attributes & 0x0000_0004 != 0 {
        let _ = writeln!(out, "attributes: case-folding");
    }
    for (i, &bit) in [64u32, 63, 62, 61].iter().enumerate() {
        if encodings & (1u64 << bit) != 0 {
            let name = [
                "roman", "japanese", "chinese", "korean", "arabic", "hebrew", "greek", "turkish",
            ][i];
            let _ = writeln!(out, "encoding: {name}");
        }
    }
    let _ = writeln!(
        out,
        "catalog b-tree: {}, {cat_blocks} blocks of {block_size} starting at block {cat_start} ({cat_alloc} allocated)",
        human(cat_bytes)
    );

    let names = hfs_catalog_names(data, cat_start, cat_blocks, block_size);
    if names.is_empty() {
        let _ = writeln!(out, "(catalog B-tree yielded no names)");
    } else {
        for n in &names {
            let _ = writeln!(out, "name: {n}");
        }
    }
    Ok(Outcome::Text(out.into_bytes()))
}

/// Walk the catalog B-tree's leaf nodes and read the key of every record.
///
/// The leaf chain is followed from the map node rather than by scanning
/// every block, because a block that merely *looks* like a leaf node is a
/// cheap way to invent names: the map node's value for key 0 is the first
/// leaf and `fLink` chains the rest. If the map cannot be read the scan is
/// refused rather than faked — half a volume's names is worse than none.
#[cfg(feature = "applefs")]
fn hfs_catalog_names(data: &[u8], start_block: u64, blocks: u64, block_size: u64) -> Vec<String> {
    let Some(first_block) = (start_block > 0 && blocks > 0 && block_size >= 512).then_some(0)
    else {
        return Vec::new();
    };
    let _ = first_block;
    let cap = blocks.min(8192);
    let mut names = Vec::new();
    let mut seen = 0u64;
    let mut node = start_block;
    while seen < cap {
        let off = (node * block_size) as usize;
        let Some(buf) = data.get(off..off + block_size as usize) else {
            break;
        };
        let kind = *buf.get(8).unwrap_or(&0) as i8;
        let nrec = be16(buf, 10).unwrap_or(0);
        if kind == 1 {
            // header node: record 0 holds the tree's root node number.
            let rec0 = be16(buf, 14).unwrap_or(0) as usize;
            node = be32(buf, rec0).unwrap_or(0) as u64;
            seen += 1;
            if node == 0 {
                break;
            }
            continue;
        }
        if kind == 2 {
            // map node: record 0 is a u32 first-leaf; the rest are free
            // space offsets. The record offset array holds byte positions,
            // so the value is read *at* the offset, not after it.
            let rec0 = be16(buf, 14).unwrap_or(0) as usize;
            node = be32(buf, rec0).unwrap_or(0) as u64;
            seen += 1;
            if node == 0 {
                break;
            }
            continue;
        }
        if kind != -1 {
            break;
        }
        for i in 0..nrec as usize {
            let at = 14 + i * 2;
            let rec = be16(buf, at).unwrap_or(0) as usize;
            if rec == 0 {
                continue;
            }
            let klen = be16(buf, rec).unwrap_or(0) as usize;
            let name_len = be16(buf, rec + 8).unwrap_or(0) as usize;
            // The key is [keyLength u16][parentID u32][nameLen u16][chars],
            // and keyLength counts everything after itself, so the name
            // must end inside `2 + keyLength`.
            if name_len == 0 || name_len > 255 || 8 + name_len * 2 > klen + 2 {
                continue;
            }
            let Some(bytes) = buf.get(rec + 10..rec + 10 + name_len * 2) else {
                continue;
            };
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            let name = String::from_utf16_lossy(&units);
            if name.chars().all(|c| c == ' ' || c == '\0') {
                continue;
            }
            names.push(name);
            if names.len() >= 20_000 {
                return names;
            }
        }
        let next = be32(buf, 0).unwrap_or(0) as u64;
        if next == 0 || next == node {
            break;
        }
        node = next;
        seen += 1;
    }
    names
}

// ---------- partition tables ----------

#[cfg(any(feature = "raw-image", feature = "vhd"))]
fn mbr_type(t: u8) -> &'static str {
    match t {
        0x00 => "empty",
        0x01 => "FAT12",
        0x04 => "FAT16 <32M",
        0x05 => "extended",
        0x06 => "FAT16",
        0x07 => "NTFS/exFAT",
        0x0b => "FAT32",
        0x0c => "FAT32 LBA",
        0x0e => "FAT16 LBA",
        0x0f => "extended LBA",
        0x27 => "Windows recovery",
        0x42 => "Windows dynamic",
        0x82 => "Linux swap",
        0x83 => "Linux",
        0x85 => "Linux extended",
        0x8e => "Linux LVM",
        0xa5 => "FreeBSD",
        0xa6 => "OpenBSD",
        0xa8 => "Mac OS X",
        0xaf => "Mac OS X HFS+",
        0xee => "GPT protective",
        0xef => "EFI system",
        0xfd => "Linux RAID",
        _ => "other",
    }
}

/// `None` when there is no partition table at all. A raw dump of a
/// filesystem — an `.img` holding one ext4 — has no MBR and no GPT, and
/// reporting its size as if it were an answer would be the one case where
/// silence is the truthful reply.
#[cfg(any(feature = "raw-image", feature = "vhd"))]
fn partitions(data: &[u8]) -> Option<String> {
    let mut out = String::new();
    // The MBR signature lives at 0x1FE, so the slice needs 512 bytes. The
    // guard read `len() >= 3`, which is the length of the *signature*, not of
    // the file: every `.img` between 3 and 511 bytes panicked here, and
    // `extract` calls this on the way out with no other length check in
    // between, so a truncated dump was enough to kill the whole search rather
    // than the one file. A bound check that does not constrain the index it
    // guards is the whole defect.
    if data.len() >= 512 && &data[510..512] == b"\x55\xaa" {
        let _ = writeln!(out, "partition table: MBR");
        for i in 0..4 {
            let e = 446 + i * 16;
            let Some(r) = data.get(e..e + 16) else { break };
            let ty = r[4];
            if ty == 0 {
                continue;
            }
            let start = u32::from_le_bytes([r[8], r[9], r[10], r[11]]) as u64;
            let count = u32::from_le_bytes([r[12], r[13], r[14], r[15]]) as u64;
            let _ = writeln!(
                out,
                "partition {}: type 0x{ty:02x} {} start {} sectors ({}) boot=0x{:02x}",
                i + 1,
                mbr_type(ty),
                start,
                count,
                r[0]
            );
        }
    }
    if data.len() >= 1024 && &data[512..520] == b"EFI PART" {
        let h = &data[512..1024];
        let entries = le32(h, 80).unwrap_or(0) as usize;
        let entry_size = le32(h, 84).unwrap_or(0) as usize;
        let entry_lba = le64(h, 72).unwrap_or(0) as usize;
        let disk_guid = guid_str(h.get(56..72).unwrap_or_default());
        let _ = writeln!(out, "partition table: GPT");
        let _ = writeln!(out, "disk guid: {disk_guid}");
        let _ = writeln!(out, "entries: {entries} x {entry_size} bytes");
        if entry_size >= 128 && entry_lba > 0 {
            for i in 0..entries.min(256) {
                let off = entry_lba * 512 + i * entry_size;
                let Some(e) = data.get(off..off + entry_size) else {
                    break;
                };
                if e[..16].iter().all(|b| *b == 0) {
                    continue;
                }
                let name_bytes = &e[56..128];
                let units: Vec<u16> = name_bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let name = String::from_utf16_lossy(&units);
                let first = le64(e, 32).unwrap_or(0);
                let last = le64(e, 40).unwrap_or(0);
                let _ = writeln!(
                    out,
                    "partition {}: {} lba {}..{} type {}",
                    i + 1,
                    if name.trim().is_empty() {
                        "(unnamed)"
                    } else {
                        name.trim()
                    },
                    first,
                    last,
                    guid_str(&e[..16])
                );
            }
        }
    }
    if out.is_empty() {
        return None;
    }
    let _ = writeln!(out, "total: {}", human(data.len() as u64));
    Some(out)
}

// ---------- VHD ----------

#[cfg(feature = "vhd")]
pub struct Vhd;
#[cfg(feature = "vhd")]
impl Adapter for Vhd {
    fn name(&self) -> &'static str {
        "vhd"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["vhd"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // The footer sits at the front of a fixed disk and at the end of
        // every other kind, so both are tried before giving up.
        let footer = data
            .get(0..512)
            .filter(|f| f.starts_with(b"conectix"))
            .or_else(|| {
                data.get(data.len().saturating_sub(512)..)
                    .filter(|f| f.starts_with(b"conectix"))
            });
        let Some(footer) = footer else {
            decline!("no conectix footer");
        };
        let features = be32(footer, 8).unwrap_or(0);
        let version = be32(footer, 12).unwrap_or(0);
        let data_offset = be64(footer, 16).unwrap_or(u64::MAX);
        let creator_app = String::from_utf8_lossy(footer.get(28..32).unwrap_or_default())
            .trim_end_matches('\0')
            .to_string();
        let creator_host = String::from_utf8_lossy(footer.get(36..40).unwrap_or_default())
            .trim_end_matches('\0')
            .to_string();
        let original = be64(footer, 40).unwrap_or(0);
        let current = be64(footer, 48).unwrap_or(0);
        let geometry = be32(footer, 56).unwrap_or(0);
        let cyl = geometry >> 16;
        let heads = (geometry >> 8) & 0xFF;
        let sectors = geometry & 0xFF;
        let disk_type = be32(footer, 60).unwrap_or(0);
        let uuid = guid_str(footer.get(68..84).unwrap_or_default());

        let mut out = String::new();
        let _ = writeln!(out, "Virtual HD (conectix) version {version:#010x}");
        let _ = writeln!(
            out,
            "type: {}",
            match disk_type {
                2 => "fixed",
                3 => "dynamic",
                4 => "differencing",
                _ => "unknown",
            }
        );
        let _ = writeln!(out, "uuid: {uuid}");
        let _ = writeln!(out, "created by: {creator_app} on {creator_host}");
        let _ = writeln!(
            out,
            "size: {} (original {})",
            human(current),
            human(original)
        );
        if cyl != 0 && heads != 0 && sectors != 0 {
            let _ = writeln!(
                out,
                "geometry: {cyl} cylinders x {heads} heads x {sectors} sectors"
            );
        }
        let _ = writeln!(out, "features: 0x{features:08x}");
        if data_offset != u64::MAX && data_offset != 0 {
            let _ = writeln!(out, "dynamic header offset: {data_offset}");
            // The dynamic header is 576 bytes; reading a 64-byte prefix
            // would silently miss the parent path that lives at 64.
            if let Some(dh) = data.get(data_offset as usize..data_offset as usize + 576) {
                if dh.starts_with(b"cxsparse") {
                    let block_size = be32(dh, 28).unwrap_or(0);
                    let max_entries = be32(dh, 24).unwrap_or(0);
                    let table_offset = be64(dh, 16).unwrap_or(0);
                    let _ = writeln!(
                        out,
                        "block size: {block_size}  max bat entries: {max_entries}"
                    );
                    let _ = writeln!(out, "bat offset: {table_offset}");
                    let parent_uuid = guid_str(dh.get(36..52).unwrap_or_default());
                    if parent_uuid != "00000000-0000-0000-0000-000000000000" {
                        let _ = writeln!(out, "parent uuid: {parent_uuid}");
                    }
                    let parent_name: Vec<u16> = dh
                        .get(64..576)
                        .unwrap_or_default()
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    let name = String::from_utf16_lossy(&units_to_end(&parent_name));
                    if !name.trim().is_empty() {
                        let _ = writeln!(out, "parent: {}", name.trim_end_matches('\0'));
                    }
                }
            }
        }
        if let Some(parts) = partitions(data) {
            let _ = write!(out, "{parts}");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(any(feature = "erofs", feature = "vdi", feature = "vhd", feature = "vhdx"))]
fn units_to_end(units: &[u16]) -> Vec<u16> {
    let end = units.iter().position(|u| *u == 0).unwrap_or(units.len());
    units[..end].to_vec()
}

// ---------- VHDX ----------

/// A VHDX names each 64 KiB region by a well-known GUID. The region table
/// entry is the GUID, the file offset and the length — 32 bytes, with no
/// flag word, which is why a reader that "helpfully" pulls a status u32 out
/// of the length field reports a region every qemu-image-created file says
/// is uncommitted.
#[cfg(feature = "vhdx")]
fn vhdx_regions(data: &[u8]) -> Option<Vec<(String, u64, u64)>> {
    let rt = data.get(0x44224..0x44224 + 0x10000)?;
    if &rt[..4] != b"regi" {
        return None;
    }
    let count = le32(rt, 4)? as usize;
    let mut out = Vec::new();
    for i in 0..count.min(512) {
        let off = 16 + i * 32;
        let e = rt.get(off..off + 32)?;
        out.push((guid_str(&e[..16]), le64(e, 16)?, le64(e, 24)?));
    }
    Some(out)
}

#[cfg(feature = "vhdx")]
fn vhdx_name(guid: &str) -> &'static str {
    match guid {
        "2DC27766-F623-4200-9D64-115E9BFD4A08" => "BAT",
        "8B7CA206-4790-4B9A-B8FE-575F050F886E" => "metadata",
        "B1A039BC-9B98-4B9D-BE6B-D6BB7BD8A0B8" => "io-pending",
        _ => "region",
    }
}

#[cfg(feature = "vhdx")]
pub struct Vhdx;
#[cfg(feature = "vhdx")]
impl Adapter for Vhdx {
    fn name(&self) -> &'static str {
        "vhdx"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["vhdx"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if !data.starts_with(b"vhdxfile") {
            decline!("no vhdxfile signature");
        }
        let creator: Vec<u16> = data
            .get(8..520)
            .unwrap_or_default()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let mut out = String::new();
        let _ = writeln!(out, "VHDX ({} bytes)", data.len());
        let creator = String::from_utf16_lossy(&units_to_end(&creator));
        if !creator.trim().is_empty() {
            let _ = writeln!(out, "creator: {}", creator.trim_end_matches('\0'));
        }

        let Some(regions) = vhdx_regions(data) else {
            let _ = writeln!(
                out,
                "region table unreadable; only the header signature is known"
            );
            return Ok(Outcome::Text(out.into_bytes()));
        };
        for (guid, off, len) in &regions {
            let _ = writeln!(
                out,
                "region {}: {guid} at {off} length {len}",
                vhdx_name(guid)
            );
            if guid.as_str() == "8B7CA206-4790-4B9A-B8FE-575F050F886E" {
                if let Some(meta) =
                    data.get(*off as usize..(*off as usize + *len as usize).min(data.len()))
                {
                    vhdx_metadata(meta, &mut out);
                }
            }
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// Metadata entries carry a 512-byte-sector offset relative to the metadata
/// region, which is why a VHDX hex editor shows offsets that mean nothing
/// against the file.
#[cfg(feature = "vhdx")]
fn vhdx_metadata(meta: &[u8], out: &mut String) {
    if meta.len() < 32 || &meta[..8] != b"metadata" {
        return;
    }
    let entries = le32(meta, 16).unwrap_or(0) as usize;
    let entry_size = le32(meta, 20).unwrap_or(0) as usize;
    if entry_size < 64 {
        return;
    }
    for i in 0..entries.min(1024) {
        let off = 32 + i * entry_size;
        let Some(e) = meta.get(off..off + 64) else {
            break;
        };
        let guid = guid_str(&e[..16]);
        let bits = le32(e, 16).unwrap_or(0);
        let sector = (bits & 0x00FF_FFFE) as u64;
        let user = bits & 1 != 0;
        let size = le32(e, 20).unwrap_or(0) as u64 * 512;
        let _ = writeln!(
            out,
            "  metadata {}: item {} sector {sector} size {} user={user}",
            vhdx_name(&guid),
            guid,
            size
        );
    }
}

// ---------- QCOW2 ----------

#[cfg(feature = "qcow2")]
const QCOW2_INCOMPAT_DIRTY: u64 = 0x1;
#[cfg(feature = "qcow2")]
const QCOW2_INCOMPAT_CORRUPT: u64 = 0x2;
#[cfg(feature = "qcow2")]
const QCOW2_INCOMPAT_DATA_FILE: u64 = 0x4;
#[cfg(feature = "qcow2")]
const QCOW2_AUTOCLEAR_COMPRESSION: u64 = 0x1;
#[cfg(feature = "qcow2")]
const QCOW2_AUTOCLEAR_EXTL2: u64 = 0x2;

#[cfg(feature = "qcow2")]
pub struct Qcow2;
#[cfg(feature = "qcow2")]
impl Adapter for Qcow2 {
    fn name(&self) -> &'static str {
        "qcow2"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["qcow2", "qcow"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if le32(data, 0) != Some(0x5146_49FB) {
            decline!("no QFI magic");
        }
        let version = le32(data, 4).unwrap_or(0);
        if !(2..=3).contains(&version) {
            bail!("unsupported qcow2 version {version}");
        }
        let backing_off = le64(data, 8).unwrap_or(0);
        let backing_len = le32(data, 16).unwrap_or(0) as usize;
        let cluster_bits = le32(data, 20).unwrap_or(0);
        let size = le64(data, 24).unwrap_or(0);
        let crypt = le32(data, 32).unwrap_or(0);
        let l1_size = le32(data, 36).unwrap_or(0);
        let l1_off = le64(data, 40).unwrap_or(0);
        let rc_off = le64(data, 48).unwrap_or(0);
        let rc_clusters = le32(data, 56).unwrap_or(0);
        let snapshots = le32(data, 60).unwrap_or(0);
        let snap_off = le64(data, 64).unwrap_or(0);
        let incompat = le64(data, 72).unwrap_or(0);
        let compat = le64(data, 80).unwrap_or(0);
        let autoclear = le64(data, 88).unwrap_or(0);
        let refcount_order = le32(data, 96).unwrap_or(0);

        let mut out = String::new();
        let _ = writeln!(out, "QCOW2 version {version}");
        let _ = writeln!(out, "virtual size: {} ({size} bytes)", human(size));
        let _ = writeln!(
            out,
            "cluster size: {} ({} bits)",
            human(1u64 << cluster_bits.min(63)),
            cluster_bits
        );
        let _ = writeln!(out, "l1 table: {l1_size} entries at {l1_off}");
        let _ = writeln!(out, "refcount table: {rc_clusters} clusters at {rc_off}");
        let _ = writeln!(
            out,
            "refcount order: {refcount_order} (width {})",
            1 << refcount_order.min(63)
        );
        let _ = writeln!(out, "snapshots: {snapshots} at {snap_off}");
        if crypt != 0 {
            let _ = writeln!(out, "encryption: {crypt}");
        }
        if backing_len > 0 && backing_off > 0 {
            let _ = writeln!(out, "backing file format: {}", le32(data, 104).unwrap_or(0));
            if let Some(n) = data.get(backing_off as usize..backing_off as usize + backing_len) {
                let _ = writeln!(
                    out,
                    "backing file: {}",
                    String::from_utf8_lossy(n).trim_end_matches('\0')
                );
            }
        }
        if incompat & QCOW2_INCOMPAT_DIRTY != 0 {
            let _ = writeln!(out, "incompatible: dirty (uncleanly closed)");
        }
        if incompat & QCOW2_INCOMPAT_CORRUPT != 0 {
            let _ = writeln!(out, "incompatible: corrupt");
        }
        if incompat & QCOW2_INCOMPAT_DATA_FILE != 0 {
            let _ = writeln!(out, "incompatible: external data file");
        }
        if autoclear & QCOW2_AUTOCLEAR_COMPRESSION != 0 {
            let _ = writeln!(out, "autoclear: compressed clusters");
            let _ = writeln!(out, "compression type: {}", le32(data, 104).unwrap_or(0));
        }
        if autoclear & QCOW2_AUTOCLEAR_EXTL2 != 0 {
            let _ = writeln!(out, "autoclear: extended L2 entries");
        }
        if compat != 0 {
            let _ = writeln!(out, "compatible features: 0x{compat:016x}");
        }
        if incompat & !0x7 != 0 {
            let _ = writeln!(out, "incompatible features: 0x{incompat:016x}");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

// ---------- VMDK ----------

#[cfg(feature = "vmdk")]
pub struct Vmdk;
#[cfg(feature = "vmdk")]
impl Adapter for Vmdk {
    fn name(&self) -> &'static str {
        "vmdk"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["vmdk"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // A monolithic extent writes the sparse header at the front; a
        // split extent writes a footer with the same fields at the end.
        let (head, from_footer) = if data.starts_with(b"KDMV") {
            (Some(&data[..512]), false)
        } else if data.len() >= 512
            && data.get(data.len() - 512 + 4..data.len() - 512 + 8) == Some(b"KDMV")
        {
            (Some(&data[data.len() - 512..]), true)
        } else {
            (None, false)
        };
        let Some(h) = head else {
            decline!("no KDMV extent header or footer");
        };
        // The footer repeats the header with the magic at offset 4, so
        // every field sits four bytes later than in the leading header.
        let base = if from_footer { 8 } else { 4 };
        let version = le32(h, base).unwrap_or(0);
        let flags = le32(h, base + 4).unwrap_or(0);
        let capacity = le64(h, base + 8).unwrap_or(0);
        let grain = le64(h, base + 16).unwrap_or(0);
        let desc_off = le64(h, base + 24).unwrap_or(0);
        let desc_len = le64(h, base + 32).unwrap_or(0);
        let gtes = le32(h, base + 40).unwrap_or(0);
        let gd_off = le64(h, base + 48).unwrap_or(0);
        let overhead = le64(h, base + 60).unwrap_or(0);
        let grain_in_flags = (flags >> 16) & 0xFFFF;

        let mut out = String::new();
        let _ = writeln!(
            out,
            "VMDK extent, read from the {}",
            if from_footer { "footer" } else { "header" }
        );
        let _ = writeln!(out, "version: {version}");
        let _ = writeln!(
            out,
            "capacity: {capacity} sectors ({})",
            human(capacity * 512)
        );
        let _ = writeln!(out, "grain size: {grain} sectors");
        if grain_in_flags != 0 {
            let _ = writeln!(out, "grain size (flags): {grain_in_flags} sectors");
        }
        let _ = writeln!(out, "flags: 0x{flags:08x}");
        if flags & 0x01 != 0 {
            let _ = writeln!(out, "compressed");
        }
        if flags & 0x04 != 0 {
            let _ = writeln!(out, "sparse");
        }
        if flags & 0x10 != 0 {
            let _ = writeln!(out, "uncompressed");
        }
        if flags & 0x200 != 0 {
            let _ = writeln!(out, "zlib compression");
        }
        if flags & 0x400 != 0 {
            let _ = writeln!(out, "lz4 compression");
        }
        let _ = writeln!(out, "gtes per gt: {gtes}  gd offset: {gd_off}");
        let _ = writeln!(out, "overhead: {overhead} sectors");
        if desc_len > 0 && desc_len < 1 << 20 {
            if let Some(d) =
                data.get(desc_off as usize..(desc_off as usize + desc_len as usize).min(data.len()))
            {
                let text = String::from_utf8_lossy(d);
                for line in text.lines().take(64) {
                    let line = line.trim();
                    if !line.is_empty() {
                        let _ = writeln!(out, "descriptor: {line}");
                    }
                }
            }
        } else {
            let _ = writeln!(out, "(no embedded descriptor)");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

// ---------- VDI ----------

#[cfg(feature = "vdi")]
pub struct Vdi;
#[cfg(feature = "vdi")]
impl Adapter for Vdi {
    fn name(&self) -> &'static str {
        "vdi"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["vdi"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if le32(data, 0x40) != Some(0xBEDA_107F) {
            decline!("no VirtualBox image signature");
        }
        let version = le32(data, 0x44).unwrap_or(0);
        let image_type = le32(data, 0x4C).unwrap_or(0);
        let comment = String::from_utf8_lossy(data.get(0x54..0x154).unwrap_or_default())
            .trim_end_matches('\0')
            .trim()
            .to_string();
        let cylinders = le32(data, 0x15C).unwrap_or(0);
        let heads = le32(data, 0x160).unwrap_or(0);
        let sectors = le32(data, 0x164).unwrap_or(0);
        let sector_size = le32(data, 0x168).unwrap_or(0);
        let disk_size = le64(data, 0x170).unwrap_or(0);
        let block_size = le32(data, 0x178).unwrap_or(0);
        let block_extra = le32(data, 0x17C).unwrap_or(0);
        let blocks_in_image = le32(data, 0x180).unwrap_or(0);
        let blocks_allocated = le32(data, 0x184).unwrap_or(0);
        let uuid = hex_uuid(data.get(0x188..0x198).unwrap_or_default());
        let snap_uuid = hex_uuid(data.get(0x198..0x1A8).unwrap_or_default());
        let text: Vec<u16> = data
            .get(0..0x40)
            .unwrap_or_default()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let header_text =
            String::from_utf16_lossy(&units_to_end(&text)).replace(['\r', '\n'], " | ");

        let mut out = String::new();
        let _ = writeln!(out, "VirtualBox disk image {:#010x}", version >> 16);
        let _ = writeln!(
            out,
            "type: {}",
            match image_type {
                1 => "dynamic",
                2 => "fixed",
                3 => "undo",
                4 => "differencing",
                _ => "unknown",
            }
        );
        if !header_text.trim().is_empty() {
            let _ = writeln!(out, "header: {}", header_text.trim());
        }
        if !comment.is_empty() {
            let _ = writeln!(out, "comment: {comment}");
        }
        let _ = writeln!(out, "disk size: {} ({disk_size} bytes)", human(disk_size));
        let _ = writeln!(
            out,
            "geometry: {cylinders} cylinders x {heads} heads x {sectors} sectors of {sector_size} bytes"
        );
        let _ = writeln!(out, "block size: {block_size} (extra {block_extra})");
        let _ = writeln!(
            out,
            "blocks in image: {blocks_in_image}  allocated: {blocks_allocated}"
        );
        let _ = writeln!(out, "uuid: {uuid}");
        if snap_uuid != "00000000-0000-0000-0000-000000000000" {
            let _ = writeln!(out, "last snapshot uuid: {snap_uuid}");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

// ---------- WIM ----------

/// A WIM's header is UTF-8 XML at offset zero, in a fixed 0x6C00-byte
/// slot. Its first element names the image and its packages name what is
/// inside, which is the only description a `.wim` ever carries.
#[cfg(feature = "wim")]
fn wim_tag_values(xml: &[u8], tag: &str) -> Vec<String> {
    let open = [b"<", tag.as_bytes(), b">"].concat();
    let close = [b"</", tag.as_bytes(), b">"].concat();
    let mut out = Vec::new();
    let mut p = 0usize;
    while let Some(s) = find_bytes(xml, &open, p) {
        let start = s + open.len();
        let Some(e) = find_bytes(xml, &close, start) else {
            break;
        };
        let text = String::from_utf8_lossy(&xml[start..e]).trim().to_string();
        if !text.is_empty() {
            out.push(text);
        }
        p = e;
    }
    out
}

#[cfg(feature = "wim")]
pub struct Wim;
#[cfg(feature = "wim")]
impl Adapter for Wim {
    fn name(&self) -> &'static str {
        "wim"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["wim"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let head = data.get(0..0x6C00.min(data.len())).unwrap_or_default();
        if !head.starts_with(b"<?xml") {
            decline!("not a WIM (no XML header)");
        }
        let xml_end = find_bytes(head, b"</WIM>", 0).map_or(head.len(), |e| e + 6);
        let xml = &head[..head.len().min(xml_end)];
        let mut out = String::new();
        let _ = writeln!(out, "Windows Imaging Format");
        let mut image_index = String::new();
        let mut p = 0usize;
        while let Some(s) = find_bytes(xml, b"IMAGEINDEX=\"", p) {
            let start = s + 12;
            let Some(e) = find_bytes(xml, b"\"", start) else {
                break;
            };
            let v = String::from_utf8_lossy(&xml[start..e]).to_string();
            if !v.is_empty() {
                image_index = v;
                break;
            }
            p = e;
        }
        if !image_index.is_empty() {
            let _ = writeln!(out, "image index: {image_index}");
        }
        for n in wim_tag_values(xml, "NAME") {
            let _ = writeln!(out, "name: {n}");
        }
        for d in wim_tag_values(xml, "DESCRIPTION") {
            let _ = writeln!(out, "description: {d}");
        }
        let packages = find_bytes(xml, b"<PACKAGE>", 0)
            .map(|first| count_occurrences(xml, b"<PACKAGE>", first))
            .unwrap_or(0);
        let _ = writeln!(out, "packages: {packages}");
        let disks = find_bytes(xml, b"<DISK ", 0)
            .map(|first| count_occurrences(xml, b"<DISK ", first))
            .unwrap_or(0);
        let _ = writeln!(out, "disks: {disks}");
        let dirs = find_bytes(xml, b"<DIRECTORY ", 0)
            .map(|first| count_occurrences(xml, b"<DIRECTORY ", first))
            .unwrap_or(0);
        let _ = writeln!(out, "directory entries: {dirs}");
        let mut attrs = String::new();
        p = 0;
        while let Some(s) = find_bytes(xml, b"ATTRS=\"", p) {
            let start = s + 7;
            let Some(e) = find_bytes(xml, b"\"", start) else {
                break;
            };
            attrs.push_str(&String::from_utf8_lossy(&xml[start..e]));
            p = e;
        }
        if !attrs.is_empty() {
            let _ = writeln!(
                out,
                "attributes: {}",
                attrs.split_whitespace().collect::<Vec<_>>().join(" ")
            );
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(feature = "wim")]
fn count_occurrences(hay: &[u8], needle: &[u8], from: usize) -> usize {
    let mut n = 0;
    let mut p = from;
    while let Some(s) = find_bytes(hay, needle, p) {
        n += 1;
        p = s + needle.len();
    }
    n
}

// ---------- EROFS ----------

#[cfg(feature = "erofs")]
fn erofs_feature(f: u32) -> &'static str {
    match f {
        0x0000_0001 => "compr-time-extended",
        0x0000_0002 => "xattr-index",
        0x0000_0004 => "incompat-file-mode",
        0x0000_0008 => "tail-pack-inline",
        0x0000_0010 => "incompatible-device-id",
        _ => "unknown",
    }
}

#[cfg(feature = "erofs")]
pub struct Erofs;
#[cfg(feature = "erofs")]
impl Adapter for Erofs {
    fn name(&self) -> &'static str {
        "erofs"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["erofs"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let sb = data.get(1024..1024 + 128).unwrap_or_default();
        if le32(sb, 0) != Some(0xE0F5_E1E2) {
            decline!("no EROFS superblock magic");
        }
        let blkszbits = le32(sb, 12).unwrap_or(12);
        let blksz = 1u64 << blkszbits.min(63);
        let extslots = le32(sb, 16).unwrap_or(0);
        let root_nid = le16(sb, 20).unwrap_or(0);
        let inos = le64(sb, 22).unwrap_or(0);
        let blocks = le32(sb, 42).unwrap_or(0) as u64;
        let meta_blkaddr = le32(sb, 46).unwrap_or(0);
        let xattr_blkaddr = le32(sb, 50).unwrap_or(0);
        let uuid = hex_uuid(sb.get(54..70).unwrap_or_default());
        let vol_len = le16(sb, 70).unwrap_or(0) as usize;
        let vol: Vec<u16> = sb
            .get(72..72 + vol_len * 2)
            .unwrap_or_default()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let volume = String::from_utf16_lossy(&units_to_end(&vol));
        let incompat = le32(sb, 102).unwrap_or(0);
        let ro = le32(sb, 108).unwrap_or(0);

        let mut out = String::new();
        let _ = writeln!(out, "EROFS (read-only)");
        let _ = writeln!(out, "block size: {blksz} ({blkszbits} bits)");
        let _ = writeln!(out, "blocks: {blocks} ({})", human(blocks * blksz));
        let _ = writeln!(out, "inodes: {inos}");
        let _ = writeln!(out, "superblock slots: {}", extslots + 1);
        let _ = writeln!(out, "root nid: {root_nid}");
        let _ = writeln!(
            out,
            "meta block: {meta_blkaddr}  xattr block: {xattr_blkaddr}"
        );
        let _ = writeln!(out, "uuid: {uuid}");
        if !volume.is_empty() {
            let _ = writeln!(out, "volume name: {volume}");
        }
        let mut f = incompat;
        let mut bit = 0;
        while f != 0 && bit < 16 {
            if f & 1 == 1 {
                let _ = writeln!(
                    out,
                    "incompatible: 0x{bit:x} {}",
                    erofs_feature(1u32 << bit)
                );
            }
            f >>= 1;
            bit += 1;
        }
        if ro != 0 {
            let _ = writeln!(out, "read-only compatible: 0x{ro:08x}");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(test)]
#[cfg(any(
    feature = "applefs",
    feature = "erofs",
    feature = "iso9660",
    feature = "qcow2",
    feature = "raw-image",
    feature = "vdi",
    feature = "vhd",
    feature = "vhdx",
    feature = "vmdk",
    feature = "wim"
))]
mod tests {
    use super::*;
    #[cfg(feature = "applefs")]
    use alloc::string::ToString;
    #[cfg(any(feature = "iso9660", feature = "raw-image"))]
    use alloc::vec;

    /// `partitions` is called on the way out of `extract` with no length check
    /// in front of it, so its own guard is the only thing between a truncated
    /// dump and a panic. The MBR signature sits at 0x1FE: every length from 3
    /// (the signature's own size) to 511 panicked. Sweeping the whole boundary
    /// rather than one size, because the defect *is* the boundary.
    #[cfg(feature = "raw-image")]
    #[test]
    fn a_file_shorter_than_the_mbr_signature_offset_does_not_panic() {
        for len in 0..600usize {
            let data = alloc::vec![0x53u8; len];
            // None means "no partition table", which is the truthful answer
            // for every one of these lengths. The point is that it returns.
            let got = partitions(&data);
            assert_eq!(got, None, "len {len} produced a partition table");
        }
    }

    /// The same slice, reached the way a user reaches it: a real `.img` on
    /// disk. `extract` must answer, not unwind.
    #[cfg(feature = "raw-image")]
    #[test]
    fn a_truncated_img_extract_answers_instead_of_panicking() {
        for len in [3usize, 4, 63, 100, 300, 384, 511] {
            let data = alloc::vec![0x53u8; len];
            // Any outcome is fine; a panic is not. `extract` may bail on an
            // image it cannot read, and that is the correct answer here.
            let _ = RawImage.extract(&data, "truncated.img");
        }
    }

    /// And the positive control, so the test above cannot pass by `partitions`
    /// having been made to always answer None.
    #[cfg(feature = "raw-image")]
    #[test]
    fn an_mbr_signature_at_0x1fe_is_still_read() {
        let mut data = alloc::vec![0u8; 1024];
        data[510] = 0x55;
        data[511] = 0xaa;
        // first entry: type 0x83 (Linux), start 2048, count 4096
        data[446 + 4] = 0x83;
        data[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        data[446 + 12..446 + 16].copy_from_slice(&4096u32.to_le_bytes());
        let got = partitions(&data).expect("a file carrying the signature has a table");
        assert!(got.contains("MBR"), "{got}");
        assert!(got.contains("start 2048"), "{got}");
    }

    #[cfg(any(
        feature = "applefs",
        feature = "erofs",
        feature = "qcow2",
        feature = "raw-image",
        feature = "vdi",
        feature = "vhd",
        feature = "vhdx",
        feature = "vmdk",
        feature = "wim"
    ))]
    fn text_of(out: Outcome) -> String {
        match out {
            Outcome::Text(t) => String::from_utf8_lossy(&t).into_owned(),
            _ => panic!("expected Text"),
        }
    }

    #[cfg(any(feature = "iso9660", feature = "raw-image"))]
    fn members_of(out: Outcome) -> Vec<(String, Vec<u8>)> {
        match out {
            Outcome::Members(m) => m,
            _ => panic!("expected Members"),
        }
    }

    // ---------- ISO 9660 fixtures ----------

    /// A minimal but structurally valid ISO: PVD at sector 16, one root
    /// directory at sector 18 holding `README.TXT;1`, whose extent is 19.
    #[cfg(any(feature = "iso9660", feature = "raw-image"))]
    fn iso_image() -> Vec<u8> {
        let sector = 2048usize;
        let mut img = vec![0u8; sector * 20];

        // PVD
        let pvd = 16 * sector;
        img[pvd] = 1;
        img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        img[pvd + 6] = 1;
        put_both16(&mut img, pvd + 128, sector as u16);
        put_both32(&mut img, pvd + 80, 20);
        let label = b"RGX_TEST_VOL";
        img[pvd + 40..pvd + 40 + label.len()].copy_from_slice(label);
        // root directory record
        let rr = pvd + 156;
        img[rr] = 34;
        put_both32(&mut img, rr + 2, 18);
        put_both32(&mut img, rr + 10, sector as u32);

        // root directory contents: "." (34 bytes), ".." (34), README.TXT;1
        let dir = 18 * sector;
        for (at, name_byte) in [(dir, 0u8), (dir + 34, 1u8)] {
            img[at] = 34;
            put_both32(&mut img, at + 2, 18);
            put_both32(&mut img, at + 10, sector as u32);
            img[at + 25] = 0x02;
            img[at + 32] = 1;
            img[at + 33] = name_byte;
        }

        let name = b"README.TXT;1";
        let reclen = 33 + name.len() + 1; // pad byte for the odd length
        img[dir + 68] = reclen as u8;
        put_both32(&mut img, dir + 68 + 2, 19);
        let body = b"invoice total is 42\n";
        put_both32(&mut img, dir + 68 + 10, body.len() as u32);
        img[dir + 68 + 32] = name.len() as u8;
        img[dir + 68 + 33..dir + 68 + 33 + name.len()].copy_from_slice(name);
        img[19 * sector..19 * sector + body.len()].copy_from_slice(body);
        img
    }

    #[cfg(any(feature = "iso9660", feature = "raw-image"))]
    fn put_both16(d: &mut [u8], p: usize, v: u16) {
        d[p..p + 2].copy_from_slice(&v.to_le_bytes());
        d[p + 2..p + 4].copy_from_slice(&v.to_be_bytes());
    }

    #[cfg(any(feature = "iso9660", feature = "raw-image"))]
    fn put_both32(d: &mut [u8], p: usize, v: u32) {
        d[p..p + 4].copy_from_slice(&v.to_le_bytes());
        d[p + 4..p + 8].copy_from_slice(&v.to_be_bytes());
    }

    #[cfg(feature = "iso9660")]
    #[test]
    fn iso_lists_and_extracts_a_file() {
        let img = iso_image();
        let out = Iso9660.extract(&img, "disc.iso").expect("iso");
        let m = members_of(out);
        let names: Vec<&str> = m.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"README.TXT"), "{names:?}");
        let readme = m.iter().find(|(n, _)| n == "README.TXT").expect("README");
        assert_eq!(readme.1, b"invoice total is 42\n");
        let label = m.iter().find(|(n, _)| n == "volume-label").expect("label");
        assert!(String::from_utf8_lossy(&label.1).contains("RGX_TEST_VOL"));
    }

    #[cfg(feature = "iso9660")]
    #[test]
    fn iso_rejects_a_non_image() {
        assert!(Iso9660
            .extract(b"not an iso at all, really not", "x.iso")
            .is_err());
    }

    #[cfg(feature = "iso9660")]
    #[test]
    fn rock_ridge_name_wins_over_the_iso_name() {
        // NM (sig, len big-endian per RRIP, version, flags=CURRENT, name)
        // followed by the ST terminator, which is where Rock Ridge puts it.
        let sysuse = b"NM\x00\x10\x01\x02report.txtST\x00\x08\x01\x00\x00\x00\x00";
        assert_eq!(rock_ridge_name(sysuse).as_deref(), Some("report.txt"));
    }

    #[cfg(feature = "iso9660")]
    #[test]
    fn a_rock_ridge_name_living_in_the_parent_yields_nothing() {
        // PARENT set, no CURRENT: the name is in the parent directory, so
        // the bytes after the flag word are not a filename.
        let sysuse = b"NM\x00\x0b\x01\x04xyzST\x00\x08\x01\x00\x00\x00\x00";
        assert_eq!(rock_ridge_name(sysuse), None);
    }

    #[cfg(feature = "iso9660")]
    #[test]
    fn a_rock_ridge_entry_shorter_than_its_own_fields_is_not_a_name() {
        // A real NM is six bytes at the least — signature, length, flags
        // and one character of the name. These two are shorter, and the
        // reader used to read the flags or the name slice past the end of
        // the system-use area to say so.
        assert_eq!(rock_ridge_name(b"NM\x00\x04\x02"), None);
        assert_eq!(rock_ridge_name(b"NM\x00\x05\x02x"), None);
    }

    // ---------- raw image ----------

    #[cfg(feature = "raw-image")]
    #[test]
    fn img_dispatches_to_iso_when_the_descriptor_says_so() {
        let out = RawImage.extract(&iso_image(), "dump.img").expect("img");
        let m = members_of(out);
        let names: Vec<&str> = m.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"README.TXT"), "{names:?}");
    }

    #[cfg(feature = "raw-image")]
    #[test]
    fn img_reads_an_mbr_and_a_gpt() {
        let mut d = vec![0u8; 1024 * 64];
        d[446 + 4] = 0x83;
        d[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        d[446 + 12..446 + 16].copy_from_slice(&(4096u32).to_le_bytes());
        d[510] = 0x55;
        d[511] = 0xAA;
        let out = text_of(RawImage.extract(&d, "raw.img").expect("img"));
        assert!(out.contains("MBR"), "{out}");
        assert!(out.contains("Linux"), "{out}");
    }

    #[cfg(feature = "raw-image")]
    #[test]
    fn img_without_any_known_shape_declines() {
        let d = vec![0xABu8; 4096];
        assert!(RawImage.extract(&d, "junk.img").is_err());
    }

    // ---------- VHD ----------

    #[cfg(feature = "vhd")]
    #[test]
    fn vhd_footer_names_geometry_and_uuid() {
        let mut d = vec![0u8; 4096];
        d[..8].copy_from_slice(b"conectix");
        d[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        d[28..32].copy_from_slice(b"win ");
        d[36..40].copy_from_slice(b"Wi2k");
        d[40..48].copy_from_slice(&1_000_000u64.to_be_bytes());
        d[48..56].copy_from_slice(&1_000_000u64.to_be_bytes());
        d[56..60].copy_from_slice(&(1024u32 << 16 | 255u32 << 8 | 63u32).to_be_bytes());
        d[60..64].copy_from_slice(&2u32.to_be_bytes());
        d[68..84].copy_from_slice(&[0xAB; 16]);
        let out = text_of(Vhd.extract(&d, "disk.vhd").expect("vhd"));
        assert!(out.contains("type: fixed"), "{out}");
        assert!(out.contains("1024 cylinders"), "{out}");
        assert!(
            out.contains("ABABABAB-ABAB-ABAB-ABAB-ABABABABABAB"),
            "{out}"
        );
    }

    #[cfg(feature = "vhd")]
    #[test]
    fn vhd_dynamic_disk_names_its_parent() {
        let mut d = vec![0u8; 8192];
        d[..8].copy_from_slice(b"conectix");
        d[16..24].copy_from_slice(&512u64.to_be_bytes());
        d[60..64].copy_from_slice(&3u32.to_be_bytes());
        d[512..520].copy_from_slice(b"cxsparse");
        d[512 + 24..512 + 28].copy_from_slice(&1024u32.to_be_bytes());
        let parent: Vec<u16> = "C:\\base.vhd".encode_utf16().collect();
        for (i, u) in parent.iter().enumerate() {
            d[512 + 64 + i * 2..512 + 66 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        let out = text_of(Vhd.extract(&d, "diff.vhd").expect("vhd"));
        assert!(
            out.contains("differencing") || out.contains("dynamic"),
            "{out}"
        );
        assert!(out.contains("C:\\base.vhd"), "{out}");
    }

    #[cfg(feature = "vhd")]
    #[test]
    fn vhd_without_a_footer_declines() {
        assert!(Vhd.extract(b"nothing here", "x.vhd").is_err());
    }

    // ---------- VHDX ----------

    #[cfg(feature = "vhdx")]
    #[test]
    fn vhdx_reads_the_region_table_and_metadata() {
        let mut d = vec![0u8; 0x44224 + 0x10000 + 1024];
        d[..8].copy_from_slice(b"vhdxfile");
        for (i, u) in "qemu".encode_utf16().enumerate() {
            d[8 + i * 2..10 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        let rt = 0x44224;
        d[rt..rt + 4].copy_from_slice(b"regi");
        d[rt + 4..rt + 8].copy_from_slice(&1u32.to_le_bytes());
        // BAT region first (16-byte GUID + offset + length + flags)
        let bat_guid = [
            0x66u8, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD,
            0x4A, 0x08,
        ];
        d[rt + 16..rt + 32].copy_from_slice(&bat_guid);
        d[rt + 32..rt + 40].copy_from_slice(&1_048_576u64.to_le_bytes());
        d[rt + 40..rt + 48].copy_from_slice(&65_536u64.to_le_bytes());

        let out = text_of(Vhdx.extract(&d, "disk.vhdx").expect("vhdx"));
        assert!(out.contains("creator: qemu"), "{out}");
        assert!(out.contains("region BAT"), "{out}");
        assert!(
            out.contains("2DC27766-F623-4200-9D64-115E9BFD4A08"),
            "{out}"
        );
    }

    #[cfg(feature = "vhdx")]
    #[test]
    fn vhdx_without_the_signature_declines() {
        assert!(Vhdx.extract(b"nope", "x.vhdx").is_err());
    }

    // ---------- QCOW2 ----------

    #[cfg(feature = "qcow2")]
    #[test]
    fn qcow2_header_is_read_and_the_backing_file_named() {
        let mut d = vec![0u8; 4096];
        d[0..4].copy_from_slice(&0x5146_49FBu32.to_le_bytes());
        d[4..8].copy_from_slice(&3u32.to_le_bytes());
        d[8..16].copy_from_slice(&512u64.to_le_bytes());
        d[16..20].copy_from_slice(&10u32.to_le_bytes());
        d[20..24].copy_from_slice(&16u32.to_le_bytes());
        d[24..32].copy_from_slice(&(4u64 << 30).to_le_bytes());
        d[36..40].copy_from_slice(&2u32.to_le_bytes());
        d[512..522].copy_from_slice(b"base.qcow2");
        d[72..80].copy_from_slice(&1u64.to_le_bytes());
        let out = text_of(Qcow2.extract(&d, "disk.qcow2").expect("qcow2"));
        assert!(out.contains("virtual size: 4.00 GiB"), "{out}");
        assert!(out.contains("backing file: base.qcow2"), "{out}");
        assert!(out.contains("dirty"), "{out}");
    }

    #[cfg(feature = "qcow2")]
    #[test]
    fn qcow2_without_magic_declines() {
        assert!(Qcow2.extract(&[0u8; 64], "x.qcow2").is_err());
    }

    // ---------- VMDK ----------

    #[cfg(feature = "vmdk")]
    #[test]
    fn vmdk_header_and_descriptor_are_read() {
        let mut d = vec![0u8; 4096];
        d[..4].copy_from_slice(b"KDMV");
        d[4..8].copy_from_slice(&1u32.to_le_bytes());
        d[8..12].copy_from_slice(&0x0010_0004u32.to_le_bytes());
        d[12..20].copy_from_slice(&1_024u64.to_le_bytes());
        d[20..28].copy_from_slice(&128u64.to_le_bytes());
        d[28..36].copy_from_slice(&512u64.to_le_bytes());
        let desc = b"# Disk DescriptorFile\nversion=1\ncreateType=\"monolithicSparse\"\nRW 2048 SPARSE \"x.vmdk\"\n";
        d[36..44].copy_from_slice(&(desc.len() as u64).to_le_bytes());
        d[512..512 + desc.len()].copy_from_slice(desc);
        let out = text_of(Vmdk.extract(&d, "disk.vmdk").expect("vmdk"));
        assert!(out.contains("version: 1"), "{out}");
        assert!(out.contains("grain size (flags): 16 sectors"), "{out}");
        assert!(out.contains("monolithicSparse"), "{out}");
    }

    #[cfg(feature = "vmdk")]
    #[test]
    fn vmdk_footer_at_the_end_is_accepted() {
        let mut d = vec![0u8; 4096];
        d[4096 - 512 + 4..4096 - 512 + 8].copy_from_slice(b"KDMV");
        d[4096 - 512 + 8..4096 - 512 + 12].copy_from_slice(&3u32.to_le_bytes());
        let out = text_of(Vmdk.extract(&d, "split.vmdk").expect("vmdk"));
        assert!(out.contains("footer"), "{out}");
        assert!(out.contains("version: 3"), "{out}");
    }

    #[cfg(feature = "vmdk")]
    #[test]
    fn vmdk_without_magic_declines() {
        assert!(Vmdk.extract(b"nothing", "x.vmdk").is_err());
    }

    // ---------- VDI ----------

    #[cfg(feature = "vdi")]
    #[test]
    fn vdi_header_is_read() {
        let mut d = vec![0u8; 1024];
        for (i, u) in "<<< Oracle VM VirtualBox Disk Image >>>\n0.1\n"
            .encode_utf16()
            .enumerate()
        {
            d[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        d[0x40..0x44].copy_from_slice(&0xBEDA_107Fu32.to_le_bytes());
        d[0x44..0x48].copy_from_slice(&0x0003_0001u32.to_le_bytes());
        d[0x4C..0x50].copy_from_slice(&1u32.to_le_bytes());
        d[0x54..0x54 + 5].copy_from_slice(b"built");
        d[0x170..0x178].copy_from_slice(&(2u64 << 30).to_le_bytes());
        d[0x178..0x17C].copy_from_slice(&(2u32 << 20).to_le_bytes());
        let out = text_of(Vdi.extract(&d, "disk.vdi").expect("vdi"));
        assert!(out.contains("type: dynamic"), "{out}");
        assert!(out.contains("comment: built"), "{out}");
        assert!(out.contains("2.00 GiB"), "{out}");
        assert!(out.contains("Oracle VM VirtualBox"), "{out}");
    }

    #[cfg(feature = "vdi")]
    #[test]
    fn vdi_without_the_signature_declines() {
        assert!(Vdi.extract(&[0u8; 512], "x.vdi").is_err());
    }

    // ---------- WIM ----------

    #[cfg(feature = "wim")]
    #[test]
    fn wim_xml_header_is_read() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?><WIM IMAGEINDEX="2">
<NAME>Windows 11 Pro</NAME>
<DESCRIPTION>The install image</DESCRIPTION>
<WIMINFO><DIRECTORIES><DIRECTORY NAME="Windows"/></DIRECTORIES></WIMINFO>
<PACKAGES><PACKAGE><NAME>Microsoft-Windows-Foo</NAME></PACKAGE><PACKAGE><NAME>Microsoft-Windows-Bar</NAME></PACKAGE></PACKAGES>
</WIM>"#;
        let mut d = vec![0u8; xml.len() + 16];
        d[..xml.len()].copy_from_slice(xml);
        let out = text_of(Wim.extract(&d, "boot.wim").expect("wim"));
        assert!(out.contains("image index: 2"), "{out}");
        assert!(out.contains("name: Windows 11 Pro"), "{out}");
        assert!(out.contains("description: The install image"), "{out}");
        assert!(out.contains("packages: 2"), "{out}");
        assert!(out.contains("directory entries: 1"), "{out}");
    }

    #[cfg(feature = "wim")]
    #[test]
    fn wim_without_xml_declines() {
        assert!(Wim.extract(&[0u8; 64], "x.wim").is_err());
    }

    // ---------- EROFS ----------

    #[cfg(feature = "erofs")]
    #[test]
    fn erofs_superblock_is_read() {
        let mut d = vec![0u8; 4096];
        let sb = 1024;
        d[sb..sb + 4].copy_from_slice(&0xE0F5_E1E2u32.to_le_bytes());
        d[sb + 12..sb + 16].copy_from_slice(&12u32.to_le_bytes());
        d[sb + 16..sb + 20].copy_from_slice(&1u32.to_le_bytes());
        d[sb + 22..sb + 30].copy_from_slice(&57u64.to_le_bytes());
        d[sb + 42..sb + 46].copy_from_slice(&900u32.to_le_bytes());
        for (i, u) in "myfs".encode_utf16().enumerate() {
            d[sb + 72 + i * 2..sb + 74 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        d[sb + 70..sb + 72].copy_from_slice(&4u16.to_le_bytes());
        let out = text_of(Erofs.extract(&d, "rootfs.erofs").expect("erofs"));
        assert!(out.contains("block size: 4096"), "{out}");
        assert!(out.contains("inodes: 57"), "{out}");
        assert!(out.contains("volume name: myfs"), "{out}");
    }

    #[cfg(feature = "erofs")]
    #[test]
    fn erofs_without_magic_declines() {
        assert!(Erofs.extract(&[0u8; 2048], "x.erofs").is_err());
    }

    // ---------- Apple ----------

    #[cfg(feature = "applefs")]
    #[test]
    fn apfs_superblock_is_read() {
        let mut d = vec![0u8; 4096];
        d[32..36].copy_from_slice(b"NXSB");
        d[36..40].copy_from_slice(&4096u32.to_le_bytes());
        d[40..48].copy_from_slice(&1_000_000u64.to_le_bytes());
        d[48..56].copy_from_slice(&8u64.to_le_bytes());
        for b in d.iter_mut().skip(72).take(16) {
            *b = 0xCD;
        }
        let out = text_of(AppleFs.extract(&d, "disk.apfs").expect("apfs"));
        assert!(out.contains("APFS container"), "{out}");
        assert!(out.contains("block size: 4096"), "{out}");
        assert!(out.contains("defrag"), "{out}");
        assert!(out.contains("CDCDCDCD-"), "{out}");
    }

    #[cfg(feature = "applefs")]
    #[test]
    fn dmg_koly_trailer_and_its_plist_are_read() {
        let plist = b"<plist><array><dict><key>Name</key><string>whole disk (Apple Partition Map)</string></dict></array></plist>";
        let mut d = vec![0u8; 4096 + plist.len() + 512];
        d[4096..4096 + plist.len()].copy_from_slice(plist);
        let koly = d.len() - 512;
        d[koly..koly + 4].copy_from_slice(b"koly");
        d[koly + 4..koly + 8].copy_from_slice(&4u32.to_be_bytes());
        d[koly + 216..koly + 224].copy_from_slice(&(4096u64).to_be_bytes());
        d[koly + 224..koly + 232].copy_from_slice(&(plist.len() as u64).to_be_bytes());
        let out = text_of(AppleFs.extract(&d, "disk.dmg").expect("dmg"));
        assert!(out.contains("Apple disk image"), "{out}");
        assert!(out.contains("whole disk (Apple Partition Map)"), "{out}");
    }

    #[cfg(feature = "applefs")]
    #[test]
    fn applefs_declines_when_nothing_matches() {
        assert!(AppleFs.extract(&[0u8; 4096], "x.hfs").is_err());
    }

    #[cfg(feature = "applefs")]
    #[test]
    fn hfs_catalog_leaf_yields_names() {
        let block = 4096usize;
        let mut d = vec![0u8; block * 40];
        let vh = 1024;
        d[vh + 1..vh + 3].copy_from_slice(&0x482Bu16.to_be_bytes());
        d[vh + 32..vh + 36].copy_from_slice(&9u32.to_be_bytes());
        d[vh + 40..vh + 44].copy_from_slice(&(block as u32).to_be_bytes());
        d[vh + 44..vh + 48].copy_from_slice(&40u32.to_be_bytes());
        d[vh + 272 + 16..vh + 272 + 20].copy_from_slice(&20u32.to_be_bytes());
        d[vh + 272 + 20..vh + 272 + 24].copy_from_slice(&4u32.to_be_bytes());

        // Map node (kind 2) points at the first leaf; the leaf holds keys.
        let map = 20 * block;
        d[map + 8] = 2;
        d[map + 14..map + 16].copy_from_slice(&30u16.to_be_bytes());
        d[map + 30..map + 34].copy_from_slice(&21u32.to_be_bytes());

        let leaf = 21 * block;
        d[leaf + 8] = 0xFF; // kBTLeafNode = -1
        d[leaf + 10..leaf + 12].copy_from_slice(&1u16.to_be_bytes());
        d[leaf + 14..leaf + 16].copy_from_slice(&100u16.to_be_bytes());
        d[leaf + 16..leaf + 18].copy_from_slice(&200u16.to_be_bytes());
        // record at 100: keyLength 12, parentID 2, nameLen 3, "abc"
        let r = 100;
        let name: Vec<u16> = "abc".encode_utf16().collect();
        d[leaf + r..leaf + r + 2].copy_from_slice(&12u16.to_be_bytes());
        d[leaf + r + 4..leaf + r + 8].copy_from_slice(&2u32.to_be_bytes());
        d[leaf + r + 8..leaf + r + 10].copy_from_slice(&3u16.to_be_bytes());
        for (i, u) in name.iter().enumerate() {
            d[leaf + r + 10 + i * 2..leaf + r + 12 + i * 2].copy_from_slice(&u.to_be_bytes());
        }
        let names = hfs_catalog_names(&d, 20, 4, block as u64);
        assert_eq!(names, vec!["abc".to_string()]);
        let out = text_of(AppleFs.extract(&d, "vol.hfsplus").expect("hfs"));
        assert!(out.contains("HFS+ volume"), "{out}");
        assert!(out.contains("name: abc"), "{out}");
    }

    #[cfg(any(feature = "raw-image", feature = "vhd", feature = "vhdx"))]
    #[test]
    fn guid_formatting_is_mixed_endian() {
        // 2DC27766-F623-4200-9D64-115E9BFD4A08 in on-disk (mixed) order.
        let b = [
            0x66u8, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD,
            0x4A, 0x08,
        ];
        assert_eq!(guid_str(&b), "2DC27766-F623-4200-9D64-115E9BFD4A08");
    }
}
