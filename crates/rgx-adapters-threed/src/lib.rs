// SPDX-License-Identifier: Apache-2.0

//! 3D-model adapters: extract structure and names, not geometry payloads.
//! Text-based formats (obj, mtl, off, usda) are plain text and need no
//! adapter — they fall through to raw search.

#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::boxed::Box;
use alloc::vec::Vec;
use rgx_core::Adapter;

// Every adapter writes its report into a `String`.
#[cfg(any(
    feature = "glb",
    feature = "stl",
    feature = "ply",
    feature = "fbx",
    feature = "pcd",
    feature = "las",
    feature = "vtk",
    feature = "blend",
    feature = "threeds",
    feature = "nifti",
    feature = "mrc"
))]
use alloc::string::String;

// Every adapter but `glb` and `las` turns a borrowed string into
// an owned one.
#[cfg(any(
    feature = "stl",
    feature = "ply",
    feature = "fbx",
    feature = "pcd",
    feature = "vtk",
    feature = "blend",
    feature = "threeds",
    feature = "nifti",
    feature = "mrc"
))]
use alloc::string::ToString;

// The blend and threeds adapters count their chunks in a map.
#[cfg(any(feature = "blend", feature = "threeds"))]
use alloc::collections::BTreeMap;

// Only the blend adapter sorts its histogram.
#[cfg(feature = "blend")]
use core::cmp::Reverse;

// Only the glb adapter reads its JSON chunk as text.
#[cfg(feature = "glb")]
use core::str;

// The adapters that write into their report need `fmt::Write`.
#[cfg(any(
    feature = "glb",
    feature = "fbx",
    feature = "las",
    feature = "blend",
    feature = "threeds",
    feature = "nifti",
    feature = "mrc"
))]
use core::fmt::Write as _;

// The glb and blend adapters report a broken file.
#[cfg(any(feature = "glb", feature = "blend"))]
use rgx_core::bail;

// Every adapter but pcd declines a file it does not recognise.
#[cfg(any(
    feature = "glb",
    feature = "stl",
    feature = "ply",
    feature = "fbx",
    feature = "las",
    feature = "vtk",
    feature = "blend",
    feature = "threeds",
    feature = "nifti",
    feature = "mrc"
))]
use rgx_core::decline;

// The glb, ply, pcd and vtk adapters attach a context to a failure.
#[cfg(any(feature = "glb", feature = "ply", feature = "pcd", feature = "vtk"))]
use rgx_core::Context;

// Every adapter answers with a `Result`.
#[cfg(any(
    feature = "glb",
    feature = "stl",
    feature = "ply",
    feature = "fbx",
    feature = "pcd",
    feature = "las",
    feature = "vtk",
    feature = "blend",
    feature = "threeds",
    feature = "nifti",
    feature = "mrc"
))]
use rgx_core::Result;

// Every adapter answers with an `Outcome`.
#[cfg(any(
    feature = "glb",
    feature = "stl",
    feature = "ply",
    feature = "fbx",
    feature = "pcd",
    feature = "las",
    feature = "vtk",
    feature = "blend",
    feature = "threeds",
    feature = "nifti",
    feature = "mrc"
))]
use rgx_core::Outcome;

pub fn adapters() -> Vec<Box<dyn Adapter>> {
    vec![
        #[cfg(feature = "glb")]
        Box::new(Glb),
        #[cfg(feature = "stl")]
        Box::new(Stl),
        #[cfg(feature = "ply")]
        Box::new(Ply),
        #[cfg(feature = "fbx")]
        Box::new(Fbx),
        #[cfg(feature = "pcd")]
        Box::new(Pcd),
        #[cfg(feature = "las")]
        Box::new(Las),
        #[cfg(feature = "vtk")]
        Box::new(Vtk),
        #[cfg(feature = "blend")]
        Box::new(Blend),
        #[cfg(feature = "threeds")]
        Box::new(Threeds),
        #[cfg(feature = "nifti")]
        Box::new(Nifti),
        #[cfg(feature = "mrc")]
        Box::new(Mrc),
    ]
}

#[cfg(any(
    feature = "glb",
    feature = "stl",
    feature = "fbx",
    feature = "las",
    feature = "nifti"
))]
fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
#[cfg(feature = "las")]
fn rd_f64(b: &[u8], o: usize) -> f64 {
    f64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
#[cfg(feature = "mrc")]
fn rd_i32(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
#[cfg(feature = "mrc")]
fn rd_f32(b: &[u8], o: usize) -> f32 {
    f32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// JSON chunk of a .glb, summarized: counts + every name field.
#[cfg(feature = "glb")]
pub struct Glb;
#[cfg(feature = "glb")]
impl Adapter for Glb {
    fn name(&self) -> &'static str {
        "glb"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["glb"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 20 || &data[0..4] != b"glTF" {
            decline!("not a GLB file (bad magic)");
        }
        let total = rd_u32(data, 8) as usize;
        if total > data.len() {
            bail!("GLB length field overruns file");
        }
        // first chunk: u32 len + u32 type ("JSON")
        let clen = rd_u32(data, 12) as usize;
        if rd_u32(data, 16) != u32::from_le_bytes(*b"JSON") {
            bail!("GLB has no JSON chunk");
        }
        // the declared chunk length must fit inside the declared total
        // length *and* the actual file — fuzzed headers lie about both
        let json_end = 20usize.saturating_add(clen);
        if json_end > total || json_end > data.len() {
            bail!("GLB JSON chunk length overruns file");
        }
        let text = str::from_utf8(&data[20..json_end]).context("GLB JSON chunk is not UTF-8")?;
        // The lazy walk, not the Arena parser: the summary needs seven
        // fixed keys, each item's `name`, and the `asset` fragment --
        // the accessor/bufferView tails that dominate a glTF chunk are
        // validated and never materialised. Every walk error takes the
        // same context the Arena parser's errors took, so a malformed
        // chunk fails exactly as it failed before.
        let mut doc = rgx_core::djson::ondemand::Ondemand::new(text)
            .map_err(rgx_core::Error::msg)
            .context("GLB JSON chunk is not valid JSON")?;
        let jerr = |e: rgx_core::djson::parser::JsonParseError| {
            rgx_core::Error::msg(e).context("GLB JSON chunk is not valid JSON")
        };

        // One forward pass collects everything; output order is the
        // fixed key list below, not source order. Per key, the LAST
        // duplicate entry wins (the Arena's `object_get` semantics),
        // which is why each entry overwrites rather than accumulates.
        const KEYS: [&str; 7] = [
            "scenes",
            "nodes",
            "meshes",
            "materials",
            "animations",
            "skins",
            "images",
        ];
        let mut found: [Option<(usize, Vec<String>)>; 7] = Default::default();
        let mut asset: Option<String> = None;

        let mut root = doc.root().map_err(jerr)?;
        if root.is_object().map_err(jerr)? {
            root.object_entries(|k, mut v| {
                if k.as_ref() == "asset" {
                    asset = Some(v.to_compact_string()?);
                    return Ok(true);
                }
                if let Some(slot) = KEYS.iter().position(|&key| key == k.as_ref()) {
                    let mut got = None;
                    if v.is_array()? {
                        let mut len = 0usize;
                        let mut names = Vec::new();
                        v.array_items(|_, item| {
                            len += 1;
                            let mut name = None;
                            item.find_key("name", |n| {
                                name = n.as_str()?;
                                Ok(())
                            })?;
                            if let Some(n) = name {
                                names.push(n.into_owned());
                            }
                            Ok(true)
                        })?;
                        got = Some((len, names));
                    }
                    found[slot] = got;
                }
                Ok(true)
            })
            .map_err(jerr)?;
        } else {
            root.skip().map_err(jerr)?;
        }
        doc.finish().map_err(jerr)?;

        let mut out = String::new();
        for (i, key) in KEYS.iter().enumerate() {
            if let Some((len, names)) = &found[i] {
                let _ = writeln!(out, "{key}: {len}");
                for name in names {
                    let _ = writeln!(out, "  {key}[..]: {name}");
                }
            }
        }
        if let Some(a) = &asset {
            let _ = writeln!(out, "asset: {a}");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(feature = "stl")]
pub struct Stl;
#[cfg(feature = "stl")]
impl Adapter for Stl {
    fn name(&self) -> &'static str {
        "stl"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["stl"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.starts_with(b"solid") {
            // ASCII STL is plain text — search it raw (bail semantics)
            return Ok(Outcome::Bail("ascii stl is plain text".into()));
        }
        if data.len() < 84 {
            decline!("unrecognized stl file");
        }
        let header = String::from_utf8_lossy(&data[..80]).trim().to_string();
        let count = rd_u32(data, 80);
        Ok(Outcome::Text(
            format!("stl: {count} triangles\nheader: {header}\n").into_bytes(),
        ))
    }
}

#[cfg(feature = "ply")]
pub struct Ply;
#[cfg(feature = "ply")]
impl Adapter for Ply {
    fn name(&self) -> &'static str {
        "ply"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ply"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if !data.starts_with(b"ply") {
            decline!("not a ply file");
        }
        let header_end = find_subslice(data, b"end_header").context("ply header not terminated")?;
        let header = String::from_utf8_lossy(&data[..header_end]).to_string();
        if header.contains("format ascii") {
            return Ok(Outcome::Bail("ascii ply is plain text".into()));
        }
        // keep only the header lines (element/property structure)
        Ok(Outcome::Text(header.into_bytes()))
    }
}

#[cfg(any(feature = "ply", feature = "fbx", feature = "pcd", feature = "vtk"))]
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    rgx_core::memchr::memmem::find(hay, needle)
}

/// Binary FBX: walk the node record tree, print node names + string props.
/// ASCII FBX bails to plain-text search.
#[cfg(feature = "fbx")]
pub struct Fbx;
#[cfg(feature = "fbx")]
impl Adapter for Fbx {
    fn name(&self) -> &'static str {
        "fbx"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["fbx"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        const MAGIC: &[u8; 23] = b"Kaydara FBX Binary  \x00\x1a\x00";
        if data.len() < 27 || &data[..23] != MAGIC {
            if data.starts_with(b"; FBX")
                || find_subslice(&data[..64.min(data.len())], b"FBXHeaderExtension").is_some()
            {
                return Ok(Outcome::Bail("ascii fbx is plain text".into()));
            }
            decline!("not a binary fbx file");
        }
        let version = rd_u32(data, 23);
        let ver740 = version >= 7400;
        let mut out = format!("fbx version: {version}\n");
        let mut pos = 27usize;
        let end = data.len();
        walk_fbx_nodes(data, &mut pos, end, ver740, 0, &mut out)?;
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(feature = "fbx")]
fn walk_fbx_nodes(
    d: &[u8],
    pos: &mut usize,
    limit: usize,
    ver740: bool,
    depth: usize,
    out: &mut String,
) -> Result<()> {
    if depth > 64 {
        return Ok(());
    }
    loop {
        let (end_off, _nprops, prop_len) = if ver740 {
            if *pos + 25 > d.len() {
                return Ok(());
            }
            let end = u64::from_le_bytes(d[*pos..*pos + 8].try_into()?) as usize;
            if end == 0 {
                return Ok(()); // null record = end of sibling list
            }
            (
                end,
                rd_u32(d, *pos + 8),
                d[*pos + 12..*pos + 20].try_into().map(u64::from_le_bytes)? as usize,
            )
        } else {
            if *pos + 13 > d.len() {
                return Ok(());
            }
            let end = rd_u32(d, *pos) as usize;
            if end == 0 {
                return Ok(());
            }
            (end, rd_u32(d, *pos + 4), rd_u32(d, *pos + 8) as usize)
        };
        let nlen_off = if ver740 { 20 } else { 12 };
        let nlen = d[*pos + nlen_off] as usize;
        let name_start = *pos + nlen_off + 1;
        let name_end = name_start.saturating_add(nlen);
        if name_end > d.len() {
            return Ok(()); // truncated record name
        }
        let name = String::from_utf8_lossy(&d[name_start..name_end]).to_string();
        out.push_str(&"  ".repeat(depth));
        let _ = writeln!(out, "node: {name}");
        // parse string properties (type 'S')
        let mut p = name_start + nlen;
        let prop_end = p.saturating_add(prop_len);
        while p + 1 < prop_end.min(d.len()) {
            match d[p] {
                b'S' | b'R' => {
                    let Some(lb) = d.get(p + 1..p + 5) else { break };
                    let len = u32::from_le_bytes(lb.try_into().unwrap()) as usize;
                    if p + 5 + len <= d.len() {
                        let s = String::from_utf8_lossy(&d[p + 5..p + 5 + len]).to_string();
                        out.push_str(&"  ".repeat(depth));
                        let _ = writeln!(out, "  S: {s}");
                        p += 5 + len;
                    } else {
                        break;
                    }
                }
                b'C' | b'B' | b'Y' | b'I' | b'F' | b'D' | b'L' => {
                    p += match d[p] {
                        b'C' | b'B' | b'Y' => 2,
                        b'I' | b'F' => 5,
                        _ => 9,
                    };
                }
                b'i' | b'f' | b'l' | b'd' | b'b' => {
                    // array: [type][n u32][encoding u32][complen u32][data]
                    let Some(lb) = d.get(p + 9..p + 13) else {
                        break;
                    };
                    let data_len = u32::from_le_bytes(lb.try_into().unwrap()) as usize;
                    p = p.saturating_add(13).saturating_add(data_len);
                }
                _ => break,
            }
        }
        let record_start = *pos;
        // prop_len comes from the file and can be u64::MAX on fuzzed input
        *pos = name_start.saturating_add(nlen).saturating_add(prop_len);
        // nested children live before end_off
        if *pos < end_off.saturating_sub(if ver740 { 25 } else { 13 }) && end_off <= d.len() {
            walk_fbx_nodes(d, pos, end_off, ver740, depth + 1, out)?;
        }
        *pos = end_off;
        // a record whose end does not move past its own start would loop
        // forever — fuzzed headers craft exactly that
        if end_off <= record_start || *pos >= limit {
            return Ok(());
        }
    }
}

#[cfg(feature = "pcd")]
pub struct Pcd;
#[cfg(feature = "pcd")]
impl Adapter for Pcd {
    fn name(&self) -> &'static str {
        "pcd"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["pcd"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let header_end =
            find_subslice(data, b"DATA").decline_context("pcd header has no DATA line")?;
        let header = String::from_utf8_lossy(&data[..header_end]).to_string();
        if header.contains("DATA ascii") {
            return Ok(Outcome::Bail("ascii pcd is plain text".into()));
        }
        Ok(Outcome::Text(header.into_bytes()))
    }
}

/// LAS point clouds, and the LAZ files LASzip produces from them.
///
/// **What this is.** A LAS file is a public header block, a list of VLRs
/// and the point records. A LAZ file is the same header block and the same
/// VLR list -- LASzip stores both verbatim -- with the point records
/// replaced by LASzip's compressed form. So every header field below is the
/// same number in a `.las` and in a `.laz`.
///
/// **What is read.** The point records, in both forms: a `.las` yields them
/// from the file, a `.laz` from the LASzip decompressor below. The
/// decompressor is the arithmetic coder and the per-field compressors of
/// the LASzip reference implementation, so the two paths print the same
/// line for the same point. That equality is the whole point: a `.laz`
/// whose numbers differ from its uncompressed twin is a `.laz` nobody can
/// search.
///
/// **What is refused.** The LAS 1.4 native compressor (LASzip item version
/// 3 and 4 -- the `POINT14` and `RGBNIR14` items) and the LASzip 1.x item
/// compressors (item version 1). They are different item sets behind
/// different chunk tables, and one decoder stretched over all of them is
/// right about none of them. A refused file keeps its header numbers and
/// says why the points are missing.
#[cfg(feature = "las")]
pub struct Las;
#[cfg(feature = "las")]
impl Adapter for Las {
    fn name(&self) -> &'static str {
        "las"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["las", "laz"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 227 || &data[0..4] != b"LASF" {
            decline!("not a LAS file (bad signature)");
        }
        Ok(Outcome::Text(las_report(data).into_bytes()))
    }
}

/// Ceiling on the point records reported for one file. A cloud with more
/// points than this is truncated: the header's own count says how many
/// the file holds, so a report that stops short of it is visibly short.
#[cfg(feature = "las")]
const MAX_LAS_POINTS: usize = 100_000;

/// Ceiling on the rendered point report.
#[cfg(feature = "las")]
const MAX_LAS_OUT: usize = 16 << 20;

/// The public header block of a LAS file, which LASzip stores verbatim in
/// a `.laz`: the same bytes, so the same numbers.
#[cfg(feature = "las")]
struct LasHeader {
    version: (u8, u8),
    point_format: u8,
    point_len: u16,
    header_size: u16,
    /// The number of point records the file claims.
    count: u64,
    /// Where the point data starts.
    point_offset: u32,
    scale: [f64; 3],
    offset: [f64; 3],
    /// The bounding box the header states: (min, max) per axis.
    bbox: ([f64; 3], [f64; 3]),
}

#[cfg(feature = "las")]
fn las_header(data: &[u8]) -> LasHeader {
    let version = (data[24], data[25]);
    let header_size = u16::from_le_bytes([data[94], data[95]]);
    // LAS 1.4 moved the point count into a field of its own and leaves the
    // legacy count at 107 zero, so reporting the legacy count would report
    // no points at all for a LAS 1.4 file.
    let count = if version.0 > 1 || (version.0 == 1 && version.1 >= 4) {
        if header_size >= 375 && data.len() >= 255 {
            u64::from_le_bytes(data[247..255].try_into().unwrap())
        } else {
            rd_u32(data, 107) as u64
        }
    } else {
        rd_u32(data, 107) as u64
    };
    LasHeader {
        version,
        point_format: data[104] & 0x3f,
        point_len: u16::from_le_bytes([data[105], data[106]]),
        header_size,
        count,
        point_offset: rd_u32(data, 96),
        scale: [rd_f64(data, 131), rd_f64(data, 139), rd_f64(data, 147)],
        offset: [rd_f64(data, 155), rd_f64(data, 163), rd_f64(data, 171)],
        bbox: (
            [rd_f64(data, 187), rd_f64(data, 203), rd_f64(data, 219)],
            [rd_f64(data, 179), rd_f64(data, 195), rd_f64(data, 211)],
        ),
    }
}

/// A point record reduced to the fields the report prints. The raw `.las`
/// path and the decompressed `.laz` path both build one, so the two render
/// the same line for the same point.
#[cfg(feature = "las")]
#[derive(Clone, Copy)]
struct LasPoint {
    x: i32,
    y: i32,
    z: i32,
    intensity: u16,
    flags: u8,
    classification: u8,
    scan_angle: i8,
    user_data: u8,
    point_source: u16,
    gps_time: Option<f64>,
    rgb: Option<(u16, u16, u16)>,
}

/// The point records of an uncompressed `.las`, in the layout the point
/// format prescribes: formats 1, 3, 4 and 5 carry a GPS time, formats 2
/// to 5 carry RGB.
#[cfg(feature = "las")]
fn las_raw_points(data: &[u8], hdr: &LasHeader) -> core::result::Result<Vec<LasPoint>, String> {
    let rec = hdr.point_len as usize;
    if rec == 0 {
        return Err("the point record length in the header is zero".into());
    }
    let has_gps = matches!(hdr.point_format, 1 | 3 | 4 | 5);
    let has_rgb = matches!(hdr.point_format, 2..=5);
    let rgb_at = if has_gps { 28 } else { 20 };
    let mut out = Vec::new();
    let mut off = hdr.point_offset as usize;
    for _ in 0..hdr.count.min(MAX_LAS_POINTS as u64) {
        if off + rec > data.len() {
            break;
        }
        let p = &data[off..off + rec];
        let gps_time = if has_gps && rec >= 28 {
            Some(f64::from_le_bytes(p[20..28].try_into().unwrap()))
        } else {
            None
        };
        let rgb = if has_rgb && rec >= rgb_at + 6 {
            Some((
                u16::from_le_bytes([p[rgb_at], p[rgb_at + 1]]),
                u16::from_le_bytes([p[rgb_at + 2], p[rgb_at + 3]]),
                u16::from_le_bytes([p[rgb_at + 4], p[rgb_at + 5]]),
            ))
        } else {
            None
        };
        out.push(LasPoint {
            x: i32::from_le_bytes([p[0], p[1], p[2], p[3]]),
            y: i32::from_le_bytes([p[4], p[5], p[6], p[7]]),
            z: i32::from_le_bytes([p[8], p[9], p[10], p[11]]),
            intensity: u16::from_le_bytes([p[12], p[13]]),
            flags: p[14],
            classification: p[15],
            scan_angle: p[16] as i8,
            user_data: p[17],
            point_source: u16::from_le_bytes([p[18], p[19]]),
            gps_time,
            rgb,
        });
        off += rec;
    }
    Ok(out)
}

/// The LASzip VLR: the record that says the point data is compressed, and
/// how. Its user id is `laszip encoded` and its record id is 22204.
#[cfg(feature = "las")]
struct LaszipVlr {
    compressor: u16,
    chunk_size: u32,
    /// The items the point record is split into: (type, size, version).
    items: Vec<(u16, u16, u16)>,
}

/// The LASzip item types this adapter decodes.
#[cfg(feature = "las")]
const LASZIP_ITEM_POINT10: u16 = 6;
#[cfg(feature = "las")]
const LASZIP_ITEM_GPSTIME11: u16 = 7;
#[cfg(feature = "las")]
const LASZIP_ITEM_RGB12: u16 = 8;

/// The LASzip compressor identifiers (`LASZIP_COMPRESSOR_*`).
#[cfg(feature = "las")]
const LASZIP_COMPRESSOR_POINTWISE: u16 = 1;
#[cfg(feature = "las")]
const LASZIP_COMPRESSOR_POINTWISE_CHUNKED: u16 = 2;

/// Find the LASzip VLR among the VLRs, if the file has one.
#[cfg(feature = "las")]
fn laszip_vlr(data: &[u8], hdr: &LasHeader) -> Option<LaszipVlr> {
    let count = rd_u32(data, 100) as usize;
    let mut pos = hdr.header_size as usize;
    for _ in 0..count {
        if pos + 54 > data.len() {
            return None;
        }
        let rec_len = u16::from_le_bytes([data[pos + 20], data[pos + 21]]) as usize;
        if data[pos + 2..pos + 16] == *b"laszip encoded"
            && u16::from_le_bytes([data[pos + 18], data[pos + 19]]) == 22204
        {
            let d = pos + 54;
            if d + 34 > data.len() {
                return None;
            }
            let n_items = u16::from_le_bytes([data[d + 32], data[d + 33]]) as usize;
            let mut items = Vec::with_capacity(n_items);
            let mut q = d + 34;
            for _ in 0..n_items {
                if q + 6 > data.len() {
                    return None;
                }
                items.push((
                    u16::from_le_bytes([data[q], data[q + 1]]),
                    u16::from_le_bytes([data[q + 2], data[q + 3]]),
                    u16::from_le_bytes([data[q + 4], data[q + 5]]),
                ));
                q += 6;
            }
            return Some(LaszipVlr {
                compressor: u16::from_le_bytes([data[d], data[d + 1]]),
                chunk_size: rd_u32(data, d + 12),
                items,
            });
        }
        pos += 54 + rec_len;
    }
    None
}

/// The point records of a `.laz`, decoded with the LASzip decompressor.
///
/// The failure is a reason, not an error: a `.laz` this adapter cannot
/// decode is still a file whose header it can report, and the report says
/// which compressor it did not read.
#[cfg(feature = "las")]
fn laszip_points(
    data: &[u8],
    hdr: &LasHeader,
    vlr: &LaszipVlr,
) -> core::result::Result<Vec<LasPoint>, String> {
    // Only the version-2 items are decoded here. The other two item
    // versions are different compressors over different fields.
    for (ty, _, version) in &vlr.items {
        match version {
            2 => {}
            1 => {
                return Err(format!(
                    "the LASzip 1.x item compressors (item version 1, item type {ty}) are not decoded here"
                ))
            }
            3 | 4 => {
                return Err(format!(
                    "the LAS 1.4 native item compressors (item version {version}, item type {ty}) are not decoded here"
                ))
            }
            other => {
                return Err(format!(
                    "LASzip item type {ty} uses item version {other}, which is not decoded here"
                ))
            }
        }
    }
    let mut has_point = false;
    let mut has_gps = false;
    let mut has_rgb = false;
    for (ty, size, _) in &vlr.items {
        match *ty {
            LASZIP_ITEM_POINT10 => {
                if *size != 20 {
                    return Err(format!("the LASzip point item has size {size}, not 20"));
                }
                has_point = true;
            }
            LASZIP_ITEM_GPSTIME11 => {
                if *size != 8 {
                    return Err(format!("the LASzip GPS time item has size {size}, not 8"));
                }
                has_gps = true;
            }
            LASZIP_ITEM_RGB12 => {
                if *size != 6 {
                    return Err(format!("the LASzip RGB item has size {size}, not 6"));
                }
                has_rgb = true;
            }
            other => return Err(format!("LASzip item type {other} is not decoded here")),
        }
    }
    if !has_point {
        return Err("the LASzip item list has no point item".into());
    }
    match vlr.compressor {
        LASZIP_COMPRESSOR_POINTWISE | LASZIP_COMPRESSOR_POINTWISE_CHUNKED => {}
        other => return Err(format!("the LASzip compressor {other} is not decoded here")),
    }

    // The chunked compressor puts an eight-byte pointer to the chunk
    // table at the point data offset, and the chunks follow it. The
    // pointwise compressor has no chunk table: the compressed points
    // follow the header directly.
    let chunked = vlr.compressor == LASZIP_COMPRESSOR_POINTWISE_CHUNKED;
    let off = hdr.point_offset as usize;
    let (chunks_start, table_at) = if chunked {
        if off + 8 > data.len() {
            return Err("the point data offset points past the end of the file".into());
        }
        (
            off as u64 + 8,
            i64::from_le_bytes(data[off..off + 8].try_into().unwrap()),
        )
    } else {
        (off as u64, -1)
    };

    // The chunk table: a version, a chunk count, and the chunk sizes
    // arithmetic-coded with the previous size as the prediction.
    let mut starts: Vec<u64> = Vec::new();
    let mut counts: Vec<u64> = Vec::new();
    if chunked {
        if table_at < 0 || table_at as u64 + 8 > data.len() as u64 {
            return Err("the chunk table is missing".into());
        }
        let t = table_at as usize;
        let version = rd_u32(data, t);
        if version != 0 {
            return Err(format!("the chunk table has version {version}"));
        }
        let n = rd_u32(data, t + 4) as usize;
        // A chunk holds at least one point and occupies at least one byte of
        // the file, so the point count and the file's own length bound the
        // table. Without that bound a mutated count asks the decoder to
        // grind through a million chunk sizes out of an arithmetic stream
        // that never runs dry -- seconds of work on a file that is refused
        // anyway, and the reason a `.laz` could take longer than the
        // watchdog the fuzz kit gives it.
        if n == 0 || n > 1_000_000 || n as u64 > hdr.count || n > data.len() {
            return Err(format!("the chunk table declares {n} chunks"));
        }
        let mut arith = Arith::new(&data[t + 8..]);
        let mut ic = IntComp::new(32, 2);
        ic.init();
        // A chunk size of `u32::MAX` means the chunks hold a varying
        // number of points; the table then codes those counts too, in
        // the second context.
        let variable = vlr.chunk_size == u32::MAX;
        let mut prev_bytes = 0i32;
        let mut prev_count = 0i32;
        let mut sizes = Vec::with_capacity(n);
        for _ in 0..n {
            // The reference throws the moment the chunk runs out of bytes.
            // This decoder has to notice it here, inside the loop: a stream
            // that ran dry still hands back a value per iteration, and a
            // table that declares a million chunks would cost seconds to
            // refuse.
            if arith.starved {
                return Err("the chunk table is truncated".into());
            }
            if variable {
                let c = ic.decompress(&mut arith, prev_count, 0);
                prev_count = c;
                counts.push(c as u32 as u64);
            }
            let b = ic.decompress(&mut arith, prev_bytes, 1);
            prev_bytes = b;
            sizes.push(b as u32 as u64);
        }
        if arith.starved {
            return Err("the chunk table is truncated".into());
        }
        // The chunk starts are the cumulative sum of the chunk byte
        // sizes, counted from the first chunk.
        let mut at = chunks_start;
        starts.push(at);
        for size in sizes {
            at += size;
            starts.push(at);
        }
        if !variable {
            let fixed = vlr.chunk_size as u64;
            let mut left = hdr.count;
            for _ in 0..n {
                let take = fixed.min(left);
                counts.push(take);
                left -= take;
            }
        }
    } else {
        // One implicit chunk holding every point.
        starts.push(chunks_start);
        counts.push(hdr.count);
    }

    let mut point10 = LaszipPoint10::new();
    let mut gps = LaszipGpsTime::new();
    let mut rgb = LaszipRgb12::new();
    let mut out: Vec<LasPoint> = Vec::new();
    // The raw first point of a chunk holds the items the file has, in
    // order: the point, then the GPS time, then the colour.
    let raw_len = 20 + if has_gps { 8 } else { 0 } + if has_rgb { 6 } else { 0 };
    for (ci, start) in starts.iter().enumerate() {
        let n_in = counts.get(ci).copied().unwrap_or(0);
        if n_in == 0 {
            continue;
        }
        let start = *start as usize;
        // Every chunk starts with the raw bytes of its first point, and
        // the compressed stream follows them.
        if start + raw_len > data.len() {
            return Err(format!("chunk {ci} is truncated"));
        }
        let raw = &data[start..start + raw_len];
        let mut first = [0u8; 20];
        let mut first_gps = [0u8; 8];
        let mut first_rgb = [0u8; 6];
        first.copy_from_slice(&raw[0..20]);
        let mut at = 20;
        if has_gps {
            first_gps.copy_from_slice(&raw[at..at + 8]);
            at += 8;
        }
        if has_rgb {
            first_rgb.copy_from_slice(&raw[at..at + 6]);
        }
        point10.init(&first);
        gps.init(&first_gps);
        rgb.init(&first_rgb);
        out.push(laszip_point(
            &first, &first_gps, &first_rgb, has_gps, has_rgb,
        ));
        let mut arith = Arith::new(&data[start + raw_len..]);
        for _ in 1..n_in {
            let mut p = [0u8; 20];
            let mut g = [0u8; 8];
            let mut r = [0u8; 6];
            point10.read(&mut arith, &mut p);
            // Only the items the file has are read: a reader for an
            // item that is not there would take bytes from the
            // arithmetic stream that belong to another field.
            if has_gps {
                gps.read(&mut arith, &mut g)?;
            }
            if has_rgb {
                rgb.read(&mut arith, &mut r);
            }
            out.push(laszip_point(&p, &g, &r, has_gps, has_rgb));
            // Same rule as the chunk table: the stream that ran dry has to
            // stop the loop here. A dead stream still yields a point per
            // iteration, and the point count comes from the file's own
            // header — so a file that claims a hundred thousand points
            // would cost seconds to refuse, on bytes that carry nothing.
            if arith.starved {
                return Err(format!(
                    "chunk {ci} ran out of compressed bytes after {} points",
                    out.len()
                ));
            }
            if out.len() >= MAX_LAS_POINTS {
                return Ok(out);
            }
        }
        if arith.starved {
            return Err(format!(
                "chunk {ci} ran out of compressed bytes after {} points",
                out.len()
            ));
        }
    }
    Ok(out)
}

/// The point the decompressed items describe.
#[cfg(feature = "las")]
fn laszip_point(p: &[u8; 20], g: &[u8; 8], r: &[u8; 6], has_gps: bool, has_rgb: bool) -> LasPoint {
    LasPoint {
        x: i32::from_le_bytes([p[0], p[1], p[2], p[3]]),
        y: i32::from_le_bytes([p[4], p[5], p[6], p[7]]),
        z: i32::from_le_bytes([p[8], p[9], p[10], p[11]]),
        intensity: u16::from_le_bytes([p[12], p[13]]),
        flags: p[14],
        classification: p[15],
        scan_angle: p[16] as i8,
        user_data: p[17],
        point_source: u16::from_le_bytes([p[18], p[19]]),
        gps_time: if has_gps {
            Some(f64::from_le_bytes(g[0..8].try_into().unwrap()))
        } else {
            None
        },
        rgb: if has_rgb {
            Some((
                u16::from_le_bytes([r[0], r[1]]),
                u16::from_le_bytes([r[2], r[3]]),
                u16::from_le_bytes([r[4], r[5]]),
            ))
        } else {
            None
        },
    }
}

/// The report of a LAS or LAZ file: the header, then the point records.
#[cfg(feature = "las")]
fn las_report(data: &[u8]) -> String {
    let hdr = las_header(data);
    let mut out = String::new();
    let _ = writeln!(out, "las version: {}.{}", hdr.version.0, hdr.version.1);
    let _ = writeln!(out, "point format: {}", hdr.point_format);
    let _ = writeln!(out, "points: {}", hdr.count);
    let _ = writeln!(
        out,
        "bbox: ({},{},{}) .. ({},{},{})",
        hdr.bbox.0[0], hdr.bbox.0[1], hdr.bbox.0[2], hdr.bbox.1[0], hdr.bbox.1[1], hdr.bbox.1[2]
    );
    let points = match laszip_vlr(data, &hdr) {
        Some(vlr) => laszip_points(data, &hdr, &vlr),
        None => las_raw_points(data, &hdr),
    };
    match points {
        Ok(pts) => {
            for (i, p) in pts.iter().enumerate() {
                if out.len() >= MAX_LAS_OUT {
                    let _ = writeln!(
                        out,
                        "the point report stops here: the file is larger than the report ceiling"
                    );
                    break;
                }
                las_push_point(&mut out, i, p, &hdr);
            }
        }
        Err(reason) => {
            let _ = writeln!(out, "the point records are not decoded: {reason}");
        }
    }
    out
}

/// One point record, on one line, in the scaled coordinates the header
/// states -- the numbers a reader of the cloud sees.
#[cfg(feature = "las")]
fn las_push_point(out: &mut String, idx: usize, p: &LasPoint, hdr: &LasHeader) {
    let x = p.x as f64 * hdr.scale[0] + hdr.offset[0];
    let y = p.y as f64 * hdr.scale[1] + hdr.offset[1];
    let z = p.z as f64 * hdr.scale[2] + hdr.offset[2];
    let _ = write!(
        out,
        "point {}: x={} y={} z={} intensity={} flags=0x{:02x} class={} scan_angle={} user_data={} point_source={}",
        idx, x, y, z, p.intensity, p.flags, p.classification, p.scan_angle, p.user_data, p.point_source
    );
    if let Some(t) = p.gps_time {
        let _ = write!(out, " gps_time={t}");
    }
    if let Some((r, g, b)) = p.rgb {
        let _ = write!(out, " rgb={r},{g},{b}");
    }
    out.push('\n');
}

// ---------- LASzip: the arithmetic decoder and the item compressors ----------

/// The renormalisation threshold of the arithmetic coder
/// (`AC__MinLength`): below this interval length the decoder pulls a byte
/// in and multiplies the length by 256.
#[cfg(feature = "las")]
const AC_MIN_LENGTH: u32 = 0x0100_0000;

/// The interval length the decoder starts with (`AC__MaxLength`).
#[cfg(feature = "las")]
const AC_MAX_LENGTH: u32 = 0xFFFF_FFFF;

/// The length shift of the binary models (`BM__LengthShift`).
#[cfg(feature = "las")]
const BM_LENGTH_SHIFT: u32 = 13;

/// The length shift of the symbol models (`DM__LengthShift`).
#[cfg(feature = "las")]
const DM_LENGTH_SHIFT: u32 = 15;

/// The count at which a model halves its counts (`BM__MaxCount`,
/// `DM__MaxCount`).
#[cfg(feature = "las")]
const BM_MAX_COUNT: u32 = 1 << BM_LENGTH_SHIFT;
#[cfg(feature = "las")]
const DM_MAX_COUNT: u32 = 1 << DM_LENGTH_SHIFT;

/// The arithmetic decoder of the LASzip reference implementation
/// (`ArithmeticDecoder` in `src/arithmeticdecoder.cpp`), itself Amir Said's
/// FastAC with 32-bit intervals.
///
/// The interval arithmetic is the reference's: the value and the length
/// are 32-bit, the length is renormalised by pulling bytes in from the
/// chunk, and every product is a wrapping 32-bit product. The wrapping
/// matters -- the reference relies on it, and a decoder that treats the
/// overflow as an error stops on the first symbol whose interval product
/// leaves the 32-bit range.
#[cfg(feature = "las")]
struct Arith<'a> {
    src: &'a [u8],
    value: u32,
    length: u32,
    /// Set when the chunk ran out of bytes. The reference throws there;
    /// this decoder stops, and the caller turns that into a refusal.
    starved: bool,
}

#[cfg(feature = "las")]
impl<'a> Arith<'a> {
    /// Start a decoder on a chunk's compressed bytes. The reference reads
    /// the first four bytes big-endian as the initial value and starts
    /// with the full 32-bit interval.
    fn new(src: &'a [u8]) -> Self {
        let mut value = 0u32;
        for i in 0..4 {
            value = (value << 8) | src.get(i).copied().unwrap_or(0) as u32;
        }
        let starved = src.len() < 4;
        Arith {
            src: &src[4.min(src.len())..],
            value,
            length: AC_MAX_LENGTH,
            starved,
        }
    }

    fn byte(&mut self) -> u32 {
        match self.src.split_first() {
            Some((&b, rest)) => {
                self.src = rest;
                b as u32
            }
            None => {
                self.starved = true;
                0
            }
        }
    }

    /// Pull bytes in until the interval is long enough again.
    fn renorm(&mut self) {
        // An interval that collapsed to zero would shift into zero for
        // ever -- 0 << 8 is still 0 -- and the loop below would never end.
        // The reference cannot reach a zero interval: its search always
        // lands on a symbol whose interval is not empty. This one can, if
        // the model gave two symbols the same cumulative count, so the
        // guard is here rather than a hope.
        if self.length == 0 {
            self.starved = true;
            return;
        }
        loop {
            self.value = (self.value << 8) | self.byte();
            self.length <<= 8;
            if self.length >= AC_MIN_LENGTH {
                break;
            }
        }
    }

    /// Decode a bit with the given binary model.
    fn decode_bit(&mut self, m: &mut ArithBit) -> u32 {
        let x = m.bit_0_prob.wrapping_mul(self.length >> BM_LENGTH_SHIFT);
        let sym = u32::from(self.value >= x);
        if sym == 0 {
            self.length = x;
            m.bit_0_count = m.bit_0_count.saturating_add(1);
        } else {
            self.value -= x;
            self.length -= x;
        }
        if self.length < AC_MIN_LENGTH {
            self.renorm();
        }
        m.bits_until_update = m.bits_until_update.saturating_sub(1);
        if m.bits_until_update == 0 {
            m.update();
        }
        sym
    }

    /// Decode a symbol with the given model.
    fn decode_symbol(&mut self, m: &mut ArithModel) -> u32 {
        // A collapsed interval divides by zero below, and `renorm`'s
        // guard stops the loop without repairing the length: a wrapped
        // product in the previous symbol can leave exactly that, and
        // `starved` is only read between points, not between the four
        // decodes one point performs.
        if self.length == 0 {
            self.starved = true;
            return 0;
        }
        // The reference takes the interval length as the upper bound
        // before it shifts the length down, so the bound is the length
        // the decoder came in with.
        let mut y = self.length;
        let mut sym = 0u32;
        let mut x = 0u32;
        if m.table_size != 0 {
            self.length >>= DM_LENGTH_SHIFT;
            let dv = self.value / self.length;
            let t = (dv >> m.table_shift) as usize;
            sym = m.decoder_table[t];
            let mut n = m.decoder_table[t + 1] + 1;
            while n > sym + 1 {
                let k = (sym + n) >> 1;
                if m.distribution[k as usize] > dv {
                    n = k;
                } else {
                    sym = k;
                }
            }
            x = m.distribution[sym as usize].wrapping_mul(self.length);
            if sym != m.last_symbol {
                y = m.distribution[sym as usize + 1].wrapping_mul(self.length);
            }
        } else {
            self.length >>= DM_LENGTH_SHIFT;
            let mut n = m.symbols;
            let mut k = n >> 1;
            loop {
                let z = self.length.wrapping_mul(m.distribution[k as usize]);
                if z > self.value {
                    n = k;
                    y = z;
                } else {
                    sym = k;
                    x = z;
                }
                k = (sym + n) >> 1;
                if k == sym {
                    break;
                }
            }
        }
        self.value -= x;
        self.length = y - x;
        if self.length < AC_MIN_LENGTH {
            self.renorm();
        }
        m.symbol_count[sym as usize] = m.symbol_count[sym as usize].saturating_add(1);
        m.symbols_until_update = m.symbols_until_update.saturating_sub(1);
        if m.symbols_until_update == 0 {
            m.update();
        }
        sym
    }

    /// Decode `bits` bits without a model.
    fn read_bits(&mut self, bits: u32) -> u32 {
        if bits > 19 {
            let low = self.read_short();
            return (self.read_bits(bits - 16) << 16) | low;
        }
        // As in `decode_symbol`: a zero interval must not reach the
        // division.
        if self.length == 0 {
            self.starved = true;
            return 0;
        }
        self.length >>= bits;
        let sym = self.value / self.length;
        self.value -= self.length.wrapping_mul(sym);
        if self.length < AC_MIN_LENGTH {
            self.renorm();
        }
        sym
    }

    /// Decode sixteen bits without a model.
    fn read_short(&mut self) -> u32 {
        // As in `decode_symbol`: a zero interval must not reach the
        // division.
        if self.length == 0 {
            self.starved = true;
            return 0;
        }
        self.length >>= 16;
        let sym = self.value / self.length;
        self.value -= self.length.wrapping_mul(sym);
        if self.length < AC_MIN_LENGTH {
            self.renorm();
        }
        sym
    }

    /// Decode thirty-two bits without a model.
    fn read_int(&mut self) -> u32 {
        let lower = self.read_short();
        let upper = self.read_short();
        (upper << 16) | lower
    }
}

/// A symbol model of the arithmetic coder (`ArithmeticModel` in the
/// reference). It keeps the frequency of every symbol, turns those into
/// a cumulative distribution, and halves the counts when they grow past
/// the ceiling -- the adaptation that makes the coder's model follow the
/// data.
#[cfg(feature = "las")]
struct ArithModel {
    symbols: u32,
    last_symbol: u32,
    distribution: Vec<u32>,
    symbol_count: Vec<u32>,
    /// The lookup table the reference uses for models with more than
    /// sixteen symbols; empty for the small ones.
    decoder_table: Vec<u32>,
    table_size: u32,
    table_shift: u32,
    total_count: u32,
    update_cycle: u32,
    symbols_until_update: u32,
}

#[cfg(feature = "las")]
impl ArithModel {
    fn new(symbols: u32) -> Self {
        ArithModel {
            symbols,
            last_symbol: 0,
            distribution: Vec::new(),
            symbol_count: Vec::new(),
            decoder_table: Vec::new(),
            table_size: 0,
            table_shift: 0,
            total_count: 0,
            update_cycle: 0,
            symbols_until_update: 0,
        }
    }

    /// Reset the model to equiprobable symbols.
    fn init(&mut self) {
        if self.distribution.is_empty() {
            self.last_symbol = self.symbols - 1;
            if self.symbols > 16 {
                let mut table_bits = 3u32;
                while self.symbols > (1u32 << (table_bits + 2)) {
                    table_bits += 1;
                }
                self.table_size = 1u32 << table_bits;
                self.table_shift = DM_LENGTH_SHIFT - table_bits;
                self.decoder_table = vec![0u32; self.table_size as usize + 2];
            }
            self.distribution = vec![0u32; 2 * self.symbols as usize];
            self.symbol_count = vec![1u32; self.symbols as usize];
        }
        self.total_count = 0;
        self.update_cycle = self.symbols;
        self.update();
        self.symbols_until_update = (self.symbols + 6) >> 1;
        self.update_cycle = (self.symbols + 6) >> 1;
    }

    /// Recompute the distribution from the symbol counts.
    fn update(&mut self) {
        self.total_count = self.total_count.wrapping_add(self.update_cycle);
        if self.total_count > DM_MAX_COUNT {
            self.total_count = 0;
            for count in self.symbol_count.iter_mut() {
                *count = (*count + 1) >> 1;
                self.total_count = self.total_count.wrapping_add(*count);
            }
        }
        let scale = 0x8000_0000u32 / self.total_count;
        let mut sum = 0u32;
        let mut s = 0u32;
        if self.table_size == 0 {
            for k in 0..self.symbols as usize {
                self.distribution[k] = scale.wrapping_mul(sum) >> (31 - DM_LENGTH_SHIFT);
                sum = sum.wrapping_add(self.symbol_count[k]);
            }
        } else {
            for k in 0..self.symbols as usize {
                self.distribution[k] = scale.wrapping_mul(sum) >> (31 - DM_LENGTH_SHIFT);
                sum = sum.wrapping_add(self.symbol_count[k]);
                let w = self.distribution[k] >> self.table_shift;
                while s < w {
                    s += 1;
                    self.decoder_table[s as usize] = (k as u32).wrapping_sub(1);
                }
            }
            self.decoder_table[0] = 0;
            while s <= self.table_size {
                s += 1;
                self.decoder_table[s as usize] = self.symbols - 1;
            }
        }
        self.update_cycle = (5 * self.update_cycle) >> 2;
        let max_cycle = (self.symbols + 6) << 3;
        if self.update_cycle > max_cycle {
            self.update_cycle = max_cycle;
        }
        self.symbols_until_update = self.update_cycle;
    }
}

/// A binary model of the arithmetic coder (`ArithmeticBitModel` in the
/// reference): the probability that the next bit is zero.
#[cfg(feature = "las")]
struct ArithBit {
    update_cycle: u32,
    bits_until_update: u32,
    bit_0_prob: u32,
    bit_0_count: u32,
    bit_count: u32,
}

#[cfg(feature = "las")]
impl ArithBit {
    fn new() -> Self {
        ArithBit {
            update_cycle: 4,
            bits_until_update: 4,
            bit_0_prob: 1u32 << (BM_LENGTH_SHIFT - 1),
            bit_0_count: 1,
            bit_count: 2,
        }
    }

    fn init(&mut self) {
        *self = ArithBit::new();
    }

    /// Recompute the bit probability from the counts.
    fn update(&mut self) {
        self.bit_count = self.bit_count.wrapping_add(self.update_cycle);
        if self.bit_count > BM_MAX_COUNT {
            self.bit_count = (self.bit_count + 1) >> 1;
            self.bit_0_count = (self.bit_0_count + 1) >> 1;
            if self.bit_0_count == self.bit_count {
                self.bit_count += 1;
            }
        }
        let scale = 0x8000_0000u32 / self.bit_count;
        self.bit_0_prob = (self.bit_0_count.wrapping_mul(scale)) >> (31 - BM_LENGTH_SHIFT);
        self.update_cycle = (5 * self.update_cycle) >> 2;
        if self.update_cycle > 64 {
            self.update_cycle = 64;
        }
        self.bits_until_update = self.update_cycle;
    }
}

/// The integer compressor of the LASzip reference implementation
/// (`IntegerCompressor` in `src/integercompressor.cpp`): a value is coded
/// as the number of significant bits it needs, then as its position in
/// the interval those bits describe.
#[cfg(feature = "las")]
struct IntComp {
    bits_high: u32,
    corr_range: u32,
    corr_min: i32,
    /// The model that codes how many bits the corrector needs.
    m_bits: Vec<ArithModel>,
    /// The models that code the corrector itself, one per bit count.
    m_corrector: Vec<ArithModel>,
    /// The model that codes a corrector of zero or one bit.
    m_corrector_bit: ArithBit,
    /// The bit count of the last corrector, which the point compressors
    /// use to pick the context of the next field.
    k: u32,
}

#[cfg(feature = "las")]
impl IntComp {
    fn new(bits: u32, contexts: u32) -> Self {
        // A compressor with a fixed bit count folds the corrector into a
        // signed interval of that width; one without a limit codes a
        // full thirty-two bit corrector.
        let (corr_bits, corr_range, corr_min) = if bits != 0 && bits < 32 {
            let range = 1u32 << bits;
            (bits, range, -((range / 2) as i32))
        } else {
            (32, 0, i32::MIN)
        };
        let bits_high = 8u32;
        let mut m_bits = Vec::with_capacity(contexts as usize);
        for _ in 0..contexts {
            m_bits.push(ArithModel::new(corr_bits + 1));
        }
        let mut m_corrector = Vec::with_capacity(corr_bits as usize);
        for i in 1..=corr_bits {
            // The reference codes the low bits with a model of their own
            // and the high bits with a shared model of `bits_high` symbols.
            let symbols = if i <= bits_high {
                1u32 << i
            } else {
                1u32 << bits_high
            };
            m_corrector.push(ArithModel::new(symbols));
        }
        IntComp {
            bits_high,
            corr_range,
            corr_min,
            m_bits,
            m_corrector,
            m_corrector_bit: ArithBit::new(),
            k: 0,
        }
    }

    fn init(&mut self) {
        for m in self.m_bits.iter_mut() {
            m.init();
        }
        self.m_corrector_bit.init();
        for m in self.m_corrector.iter_mut() {
            m.init();
        }
    }

    /// Decode the value that follows the prediction `pred` in the given
    /// context.
    fn decompress(&mut self, arith: &mut Arith, pred: i32, context: u32) -> i32 {
        let corr = self.read_corrector(arith, context);
        let mut real = pred.wrapping_add(corr);
        if real < 0 {
            real = real.wrapping_add(self.corr_range as i32);
        } else if (real as u32) >= self.corr_range {
            real = real.wrapping_sub(self.corr_range as i32);
        }
        real
    }

    fn read_corrector(&mut self, arith: &mut Arith, context: u32) -> i32 {
        self.k = arith.decode_symbol(&mut self.m_bits[context as usize]);
        if self.k == 0 {
            return arith.decode_bit(&mut self.m_corrector_bit) as i32;
        }
        if self.k >= 32 {
            return self.corr_min;
        }
        let k = self.k;
        let c: u32 = if k <= self.bits_high {
            arith.decode_symbol(&mut self.m_corrector[(k - 1) as usize])
        } else {
            // The high bits go through the model, the low ones are
            // stored raw.
            let k1 = k - self.bits_high;
            let high = arith.decode_symbol(&mut self.m_corrector[(k - 1) as usize]);
            let low = arith.read_bits(k1);
            (high << k1) | low
        };
        // The corrector sits in the interval the bit count describes:
        // the upper half is positive, the lower half negative.
        if c >= (1u32 << (k - 1)) {
            c.wrapping_add(1) as i32
        } else {
            c.wrapping_sub((1u32 << k).wrapping_sub(1)) as i32
        }
    }
}

/// The reference's `U8_FOLD`: fold a value into a byte by adding or
/// subtracting 256 once.
#[cfg(feature = "las")]
fn u8_fold(n: i32) -> u8 {
    if n < 0 {
        (n + 256) as u8
    } else if n > 255 {
        (n - 256) as u8
    } else {
        n as u8
    }
}

/// The reference's `U8_CLAMP`.
#[cfg(feature = "las")]
fn u8_clamp(n: i32) -> u8 {
    if n <= 0 {
        0
    } else if n >= 255 {
        255
    } else {
        n as u8
    }
}

/// The streaming median of five values the reference keeps per point
/// context (`StreamingMedian5` in `laszip_common_v2.hpp`): the median of
/// the last five differences, used to predict the next one.
#[cfg(feature = "las")]
#[derive(Clone, Copy)]
struct Median5 {
    values: [i32; 5],
    high: bool,
}

#[cfg(feature = "las")]
impl Median5 {
    fn new() -> Self {
        Median5 {
            values: [0; 5],
            high: true,
        }
    }

    fn init(&mut self) {
        *self = Median5::new();
    }

    fn get(&self) -> i32 {
        self.values[2]
    }

    fn add(&mut self, v: i32) {
        if self.high {
            if v < self.values[2] {
                self.values[4] = self.values[3];
                self.values[3] = self.values[2];
                if v < self.values[0] {
                    self.values[2] = self.values[1];
                    self.values[1] = self.values[0];
                    self.values[0] = v;
                } else if v < self.values[1] {
                    self.values[2] = self.values[1];
                    self.values[1] = v;
                } else {
                    self.values[2] = v;
                }
            } else {
                if v < self.values[3] {
                    self.values[4] = self.values[3];
                    self.values[3] = v;
                } else {
                    self.values[4] = v;
                }
                self.high = false;
            }
        } else if self.values[2] < v {
            self.values[0] = self.values[1];
            self.values[1] = self.values[2];
            if self.values[4] < v {
                self.values[2] = self.values[3];
                self.values[3] = self.values[4];
                self.values[4] = v;
            } else if self.values[3] < v {
                self.values[2] = self.values[3];
                self.values[3] = v;
            } else {
                self.values[2] = v;
            }
        } else {
            if self.values[1] < v {
                self.values[0] = self.values[1];
                self.values[1] = v;
            } else {
                self.values[0] = v;
            }
            self.high = true;
        }
    }
}

/// The return-number context map of the reference
/// (`number_return_map` in `laszip_common_v2.hpp`): the intensity
/// context a point is coded in, by its return number and the number of
/// returns of its pulse.
#[cfg(feature = "las")]
const NUMBER_RETURN_MAP: [[u8; 8]; 8] = [
    [15, 14, 13, 12, 11, 10, 9, 8],
    [14, 0, 1, 3, 6, 10, 10, 9],
    [13, 1, 2, 4, 7, 11, 11, 10],
    [12, 3, 4, 5, 8, 12, 12, 11],
    [11, 6, 7, 8, 9, 13, 13, 12],
    [10, 10, 11, 12, 13, 14, 14, 13],
    [9, 10, 11, 12, 13, 14, 15, 14],
    [8, 9, 10, 11, 12, 13, 14, 15],
];

/// The height context level of a point (`number_return_level` in the same
/// header): which of the eight last heights a point is predicted from.
///
/// The tables are the ones every released LASzip up to 3.4.4 carries;
/// LASzip 3.5 changed the entries for return numbers of five and more.
#[cfg(feature = "las")]
const NUMBER_RETURN_LEVEL: [[u8; 8]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7],
    [1, 0, 1, 2, 3, 4, 5, 6],
    [2, 1, 0, 1, 2, 3, 4, 5],
    [3, 2, 1, 0, 1, 2, 3, 4],
    [4, 3, 2, 1, 0, 1, 2, 3],
    [5, 4, 3, 2, 1, 0, 1, 2],
    [6, 5, 4, 3, 2, 1, 0, 1],
    [7, 6, 5, 4, 3, 2, 1, 0],
];

/// The point item of the LASzip version-2 compressors
/// (`LASreadItemCompressed_POINT10_v2` in the reference): the twenty
/// bytes of the point record, minus the GPS time and the colour.
#[cfg(feature = "las")]
struct LaszipPoint10 {
    m_changed_values: ArithModel,
    ic_intensity: IntComp,
    m_scan_angle_rank: [ArithModel; 2],
    ic_point_source: IntComp,
    /// The models for the byte fields, one per value the byte can take.
    /// The reference creates them the first time a value is seen.
    m_bit_byte: Vec<Option<ArithModel>>,
    m_classification: Vec<Option<ArithModel>>,
    m_user_data: Vec<Option<ArithModel>>,
    ic_dx: IntComp,
    ic_dy: IntComp,
    ic_z: IntComp,
    last_item: [u8; 20],
    last_intensity: [u16; 16],
    last_x: [Median5; 16],
    last_y: [Median5; 16],
    last_height: [i32; 8],
}

#[cfg(feature = "las")]
impl LaszipPoint10 {
    fn new() -> Self {
        LaszipPoint10 {
            m_changed_values: ArithModel::new(64),
            ic_intensity: IntComp::new(16, 4),
            m_scan_angle_rank: [ArithModel::new(256), ArithModel::new(256)],
            ic_point_source: IntComp::new(16, 1),
            m_bit_byte: (0..256).map(|_| None).collect(),
            m_classification: (0..256).map(|_| None).collect(),
            m_user_data: (0..256).map(|_| None).collect(),
            ic_dx: IntComp::new(32, 2),
            ic_dy: IntComp::new(32, 22),
            ic_z: IntComp::new(32, 20),
            last_item: [0; 20],
            last_intensity: [0; 16],
            last_x: [Median5::new(); 16],
            last_y: [Median5::new(); 16],
            last_height: [0; 8],
        }
    }

    /// Start a chunk: the first point of a chunk is stored raw, and its
    /// fields seed the predictors.
    fn init(&mut self, item: &[u8; 20]) {
        for i in 0..16 {
            self.last_x[i].init();
            self.last_y[i].init();
            self.last_intensity[i] = 0;
            self.last_height[i / 2] = 0;
        }
        self.m_changed_values.init();
        self.ic_intensity.init();
        self.m_scan_angle_rank[0].init();
        self.m_scan_angle_rank[1].init();
        self.ic_point_source.init();
        for i in 0..256 {
            if let Some(m) = self.m_bit_byte[i].as_mut() {
                m.init();
            }
            if let Some(m) = self.m_classification[i].as_mut() {
                m.init();
            }
            if let Some(m) = self.m_user_data[i].as_mut() {
                m.init();
            }
        }
        self.ic_dx.init();
        self.ic_dy.init();
        self.ic_z.init();
        self.last_item = *item;
        // The intensity is coded against the previous intensity, so the
        // seed's own intensity is not the prediction.
        self.last_item[12] = 0;
        self.last_item[13] = 0;
    }

    /// Decode one point into the twenty bytes of the item.
    fn read(&mut self, arith: &mut Arith, out: &mut [u8; 20]) {
        let changed_values = arith.decode_symbol(&mut self.m_changed_values) as i32;
        let (m, l, n);
        if changed_values != 0 {
            if changed_values & 32 != 0 {
                // The flag byte changed, so the return numbers change
                // with it -- and the context of every other field with
                // them.
                let idx = self.last_item[14] as usize;
                if self.m_bit_byte[idx].is_none() {
                    let mut model = ArithModel::new(256);
                    model.init();
                    self.m_bit_byte[idx] = Some(model);
                }
                let model = self.m_bit_byte[idx].as_mut().unwrap();
                self.last_item[14] = arith.decode_symbol(model) as u8;
            }
            let r = (self.last_item[14] & 0x07) as usize;
            n = ((self.last_item[14] >> 3) & 0x07) as usize;
            m = NUMBER_RETURN_MAP[n][r] as usize;
            l = NUMBER_RETURN_LEVEL[n][r] as usize;
            if changed_values & 16 != 0 {
                let ctx = if m < 3 { m } else { 3 };
                let v =
                    self.ic_intensity
                        .decompress(arith, self.last_intensity[m] as i32, ctx as u32);
                self.last_intensity[m] = v as u16;
                self.last_item[12] = v as u8;
                self.last_item[13] = (v >> 8) as u8;
            } else {
                let v = self.last_intensity[m];
                self.last_item[12] = v as u8;
                self.last_item[13] = (v >> 8) as u8;
            }
            if changed_values & 8 != 0 {
                let idx = self.last_item[15] as usize;
                if self.m_classification[idx].is_none() {
                    let mut model = ArithModel::new(256);
                    model.init();
                    self.m_classification[idx] = Some(model);
                }
                let model = self.m_classification[idx].as_mut().unwrap();
                self.last_item[15] = arith.decode_symbol(model) as u8;
            }
            if changed_values & 4 != 0 {
                let dir = ((self.last_item[14] >> 6) & 1) as usize;
                let val = arith.decode_symbol(&mut self.m_scan_angle_rank[dir]) as i32;
                self.last_item[16] = u8_fold(val + self.last_item[16] as i32);
            }
            if changed_values & 2 != 0 {
                let idx = self.last_item[17] as usize;
                if self.m_user_data[idx].is_none() {
                    let mut model = ArithModel::new(256);
                    model.init();
                    self.m_user_data[idx] = Some(model);
                }
                let model = self.m_user_data[idx].as_mut().unwrap();
                self.last_item[17] = arith.decode_symbol(model) as u8;
            }
            if changed_values & 1 != 0 {
                let psid = u16::from_le_bytes([self.last_item[18], self.last_item[19]]);
                let v = self.ic_point_source.decompress(arith, psid as i32, 0);
                self.last_item[18] = v as u8;
                self.last_item[19] = (v >> 8) as u8;
            }
        } else {
            let r = (self.last_item[14] & 0x07) as usize;
            n = ((self.last_item[14] >> 3) & 0x07) as usize;
            m = NUMBER_RETURN_MAP[n][r] as usize;
            l = NUMBER_RETURN_LEVEL[n][r] as usize;
        }

        // The coordinates are differences against the median of the last
        // five differences of the same context.
        let median = self.last_x[m].get();
        let diff = self.ic_dx.decompress(arith, median, u32::from(n == 1));
        let x = i32::from_le_bytes([
            self.last_item[0],
            self.last_item[1],
            self.last_item[2],
            self.last_item[3],
        ])
        .wrapping_add(diff);
        self.last_item[0..4].copy_from_slice(&x.to_le_bytes());
        self.last_x[m].add(diff);

        let median = self.last_y[m].get();
        let k_bits = self.ic_dx.k;
        let ctx = u32::from(n == 1) + if k_bits < 20 { k_bits & !1 } else { 20 };
        let diff = self.ic_dy.decompress(arith, median, ctx);
        let y = i32::from_le_bytes([
            self.last_item[4],
            self.last_item[5],
            self.last_item[6],
            self.last_item[7],
        ])
        .wrapping_add(diff);
        self.last_item[4..8].copy_from_slice(&y.to_le_bytes());
        self.last_y[m].add(diff);

        let k_bits = (self.ic_dx.k + self.ic_dy.k) / 2;
        let ctx = u32::from(n == 1) + if k_bits < 18 { k_bits & !1 } else { 18 };
        let z = self.ic_z.decompress(arith, self.last_height[l], ctx);
        self.last_height[l] = z;
        self.last_item[8..12].copy_from_slice(&z.to_le_bytes());

        out.copy_from_slice(&self.last_item);
    }
}

/// The GPS time item of the LASzip version-2 compressors
/// (`LASreadItemCompressed_GPSTIME11_v2`): the eight bytes of the time,
/// coded as a difference against the last time.
#[cfg(feature = "las")]
struct LaszipGpsTime {
    m_gpstime_multi: ArithModel,
    m_gpstime_0diff: ArithModel,
    ic_gpstime: IntComp,
    last: usize,
    next: usize,
    last_gpstime: [u64; 4],
    last_gpstime_diff: [i32; 4],
    multi_extreme_counter: [i32; 4],
}

/// The number of symbols the "unchanged" GPS time model carries.
#[cfg(feature = "las")]
const GPS_TIME_MULTI: u32 = 500;
/// The lower end of the multiplier range.
#[cfg(feature = "las")]
const GPS_TIME_MULTI_MINUS: i32 = -10;
/// The symbol that means the time did not change.
#[cfg(feature = "las")]
const GPS_TIME_MULTI_UNCHANGED: u32 = GPS_TIME_MULTI + (-GPS_TIME_MULTI_MINUS) as u32 + 1;
/// The symbol that means the time jumped.
#[cfg(feature = "las")]
const GPS_TIME_MULTI_CODE_FULL: u32 = GPS_TIME_MULTI + (-GPS_TIME_MULTI_MINUS) as u32 + 2;
/// The number of symbols the GPS time model carries.
#[cfg(feature = "las")]
const GPS_TIME_MULTI_TOTAL: u32 = GPS_TIME_MULTI + (-GPS_TIME_MULTI_MINUS) as u32 + 6;

/// How many sequences one point's GPS time may switch between before the
/// coding is declared out of sync.
///
/// The reference's reader switches as often as the `multi` symbol asks,
/// and what stops it is its decoder throwing when the chunk's bytes run
/// out. A point's time lives in one of four sequences, and the reference's
/// own files switch at most once or twice, so a handful is a generous
/// allowance -- and a file that needs more is refused rather than read.
#[cfg(feature = "las")]
const GPS_TIME_MAX_SWITCHES: usize = 64;

#[cfg(feature = "las")]
impl LaszipGpsTime {
    fn new() -> Self {
        LaszipGpsTime {
            m_gpstime_multi: ArithModel::new(GPS_TIME_MULTI_TOTAL),
            m_gpstime_0diff: ArithModel::new(6),
            ic_gpstime: IntComp::new(32, 9),
            last: 0,
            next: 0,
            last_gpstime: [0; 4],
            last_gpstime_diff: [0; 4],
            multi_extreme_counter: [0; 4],
        }
    }

    fn init(&mut self, item: &[u8; 8]) {
        self.last = 0;
        self.next = 0;
        self.last_gpstime_diff = [0; 4];
        self.multi_extreme_counter = [0; 4];
        self.m_gpstime_multi.init();
        self.m_gpstime_0diff.init();
        self.ic_gpstime.init();
        self.last_gpstime = [u64::from_le_bytes(item[0..8].try_into().unwrap()), 0, 0, 0];
    }

    /// Decode one GPS time into the eight bytes of the item.
    fn read(&mut self, arith: &mut Arith, out: &mut [u8; 8]) -> Result<(), String> {
        // This is the reference's `while (1)`: it picks the sequence the
        // time belongs to and decodes the time against it, and a `multi`
        // of three or more says "the time continues in another sequence",
        // so the reference loops and switches. What bounds the reference's
        // loop is its decoder: it throws when the chunk's bytes run out.
        // This decoder does not throw, and a symbol can be decoded without
        // reading a byte at all, so the loop here is bounded by the number
        // of switches instead. A point needs one sequence; a file that
        // keeps switching is a file whose coding is out of sync, and the
        // price of not noticing is 367 million iterations and nearly
        // three seconds for one `.laz` -- which is what the fuzz kit's
        // watchdog sees as a hang.
        let mut settled = false;
        for _ in 0..GPS_TIME_MAX_SWITCHES {
            if arith.starved {
                // The chunk ran out of bytes. The caller refuses the file
                // on that, so the time this point carries does not matter.
                settled = true;
                break;
            }
            if self.last_gpstime_diff[self.last] == 0 {
                let multi = arith.decode_symbol(&mut self.m_gpstime_0diff);
                if multi == 1 {
                    let d = self.ic_gpstime.decompress(arith, 0, 0);
                    self.last_gpstime_diff[self.last] = d;
                    self.last_gpstime[self.last] =
                        (self.last_gpstime[self.last] as i64).wrapping_add(d as i64) as u64;
                    self.multi_extreme_counter[self.last] = 0;
                } else if multi == 2 {
                    self.next = (self.next + 1) & 3;
                    let high = self.ic_gpstime.decompress(
                        arith,
                        (self.last_gpstime[self.last] >> 32) as u32 as i32,
                        8,
                    );
                    self.last_gpstime[self.next] =
                        ((high as u32 as u64) << 32) | arith.read_int() as u64;
                    self.last = self.next;
                    self.last_gpstime_diff[self.last] = 0;
                    self.multi_extreme_counter[self.last] = 0;
                } else if multi > 2 {
                    // The time continues in another of the four
                    // sequences the reference keeps.
                    self.last = (self.last + multi as usize - 2) & 3;
                    continue;
                }
            } else {
                let multi = arith.decode_symbol(&mut self.m_gpstime_multi);
                if multi == 1 {
                    let d = self
                        .ic_gpstime
                        .decompress(arith, self.last_gpstime_diff[self.last], 1);
                    self.last_gpstime[self.last] =
                        (self.last_gpstime[self.last] as i64).wrapping_add(d as i64) as u64;
                    self.multi_extreme_counter[self.last] = 0;
                } else if multi < GPS_TIME_MULTI_UNCHANGED {
                    let diff;
                    if multi == 0 {
                        diff = self.ic_gpstime.decompress(arith, 0, 7);
                        self.multi_extreme_counter[self.last] += 1;
                        if self.multi_extreme_counter[self.last] > 3 {
                            self.last_gpstime_diff[self.last] = diff;
                            self.multi_extreme_counter[self.last] = 0;
                        }
                    } else if multi < GPS_TIME_MULTI {
                        let pred = (multi as i32).wrapping_mul(self.last_gpstime_diff[self.last]);
                        diff = if multi < 10 {
                            self.ic_gpstime.decompress(arith, pred, 2)
                        } else {
                            self.ic_gpstime.decompress(arith, pred, 3)
                        };
                    } else if multi == GPS_TIME_MULTI {
                        let pred =
                            (GPS_TIME_MULTI as i32).wrapping_mul(self.last_gpstime_diff[self.last]);
                        diff = self.ic_gpstime.decompress(arith, pred, 4);
                        self.multi_extreme_counter[self.last] += 1;
                        if self.multi_extreme_counter[self.last] > 3 {
                            self.last_gpstime_diff[self.last] = diff;
                            self.multi_extreme_counter[self.last] = 0;
                        }
                    } else {
                        let m = GPS_TIME_MULTI as i32 - multi as i32;
                        if m > GPS_TIME_MULTI_MINUS {
                            let pred = m.wrapping_mul(self.last_gpstime_diff[self.last]);
                            diff = self.ic_gpstime.decompress(arith, pred, 5);
                        } else {
                            let pred = GPS_TIME_MULTI_MINUS
                                .wrapping_mul(self.last_gpstime_diff[self.last]);
                            diff = self.ic_gpstime.decompress(arith, pred, 6);
                            self.multi_extreme_counter[self.last] += 1;
                            if self.multi_extreme_counter[self.last] > 3 {
                                self.last_gpstime_diff[self.last] = diff;
                                self.multi_extreme_counter[self.last] = 0;
                            }
                        }
                    }
                    self.last_gpstime[self.last] =
                        (self.last_gpstime[self.last] as i64).wrapping_add(diff as i64) as u64;
                } else if multi == GPS_TIME_MULTI_CODE_FULL {
                    self.next = (self.next + 1) & 3;
                    let high = self.ic_gpstime.decompress(
                        arith,
                        (self.last_gpstime[self.last] >> 32) as u32 as i32,
                        8,
                    );
                    self.last_gpstime[self.next] =
                        ((high as u32 as u64) << 32) | arith.read_int() as u64;
                    self.last = self.next;
                    self.last_gpstime_diff[self.last] = 0;
                    self.multi_extreme_counter[self.last] = 0;
                } else if multi >= GPS_TIME_MULTI_CODE_FULL {
                    self.last =
                        (self.last + multi as usize - GPS_TIME_MULTI_CODE_FULL as usize) & 3;
                    continue;
                }
            }
            settled = true;
            break;
        }
        if !settled {
            return Err("the GPS time coding does not settle".into());
        }
        out.copy_from_slice(&self.last_gpstime[self.last].to_le_bytes());
        Ok(())
    }
}

/// The colour item of the LASzip version-2 compressors
/// (`LASreadItemCompressed_RGB12_v2`): the six bytes of the three
/// sixteen-bit colour channels, each coded against the last one.
#[cfg(feature = "las")]
struct LaszipRgb12 {
    m_byte_used: ArithModel,
    m_rgb_diff: [ArithModel; 6],
    last_item: [u8; 6],
}

#[cfg(feature = "las")]
impl LaszipRgb12 {
    fn new() -> Self {
        LaszipRgb12 {
            m_byte_used: ArithModel::new(128),
            m_rgb_diff: [
                ArithModel::new(256),
                ArithModel::new(256),
                ArithModel::new(256),
                ArithModel::new(256),
                ArithModel::new(256),
                ArithModel::new(256),
            ],
            last_item: [0; 6],
        }
    }

    fn init(&mut self, item: &[u8; 6]) {
        self.m_byte_used.init();
        for m in self.m_rgb_diff.iter_mut() {
            m.init();
        }
        self.last_item = *item;
    }

    /// Decode one colour into the six bytes of the item.
    fn read(&mut self, arith: &mut Arith, out: &mut [u8; 6]) {
        let sym = arith.decode_symbol(&mut self.m_byte_used);
        let mut item = [0u8; 6];
        let last = self.last_item;
        // The red channel: the low byte and the high byte are coded
        // separately, each against the last point's.
        if sym & (1 << 0) != 0 {
            let corr = arith.decode_symbol(&mut self.m_rgb_diff[0]) as i32;
            item[0] = u8_fold(corr + last[0] as i32);
        } else {
            item[0] = last[0];
        }
        if sym & (1 << 1) != 0 {
            let corr = arith.decode_symbol(&mut self.m_rgb_diff[1]) as i32;
            item[1] = u8_fold(corr + last[1] as i32);
        } else {
            item[1] = last[1];
        }
        // The green channel, predicted from the change of the red one.
        let mut diff = item[0] as i32 - last[0] as i32;
        if sym & (1 << 6) != 0 {
            if sym & (1 << 2) != 0 {
                let corr = arith.decode_symbol(&mut self.m_rgb_diff[2]) as i32;
                item[2] = u8_fold(corr + u8_clamp(diff + last[2] as i32) as i32);
            } else {
                item[2] = last[2];
            }
            // The blue channel, predicted from the change of the green
            // one.
            if sym & (1 << 4) != 0 {
                let corr = arith.decode_symbol(&mut self.m_rgb_diff[4]) as i32;
                diff = (diff + (item[2] as i32 - last[2] as i32)) / 2;
                item[4] = u8_fold(corr + u8_clamp(diff + last[4] as i32) as i32);
            } else {
                item[4] = last[4];
            }
            diff = item[1] as i32 - last[1] as i32;
            if sym & (1 << 3) != 0 {
                let corr = arith.decode_symbol(&mut self.m_rgb_diff[3]) as i32;
                item[3] = u8_fold(corr + u8_clamp(diff + last[3] as i32) as i32);
            } else {
                item[3] = last[3];
            }
            if sym & (1 << 5) != 0 {
                let corr = arith.decode_symbol(&mut self.m_rgb_diff[5]) as i32;
                diff = (diff + (item[3] as i32 - last[3] as i32)) / 2;
                item[5] = u8_fold(corr + u8_clamp(diff + last[5] as i32) as i32);
            } else {
                item[5] = last[5];
            }
        } else {
            // Without the difference the three channels are the same.
            item[2] = item[0];
            item[3] = item[1];
            item[4] = item[0];
            item[5] = item[1];
        }
        self.last_item = item;
        out.copy_from_slice(&item);
    }
}

/// Legacy VTK: title + dataset type (+ dims for structured sets). Binary
/// files contribute only the header; ASCII bails to plain-text search.
#[cfg(feature = "vtk")]
pub struct Vtk;
#[cfg(feature = "vtk")]
impl Adapter for Vtk {
    fn name(&self) -> &'static str {
        "vtk"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["vtk"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let first = data
            .get(..70)
            .map(|h| String::from_utf8_lossy(h).to_string())
            .decline_context("vtk file too small")?;
        if !first.starts_with("# vtk DataFile Version") {
            decline!("not a legacy vtk file");
        }
        if find_subslice(&data[..data.len().min(4096)], b"BINARY").is_some() {
            let header: String = first.lines().take(6).map(|l| format!("{l}\n")).collect();
            return Ok(Outcome::Text(header.into_bytes()));
        }
        Ok(Outcome::Bail("ascii vtk is plain text".into()))
    }
}

// ---------- Blender .blend ----------

/// Blender scene file: walk the block sequence (code, size, sdna, count)
/// and lift the names out of ID blocks — object, mesh, material, camera,
/// light, scene names are what a code search wants from a .blend. The name
/// sits at offset 4×pointer_size inside every two-uppercase-letter block
/// (ID struct header: 4 pointers then `name[66]`).
#[cfg(feature = "blend")]
pub struct Blend;
#[cfg(feature = "blend")]
impl Adapter for Blend {
    fn name(&self) -> &'static str {
        "blend"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["blend"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 12 || &data[0..7] != b"BLENDER" {
            decline!("not a Blender file (bad magic)");
        }
        let ptr = match data[7] {
            b'_' => 4usize,
            b'-' => 8,
            c => bail!("unknown Blender pointer-size marker {c:#x}"),
        };
        let le = match data[8] {
            b'v' => true,
            b'V' => false,
            c => bail!("unknown Blender endianness marker {c:#x}"),
        };
        let version = String::from_utf8_lossy(&data[9..12]).into_owned();
        let rd32 = |b: &[u8], o: usize| -> u32 {
            let s = &b[o..o + 4];
            if le {
                u32::from_le_bytes([s[0], s[1], s[2], s[3]])
            } else {
                u32::from_be_bytes([s[0], s[1], s[2], s[3]])
            }
        };
        let mut out = format!(
            "blender v{version} ptr={ptr}B {}\n",
            if le { "little-endian" } else { "big-endian" }
        );
        let mut p = 12usize;
        // block codes are 4 raw bytes, NUL-padded ("OB\0\0"). Counting by
        // the raw `[u8; 4]` keeps the inner loop alloc-free: a file with
        // 100 000 blocks used to allocate one `String` per block just to
        // bump the histogram counter. The owned `String` is built only
        // for the 24 lines the summary actually prints.
        let mut counts: BTreeMap<[u8; 4], usize> = BTreeMap::new();
        let mut names = 0usize;
        let mut blocks = 0usize;
        while p + 4 + 4 + ptr + 8 <= data.len() && blocks < 100_000 {
            let code = &data[p..p + 4];
            if code == b"ENDB" {
                break;
            }
            let size = rd32(data, p + 4) as usize;
            let body = p + 4 + 4 + ptr + 8;
            if size > (1 << 30) || body.checked_add(size).is_none_or(|e| e > data.len()) {
                bail!("blend block overruns file");
            }
            blocks += 1;
            // Copy the 4-byte code into an owned `[u8; 4]` so the
            // histogram key is hashable; `entry` requires `K: Borrow<[u8; 4]>`,
            // which the borrowed slice `&[u8]` is not.
            let code_arr: [u8; 4] = [code[0], code[1], code[2], code[3]];
            *counts.entry(code_arr).or_insert(0) += 1;
            // ID blocks: two uppercase letters carry a name at 4*ptr
            let is_id = code[0].is_ascii_uppercase() && code[1].is_ascii_uppercase();
            if is_id && names < 4096 {
                let noff = body + 4 * ptr;
                // name window must fit inside both the file and the block
                let end = (noff + 66).min(data.len()).min(body + size);
                if noff < end {
                    let avail = &data[noff..end];
                    let end = avail.iter().position(|&b| b == 0).unwrap_or(avail.len());
                    let name = String::from_utf8_lossy(&avail[..end]).trim().to_string();
                    if !name.is_empty() && out.len() < (1 << 20) {
                        // ASCII prefix is always valid UTF-8; the
                        // 2-letter code is rendered as a str slice to
                        // avoid a transient String.
                        let code_prefix = core::str::from_utf8(&code_arr[..2]).unwrap_or("??");
                        let _ = writeln!(out, "{code_prefix}: {name}");
                        names += 1;
                    }
                }
            }
            p = body + size;
        }
        if blocks == 0 {
            decline!("no blend blocks");
        }
        let mut hist: Vec<([u8; 4], usize)> = counts.into_iter().collect();
        hist.sort_by_key(|a| Reverse(a.1));
        let summary: Vec<String> = hist
            .iter()
            .take(24)
            .map(|(c, n)| {
                // Trim NULs once, here, for the 24 lines that actually ship.
                let trimmed_end = c.iter().position(|&b| b == 0).unwrap_or(c.len());
                let code_str = core::str::from_utf8(&c[..trimmed_end]).unwrap_or("?");
                format!("{code_str}×{n}")
            })
            .collect();
        let _ = writeln!(out, "blocks: {blocks} [{}]", summary.join(" "));
        Ok(Outcome::Text(out.into_bytes()))
    }
}

// ---------- 3D Studio .3ds ----------

/// 3ds Max chunk hierarchy: u16 id + u32 length, recursive. Lift object
/// names (0x4000), material names (0xA000) and texture filenames (0xA300)
/// — everything else gets counted, not decoded.
#[cfg(feature = "threeds")]
pub struct Threeds;
#[cfg(feature = "threeds")]
impl Adapter for Threeds {
    fn name(&self) -> &'static str {
        "3ds"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["3ds", "max3ds"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 6 {
            decline!("3ds file too small");
        }
        let mut out = String::new();
        let mut counts: BTreeMap<u16, usize> = BTreeMap::new();
        let mut entries = 0usize;
        walk3ds(data, 0, data.len(), 0, &mut |id, payload, named| {
            *counts.entry(id).or_default() += 1;
            if named && entries < 2048 && out.len() < (1 << 20) {
                let label = match id {
                    0x4000 => "object",
                    0xA000 => "material",
                    0xA300 => "texture",
                    _ => "name",
                };
                let end = payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(payload.len());
                let name = String::from_utf8_lossy(&payload[..end]).trim().to_string();
                if !name.is_empty() {
                    let _ = writeln!(out, "{label}: {name}");
                    entries += 1;
                }
            }
        });
        if counts.is_empty() {
            decline!("no 3ds chunks");
        }
        let main = counts.get(&0x4D4D).copied().unwrap_or(0);
        if main == 0 {
            decline!("no 0x4D4D main chunk (not a 3ds file)");
        }
        let mut summary = format!("3ds main chunks: {main}\n");
        summary.push_str(&out);
        Ok(Outcome::Text(summary.into_bytes()))
    }
}

/// recursive chunk walk; `f` sees (id, payload-prefix, carries-a-name)
#[cfg(feature = "threeds")]
fn walk3ds(
    data: &[u8],
    start: usize,
    end: usize,
    depth: usize,
    f: &mut impl FnMut(u16, &[u8], bool),
) {
    if depth > 12 {
        return;
    }
    let mut p = start;
    while p + 6 <= end.min(data.len()) {
        let id = u16::from_le_bytes([data[p], data[p + 1]]);
        let len = u32::from_le_bytes([data[p + 2], data[p + 3], data[p + 4], data[p + 5]]) as usize;
        if len < 6 {
            return; // corrupt length: stop this level
        }
        let cend = match p.checked_add(len) {
            Some(e) if e <= end.min(data.len()) => e,
            _ => return,
        };
        let payload = &data[p + 6..cend];
        let named = matches!(id, 0x4000 | 0xA000 | 0xA300);
        f(id, payload, named);
        // container chunks worth descending into
        if matches!(id, 0x4D4D | 0x3D3D | 0x4100 | 0xA200 | 0xB000) {
            walk3ds(data, p + 6, cend, depth + 1, f);
        }
        p = cend;
    }
}

// ---------- NIfTI neuroimaging volume ----------

#[cfg(feature = "nifti")]
fn datatype_name(code: i16) -> &'static str {
    match code {
        2 => "uint8",
        4 => "int16",
        8 => "int32",
        16 => "float32",
        32 => "float64",
        64 => "float128",
        128 => "rgb",
        256 => "int8",
        512 => "uint16",
        768 => "uint32",
        1024 => "int64",
        1280 => "uint64",
        _ => "unknown",
    }
}

/// NIfTI-1/2 medical volume header: dims, voxel datatype/size, spacing,
/// description, intent name and qform/sform orientation codes. The voxel
/// payload is never decoded — a code search wants the metadata.
#[cfg(feature = "nifti")]
pub struct Nifti;
#[cfg(feature = "nifti")]
impl Adapter for Nifti {
    fn name(&self) -> &'static str {
        "nifti"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["nii"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 348 {
            decline!("shorter than a nifti-1 header");
        }
        // NIfTI-1 is allowed in either byte order, and `sizeof_hdr` is what
        // records which: 348 little-endian, and the same value byte-swapped
        // when a big-endian host wrote it. Every other field in the header
        // follows that order, so it is a property of the whole header and not
        // of one field — reading only the little-endian spelling refused half
        // the format, and `anatomical.nii` from nibabel is one of those.
        let (be, sizeof_hdr) = match rd_u32(data, 0) {
            348 => (false, 348),
            540 => (false, 540),
            v if v == 348u32.swap_bytes() => (true, 348),
            v if v == 540u32.swap_bytes() => (true, 540),
            v => decline!("not a nifti file (sizeof_hdr = {v})"),
        };
        let rd16 = |d: &[u8], o: usize| -> i16 {
            if be {
                i16::from_be_bytes([d[o], d[o + 1]])
            } else {
                i16::from_le_bytes([d[o], d[o + 1]])
            }
        };
        let rdu32 = |d: &[u8], o: usize| -> u32 {
            if be {
                u32::from_be_bytes(d[o..o + 4].try_into().unwrap())
            } else {
                u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
            }
        };
        let rdf32 = |d: &[u8], o: usize| -> f32 {
            if be {
                f32::from_be_bytes(d[o..o + 4].try_into().unwrap())
            } else {
                f32::from_le_bytes(d[o..o + 4].try_into().unwrap())
            }
        };
        let rdf64 = |d: &[u8], o: usize| -> f64 {
            if be {
                f64::from_be_bytes(d[o..o + 8].try_into().unwrap())
            } else {
                f64::from_le_bytes(d[o..o + 8].try_into().unwrap())
            }
        };
        let rdi64 = |d: &[u8], o: usize| -> i64 {
            if be {
                i64::from_be_bytes(d[o..o + 8].try_into().unwrap())
            } else {
                i64::from_le_bytes(d[o..o + 8].try_into().unwrap())
            }
        };
        let (version, magic) = match sizeof_hdr {
            348 => {
                let magic = &data[344..348];
                (1, magic)
            }
            540 if data.len() >= 540 => {
                let magic = &data[488..492];
                (2, magic)
            }
            _ => decline!("not a nifti file (sizeof_hdr = {sizeof_hdr})"),
        };
        let mut out = String::from("nifti volume\n");
        match version {
            1 => {
                let _ = writeln!(
                    out,
                    "version: 1 ({})",
                    String::from_utf8_lossy(magic).trim_end_matches('\0')
                );
                let ndim = data[40] as usize;
                let dims: Vec<i16> = (0..8).map(|i| rd16(data, 40 + i * 2)).collect();
                let datatype = rd16(data, 70);
                let bitpix = rd16(data, 72);
                let pixdim: Vec<f32> = (0..8).map(|i| rdf32(data, 76 + i * 4)).collect();
                let vox_offset = rdf32(data, 108);
                let descrip = String::from_utf8_lossy(&data[148..228])
                    .trim_end_matches('\0')
                    .to_string();
                let intent_name = String::from_utf8_lossy(&data[328..344])
                    .trim_end_matches('\0')
                    .to_string();
                let qform = rd16(data, 252);
                let sform = rd16(data, 254);
                let _ = writeln!(
                    out,
                    "datatype: {} ({} bit)\ndim: {:?}\npixdim: {:?}\nvoxel data offset: {vox_offset}\nbyte order: {}\n",
                    datatype_name(datatype),
                    bitpix,
                    &dims[..ndim.min(7) + 1],
                    &pixdim[..ndim.min(7) + 1],
                    if be { "big" } else { "little" },
                );
                let _ = writeln!(out, "qform: {qform} sform: {sform}");
                if !descrip.is_empty() {
                    let _ = writeln!(out, "description: {descrip}");
                }
                if !intent_name.is_empty() {
                    let _ = writeln!(out, "intent: {intent_name}");
                }
            }
            _ => {
                let _ = writeln!(
                    out,
                    "version: 2 ({})",
                    String::from_utf8_lossy(magic).trim_end_matches('\0')
                );
                let datatype = rd16(data, 4);
                let bitpix = rd16(data, 6);
                let dims: Vec<i16> = (0..8).map(|i| rd16(data, 8 + i * 2)).collect();
                let pixdim: Vec<f64> = (0..8).map(|i| rdf64(data, 48 + i * 8)).collect();
                let vox_offset = rdi64(data, 112);
                let descrip = String::from_utf8_lossy(&data[184..264])
                    .trim_end_matches('\0')
                    .to_string();
                let intent_name = String::from_utf8_lossy(&data[456..472])
                    .trim_end_matches('\0')
                    .to_string();
                let qform = rdu32(data, 288);
                let sform = rdu32(data, 292);
                let _ = writeln!(
                    out,
                    "datatype: {} ({} bit)\ndim: {:?}\npixdim: {:?}\nvoxel data offset: {vox_offset}\nbyte order: {}\n",
                    datatype_name(datatype),
                    bitpix,
                    &dims[..8],
                    &pixdim[..8],
                    if be { "big" } else { "little" },
                );
                let _ = writeln!(out, "qform: {qform} sform: {sform}");
                if !descrip.is_empty() {
                    let _ = writeln!(out, "description: {descrip}");
                }
                if !intent_name.is_empty() {
                    let _ = writeln!(out, "intent: {intent_name}");
                }
            }
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// MRC/CCP4 volume-data header reader.
///
/// MRC is the medical-/structural-biology volume format: a 1024-byte
/// little-endian header followed by a voxel slab. The searchable
/// shape is the header — voxel counts, cell dimensions, mode, the
/// 800-byte label block — and the format itself encodes no text past
/// the labels, so a search that wants to find a volume named
/// "nucleosome" needs the labels and the comment that some tools
/// stash in byte 800. CCP4 extends MRC: at offset 208 the file carries
/// the magic "MAP " (little-endian 0x4d415020), which the adapter
/// reads to print `format: ccp4` instead of `format: mrc`.
#[cfg(feature = "mrc")]
pub struct Mrc;
#[cfg(feature = "mrc")]
impl Adapter for Mrc {
    fn name(&self) -> &'static str {
        "mrc"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["mrc", "ccp4", "map"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // The header is 1024 bytes; the file is required to be at
        // least that long. A truncated header is not a fatal error --
        // the volume is unreadable either way, but emitting a
        // searchable note lets the user find that fact with the
        // matcher rather than discovering it from a silent skip.
        if data.len() < 1024 {
            decline!("mrc/CCP4 header is 1024 bytes; file is {}", data.len());
        }
        let nx = rd_i32(data, 0);
        let ny = rd_i32(data, 4);
        let nz = rd_i32(data, 8);
        let mode = rd_i32(data, 12);
        let cell_a = rd_f32(data, 40);
        let cell_b = rd_f32(data, 44);
        let cell_c = rd_f32(data, 48);
        let alpha = rd_f32(data, 52);
        let beta = rd_f32(data, 56);
        let gamma = rd_f32(data, 60);
        let dmin = rd_f32(data, 76);
        let dmax = rd_f32(data, 80);
        let dmean = rd_f32(data, 84);
        let ispg = rd_i32(data, 88);
        let nlabl = rd_i32(data, 92);
        // CCP4 magic: at offset 208, the bytes "MAP " (little-endian
        // 0x20 0x50 0x41 0x4d reads as " MAP" forward, but the file
        // stores them as 0x4d 0x41 0x50 0x20 which is "MAP ").
        let format = if data.len() >= 212 && &data[208..212] == b"MAP " {
            "ccp4"
        } else {
            "mrc"
        };
        let mode_name = match mode {
            0 => "int8",
            1 => "int16",
            2 => "float32",
            3 => "complex-int32",
            4 => "complex-float32",
            5 => "int16-unsigned",
            6 => "float16",
            _ => "unknown",
        };
        let mut out = String::with_capacity(1024);
        let _ = writeln!(out, "format: {format}");
        let _ = writeln!(out, "dimensions: {nx} {ny} {nz}");
        let _ = writeln!(out, "mode: {mode} ({mode_name})");
        let _ = writeln!(out, "cell: {cell_a:.3} {cell_b:.3} {cell_c:.3} A");
        let _ = writeln!(out, "angles: {alpha:.2} {beta:.2} {gamma:.2} deg");
        let _ = writeln!(out, "density: min={dmin:.4} max={dmax:.4} mean={dmean:.4}");
        let _ = writeln!(out, "spacegroup: {ispg}");
        // 10 labels of 80 bytes each, starting at offset 104. NLABL is
        // informational; the fixed 10-slot layout is the contract.
        let labels_end = 104 + 10 * 80;
        let labels_end = labels_end.min(data.len());
        if labels_end > 104 {
            for (i, label) in data[104..labels_end].chunks(80).take(10).enumerate() {
                let text = String::from_utf8_lossy(label)
                    .trim_end_matches('\0')
                    .trim()
                    .to_string();
                if !text.is_empty() {
                    let _ = writeln!(out, "label{i}: {text}");
                }
                if nlabl >= 0 && i + 1 >= nlabl as usize {
                    break;
                }
            }
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(all(
    test,
    any(
        feature = "glb",
        feature = "stl",
        feature = "ply",
        feature = "fbx",
        feature = "pcd",
        feature = "las",
        feature = "vtk",
        feature = "blend",
        feature = "threeds",
        feature = "nifti",
        feature = "mrc"
    )
))]
mod tests {
    use super::*;

    #[cfg(feature = "stl")]
    #[test]
    fn binary_stl_triangle_count() {
        let mut stl = vec![0u8; 80];
        stl[0] = b'x'; // not "solid" -> binary
        stl.extend_from_slice(&2u32.to_le_bytes());
        stl.extend_from_slice(&[0u8; 100]);
        let out = Stl.extract(&stl, "p.stl").unwrap();
        match out {
            Outcome::Text(t) => assert!(String::from_utf8_lossy(&t).contains("2 triangles")),
            _ => panic!("expected text"),
        }
    }

    #[cfg(feature = "stl")]
    #[test]
    fn ascii_stl_bails() {
        let out = Stl.extract(b"solid foo\nendsolid foo\n", "p.stl").unwrap();
        assert!(matches!(out, Outcome::Bail(_)));
    }

    #[cfg(feature = "nifti")]
    fn nifti1_fixture() -> Vec<u8> {
        let mut d = vec![0u8; 360];
        d[0..4].copy_from_slice(&348u32.to_le_bytes());
        d[40] = 3; // ndim
        for (i, v) in [64i16, 64, 32].iter().enumerate() {
            d[40 + i * 2..42 + i * 2].copy_from_slice(&v.to_le_bytes());
        }
        d[70..72].copy_from_slice(&16i16.to_le_bytes()); // float32
        d[72..74].copy_from_slice(&32i16.to_le_bytes()); // bitpix
        for i in 0..4 {
            let px = 2.0f32.to_le_bytes();
            d[76 + i * 4..80 + i * 4].copy_from_slice(&px);
        }
        d[108..112].copy_from_slice(&352.0f32.to_le_bytes()); // vox_offset
        d[148..148 + 12].copy_from_slice(b"ZIRCALOY MRI");
        d[344..348].copy_from_slice(b"n+1\0");
        d
    }

    #[cfg(feature = "nifti")]
    #[test]
    fn nifti1_summarizes_header() {
        let out = Nifti.extract(&nifti1_fixture(), "scan.nii").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8_lossy(&t);
        assert!(s.contains("version: 1 (n+1)"), "{s}");
        assert!(s.contains("float32 (32 bit)"), "{s}");
        assert!(s.contains("description: ZIRCALOY MRI"), "{s}");
    }

    #[cfg(feature = "nifti")]
    #[test]
    fn nifti2_summarizes_header() {
        let mut d = vec![0u8; 560];
        d[0..4].copy_from_slice(&540u32.to_le_bytes());
        d[4..6].copy_from_slice(&16i16.to_le_bytes()); // float32
        d[6..8].copy_from_slice(&32i16.to_le_bytes()); // bitpix
        d[8..10].copy_from_slice(&2i16.to_le_bytes()); // ndim
        d[488..492].copy_from_slice(b"n+2\0");
        let out = Nifti.extract(&d, "scan.nii").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8_lossy(&t);
        assert!(s.contains("version: 2 (n+2)"), "{s}");
    }

    #[cfg(feature = "nifti")]
    #[test]
    fn nifti_never_panics_on_mutation() {
        rgx_core::fuzzkit::assert_never_panics(
            vec![
                ("nifti1", nifti1_fixture()),
                ("sizeof-only", 348u32.to_le_bytes().to_vec()),
                ("empty", vec![]),
            ],
            1200,
            "nii",
            |data| {
                let _ = Nifti.extract(data, "fuzz.nii");
            },
        );
    }

    #[cfg(feature = "glb")]
    #[test]
    fn glb_summarizes_names() {
        let json = br#"{"asset":{"version":"2.0"},"scenes":[{"name":"main"}],"nodes":[{"name":"root"},{"name":"wheel"}],"meshes":[{"name":"body"}]}"#;
        let mut glb = Vec::new();
        glb.extend_from_slice(b"glTF");
        glb.extend_from_slice(&2u32.to_le_bytes());
        glb.extend_from_slice(&((12 + 8 + json.len()) as u32).to_le_bytes());
        glb.extend_from_slice(&(json.len() as u32).to_le_bytes());
        glb.extend_from_slice(b"JSON");
        glb.extend_from_slice(json);
        let out = Glb.extract(&glb, "m.glb").unwrap();
        match out {
            Outcome::Text(t) => {
                let t = String::from_utf8_lossy(&t);
                assert!(t.contains("nodes: 2") && t.contains("wheel") && t.contains("meshes: 1"));
            }
            _ => panic!("expected text"),
        }
    }

    /// Wrap a JSON chunk in the minimal GLB container the adapter
    /// accepts: 12-byte header + 8-byte chunk header + chunk.
    #[cfg(feature = "glb")]
    fn glb_wrap(json: &[u8]) -> Vec<u8> {
        let mut glb = Vec::new();
        glb.extend_from_slice(b"glTF");
        glb.extend_from_slice(&2u32.to_le_bytes());
        glb.extend_from_slice(&((12 + 8 + json.len()) as u32).to_le_bytes());
        glb.extend_from_slice(&(json.len() as u32).to_le_bytes());
        glb.extend_from_slice(b"JSON");
        glb.extend_from_slice(json);
        glb
    }

    /// Golden: the full GLB summary, byte for byte.
    ///
    /// The `asset` fragment pins the one order quirk of the Arena
    /// parser: object keys serialise in first-appearance rank order,
    /// not source order. `"version"` is interned under `"pre"` before
    /// `"generator"` appears, so `version` leads the `asset` line even
    /// though `generator` comes first in the source. The lazy walk
    /// must reproduce this exactly.
    #[cfg(feature = "glb")]
    #[test]
    fn glb_output_is_pinned_byte_for_byte() {
        let json = br#"{"pre":{"version":null},"asset":{"generator":"g","version":"2.0"},"scenes":[{"name":"Scene"}],"nodes":[{"name":"Wheel","mesh":0},{"name":"Door"}],"meshes":[{}],"images":[{},{"name":"tex"}]}"#;
        let out = Glb.extract(&glb_wrap(json), "m.glb").unwrap();
        let Outcome::Text(t) = out else {
            panic!("expected text");
        };
        let s = String::from_utf8_lossy(&t);
        assert_eq!(
            s,
            "scenes: 1\n  scenes[..]: Scene\nnodes: 2\n  nodes[..]: Wheel\n  \
nodes[..]: Door\nmeshes: 1\nimages: 2\n  images[..]: tex\n\
asset: {\"version\":\"2.0\",\"generator\":\"g\"}\n"
        );
    }

    /// Duplicate keys take the last value, matching the Arena parser's
    /// `BTreeMap` lookup.
    #[cfg(feature = "glb")]
    #[test]
    fn glb_duplicate_keys_take_the_last_value() {
        let json = br#"{"images":[{"name":"first"}],"images":[{"name":"second"}],"nodes":[{"name":"a"},{"name":"a"}]}"#;
        let out = Glb.extract(&glb_wrap(json), "m.glb").unwrap();
        let Outcome::Text(t) = out else {
            panic!("expected text");
        };
        let s = String::from_utf8_lossy(&t);
        assert_eq!(
            s,
            "nodes: 2\n  nodes[..]: a\n  nodes[..]: a\nimages: 1\n  images[..]: second\n"
        );
    }

    /// A valid JSON chunk that is not an object summarises to nothing,
    /// just as `Value::get` finds nothing on a non-object.
    #[cfg(feature = "glb")]
    #[test]
    fn glb_non_object_json_chunk_yields_empty_text() {
        let out = Glb.extract(&glb_wrap(b"[1, 2, 3]"), "m.glb").unwrap();
        let Outcome::Text(t) = out else {
            panic!("expected text");
        };
        assert!(t.is_empty(), "{t:?}");
    }

    /// Invalid JSON in the chunk is an adapter failure with its
    /// context message, not a silent empty summary.
    #[cfg(feature = "glb")]
    #[test]
    fn glb_invalid_json_reports_the_context_error() {
        let err = match Glb.extract(&glb_wrap(b"{\"a\": 01}"), "m.glb") {
            Ok(_) => panic!("bad number must fail"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(msg.contains("GLB JSON chunk is not valid JSON"), "{msg}");
    }

    #[cfg(any(
        feature = "glb",
        feature = "stl",
        feature = "ply",
        feature = "fbx",
        feature = "pcd",
        feature = "las",
        feature = "vtk",
        feature = "blend",
        feature = "threeds",
        feature = "mrc"
    ))]
    mod fuzz {
        use super::*;

        /// header + one OB block whose ID name sits at 4×ptr + ENDB
        #[cfg(feature = "blend")]
        fn blend_fixture() -> Vec<u8> {
            let mut d = b"BLENDER-v293".to_vec();
            // OB block: code + size + oldaddr(8) + sdna(4) + count(4) + body
            let body = {
                let mut b = vec![0u8; 32]; // 4 pointers
                b.extend_from_slice(b"Cube_ZIRCALOY_probe\0");
                b
            };
            d.extend_from_slice(b"OB\0\0");
            d.extend_from_slice(&(body.len() as u32).to_le_bytes());
            d.extend_from_slice(&[0u8; 8]); // old address
            d.extend_from_slice(&0u32.to_le_bytes()); // sdna
            d.extend_from_slice(&1u32.to_le_bytes()); // count
            d.extend_from_slice(&body);
            d.extend_from_slice(b"ENDB");
            d.extend_from_slice(&[0u8; 16]);
            d
        }

        /// 4D4D main chunk containing a 4000 object chunk
        #[cfg(feature = "threeds")]
        fn threeds_fixture() -> Vec<u8> {
            let mut obj = Vec::new();
            obj.extend_from_slice(&0x4000u16.to_le_bytes());
            let name = b"turbine_blade";
            let obj_len = 6 + name.len() + 1 + 6; // header + name + empty subchunk header
            obj.extend_from_slice(&(obj_len as u32).to_le_bytes());
            obj.extend_from_slice(name);
            obj.push(0);
            obj.extend_from_slice(&0x4100u16.to_le_bytes());
            obj.extend_from_slice(&6u32.to_le_bytes()); // empty mesh chunk
            let mut d = Vec::new();
            d.extend_from_slice(&0x4D4Du16.to_le_bytes());
            d.extend_from_slice(&((6 + obj.len()) as u32).to_le_bytes());
            d.extend_from_slice(&obj);
            d
        }

        #[cfg(feature = "blend")]
        #[test]
        fn blend_lifts_id_names() {
            let out = Blend.extract(&blend_fixture(), "s.blend").unwrap();
            let Outcome::Text(t) = out else {
                panic!("text")
            };
            let s = String::from_utf8_lossy(&t);
            assert!(s.contains("blender v293"), "{s}");
            assert!(s.contains("OB: Cube_ZIRCALOY_probe"), "{s}");
            assert!(s.contains("blocks: 1"), "{s}");
        }

        #[cfg(feature = "threeds")]
        #[test]
        fn threeds_lifts_object_names() {
            let out = Threeds.extract(&threeds_fixture(), "m.3ds").unwrap();
            let Outcome::Text(t) = out else {
                panic!("text")
            };
            let s = String::from_utf8_lossy(&t);
            assert!(s.contains("object: turbine_blade"), "{s}");
            assert!(s.contains("3ds main chunks: 1"), "{s}");
        }

        #[cfg(feature = "blend")]
        #[test]
        fn blend_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("v293", blend_fixture()),
                    ("magic-only", b"BLENDER-v".to_vec()),
                    ("be", b"BLENDER_V400".to_vec()),
                    ("empty", vec![]),
                ],
                1200,
                "blend",
                |data| {
                    let _ = Blend.extract(data, "fuzz.blend");
                },
            );
        }

        #[cfg(feature = "threeds")]
        #[test]
        fn threeds_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("object", threeds_fixture()),
                    ("main-only", {
                        let mut d = 0x4D4Du16.to_le_bytes().to_vec();
                        d.extend_from_slice(&6u32.to_le_bytes());
                        d
                    }),
                    ("empty", vec![]),
                ],
                1200,
                "3ds",
                |data| {
                    let _ = Threeds.extract(data, "fuzz.3ds");
                },
            );
        }

        #[cfg(feature = "stl")]
        fn binary_stl() -> Vec<u8> {
            let mut stl = vec![0u8; 80];
            stl[0] = b'x';
            stl.extend_from_slice(&2u32.to_le_bytes());
            stl.extend_from_slice(&[0u8; 100]);
            stl
        }

        #[cfg(feature = "glb")]
        fn glb_fixture() -> Vec<u8> {
            let json = br#"{"asset":{"version":"2.0"},"nodes":[{"name":"root"}]}"#;
            let mut glb = Vec::new();
            glb.extend_from_slice(b"glTF");
            glb.extend_from_slice(&2u32.to_le_bytes());
            glb.extend_from_slice(&((12 + 8 + json.len()) as u32).to_le_bytes());
            glb.extend_from_slice(&(json.len() as u32).to_le_bytes());
            glb.extend_from_slice(b"JSON");
            glb.extend_from_slice(json);
            glb
        }

        #[cfg(feature = "fbx")]
        fn binary_fbx() -> Vec<u8> {
            let mut d = b"Kaydara FBX Binary  \x00\x1a\x00".to_vec();
            d.extend_from_slice(&7400u32.to_le_bytes());
            // one node record + null record
            d.extend_from_slice(&[0u8; 25]);
            d
        }

        #[cfg(feature = "las")]
        fn las_header() -> Vec<u8> {
            let mut d = vec![0u8; 227];
            d[0..4].copy_from_slice(b"LASF");
            d[24] = 1;
            d[25] = 2;
            d
        }

        #[cfg(feature = "stl")]
        #[test]
        fn stl_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("binary", binary_stl()),
                    ("magic-only", b"solid ".to_vec()),
                    ("empty", vec![]),
                ],
                1200,
                "stl",
                |data| {
                    let _ = Stl.extract(data, "fuzz.stl");
                },
            );
        }

        #[cfg(feature = "glb")]
        #[test]
        fn glb_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("glb", glb_fixture()),
                    ("magic-only", b"glTF".to_vec()),
                    ("empty", vec![]),
                ],
                1200,
                "glb",
                |data| {
                    let _ = Glb.extract(data, "fuzz.glb");
                },
            );
        }

        #[cfg(feature = "fbx")]
        #[test]
        fn fbx_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("binary", binary_fbx()),
                    ("magic-only", b"Kaydara FBX Binary  \x00\x1a\x00".to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "fbx",
                |data| {
                    let _ = Fbx.extract(data, "fuzz.fbx");
                },
            );
        }

        #[cfg(feature = "ply")]
        #[test]
        fn ply_never_panics_on_mutation() {
            let ply =
                b"ply\nformat binary_little_endian 1.0\nelement vertex 3\nend_header\n".to_vec();
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("binary-ply", ply),
                    ("magic-only", b"ply\n".to_vec()),
                    ("empty", vec![]),
                ],
                1000,
                "ply",
                |data| {
                    let _ = Ply.extract(data, "fuzz.ply");
                },
            );
        }

        #[cfg(feature = "pcd")]
        #[test]
        fn pcd_never_panics_on_mutation() {
            let pcd = b"# .PCD v0.7\nVERSION 0.7\nFIELDS x y z\nSIZE 4 4 4\nTYPE F F F\nCOUNT 1 1 1\nWIDTH 1\nHEIGHT 1\nPOINTS 1\nDATA binary\n".to_vec();
            rgx_core::fuzzkit::assert_never_panics(
                vec![("binary-pcd", pcd), ("empty", vec![])],
                1000,
                "pcd",
                |data| {
                    let _ = Pcd.extract(data, "fuzz.pcd");
                },
            );
        }

        #[cfg(feature = "las")]
        #[test]
        fn las_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("las", las_header()),
                    ("magic-only", b"LASF".to_vec()),
                    ("empty", vec![]),
                ],
                1200,
                "las",
                |data| {
                    let _ = Las.extract(data, "fuzz.las");
                },
            );
        }

        /// The PDAL test data holds the same cloud twice: once
        /// uncompressed, once LASzip-compressed. The compressed twin is
        /// the oracle -- if the decompressor and the raw reader disagree
        /// on a single point, the `.laz` is not searchable and the
        /// report is a lie.
        #[cfg(feature = "las")]
        const BASEFILE_LAS: &[u8] = include_bytes!("../testdata/basefile.las");
        #[cfg(feature = "las")]
        const LASZIP_GENERATED_LAZ: &[u8] = include_bytes!("../testdata/laszip-generated.laz");
        #[cfg(feature = "las")]
        const LASZIP_PADDED_LAZ: &[u8] =
            include_bytes!("../testdata/laszip-generated_with2bytespadding.laz");
        #[cfg(feature = "las")]
        const LIBLAS_GENERATED_LAZ: &[u8] = include_bytes!("../testdata/liblas-generated.laz");
        #[cfg(feature = "las")]
        const LASZIP_1_2_LAZ: &[u8] =
            include_bytes!("../testdata/simple-laszip-compressor-version-1.2r0.laz");
        #[cfg(feature = "las")]
        const SIMPLE_LAS: &[u8] = include_bytes!("../testdata/simple.las");
        #[cfg(feature = "las")]
        const SIMPLE_LAZ: &[u8] = include_bytes!("../testdata/simple.laz");
        #[cfg(feature = "las")]
        const LAZ_GPS_OUT_OF_SYNC: &[u8] =
            include_bytes!("../testdata/laz-gps-time-coding-out-of-sync.laz");

        /// A `.laz` whose GPS time coding never settles: the `multi`
        /// symbol keeps asking for another of the four time sequences, and
        /// a reader that follows it has to stop.
        ///
        /// The file is the LASzip-generated cloud with round 39 of the fuzz
        /// kit's mutator applied to it -- the round whose watchdog fired.
        /// Before the time-sequence loop was bounded the decode ran 367
        /// million iterations of it and took nearly three seconds, which is
        /// a hang on any machine that is busy. Now the file is refused,
        /// and the report says why.
        #[cfg(feature = "las")]
        #[test]
        fn laz_refuses_a_gps_time_coding_that_does_not_settle() {
            let txt = las_text(LAZ_GPS_OUT_OF_SYNC);
            assert!(txt.contains("the GPS time coding does not settle"), "{txt}");
        }

        #[cfg(feature = "las")]
        const LAS14_LAZ: &[u8] = include_bytes!("../testdata/las_with_several_extra_byte_bloc.laz");

        /// The report of a file, as text.
        #[cfg(feature = "las")]
        fn las_text(data: &[u8]) -> String {
            let out = Las.extract(data, "x.las").unwrap();
            String::from_utf8_lossy(out_text(&out)).into_owned()
        }

        /// The point lines of a report. The header line "point format:"
        /// is not one of them, hence the digit test.
        #[cfg(feature = "las")]
        fn point_lines(report: &str) -> Vec<&str> {
            report
                .lines()
                .filter(|l| {
                    l.starts_with("point ") && l[6..].starts_with(|ch: char| ch.is_ascii_digit())
                })
                .collect()
        }

        #[cfg(feature = "las")]
        #[test]
        fn laz_matches_its_uncompressed_twin() {
            let laz = las_text(LASZIP_GENERATED_LAZ);
            let las = las_text(BASEFILE_LAS);
            // The whole report, byte for byte: the header the two files
            // share and every point record of the cloud.
            assert_eq!(laz, las);
            // The comparison is only worth anything if it covers the
            // points, not just the header.
            assert!(laz.contains("points: 1065"), "{laz}");
            assert_eq!(point_lines(&laz).len(), 1065);
        }

        #[cfg(feature = "las")]
        #[test]
        fn simple_laz_matches_simple_las() {
            let laz = las_text(SIMPLE_LAZ);
            let las = las_text(SIMPLE_LAS);
            assert_eq!(laz, las);
            assert_eq!(point_lines(&laz).len(), 1065);
        }

        #[cfg(feature = "las")]
        #[test]
        fn laz_reports_the_points_it_decoded() {
            let txt = las_text(LASZIP_GENERATED_LAZ);
            let first = txt.lines().find(|l| l.starts_with("point 0:")).unwrap();
            assert!(
                first.contains("x=637012.24")
                    && first.contains("y=849028.31")
                    && first.contains("z=431.66")
                    && first.contains("intensity=143")
                    && first.contains("flags=0x49")
                    && first.contains("class=1")
                    && first.contains("scan_angle=-9")
                    && first.contains("user_data=132")
                    && first.contains("point_source=7326")
                    && first.contains("gps_time=245380.78254962614")
                    && first.contains("rgb=68,77,88"),
                "{first}"
            );
        }

        /// A `.laz` this adapter cannot decode still answers for its
        /// header, and says why the points are missing. A file that
        /// silently reports nothing is worse than one that refuses.
        #[cfg(feature = "las")]
        #[test]
        fn laz_refuses_the_las14_native_compressor() {
            let txt = las_text(LAS14_LAZ);
            assert!(txt.contains("las version: 1.4"), "{txt}");
            assert!(
                txt.contains("the point records are not decoded:")
                    && txt.contains("LAS 1.4 native item compressors"),
                "{txt}"
            );
        }

        /// The LASzip 1.x item compressors are a different set of
        /// compressors over the same fields, and they are refused with
        /// the reason rather than decoded approximately.
        #[cfg(feature = "las")]
        #[test]
        fn laz_refuses_the_laszip_1x_item_compressors() {
            let txt = las_text(LASZIP_1_2_LAZ);
            assert!(
                txt.contains("the point records are not decoded:")
                    && txt.contains("LASzip 1.x item compressors"),
                "{txt}"
            );
        }

        /// The same cloud, compressed three ways: by LASzip, by LASzip
        /// with two bytes of padding in front of the point data, and by
        /// libLAS. The three reports are the same report.
        #[cfg(feature = "las")]
        #[test]
        fn the_laz_variants_of_one_cloud_agree() {
            let a = las_text(LASZIP_GENERATED_LAZ);
            // The padded file is the same file with two bytes in front
            // of the point data: the same report.
            assert_eq!(a, las_text(LASZIP_PADDED_LAZ));
            // libLAS wrote the same cloud and the same points; only the
            // minimum z in its header differs in the last bit, because
            // the two writers rounded that number differently.
            let points = point_lines;
            assert_eq!(points(&a), points(&las_text(LIBLAS_GENERATED_LAZ)));
        }

        #[cfg(feature = "las")]
        #[test]
        fn laz_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("laz", LASZIP_GENERATED_LAZ.to_vec()),
                    ("laz-truncated", LASZIP_GENERATED_LAZ[..4000].to_vec()),
                    ("las", BASEFILE_LAS.to_vec()),
                    ("empty", vec![]),
                ],
                400,
                "laz",
                |data| {
                    let _ = Las.extract(data, "fuzz.laz");
                },
            );
        }

        #[cfg(feature = "vtk")]
        #[test]
        fn vtk_never_panics_on_mutation() {
            let vtk = b"# vtk DataFile Version 3.0\nZIRCALOY sim\nBINARY\nDATASET STRUCTURED_POINTS\nDIMENSIONS 2 2 2\n".to_vec();
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("binary-vtk", vtk),
                    ("magic-only", b"# vtk DataFile Version".to_vec()),
                    ("empty", vec![]),
                ],
                1000,
                "vtk",
                |data| {
                    let _ = Vtk.extract(data, "fuzz.vtk");
                },
            );
        }

        /// Build a 1024-byte MRC header with the given dims, mode and a
        /// label in slot 0. The header is the entire extractable text
        /// for an MRC; the voxel slab that follows is just bytes.
        #[cfg(feature = "mrc")]
        fn mrc_header(nx: i32, ny: i32, nz: i32, mode: i32, label: &[u8]) -> Vec<u8> {
            let mut h = vec![0u8; 1024];
            h[0..4].copy_from_slice(&nx.to_le_bytes());
            h[4..8].copy_from_slice(&ny.to_le_bytes());
            h[8..12].copy_from_slice(&nz.to_le_bytes());
            h[12..16].copy_from_slice(&mode.to_le_bytes());
            h[40..44].copy_from_slice(&1.0f32.to_le_bytes()); // cell_a
            h[44..48].copy_from_slice(&1.0f32.to_le_bytes()); // cell_b
            h[48..52].copy_from_slice(&1.0f32.to_le_bytes()); // cell_c
            h[52..56].copy_from_slice(&90.0f32.to_le_bytes()); // alpha
            h[56..60].copy_from_slice(&90.0f32.to_le_bytes()); // beta
            h[60..64].copy_from_slice(&90.0f32.to_le_bytes()); // gamma
            h[76..80].copy_from_slice(&0.0f32.to_le_bytes()); // dmin
            h[80..84].copy_from_slice(&1.0f32.to_le_bytes()); // dmax
            h[84..88].copy_from_slice(&0.5f32.to_le_bytes()); // dmean
            h[88..92].copy_from_slice(&1i32.to_le_bytes()); // ispg
            h[92..96].copy_from_slice(&1i32.to_le_bytes()); // nlabl
                                                            // label slot 0 starts at offset 104 and is 80 bytes
            let len = label.len().min(80);
            h[104..104 + len].copy_from_slice(&label[..len]);
            h
        }

        #[cfg(feature = "mrc")]
        #[test]
        fn mrc_extracts_a_label() {
            let h = mrc_header(64, 64, 32, 1, b"nucleosome map EMDB-1234            ");
            let out = Mrc.extract(&h, "test.mrc").unwrap();
            let txt = String::from_utf8_lossy(out_text(&out));
            assert!(txt.contains("format: mrc"));
            assert!(txt.contains("dimensions: 64 64 32"));
            assert!(txt.contains("mode: 1 (int16)"));
            assert!(txt.contains("nucleosome"));
        }

        #[cfg(feature = "mrc")]
        #[test]
        fn mrc_recognises_ccp4_via_map_magic() {
            let mut h = mrc_header(8, 8, 8, 2, b"");
            // CCP4 magic at offset 208.
            h[208..212].copy_from_slice(b"MAP ");
            let out = Mrc.extract(&h, "test.ccp4").unwrap();
            let txt = String::from_utf8_lossy(out_text(&out));
            assert!(txt.contains("format: ccp4"), "got {txt}");
            assert!(txt.contains("mode: 2 (float32)"));
        }

        #[cfg(feature = "mrc")]
        #[test]
        fn mrc_rejects_a_truncated_header() {
            let too_short = vec![0u8; 512];
            assert!(Mrc.extract(&too_short, "x.mrc").is_err());
        }

        /// `out_text` pulls the bytes out of an `Outcome::Text`. The
        /// `Outcome` enum is non-exhaustive, so the `as` cast keeps the
        /// match exhaustive at the call site.
        #[cfg(any(feature = "las", feature = "mrc"))]
        fn out_text(o: &Outcome) -> &[u8] {
            match o {
                Outcome::Text(v) => v,
                _ => &[],
            }
        }
    }
}
