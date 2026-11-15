// SPDX-License-Identifier: Apache-2.0

//! ISO base media files (ISO/IEC 14496-12): HEIC, AVIF, and the `moov`
//! metadata of MP4/M4A/MOV/3GP.
//!
//! Every one of these is a tree of boxes, and the interesting bytes — the
//! EXIF block of a HEIC, the XMP packet of an AVIF, the title and artist of
//! an MP4 — live in a box several levels down, behind an item table whose
//! offsets are relative to the *file*, not to the box that holds them. That
//! last point is the whole difficulty: an item located inside `meta` is not
//! stored inside `meta`.
//!
//! `Reach::Reveal` applies. The XMP packet in particular is plain XML and
//! ripgrep cannot see it because it is not at any searchable offset.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use rgx_core::{decline, Adapter, Outcome, Result};

/// Boxes whose payload is another list of boxes.
const CONTAINERS: [&[u8; 4]; 16] = [
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"udta", b"moof", b"traf", b"mvex", b"edts",
    b"dinf", b"iprp", b"ipco", b"sinf", b"schi", b"mfra",
];

/// Containers that begin with a version/flags word instead of a child box.
const FULL_CONTAINERS: [&[u8; 4]; 3] = [b"meta", b"iprp", b"sinf"];

/// Atom names Apple uses in `ilst`, mapped to what they mean. The leading
/// 0xA9 is the copyright sign in the file and has to be typed as a byte.
fn ilst_name(t: &[u8; 4]) -> &'static str {
    match t {
        b"\xa9nam" => "title",
        b"\xa9ART" => "artist",
        b"\xa9alb" => "album",
        b"\xa9day" => "year",
        b"\xa9cmt" => "comment",
        b"\xa9gen" => "genre",
        b"\xa9too" => "encoder",
        b"\xa9wrt" => "composer",
        b"trkn" => "track",
        b"disk" => "disc",
        b"stik" => "media kind",
        b"hdvd" => "hdtv",
        b"cpil" => "compilation",
        b"covr" => "cover art",
        b"----" => "custom (mdta)",
        _ => "",
    }
}

/// The brands that make a file a still image rather than a movie, and the
/// brand that makes it a movie.
fn brand_kind(major: &[u8; 4]) -> &'static str {
    match major {
        b"heic" => "HEIF image (HEIC)",
        b"heix" => "HEIF image (HEIX)",
        b"mif1" | b"msf1" => "HEIF image",
        b"heim" | b"heis" => "HEIF image sequence",
        b"hevm" => "HEIF image sequence (video)",
        b"hevs" => "HEIF image sequence",
        b"avif" => "AVIF image",
        b"avis" => "AVIF image sequence",
        b"qt  " => "QuickTime",
        b"3gp4" | b"3gp5" => "3GPP",
        b"M4A " => "MPEG-4 audio",
        b"M4V " => "MPEG-4 video",
        _ => "MPEG-4 (ISO base media)",
    }
}

pub struct IsoBmff;
impl Adapter for IsoBmff {
    fn name(&self) -> &'static str {
        "isobmff"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["heic", "heif", "avif", "mp4", "m4a", "m4v", "mov", "3gp"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let mut out = String::new();
        if Box::children_at(data, 0).is_empty() {
            decline!("not an ISO base media file (no top-level box)");
        }
        let mut found = false;
        for b in Box::children_at(data, 0) {
            match &b.typ {
                b"ftyp" => {
                    found = true;
                    let _ = writeln!(out, "{}", ftyp_line(&b));
                }
                b"meta" => {
                    found = true;
                    // `meta` is a FullBox: four bytes of version and flags
                    // come before its children. Reading them as a box header
                    // is what makes a HEIC look empty.
                    if let Some(p) = b.payload().get(4..) {
                        for c in Box::children_at(p, 0) {
                            match &c.typ {
                                b"iinf" => {
                                    let _ = writeln!(out, "items:");
                                    items(&c, &mut out);
                                }
                                b"iloc" => locations(&c, &mut out),
                                b"ipco" => properties(&c, &mut out),
                                b"iprp" => {
                                    for k in
                                        Box::children_at(c.payload().get(4..).unwrap_or(&[]), 0)
                                    {
                                        match &k.typ {
                                            b"ipma" => associations(&k, &mut out),
                                            b"ipco" => properties(&k, &mut out),
                                            _ => {}
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                b"moov" => {
                    found = true;
                    movie_tags(&b, 0, &mut out);
                }
                _ => {}
            }
        }
        if !found {
            decline!("ISO base media file with neither ftyp, meta nor moov");
        }
        // Items whose payload is text: the EXIF block and the XMP packet.
        payloads(data, &mut out);
        Ok(Outcome::Text(out.into_bytes()))
    }
}

struct Box<'a> {
    typ: [u8; 4],
    body: &'a [u8],
}

impl<'a> Box<'a> {
    fn children_at(d: &'a [u8], at: usize) -> Vec<Self> {
        let mut out = Vec::new();
        let mut p = at;
        while p + 8 <= d.len() {
            let size = match d.get(p..p + 4) {
                Some(b) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                None => break,
            };
            let Some(t) = d
                .get(p + 4..p + 8)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
            else {
                break;
            };
            // size 1 means a 64-bit largesize follows; size 0 means "to the
            // end of file", which is how `mdat` is normally written.
            let (hdr, body_at) = match size {
                0 => (8usize, d.len()),
                1 => {
                    let Some(ls) = d.get(p + 8..p + 16) else {
                        break;
                    };
                    let big = u64::from_be_bytes([
                        ls[0], ls[1], ls[2], ls[3], ls[4], ls[5], ls[6], ls[7],
                    ]);
                    if big > d.len() as u64 {
                        break;
                    }
                    (16usize, p + big as usize)
                }
                s => (8usize, p + s as usize),
            };
            if body_at > d.len() || body_at < p + hdr {
                break;
            }
            out.push(Box {
                typ: t,
                body: d.get(p + hdr..body_at).unwrap_or_default(),
            });
            p = body_at;
        }
        out
    }

    fn payload(&self) -> &'a [u8] {
        self.body
    }
}

fn ftyp_line(b: &Box<'_>) -> String {
    let Some(major) = b
        .payload()
        .get(..4)
        .and_then(|x| <[u8; 4]>::try_from(x).ok())
    else {
        return "ftyp (truncated)".to_string();
    };
    let mut s = alloc::format!("{} ", brand_kind(&major));
    let rest = b.payload().get(8..).unwrap_or_default();
    let mut line = String::new();
    for chunk in rest.as_chunks::<4>().0 {
        let _ = write!(line, " {chunk:?}");
    }
    s.push_str(line.trim_start());
    s
}

/// `iinf` → `infe` children: the item IDs, their four-character type and
/// their name. The names are the searchable payload.
fn items(inf: &Box<'_>, out: &mut String) {
    // FullBox header, then entry_count as u16 in version 0 and u32 after.
    let Some(head) = inf.payload().get(..4) else {
        return;
    };
    let version = head[0];
    let count = if version == 0 {
        inf.payload().get(4..6).map(be16).unwrap_or(0) as usize
    } else {
        inf.payload().get(4..8).map(be32).unwrap_or(0) as usize
    };
    let children_at = if version == 0 { 6 } else { 8 };
    for (i, c) in Box::children_at(inf.payload().get(children_at..).unwrap_or(&[]), 0)
        .iter()
        .take(count.min(4096))
        .enumerate()
    {
        let _ = writeln!(out, "  item {i}: {}", infe_line(c));
    }
}

fn infe_line(c: &Box<'_>) -> String {
    let p = c.payload();
    let Some(head) = p.get(..4) else {
        return "infe (truncated)".to_string();
    };
    let version = head[0];
    let (id, mut at) = match version {
        0 | 1 => (
            p.get(4..6)
                .map(|b| u16::from_be_bytes([b[0], b[1]]))
                .unwrap_or(0) as u64,
            6,
        ),
        _ => (
            p.get(4..8)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                .unwrap_or(0) as u64,
            8,
        ),
    };
    // protection index, then the item type
    at += 2;
    let typ = p.get(at..at + 4).unwrap_or(b"    ");
    at += 4;
    let name = cstr(p.get(at..).unwrap_or_default());
    let kind = match typ {
        b"Exif" => "exif",
        b"mime" => "mime",
        b"hvc1" | b"av01" | b"jpeg" => "image data",
        b"uri " => "uri",
        b"pict" => "picture",
        _ => "payload",
    };
    if name.is_empty() {
        alloc::format!("id {id} {kind}")
    } else {
        alloc::format!("id {id} {kind} \"{name}\"")
    }
}

/// `iloc`: where each item's bytes live, which is in the *file*, not in the
/// box. Every offset below is measured from the start of the file.
fn locations(l: &Box<'_>, out: &mut String) {
    let p = l.payload();
    let Some(head) = p.get(..4) else { return };
    let version = head[0];
    let flags = u16::from_be_bytes([head[2], head[3]]);
    // Three nibble pairs packed into four bytes, plus index_size in version
    // 1 and 2. Reading these as bytes rather than nibbles shifts every item.
    let Some(sizes) = p.get(4..8) else { return };
    let offset_size = (sizes[0] & 0x0F) as usize;
    let length_size = (sizes[1] & 0x0F) as usize;
    let base_offset_size = (sizes[2] & 0x0F) as usize;
    let index_size = if version >= 1 {
        sizes.get(3).map(|b| (b & 0x0F) as usize).unwrap_or(0)
    } else {
        0
    };
    let mut at = 8usize;
    let count = if flags & 1 == 1 {
        let v = p.get(at..at + 4).map(be32).unwrap_or(0);
        at += 4;
        v as usize
    } else {
        let v = p
            .get(at..at + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .unwrap_or(0);
        at += 2;
        v as usize
    };
    let _ = writeln!(
        out,
        "  item locations: {count} items, {offset_size}-byte offsets, {length_size}-byte lengths, {index_size}-byte indices"
    );
    for _ in 0..count.min(4096) {
        let id_width = if version < 2 { 2 } else { 4 };
        let Some(idb) = p.get(at..at + id_width) else {
            break;
        };
        let id = if id_width == 2 {
            u16::from_be_bytes([idb[0], idb[1]]) as u64
        } else {
            u32::from_be_bytes([idb[0], idb[1], idb[2], idb[3]]) as u64
        };
        at += id_width;
        if version == 1 || version == 2 {
            at += 4; // reserved + construction method
        }
        at += 2; // data reference index
        let base = read_be(
            p.get(at..at + base_offset_size).unwrap_or(&[]),
            base_offset_size,
        );
        at += base_offset_size;
        let Some(ecb) = p.get(at..at + 2) else { break };
        let extents = u16::from_be_bytes([ecb[0], ecb[1]]) as usize;
        at += 2;
        for _ in 0..extents.min(1024) {
            if index_size > 0 && flags & 1 == 1 && version >= 1 {
                at += 2; // extent_index
                at += 8; // a 64-bit offset when index_size is present
            } else {
                let off = read_be(p.get(at..at + offset_size).unwrap_or(&[]), offset_size);
                at += offset_size;
                let len = read_be(p.get(at..at + length_size).unwrap_or(&[]), length_size);
                at += length_size;
                let _ = writeln!(out, "    item {id} at {} ({len} bytes)", base + off);
            }
        }
    }
}

/// `ipco`: the property boxes. For a still image this is where the content
/// type of each item lives, and `mime` is how the XMP packet is recognised.
fn properties(p: &Box<'_>, out: &mut String) {
    for (i, c) in Box::children_at(p.payload(), 0).iter().enumerate() {
        match &c.typ {
            b"mime" => {
                let ct = cstr(c.payload());
                let _ = writeln!(out, "  property {i}: mime {ct}");
            }
            b"hvcC" => {
                let _ = writeln!(out, "  property {i}: HEVC configuration");
            }
            b"av1C" => {
                let _ = writeln!(out, "  property {i}: AV1 configuration");
            }
            b"ispe" => {
                let s = c.payload();
                if s.len() >= 12 {
                    let w = u32::from_be_bytes([s[4], s[5], s[6], s[7]]);
                    let h = u32::from_be_bytes([s[8], s[9], s[10], s[11]]);
                    let _ = writeln!(out, "  property {i}: image {w}x{h}");
                }
            }
            b"pixi" => {
                let _ = writeln!(
                    out,
                    "  property {i}: pixel format ({} bytes)",
                    c.payload().len()
                );
            }
            b"colr" => {
                let _ = writeln!(out, "  property {i}: colour information");
            }
            b"irot" => {
                let _ = writeln!(out, "  property {i}: rotation");
            }
            b"auxC" => {
                let _ = writeln!(out, "  property {i}: auxiliary type {}", cstr(c.payload()));
            }
            other => {
                let _ = writeln!(out, "  property {i}: {}", String::from_utf8_lossy(other));
            }
        }
    }
}

/// `ipma`: which property belongs to which item, by index.
fn associations(a: &Box<'_>, out: &mut String) {
    let p = a.payload();
    let Some(head) = p.get(..4) else { return };
    let version = head[0];
    let flags = u16::from_be_bytes([head[2], head[3]]);
    let count = p
        .get(4..8)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0) as usize;
    let mut at = 8usize;
    for _ in 0..count.min(4096) {
        let id_width = if version < 1 { 2 } else { 4 };
        let Some(idb) = p.get(at..at + id_width) else {
            break;
        };
        let id = if id_width == 2 {
            u16::from_be_bytes([idb[0], idb[1]]) as u64
        } else {
            u32::from_be_bytes([idb[0], idb[1], idb[2], idb[3]]) as u64
        };
        at += id_width;
        let Some(nb) = p.get(at) else { break };
        let n = *nb as usize;
        at += 1;
        let names_len = n.min(64);
        let _ = names_len;
        let mut ids = String::new();
        for _ in 0..names_len {
            if version < 1 {
                let Some(b) = p.get(at..at + 1) else { break };
                at += 1;
                let _ = write!(ids, " {}", b[0]);
            } else {
                let Some(b) = p.get(at..at + 2) else { break };
                at += 2;
                let _ = write!(ids, " {}", b[0]);
                if flags & 1 == 1 {
                    let _ = write!(ids, ":{}", b[1]);
                }
            }
        }
        let _ = writeln!(out, "  item {id} uses properties:{ids}");
    }
}

/// MP4/MOV `moov` → `udta` → `meta` → `ilst`, and the `mdta` key names that
/// `----` atoms refer to by index.
fn movie_tags(b: &Box<'_>, depth: usize, out: &mut String) {
    if depth > 8 {
        return;
    }
    for c in Box::children_at(b.payload(), 0) {
        match &c.typ {
            b"udta" | b"trak" | b"moov" | b"mdia" => movie_tags(&c, depth + 1, out),
            b"meta" => {
                // FullBox: skip version/flags, then `keys` and `ilst`.
                for k in Box::children_at(c.payload().get(4..).unwrap_or(&[]), 0) {
                    match &k.typ {
                        b"keys" => key_names(&k, out),
                        b"ilst" => item_list(&k, out),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

fn key_names(k: &Box<'_>, out: &mut String) {
    let p = k.payload();
    let Some(head) = p.get(..4) else { return };
    let count = if head[0] == 0 {
        p.get(4..6)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .unwrap_or(0) as usize
    } else {
        p.get(4..8).map(be32).unwrap_or(0) as usize
    };
    let _ = writeln!(out, "  metadata keys: {count}");
    for (i, c) in Box::children_at(p.get(8..).unwrap_or(&[]), 0)
        .iter()
        .take(count.min(1024))
        .enumerate()
    {
        if &c.typ[..] == b"keyname" {
            let _ = writeln!(
                out,
                "    {i}: {}",
                cstr(c.payload().get(4..).unwrap_or(&[]))
            );
        }
    }
}

fn item_list(l: &Box<'_>, out: &mut String) {
    for c in Box::children_at(l.payload(), 0) {
        let raw = &c.typ;
        let label = ilst_name(raw);
        // `----` atoms hold the mdta key index in their body and no payload.
        let mut children = Box::children_at(c.payload(), 0);
        if children.is_empty() && label != "custom (mdta)" {
            let _ = writeln!(out, "  {label} (empty)");
            continue;
        }
        let name = if label.is_empty() {
            String::from_utf8_lossy(raw).into_owned()
        } else {
            label.to_string()
        };
        for d in children.drain(..) {
            match &d.typ {
                b"data" => {
                    let p = d.payload();
                    // 4 bytes of type-set then a 4-byte locale, then the
                    // value. Reading from offset 0 yields the locale instead.
                    let kind = p.get(..4).map(be32).unwrap_or(0);
                    let body = p.get(8..).unwrap_or_default();
                    match kind {
                        1 => {
                            let _ = writeln!(out, "  {name}: {}", String::from_utf8_lossy(body));
                        }
                        0 => {
                            let n = u16::from_be_bytes([
                                body.first().copied().unwrap_or(0),
                                body.get(1).copied().unwrap_or(0),
                            ]);
                            let t = body.get(2).copied().unwrap_or(0);
                            let n2 = u16::from_be_bytes([
                                body.get(3).copied().unwrap_or(0),
                                body.get(4).copied().unwrap_or(0),
                            ]);
                            let _ = writeln!(out, "  {name}: {n}/{t}/{n2}");
                        }
                        21 | 22 => {
                            let v = body
                                .get(..4)
                                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                                .unwrap_or(0);
                            let _ = writeln!(out, "  {name}: {v}");
                        }
                        13 | 14 | 27 => {
                            let _ = writeln!(out, "  {name}: {} bytes of binary", body.len());
                        }
                        _ => {
                            let _ = writeln!(out, "  {name}: {} bytes", body.len());
                        }
                    }
                }
                b"name" | b"mean" => {
                    let _ = writeln!(out, "  {name}: {}", cstr(d.payload()));
                }
                _ => {}
            }
        }
    }
}

/// The EXIF block and the XMP packet, which are stored as item payloads at
/// file offsets. Both are printable: EXIF holds camera, artist, GPS and
/// description strings, and XMP is XML outright.
fn payloads(data: &[u8], out: &mut String) {
    let mut bodies = Vec::new();
    find_meta(data, 0, 0, &mut bodies);
    for d in bodies {
        payloads_of(d, data, out);
    }
}

/// The body of every `meta` box in the file, found by walking the box tree.
///
/// A byte search for `meta` is not this: the four ASCII bytes also occur
/// inside payload data, it cannot tell a box header from data, and the offset
/// it returns is then decremented to reach the header -- which underflows on a
/// file whose first four bytes are `meta`. A walk also finds every `meta`,
/// not just the first, which is what a HEIC with both a movie-level and a
/// picture-level one needs.
fn find_meta<'a>(d: &'a [u8], at: usize, depth: usize, out: &mut Vec<&'a [u8]>) -> usize {
    if depth > 8 {
        return 0;
    }
    let mut n = 0usize;
    for b in Box::children_at(d, at) {
        if &b.typ == b"meta" {
            if let Some(p) = b.payload().get(4..) {
                out.push(p);
                n += 1;
            }
        }
        let full = FULL_CONTAINERS.contains(&&b.typ);
        if CONTAINERS.contains(&&b.typ) || full {
            // A FullBox container opens with version/flags before its children.
            let from = if full { 4 } else { 0 };
            if let Some(p) = b.payload().get(from..) {
                n += find_meta(p, 0, depth + 1, out);
            }
        }
    }
    n
}

fn payloads_of(body: &[u8], data: &[u8], out: &mut String) {
    let kids = Box::children_at(body, 0);
    let loc = kids.iter().find(|b| &b.typ == b"iloc");
    let inf = kids.iter().find(|b| &b.typ == b"iinf");
    let (Some(loc), Some(inf)) = (loc, inf) else {
        return;
    };

    let extents = extent_table(loc.payload());
    let types = item_types(inf.payload());
    if extents.is_empty() {
        return;
    }
    let _ = writeln!(out, "embedded payloads:");
    for (id, off, len) in extents.iter().take(64) {
        let Some(body) = data.get(*off..off.saturating_add(*len)) else {
            continue;
        };
        let kind = types.get(id).map(String::as_str).unwrap_or("");
        if kind == "mime" || looks_like_xml(body) {
            let _ = writeln!(out, "--- XMP packet ({len} bytes) ---");
            for line in text_lines(body, 200) {
                let _ = writeln!(out, "{line}");
            }
        } else if kind == "exif" {
            // The item's first four bytes are the offset from the item's own
            // start to the TIFF header; TIFF strings live past it.
            let skip = body
                .get(..4)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
                .unwrap_or(0);
            let tiff = body.get(skip..).unwrap_or(body);
            let _ = writeln!(out, "--- EXIF ({len} bytes, {skip}-byte item header) ---");
            let mut n = 0;
            for s in printable_runs(tiff, 96) {
                let _ = writeln!(out, "  {s}");
                n += 1;
                if n > 64 {
                    break;
                }
            }
        }
    }
}

fn extent_table(loc: &[u8]) -> Vec<(u64, usize, usize)> {
    let Some(head) = loc.get(..4) else {
        return Vec::new();
    };
    let version = head[0];
    let flags = u16::from_be_bytes([head[2], head[3]]);
    let Some(sizes) = loc.get(4..8) else {
        return Vec::new();
    };
    let offset_size = (sizes[0] & 0x0F) as usize;
    let length_size = (sizes[1] & 0x0F) as usize;
    let base_offset_size = (sizes[2] & 0x0F) as usize;
    let index_size = if version >= 1 {
        sizes.get(3).map(|b| (b & 0x0F) as usize).unwrap_or(0)
    } else {
        0
    };
    let mut at = 8usize;
    let count = if flags & 1 == 1 {
        let v = loc.get(at..at + 4).map(be32).unwrap_or(0);
        at += 4;
        v as usize
    } else {
        let v = loc
            .get(at..at + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .unwrap_or(0);
        at += 2;
        v as usize
    };
    let mut out = Vec::new();
    for _ in 0..count.min(4096) {
        let id_width = if version < 2 { 2 } else { 4 };
        let Some(idb) = loc.get(at..at + id_width) else {
            break;
        };
        let id = if id_width == 2 {
            u16::from_be_bytes([idb[0], idb[1]]) as u64
        } else {
            u32::from_be_bytes([idb[0], idb[1], idb[2], idb[3]]) as u64
        };
        at += id_width;
        if version == 1 || version == 2 {
            at += 4;
        }
        at += 2;
        let base = read_be(
            loc.get(at..at + base_offset_size).unwrap_or(&[]),
            base_offset_size,
        );
        at += base_offset_size;
        let Some(ecb) = loc.get(at..at + 2) else {
            break;
        };
        let extents = u16::from_be_bytes([ecb[0], ecb[1]]) as usize;
        at += 2;
        for _ in 0..extents.min(1024) {
            if index_size > 0 && flags & 1 == 1 && version >= 1 {
                at += 2 + 8;
                continue;
            }
            let off = read_be(loc.get(at..at + offset_size).unwrap_or(&[]), offset_size);
            at += offset_size;
            let len = read_be(loc.get(at..at + length_size).unwrap_or(&[]), length_size);
            at += length_size;
            out.push((id, (base + off) as usize, len as usize));
        }
    }
    out
}

fn item_types(inf: &[u8]) -> alloc::collections::BTreeMap<u64, String> {
    let mut map = alloc::collections::BTreeMap::new();
    let Some(head) = inf.get(..4) else { return map };
    let version = head[0];
    let (count, at0) = if version == 0 {
        (
            inf.get(4..6)
                .map(|b| u16::from_be_bytes([b[0], b[1]]))
                .unwrap_or(0) as usize,
            6usize,
        )
    } else {
        (inf.get(4..8).map(be32).unwrap_or(0) as usize, 8usize)
    };
    for c in Box::children_at(inf.get(at0..).unwrap_or(&[]), 0)
        .iter()
        .take(count.min(4096))
    {
        let p = c.payload();
        let (id, mut at) = match version {
            0 | 1 => (
                p.get(4..6)
                    .map(|b| u16::from_be_bytes([b[0], b[1]]))
                    .unwrap_or(0) as u64,
                6,
            ),
            _ => (p.get(4..8).map(be32).unwrap_or(0) as u64, 8),
        };
        at += 2;
        let typ = p.get(at..at + 4).unwrap_or(b"    ");
        let kind = match typ {
            b"Exif" => "exif",
            b"mime" => "mime",
            _ => "image",
        };
        map.insert(id, kind.to_string());
    }
    map
}

fn be16(b: &[u8]) -> u16 {
    let s = b.get(..2).unwrap_or(&[0, 0]);
    u16::from_be_bytes([s[0], s[1]])
}

fn be32(b: &[u8]) -> u32 {
    let s = b.get(..4).unwrap_or(&[0, 0, 0, 0]);
    u32::from_be_bytes([s[0], s[1], s[2], s[3]])
}

fn read_be(b: &[u8], width: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..width.min(8) {
        v = (v << 8) | b.get(i).copied().unwrap_or(0) as u64;
    }
    v
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|x| *x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn looks_like_xml(b: &[u8]) -> bool {
    let head = &b[..b.len().min(512)];
    head.windows(5).any(|w| w == b"<?xml") || head.windows(9).any(|w| w == b"<x:xmpmeta")
}

fn text_lines(b: &[u8], max: usize) -> Vec<String> {
    let s = String::from_utf8_lossy(b);
    s.lines().take(max).map(ToString::to_string).collect()
}

fn printable_runs(b: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        if b[i] >= 0x20 && b[i] < 0x7f {
            i += 1;
            continue;
        }
        if i - start >= min {
            out.push(String::from_utf8_lossy(&b[start..i]).into_owned());
        }
        start = i + 1;
        i += 1;
    }
    if i - start >= min {
        out.push(String::from_utf8_lossy(&b[start..i]).into_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn box_(typ: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut v = ((body.len() + 8) as u32).to_be_bytes().to_vec();
        v.extend_from_slice(typ);
        v.extend_from_slice(body);
        v
    }

    fn text_of(data: &[u8]) -> String {
        String::from_utf8_lossy(&match IsoBmff.extract(data, "x.mp4").expect("isobmff") {
            Outcome::Text(t) => t,
            _ => panic!("expected Text"),
        })
        .into_owned()
    }

    fn ftyp() -> Vec<u8> {
        let mut body = b"isom".to_vec();
        body.extend_from_slice(&0x200u32.to_be_bytes());
        body.extend_from_slice(b"isomiso2avc1mp41");
        box_(b"ftyp", &body)
    }

    /// `ilst` with a title and an artist, the two tags anyone greps for.
    fn moov_with_tags() -> Vec<u8> {
        let data_box = |s: &str| {
            let mut body = 1u32.to_be_bytes().to_vec(); // type 1 = UTF-8
            body.extend_from_slice(&0u32.to_be_bytes()); // locale
            body.extend_from_slice(s.as_bytes());
            box_(b"data", &body)
        };
        let ilst = {
            let mut b = box_(b"\xa9nam", &data_box("Uma Cancao"));
            b.extend_from_slice(&box_(b"\xa9ART", &data_box("Artista")));
            box_(b"ilst", &b)
        };
        // `meta` is a FullBox: four bytes of version and flags precede its
        // children, and omitting them shifts every child box by four bytes.
        let mut meta_body = vec![0u8; 4];
        meta_body.extend_from_slice(&ilst);
        let meta = box_(b"meta", &meta_body);
        let udta = box_(b"udta", &meta);
        box_(b"moov", &udta)
    }

    #[test]
    fn an_mp4_reports_its_ftyp_brand_and_ilst_tags() {
        let mut d = ftyp();
        d.extend_from_slice(&moov_with_tags());
        let out = text_of(&d);
        assert!(out.contains("MPEG-4"), "{out}");
        assert!(out.contains("title: Uma Cancao"), "{out}");
        assert!(out.contains("artist: Artista"), "{out}");
    }

    #[test]
    fn an_ilst_value_does_not_start_with_the_locale() {
        // The `data` box carries a 4-byte type-set and a 4-byte locale before
        // the string. Reading from offset 0 yields 0x00000001 as text.
        let mut body = 1u32.to_be_bytes().to_vec();
        body.extend_from_slice(&[0xABu8, 0xC7, 0x01, 0x5A]);
        body.extend_from_slice("Titulo".as_bytes());
        let ilst = box_(b"ilst", &box_(b"\xa9nam", &box_(b"data", &body)));
        let mut meta = vec![0u8; 4];
        meta.extend_from_slice(&ilst);
        let udta = box_(b"udta", &box_(b"meta", &meta));
        let mut d = ftyp();
        d.extend_from_slice(&box_(b"moov", &udta));
        let out = text_of(&d);
        assert!(out.contains("title: Titulo"), "{out}");
    }

    #[test]
    fn a_file_that_is_not_iso_bmff_is_declined() {
        assert!(IsoBmff
            .extract(b"\x00\x00\x00\x10junkjunkjunkjunk", "x.mp4")
            .is_err());
        assert!(IsoBmff.extract(b"", "x.avif").is_err());
    }

    #[test]
    fn a_box_whose_size_runs_past_the_file_stops_the_walk() {
        let mut d = ftyp();
        // size 0x7fffffff inside a 40-byte file.
        let bad = 0x7FFF_FFFFu32.to_be_bytes();
        let mut tail = bad.to_vec();
        tail.extend_from_slice(b"moov");
        d.extend_from_slice(&tail);
        // Must not panic and must still report what it did read.
        let out = text_of(&d);
        assert!(out.contains("MPEG-4"), "{out}");
    }
}
