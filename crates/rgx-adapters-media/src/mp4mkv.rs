// SPDX-License-Identifier: Apache-2.0

//! Video-container metadata, hand-rolled: MP4/MOV (iTunes-style `ilst`
//! atoms under moov/udta/meta) and MKV/WebM (EBML Tags under Segment).
//! Only tags/titles are extracted — never the media streams themselves.
//!
//! A reduced port of the media reader of the `io` project by Dan Gohman,
//! whose work is used here under Apache-2.0: the typed container kind and
//! the ordered tags with their raw fourcc/element IDs are what this reader
//! walks. See `NOTICE`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use rgx_core::{decline, Result};
use rgx_core::{Adapter, Outcome};

const EBML_MAGIC: [u8; 4] = [0x1A, 0x45, 0xDF, 0xA3];

pub fn extract_text(data: &[u8]) -> Result<String> {
    if data.starts_with(&EBML_MAGIC) {
        mkv_tags(data)
    } else if data.starts_with(b"OggS") {
        ogg_tags(data)
    } else {
        mp4_tags(data)
    }
}

// ---------------------------------------------------------------- MP4

fn fourcc(b: &[u8]) -> [u8; 4] {
    [b[0], b[1], b[2], b[3]]
}

/// iTunes metadata keys we render, mapped to friendly names.
fn mp4_key_name(k: &[u8; 4]) -> Option<&'static str> {
    Some(match k {
        [0xA9, b'n', b'a', b'm'] => "title",
        [0xA9, b'A', b'R', b'T'] | [b'a', b'A', b'R', b'T'] => "artist",
        [0xA9, b'a', b'l', b'b'] => "album",
        [0xA9, b'd', b'a', b'y'] => "year",
        [0xA9, b'c', b'm', b't'] => "comment",
        [0xA9, b'g', b'e', b'n'] => "genre",
        [0xA9, b't', b'o', b'o'] => "encoder",
        [0xA9, b'w', b'r', b't'] => "composer",
        [b's', b't', b'i', b'l'] => "subtitle",
        _ => return None,
    })
}

fn is_mp4_container(ty: &[u8; 4]) -> bool {
    matches!(
        ty,
        b"moov" | b"udta" | b"trak" | b"mdia" | b"minf" | b"stbl" | b"edts" | b"dinf" | b"meta"
    )
}

/// A QuickTime text atom key: the same fourcc table as `ilst`, restricted to
/// the 0xA9 prefix. The prefix is what separates the two layouts — under `ilst`
/// the value hides in a `data` sub-box, under `udta` the atom payload IS the
/// value — so the caller has to know which one it is walking.
fn mp4_udta_text_key(k: &[u8; 4]) -> Option<&'static str> {
    if k[0] != 0xA9 {
        return None;
    }
    mp4_key_name(k)
}

/// The payload of a QuickTime text atom, or `None` when it is not text.
///
/// Two shapes reach here. A bare text payload, and the QuickTime *user data*
/// framing ffmpeg actually writes: a 2-byte length, a 2-byte language code,
/// then the bytes. Those four leading bytes are what made the printability
/// guard decline the very title it was added to catch — the length is
/// big-endian, because it is a QuickTime convention and not ISO-BMFF, and
/// reading it little-endian never matches, so the framing is only stripped
/// when the declared length is exactly the rest of the payload.
///
/// Being under a text key is not enough either: `udta` also carries binary
/// atoms, and lossy-rendering one of those would invent a tag out of a codec
/// blob. UTF-16 payloads are declined rather than mangled.
fn mp4_udta_text(raw: &[u8]) -> Option<String> {
    let body = match raw.get(..2) {
        Some(head)
            if raw.len() >= 4
                && u16::from_be_bytes([head[0], head[1]]) as usize == raw.len() - 4 =>
        {
            &raw[4..]
        }
        _ => raw,
    };
    let text = core::str::from_utf8(body).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let printable = trimmed.bytes().filter(|b| *b >= 0x20).count();
    if printable * 10 < trimmed.len() * 9 {
        return None;
    }
    Some(trimmed.to_string())
}

fn mp4_box(data: &[u8], p: usize, end: usize) -> Option<(usize, [u8; 4], usize, usize)> {
    if p + 8 > end {
        return None;
    }
    let size = super::rd_u32be(data, p) as u64;
    let ty = fourcc(&data[p + 4..p + 8]);
    let (body, bend) = match size {
        0 => (p + 8, end),
        1 => {
            if p + 16 > end {
                return None;
            }
            let large = u64::from_be_bytes(data[p + 8..p + 16].try_into().ok()?);
            (p + 16, (p as u64 + large).min(end as u64) as usize)
        }
        s if s >= 8 => (p + 8, (p as u64 + s).min(end as u64) as usize),
        _ => return None,
    };
    if bend < body || bend > end {
        return None;
    }
    Some((body, ty, bend, if size == 1 { 16 } else { 8 }))
}

fn mp4_walk(
    data: &[u8],
    start: usize,
    end: usize,
    depth: usize,
    in_ilst_path: bool,
    tags: &mut Vec<(&'static str, String)>,
) {
    if depth > 12 {
        return;
    }
    let mut p = start;
    while let Some((body, ty, bend, _hdrlen)) = mp4_box(data, p, end) {
        if in_ilst_path {
            // children of ilst are metadata keys like ©nam
            if let Some(name) = mp4_key_name(&ty) {
                if let Some(v) = mp4_ilst_value(data, body, bend) {
                    if !v.trim().is_empty() {
                        // The name comes from a small fixed table of
                        // friendly labels, so a borrow into .rodata
                        // is enough -- the previous `name.to_string()`
                        // was a heap allocation per tag for a string
                        // the program already owns.
                        tags.push((name, v.trim().to_string()));
                    }
                }
            }
        } else if ty == *b"ilst" {
            mp4_walk(data, body, bend, depth + 1, true, tags);
        } else if ty == *b"meta" {
            // full box: 4 bytes version/flags before children
            if body + 4 <= bend {
                mp4_walk(data, body + 4, bend, depth + 1, false, tags);
            }
        } else if let Some(name) = mp4_udta_text_key(&ty) {
            // QuickTime keeps the same metadata keys as plain text atoms
            // directly under moov/udta, with no meta/ilst wrapper and no `data`
            // sub-box -- and that is where ffmpeg writes a title. Reading only
            // moov/udta/meta/ilst meant a MOV written in the QuickTime layout
            // reported no tag at all, while ffprobe read the same field.
            if let Some(v) = mp4_udta_text(&data[body..bend]) {
                tags.push((name, v));
            }
        } else if is_mp4_container(&ty) {
            mp4_walk(data, body, bend, depth + 1, false, tags);
        }
        if bend <= p {
            break;
        }
        p = bend;
    }
}

/// Inside a metadata key atom: first child is a `data` box whose payload
/// starts with type u32 + locale u32; type 1 = UTF-8, 2 = UTF-16BE.
fn mp4_ilst_value(data: &[u8], start: usize, end: usize) -> Option<String> {
    let (body, ty, bend, _) = mp4_box(data, start, end)?;
    if &ty != b"data" || body + 8 > bend {
        return None;
    }
    let kind = super::rd_u32be(data, body);
    let value = &data[body + 8..bend];
    Some(match kind {
        2 => {
            let units: Vec<u16> = value
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        _ => String::from_utf8_lossy(value).into_owned(),
    })
}

fn mp4_tags(data: &[u8]) -> Result<String> {
    if data.len() < 8 {
        decline!("not a video container (too small)");
    }
    // sanity: offset-4 fourcc should be a plausible box type
    let first = fourcc(&data[4..8]);
    if !is_mp4_container(&first)
        && first != *b"ftyp"
        && first != *b"mdat"
        && first != *b"free"
        && first != *b"wide"
    {
        decline!(
            "not an MP4/MOV container (bad first box {})",
            String::from_utf8_lossy(&first)
        );
    }
    let mut tags: Vec<(&'static str, String)> = Vec::new();
    mp4_walk(data, 0, data.len(), 0, false, &mut tags);
    if tags.is_empty() {
        decline!("no ilst metadata atoms found");
    }
    let mut out = String::new();
    // Write directly via `write!` instead of `format!` + `push_str`:
    // the keys are `&'static str` so the macro expands to a single
    // write per key without the throwaway String the previous path
    // allocated per tag.
    use core::fmt::Write as _;
    for (k, v) in tags {
        let _ = writeln!(out, "{k}: {v}");
    }
    Ok(out)
}

// ---------------------------------------------------------------- MKV / EBML

/// EBML variable-length integer: leading zero bits give the width; the
/// marker bit is part of the value for IDs, masked off for sizes.
fn vint(data: &[u8], p: usize, strip_marker: bool) -> Option<(u64, usize)> {
    let b = *data.get(p)?;
    let len = if b & 0x80 != 0 {
        1
    } else if b & 0x40 != 0 {
        2
    } else if b & 0x20 != 0 {
        3
    } else if b & 0x10 != 0 {
        4
    } else if b & 0x08 != 0 {
        5
    } else if b & 0x04 != 0 {
        6
    } else if b & 0x02 != 0 {
        7
    } else if b & 0x01 != 0 {
        8
    } else {
        return None;
    };
    let mut v = b as u64;
    for k in 1..len {
        v = (v << 8) | *data.get(p + k)? as u64;
    }
    if strip_marker {
        v &= (1u64 << (7 * len)) - 1;
        if v == (1u64 << (7 * len)) - 1 {
            return Some((u64::MAX, len)); // unknown size
        }
    }
    Some((v, len))
}

fn be_float(b: &[u8]) -> f64 {
    match b.len() {
        4 => {
            let s = b.get(..4).unwrap_or(&[0, 0, 0, 0]);
            f32::from_be_bytes([s[0], s[1], s[2], s[3]]) as f64
        }
        8 => {
            let s = b.get(..8).unwrap_or(&[0, 0, 0, 0, 0, 0, 0, 0]);
            f64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
        }
        _ => 0.0,
    }
}

const ID_SEGMENT: u64 = 0x1853_8067;
const ID_INFO: u64 = 0x1549_A966;
const ID_TITLE: u64 = 0x7BA9;
const ID_MUXINGAPP: u64 = 0x4D80;
const ID_WRITINGAPP: u64 = 0x5741;
const ID_DOCTYPE: u64 = 0x4282;
const ID_TAGS: u64 = 0x1254_A3A6;
const ID_TAG: u64 = 0x7373;
const ID_SIMPLETAG: u64 = 0x67C8;
const ID_TAGNAME: u64 = 0x45A3;
const ID_TAGSTRING: u64 = 0x4487;
// Chapters: a container of ChapterAtom, each holding a ChapString (the name
// people search for), a language and a start time.
const ID_CHAPTERS: u64 = 0x1043_A770;
const ID_CHAPTER_ATOM: u64 = 0xB6;
const ID_CHAP_STRING: u64 = 0x85;
const ID_CHAP_LANGUAGE: u64 = 0x437C;
const ID_CHAP_COUNTRY: u64 = 0x437E;
const ID_CHAP_START: u64 = 0x91;

fn ebml_elements(
    data: &[u8],
    start: usize,
    end: usize,
    depth: usize,
    out: &mut Vec<(String, String)>,
) {
    if depth > 16 {
        return;
    }
    let end = end.min(data.len());
    let mut p = start;
    while p + 2 <= end {
        let Some((id, ilen)) = vint(data, p, false) else {
            break;
        };
        let Some((mut size, slen)) = vint(data, p + ilen, true) else {
            break;
        };
        let body = p + ilen + slen;
        if body > end {
            break;
        }
        if size == u64::MAX {
            size = (end - body) as u64;
        }
        let bend = body.saturating_add(size as usize).min(end);
        match id {
            // EBML header (0x1A45DFA3) + the containers we care about
            0x1A45_DFA3 | ID_SEGMENT | ID_TAGS | ID_INFO | ID_CHAPTERS => {
                ebml_elements(data, body, bend, depth + 1, out);
            }
            ID_CHAPTER_ATOM => {
                // A chapter's name, language and country are siblings inside
                // the atom, not inside a nested container, so they are read
                // here rather than by recursing.
                let mut title = String::new();
                let mut lang = String::new();
                let mut country = String::new();
                let mut start = String::new();
                let mut q = body;
                while q + 2 <= bend {
                    let Some((cid, cilen)) = vint(data, q, false) else {
                        break;
                    };
                    let Some((mut csize, cslen)) = vint(data, q + cilen, true) else {
                        break;
                    };
                    let cbody = q + cilen + cslen;
                    if cbody > bend {
                        break;
                    }
                    if csize == u64::MAX {
                        csize = (bend - cbody) as u64;
                    }
                    let cend = cbody.saturating_add(csize as usize).min(bend);
                    let text = || String::from_utf8_lossy(&data[cbody..cend]).into_owned();
                    match cid {
                        ID_CHAP_STRING => title = text(),
                        ID_CHAP_LANGUAGE => lang = text(),
                        ID_CHAP_COUNTRY => country = text(),
                        // ChapStart is in *timecode units*, not seconds: the unit is
                        // TimecodeScale nanoseconds (1 ms by default), and
                        // TimecodeScale is a sibling element this reader does
                        // not resolve. Printing it as seconds would be a
                        // confident wrong number, so the raw unit is named.
                        ID_CHAP_START => start = format!("{} tc", be_float(&data[cbody..cend])),
                        _ => {}
                    }
                    q = cend;
                    if cend <= cbody {
                        break;
                    }
                }
                if !title.is_empty() {
                    let mut label = title;
                    if !lang.is_empty() {
                        let _ = core::fmt::Write::write_fmt(
                            &mut label,
                            format_args!(
                                " [{}{}]",
                                lang.trim(),
                                if country.is_empty() {
                                    String::new()
                                } else {
                                    alloc::format!("-{}", country.trim())
                                }
                            ),
                        );
                    }
                    if !start.is_empty() {
                        let _ = core::fmt::Write::write_fmt(&mut label, format_args!(" @{start}"));
                    }
                    out.push(("chapter".into(), label));
                }
            }
            ID_TAG => {
                let mut name = String::new();
                let mut value = String::new();
                simple_tag(data, body, bend, depth + 1, &mut name, &mut value);
                if !name.is_empty() && !value.is_empty() {
                    out.push((name, value));
                }
            }
            ID_TITLE => out.push((
                "title".into(),
                String::from_utf8_lossy(&data[body..bend]).into_owned(),
            )),
            ID_MUXINGAPP => out.push((
                "muxingapp".into(),
                String::from_utf8_lossy(&data[body..bend]).into_owned(),
            )),
            ID_WRITINGAPP => out.push((
                "writingapp".into(),
                String::from_utf8_lossy(&data[body..bend]).into_owned(),
            )),
            ID_DOCTYPE => out.push((
                "doctype".into(),
                String::from_utf8_lossy(&data[body..bend]).into_owned(),
            )),
            _ => {}
        }
        if bend <= p {
            break;
        }
        p = bend;
    }
}

/// SimpleTag children: TagName + TagString (nested SimpleTags ignored for
/// grep purposes; first level is what people tag).
fn simple_tag(
    data: &[u8],
    start: usize,
    end: usize,
    depth: usize,
    name: &mut String,
    value: &mut String,
) {
    if depth > 8 {
        return;
    }
    let mut p = start;
    while p + 2 <= end {
        let Some((id, ilen)) = vint(data, p, false) else {
            break;
        };
        let Some((mut size, slen)) = vint(data, p + ilen, true) else {
            break;
        };
        let body = p + ilen + slen;
        if body > end {
            break;
        }
        if size == u64::MAX {
            size = (end - body) as u64;
        }
        let bend = body.saturating_add(size as usize).min(end);
        match id {
            ID_TAGNAME if name.is_empty() => {
                *name = String::from_utf8_lossy(&data[body..bend]).into_owned()
            }
            ID_TAGSTRING if value.is_empty() => {
                *value = String::from_utf8_lossy(&data[body..bend]).into_owned()
            }
            // SimpleTags nest (e.g. targets); take the first level that has data
            ID_SIMPLETAG if name.is_empty() && value.is_empty() => {
                let (mut n2, mut v2) = (String::new(), String::new());
                simple_tag(data, body, bend, depth + 1, &mut n2, &mut v2);
                if !n2.is_empty() {
                    *name = n2;
                }
                if !v2.is_empty() {
                    *value = v2;
                }
            }
            _ => {}
        }
        if bend <= p {
            break;
        }
        p = bend;
    }
}

fn mkv_tags(data: &[u8]) -> Result<String> {
    let mut tags = Vec::new();
    ebml_elements(data, 0, data.len(), 0, &mut tags);
    if tags.is_empty() {
        decline!("no EBML tags found");
    }
    let mut out = String::new();
    for (k, v) in tags {
        if !v.trim().is_empty() {
            let _ = writeln!(out, "{k}: {v}");
        }
    }
    if out.trim().is_empty() {
        decline!("no EBML tags found");
    }
    Ok(out)
}

/// Ogg: the comment header carries the vendor string and the `key=value`
/// list. The block is the one every Ogg codec uses -- Theora, Opus and
/// Vorbis alike -- so the reader is the shared Ogg one and not a second
/// implementation of the same list.
fn ogg_tags(data: &[u8]) -> Result<String> {
    let text = crate::ogg_comment(data);
    if text.trim().is_empty() {
        decline!("no Ogg comment header found");
    }
    Ok(text)
}

pub struct VideoTags;
impl Adapter for VideoTags {
    fn name(&self) -> &'static str {
        "videotags"
    }
    fn extensions(&self) -> &'static [&'static str] {
        // `aac` was listed here and is deliberately NOT. This reader walks the
        // atoms of an MP4/MOV/MKV container; a bare `.aac` is an ADTS
        // elementary stream with no `moov` at all, so the claim only ever
        // produced a refusal on the one file the extension promises. With the
        // claim gone an ADTS file falls through to the raw search, which is
        // `rg`'s answer and the honest one for a format with no reader here.
        //
        // `ogv` is here for the other reason: an Ogg Theora video carries
        // the same comment block the Ogg family shares, and the reader for
        // it was already written -- what was missing was the claim, so the
        // file was searched raw and its title never became a property.
        &["mp4", "m4v", "mov", "mkv", "webm", "m4a", "ogv"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(extract_text(data)?.into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mp4_box_b(ty: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + payload.len());
        v.extend_from_slice(&((payload.len() + 8) as u32).to_be_bytes());
        v.extend_from_slice(ty);
        v.extend_from_slice(payload);
        v
    }

    fn ilst_key(key: [u8; 4], value: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_be_bytes()); // type: UTF-8
        data.extend_from_slice(&0u32.to_be_bytes()); // locale
        data.extend_from_slice(value.as_bytes());
        let data_box = mp4_box_b(b"data", &data);
        let mut k = Vec::new();
        k.extend_from_slice(&((data_box.len() + 8) as u32).to_be_bytes());
        k.extend_from_slice(&key);
        k.extend_from_slice(&data_box);
        k
    }

    fn sample_mp4() -> Vec<u8> {
        let ilst = mp4_box_b(
            b"ilst",
            &[
                ilst_key([0xA9, b'n', b'a', b'm'], "ZIRCALOY documentary"),
                ilst_key([0xA9, b'A', b'R', b'T'], "Lab Band"),
                ilst_key([0xA9, b'd', b'a', b'y'], "2026"),
            ]
            .concat(),
        );
        let mut meta_payload = vec![0u8; 4]; // fullbox version/flags
        meta_payload.extend_from_slice(&ilst);
        let meta = mp4_box_b(b"meta", &meta_payload);
        let udta = mp4_box_b(b"udta", &meta);
        let moov = mp4_box_b(b"moov", &udta);
        let ftyp = mp4_box_b(b"ftyp", b"isom\0\0\0\x01isom");
        [ftyp, moov].concat()
    }

    // ---- EBML test builders ----

    /// ID vint: width comes from the ID's bit length (the marker bit is
    /// part of the ID value itself).
    fn id_vint(id: u64) -> Vec<u8> {
        let w = (64 - id.leading_zeros()).div_ceil(8) as usize;
        (id | (1u64 << (7 * w))).to_be_bytes()[8 - w..].to_vec()
    }

    /// size vint: smallest width whose 7*w payload bits fit the value.
    fn size_vint(n: usize) -> Vec<u8> {
        let mut w = 1usize;
        while n >= (1usize << (7 * w)) - 1 {
            w += 1;
        }
        ((n as u64) | (1u64 << (7 * w))).to_be_bytes()[8 - w..].to_vec()
    }

    fn ebml_el(id: u64, payload: &[u8]) -> Vec<u8> {
        let mut v = id_vint(id);
        v.extend_from_slice(&size_vint(payload.len()));
        v.extend_from_slice(payload);
        v
    }

    fn sample_mkv() -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&ebml_el(0x4286, &[1])); // EBMLVersion
        header.extend_from_slice(&ebml_el(ID_DOCTYPE, b"matroska"));
        let mut doc = ebml_el(0x1A45DFA3, &header); // EBML header element
        let mut info = Vec::new();
        info.extend_from_slice(&ebml_el(ID_TITLE, b"ZIRCALOY capture"));
        info.extend_from_slice(&ebml_el(ID_MUXINGAPP, b"rgx-test"));
        let mut simple = Vec::new();
        simple.extend_from_slice(&ebml_el(ID_TAGNAME, b"SUBJECT"));
        simple.extend_from_slice(&ebml_el(ID_TAGSTRING, b"cladding analysis"));
        let mut tag = Vec::new();
        tag.extend_from_slice(&ebml_el(ID_SIMPLETAG, &simple));
        let mut tags = Vec::new();
        tags.extend_from_slice(&ebml_el(ID_TAG, &tag));
        let mut seg = Vec::new();
        seg.extend_from_slice(&ebml_el(ID_INFO, &info));
        seg.extend_from_slice(&ebml_el(ID_TAGS, &tags));
        doc.extend_from_slice(&ebml_el(ID_SEGMENT, &seg));
        doc
    }

    #[test]
    fn mp4_ilst_tags() {
        let text = extract_text(&sample_mp4()).unwrap();
        assert!(text.contains("title: ZIRCALOY documentary"), "{text}");
        assert!(text.contains("artist: Lab Band"), "{text}");
        assert!(text.contains("year: 2026"), "{text}");
    }

    /// QuickTime user data framing: u16 length, u16 language, then the bytes.
    /// ffmpeg writes every `udta` string atom this way, so a test that omits it
    /// would pass while every real MOV still reported nothing.
    fn qt_user_data(text: &str) -> Vec<u8> {
        let mut v = (text.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(&0x55C4u16.to_be_bytes()); // 'und'
        v.extend_from_slice(text.as_bytes());
        v
    }

    /// QuickTime layout: the text atoms sit directly under `moov/udta`, and
    /// there is no `meta`/`ilst` anywhere in the file. This is what ffmpeg
    /// writes for `-metadata title=...`, and reading only the ilst path
    /// reported it as a container with no metadata at all. The title is framed
    /// as user data and the artist is bare, so both payload shapes are covered
    /// by one file.
    fn sample_mov_udta() -> Vec<u8> {
        let mut udta = Vec::new();
        udta.extend_from_slice(&mp4_box_b(
            &[0xA9, b'n', b'a', b'm'],
            &qt_user_data("Zircaloy field notes"),
        ));
        udta.extend_from_slice(&mp4_box_b(&[0xA9, b'A', b'R', b'T'], b"Lab Band"));
        let moov = mp4_box_b(b"moov", &mp4_box_b(b"udta", &udta));
        [mp4_box_b(b"ftyp", b"qt  \0\0\x02\0"), moov].concat()
    }

    #[test]
    fn mov_quicktime_udta_tags_are_read_with_no_ilst_in_the_file() {
        let bytes = sample_mov_udta();
        assert!(
            !bytes.windows(4).any(|w| w == b"ilst"),
            "the fixture must not contain an ilst, or it proves nothing"
        );
        let text = extract_text(&bytes).unwrap();
        assert!(text.contains("title: Zircaloy field notes"), "{text}");
        assert!(text.contains("artist: Lab Band"), "{text}");
    }

    /// The printability guard earns its own case: `udta` carries binary atoms,
    /// and the whole point of the check is that a blob under a text fourcc is
    /// declined instead of rendered into a tag full of mojibake.
    #[test]
    fn a_binary_atom_under_udta_is_not_rendered_as_a_title() {
        let blob = [0x00u8, 0x01, 0x02, 0x03, 0x00, 0xFF, 0x00, 0x00];
        let udta = mp4_box_b(&[0xA9, b'n', b'a', b'm'], &blob);
        let moov = mp4_box_b(b"moov", &udta);
        assert!(
            extract_text(&moov).is_err(),
            "a codec blob rendered itself as a title"
        );
    }

    #[test]
    fn mkv_ebml_tags() {
        let text = extract_text(&sample_mkv()).unwrap();
        assert!(text.contains("doctype: matroska"), "{text}");
        assert!(text.contains("title: ZIRCALOY capture"), "{text}");
        assert!(text.contains("muxingapp: rgx-test"), "{text}");
        assert!(text.contains("SUBJECT: cladding analysis"), "{text}");
    }

    #[test]
    fn mkv_chapter_names_are_read_alongside_tags() {
        // Chapters live in their own container under Segment, so a reader
        // that only walks Info and Tags parses the file and reports none of
        // them. A chap list's names are usually the only prose in the file.
        let mut atom = ebml_el(ID_CHAP_STRING, b"Cladding inspection");
        atom.extend_from_slice(&ebml_el(ID_CHAP_LANGUAGE, b"eng"));
        atom.extend_from_slice(&ebml_el(ID_CHAP_COUNTRY, b"BR"));
        atom.extend_from_slice(&ebml_el(ID_CHAP_START, &125000f64.to_be_bytes()));
        let chapters = ebml_el(ID_CHAPTERS, &ebml_el(ID_CHAPTER_ATOM, &atom));

        let mut doc = ebml_el(0x1A45DFA3, &ebml_el(ID_DOCTYPE, b"matroska"));
        let mut seg = chapters;
        seg.extend_from_slice(&ebml_el(ID_INFO, &ebml_el(ID_TITLE, b"Run 42")));
        doc.extend_from_slice(&ebml_el(ID_SEGMENT, &seg));

        let text = extract_text(&doc).unwrap();
        assert!(
            text.contains("chapter: Cladding inspection [eng-BR]"),
            "{text}"
        );
        assert!(text.contains("@125000 tc"), "{text}");
        assert!(text.contains("title: Run 42"), "{text}");
    }

    /// An Ogg Theora file: the page header, the codec's comment header
    /// (`\x81theora`), then the comment block the Ogg family shares.
    fn sample_ogv() -> Vec<u8> {
        let mut d = vec![0u8; 64];
        d[0..4].copy_from_slice(b"OggS");
        d.extend_from_slice(b"\x81theora");
        d.extend_from_slice(&3u32.to_le_bytes()); // vendor length
        d.extend_from_slice(b"rgx");
        d.extend_from_slice(&1u32.to_le_bytes()); // one comment
        let kv = "TITLE=Zircaloy Clip";
        d.extend_from_slice(&(kv.len() as u32).to_le_bytes());
        d.extend_from_slice(kv.as_bytes());
        d
    }

    /// An Ogg Theora video carries the same comment block every Ogg codec
    /// carries, and the reader for it was already written. What was missing
    /// was the claim: the file was searched raw, and its title never became
    /// a property.
    #[test]
    fn an_ogg_theora_file_is_read_and_claimed() {
        let reg = rgx_core::Registry::new(vec![alloc::boxed::Box::new(VideoTags)]);
        assert!(
            reg.may_claim_for_path("movie.ogv"),
            "the registry must claim .ogv"
        );
        match VideoTags.extract(&sample_ogv(), "movie.ogv").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("TITLE: Zircaloy Clip"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(extract_text(b"not a video container at all").is_err());
        assert!(extract_text(&[]).is_err());
    }

    #[test]
    fn never_panics_on_mutation() {
        rgx_core::fuzzkit::assert_never_panics(
            vec![
                ("mp4", sample_mp4()),
                ("mkv", sample_mkv()),
                ("empty", vec![]),
            ],
            2000,
            "videotags",
            |data| {
                let _ = extract_text(data);
            },
        );
    }
}
