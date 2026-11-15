// SPDX-License-Identifier: Apache-2.0

//! ASF/WMV metadata, hand-rolled — reduced port of an upstream ASF
//! reader: File Properties (duration, bitrate, creation
//! time), Content Description (title/author/...), Extended Content
//! Description (`WM/*` attributes), Stream Properties (audio WAVEFORMATEX,
//! video BITMAPINFOHEADER with codec fourCC). Packet payloads are never
//! decoded.

use alloc::string::{String, ToString};
use core::fmt::Write as _;
use rgx_core::{bail, decline, Result};
use rgx_core::{Adapter, Outcome};

pub struct AsfInfo;
impl Adapter for AsfInfo {
    fn name(&self) -> &'static str {
        "asf"
    }
    fn extensions(&self) -> &'static [&'static str] {
        // `wma` is here for the same reason `wmv` is: a Windows Media file
        // and a Windows Media Video file are the same ASF container, and
        // the reader does not care which one it is holding. The claim was
        // missing, and the missing claim was not a cosmetic gap: ASF
        // stores its strings as UTF-16, so the title of a `.wma` is not
        // findable in the raw bytes by a search for its own text -- the
        // file was in the corpus, the words were in it, and only the
        // reader could see them.
        &["wmv", "asf", "wm", "wma"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(asf_text(data)?.into_bytes()))
    }
}

const HEADER_OBJECT: [u8; 16] = [
    0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
];
const FILE_PROPERTIES: [u8; 16] = [
    0xA1, 0xDC, 0xAB, 0x8C, 0x47, 0xA9, 0xCF, 0x11, 0x8E, 0xE4, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65,
];
const STREAM_PROPERTIES: [u8; 16] = [
    0x91, 0x07, 0xDC, 0xB7, 0xB7, 0xA9, 0xCF, 0x11, 0x8E, 0xE6, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65,
];
const HEADER_EXTENSION: [u8; 16] = [
    0xB5, 0x03, 0xBF, 0x5F, 0x2E, 0xA9, 0xCF, 0x11, 0x8E, 0xE3, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65,
];
const CONTENT_DESCRIPTION: [u8; 16] = [
    0x33, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
];
const EXTENDED_CONTENT_DESCRIPTION: [u8; 16] = [
    0x40, 0xA4, 0xD0, 0xD2, 0x07, 0xE3, 0xD2, 0x11, 0x97, 0xF0, 0x00, 0xA0, 0xC9, 0x5E, 0xA8, 0x50,
];
const STREAM_TYPE_AUDIO: [u8; 16] = [
    0x40, 0x9E, 0x69, 0xF8, 0x4D, 0x5B, 0xCF, 0x11, 0xA8, 0xFD, 0x00, 0x80, 0x5F, 0x5C, 0x44, 0x2B,
];
const STREAM_TYPE_VIDEO: [u8; 16] = [
    0xC0, 0xEF, 0x19, 0xBC, 0x4D, 0x5B, 0xCF, 0x11, 0xA8, 0xFD, 0x00, 0x80, 0x5F, 0x5C, 0x44, 0x2B,
];

const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

fn rd_u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd_u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd_u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}

fn utf16le(b: &[u8]) -> String {
    let mut s = String::new();
    for ch in b.as_chunks::<2>().0 {
        let u = u16::from_le_bytes([ch[0], ch[1]]);
        if u == 0 {
            break;
        }
        if let Some(c) = char::from_u32(u as u32) {
            s.push(c);
        }
    }
    s
}

fn fourcc(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if c.is_ascii_graphic() || c == b' ' {
                c as char
            } else {
                '.'
            }
        })
        .collect()
}

struct Ctx {
    out: String,
}

fn asf_text(data: &[u8]) -> Result<String> {
    if data.len() < 30 {
        decline!("fewer bytes than an ASF header");
    }
    if data[0..16] != HEADER_OBJECT {
        decline!("not an ASF/WMV file (bad header GUID)");
    }
    let header_size = rd_u64le(data, 16) as usize;
    if header_size < 30 || header_size > data.len() {
        bail!("ASF header object truncated");
    }
    let mut ctx = Ctx {
        out: String::from("container: asf\n"),
    };
    let num_objects = rd_u32le(data, 24) as usize;
    walk(data, 30, header_size, num_objects, false, &mut ctx)?;
    walk(data, header_size, data.len(), usize::MAX, false, &mut ctx)?;
    if ctx.out.trim_end() == "container: asf" {
        bail!("ASF structure present but no metadata found");
    }
    Ok(ctx.out)
}

fn walk(
    data: &[u8],
    start: usize,
    end: usize,
    limit: usize,
    extended: bool,
    ctx: &mut Ctx,
) -> Result<()> {
    let mut pos = start;
    let mut seen = 0usize;
    while pos + 24 <= end && seen < limit {
        seen += 1;
        let guid = &data[pos..pos + 16];
        let size = rd_u64le(data, pos + 16) as usize;
        if size < 24 {
            bail!("ASF object with bad size");
        }
        let body_start = pos + 24;
        let body_end = body_start.saturating_add(size - 24).min(end);
        if body_end > data.len() {
            bail!("ASF object truncated");
        }
        dispatch(data, guid, body_start, body_end, extended, ctx)?;
        pos = body_end;
    }
    Ok(())
}

fn dispatch(
    data: &[u8],
    guid: &[u8],
    bs: usize,
    be: usize,
    extended: bool,
    ctx: &mut Ctx,
) -> Result<()> {
    let len = be - bs;
    match guid {
        g if g == FILE_PROPERTIES && len >= 80 => {
            let creation = rd_u64le(data, bs + 24);
            if creation >= FILETIME_UNIX_EPOCH {
                let _ = writeln!(
                    ctx.out,
                    "creation_time: {}",
                    (creation - FILETIME_UNIX_EPOCH) / 10_000_000
                );
            }
            let _ = writeln!(ctx.out, "data_packets: {}", rd_u64le(data, bs + 32));
            let play_100ns = rd_u64le(data, bs + 40);
            let proll_ms = rd_u64le(data, bs + 56);
            let dur = play_100ns.saturating_div(10_000).saturating_sub(proll_ms);
            let _ = writeln!(ctx.out, "duration_ms: {dur}");
            let flags = rd_u32le(data, bs + 64);
            if flags & 0x2 != 0 {
                ctx.out.push_str("seekable: true\n");
            }
            let _ = writeln!(ctx.out, "bitrate: {}", rd_u32le(data, bs + 76));
        }
        g if g == STREAM_PROPERTIES && len >= 54 => {
            let stream_type = &data[bs..bs + 16];
            let is_audio = stream_type == STREAM_TYPE_AUDIO;
            let is_video = stream_type == STREAM_TYPE_VIDEO;
            let specific_len = rd_u32le(data, bs + 40) as usize;
            let specific_start = bs + 54;
            let avail = specific_start
                .saturating_add(specific_len)
                .min(be)
                .saturating_sub(specific_start);
            let mut line = String::from("stream: ");
            if is_audio {
                line.push_str("audio");
                if avail >= 16 {
                    let _ = write!(line, " format={}", rd_u16le(data, specific_start));
                    let _ = write!(line, " {}Hz", rd_u32le(data, specific_start + 4));
                    let _ = write!(line, " {}ch", rd_u16le(data, specific_start + 2));
                    let _ = write!(line, " {}bit", rd_u16le(data, specific_start + 14));
                }
            } else if is_video {
                line.push_str("video");
                if avail >= 20 {
                    let width = i32::from_le_bytes([
                        data[specific_start + 4],
                        data[specific_start + 5],
                        data[specific_start + 6],
                        data[specific_start + 7],
                    ]);
                    let height = i32::from_le_bytes([
                        data[specific_start + 8],
                        data[specific_start + 9],
                        data[specific_start + 10],
                        data[specific_start + 11],
                    ]);
                    let _ = write!(
                        line,
                        " {}",
                        fourcc(&data[specific_start + 16..specific_start + 20]).trim()
                    );
                    if width > 0 {
                        let _ = write!(line, " {width}x{height}");
                    }
                    let _ = write!(line, " {}bpp", rd_u16le(data, specific_start + 14));
                }
            } else {
                line.push_str(&fourcc(stream_type));
            }
            if rd_u16le(data, bs + 48) & 0x8000 != 0 {
                line.push_str(" (encrypted)");
            }
            ctx.out.push_str(&line);
            ctx.out.push('\n');
        }
        g if g == HEADER_EXTENSION && len >= 22 => {
            let ext_size = rd_u32le(data, bs + 18) as usize;
            let ext_start = bs + 22;
            let ext_end = ext_start.saturating_add(ext_size).min(be);
            walk(data, ext_start, ext_end, 10_000, true, ctx)?;
        }
        g if g == CONTENT_DESCRIPTION && len >= 10 => {
            let lens = [
                ("title", rd_u16le(data, bs) as usize),
                ("author", rd_u16le(data, bs + 2) as usize),
                ("copyright", rd_u16le(data, bs + 4) as usize),
                ("description", rd_u16le(data, bs + 6) as usize),
                ("rating", rd_u16le(data, bs + 8) as usize),
            ];
            let mut p = bs + 10;
            for (name, n) in lens {
                let end_s = p.saturating_add(n).min(be);
                if end_s > data.len() {
                    break;
                }
                let v = utf16le(&data[p..end_s]);
                p = end_s;
                if !v.is_empty() {
                    let _ = writeln!(ctx.out, "{name}: {v}");
                }
            }
        }
        g if g == EXTENDED_CONTENT_DESCRIPTION && len >= 2 => {
            let count = rd_u16le(data, bs) as usize;
            let mut p = bs + 2;
            for _ in 0..count.min(10_000) {
                if p + 2 > be {
                    break;
                }
                let name_len = rd_u16le(data, p) as usize;
                p += 2;
                if p + name_len + 4 > be {
                    break;
                }
                let name = utf16le(&data[p..p + name_len]);
                p += name_len;
                let value_type = rd_u16le(data, p);
                let value_len = rd_u16le(data, p + 2) as usize;
                p += 4;
                if p + value_len > be {
                    break;
                }
                let value = match value_type {
                    0 => utf16le(&data[p..p + value_len]),
                    3 if value_len == 4 => rd_u32le(data, p).to_string(),
                    4 if value_len == 8 => rd_u64le(data, p).to_string(),
                    5 if value_len == 2 => rd_u16le(data, p).to_string(),
                    2 if value_len == 4 => (rd_u32le(data, p) != 0).to_string(),
                    _ => alloc_len(value_len),
                };
                p += value_len;
                if !name.is_empty() && !value.is_empty() {
                    let _ = writeln!(ctx.out, "{name}: {value}");
                }
            }
        }
        _ => {
            let _ = extended;
        }
    }
    Ok(())
}

fn alloc_len(n: usize) -> String {
    format!("{n} bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn obj(guid: &[u8; 16], body: &[u8]) -> Vec<u8> {
        let mut v = guid.to_vec();
        v.extend_from_slice(&((body.len() + 24) as u64).to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    fn utf16(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    fn file_props_body() -> Vec<u8> {
        let mut b = vec![0u8; 80];
        b[16..24].copy_from_slice(&4096u64.to_le_bytes());
        b[24..32].copy_from_slice(&133_170_048_000_000_000u64.to_le_bytes()); // 2023-01-01
        b[32..40].copy_from_slice(&500u64.to_le_bytes());
        b[40..48].copy_from_slice(&60_000_000u64.to_le_bytes());
        b[56..64].copy_from_slice(&3_000u64.to_le_bytes());
        b[64..68].copy_from_slice(&2u32.to_le_bytes());
        b[76..80].copy_from_slice(&1_000_000u32.to_le_bytes());
        b
    }

    fn stream_video_body() -> Vec<u8> {
        let mut specific = vec![0u8; 40];
        specific[0..4].copy_from_slice(&40u32.to_le_bytes());
        specific[4..8].copy_from_slice(&640i32.to_le_bytes());
        specific[8..12].copy_from_slice(&480i32.to_le_bytes());
        specific[14..16].copy_from_slice(&24u16.to_le_bytes());
        specific[16..20].copy_from_slice(b"WMV3");
        let mut b = STREAM_TYPE_VIDEO.to_vec();
        b.extend_from_slice(&[0u8; 16]);
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&(specific.len() as u32).to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&specific);
        b
    }

    fn content_description_body() -> Vec<u8> {
        let title = utf16("Zircaloy Clip");
        let author = utf16("rgx lab");
        let empty = Vec::<u8>::new();
        let mut b = Vec::new();
        for s in [&title, &author, &empty, &empty, &empty] {
            b.extend_from_slice(&(s.len() as u16).to_le_bytes());
        }
        b.extend_from_slice(&title);
        b.extend_from_slice(&author);
        b
    }

    fn ext_content_description_body() -> Vec<u8> {
        let name = utf16("WM/ToolName");
        let value = utf16("rgx-encoder 1.0");
        let mut b = 1u16.to_le_bytes().to_vec();
        b.extend_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(&name);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(value.len() as u16).to_le_bytes());
        b.extend_from_slice(&value);
        b
    }

    fn mini_asf() -> Vec<u8> {
        let mut inner = obj(&FILE_PROPERTIES, &file_props_body());
        inner.extend_from_slice(&obj(&STREAM_PROPERTIES, &stream_video_body()));
        inner.extend_from_slice(&obj(&CONTENT_DESCRIPTION, &content_description_body()));
        inner.extend_from_slice(&obj(
            &EXTENDED_CONTENT_DESCRIPTION,
            &ext_content_description_body(),
        ));
        let mut header = HEADER_OBJECT.to_vec();
        header.extend_from_slice(&((inner.len() + 30) as u64).to_le_bytes());
        header.extend_from_slice(&4u32.to_le_bytes());
        header.extend_from_slice(&[0u8; 2]);
        header.extend_from_slice(&inner);
        header
    }

    #[test]
    fn asf_metadata_text() {
        let text = asf_text(&mini_asf()).unwrap();
        assert!(text.contains("container: asf"), "{text}");
        assert!(text.contains("creation_time: 1672531200"), "{text}");
        assert!(text.contains("duration_ms: 3000"), "{text}");
        assert!(text.contains("bitrate: 1000000"), "{text}");
        assert!(text.contains("seekable: true"), "{text}");
        assert!(text.contains("stream: video WMV3 640x480 24bpp"), "{text}");
        assert!(text.contains("title: Zircaloy Clip"), "{text}");
        assert!(text.contains("author: rgx lab"), "{text}");
        assert!(text.contains("WM/ToolName: rgx-encoder 1.0"), "{text}");
    }

    /// A `.wma` is the same ASF container as a `.wmv`, and the claim was
    /// missing. The missing claim was not a cosmetic gap: ASF stores its
    /// strings as UTF-16, so the title of a `.wma` cannot be found in the
    /// raw bytes by a search for its own text. The file was in the corpus,
    /// the words were in it, and only the reader could see them.
    #[test]
    fn a_wma_is_the_same_container_and_is_claimed() {
        let reg = rgx_core::Registry::new(vec![alloc::boxed::Box::new(AsfInfo)]);
        assert!(
            reg.may_claim_for_path("song.wma"),
            "the registry must claim .wma"
        );
        match AsfInfo.extract(&mini_asf(), "song.wma").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("title: Zircaloy Clip"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn rejects_non_asf() {
        assert!(asf_text(b"").is_err());
        assert!(asf_text(b"RIFF\x00\x00\x00\x00AVI ").is_err());
        assert!(asf_text(b"not asf at all, just text").is_err());
    }

    #[test]
    fn adapter_extracts() {
        match AsfInfo.extract(&mini_asf(), "a.wmv").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("title: Zircaloy Clip"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    mod fuzz {
        use super::*;

        #[test]
        fn asf_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("asf", mini_asf()),
                    ("header-magic", HEADER_OBJECT.to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "asf",
                |data| {
                    let _ = AsfInfo.extract(data, "fuzz.wmv");
                },
            );
        }
    }
}
