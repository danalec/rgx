// SPDX-License-Identifier: Apache-2.0

//! AVI (RIFF) metadata, hand-rolled — a reduced port of the AVI reader of
//! the `io` project by Dan Gohman, whose work is used here under Apache-2.0:
//! `avih` main header, `strh`/`strf` stream headers (codecs, audio format,
//! video bit depth) and `LIST INFO` tags. Frame data is never decoded.
//! See `NOTICE`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use rgx_core::{bail, decline, Result};
use rgx_core::{Adapter, Outcome};

pub struct AviInfo;
impl Adapter for AviInfo {
    fn name(&self) -> &'static str {
        "avi"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["avi"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(avi_text(data)?.into_bytes()))
    }
}

fn rd_u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd_u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
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

struct StreamOut {
    line: String,
}

fn avi_text(data: &[u8]) -> Result<String> {
    if data.len() < 12 {
        decline!("too small for a RIFF header");
    }
    if &data[0..4] != b"RIFF" {
        decline!("not a RIFF file");
    }
    if &data[8..12] != b"AVI " {
        decline!("not an AVI RIFF form");
    }
    let mut out = String::from("container: avi\n");
    let mut streams: Vec<StreamOut> = Vec::new();
    let mut tags: Vec<(String, String)> = Vec::new();
    let mut frames = 0u32;
    let mut width = 0u32;
    let mut height = 0u32;
    let mut stream_count = 0u32;
    let mut microsec = 0u32;
    let mut has_movi = false;
    let mut has_idx1 = false;

    walk_chunks(
        data,
        12,
        data.len(),
        0,
        &mut Ctx {
            streams: &mut streams,
            tags: &mut tags,
            frames: &mut frames,
            width: &mut width,
            height: &mut height,
            stream_count: &mut stream_count,
            microsec: &mut microsec,
            has_movi: &mut has_movi,
            has_idx1: &mut has_idx1,
        },
    )?;

    if width > 0 {
        let _ = writeln!(out, "width: {width}");
        let _ = writeln!(out, "height: {height}");
    }
    if microsec > 0 {
        let _ = writeln!(out, "frame_duration_us: {microsec}");
    }
    if frames > 0 {
        let _ = writeln!(out, "frames: {frames}");
    }
    if stream_count > 0 {
        let _ = writeln!(out, "streams: {stream_count}");
    }
    for s in &streams {
        let _ = writeln!(out, "stream: {}", s.line);
    }
    for (k, v) in &tags {
        let _ = writeln!(out, "{k}: {v}");
    }
    if has_movi {
        out.push_str("has_movi: true\n");
    }
    if has_idx1 {
        out.push_str("has_index: true\n");
    }
    if out.trim_end() == "container: avi" {
        bail!("AVI structure present but no metadata found");
    }
    Ok(out)
}

struct Ctx<'a> {
    streams: &'a mut Vec<StreamOut>,
    tags: &'a mut Vec<(String, String)>,
    frames: &'a mut u32,
    width: &'a mut u32,
    height: &'a mut u32,
    stream_count: &'a mut u32,
    microsec: &'a mut u32,
    has_movi: &'a mut bool,
    has_idx1: &'a mut bool,
}

fn walk_chunks(data: &[u8], start: usize, end: usize, depth: usize, ctx: &mut Ctx) -> Result<()> {
    if depth > 8 {
        return Ok(());
    }
    let mut pos = start;
    while pos + 8 <= end {
        let id = &data[pos..pos + 4];
        let size = rd_u32le(data, pos + 4) as usize;
        let body_start = pos + 8;
        let body_end = body_start.saturating_add(size).min(end);
        if body_end > data.len() {
            bail!("AVI chunk truncated");
        }
        match id {
            b"LIST" if body_end - body_start >= 4 => {
                let list_type = &data[body_start..body_start + 4];
                match list_type {
                    b"hdrl" => walk_hdrl(data, body_start + 4, body_end, depth + 1, ctx)?,
                    b"INFO" => walk_info(data, body_start + 4, body_end, ctx)?,
                    b"movi" => *ctx.has_movi = true,
                    _ => {}
                }
            }
            b"avih" if body_end - body_start >= 40 => {
                *ctx.microsec = rd_u32le(data, body_start);
                *ctx.frames = rd_u32le(data, body_start + 16);
                *ctx.stream_count = rd_u32le(data, body_start + 24);
                *ctx.width = rd_u32le(data, body_start + 32);
                *ctx.height = rd_u32le(data, body_start + 36);
            }
            b"idx1" => *ctx.has_idx1 = true,
            _ => {}
        }
        pos = body_end + (size & 1);
    }
    Ok(())
}

fn walk_hdrl(data: &[u8], start: usize, end: usize, depth: usize, ctx: &mut Ctx) -> Result<()> {
    if depth > 8 {
        return Ok(());
    }
    let mut pos = start;
    while pos + 8 <= end {
        let id = &data[pos..pos + 4];
        let size = rd_u32le(data, pos + 4) as usize;
        let body_start = pos + 8;
        let body_end = body_start.saturating_add(size).min(end);
        if body_end > data.len() {
            bail!("AVI chunk truncated");
        }
        if id == b"LIST"
            && body_end - body_start >= 4
            && &data[body_start..body_start + 4] == b"strl"
        {
            if let Some(line) = walk_strl(data, body_start + 4, body_end)? {
                ctx.streams.push(StreamOut { line });
            }
        } else if id == b"avih" && body_end - body_start >= 40 {
            *ctx.microsec = rd_u32le(data, body_start);
            *ctx.frames = rd_u32le(data, body_start + 16);
            *ctx.stream_count = rd_u32le(data, body_start + 24);
            *ctx.width = rd_u32le(data, body_start + 32);
            *ctx.height = rd_u32le(data, body_start + 36);
        }
        pos = body_end + (size & 1);
    }
    Ok(())
}

/// Returns a one-line description of the stream (codec, rate, format).
fn walk_strl(data: &[u8], start: usize, end: usize) -> Result<Option<String>> {
    let mut stream_type = String::new();
    let mut codec = String::new();
    let mut scale = 0u32;
    let mut rate = 0u32;
    let mut fw = 0u32;
    let mut fh = 0u32;
    let mut fmt: Option<u16> = None;
    let mut channels: Option<u16> = None;
    let mut hz: Option<u32> = None;
    let mut bits: Option<u16> = None;
    let mut bpp: Option<u16> = None;
    let mut saw_strh = false;
    let mut pos = start;
    while pos + 8 <= end {
        let id = &data[pos..pos + 4];
        let size = rd_u32le(data, pos + 4) as usize;
        let body_start = pos + 8;
        let body_end = body_start.saturating_add(size).min(end);
        if body_end > data.len() {
            bail!("AVI chunk truncated");
        }
        if id == b"strh" && body_end - body_start >= 64 {
            saw_strh = true;
            stream_type = fourcc(&data[body_start..body_start + 4]);
            codec = fourcc(&data[body_start + 4..body_start + 8]);
            scale = rd_u32le(data, body_start + 20);
            rate = rd_u32le(data, body_start + 24);
            fw = rd_u32le(data, body_start + 56);
            fh = rd_u32le(data, body_start + 60);
        } else if id == b"strf" {
            if stream_type == "auds" && body_end - body_start >= 16 {
                fmt = Some(rd_u16le(data, body_start));
                channels = Some(rd_u16le(data, body_start + 2));
                hz = Some(rd_u32le(data, body_start + 4));
                bits = Some(rd_u16le(data, body_start + 14));
            } else if stream_type == "vids" && body_end - body_start >= 16 {
                bpp = Some(rd_u16le(data, body_start + 14));
            }
        }
        pos = body_end + (size & 1);
    }
    if !saw_strh {
        return Ok(None);
    }
    let mut line = String::new();
    if stream_type == "vids" {
        let _ = write!(line, "video {}", codec.trim());
        if fw > 0 {
            let _ = write!(line, " {fw}x{fh}");
        }
        if let Some(b) = bpp {
            let _ = write!(line, " {b}bpp");
        }
        if scale > 0 && rate > 0 {
            let _ = write!(
                line,
                " {}.{:02}fps",
                rate / scale,
                (rate % scale) * 100 / scale
            );
        }
    } else if stream_type == "auds" {
        line.push_str("audio");
        if let Some(f) = fmt {
            let _ = write!(line, " format={f}");
        }
        if let Some(h) = hz {
            let _ = write!(line, " {h}Hz");
        }
        if let Some(c) = channels {
            let _ = write!(line, " {c}ch");
        }
        if let Some(b) = bits {
            let _ = write!(line, " {b}bit");
        }
    } else {
        line.push_str(&stream_type);
        if !codec.trim().is_empty() {
            let _ = write!(line, " {}", codec.trim());
        }
    }
    Ok(Some(line))
}

fn walk_info(data: &[u8], start: usize, end: usize, ctx: &mut Ctx) -> Result<()> {
    let mut pos = start;
    while pos + 8 <= end {
        let id = fourcc(&data[pos..pos + 4]);
        let size = rd_u32le(data, pos + 4) as usize;
        let body_start = pos + 8;
        let body_end = body_start.saturating_add(size).min(end);
        if body_end > data.len() {
            bail!("AVI chunk truncated");
        }
        let value: Vec<u8> = data[body_start..body_end]
            .iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect();
        let value = String::from_utf8_lossy(&value).into_owned();
        if !value.is_empty() {
            ctx.tags.push((id, value));
        }
        pos = body_end + (size & 1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(id: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(id);
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(body);
        if body.len() % 2 == 1 {
            v.push(0);
        }
        v
    }

    fn list(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut inner = kind.to_vec();
        inner.extend_from_slice(body);
        chunk(b"LIST", &inner)
    }

    fn avih_body() -> Vec<u8> {
        let mut b = vec![0u8; 56];
        b[0..4].copy_from_slice(&33333u32.to_le_bytes());
        b[16..20].copy_from_slice(&1000u32.to_le_bytes());
        b[24..28].copy_from_slice(&1u32.to_le_bytes());
        b[32..36].copy_from_slice(&640u32.to_le_bytes());
        b[36..40].copy_from_slice(&480u32.to_le_bytes());
        b
    }

    fn strh_body() -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[0..4].copy_from_slice(b"vids");
        b[4..8].copy_from_slice(b"MJPG");
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..28].copy_from_slice(&30u32.to_le_bytes());
        b[56..60].copy_from_slice(&640u32.to_le_bytes());
        b[60..64].copy_from_slice(&480u32.to_le_bytes());
        b
    }

    fn mini_avi() -> Vec<u8> {
        let mut hdrl_inner = chunk(b"avih", &avih_body());
        let mut strl_inner = chunk(b"strh", &strh_body());
        let mut strf = vec![0u8; 40];
        strf[14..16].copy_from_slice(&24u16.to_le_bytes());
        strl_inner.extend_from_slice(&chunk(b"strf", &strf));
        hdrl_inner.extend_from_slice(&list(b"strl", &strl_inner));

        let mut info_inner = chunk(b"INAM", b"Zircaloy Demo\0");
        info_inner.extend_from_slice(&chunk(b"IART", b"rgx lab\0"));

        let mut body = b"AVI ".to_vec();
        body.extend_from_slice(&list(b"hdrl", &hdrl_inner));
        body.extend_from_slice(&list(b"INFO", &info_inner));
        body.extend_from_slice(&list(b"movi", &[]));
        let mut v = b"RIFF".to_vec();
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&body);
        v
    }

    #[test]
    fn avi_metadata_text() {
        let text = avi_text(&mini_avi()).unwrap();
        assert!(text.contains("container: avi"), "{text}");
        assert!(text.contains("width: 640"), "{text}");
        assert!(text.contains("height: 480"), "{text}");
        assert!(text.contains("frames: 1000"), "{text}");
        assert!(
            text.contains("stream: video MJPG 640x480 24bpp 30.00fps"),
            "{text}"
        );
        assert!(text.contains("INAM: Zircaloy Demo"), "{text}");
        assert!(text.contains("IART: rgx lab"), "{text}");
        assert!(text.contains("has_movi: true"), "{text}");
    }

    #[test]
    fn rejects_non_avi() {
        assert!(avi_text(b"").is_err());
        assert!(avi_text(b"RIFF\x04\x00\x00\x00WAVE").is_err());
        assert!(avi_text(b"not riff at all").is_err());
    }

    #[test]
    fn adapter_extracts() {
        match AviInfo.extract(&mini_avi(), "a.avi").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("width: 640"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    mod fuzz {
        use super::*;

        #[test]
        fn avi_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("avi", mini_avi()),
                    ("riff-magic", b"RIFF\x00\x00\x00\x00AVI ".to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "avi",
                |data| {
                    let _ = AviInfo.extract(data, "fuzz.avi");
                },
            );
        }
    }
}
