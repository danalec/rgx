// SPDX-License-Identifier: Apache-2.0

//! FLV metadata, hand-rolled — a reduced port of the FLV reader of the `io`
//! project by Dan Gohman, whose work is used here under Apache-2.0: the file
//! header, the `onMetaData` script tag (AMF0) and the first audio/video tag
//! codec bytes. Media payloads are never decoded. See `NOTICE`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use rgx_core::{bail, decline, Result};
use rgx_core::{Adapter, Outcome};

pub struct FlvInfo;
impl Adapter for FlvInfo {
    fn name(&self) -> &'static str {
        "flv"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["flv"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(flv_text(data)?.into_bytes()))
    }
}

fn rd_u24be(b: &[u8], o: usize) -> u32 {
    ((b[o] as u32) << 16) | ((b[o + 1] as u32) << 8) | b[o + 2] as u32
}
fn rd_u32be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd_f64be(b: &[u8], o: usize) -> f64 {
    f64::from_be_bytes([
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

fn flv_text(data: &[u8]) -> Result<String> {
    if data.len() < 9 {
        decline!("fewer bytes than an FLV header");
    }
    if &data[0..3] != b"FLV" {
        decline!("not an FLV file (bad signature)");
    }
    let data_offset = rd_u32be(data, 5) as usize;
    if data_offset < 9 || data_offset > data.len() {
        bail!("FLV header truncated");
    }
    let flags = data[4];
    let mut out = format!("container: flv\nversion: {}\n", data[3]);
    if flags & 0x01 != 0 {
        out.push_str("has_audio: true\n");
    }
    if flags & 0x04 != 0 {
        out.push_str("has_video: true\n");
    }
    // header, then PreviousTagSize0 (u32), then tags each followed by
    // their own PreviousTagSize (u32)
    let mut pos = data_offset + 4;
    let mut guard = 0u32;
    let mut tags = 0u32;
    while pos + 11 <= data.len() {
        guard += 1;
        if guard > 1_000_000 {
            break;
        }
        let tag_type = data[pos];
        let size = rd_u24be(data, pos + 1) as usize;
        let body_start = pos + 11;
        let body_end = match body_start.checked_add(size) {
            Some(e) if e <= data.len() => e,
            _ => break, // truncated tail: keep what we have
        };
        match tag_type {
            18 => {
                if !out.contains("duration:") && !out.contains("encoder:") {
                    if let Some(pairs) = parse_script(&data[body_start..body_end]) {
                        for (k, v) in pairs {
                            let _ = writeln!(out, "{k}: {v}");
                        }
                    }
                }
            }
            9 => {
                if !out.contains("video_codec:") && body_end > body_start {
                    let codec = match data[body_start] & 0x0F {
                        2 => "h263",
                        3 => "screen",
                        4 => "vp6",
                        5 => "vp6-alpha",
                        6 => "screen-v2",
                        7 => "avc",
                        _ => "unknown",
                    };
                    let _ = writeln!(out, "video_codec: {codec}");
                }
            }
            8 if !out.contains("audio_codec:") && body_end > body_start => {
                let b = data[body_start];
                let codec = match (b >> 4) & 0x0F {
                    0 => "pcm",
                    1 => "adpcm",
                    2 => "mp3",
                    3 => "pcm-le",
                    4 => "nellymoser-16k",
                    5 => "nellymoser-8k",
                    6 => "nellymoser",
                    7 => "g711-a",
                    8 => "g711-mu",
                    10 => "aac",
                    11 => "speex",
                    14 => "mp3-8k",
                    _ => "unknown",
                };
                let _ = writeln!(out, "audio_codec: {codec}");
                let _ = writeln!(
                    out,
                    "audio_rate_hz: {}",
                    match (b >> 2) & 0x03 {
                        0 => 5500,
                        1 => 11000,
                        2 => 22000,
                        _ => 44000,
                    }
                );
            }
            _ => {}
        }
        tags += 1;
        pos = body_end + 4; // skip PreviousTagSize
    }
    let _ = writeln!(out, "tags: {tags}");
    Ok(out)
}

/// Flattened key/value pairs from an `onMetaData` script tag body.
fn parse_script(body: &[u8]) -> Option<Vec<(String, String)>> {
    let skip = amf0_skip(body, 0, 0)?;
    // form 1: String "onMetaData" then the object payload
    if body.first() == Some(&0x02) {
        let (value, _) = amf0_read(body, 0, 0).ok()?;
        if let Amf::Str(name) = value {
            if name == "onMetaData" {
                let mut p = skip;
                if body.get(p) == Some(&0x11) {
                    p += 1; // AMF3 marker
                }
                let (obj, _) = amf0_read(body, p, 0).ok()?;
                return flatten(&obj);
            }
        }
    }
    // form 2: bare object payload
    let (value, _) = amf0_read(body, 0, 0).ok()?;
    flatten(&value)
}

enum Amf {
    Num(f64),
    Bool(bool),
    Str(String),
    Obj(Vec<(String, Amf)>),
    Other,
}

fn flatten(value: &Amf) -> Option<Vec<(String, String)>> {
    let pairs = match value {
        Amf::Obj(p) => p,
        _ => return None,
    };
    let mut out = Vec::new();
    for (k, v) in pairs {
        let s = match v {
            Amf::Num(n) => {
                if n.fract() == 0.0 && n.abs() < 9.0e15 {
                    format!("{}", *n as i64)
                } else {
                    format!("{n}")
                }
            }
            Amf::Bool(b) => b.to_string(),
            Amf::Str(s) => s.clone(),
            _ => continue,
        };
        out.push((k.clone(), s));
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Read one AMF0 value; returns the value and the offset after it.
fn amf0_read(b: &[u8], pos: usize, depth: usize) -> Result<(Amf, usize)> {
    if depth > 8 {
        bail!("AMF0 nesting too deep");
    }
    let Some(&ty) = b.get(pos) else {
        bail!("AMF0 truncated");
    };
    let p = pos + 1;
    Ok(match ty {
        0x00 => {
            if p + 8 > b.len() {
                bail!("AMF0 number truncated");
            }
            (Amf::Num(rd_f64be(b, p)), p + 8)
        }
        0x01 => {
            let Some(&v) = b.get(p) else {
                bail!("AMF0 bool truncated");
            };
            (Amf::Bool(v != 0), p + 1)
        }
        0x02 => {
            if p + 2 > b.len() {
                bail!("AMF0 string truncated");
            }
            let len = ((b[p] as usize) << 8) | b[p + 1] as usize;
            if p + 2 + len > b.len() {
                bail!("AMF0 string truncated");
            }
            (
                Amf::Str(String::from_utf8_lossy(&b[p + 2..p + 2 + len]).into_owned()),
                p + 2 + len,
            )
        }
        0x03 | 0x08 => {
            let mut q = p;
            if ty == 0x08 {
                if q + 4 > b.len() {
                    bail!("AMF0 ecma array truncated");
                }
                q += 4; // count is advisory
            }
            let mut pairs = Vec::new();
            loop {
                if q + 2 > b.len() {
                    bail!("AMF0 object truncated");
                }
                let klen = ((b[q] as usize) << 8) | b[q + 1] as usize;
                if klen == 0 {
                    if b.get(q + 2) == Some(&0x09) {
                        break;
                    }
                    bail!("AMF0 object missing end marker");
                }
                q += 2;
                if q + klen > b.len() {
                    bail!("AMF0 key truncated");
                }
                let key = String::from_utf8_lossy(&b[q..q + klen]).into_owned();
                q += klen;
                let (value, next) = amf0_read(b, q, depth + 1)?;
                pairs.push((key, value));
                q = next;
                if pairs.len() > 10_000 {
                    bail!("AMF0 object too large");
                }
            }
            (Amf::Obj(pairs), q + 3)
        }
        _ => (Amf::Other, p),
    })
}

fn amf0_skip(b: &[u8], pos: usize, depth: usize) -> Option<usize> {
    amf0_read(b, pos, depth).ok().map(|(_, next)| next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amf_string(s: &str) -> Vec<u8> {
        let mut v = vec![0x02, (s.len() >> 8) as u8, s.len() as u8];
        v.extend_from_slice(s.as_bytes());
        v
    }

    fn amf_number(n: f64) -> Vec<u8> {
        let mut v = vec![0x00];
        v.extend_from_slice(&n.to_be_bytes());
        v
    }

    fn amf_ecma(pairs: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut v = vec![0x08];
        v.extend_from_slice(&(pairs.len() as u32).to_be_bytes());
        for (k, val) in pairs {
            v.extend_from_slice(&[(k.len() >> 8) as u8, k.len() as u8]);
            v.extend_from_slice(k.as_bytes());
            v.extend_from_slice(val);
        }
        v.extend_from_slice(&[0, 0, 0x09]);
        v
    }

    fn tag(tag_type: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![
            tag_type,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        v.extend_from_slice(body);
        v.extend_from_slice(&(body.len() as u32).to_be_bytes());
        v
    }

    fn mini_flv() -> Vec<u8> {
        let mut script_body = amf_string("onMetaData");
        script_body.extend_from_slice(&amf_ecma(&[
            ("duration", amf_number(12.5)),
            ("width", amf_number(640.0)),
            ("height", amf_number(480.0)),
            ("encoder", amf_string("upstream-enc 2.0")),
        ]));
        let mut v = b"FLV\x01\x05".to_vec();
        v.extend_from_slice(&9u32.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&tag(18, &script_body));
        v.extend_from_slice(&tag(9, &[0x17, 0x01, 0x00]));
        v.extend_from_slice(&tag(8, &[0xAF, 0x01]));
        v
    }

    #[test]
    fn flv_metadata_text() {
        let text = flv_text(&mini_flv()).unwrap();
        assert!(text.contains("container: flv"), "{text}");
        assert!(text.contains("version: 1"), "{text}");
        assert!(text.contains("has_audio: true"), "{text}");
        assert!(text.contains("has_video: true"), "{text}");
        assert!(text.contains("duration: 12.5"), "{text}");
        assert!(text.contains("width: 640"), "{text}");
        assert!(text.contains("height: 480"), "{text}");
        assert!(text.contains("encoder: upstream-enc 2.0"), "{text}");
        assert!(text.contains("video_codec: avc"), "{text}");
        assert!(text.contains("audio_codec: aac"), "{text}");
        assert!(text.contains("audio_rate_hz: 44000"), "{text}");
        assert!(text.contains("tags: 3"), "{text}");
    }

    #[test]
    fn rejects_non_flv() {
        assert!(flv_text(b"").is_err());
        assert!(flv_text(b"FLV").is_err());
        assert!(flv_text(b"NOTFLV\x01\x00\x00\x00\x00\x09").is_err());
    }

    #[test]
    fn adapter_extracts() {
        match FlvInfo.extract(&mini_flv(), "a.flv").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("encoder: upstream-enc 2.0"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    mod fuzz {
        use super::*;

        #[test]
        fn flv_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("flv", mini_flv()),
                    ("magic-only", b"FLV\x01\x00".to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "flv",
                |data| {
                    let _ = FlvInfo.extract(data, "fuzz.flv");
                },
            );
        }
    }
}
