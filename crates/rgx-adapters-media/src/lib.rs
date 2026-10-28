// SPDX-License-Identifier: Apache-2.0

//! Media-metadata adapters: EXIF/TIFF, audio tags, FITS, DICOM.
//!
//! Heavy binary payloads (pixels, waveforms) are never extracted — only
//! metadata. Audio tags are parsed manually (ID3v1, RIFF INFO, FLAC Vorbis
//! comment, Ogg Vorbis), and so is EXIF/TIFF, which is why the crate's only
//! dependency is `rgx-core`.

#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::boxed::Box;
#[cfg(any(
    feature = "exif",
    feature = "tiff",
    feature = "psd",
    feature = "jpeg2000",
    feature = "jpegxl",
    feature = "audio-tags",
    feature = "video-tags",
    feature = "fits",
    feature = "dicom"
))]
use alloc::string::String;
#[cfg(any(
    feature = "exif",
    feature = "tiff",
    feature = "audio-tags",
    feature = "video-tags",
    feature = "fits",
    feature = "dicom"
))]
use alloc::string::ToString;
use alloc::vec::Vec;
#[cfg(any(
    feature = "exif",
    feature = "tiff",
    feature = "psd",
    feature = "jpeg2000",
    feature = "jpegxl",
    feature = "audio-tags",
    feature = "video-tags",
    feature = "fits",
    feature = "dicom"
))]
use core::fmt::Write as _;
#[cfg(feature = "tiff")]
use rgx_core::bail;
#[cfg(any(
    feature = "exif",
    feature = "audio-tags",
    feature = "fits",
    feature = "dicom"
))]
use rgx_core::decline;
use rgx_core::Adapter;
#[cfg(any(feature = "exif", feature = "tiff"))]
use rgx_core::Context;
#[cfg(any(feature = "exif", feature = "tiff"))]
use rgx_core::Field;
#[cfg(any(
    feature = "exif",
    feature = "tiff",
    feature = "audio-tags",
    feature = "fits",
    feature = "dicom"
))]
use rgx_core::Outcome;
#[cfg(any(
    feature = "exif",
    feature = "tiff",
    feature = "audio-tags",
    feature = "fits",
    feature = "dicom"
))]
use rgx_core::Result;

#[cfg(feature = "asf")]
mod asf;
#[cfg(feature = "avi")]
mod avi;
#[cfg(any(
    feature = "exif",
    feature = "tiff",
    feature = "psd",
    feature = "jpeg2000",
    feature = "jpegxl"
))]
mod exif;
#[cfg(any(feature = "font", feature = "woff", feature = "mobi"))]
mod extra;
#[cfg(feature = "flv")]
mod flv;
#[cfg(any(feature = "gif", feature = "bmp"))]
mod imgmeta;
#[cfg(feature = "video-tags")]
mod mp4mkv;
#[cfg(feature = "mpeg")]
mod mpeg;
#[cfg(any(
    feature = "psd",
    feature = "jpeg2000",
    feature = "jpegxl",
    feature = "openexr"
))]
mod photos;

pub fn adapters() -> Vec<Box<dyn Adapter>> {
    vec![
        #[cfg(feature = "exif")]
        Box::new(ExifJpeg),
        #[cfg(feature = "tiff")]
        Box::new(Tiff),
        #[cfg(feature = "gif")]
        Box::new(imgmeta::Gif),
        #[cfg(feature = "bmp")]
        Box::new(imgmeta::Bmp),
        #[cfg(feature = "psd")]
        Box::new(photos::Psd),
        #[cfg(feature = "jpeg2000")]
        Box::new(photos::Jpeg2000),
        #[cfg(feature = "jpegxl")]
        Box::new(photos::JpegXl),
        #[cfg(feature = "openexr")]
        Box::new(photos::OpenExr),
        #[cfg(feature = "avi")]
        Box::new(avi::AviInfo),
        #[cfg(feature = "asf")]
        Box::new(asf::AsfInfo),
        #[cfg(feature = "flv")]
        Box::new(flv::FlvInfo),
        #[cfg(feature = "mpeg")]
        Box::new(mpeg::MpegInfo),
        #[cfg(feature = "audio-tags")]
        Box::new(AudioTags),
        #[cfg(feature = "fits")]
        Box::new(Fits),
        #[cfg(feature = "dicom")]
        Box::new(Dicom),
        #[cfg(feature = "font")]
        Box::new(extra::FontNames),
        #[cfg(feature = "woff")]
        Box::new(extra::Woff),
        #[cfg(feature = "mobi")]
        Box::new(extra::Mobi),
        #[cfg(feature = "video-tags")]
        Box::new(mp4mkv::VideoTags),
    ]
}

#[cfg(feature = "dicom")]
fn rd_u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
#[cfg(any(feature = "audio-tags", feature = "dicom", feature = "video-tags"))]
fn rd_u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
#[cfg(any(feature = "audio-tags", feature = "video-tags"))]
fn rd_u32be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Whole-file EXIF listing: every IFD (primary, thumbnail, Exif, GPS,
/// Interop) walked tag by tag. `exif::ExifReader` is this crate's own
/// (see `exif/`), container-aware for JPEG, WebP, PNG and TIFF alike.
///
/// The `photos` module reads the EXIF block of a PSD, a JPEG 2000 or a
/// JPEG XL, and renders it the same way.
#[cfg(any(
    feature = "exif",
    feature = "tiff",
    feature = "psd",
    feature = "jpeg2000",
    feature = "jpegxl"
))]
pub(crate) fn fmt_exif(r: &exif::ExifReader) -> String {
    let mut out = String::new();
    let ifds: [(&str, &[exif::IfdEntry]); 5] = [
        ("ifd0", &r.ifd0),
        ("ifd1", &r.ifd1),
        ("exif", &r.exif_ifd),
        ("gps", &r.gps_ifd),
        ("interop", &r.interop_ifd),
    ];
    for (name, entries) in ifds {
        for e in entries {
            // `tag_name` returns a `&'static str` for the well-known tags;
            // the `format!` fallback only fires for the long tail of
            // vendor-specific tags that aren't in the table. The
            // value formatter is `Display` already, so route everything
            // through `writeln!` to keep the loop alloc-free.
            if let Some(tag) = exif::tag_name(e.tag) {
                let _ = writeln!(out, "{name} {tag}: {}", r.entry_value(e));
            } else {
                let _ = writeln!(out, "{name} 0x{:04x}: {}", e.tag, r.entry_value(e));
            }
        }
    }
    out
}

/// A tag's own string, cut at its NUL and trimmed of the padding
/// around it.
///
/// The padding is not part of the name a user types: a camera writes
/// `NIKON CORPORATION` padded with spaces and NULs, and a fact
/// carrying the padding would not compare equal to the camera the
/// user is asking about.
///
/// An empty tag is not a value at all. A fact carrying one would
/// match a predicate that asks for nothing, and the answer to
/// "does this picture name its camera?" would be yes for every
/// picture.
#[cfg(any(feature = "exif", feature = "tiff"))]
fn tag_text(value: Option<String>) -> Option<String> {
    let value = value?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// The EXIF metadata of a parsed picture, as the facts a filter asks
/// about.
///
/// The names are the ones this adapter owns, namespaced `exif.` so
/// that no other adapter's `camera` or `gps` can answer for a
/// picture: `exif.make`, `exif.model`, `exif.camera`, `exif.gps` and
/// `exif.datetime`.
///
/// **The values are the file's.** A make is the string the file
/// holds — `NIKON CORPORATION`, not `Nikon` — because a predicate
/// compares what the file says, and a rewritten make is a make the
/// file does not have.
///
/// **The camera fact is the two tags together**, make and model joined
/// by a space, and either one alone when the file carries only that
/// one. It is reported when the file names a camera at all.
///
/// **The GPS fact is reported only when the file has coordinates.** A
/// picture with a GPS directory but no readable latitude and
/// longitude has no place and no coordinates, and a fact that said
/// it did would turn `exif:gps` — which asks whether the picture *has*
/// a GPS fact — into a lie.
///
/// **The date is the capture date**: `DateTimeOriginal` (0x9003) when
/// the file has it, and the file's own `DateTime` (0x0132) when it
/// does not. Both are dates the file holds; neither is invented.
#[cfg(any(feature = "exif", feature = "tiff"))]
fn exif_facts(r: &exif::ExifReader) -> Vec<Field> {
    let mut facts = Vec::new();

    let make = tag_text(r.make());
    let model = tag_text(r.model());
    if let Some(value) = &make {
        facts.push(Field::new("exif.make", value));
    }
    if let Some(value) = &model {
        facts.push(Field::new("exif.model", value));
    }
    let camera = match (&make, &model) {
        (Some(make), Some(model)) => Some(format!("{make} {model}")),
        (Some(make), None) => Some(make.clone()),
        (None, Some(model)) => Some(model.clone()),
        (None, None) => None,
    };
    if let Some(value) = &camera {
        facts.push(Field::new("exif.camera", value));
    }
    if let Some((lat, lon)) = r.get_gps() {
        // The file's coordinates, in decimal degrees — the reader's
        // own conversion of the DMS triple, signed for south and
        // west.
        facts.push(Field::new("exif.gps", &format!("{lat:.6}, {lon:.6}")));
    }
    if let Some(value) = tag_text(r.datetime_original()).or_else(|| tag_text(r.datetime())) {
        facts.push(Field::new("exif.datetime", &value));
    }
    facts
}

/// EXIF metadata, by this crate's own in-house reader (`exif/`).
#[cfg(feature = "exif")]
pub struct ExifJpeg;
#[cfg(feature = "exif")]
impl Adapter for ExifJpeg {
    fn name(&self) -> &'static str {
        "exif"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["jpg", "jpeg", "webp", "png"]
    }
    /// The picture's EXIF metadata as facts: `exif.make`,
    /// `exif.model`, `exif.camera`, `exif.gps` and `exif.datetime`.
    ///
    /// A picture with no EXIF payload reports no facts. The question
    /// is asked of a file this adapter could not read, and the honest
    /// answer to a question about an unreadable file is that there is
    /// nothing to say.
    fn facts(&self, data: &[u8], _path: &str) -> Vec<Field> {
        match exif::ExifReader::parse_container(data) {
            Ok(r) => exif_facts(&r),
            Err(_) => Vec::new(),
        }
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // The in-house reader unwraps the container itself (JPEG marker
        // walk, WebP RIFF chunk, PNG eXIf chunk). HEIC/HEIF/AVIF are not
        // claimed until the ISO-BMFF `Exif` item parser lands — there the
        // payload is an item, not a top-level chunk.
        let r = exif::ExifReader::parse_container(data)
            .map_err(rgx_core::Error::msg)
            .decline_context("no EXIF payload")?;
        let text = fmt_exif(&r);
        if text.trim().is_empty() {
            decline!("EXIF container present but no fields");
        }
        Ok(Outcome::Text(text.into_bytes()))
    }
}

/// TIFF/GeoTIFF: the in-house reader parses a bare TIFF directly.
///
/// **Declines a multi-page TIFF on purpose.** `parse_tiff` reads the first
/// IFD only, so answering a two-page scan with page 1's EXIF and calling it
/// the file is a silent truncation — the page the reader wanted is not in
/// the output and nothing says so. `rgx-adapters-inspect` is registered
/// after this crate and its `Tiff` walks the whole IFD chain, so bailing
/// here hands the multipage case to the adapter that can answer it. The
/// single-page path keeps this one, whose EXIF set is the richer output.
#[cfg(feature = "tiff")]
pub struct Tiff;
#[cfg(feature = "tiff")]
impl Adapter for Tiff {
    fn name(&self) -> &'static str {
        "tiff"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["tif", "tiff"]
    }
    /// The picture's EXIF metadata as facts: `exif.make`,
    /// `exif.model`, `exif.camera`, `exif.gps` and `exif.datetime`.
    ///
    /// A multi-page TIFF reports no facts, the same way it declines
    /// to extract: this adapter reads the first IFD only, and the
    /// camera of the first page presented as the camera of the file
    /// is a truncation that nothing in the answer would show.
    fn facts(&self, data: &[u8], _path: &str) -> Vec<Field> {
        let mut r = exif::ExifReader::new(data);
        if r.parse_tiff().is_err() {
            return Vec::new();
        }
        if tiff_ifd_count(data) > 1 {
            return Vec::new();
        }
        exif_facts(&r)
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let mut r = exif::ExifReader::new(data);
        r.parse_tiff()
            .map_err(rgx_core::Error::msg)
            .decline_context("not a TIFF IFD structure")?;
        if tiff_ifd_count(data) > 1 {
            bail!("multipage TIFF: first IFD only, deferring to the chain-walking reader");
        }
        let text = fmt_exif(&r);
        if text.trim().is_empty() {
            bail!("TIFF contains no readable tags");
        }
        Ok(Outcome::Text(text.into_bytes()))
    }
}

/// How many IFDs the chain starting at the header's first-IFD offset holds.
///
/// Counts links, never parses a directory: the question is only "is there
/// more than one page", so the cost of a malformed entry is nil. Classic
/// TIFF offsets the first IFD with a `u32` at 4; BigTIFF uses a `u64` at 8.
/// Both byte orders exist, so the header magic — not the host — picks the
/// reader, exactly as the rest of this crate does.
#[cfg(feature = "tiff")]
fn tiff_ifd_count(data: &[u8]) -> usize {
    let (big, le) = match data.get(0..4) {
        Some(b"II\x2a\x00") => (false, true),
        Some(b"MM\x00\x2a") => (false, false),
        Some(b"II\x2b\x00") => (true, true),
        Some(b"MM\x00\x2b") => (true, false),
        _ => return 1,
    };
    let rd = |b: &[u8]| -> u64 {
        let mut v = 0u64;
        for i in 0..b.len() {
            // Accumulated left-to-right, so a little-endian file has to be
            // fed its bytes back to front or every value comes out reversed.
            v = (v << 8) | u64::from(if le { b[b.len() - 1 - i] } else { b[i] });
        }
        v
    };
    let mut at = if big {
        match data.get(8..16) {
            Some(b) => rd(b) as usize,
            None => return 1,
        }
    } else {
        match data.get(4..8) {
            Some(b) => rd(b) as usize,
            None => return 1,
        }
    };
    // Bounded: a cycle in the chain must not spin here, and a file with more
    // pages than this is already far past anything a report would print.
    // The link sits past the entry *count* AND past every entry, and its own
    // width differs from the count's in a classic TIFF (2 vs 4).
    let (count_w, entry_w, link_w) = if big {
        (8usize, 20usize, 8usize)
    } else {
        (2, 12, 4)
    };
    let mut n = 1usize;
    while n < 1024 {
        let Some(raw) = data.get(at..at + count_w).map(rd) else {
            return n;
        };
        let link_at = at + count_w + (raw as usize).saturating_mul(entry_w);
        let Some(next) = data.get(link_at..link_at + link_w).map(rd) else {
            return n;
        };
        let next = next as usize;
        if next == 0 || next == at {
            return n;
        }
        at = next;
        n += 1;
    }
    n
}

/// Audio tags, hand-rolled: ID3v1 (MP3), RIFF INFO (WAV), Vorbis comment
/// (FLAC), Vorbis/Ogg/Opus. No external crates — a few dozen bytes each.
#[cfg(feature = "audio-tags")]
pub struct AudioTags;
#[cfg(feature = "audio-tags")]
impl Adapter for AudioTags {
    fn name(&self) -> &'static str {
        "audiotags"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["mp3", "wav", "flac", "ogg", "oga", "opus"]
    }
    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome> {
        let ext = rgx_core::extension_of(path);
        let text = match &*ext {
            "mp3" => {
                let v2 = id3v2(data);
                if v2.trim().is_empty() {
                    id3v1(data)
                } else {
                    v2
                }
            }
            "wav" => riff_info(data),
            "flac" => flac_vorbis(data),
            "ogg" | "oga" | "opus" => ogg_comment(data),
            _ => decline!("no lightweight tag parser for .{ext}"),
        };
        if text.trim().is_empty() {
            decline!("no tags found");
        }
        Ok(Outcome::Text(text.into_bytes()))
    }
}

#[cfg(any(feature = "audio-tags", feature = "fits", feature = "video-tags"))]
fn trim_cstr(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    s.trim_matches(char::from(0)).trim().to_string()
}

/// ID3v1: last 128 bytes, "TAG" + title/artist/album/year/comment 30/30/30/4/30.
#[cfg(feature = "audio-tags")]
fn id3v1(data: &[u8]) -> String {
    if data.len() < 128 {
        return String::new();
    }
    let tag = &data[data.len() - 128..];
    if &tag[0..3] != b"TAG" {
        return String::new();
    }
    let f = |o: usize, n: usize| trim_cstr(&tag[o..o + n]);
    let mut out = String::new();
    let _ = writeln!(out, "title: {}", f(3, 30));
    let _ = writeln!(out, "artist: {}", f(33, 30));
    let _ = writeln!(out, "album: {}", f(63, 30));
    let _ = writeln!(out, "year: {}", f(93, 4));
    let _ = writeln!(out, "comment: {}", f(97, 30));
    if tag[125] == 0 && tag[126] != 0 {
        let _ = writeln!(out, "track: {}", tag[126]);
    }
    out
}

/// ID3v2 (2.3/2.4): header "ID3" + 3 bytes + syncsafe size, then 10-byte
/// frames (id, syncsafe size, flags). Text frames carry a 1-byte encoding
/// prefix. We map the common T* frames to friendly names.
#[cfg(feature = "audio-tags")]
fn id3v2(data: &[u8]) -> String {
    if data.len() < 10 || &data[0..3] != b"ID3" {
        return String::new();
    }
    let major = data[3];
    if !(2..=4).contains(&major) {
        return String::new();
    }
    // tag size: 4 syncsafe bytes (7 bits each)
    let size = ((data[6] & 0x7f) as usize) << 21
        | ((data[7] & 0x7f) as usize) << 14
        | ((data[8] & 0x7f) as usize) << 7
        | (data[9] & 0x7f) as usize;
    let end = (10 + size).min(data.len());
    let mut out = String::new();
    let mut p = 10usize;
    while p + 10 <= end {
        let id = &data[p..p + 4];
        if id.iter().all(|&b| b == 0) {
            break;
        }
        let fsize = if major == 4 {
            ((data[p + 4] & 0x7f) as usize) << 21
                | ((data[p + 5] & 0x7f) as usize) << 14
                | ((data[p + 6] & 0x7f) as usize) << 7
                | (data[p + 7] & 0x7f) as usize
        } else {
            rd_u32be_sz(data, p + 4)
        };
        if fsize == 0 || p + 10 + fsize > end {
            break;
        }
        let payload = &data[p + 10..p + 10 + fsize];
        let name = match id {
            b"TIT2" => Some("title"),
            b"TPE1" => Some("artist"),
            b"TALB" => Some("album"),
            b"TYER" | b"TDRC" => Some("year"),
            b"TRCK" => Some("track"),
            b"TCOM" => Some("composer"),
            b"TCON" => Some("genre"),
            b"TXXX" => Some("comment"),
            _ => None,
        };
        if let Some(name) = name {
            let text = decode_id3_text(payload);
            let text = if id == b"TXXX" {
                // "description\0text" — keep both halves
                text.replace('\u{0}', ": ")
            } else {
                text
            };
            if !text.trim().is_empty() {
                let _ = writeln!(out, "{name}: {}", text.trim());
            }
        }
        p += 10 + fsize;
    }
    out
}

#[cfg(feature = "audio-tags")]
fn rd_u32be_sz(b: &[u8], o: usize) -> usize {
    rd_u32be(b, o) as usize
}

/// Decode an ID3 text frame payload: 1 encoding byte + text.
#[cfg(feature = "audio-tags")]
fn decode_id3_text(payload: &[u8]) -> String {
    if payload.is_empty() {
        return String::new();
    }
    let body = &payload[1..];
    match payload[0] {
        0 => body
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect::<String>(),
        3 => String::from_utf8_lossy(body)
            .trim_matches(char::from(0))
            .to_string(),
        // UTF-16 variants: decode the even-length prefix lossily
        1 | 2 => {
            let mut s = String::new();
            for ch in body.as_chunks::<2>().0.iter().take(512) {
                let cp = if payload[0] == 1 {
                    u16::from_le_bytes([ch[0], ch[1]])
                } else {
                    u16::from_be_bytes([ch[0], ch[1]])
                };
                if cp == 0 {
                    break;
                }
                if let Some(c) = char::from_u32(cp as u32) {
                    s.push(c);
                }
            }
            s
        }
        _ => String::from_utf8_lossy(body)
            .trim_matches(char::from(0))
            .to_string(),
    }
}

/// RIFF INFO list: "LIST" chunk with INFO type, subchunks INAM/IART/IPRD...
#[cfg(feature = "audio-tags")]
fn riff_info(data: &[u8]) -> String {
    if data.len() < 12 || &data[0..4] != b"RIFF" || &data[8..12] != b"WAVE" {
        return String::new();
    }
    let mut out = String::new();
    let mut p = 12usize;
    while p + 8 <= data.len() {
        let id = &data[p..p + 4];
        let size = rd_u32le(data, p + 4) as usize;
        if id == b"LIST" && p + 8 + size <= data.len() && &data[p + 8..p + 12] == b"INFO" {
            let mut q = p + 12;
            let end = p + 8 + size;
            while q + 8 <= end {
                let key = String::from_utf8_lossy(&data[q..q + 4]).into_owned();
                let sz = rd_u32le(data, q + 4) as usize;
                if q + 8 + sz > end {
                    break;
                }
                let val = trim_cstr(&data[q + 8..q + 8 + sz]);
                if !val.is_empty() {
                    let _ = writeln!(out, "{key}: {val}");
                }
                q += 8 + sz + (sz & 1);
            }
        }
        p += 8 + size + (size & 1);
    }
    out
}

/// FLAC metadata blocks: block type 4 = Vorbis comment (vendor + key=value).
#[cfg(feature = "audio-tags")]
fn flac_vorbis(data: &[u8]) -> String {
    if data.len() < 42 || &data[0..4] != b"fLaC" {
        return String::new();
    }
    let mut p = 4usize;
    while p + 4 <= data.len() {
        let last = data[p] & 0x80 != 0;
        let btype = data[p] & 0x7f;
        let len =
            ((data[p + 1] as usize) << 16) | ((data[p + 2] as usize) << 8) | data[p + 3] as usize;
        p += 4;
        if btype == 4 && p + len <= data.len() {
            return vorbis_comment(&data[p..p + len]);
        }
        p += len;
        if last {
            break;
        }
    }
    String::new()
}

/// Vorbis comment block: a vendor string, then a list of `key=value`
/// entries. The same block in every container that carries one.
#[cfg(any(feature = "audio-tags", feature = "video-tags"))]
fn vorbis_comment(b: &[u8]) -> String {
    if b.len() < 8 {
        return String::new();
    }
    let vlen = rd_u32le(b, 0) as usize;
    if 4 + vlen + 4 > b.len() {
        return String::new();
    }
    let vendor = trim_cstr(&b[4..4 + vlen]);
    let n = rd_u32le(b, 4 + vlen) as usize;
    let mut out = format!("vendor: {vendor}\n");
    let mut p = 8 + vlen;
    for _ in 0..n.min(100_000) {
        if p + 4 > b.len() {
            break;
        }
        let l = rd_u32le(b, p) as usize;
        p += 4;
        if p + l > b.len() {
            break;
        }
        let kv = String::from_utf8_lossy(&b[p..p + l]);
        if let Some((k, v)) = kv.split_once('=') {
            let _ = writeln!(out, "{k}: {v}");
        }
        p += l;
    }
    out
}

/// Ogg: find the comment header packet and parse it.
///
/// The comment block is the same in every Ogg codec -- the vendor string
/// and the `key=value` list the Vorbis comment defines -- but the packet
/// that introduces it is not. Each codec names its own headers: Vorbis
/// opens with `\x01vorbis` and comments in `\x03vorbis`, Opus opens with
/// `OpusHead` and comments in `OpusTags`, Theora opens with `\x80theora`
/// and comments in `\x81theora`.
///
/// A reader that looked for the Vorbis marker alone read the comment of a
/// Vorbis stream and nothing else. An Opus file has no `\x03vorbis`
/// anywhere in it, so the reader came back empty, the adapter declined,
/// and the file fell through to the raw search -- where the NUL in the
/// Ogg page header cut the search before the comment. The file was in
/// the corpus and the answer was not: the tags were in the file, and
/// nothing in the file said so.
#[cfg(any(feature = "audio-tags", feature = "video-tags"))]
pub(crate) fn ogg_comment(data: &[u8]) -> String {
    if data.len() < 64 || &data[0..4] != b"OggS" {
        return String::new();
    }
    // The comment header is in the first pages of the stream; the window
    // is the one the Vorbis-only reader used.
    let window = &data[..data.len().min(1 << 16)];
    // The earliest marker wins. The comment packet follows its own
    // identification header, and a file may carry more than one codec --
    // an Ogg Theora video with a Vorbis soundtrack has both -- in which
    // case the first comment is the one the file leads with.
    let mut found: Option<(usize, usize)> = None; // (position, marker length)
    for marker in [&b"\x03vorbis"[..], &b"OpusTags"[..], &b"\x81theora"[..]] {
        if let Some(pos) = rgx_core::memchr::memmem::find(window, marker) {
            if found.is_none_or(|(p, _)| pos < p) {
                found = Some((pos, marker.len()));
            }
        }
    }
    let Some((pos, len)) = found else {
        return String::new();
    };
    vorbis_comment(&window[pos + len..])
}

/// FITS astronomy images: 80-byte keyword cards until END, `KEY = value`.
#[cfg(feature = "fits")]
pub struct Fits;
#[cfg(feature = "fits")]
impl Adapter for Fits {
    fn name(&self) -> &'static str {
        "fits"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["fits", "fit", "fts"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // FITS keyword = 8 chars, uppercase / digits / space / '-' / '_'
        if data.len() < 80
            || !data[..8].iter().all(|&b| {
                b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b' ' | b'-' | b'_')
            })
        {
            decline!("not a FITS file (bad keyword card)");
        }
        let mut out = String::new();
        let mut p = 0usize;
        while p + 80 <= data.len() && out.len() < 1 << 20 {
            let card = &data[p..p + 80];
            p += 80;
            let key = trim_cstr(&card[0..8]);
            if key == "END" {
                break;
            }
            if card.len() >= 10 && card[8] == b'=' {
                let value = String::from_utf8_lossy(&card[10..])
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_matches('\'')
                    .to_string();
                let _ = writeln!(out, "{key}: {value}");
            } else if !key.is_empty() {
                out.push_str(&key);
                out.push('\n');
            }
        }
        if out.trim().is_empty() {
            decline!("FITS header has no keywords");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// DICOM (medical imaging): 128-byte preamble + "DICM", then data elements.
/// Stops before pixel data (7FE0,0010); strings and numeric VRs only.
#[cfg(feature = "dicom")]
pub struct Dicom;
#[cfg(feature = "dicom")]
impl Adapter for Dicom {
    fn name(&self) -> &'static str {
        "dicom"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["dcm", "dicom", "ima"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 132 || &data[128..132] != b"DICM" {
            decline!("not a DICOM file (missing DICM preamble)");
        }
        // long VRs carry 32-bit lengths (OB, OD, OF, OL, OW, SQ, UC, UR, UT, UN)
        const LONG_VR: &[&[u8; 2]] = &[
            b"OB", b"OD", b"OF", b"OL", b"OW", b"SQ", b"UC", b"UR", b"UT", b"UN",
        ];
        let mut out = String::new();
        let mut p = 132usize;
        while p + 8 <= data.len() && out.len() < 1 << 20 {
            let group = rd_u16le(data, p);
            let element = rd_u16le(data, p + 2);
            if group == 0x7fe0 && element == 0x0010 {
                break;
            } // pixel data
            if group == 0xfffe {
                // item delimiter / sequence item: skip length
                let len = rd_u32le(data, p + 4) as usize;
                p += 8;
                if len == 0xFFFF_FFFF {
                    break;
                }
                p += len;
                continue;
            }
            let vr = [data[p + 4], data[p + 5]];
            if vr[0] == 0 || !vr[0].is_ascii_alphabetic() {
                break; // implicit VR or garbage — stop cleanly
            }
            let (vlen, header_len) = if LONG_VR.contains(&&vr) {
                // A long VR's length is the four bytes after the short
                // header, so the element needs twelve of them: the loop's
                // own eight-byte guarantee does not cover the read.
                if p + 12 > data.len() {
                    break;
                }
                (rd_u32le(data, p + 8) as usize, 12usize)
            } else {
                (rd_u16le(data, p + 6) as usize, 8usize)
            };
            if vlen == 0xFFFF_FFFF {
                break;
            } // undefined length
            let voff = p + header_len;
            let Some(end) = voff.checked_add(vlen) else {
                break;
            };
            if end > data.len() {
                break;
            }
            let tag = format!("({:04X},{:04X})", group, element);
            let value = match &vr {
                b"PN" | b"LO" | b"SH" | b"ST" | b"LT" | b"UT" | b"DA" | b"TM" | b"UI" | b"CS"
                | b"AS" | b"AE" | b"DS" | b"IS" | b"DT" => {
                    let s = String::from_utf8_lossy(&data[voff..end]);
                    Some(s.trim_matches(char::from(0)).trim().to_string())
                }
                b"US" if vlen == 2 => Some(rd_u16le(data, voff).to_string()),
                b"UL" if vlen == 4 => Some(rd_u32le(data, voff).to_string()),
                _ => None,
            };
            if let Some(v) = value {
                if !v.is_empty() {
                    let vr_s = String::from_utf8_lossy(&vr);
                    let _ = writeln!(out, "{tag} {vr_s}: {v}");
                }
            }
            p = end;
        }
        if out.trim().is_empty() {
            decline!("no DICOM elements decoded");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(all(
    test,
    any(
        feature = "exif",
        feature = "tiff",
        feature = "audio-tags",
        feature = "video-tags",
        feature = "fits",
        feature = "dicom"
    )
))]
mod tests {
    use super::*;

    /// A little-endian TIFF/EXIF payload with the given ASCII IFD0
    /// tags.
    ///
    /// A string longer than four bytes is stored out of line, the way
    /// a real file stores it, so the reader's offset handling is
    /// exercised rather than bypassed.
    #[cfg(feature = "exif")]
    fn tiff_with_ascii(tags: &[(u16, &str)]) -> Vec<u8> {
        let mut tiff = Vec::new();
        tiff.extend_from_slice(b"II");
        tiff.extend_from_slice(&42u16.to_le_bytes());
        tiff.extend_from_slice(&8u32.to_le_bytes()); // IFD0 at 8
        tiff.extend_from_slice(&(tags.len() as u16).to_le_bytes());
        // The data area follows the directory: the count, the entries
        // and the next-IFD offset.
        let data_at = (8 + 2 + 12 * tags.len() + 4) as u32;
        let mut at = data_at;
        let mut values: Vec<Vec<u8>> = Vec::new();
        for (tag, text) in tags {
            let bytes = text.as_bytes();
            let count = bytes.len() as u32 + 1; // with its NUL
            tiff.extend_from_slice(&tag.to_le_bytes());
            tiff.extend_from_slice(&2u16.to_le_bytes()); // ASCII
            tiff.extend_from_slice(&count.to_le_bytes());
            if count <= 4 {
                let mut slot = [0u8; 4];
                slot[..bytes.len()].copy_from_slice(bytes);
                tiff.extend_from_slice(&slot);
            } else {
                tiff.extend_from_slice(&at.to_le_bytes());
                let mut value = bytes.to_vec();
                value.push(0);
                at += value.len() as u32;
                values.push(value);
            }
        }
        tiff.extend_from_slice(&0u32.to_le_bytes()); // no next IFD
        assert_eq!(
            tiff.len() as u32,
            data_at,
            "the data area starts right past the directory"
        );
        for value in values {
            tiff.extend_from_slice(&value);
        }
        tiff
    }

    /// A JPEG whose APP1 segment carries the given TIFF/EXIF payload.
    #[cfg(feature = "exif")]
    fn jpeg_with_exif(tiff: &[u8]) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend_from_slice(b"Exif\0\0");
        segment.extend_from_slice(tiff);
        let mut jpeg = Vec::new();
        jpeg.extend_from_slice(&[0xFF, 0xD8]); // SOI
        jpeg.extend_from_slice(&[0xFF, 0xE1]); // APP1
        jpeg.extend_from_slice(&((segment.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(&segment);
        jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI
        jpeg
    }

    /// The value of a fact, when it was reported.
    #[cfg(any(feature = "exif", feature = "tiff"))]
    fn fact_value<'a>(facts: &'a [Field], name: &str) -> Option<&'a str> {
        facts
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.value.as_str())
    }

    /// The camera of a picture is the make and the model the file
    /// holds, and each of them on its own.
    #[test]
    #[cfg(feature = "exif")]
    fn exif_facts_carry_the_make_and_the_model() {
        let jpeg = jpeg_with_exif(&tiff_with_ascii(&[
            (0x010F, "NIKON CORPORATION"),
            (0x0110, "NIKON D850"),
        ]));
        let facts = ExifJpeg.facts(&jpeg, "photo.jpg");
        assert_eq!(fact_value(&facts, "exif.make"), Some("NIKON CORPORATION"));
        assert_eq!(fact_value(&facts, "exif.model"), Some("NIKON D850"));
        assert_eq!(
            fact_value(&facts, "exif.camera"),
            Some("NIKON CORPORATION NIKON D850")
        );
    }

    /// A picture with no coordinates reports no `exif.gps` fact. The
    /// fact's presence is the answer to `exif:gps`, so reporting one
    /// for a picture without GPS would make the predicate a lie.
    #[test]
    #[cfg(feature = "exif")]
    fn exif_facts_omit_gps_when_the_file_has_no_coordinates() {
        let jpeg = jpeg_with_exif(&tiff_with_ascii(&[(0x010F, "KADANE")]));
        let facts = ExifJpeg.facts(&jpeg, "photo.jpg");
        assert_eq!(fact_value(&facts, "exif.make"), Some("KADANE"));
        assert_eq!(fact_value(&facts, "exif.gps"), None);
    }

    /// A picture that really carries coordinates reports them, in
    /// decimal degrees, together with the camera that took it and the
    /// date it was taken.
    #[test]
    #[cfg(feature = "exif")]
    fn exif_facts_report_the_coordinates_a_file_holds() {
        let jpeg = include_bytes!("../testdata/exif_sample.jpg");
        let facts = ExifJpeg.facts(jpeg, "photo.jpg");
        assert_eq!(fact_value(&facts, "exif.make"), Some("KADANE"));
        assert_eq!(fact_value(&facts, "exif.model"), Some("RGX-CAM"));
        assert_eq!(fact_value(&facts, "exif.camera"), Some("KADANE RGX-CAM"));
        let gps = fact_value(&facts, "exif.gps").expect("the sample has GPS");
        assert!(gps.starts_with("48.858"), "{gps}");
        assert!(gps.contains("2.292"), "{gps}");
        assert_eq!(
            fact_value(&facts, "exif.datetime"),
            Some("2026:09:28 12:00:00")
        );
    }

    /// The TIFF adapter reports the same facts from a bare TIFF.
    #[test]
    #[cfg(feature = "tiff")]
    fn tiff_facts_carry_the_camera_and_the_coordinates() {
        let tiff = include_bytes!("../testdata/exif_sample.tiff");
        let facts = Tiff.facts(tiff, "scan.tif");
        assert_eq!(fact_value(&facts, "exif.make"), Some("KADANE"));
        assert_eq!(fact_value(&facts, "exif.model"), Some("RGX-CAM"));
        assert_eq!(fact_value(&facts, "exif.camera"), Some("KADANE RGX-CAM"));
        assert!(
            fact_value(&facts, "exif.gps").is_some(),
            "the sample carries coordinates"
        );
    }

    /// A file with no EXIF at all reports no facts, and reports none
    /// rather than failing: the question is asked of a file this
    /// adapter could not read.
    #[test]
    #[cfg(all(feature = "exif", feature = "tiff"))]
    fn exif_facts_are_empty_for_a_file_without_exif() {
        assert!(ExifJpeg
            .facts(&[0xFF, 0xD8, 0xFF, 0xD9], "photo.jpg")
            .is_empty());
        assert!(Tiff.facts(b"II*\x00", "scan.tif").is_empty());
        assert!(ExifJpeg.facts(&[], "photo.jpg").is_empty());
    }

    #[test]
    #[cfg(feature = "audio-tags")]
    fn id3v1_basic() {
        let mut mp3 = vec![0xff; 500];
        let mut tag = vec![0u8; 128];
        tag[0..3].copy_from_slice(b"TAG");
        tag[3..9].copy_from_slice(b"Song\0\0");
        tag[33..39].copy_from_slice(b"Band\0\0");
        mp3.extend_from_slice(&tag);
        let t = id3v1(&mp3);
        assert!(t.contains("title: Song"), "{t}");
        assert!(t.contains("artist: Band"), "{t}");
    }

    /// A minimal Ogg stream carrying one codec's comment header and a
    /// comment block: the page header, the marker, then the vendor
    /// string and the `key=value` list the Vorbis comment defines.
    #[cfg(any(feature = "audio-tags", feature = "video-tags"))]
    fn ogg_with(marker: &[u8], comments: &[(&str, &str)]) -> Vec<u8> {
        let mut d = vec![0u8; 64];
        d[0..4].copy_from_slice(b"OggS");
        d.extend_from_slice(marker);
        d.extend_from_slice(&3u32.to_le_bytes()); // vendor length
        d.extend_from_slice(b"rgx");
        d.extend_from_slice(&(comments.len() as u32).to_le_bytes());
        for (k, v) in comments {
            let kv = format!("{k}={v}");
            d.extend_from_slice(&(kv.len() as u32).to_le_bytes());
            d.extend_from_slice(kv.as_bytes());
        }
        d
    }

    /// The comment block is the same in every Ogg codec, but the packet
    /// that introduces it is not: Vorbis comments in `\x03vorbis`, Opus in
    /// `OpusTags`, Theora in `\x81theora`. A reader that knew only the
    /// Vorbis marker read a Vorbis stream and nothing else -- and an Opus
    /// file has no `\x03vorbis` in it at all, so the adapter declined, the
    /// file fell to the raw search, and the NUL in the Ogg page header
    /// cut the search before the comment. The tags were in the file and
    /// the answer was not.
    #[test]
    #[cfg(any(feature = "audio-tags", feature = "video-tags"))]
    fn the_ogg_comment_is_read_whatever_the_codec_is() {
        for marker in [&b"\x03vorbis"[..], &b"OpusTags"[..], &b"\x81theora"[..]] {
            let d = ogg_with(marker, &[("TITLE", "Zircaloy Clip")]);
            let text = ogg_comment(&d);
            assert!(text.contains("TITLE: Zircaloy Clip"), "{text}");
        }
    }

    /// The Opus file the corpus holds: an Ogg Opus stream whose comment
    /// header is `OpusTags`. The adapter claims `.opus`, so this is the
    /// path that has to answer.
    #[test]
    #[cfg(feature = "audio-tags")]
    fn an_opus_file_is_read_through_its_own_comment_header() {
        let d = ogg_with(b"OpusTags", &[("TITLE", "Zircaloy Clip")]);
        match AudioTags.extract(&d, "a.opus").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("TITLE: Zircaloy Clip"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    #[test]
    #[cfg(feature = "fits")]
    fn fits_cards() {
        let card = |k: &str, v: &str| {
            let mut c = format!("{k:<8}= {v}");
            c.truncate(80);
            format!("{c:<80}")
        };
        let mut data = String::new();
        data.push_str(&card("SIMPLE", "T / conforms"));
        data.push_str(&card("BITPIX", "8"));
        data.push_str(&card("END", ""));
        let f = Fits;
        match f.extract(data.as_bytes(), "a.fits").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("SIMPLE: T"), "{s}");
                assert!(s.contains("BITPIX: 8"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    #[test]
    #[cfg(feature = "dicom")]
    fn dicom_preamble() {
        let mut data = vec![0u8; 128];
        data.extend_from_slice(b"DICM");
        // (0008,0060) Modality CS len 2 "MR"
        data.extend_from_slice(&[0x08, 0x00, 0x60, 0x00]);
        data.extend_from_slice(b"CS");
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(b"MR");
        let d = Dicom;
        match d.extract(&data, "x.dcm").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("(0008,0060) CS: MR"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    /// A long VR's 32-bit length sits in the four bytes after the short
    /// header, so an element whose eight-byte header ends at the end of
    /// the file has not declared its length at all: the walk used to read
    /// those four bytes anyway, past the end of the file.
    #[test]
    #[cfg(feature = "dicom")]
    fn a_dicom_element_whose_long_vr_header_ends_the_file_stops_there() {
        let mut data = vec![0u8; 128];
        data.extend_from_slice(b"DICM");
        data.extend_from_slice(&[0x08, 0x00, 0x60, 0x00]);
        data.extend_from_slice(b"CS");
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(b"MR");
        // (0008,1150) with VR OB — a long VR — and no length bytes.
        data.extend_from_slice(&[0x08, 0x00, 0x50, 0x11]);
        data.extend_from_slice(b"OB\x00\x00");
        match Dicom.extract(&data, "x.dcm").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8_lossy(&t);
                assert!(s.contains("(0008,0060) CS: MR"), "{s}");
                assert!(
                    !s.contains("(0008,1150)"),
                    "the element was never read: {s}"
                );
            }
            _ => panic!("expected text"),
        }
    }

    mod fuzz {
        use super::*;

        #[cfg(feature = "fits")]
        fn fits_cards() -> Vec<u8> {
            let card = |k: &str, v: &str| {
                let mut c = format!("{k:<8}= {v}");
                c.truncate(80);
                format!("{c:<80}")
            };
            let mut data = String::new();
            data.push_str(&card("SIMPLE", "T / conforms"));
            data.push_str(&card("BITPIX", "8"));
            data.push_str(&card("END", ""));
            data.into_bytes()
        }

        #[cfg(feature = "dicom")]
        fn dicom_mr() -> Vec<u8> {
            let mut data = vec![0u8; 128];
            data.extend_from_slice(b"DICM");
            data.extend_from_slice(&[0x08, 0x00, 0x60, 0x00]);
            data.extend_from_slice(b"CS");
            data.extend_from_slice(&2u16.to_le_bytes());
            data.extend_from_slice(b"MR");
            data
        }

        #[cfg(feature = "audio-tags")]
        fn mp3_id3v1() -> Vec<u8> {
            let mut mp3 = vec![0xffu8; 500];
            let mut tag = vec![0u8; 128];
            tag[0..3].copy_from_slice(b"TAG");
            tag[3..9].copy_from_slice(b"Song\0\0");
            mp3.extend_from_slice(&tag);
            mp3
        }

        #[cfg(feature = "exif")]
        fn mini_jpeg() -> Vec<u8> {
            let mut j = Vec::new();
            j.extend_from_slice(&[0xFF, 0xD8]); // SOI
            j.extend_from_slice(&[0xFF, 0xE0]); // APP0
            j.extend_from_slice(&16u16.to_be_bytes());
            j.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
            j.extend_from_slice(&[0xFF, 0xD9]); // EOI
            j
        }

        #[cfg(feature = "tiff")]
        fn mini_tiff() -> Vec<u8> {
            let mut t = Vec::new();
            t.extend_from_slice(b"II*\x00"); // little-endian, magic 42
            t.extend_from_slice(&8u32.to_le_bytes()); // IFD offset
            t.extend_from_slice(&0u16.to_le_bytes()); // 0 entries
            t.extend_from_slice(&0u32.to_le_bytes()); // next IFD
            t
        }

        #[test]
        #[cfg(feature = "tiff")]
        fn a_single_page_tiff_answers_here_and_a_two_page_one_defers() {
            /// `n` classic-TIFF pages, chained.
            fn pages(n: u16) -> Vec<u8> {
                let mut t = Vec::new();
                t.extend_from_slice(b"II*\x00");
                t.extend_from_slice(&8u32.to_le_bytes());
                let mut at = 8u32;
                for i in 0..n {
                    let next = if i + 1 == n { 0 } else { at + 18 };
                    t.extend_from_slice(&1u16.to_le_bytes()); // one entry
                    t.extend_from_slice(&256u16.to_le_bytes()); // ImageWidth
                    t.extend_from_slice(&4u16.to_le_bytes()); // LONG
                    t.extend_from_slice(&1u32.to_le_bytes());
                    t.extend_from_slice(&800u32.to_le_bytes());
                    t.extend_from_slice(&next.to_le_bytes());
                    at += 18;
                }
                t
            }
            assert_eq!(tiff_ifd_count(&pages(1)), 1);
            assert_eq!(tiff_ifd_count(&pages(2)), 2);
            assert_eq!(tiff_ifd_count(&pages(4)), 4);
            // The two-page file must be refused so the chain walker answers; the
            // one-page file must NOT be, because this adapter's EXIF set is
            // the richer output and it is the one that should get it.
            assert!(Tiff.extract(&pages(2), "x.tif").is_err());
            assert!(Tiff.extract(&pages(1), "x.tif").is_ok());
        }

        #[test]
        #[cfg(feature = "fits")]
        fn fits_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![("cards", fits_cards()), ("empty", vec![])],
                1000,
                "fits",
                |data| {
                    let _ = Fits.extract(data, "fuzz.fits");
                },
            );
        }

        #[test]
        #[cfg(feature = "dicom")]
        fn dicom_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("mr", dicom_mr()),
                    ("dicm-only", b"DICM".to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "dicom",
                |data| {
                    let _ = Dicom.extract(data, "fuzz.dcm");
                },
            );
        }

        #[test]
        #[cfg(feature = "audio-tags")]
        fn audio_tags_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![("id3v1", mp3_id3v1()), ("empty", vec![])],
                1000,
                "audio-tags",
                |data| {
                    let _ = AudioTags.extract(data, "fuzz.mp3");
                },
            );
        }

        #[test]
        #[cfg(feature = "exif")]
        fn exif_jpeg_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("jpeg", mini_jpeg()),
                    ("soi-only", vec![0xFF, 0xD8]),
                    ("empty", vec![]),
                ],
                1500,
                "exif-jpeg",
                |data| {
                    let _ = ExifJpeg.extract(data, "fuzz.jpg");
                },
            );
        }

        #[test]
        #[cfg(feature = "tiff")]
        fn tiff_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("tiff", mini_tiff()),
                    ("magic-only", b"II*\x00".to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "tiff",
                |data| {
                    let _ = Tiff.extract(data, "fuzz.tiff");
                },
            );
        }

        /// The facts are asked of whatever the bytes turned out to be,
        /// so they must not panic on a mutated picture either.
        #[test]
        #[cfg(all(feature = "exif", feature = "tiff"))]
        fn exif_facts_never_panics_on_mutation() {
            let jpeg = jpeg_with_exif(&tiff_with_ascii(&[(0x010F, "KADANE")]));
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("jpeg-with-exif", jpeg),
                    (
                        "sample",
                        include_bytes!("../testdata/exif_sample.jpg").to_vec(),
                    ),
                    ("soi-only", vec![0xFF, 0xD8]),
                    ("empty", vec![]),
                ],
                1500,
                "exif-facts",
                |data| {
                    let _ = ExifJpeg.facts(data, "fuzz.jpg");
                    let _ = Tiff.facts(data, "fuzz.tif");
                },
            );
        }
    }
}
