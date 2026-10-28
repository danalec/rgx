// SPDX-License-Identifier: Apache-2.0

//! Four image formats whose metadata is the payload: PSD, JPEG 2000,
//! JPEG XL and OpenEXR.
//!
//! Only the front of the file is read. No pixel is decoded, no tile is
//! unpacked, no wavelet is inverted: what a search wants from a picture
//! is what the picture says about itself -- its dimensions, its colour
//! space, its camera, and the text it carries (XMP, EXIF, IPTC, comments)
//! -- and all of that is in the header.
//!
//! **What each one can answer.**
//!
//! - **PSD** (Photoshop Document): the header, the inventory of the image
//!   resources, and the text of the ones that are text -- XMP, IPTC, and
//!   the EXIF block read through the crate's own EXIF reader.
//! - **JPEG 2000**: the JP2 container (dimensions, colour space,
//!   resolution, XMP) or the bare codestream (the SIZ marker, which
//!   carries the dimensions and the component description).
//! - **JPEG XL**: the container's EXIF and XMP. The dimensions live in
//!   the codestream's size header, which is entropy-coded, and are not
//!   read.
//! - **OpenEXR**: the header's attributes -- the channels, the data and
//!   display windows (so the dimensions), the compression, the comments.

#[cfg(any(
    feature = "psd",
    feature = "jpeg2000",
    feature = "jpegxl",
    feature = "openexr"
))]
use alloc::string::String;
#[cfg(any(feature = "psd", feature = "jpeg2000", feature = "openexr"))]
use alloc::string::ToString;
#[cfg(any(feature = "psd", feature = "jpeg2000", feature = "openexr"))]
use alloc::vec::Vec;
#[cfg(any(
    feature = "psd",
    feature = "jpeg2000",
    feature = "jpegxl",
    feature = "openexr"
))]
use core::fmt::Write as _;
#[cfg(any(feature = "psd", feature = "jpeg2000"))]
use rgx_core::bail;
#[cfg(any(feature = "psd", feature = "openexr"))]
use rgx_core::decline;
#[cfg(any(
    feature = "psd",
    feature = "jpeg2000",
    feature = "jpegxl",
    feature = "openexr"
))]
use rgx_core::Adapter;
#[cfg(any(feature = "psd", feature = "jpeg2000", feature = "openexr"))]
use rgx_core::Field;
#[cfg(any(
    feature = "psd",
    feature = "jpeg2000",
    feature = "jpegxl",
    feature = "openexr"
))]
use rgx_core::Outcome;
#[cfg(any(
    feature = "psd",
    feature = "jpeg2000",
    feature = "jpegxl",
    feature = "openexr"
))]
use rgx_core::Result;

/// Read a big-endian `u16` at `at`.
#[cfg(any(feature = "psd", feature = "jpeg2000"))]
fn be16(data: &[u8], at: usize) -> Result<u16> {
    let b = data
        .get(at..at + 2)
        .ok_or_else(|| rgx_core::anyhow!("truncated at {at}"))?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

/// Read a big-endian `u32` at `at`.
#[cfg(any(feature = "psd", feature = "jpeg2000"))]
fn be32(data: &[u8], at: usize) -> Result<u32> {
    let b = data
        .get(at..at + 4)
        .ok_or_else(|| rgx_core::anyhow!("truncated at {at}"))?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a little-endian `u32` at `at`.
#[cfg(feature = "openexr")]
fn le32(data: &[u8], at: usize) -> Result<u32> {
    let b = data
        .get(at..at + 4)
        .ok_or_else(|| rgx_core::anyhow!("truncated at {at}"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a little-endian `i32` at `at`.
#[cfg(feature = "openexr")]
fn le32i(data: &[u8], at: usize) -> Result<i32> {
    Ok(le32(data, at)? as i32)
}

// ===========================================================================
// PSD
// ===========================================================================

/// A Photoshop Document (`.psd`) or Large Document (`.psb`).
#[cfg(feature = "psd")]
pub struct Psd;
#[cfg(feature = "psd")]
impl Adapter for Psd {
    fn name(&self) -> &'static str {
        "psd"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["psd", "psb"]
    }
    fn magic(&self) -> Option<&'static [u8]> {
        Some(b"8BPS")
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let meta = psd_meta(data)?;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "format: Photoshop {}",
            if meta.version == 2 {
                "Large Document"
            } else {
                "Document"
            }
        );
        let _ = writeln!(out, "version: {}", meta.version);
        let _ = writeln!(out, "channels: {}", meta.channels);
        let _ = writeln!(out, "width: {}", meta.width);
        let _ = writeln!(out, "height: {}", meta.height);
        let _ = writeln!(out, "depth: {}", meta.depth);
        let _ = writeln!(out, "color_mode: {}", psd_color_mode(meta.color_mode));
        for r in &meta.resources {
            let _ = writeln!(
                out,
                "resource {} {}: {} bytes",
                r.id,
                psd_resource_name(r.id),
                r.size
            );
            // The resources that are text are the searchable ones, and
            // they are searched as text: a pattern over a Photoshop file
            // is looking for the title in the XMP or the caption in the
            // IPTC record.
            match r.id {
                1060 => {
                    let _ = writeln!(out, "xmp:");
                    let _ = write!(out, "{}", text_block(data, r.payload.clone()));
                }
                4008 => {
                    let _ = writeln!(out, "iptc:");
                    let _ = write!(out, "{}", text_block(data, r.payload.clone()));
                }
                1057 | 1058 => {
                    let payload = data.get(r.payload.clone()).unwrap_or(&[]);
                    // The EXIF resource is the `Exif\0\0` prefix and a TIFF
                    // block; the crate's reader takes both shapes.
                    let mut reader = crate::exif::ExifReader::new(payload);
                    if reader.parse_jpeg().is_ok() || reader.parse_tiff().is_err() {
                        let _ = writeln!(out, "exif:");
                        let _ = write!(out, "{}", crate::fmt_exif(&reader));
                    }
                }
                1005 => {
                    // ResolutionInfo: hRes (16.16 fixed), hResUnit, vRes,
                    // vResUnit, widthUnit, heightUnit.
                    if let Some(res) = data.get(r.payload.clone()) {
                        if res.len() >= 16 {
                            let hres = be32(res, 0)? as f64 / 65536.0;
                            let hunit = be16(res, 4)?;
                            let vres = be32(res, 6)? as f64 / 65536.0;
                            let vunit = be16(res, 10)?;
                            let _ = writeln!(
                                out,
                                "resolution: {hres} dpi horizontal, {vres} dpi vertical"
                            );
                            let _ = writeln!(
                                out,
                                "resolution_units: {hunit} horizontal, {vunit} vertical"
                            );
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(Outcome::Text(out.into_bytes()))
    }

    fn facts(&self, data: &[u8], _path: &str) -> Vec<Field> {
        let Ok(meta) = psd_meta(data) else {
            return Vec::new();
        };
        vec![
            Field::new("psd.width", &meta.width.to_string()),
            Field::new("psd.height", &meta.height.to_string()),
            Field::new("psd.channels", &meta.channels.to_string()),
            Field::new("psd.color_mode", psd_color_mode(meta.color_mode)),
        ]
    }
}

#[cfg(feature = "psd")]
struct PsdMeta {
    version: u16,
    channels: u16,
    width: u32,
    height: u32,
    depth: u16,
    color_mode: u16,
    resources: Vec<PsdResource>,
}

#[cfg(feature = "psd")]
struct PsdResource {
    id: u16,
    size: u32,
    /// The resource's payload, as a range into the file.
    payload: core::ops::Range<usize>,
}

#[cfg(feature = "psd")]
fn psd_meta(data: &[u8]) -> Result<PsdMeta> {
    if data.len() < 26 {
        decline!("fewer bytes than a PSD header");
    }
    if &data[0..4] != b"8BPS" {
        decline!("not a PSD (bad signature)");
    }
    let version = be16(data, 4)?;
    if version != 1 && version != 2 {
        decline!("not a PSD (unknown version {version})");
    }
    let channels = be16(data, 12)?;
    let height = be32(data, 14)?;
    let width = be32(data, 18)?;
    let depth = be16(data, 22)?;
    let color_mode = be16(data, 24)?;

    let mut pos = 26usize;
    // The colour mode data comes first and its length is a u32.
    let cm_len = be32(data, pos)? as usize;
    pos = pos
        .checked_add(4 + cm_len)
        .ok_or_else(|| rgx_core::anyhow!("PSD colour mode data overflows"))?;
    if pos > data.len() {
        bail!("PSD colour mode data truncated");
    }
    // Then the image resources: a length, then the blocks.
    let res_len = be32(data, pos)? as usize;
    pos += 4;
    let res_end = pos
        .checked_add(res_len)
        .ok_or_else(|| rgx_core::anyhow!("PSD image resources overflow"))?;
    if res_end > data.len() {
        bail!("PSD image resources truncated");
    }
    let mut resources = Vec::new();
    while pos + 12 <= res_end {
        if &data[pos..pos + 4] != b"8BIM" {
            break;
        }
        let id = be16(data, pos + 4)?;
        // The name is a Pascal string padded to an even length, the
        // length byte included.
        let name_len = data[pos + 6] as usize;
        let mut name_field = 1 + name_len;
        if name_field % 2 == 1 {
            name_field += 1;
        }
        let size_at = pos + 6 + name_field;
        let size = be32(data, size_at)? as usize;
        let payload_at = size_at + 4;
        let payload_end = payload_at
            .checked_add(size)
            .ok_or_else(|| rgx_core::anyhow!("PSD resource overflows"))?;
        if payload_end > res_end {
            bail!("PSD image resource truncated");
        }
        resources.push(PsdResource {
            id,
            size: size as u32,
            payload: payload_at..payload_end,
        });
        // The payload is padded to an even length too.
        pos = payload_end + (size % 2);
    }
    Ok(PsdMeta {
        version,
        channels,
        width,
        height,
        depth,
        color_mode,
        resources,
    })
}

#[cfg(feature = "psd")]
fn psd_color_mode(mode: u16) -> &'static str {
    match mode {
        0 => "bitmap",
        1 => "grayscale",
        2 => "indexed",
        3 => "rgb",
        4 => "cmyk",
        7 => "multichannel",
        8 => "duotone",
        9 => "lab",
        _ => "unknown",
    }
}

#[cfg(feature = "psd")]
fn psd_resource_name(id: u16) -> &'static str {
    match id {
        1005 => "resolution info",
        1006 => "alpha channel names",
        1024 => "target printer",
        1033 => "scanner resolution info",
        1036 => "thumbnail",
        1039 => "icc profile",
        1057 => "exif data",
        1058 => "exif data",
        1060 => "xmp",
        1061 => "caption digest",
        1062 => "print scale",
        1064 => "pixel aspect ratio",
        1069 => "print flags",
        1080 => "print flags information",
        1082 => "exposure time",
        1083 => "gamma",
        2999 => "path selection state",
        4000 => "layer state",
        4008 => "iptc-naa record",
        4009 => "raw image mode",
        4010 => "jpeg quality",
        4011 => "grid and guides info",
        4025 => "print flags information",
        4040 => "lens info",
        4041 => "print flags",
        4053 => "print scale",
        4071 => "print flags",
        _ => "resource",
    }
}

/// A text block, cut at the first NUL and with the control characters
/// that a text block may carry replaced by a space.
#[cfg(any(feature = "psd", feature = "jpeg2000", feature = "jpegxl"))]
fn text_block(data: &[u8], range: core::ops::Range<usize>) -> String {
    let raw = data.get(range).unwrap_or(&[]);
    let text = match raw.iter().position(|&b| b == 0) {
        Some(end) => &raw[..end],
        None => raw,
    };
    let mut out = String::new();
    for &b in text {
        if b == b'\n' || b == b'\r' || b == b'\t' {
            out.push(' ');
        } else if b >= 0x20 || b == 0x09 {
            out.push(b as char);
        }
    }
    out
}

// ===========================================================================
// JPEG 2000
// ===========================================================================

/// A JPEG 2000 file: the JP2 container or the bare codestream.
#[cfg(feature = "jpeg2000")]
pub struct Jpeg2000;
#[cfg(feature = "jpeg2000")]
impl Adapter for Jpeg2000 {
    fn name(&self) -> &'static str {
        "jpeg2000"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["jp2", "j2k", "j2c", "jpf", "jpx", "jpm"]
    }
    fn magic(&self) -> Option<&'static [u8]> {
        Some(b"\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a")
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let mut out = String::new();
        if data.len() >= 2 && data[0] == 0xFF && data[1] == 0x4F {
            // The bare codestream: SOC, then the SIZ marker.
            let _ = writeln!(out, "container: codestream");
            j2k_codestream(data, &mut out)?;
        } else {
            let _ = writeln!(out, "container: jp2");
            jp2_boxes(data, &mut out)?;
        }
        Ok(Outcome::Text(out.into_bytes()))
    }

    fn facts(&self, data: &[u8], _path: &str) -> Vec<Field> {
        let mut facts = Vec::new();
        if data.len() >= 2 && data[0] == 0xFF && data[1] == 0x4F {
            if let Some((w, h)) = j2k_size(data) {
                facts.push(Field::new("jp2.width", &w.to_string()));
                facts.push(Field::new("jp2.height", &h.to_string()));
            }
        } else if let Some((w, h)) = jp2_dimensions(data) {
            facts.push(Field::new("jp2.width", &w.to_string()));
            facts.push(Field::new("jp2.height", &h.to_string()));
        }
        facts
    }
}

/// The SIZ marker's image size: the grid that holds the image, which is
/// the size of the image when the origin is at zero.
///
/// The marker is two bytes and the segment that follows it starts with
/// its own length, so the fields are read from `siz + 2`.
#[cfg(feature = "jpeg2000")]
fn j2k_size(data: &[u8]) -> Option<(u32, u32)> {
    let siz = find_marker(data, 0x51)?;
    let at = siz + 2;
    let xsiz = be32(data, at + 4).ok()?;
    let ysiz = be32(data, at + 8).ok()?;
    let xosiz = be32(data, at + 12).ok()?;
    let yosiz = be32(data, at + 16).ok()?;
    Some((xsiz.saturating_sub(xosiz), ysiz.saturating_sub(yosiz)))
}

/// The offset of a marker segment: the two bytes of the marker and the
/// two of its length, the length counting the length field itself.
#[cfg(feature = "jpeg2000")]
fn find_marker(data: &[u8], marker: u8) -> Option<usize> {
    let mut at = 0usize;
    while at + 4 <= data.len() {
        if data[at] != 0xFF {
            at += 1;
            continue;
        }
        if data[at + 1] == marker {
            return Some(at);
        }
        // The markers that carry no segment (SOC, EOC, RSTn, and the
        // ones without a length) are one byte; the rest carry a length.
        let no_len = matches!(data[at + 1], 0x4F | 0x4D | 0x90..=0x93 | 0xD0..=0xD7);
        if no_len {
            at += 2;
            continue;
        }
        let len = u16::from_be_bytes([data[at + 2], data[at + 3]]) as usize;
        if len < 2 {
            return None;
        }
        at += 2 + len;
    }
    None
}

/// The codestream's own markers: the image size, the components and the
/// coding parameters that are worth saying out loud.
#[cfg(feature = "jpeg2000")]
fn j2k_codestream(data: &[u8], out: &mut String) -> Result<()> {
    let siz = find_marker(data, 0x51).ok_or_else(|| rgx_core::anyhow!("no SIZ marker"))?;
    // The marker is two bytes; the segment's own length field follows it,
    // and the fields of the segment come after that.
    let at = siz + 2;
    let xsiz = be32(data, at + 4)?;
    let ysiz = be32(data, at + 8)?;
    let xosiz = be32(data, at + 12)?;
    let yosiz = be32(data, at + 16)?;
    let xtsiz = be32(data, at + 20)?;
    let ytsiz = be32(data, at + 24)?;
    let csiz = be16(data, at + 36)? as usize;
    let _ = writeln!(out, "width: {}", xsiz.saturating_sub(xosiz));
    let _ = writeln!(out, "height: {}", ysiz.saturating_sub(yosiz));
    let _ = writeln!(out, "tile_width: {}", xtsiz);
    let _ = writeln!(out, "tile_height: {}", ytsiz);
    let _ = writeln!(out, "components: {csiz}");
    for c in 0..csiz {
        let cat = at + 38 + c * 3;
        let Some(ssiz) = data.get(cat) else { break };
        // Ssiz holds the bit depth minus one, and the sign bit of the
        // high byte says the component is signed.
        let depth = (*ssiz & 0x7F) + 1;
        let signed = *ssiz & 0x80 != 0;
        let _ = writeln!(
            out,
            "component {}: {} bit{}",
            c,
            depth,
            if signed { ", signed" } else { "" }
        );
    }
    Ok(())
}

/// The JP2 container's boxes: the image header, the colour space, the
/// resolution and the XMP packet.
#[cfg(feature = "jpeg2000")]
fn jp2_boxes(data: &[u8], out: &mut String) -> Result<()> {
    let mut at = 0usize;
    while at + 8 <= data.len() {
        let size = be32(data, at)? as usize;
        let typ = &data[at + 4..at + 8];
        let body_at = at + 8;
        let body_len = if size == 0 {
            data.len() - body_at
        } else if size == 1 {
            // A 64-bit size follows the type.
            if at + 16 > data.len() {
                bail!("JP2 box truncated");
            }
            let mut v = [0u8; 8];
            for (i, b) in data[at + 8..at + 16].iter().enumerate() {
                v[i] = *b;
            }
            let big = u64::from_be_bytes(v) as usize;
            big.saturating_sub(16)
        } else {
            size.saturating_sub(8)
        };
        let body_end = body_at.saturating_add(body_len).min(data.len());
        match typ {
            b"ftyp" => {
                let brand = data.get(body_at..body_at + 4).unwrap_or(&[]);
                let _ = writeln!(out, "brand: {}", String::from_utf8_lossy(brand).trim_end());
            }
            b"jp2h" => {
                // A superbox: the image header and the colour space are
                // boxes inside it.
                jp2_superbox(data.get(body_at..body_end).unwrap_or(&[]), out)?;
            }
            b"colr" => jp2_colour(data.get(body_at..body_end).unwrap_or(&[]), out)?,
            b"res " => jp2_resolution(data.get(body_at..body_end).unwrap_or(&[]), out)?,
            b"xml " => {
                let _ = writeln!(out, "xmp:");
                let _ = write!(out, "{}", text_block(data, body_at..body_end));
            }
            b"uuid" => {
                let uuid = data.get(body_at..body_at + 16).unwrap_or(&[]);
                let mut hex = String::new();
                for b in uuid {
                    let _ = write!(hex, "{b:02x}");
                }
                let _ = writeln!(out, "uuid: {hex}");
                let payload_at = body_at + 16;
                let payload = data.get(payload_at..body_end).unwrap_or(&[]);
                if payload.starts_with(b"Exif\0\0") {
                    let mut reader = crate::exif::ExifReader::new(payload);
                    if reader.parse_jpeg().is_ok() {
                        let _ = writeln!(out, "exif:");
                        let _ = write!(out, "{}", crate::fmt_exif(&reader));
                    }
                }
            }
            _ => {}
        }
        if size == 0 {
            break;
        }
        at = body_at.saturating_add(body_len);
        if at <= body_at {
            break;
        }
    }
    Ok(())
}

/// The boxes inside the `jp2h` superbox: `ihdr` and `colr`.
#[cfg(feature = "jpeg2000")]
fn jp2_superbox(body: &[u8], out: &mut String) -> Result<()> {
    let mut at = 0usize;
    while at + 8 <= body.len() {
        let size =
            u32::from_be_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]]) as usize;
        let typ = &body[at + 4..at + 8];
        let body_at = at + 8;
        let body_len = size.saturating_sub(8).min(body.len() - body_at);
        let inner = body.get(body_at..body_at + body_len).unwrap_or(&[]);
        match typ {
            b"ihdr" => {
                if inner.len() >= 14 {
                    let height = u32::from_be_bytes([inner[0], inner[1], inner[2], inner[3]]);
                    let width = u32::from_be_bytes([inner[4], inner[5], inner[6], inner[7]]);
                    let components = u16::from_be_bytes([inner[8], inner[9]]);
                    let depth = inner[10] + 1;
                    let _ = writeln!(out, "width: {width}");
                    let _ = writeln!(out, "height: {height}");
                    let _ = writeln!(out, "components: {components}");
                    let _ = writeln!(out, "bit_depth: {depth}");
                }
            }
            b"colr" => jp2_colour(inner, out)?,
            b"res " => jp2_resolution(inner, out)?,
            _ => {}
        }
        if size == 0 {
            break;
        }
        at = body_at.saturating_add(body_len);
        if at <= body_at {
            break;
        }
    }
    Ok(())
}

/// The colour specification box: an enumerated colour space or an ICC
/// profile.
#[cfg(feature = "jpeg2000")]
fn jp2_colour(body: &[u8], out: &mut String) -> Result<()> {
    let Some(&method) = body.first() else {
        return Ok(());
    };
    match method {
        1 => {
            if body.len() >= 7 {
                let cs = u32::from_be_bytes([body[3], body[4], body[5], body[6]]);
                let _ = writeln!(out, "colour_space: {}", jp2_colour_space(cs));
            }
        }
        2 => {
            let _ = writeln!(out, "colour_space: icc profile ({} bytes)", body.len());
        }
        _ => {
            let _ = writeln!(out, "colour_space: method {method}");
        }
    }
    Ok(())
}

#[cfg(feature = "jpeg2000")]
fn jp2_colour_space(cs: u32) -> &'static str {
    match cs {
        16 => "sRGB",
        17 => "greyscale",
        18 => "sYCC",
        22 => "CIELab",
        _ => "enumerated",
    }
}

/// The resolution box: two signed 16-bit numbers and a unit.
#[cfg(feature = "jpeg2000")]
fn jp2_resolution(body: &[u8], out: &mut String) -> Result<()> {
    if body.len() >= 6 {
        let dx = i16::from_be_bytes([body[0], body[1]]);
        let dy = i16::from_be_bytes([body[2], body[3]]);
        let unit = u16::from_be_bytes([body[4], body[5]]);
        let unit_name = match unit {
            0 => "none",
            1 => "metres",
            2 => "centimetres",
            3 => "millimetres",
            _ => "unknown",
        };
        let _ = writeln!(out, "resolution: {dx} x {dy} ({unit_name})");
    }
    Ok(())
}

/// The dimensions of a JP2 container, read from its image header box.
#[cfg(feature = "jpeg2000")]
fn jp2_dimensions(data: &[u8]) -> Option<(u32, u32)> {
    let mut at = 0usize;
    while at + 8 <= data.len() {
        let size =
            u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]) as usize;
        let typ = &data[at + 4..at + 8];
        let body_at = at + 8;
        let body_len = if size == 0 {
            data.len() - body_at
        } else {
            size.saturating_sub(8)
        };
        if typ == b"jp2h" {
            let mut inner_at = 0usize;
            let inner = data.get(body_at..body_at + body_len).unwrap_or(&[]);
            while inner_at + 8 <= inner.len() {
                let isize_ = u32::from_be_bytes([
                    inner[inner_at],
                    inner[inner_at + 1],
                    inner[inner_at + 2],
                    inner[inner_at + 3],
                ]) as usize;
                let ityp = &inner[inner_at + 4..inner_at + 8];
                let ibody = inner_at + 8;
                let ilen = isize_.saturating_sub(8);
                if ityp == b"ihdr" {
                    let ihdr = inner.get(ibody..ibody + ilen)?;
                    if ihdr.len() >= 8 {
                        let height = u32::from_be_bytes([ihdr[0], ihdr[1], ihdr[2], ihdr[3]]);
                        let width = u32::from_be_bytes([ihdr[4], ihdr[5], ihdr[6], ihdr[7]]);
                        return Some((width, height));
                    }
                }
                inner_at = ibody.saturating_add(ilen);
            }
        }
        if size == 0 {
            break;
        }
        at = body_at.saturating_add(body_len);
    }
    None
}

// ===========================================================================
// JPEG XL
// ===========================================================================

/// A JPEG XL file: the ISO base media container or the bare codestream.
#[cfg(feature = "jpegxl")]
pub struct JpegXl;
#[cfg(feature = "jpegxl")]
impl Adapter for JpegXl {
    fn name(&self) -> &'static str {
        "jpegxl"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["jxl"]
    }
    fn magic(&self) -> Option<&'static [u8]> {
        Some(b"\x00\x00\x00\x0cJXL \x0d\x0a\x87\x0a")
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let mut out = String::new();
        if data.len() >= 2 && data[0] == 0xFF && data[1] == 0x0A {
            let _ = writeln!(out, "container: codestream");
            let _ = writeln!(out, "signature: FF 0A");
            let _ = writeln!(
                out,
                "dimensions: not read (the codestream's size header is entropy-coded)"
            );
        } else {
            let _ = writeln!(out, "container: iso base media");
            jxl_boxes(data, &mut out)?;
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// The JPEG XL container's boxes: the brand, the EXIF block and the XMP.
#[cfg(feature = "jpegxl")]
fn jxl_boxes(data: &[u8], out: &mut String) -> Result<()> {
    let mut at = 0usize;
    while at + 8 <= data.len() {
        let size =
            u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]) as usize;
        let typ = &data[at + 4..at + 8];
        let body_at = at + 8;
        let body_len = if size == 0 {
            data.len() - body_at
        } else if size == 1 {
            let b = data
                .get(at + 8..at + 16)
                .ok_or_else(|| rgx_core::anyhow!("JPEG XL box truncated"))?;
            let mut v = [0u8; 8];
            v.copy_from_slice(b);
            (u64::from_be_bytes(v) as usize).saturating_sub(16)
        } else {
            size.saturating_sub(8)
        };
        let body_end = body_at.saturating_add(body_len).min(data.len());
        match typ {
            b"ftyp" => {
                let brand = data.get(body_at..body_at + 4).unwrap_or(&[]);
                let _ = writeln!(out, "brand: {}", String::from_utf8_lossy(brand).trim_end());
            }
            b"Exif" => {
                // The EXIF box starts with a four-byte offset to the TIFF
                // header, which is zero in every file written so far.
                let payload = data.get(body_at..body_end).unwrap_or(&[]);
                let tiff_at = if payload.len() >= 4 {
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize
                } else {
                    0
                };
                let block = payload.get(tiff_at..).unwrap_or(&[]);
                let mut reader = crate::exif::ExifReader::new(block);
                if reader.parse_tiff().is_ok() {
                    let _ = writeln!(out, "exif:");
                    let _ = write!(out, "{}", crate::fmt_exif(&reader));
                }
            }
            b"xml " => {
                let _ = writeln!(out, "xmp:");
                let _ = write!(out, "{}", text_block(data, body_at..body_end));
            }
            b"jxlc" => {
                let _ = writeln!(out, "codestream: {} bytes", body_len);
            }
            b"jxlp" => {
                let _ = writeln!(out, "codestream_part: {} bytes", body_len);
            }
            b"jbrd" => {
                let _ = writeln!(out, "jpeg_reconstruction: {} bytes", body_len);
            }
            _ => {}
        }
        if size == 0 {
            break;
        }
        at = body_at.saturating_add(body_len);
        if at <= body_at {
            break;
        }
    }
    Ok(())
}

// ===========================================================================
// OpenEXR
// ===========================================================================

/// An OpenEXR image.
#[cfg(feature = "openexr")]
pub struct OpenExr;
#[cfg(feature = "openexr")]
impl Adapter for OpenExr {
    fn name(&self) -> &'static str {
        "openexr"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["exr"]
    }
    fn magic(&self) -> Option<&'static [u8]> {
        Some(b"\x76\x2f\x31\x01")
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let meta = exr_meta(data)?;
        let mut out = String::new();
        let _ = writeln!(out, "version: {}", meta.version);
        let _ = writeln!(out, "compression: {}", exr_compression(meta.compression));
        if let Some((w, h)) = meta.data_window {
            let _ = writeln!(out, "width: {w}");
            let _ = writeln!(out, "height: {h}");
        }
        if let Some((w, h)) = meta.display_window {
            let _ = writeln!(out, "display_width: {w}");
            let _ = writeln!(out, "display_height: {h}");
        }
        let _ = writeln!(out, "channels: {}", meta.channels.len());
        for c in &meta.channels {
            let _ = writeln!(out, "channel {}: {}", c.name, c.pixel_type);
        }
        for (name, value) in &meta.strings {
            let _ = writeln!(out, "{name}: {value}");
        }
        for (name, value) in &meta.floats {
            let _ = writeln!(out, "{name}: {value}");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }

    fn facts(&self, data: &[u8], _path: &str) -> Vec<Field> {
        let Ok(meta) = exr_meta(data) else {
            return Vec::new();
        };
        let mut facts = vec![Field::new("exr.channels", &meta.channels.len().to_string())];
        if let Some((w, h)) = meta.data_window {
            facts.push(Field::new("exr.width", &w.to_string()));
            facts.push(Field::new("exr.height", &h.to_string()));
        }
        facts
    }
}

#[cfg(feature = "openexr")]
struct ExrMeta {
    version: u32,
    compression: Option<u8>,
    data_window: Option<(u32, u32)>,
    display_window: Option<(u32, u32)>,
    channels: Vec<ExrChannel>,
    strings: Vec<(String, String)>,
    floats: Vec<(String, f32)>,
}

#[cfg(feature = "openexr")]
struct ExrChannel {
    name: String,
    pixel_type: &'static str,
}

#[cfg(feature = "openexr")]
fn exr_meta(data: &[u8]) -> Result<ExrMeta> {
    if data.len() < 8 {
        decline!("fewer bytes than an OpenEXR header");
    }
    if &data[0..4] != b"\x76\x2f\x31\x01" {
        decline!("not an OpenEXR (bad magic)");
    }
    let version_flags = le32(data, 4)?;
    let mut meta = ExrMeta {
        version: version_flags & 0xFF,
        compression: None,
        data_window: None,
        display_window: None,
        channels: Vec::new(),
        strings: Vec::new(),
        floats: Vec::new(),
    };
    let mut at = 8usize;
    while let Some(&name_end) = data.get(at) {
        if name_end == 0 {
            // The header ends with an empty name.
            break;
        }
        let name = cstr(data, at)?;
        at += name.len() + 1;
        let typ = cstr(data, at)?;
        at += typ.len() + 1;
        let size = le32i(data, at)? as usize;
        at += 4;
        let value = data
            .get(at..at + size)
            .ok_or_else(|| rgx_core::anyhow!("OpenEXR attribute truncated"))?;
        at += size;
        match typ.as_str() {
            "compression" => meta.compression = value.first().copied(),
            "lineOrder" => {}
            // A window is a `box2i`; the *name* says which window it is.
            "box2i" => match name.as_str() {
                "dataWindow" => meta.data_window = exr_box(value),
                "displayWindow" => meta.display_window = exr_box(value),
                _ => {}
            },
            "chlist" => meta.channels = exr_channels(value),
            "string" => {
                let mut v = String::from_utf8_lossy(value).into_owned();
                while v.ends_with('\0') {
                    v.pop();
                }
                meta.strings.push((name, v));
            }
            "float" if value.len() >= 4 => {
                let f = f32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                meta.floats.push((name, f));
            }
            _ => {}
        }
    }
    Ok(meta)
}

/// A NUL-terminated string at `at`.
#[cfg(feature = "openexr")]
fn cstr(data: &[u8], at: usize) -> Result<String> {
    let end = data[at..]
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| rgx_core::anyhow!("unterminated string"))?;
    Ok(String::from_utf8_lossy(&data[at..at + end]).into_owned())
}

/// A `box2i`: four signed integers, the last two being the size.
///
/// **The window is inclusive.** A data window of `(0, 0)` to `(63, 47)` is
/// sixty-four by forty-eight pixels, not sixty-three by forty-seven: the
/// two corners are pixels, not the space between them.
#[cfg(feature = "openexr")]
fn exr_box(value: &[u8]) -> Option<(u32, u32)> {
    if value.len() < 16 {
        return None;
    }
    let x1 = i32::from_le_bytes([value[0], value[1], value[2], value[3]]);
    let y1 = i32::from_le_bytes([value[4], value[5], value[6], value[7]]);
    let x2 = i32::from_le_bytes([value[8], value[9], value[10], value[11]]);
    let y2 = i32::from_le_bytes([value[12], value[13], value[14], value[15]]);
    Some(((x2 - x1 + 1).max(0) as u32, (y2 - y1 + 1).max(0) as u32))
}

/// The channel list: a name, a pixel type and the sampling.
#[cfg(feature = "openexr")]
fn exr_channels(value: &[u8]) -> Vec<ExrChannel> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < value.len() {
        let Some(end) = value[at..].iter().position(|&b| b == 0) else {
            break;
        };
        if end == 0 {
            break;
        }
        let name = String::from_utf8_lossy(&value[at..at + end]).into_owned();
        at += end + 1;
        if at + 16 > value.len() {
            break;
        }
        let ptype = i32::from_le_bytes([value[at], value[at + 1], value[at + 2], value[at + 3]]);
        at += 16;
        let pixel_type = match ptype {
            0 => "uint",
            1 => "half",
            2 => "float",
            _ => "unknown",
        };
        out.push(ExrChannel { name, pixel_type });
    }
    out
}

#[cfg(feature = "openexr")]
fn exr_compression(c: Option<u8>) -> &'static str {
    match c {
        Some(0) => "none",
        Some(1) => "rle",
        Some(2) => "zips",
        Some(3) => "zip",
        Some(4) => "piz",
        Some(5) => "pxr24",
        Some(6) => "b44",
        Some(7) => "b44a",
        Some(8) => "dwaa",
        Some(9) => "dwab",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(
        feature = "psd",
        feature = "jpeg2000",
        feature = "jpegxl",
        feature = "openexr"
    ))]
    use alloc::vec::Vec;

    #[cfg(any(
        feature = "psd",
        feature = "jpeg2000",
        feature = "jpegxl",
        feature = "openexr"
    ))]
    fn text_of(out: Outcome) -> String {
        match out {
            Outcome::Text(t) => String::from_utf8(t).unwrap(),
            _ => panic!("expected text"),
        }
    }

    // ----------------------------------------------------------------- PSD

    #[cfg(feature = "psd")]
    fn mini_psd() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"8BPS");
        v.extend_from_slice(&1u16.to_be_bytes()); // version
        v.extend_from_slice(&[0u8; 6]); // reserved
        v.extend_from_slice(&3u16.to_be_bytes()); // channels
        v.extend_from_slice(&48u32.to_be_bytes()); // height
        v.extend_from_slice(&64u32.to_be_bytes()); // width
        v.extend_from_slice(&8u16.to_be_bytes()); // depth
        v.extend_from_slice(&3u16.to_be_bytes()); // colour mode: RGB
        v.extend_from_slice(&0u32.to_be_bytes()); // colour mode data
                                                  // image resources: one XMP block
        let xmp = b"<x:xmpmeta>Jane Doe</x:xmpmeta>";
        let mut res = Vec::new();
        res.extend_from_slice(b"8BIM");
        res.extend_from_slice(&1060u16.to_be_bytes());
        res.push(0); // empty Pascal name
        res.push(0); // padding to an even length
        res.extend_from_slice(&(xmp.len() as u32).to_be_bytes());
        res.extend_from_slice(xmp);
        if res.len() % 2 == 1 {
            res.push(0);
        }
        v.extend_from_slice(&(res.len() as u32).to_be_bytes());
        v.extend_from_slice(&res);
        v.extend_from_slice(&0u32.to_be_bytes()); // layer and mask info
        v.extend_from_slice(&0u16.to_be_bytes()); // compression: raw
        v
    }

    #[test]
    #[cfg(feature = "psd")]
    fn a_psd_header_and_its_xmp() {
        let s = text_of(Psd.extract(&mini_psd(), "a.psd").unwrap());
        assert!(s.contains("format: Photoshop Document"), "{s}");
        assert!(s.contains("width: 64"), "{s}");
        assert!(s.contains("height: 48"), "{s}");
        assert!(s.contains("channels: 3"), "{s}");
        assert!(s.contains("color_mode: rgb"), "{s}");
        assert!(s.contains("resource 1060 xmp"), "{s}");
        assert!(s.contains("Jane Doe"), "{s}");
    }

    #[test]
    #[cfg(feature = "psd")]
    fn a_psd_whose_name_is_not_psd_is_refused() {
        assert!(Psd
            .extract(b"NOTPSD1234567890123456789012", "a.psd")
            .is_err());
        assert!(Psd.extract(b"", "a.psd").is_err());
    }

    #[test]
    #[cfg(feature = "psd")]
    fn the_psd_facts_carry_the_dimensions() {
        let facts = Psd.facts(&mini_psd(), "a.psd");
        let w = facts.iter().find(|f| f.name == "psd.width");
        assert_eq!(w.map(|f| f.value.as_str()), Some("64"));
    }

    // ------------------------------------------------------------ JPEG 2000

    #[cfg(feature = "jpeg2000")]
    fn jp2_container() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a");
        // ftyp
        let mut ftyp = Vec::new();
        ftyp.extend_from_slice(b"ftyp");
        ftyp.extend_from_slice(b"jp2 ");
        ftyp.extend_from_slice(&0u32.to_be_bytes());
        ftyp.extend_from_slice(b"jp2 ");
        v.extend_from_slice(&((ftyp.len() + 4) as u32).to_be_bytes());
        v.extend_from_slice(&ftyp);
        // jp2h: ihdr + colr, each a box with its own size
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(b"ihdr");
        ihdr.extend_from_slice(&48u32.to_be_bytes()); // height
        ihdr.extend_from_slice(&64u32.to_be_bytes()); // width
        ihdr.extend_from_slice(&3u16.to_be_bytes()); // components
        ihdr.push(7); // bit depth - 1
        ihdr.push(7); // compression: wavelet
        ihdr.push(0);
        ihdr.push(0);
        let mut ihdr_box = Vec::new();
        ihdr_box.extend_from_slice(&((ihdr.len() + 4) as u32).to_be_bytes());
        ihdr_box.extend_from_slice(&ihdr);
        let mut colr = Vec::new();
        colr.extend_from_slice(b"colr");
        colr.extend_from_slice(&[1, 0, 0]); // enumerated
        colr.extend_from_slice(&16u32.to_be_bytes()); // sRGB
        let mut colr_box = Vec::new();
        colr_box.extend_from_slice(&((colr.len() + 4) as u32).to_be_bytes());
        colr_box.extend_from_slice(&colr);
        let mut jp2h = Vec::new();
        jp2h.extend_from_slice(b"jp2h");
        jp2h.extend_from_slice(&ihdr_box);
        jp2h.extend_from_slice(&colr_box);
        v.extend_from_slice(&((jp2h.len() + 4) as u32).to_be_bytes());
        v.extend_from_slice(&jp2h);
        // xml
        let xmp = b"<x:xmpmeta>ACME</x:xmpmeta>";
        let mut xml = Vec::new();
        xml.extend_from_slice(b"xml ");
        xml.extend_from_slice(xmp);
        v.extend_from_slice(&((xml.len() + 4) as u32).to_be_bytes());
        v.extend_from_slice(&xml);
        v
    }

    #[cfg(feature = "jpeg2000")]
    fn j2k_codestream() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0xFF, 0x4F]); // SOC
        let mut siz = Vec::new();
        siz.extend_from_slice(&38u16.to_be_bytes()); // Lsiz
        siz.extend_from_slice(&0u16.to_be_bytes()); // Rsiz
        siz.extend_from_slice(&64u32.to_be_bytes()); // Xsiz
        siz.extend_from_slice(&48u32.to_be_bytes()); // Ysiz
        siz.extend_from_slice(&0u32.to_be_bytes()); // XOsiz
        siz.extend_from_slice(&0u32.to_be_bytes()); // YOsiz
        siz.extend_from_slice(&64u32.to_be_bytes()); // XTsiz
        siz.extend_from_slice(&48u32.to_be_bytes()); // YTsiz
        siz.extend_from_slice(&0u32.to_be_bytes()); // XTOsiz
        siz.extend_from_slice(&0u32.to_be_bytes()); // YTOsiz
        siz.extend_from_slice(&3u16.to_be_bytes()); // Csiz
        for _ in 0..3 {
            siz.extend_from_slice(&[7, 1, 1]); // Ssiz, XRsiz, YRsiz
        }
        v.extend_from_slice(&[0xFF, 0x51]);
        v.extend_from_slice(&siz);
        v
    }

    #[test]
    #[cfg(feature = "jpeg2000")]
    fn a_jp2_container_carries_its_size_and_its_xmp() {
        let s = text_of(Jpeg2000.extract(&jp2_container(), "a.jp2").unwrap());
        assert!(s.contains("container: jp2"), "{s}");
        assert!(s.contains("brand: jp2"), "{s}");
        assert!(s.contains("width: 64"), "{s}");
        assert!(s.contains("height: 48"), "{s}");
        assert!(s.contains("components: 3"), "{s}");
        assert!(s.contains("colour_space: sRGB"), "{s}");
        assert!(s.contains("ACME"), "{s}");
    }

    #[test]
    #[cfg(feature = "jpeg2000")]
    fn a_j2k_codestream_carries_its_size() {
        let s = text_of(Jpeg2000.extract(&j2k_codestream(), "a.j2k").unwrap());
        assert!(s.contains("container: codestream"), "{s}");
        assert!(s.contains("width: 64"), "{s}");
        assert!(s.contains("height: 48"), "{s}");
        assert!(s.contains("components: 3"), "{s}");
        assert!(s.contains("component 0: 8 bit"), "{s}");
    }

    #[test]
    #[cfg(feature = "jpeg2000")]
    fn the_jpeg2000_facts_carry_the_dimensions() {
        let facts = Jpeg2000.facts(&jp2_container(), "a.jp2");
        assert_eq!(
            facts
                .iter()
                .find(|f| f.name == "jp2.width")
                .map(|f| f.value.as_str()),
            Some("64")
        );
    }

    // -------------------------------------------------------------- JPEG XL

    #[cfg(feature = "jpegxl")]
    fn jxl_container() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"\x00\x00\x00\x0cJXL \x0d\x0a\x87\x0a");
        let mut ftyp = Vec::new();
        ftyp.extend_from_slice(b"ftyp");
        ftyp.extend_from_slice(b"jxl ");
        ftyp.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&((ftyp.len() + 4) as u32).to_be_bytes());
        v.extend_from_slice(&ftyp);
        let xmp = b"<x:xmpmeta>ACME</x:xmpmeta>";
        let mut xml = Vec::new();
        xml.extend_from_slice(b"xml ");
        xml.extend_from_slice(xmp);
        v.extend_from_slice(&((xml.len() + 4) as u32).to_be_bytes());
        v.extend_from_slice(&xml);
        v
    }

    #[test]
    #[cfg(feature = "jpegxl")]
    fn a_jxl_container_carries_its_xmp() {
        let s = text_of(JpegXl.extract(&jxl_container(), "a.jxl").unwrap());
        assert!(s.contains("container: iso base media"), "{s}");
        assert!(s.contains("brand: jxl"), "{s}");
        assert!(s.contains("ACME"), "{s}");
    }

    #[test]
    #[cfg(feature = "jpegxl")]
    fn a_bare_jxl_codestream_says_what_it_cannot_answer() {
        let s = text_of(JpegXl.extract(&[0xFF, 0x0A, 0, 0, 0, 0], "a.jxl").unwrap());
        assert!(s.contains("container: codestream"), "{s}");
        assert!(s.contains("not read"), "{s}");
    }

    // -------------------------------------------------------------- OpenEXR

    #[cfg(feature = "openexr")]
    fn openexr() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x76, 0x2F, 0x31, 0x01]);
        v.extend_from_slice(&2u32.to_le_bytes()); // version and flags
                                                  // channels
        let mut chlist = Vec::new();
        for name in ["R", "G", "B"] {
            chlist.extend_from_slice(name.as_bytes());
            chlist.push(0);
            chlist.extend_from_slice(&0i32.to_le_bytes()); // uint
            chlist.push(0); // pLinear
            chlist.extend_from_slice(&[0, 0, 0]); // reserved
            chlist.extend_from_slice(&1i32.to_le_bytes()); // xSampling
            chlist.extend_from_slice(&1i32.to_le_bytes()); // ySampling
        }
        v.extend_from_slice(b"channels\0");
        v.extend_from_slice(b"chlist\0");
        v.extend_from_slice(&(chlist.len() as u32).to_le_bytes());
        v.extend_from_slice(&chlist);
        // compression
        v.extend_from_slice(b"compression\0");
        v.extend_from_slice(b"compression\0");
        v.extend_from_slice(&1u32.to_le_bytes());
        v.push(0);
        // dataWindow
        v.extend_from_slice(b"dataWindow\0");
        v.extend_from_slice(b"box2i\0");
        v.extend_from_slice(&16u32.to_le_bytes());
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&63i32.to_le_bytes());
        v.extend_from_slice(&47i32.to_le_bytes());
        // comments
        v.extend_from_slice(b"comments\0");
        v.extend_from_slice(b"string\0");
        v.extend_from_slice(&6u32.to_le_bytes());
        v.extend_from_slice(b"hello\0");
        v.push(0); // end of the header
        v
    }

    #[test]
    #[cfg(feature = "openexr")]
    fn an_openexr_header_carries_its_channels_and_its_window() {
        let s = text_of(OpenExr.extract(&openexr(), "a.exr").unwrap());
        assert!(s.contains("channels: 3"), "{s}");
        assert!(s.contains("channel R: uint"), "{s}");
        assert!(s.contains("width: 64"), "{s}");
        assert!(s.contains("height: 48"), "{s}");
        assert!(s.contains("compression: none"), "{s}");
        assert!(s.contains("comments: hello"), "{s}");
    }

    #[test]
    #[cfg(feature = "openexr")]
    fn an_openexr_that_is_not_one_is_refused() {
        assert!(OpenExr
            .extract(b"\x00\x01\x02\x03\x04\x05\x06\x07", "a.exr")
            .is_err());
        assert!(OpenExr.extract(b"", "a.exr").is_err());
    }

    #[test]
    #[cfg(feature = "openexr")]
    fn the_openexr_facts_carry_the_dimensions() {
        let facts = OpenExr.facts(&openexr(), "a.exr");
        assert_eq!(
            facts
                .iter()
                .find(|f| f.name == "exr.width")
                .map(|f| f.value.as_str()),
            Some("64")
        );
        assert_eq!(
            facts
                .iter()
                .find(|f| f.name == "exr.channels")
                .map(|f| f.value.as_str()),
            Some("3")
        );
    }
}
