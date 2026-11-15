// SPDX-License-Identifier: Apache-2.0

//! EXIF reader (EXIF 2.31 / TIFF 6.0 structure).
//!
//! Independent reimplementation of the EXIF/TIFF metadata walk: a TIFF
//! header (`II`/`MM` byte order, magic 42, offset of IFD0), a chain of
//! IFDs joined by their next-IFD offsets, and the three pointer tags
//! that hang the sub-IFDs off IFD0/ExifIFD (Exif 0x8769, GPS 0x8825,
//! Interop 0xA005). Value offsets are **relative to the TIFF header**,
//! which is not buffer zero when the payload is wrapped in a JPEG APP1
//! segment's `Exif\0\0` prefix — the one place the walk is easy to get
//! wrong, and the one a 6-byte skew hides in.
//!
//! # Contract
//!
//! An IFD entry is 12 bytes: tag, type, count, then a 4-byte value
//! slot. A value of `type_size x count <= 4` bytes lives *inline* in
//! the slot — in the file's byte order, which for a 1- or 2-byte value
//! in a big-endian file means the *high* bytes of the slot, so the
//! numeric value is the slot shifted down. Anything longer stores an
//! offset to the value, relative to the TIFF header. IFD1 is the
//! thumbnail IFD at the next-IFD offset of IFD0; the pointer tags
//! above name the others.
//!
//! [`find_exif_payload`] unwraps the containers EXIF is shipped in:
//! JPEG (APP1 marker scan), WebP (RIFF `EXIF` chunk), PNG (`eXIf`
//! chunk, bare TIFF), and a bare TIFF/GeoTIFF passed through as-is.

// The tag vocabulary and MakerNote tables carry every spec tag and
// vendor tag as `pub` constants with no internal users; the unused
// pass fires on names the lookups still serve by table.
#![allow(dead_code)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;

mod ifd;
pub mod makers;
mod tags;
mod tiff;

pub use ifd::*;
pub use tags::*;
pub use tiff::*;

/// EXIF reader.
#[derive(Debug)]
pub struct ExifReader<'a> {
    data: &'a [u8],
    pos: usize,
    /// TIFF header start position in data.
    tiff_start: usize,
    /// TIFF byte order.
    pub byte_order: ByteOrder,
    /// IFD0 entries.
    pub ifd0: Vec<IfdEntry>,
    /// IFD1 entries (thumbnail).
    pub ifd1: Vec<IfdEntry>,
    /// Exif IFD entries.
    pub exif_ifd: Vec<IfdEntry>,
    /// GPS IFD entries.
    pub gps_ifd: Vec<IfdEntry>,
    /// Interop IFD entries.
    pub interop_ifd: Vec<IfdEntry>,
}

/// TIFF byte order (§4.5.2 byte-order marker).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ByteOrder {
    #[default]
    LittleEndian,
    BigEndian,
}

impl<'a> ExifReader<'a> {
    /// Create a new EXIF reader over `data`, empty until a parse runs.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            tiff_start: 0,
            byte_order: ByteOrder::LittleEndian,
            ifd0: Vec::new(),
            ifd1: Vec::new(),
            exif_ifd: Vec::new(),
            gps_ifd: Vec::new(),
            interop_ifd: Vec::new(),
        }
    }

    /// Parse EXIF out of a whole image file: JPEG (APP1 segment scan),
    /// WebP (RIFF `EXIF` chunk), PNG (`eXIf` chunk) or a bare TIFF.
    /// The container is unwrapped first; the payload is then parsed as
    /// it presents itself (`Exif\0\0`-prefixed in JPEG/WebP-EXIF, bare
    /// TIFF in PNG `eXIf` and TIFF files).
    pub fn parse_container(data: &'a [u8]) -> Result<ExifReader<'a>, String> {
        let payload = find_exif_payload(data).ok_or("no EXIF payload in container")?;
        let mut reader = ExifReader::new(payload);
        if payload.len() >= 6 && &payload[0..6] == b"Exif\x00\x00" {
            reader.parse_jpeg()?;
        } else {
            reader.parse_tiff()?;
        }
        Ok(reader)
    }

    /// Parse the `Exif\0\0`-prefixed payload of a JPEG APP1 segment:
    /// the TIFF header starts right after the 6-byte prefix.
    pub fn parse_jpeg(&mut self) -> Result<(), String> {
        if self.data.len() < 6 {
            return Err("Data too short for JPEG EXIF".into());
        }
        if &self.data[0..6] != b"Exif\x00\x00" {
            return Err("Missing Exif header".into());
        }
        self.pos = 6;
        self.tiff_start = 6;
        self.parse_tiff()
    }

    /// Parse a bare TIFF/EXIF payload at the current position.
    pub fn parse_tiff(&mut self) -> Result<(), String> {
        if self.data.len() < self.pos + 8 {
            return Err("Data too short for TIFF header".into());
        }
        if self.tiff_start == 0 {
            self.tiff_start = self.pos;
        }

        let bo = &self.data[self.pos..self.pos + 2];
        self.byte_order = if bo == b"II" {
            ByteOrder::LittleEndian
        } else if bo == b"MM" {
            ByteOrder::BigEndian
        } else {
            return Err("Invalid TIFF byte order".into());
        };
        self.pos += 2;

        let magic = self.read_u16()?;
        if magic != 42 {
            return Err("Invalid TIFF magic number".into());
        }

        // IFD0 offset is relative to the TIFF header.
        let ifd0_offset = self.read_u32()? as usize;
        let absolute_offset = self.tiff_start + ifd0_offset;
        self.ifd0 = self.parse_ifd_entries(absolute_offset, IfdType::Ifd0)?;
        self.extract_sub_ifds()?;
        Ok(())
    }

    /// Parse one IFD's entries at `offset`. For IFD0 only, the
    /// next-IFD offset that closes the directory is followed to IFD1
    /// (the thumbnail).
    fn parse_ifd_entries(
        &mut self,
        offset: usize,
        ifd_type: IfdType,
    ) -> Result<Vec<IfdEntry>, String> {
        if offset >= self.data.len() {
            return Ok(Vec::new());
        }
        self.pos = offset;

        let count = self.read_u16()? as usize;
        let mut entries = Vec::new();
        for _ in 0..count {
            if self.pos + 12 > self.data.len() {
                break;
            }
            let tag = self.read_u16()?;
            let format = self.read_u16()?;
            let entry_count = self.read_u32()?;
            let value_offset = self.pos;
            let raw_value = self.read_u32()?;
            // Inline values occupy the first `type_size x count` bytes
            // of the slot in the file's byte order. In a big-endian file
            // a 1- or 2-byte value sits in the *high* bytes, so the
            // number is the slot shifted down (ISO 400 else reads as
            // 400 << 16).
            let total = Self::type_size(format).saturating_mul(entry_count as usize);
            let value = if total > 0 && total < 4 && self.byte_order == ByteOrder::BigEndian {
                raw_value >> (8 * (4 - total))
            } else {
                raw_value
            };
            entries.push(IfdEntry {
                tag,
                format,
                count: entry_count,
                value_offset,
                value,
                ifd_type,
            });
        }

        if ifd_type == IfdType::Ifd0 && self.pos + 4 <= self.data.len() {
            let next_ifd = self.read_u32()? as usize;
            let absolute_next = self.tiff_start + next_ifd;
            if next_ifd > 0 && absolute_next < self.data.len() {
                self.ifd1 = self.parse_ifd_entries(absolute_next, IfdType::Ifd1)?;
            }
        }
        Ok(entries)
    }

    /// Follow the three pointer tags to their sub-IFDs.
    fn extract_sub_ifds(&mut self) -> Result<(), String> {
        if let Some(entry) = self.ifd0.iter().find(|e| e.tag == 0x8769) {
            let absolute_offset = self.tiff_start + entry.value as usize;
            if absolute_offset < self.data.len() {
                self.exif_ifd = self.parse_ifd_entries(absolute_offset, IfdType::Exif)?;
            }
        }
        if let Some(entry) = self.ifd0.iter().find(|e| e.tag == 0x8825) {
            let absolute_offset = self.tiff_start + entry.value as usize;
            if absolute_offset < self.data.len() {
                self.gps_ifd = self.parse_ifd_entries(absolute_offset, IfdType::Gps)?;
            }
        }
        // Interop hangs off ExifIFD, not IFD0.
        if let Some(entry) = self.exif_ifd.iter().find(|e| e.tag == 0xA005) {
            let absolute_offset = self.tiff_start + entry.value as usize;
            if absolute_offset < self.data.len() {
                self.interop_ifd = self.parse_ifd_entries(absolute_offset, IfdType::Interop)?;
            }
        }
        Ok(())
    }

    fn read_u16(&mut self) -> Result<u16, String> {
        let v = tiff::read_u16(self.data, self.pos, self.byte_order)?;
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        let v = tiff::read_u32(self.data, self.pos, self.byte_order)?;
        self.pos += 4;
        Ok(v)
    }

    /// Bytes per value of a TIFF type (§4.5, types 1-13).
    fn type_size(format: u16) -> usize {
        ifd::format_size(format)
    }

    /// Absolute buffer offset holding an entry's value.
    ///
    /// Inline values already carry their absolute position in
    /// `value_offset`; out-of-line values hold an offset that is
    /// **relative to the TIFF header** and needs `tiff_start` added —
    /// which is 6 for a JPEG payload, 0 for a bare TIFF. Reading it as
    /// absolute makes every out-of-line string and rational short by
    /// exactly the header size: for a JPEG, GPS coordinates, exposure,
    /// f-number and focal length all read from the wrong place.
    fn value_offset_of(&self, entry: &IfdEntry) -> Option<usize> {
        let total = Self::type_size(entry.format).checked_mul(entry.count as usize)?;
        if total <= 4 {
            Some(entry.value_offset)
        } else {
            self.tiff_start.checked_add(entry.value as usize)
        }
    }

    /// First entry with `tag`, searching the Exif SubIFD before IFD0.
    ///
    /// Cameras put ISO/exposure/date tags in the Exif SubIFD (0x8769);
    /// some encoders write the same tags straight into IFD0. The typed
    /// getters take either, the way a whole-file tag walk would.
    fn find_entry(&self, tag: u16) -> Option<&IfdEntry> {
        self.exif_ifd
            .iter()
            .chain(self.ifd0.iter())
            .find(|e| e.tag == tag)
    }

    /// Read an ASCII value, cut at the first NUL.
    fn read_string(&self, entry: &IfdEntry) -> Option<String> {
        let offset = self.value_offset_of(entry)?;
        let end = offset.checked_add(entry.count as usize)?;
        if end > self.data.len() {
            return None;
        }
        let bytes = &self.data[offset..end];
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    /// Render one entry's value as text: ASCII verbatim, inline
    /// numbers as numbers, rationals as decimals, anything else as its
    /// raw u32. The whole-file tag walk (`for entry in reader.ifd0…`)
    /// pairs this with [`tags::tag_name`] to produce a searchable
    /// listing without knowing each tag's type up front.
    pub fn entry_value(&self, entry: &IfdEntry) -> String {
        match entry.format {
            1 | 2 | 6 | 7 => self
                .read_string(entry)
                .unwrap_or_else(|| format!("<{} bytes>", entry.count)),
            3 | 4 | 8 | 9 => entry.value.to_string(),
            5 | 10 => match self.read_rational(entry) {
                Some(v) => {
                    if (v.fract()).abs() < f64::EPSILON {
                        format!("{}", v as i64)
                    } else {
                        format!("{v}")
                    }
                }
                None => format!("<rational {}>", entry.value),
            },
            11 => f32::from_bits(entry.value).to_string(),
            12 => self
                .value_offset_of(entry)
                .filter(|o| o + 8 <= self.data.len())
                .map(|o| {
                    f64::from_bits(u64::from_le_bytes(
                        self.data[o..o + 8].try_into().unwrap_or([0; 8]),
                    ))
                    .to_string()
                })
                .unwrap_or_else(|| "<double>".to_string()),
            _ => entry.value.to_string(),
        }
    }

    /// Get entry by tag from IFD0, else the Exif SubIFD.
    #[must_use]
    pub fn get(&self, tag: u16) -> Option<&IfdEntry> {
        self.ifd0
            .iter()
            .find(|e| e.tag == tag)
            .or_else(|| self.exif_ifd.iter().find(|e| e.tag == tag))
    }

    /// Get string value by tag.
    #[must_use]
    pub fn get_string(&self, tag: u16) -> Option<String> {
        let entry = self.get(tag)?;
        self.read_string(entry)
    }

    /// Get DateTimeOriginal (0x9003).
    #[must_use]
    pub fn datetime_original(&self) -> Option<String> {
        self.get_string(0x9003)
    }

    /// Get DateTime (0x0132).
    #[must_use]
    pub fn datetime(&self) -> Option<String> {
        self.get_string(0x0132)
    }

    /// Get make (manufacturer, 0x010F).
    #[must_use]
    pub fn make(&self) -> Option<String> {
        self.get_string(0x010F)
    }

    /// Get model (0x0110).
    #[must_use]
    pub fn model(&self) -> Option<String> {
        self.get_string(0x0110)
    }

    /// Get GPS coordinates as (latitude, longitude) in decimal degrees,
    /// from the 3-rational DMS fields and the N/S/E/W reference tags
    /// (EXIF 2.31 §4.6.6).
    #[must_use]
    pub fn get_gps(&self) -> Option<(f64, f64)> {
        let lat_entry = self.gps_ifd.iter().find(|e| e.tag == 0x0002)?;
        let lat_ref = self.gps_ifd.iter().find(|e| e.tag == 0x0001);
        let lon_entry = self.gps_ifd.iter().find(|e| e.tag == 0x0004)?;
        let lon_ref = self.gps_ifd.iter().find(|e| e.tag == 0x0003);

        let lat = self.read_rational(lat_entry)?;
        let lon = self.read_rational(lon_entry)?;

        let lat = if let Some(ref_entry) = lat_ref {
            let ref_char = self.read_string(ref_entry);
            if ref_char.map(|s| s.starts_with('S')).unwrap_or(false) {
                -lat
            } else {
                lat
            }
        } else {
            lat
        };

        let lon = if let Some(ref_entry) = lon_ref {
            let ref_char = self.read_string(ref_entry);
            if ref_char.map(|s| s.starts_with('W')).unwrap_or(false) {
                -lon
            } else {
                lon
            }
        } else {
            lon
        };

        Some((lat, lon))
    }

    /// Read a 3-rational DMS value (degrees, minutes, seconds) as
    /// decimal degrees.
    fn read_rational(&self, entry: &IfdEntry) -> Option<f64> {
        let offset = self.value_offset_of(entry)?;
        let end = offset.checked_add(24)?;
        if end > self.data.len() {
            return None;
        }
        let deg = self.read_rational_at(offset)?;
        let min = self.read_rational_at(offset + 8)?;
        let sec = self.read_rational_at(offset + 16)?;
        Some(deg + min / 60.0 + sec / 3600.0)
    }

    /// Read one RATIONAL as its decimal value.
    fn read_rational_at(&self, offset: usize) -> Option<f64> {
        let (num, denom) = tiff::read_rational(self.data, offset, self.byte_order).ok()?;
        if denom == 0 {
            return None;
        }
        Some(num as f64 / denom as f64)
    }

    /// Get ISO speed (0x8827).
    #[must_use]
    pub fn iso(&self) -> Option<u16> {
        let entry = self.find_entry(0x8827)?;
        Some(entry.value as u16)
    }

    /// Get focal length in mm (0x920A, RATIONAL).
    #[must_use]
    pub fn focal_length(&self) -> Option<f64> {
        let entry = self.find_entry(0x920A)?;
        self.read_single_rational(entry)
    }

    /// Get f-number (0x829D, RATIONAL).
    #[must_use]
    pub fn f_number(&self) -> Option<f64> {
        let entry = self.find_entry(0x829D)?;
        self.read_single_rational(entry)
    }

    /// Get exposure time in seconds (0x829A, RATIONAL).
    #[must_use]
    pub fn exposure_time(&self) -> Option<f64> {
        let entry = self.find_entry(0x829A)?;
        self.read_single_rational(entry)
    }

    /// Read one RATIONAL entry as a decimal; a different type or count
    /// is not this shape and reads as `None`.
    fn read_single_rational(&self, entry: &IfdEntry) -> Option<f64> {
        if entry.count != 1 || entry.format != 5 {
            return None;
        }
        let offset = self.value_offset_of(entry)?;
        self.read_rational_at(offset)
    }

    /// Get image width (IFD0 0x0100, else Exif 0xA002).
    #[must_use]
    pub fn image_width(&self) -> Option<u32> {
        self.ifd0
            .iter()
            .find(|e| e.tag == 0x0100)
            .map(|e| e.value)
            .or_else(|| {
                self.exif_ifd
                    .iter()
                    .find(|e| e.tag == 0xA002)
                    .map(|e| e.value)
            })
    }

    /// Get image height (IFD0 0x0101, else Exif 0xA003).
    #[must_use]
    pub fn image_height(&self) -> Option<u32> {
        self.ifd0
            .iter()
            .find(|e| e.tag == 0x0101)
            .map(|e| e.value)
            .or_else(|| {
                self.exif_ifd
                    .iter()
                    .find(|e| e.tag == 0xA003)
                    .map(|e| e.value)
            })
    }

    /// Get orientation (IFD0 0x0112).
    #[must_use]
    pub fn orientation(&self) -> Option<u16> {
        self.ifd0
            .iter()
            .find(|e| e.tag == 0x0112)
            .map(|e| e.value as u16)
    }

    /// Get X resolution in DPI (IFD0 0x011A, RATIONAL).
    #[must_use]
    pub fn x_resolution(&self) -> Option<f64> {
        let entry = self.ifd0.iter().find(|e| e.tag == 0x011A)?;
        self.read_single_rational(entry)
    }

    /// Get Y resolution in DPI (IFD0 0x011B, RATIONAL).
    #[must_use]
    pub fn y_resolution(&self) -> Option<f64> {
        let entry = self.ifd0.iter().find(|e| e.tag == 0x011B)?;
        self.read_single_rational(entry)
    }
}

/// Locate the Exif payload inside an image container.
///
/// JPEG: walk the marker segments (the SOI must be first) and return the
/// APP1 segment whose payload starts with `Exif\0\0`. WebP: the RIFF
/// `EXIF` chunk. PNG: the `eXIf` chunk (bare TIFF, no Exif header). A
/// file that is itself a TIFF/GeoTIFF is returned as-is.
pub fn find_exif_payload(data: &[u8]) -> Option<&[u8]> {
    if data.len() >= 4 && data[0] == 0xFF && data[1] == 0xD8 {
        return jpeg_exif(data);
    }
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return riff_exif(data);
    }
    if data.len() >= 8 && data[0] == 0x89 && &data[1..4] == b"PNG" {
        return png_exif(data);
    }
    if data.len() >= 4 && (&data[0..4] == b"II*\x00" || &data[0..4] == b"MM\x00*") {
        return Some(data);
    }
    None
}

/// JPEG marker-segment walk to the first `Exif\0\0` APP1 payload.
fn jpeg_exif(data: &[u8]) -> Option<&[u8]> {
    let mut pos = 2usize; // past SOI
    while pos + 4 <= data.len() {
        if data[pos] != 0xFF {
            pos += 1; // resync over fill bytes
            continue;
        }
        let marker = data[pos + 1];
        match marker {
            0xFF => {
                pos += 1; // fill byte
                continue;
            }
            // markers without a length field
            0x01 | 0xD0..=0xD9 => {
                pos += 2;
                continue;
            }
            _ => {}
        }
        if pos + 4 > data.len() {
            return None;
        }
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if len < 2 {
            return None;
        }
        let seg = data.get(pos + 4..pos + 2 + len)?;
        if marker == 0xE1 && seg.len() >= 6 && &seg[0..6] == b"Exif\0\0" {
            return Some(seg);
        }
        if marker == 0xDA {
            return None; // start of scan: no more metadata segments
        }
        pos += 2 + len;
    }
    None
}

/// WebP: RIFF chunk walk to the `EXIF` chunk payload.
fn riff_exif(data: &[u8]) -> Option<&[u8]> {
    let mut pos = 12usize; // "RIFF" + size + "WEBP"
    while pos + 8 <= data.len() {
        let fourcc = &data[pos..pos + 4];
        let size = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
            as usize;
        let body = data.get(pos + 8..pos + 8 + size)?;
        if fourcc == b"EXIF" {
            return Some(body);
        }
        pos += 8 + size + (size & 1); // chunks are word-aligned
    }
    None
}

/// PNG: chunk walk to the `eXIf` chunk (bare TIFF payload).
fn png_exif(data: &[u8]) -> Option<&[u8]> {
    let mut pos = 8usize; // signature + IHDR length/type
    while pos + 8 <= data.len() {
        let size =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let fourcc = &data[pos + 4..pos + 8];
        let body = data.get(pos + 8..pos + 8 + size)?;
        if fourcc == b"eXIf" {
            return Some(body);
        }
        pos += 8 + size + 4; // + CRC
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exif_minimal() {
        let mut data = vec![b'E', b'x', b'i', b'f', 0, 0];

        // TIFF header
        data.extend_from_slice(b"II"); // Little endian
        data.extend_from_slice(&42u16.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes()); // IFD0 offset

        // IFD0 at offset 8 (relative to TIFF header at byte 6)
        data.extend_from_slice(&1u16.to_le_bytes()); // 1 entry

        // Entry: Make (0x010F) - inline value (4 bytes max)
        data.extend_from_slice(&0x010Fu16.to_le_bytes()); // Tag
        data.extend_from_slice(&2u16.to_le_bytes()); // ASCII format
        data.extend_from_slice(&4u32.to_le_bytes()); // Count (4 chars fits inline)
        data.extend_from_slice(b"Tst\0"); // Value (4 bytes inline)

        // Next IFD offset
        data.extend_from_slice(&0u32.to_le_bytes());

        let mut reader = ExifReader::new(&data);
        reader.parse_jpeg().unwrap();

        assert_eq!(reader.make(), Some("Tst".to_string()));
    }

    /// Regression: an out-of-line value in a JPEG-wrapped EXIF.
    ///
    /// `test_exif_minimal` above uses a 4-byte Make, which fits *inline*
    /// in the entry, so it took the `value_offset` branch and passed
    /// regardless. Anything longer than four bytes is stored elsewhere as
    /// an offset **relative to the TIFF header** — which is byte 6 in a
    /// JPEG. Reading that as an absolute buffer index lands 6 bytes early.
    #[test]
    fn test_exif_out_of_line_value_in_jpeg() {
        const NAME: &[u8] = b"TestMake\0"; // 9 bytes: out of line
        let mut data: Vec<u8> = b"Exif\x00\x00".to_vec();
        // Everything below is relative to the TIFF header at byte 6.
        data.extend_from_slice(b"II");
        data.extend_from_slice(&42u16.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes()); // IFD0 at relative 8
        data.extend_from_slice(&1u16.to_le_bytes()); // one entry
        data.extend_from_slice(&0x010Fu16.to_le_bytes()); // Make
        data.extend_from_slice(&2u16.to_le_bytes()); // ASCII
        data.extend_from_slice(&(NAME.len() as u32).to_le_bytes()); // count
                                                                    // value/offset field: the offset, TIFF-header relative
        data.extend_from_slice(&30u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // next IFD
        while data.len() < 6 + 30 {
            data.push(0); // pad up to the data area
        }
        data.extend_from_slice(NAME);

        let mut reader = ExifReader::new(&data);
        reader.parse_jpeg().expect("should parse");

        assert_eq!(
            reader.make(),
            Some("TestMake".to_string()),
            "out-of-line string read from the wrong offset"
        );
    }

    #[test]
    fn test_gps_parsing() {
        let mut reader = ExifReader::new(&[]);
        reader.byte_order = ByteOrder::LittleEndian;

        // Setup GPS IFD with coordinates
        let mut gps_data = vec![0u8; 100];

        // GPSLatitude (3 rationals at offset 24)
        let lat_offset = 24;
        gps_data.extend_from_slice(&(37u32.to_le_bytes())); // 37 deg
        gps_data.extend_from_slice(&(1u32.to_le_bytes()));
        gps_data.extend_from_slice(&(46u32.to_le_bytes())); // 46 min
        gps_data.extend_from_slice(&(1u32.to_le_bytes()));
        gps_data.extend_from_slice(&(30u32.to_le_bytes())); // 30 sec
        gps_data.extend_from_slice(&(1u32.to_le_bytes()));

        reader.gps_ifd.push(IfdEntry {
            tag: 0x0002,
            format: 5,
            count: 3,
            value_offset: 0,
            value: lat_offset as u32,
            ifd_type: IfdType::Gps,
        });

        reader.gps_ifd.push(IfdEntry {
            tag: 0x0001,
            format: 2,
            count: 2,
            value_offset: 0,
            value: b'N' as u32,
            ifd_type: IfdType::Gps,
        });

        reader.data = &gps_data;

        // This would need proper data setup
    }

    /// Third-party vectors: EXIF written by Pillow's standard TIFF/EXIF
    /// writer (Make/Model/DateTime, exposure, f-number, ISO, focal
    /// length, dimensions and a full GPS IFD) in four containers.
    #[test]
    fn test_exif_third_party_containers() {
        macro_rules! case {
            ($name:literal) => {{
                let data = include_bytes!(concat!("../../testdata/exif_sample.", $name));
                let r =
                    ExifReader::parse_container(data).unwrap_or_else(|e| panic!("{}: {e}", $name));
                assert_eq!(r.make().as_deref(), Some("KADANE"), "{}", $name);
                assert_eq!(r.model().as_deref(), Some("RGX-CAM"), "{}", $name);
                assert_eq!(
                    r.datetime_original().as_deref(),
                    Some("2026:09:28 12:00:00"),
                    "{}",
                    $name
                );
                assert_eq!(r.iso(), Some(400), "{}", $name);
                assert!((r.f_number().unwrap() - 2.8).abs() < 0.01, "{}", $name);
                assert!((r.focal_length().unwrap() - 25.0).abs() < 0.01, "{}", $name);
                assert!(
                    (r.exposure_time().unwrap() - 0.008).abs() < 0.0005,
                    "{}",
                    $name
                );
                let (lat, lon) = r.get_gps().unwrap_or_else(|| panic!("gps {}", $name));
                assert!((lat - 48.8582).abs() < 0.001, "lat {lat} {}", $name);
                assert!((lon - 2.2929).abs() < 0.001, "lon {lon} {}", $name);
            }};
        }
        case!("jpg");
        case!("webp");
        case!("png");
        case!("tiff");
    }

    #[test]
    fn test_find_exif_payload_rejects_non_images() {
        assert!(find_exif_payload(b"not an image at all").is_none());
        assert!(find_exif_payload(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x02]).is_none());
    }

    #[test]
    fn test_byte_order() {
        assert_eq!(ByteOrder::default(), ByteOrder::LittleEndian);
    }

    /// In a big-endian file an inline SHORT occupies the *high* two
    /// bytes of the 4-byte slot, so the value is the slot shifted down
    /// — reading the slot raw would report 400 << 16 for ISO 400.
    #[test]
    fn big_endian_inline_short_is_shifted_down() {
        let mut data = Vec::new();
        data.extend_from_slice(b"Exif\0\0");
        data.extend_from_slice(b"MM");
        data.extend_from_slice(&42u16.to_be_bytes());
        data.extend_from_slice(&8u32.to_be_bytes()); // IFD0 at relative 8
        data.extend_from_slice(&1u16.to_be_bytes()); // one entry
        data.extend_from_slice(&0x0112u16.to_be_bytes()); // Orientation
        data.extend_from_slice(&3u16.to_be_bytes()); // SHORT
        data.extend_from_slice(&1u32.to_be_bytes()); // count 1
        data.extend_from_slice(&6u16.to_be_bytes()); // value 6, high half
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&0u32.to_be_bytes()); // next IFD

        let mut reader = ExifReader::new(&data);
        reader.parse_jpeg().expect("should parse");
        assert_eq!(reader.orientation(), Some(6));
    }

    /// The next-IFD chain of IFD0 leads to IFD1 (the thumbnail IFD);
    /// a zero next-IFD ends the chain and IFD1 stays empty.
    #[test]
    fn ifd1_comes_from_the_next_ifd_chain() {
        let mut data = Vec::new();
        data.extend_from_slice(b"Exif\0\0");
        data.extend_from_slice(b"II");
        data.extend_from_slice(&42u16.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes()); // IFD0 at 8
        data.extend_from_slice(&1u16.to_le_bytes()); // IFD0: one entry
        data.extend_from_slice(&0x0100u16.to_le_bytes()); // ImageWidth
        data.extend_from_slice(&4u16.to_le_bytes()); // LONG
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&640u32.to_le_bytes());
        // next IFD: relative 30 (after this 2+12+4 block + 6 for tiff_start)
        data.extend_from_slice(&30u32.to_le_bytes());
        while data.len() < 6 + 30 {
            data.push(0);
        }
        data.extend_from_slice(&1u16.to_le_bytes()); // IFD1: one entry
        data.extend_from_slice(&0x0101u16.to_le_bytes()); // ImageHeight
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&480u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // end of chain

        let mut reader = ExifReader::new(&data);
        reader.parse_jpeg().expect("should parse");
        assert_eq!(reader.ifd1.len(), 1);
        assert_eq!(reader.ifd1[0].tag, 0x0101);
        assert_eq!(reader.ifd1[0].value, 480);

        // A zero next-IFD leaves IFD1 empty.
        let mut data = data.clone();
        // overwrite IFD0's next-IFD (at 6 + 8 + 2 + 12 = 28) with 0
        data[28..32].copy_from_slice(&0u32.to_le_bytes());
        let mut reader = ExifReader::new(&data);
        reader.parse_jpeg().expect("should parse");
        assert!(reader.ifd1.is_empty());
    }

    /// The Interop IFD pointer (0xA005) lives in the Exif IFD, not in
    /// IFD0; a pointer in IFD0 must not be mistaken for it.
    #[test]
    fn interop_ifd_is_read_through_the_exif_ifd() {
        let mut data = Vec::new();
        data.extend_from_slice(b"Exif\0\0");
        data.extend_from_slice(b"II");
        data.extend_from_slice(&42u16.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes()); // IFD0 offset
                                                     // IFD0 at 8 with two entries: ExifIFD pointer and an Interop
                                                     // pointer in the wrong place (which must be ignored).
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0x8769u16.to_le_bytes()); // ExifIFD pointer
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&40u32.to_le_bytes()); // -> ExifIFD at rel 40
        data.extend_from_slice(&0xA005u16.to_le_bytes()); // Interop pointer in IFD0
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // points nowhere
        data.extend_from_slice(&0u32.to_le_bytes()); // next IFD
        while data.len() < 6 + 40 {
            data.push(0);
        }
        // ExifIFD at relative 40: one entry, the real Interop pointer.
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0xA005u16.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&80u32.to_le_bytes()); // -> Interop at rel 80
        data.extend_from_slice(&0u32.to_le_bytes());
        while data.len() < 6 + 80 {
            data.push(0);
        }
        // Interop IFD at relative 80: one entry.
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0x0001u16.to_le_bytes()); // InteropIndex
        data.extend_from_slice(&2u16.to_le_bytes()); // ASCII
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(b"R98\0");
        data.extend_from_slice(&0u32.to_le_bytes());

        let mut reader = ExifReader::new(&data);
        reader.parse_jpeg().expect("should parse");
        assert_eq!(reader.interop_ifd.len(), 1);
        assert_eq!(reader.interop_ifd[0].tag, 0x0001);
    }
}
