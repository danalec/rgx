// SPDX-License-Identifier: Apache-2.0

//! TIFF structure readers (TIFF 6.0 / EXIF 2.31 §4.5 data types).
//!
//! Independent reimplementation of the byte-order-aware scalar readers
//! the IFD walk needs: every TIFF field is stored in the file's byte
//! order (`II` little-endian, `MM` big-endian, declared once in the
//! header), and the value readers take that order explicitly rather
//! than holding state. The type table of §4.5 is the whole vocabulary:
//! BYTE/ASCII/SBYTE/UNDEFINED (1 byte), SHORT/SSHORT (2), LONG/SLONG/
//! FLOAT/IFD (4), RATIONAL/SRATIONAL/DOUBLE (8).
//!
//! # Contract
//!
//! Every reader is bounds-checked against the slice and returns
//! `Err` on a short buffer — a truncated image must not panic the
//! walk that feeds these. `read_string` is the one that does not
//! fail: an ASCII field is cut at the first NUL, and a field that
//! runs off the end of the buffer yields the part that is there (or
//! empty), because a metadata walk over a damaged file still has
//! whatever tags preceded the damage to report.

use super::ByteOrder;
use alloc::string::String;
use alloc::vec::Vec;

/// TIFF header (§4.5.2): byte-order marker, magic 42, offset of IFD0.
#[derive(Debug, Clone)]
pub struct TiffHeader {
    /// Byte order marker.
    pub byte_order: ByteOrder,
    /// Magic number (42).
    pub magic: u16,
    /// Offset to first IFD.
    pub ifd0_offset: u32,
}

impl Default for TiffHeader {
    fn default() -> Self {
        Self {
            byte_order: ByteOrder::LittleEndian,
            magic: 42,
            ifd0_offset: 8,
        }
    }
}

/// Parse the 8-byte TIFF header.
pub fn parse_header(data: &[u8]) -> Result<TiffHeader, String> {
    if data.len() < 8 {
        return Err("Data too short for TIFF header".into());
    }

    let byte_order = if &data[0..2] == b"II" {
        ByteOrder::LittleEndian
    } else if &data[0..2] == b"MM" {
        ByteOrder::BigEndian
    } else {
        return Err("Invalid TIFF byte order".into());
    };

    let magic = read_u16(data, 2, byte_order)?;
    if magic != 42 {
        return Err("Invalid TIFF magic number".into());
    }

    let ifd0_offset = read_u32(data, 4, byte_order)?;

    Ok(TiffHeader {
        byte_order,
        magic,
        ifd0_offset,
    })
}

/// Read a SHORT (type 3) / SSHORT-sized unsigned value.
pub fn read_u16(data: &[u8], offset: usize, byte_order: ByteOrder) -> Result<u16, String> {
    let s = data
        .get(offset..offset + 2)
        .ok_or("Unexpected end of data")?;
    Ok(match byte_order {
        ByteOrder::LittleEndian => u16::from_le_bytes([s[0], s[1]]),
        ByteOrder::BigEndian => u16::from_be_bytes([s[0], s[1]]),
    })
}

/// Read a LONG (type 4) / IFD (type 13) unsigned value.
pub fn read_u32(data: &[u8], offset: usize, byte_order: ByteOrder) -> Result<u32, String> {
    let s = data
        .get(offset..offset + 4)
        .ok_or("Unexpected end of data")?;
    Ok(match byte_order {
        ByteOrder::LittleEndian => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        ByteOrder::BigEndian => u32::from_be_bytes([s[0], s[1], s[2], s[3]]),
    })
}

/// Read a signed SHORT (type 8).
pub fn read_i16(data: &[u8], offset: usize, byte_order: ByteOrder) -> Result<i16, String> {
    let s = data
        .get(offset..offset + 2)
        .ok_or("Unexpected end of data")?;
    Ok(match byte_order {
        ByteOrder::LittleEndian => i16::from_le_bytes([s[0], s[1]]),
        ByteOrder::BigEndian => i16::from_be_bytes([s[0], s[1]]),
    })
}

/// Read a signed LONG (type 9).
pub fn read_i32(data: &[u8], offset: usize, byte_order: ByteOrder) -> Result<i32, String> {
    let s = data
        .get(offset..offset + 4)
        .ok_or("Unexpected end of data")?;
    Ok(match byte_order {
        ByteOrder::LittleEndian => i32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        ByteOrder::BigEndian => i32::from_be_bytes([s[0], s[1], s[2], s[3]]),
    })
}

/// Read a RATIONAL (type 5): two unsigned LONGs, numerator over
/// denominator.
pub fn read_rational(
    data: &[u8],
    offset: usize,
    byte_order: ByteOrder,
) -> Result<(u32, u32), String> {
    let numerator = read_u32(data, offset, byte_order)?;
    let denominator = read_u32(data, offset + 4, byte_order)?;
    Ok((numerator, denominator))
}

/// Read an SRATIONAL (type 10): two signed LONGs.
pub fn read_srational(
    data: &[u8],
    offset: usize,
    byte_order: ByteOrder,
) -> Result<(i32, i32), String> {
    let numerator = read_i32(data, offset, byte_order)?;
    let denominator = read_i32(data, offset + 4, byte_order)?;
    Ok((numerator, denominator))
}

/// Read a FLOAT (type 11).
pub fn read_f32(data: &[u8], offset: usize, byte_order: ByteOrder) -> Result<f32, String> {
    let s = data
        .get(offset..offset + 4)
        .ok_or("Unexpected end of data")?;
    let bytes = [s[0], s[1], s[2], s[3]];
    Ok(match byte_order {
        ByteOrder::LittleEndian => f32::from_le_bytes(bytes),
        ByteOrder::BigEndian => f32::from_be_bytes(bytes),
    })
}

/// Read a DOUBLE (type 12).
pub fn read_f64(data: &[u8], offset: usize, byte_order: ByteOrder) -> Result<f64, String> {
    let s = data
        .get(offset..offset + 8)
        .ok_or("Unexpected end of data")?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(s);
    Ok(match byte_order {
        ByteOrder::LittleEndian => f64::from_le_bytes(bytes),
        ByteOrder::BigEndian => f64::from_be_bytes(bytes),
    })
}

/// Read an ASCII (type 2) field: up to `length` bytes, cut at the
/// first NUL. Never fails — see the module contract. A field that
/// runs off the end of the buffer yields the part that is there.
#[must_use]
pub fn read_string(data: &[u8], offset: usize, length: usize) -> String {
    let Some(rest) = data.get(offset..) else {
        return String::new();
    };
    let bytes = &rest[..length.min(rest.len())];
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Read `count` SHORTs.
pub fn read_u16_array(
    data: &[u8],
    offset: usize,
    count: usize,
    byte_order: ByteOrder,
) -> Result<Vec<u16>, String> {
    let mut values = Vec::with_capacity(count);
    for i in 0..count {
        values.push(read_u16(data, offset + i * 2, byte_order)?);
    }
    Ok(values)
}

/// Read `count` LONGs.
pub fn read_u32_array(
    data: &[u8],
    offset: usize,
    count: usize,
    byte_order: ByteOrder,
) -> Result<Vec<u32>, String> {
    let mut values = Vec::with_capacity(count);
    for i in 0..count {
        values.push(read_u32(data, offset + i * 4, byte_order)?);
    }
    Ok(values)
}

/// Read `count` RATIONALs.
pub fn read_rational_array(
    data: &[u8],
    offset: usize,
    count: usize,
    byte_order: ByteOrder,
) -> Result<Vec<(u32, u32)>, String> {
    let mut values = Vec::with_capacity(count);
    for i in 0..count {
        values.push(read_rational(data, offset + i * 8, byte_order)?);
    }
    Ok(values)
}

/// APEX aperture to f-number: Av = 2 * log2(N), so N = 2^(Av/2).
#[must_use]
pub fn apex_to_f_number(apex_value: f64) -> f64 {
    2.0f64.powf(apex_value / 2.0)
}

/// APEX shutter to exposure time: Tv = -log2(t), so t = 2^(-Tv).
#[must_use]
pub fn apex_to_exposure_time(apex_value: f64) -> f64 {
    2.0f64.powf(-apex_value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u16_le() {
        let data = [0x01, 0x00];
        let val = read_u16(&data, 0, ByteOrder::LittleEndian).unwrap();
        assert_eq!(val, 1);
    }

    #[test]
    fn test_read_u16_be() {
        let data = [0x00, 0x01];
        let val = read_u16(&data, 0, ByteOrder::BigEndian).unwrap();
        assert_eq!(val, 1);
    }

    #[test]
    fn test_read_rational() {
        let data = [0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
        let (num, denom) = read_rational(&data, 0, ByteOrder::LittleEndian).unwrap();
        assert_eq!(num, 1);
        assert_eq!(denom, 2);
    }

    #[test]
    fn test_apex_conversion() {
        let f = apex_to_f_number(8.0);
        assert!((f - 16.0).abs() < 0.01);

        let t = apex_to_exposure_time(6.0);
        assert!((t - 1.0 / 64.0).abs() < 0.0001);
    }

    /// The header is 8 bytes and self-describing: `II`/`MM` picks the
    /// order the magic and the IFD0 offset are then read in. Both
    /// orders must give the same header values for the same numbers.
    #[test]
    fn parse_header_takes_the_byte_order_from_the_marker() {
        let mut le = Vec::new();
        le.extend_from_slice(b"II");
        le.extend_from_slice(&42u16.to_le_bytes());
        le.extend_from_slice(&8u32.to_le_bytes());
        let h = parse_header(&le).unwrap();
        assert_eq!(h.byte_order, ByteOrder::LittleEndian);
        assert_eq!(h.magic, 42);
        assert_eq!(h.ifd0_offset, 8);

        let mut be = Vec::new();
        be.extend_from_slice(b"MM");
        be.extend_from_slice(&42u16.to_be_bytes());
        be.extend_from_slice(&8u32.to_be_bytes());
        let h = parse_header(&be).unwrap();
        assert_eq!(h.byte_order, ByteOrder::BigEndian);
        assert_eq!(h.magic, 42);
        assert_eq!(h.ifd0_offset, 8);
    }

    /// Magic 42 is the TIFF identifier (§4.5.2); anything else is not
    /// a TIFF header. A short buffer is an error, not a panic.
    #[test]
    fn parse_header_rejects_bad_magic_and_short_buffers() {
        let mut bad = Vec::new();
        bad.extend_from_slice(b"II");
        bad.extend_from_slice(&43u16.to_le_bytes());
        bad.extend_from_slice(&8u32.to_le_bytes());
        assert!(parse_header(&bad).is_err());

        assert!(parse_header(b"II*\x00").is_err());
        assert!(parse_header(b"XX\x2a\x00\x08\x00\x00\x00").is_err());
    }

    /// SRATIONAL is two signed LONGs; the sign lives in each half
    /// independently (a negative exposure bias is a negative numerator
    /// over a positive denominator).
    #[test]
    fn read_srational_keeps_the_sign_of_each_half() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-3i32).to_le_bytes());
        data.extend_from_slice(&2i32.to_le_bytes());
        let (num, den) = read_srational(&data, 0, ByteOrder::LittleEndian).unwrap();
        assert_eq!((num, den), (-3, 2));
    }

    /// A short buffer is an error from the scalar readers and empty
    /// output from `read_string` — neither panics on a truncated file.
    #[test]
    fn short_buffers_error_rather_than_panic() {
        assert!(read_u16(&[0], 0, ByteOrder::LittleEndian).is_err());
        assert!(read_u32(&[0; 3], 0, ByteOrder::LittleEndian).is_err());
        assert!(read_rational(&[0; 7], 0, ByteOrder::LittleEndian).is_err());
        assert_eq!(read_string(b"a", 0, 10), "a");
        assert_eq!(read_string(b"a", 5, 1), "");
    }
}
