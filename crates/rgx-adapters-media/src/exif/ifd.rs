// SPDX-License-Identifier: Apache-2.0

//! IFD (Image File Directory) entry interpretation (TIFF 6.0 / EXIF
//! 2.31 §4.5).
//!
//! Independent reimplementation of the value half of an IFD entry: the
//! 12-byte entry carries tag, type, count and a 4-byte value slot, and
//! whether that slot holds the value or an offset is decided by
//! `type_size x count` — four bytes or fewer are inline, anything
//! larger is stored elsewhere and the slot holds the offset to it.
//!
//! # Contract
//!
//! `format_size` is the §4.5 type table exactly; an unknown type has
//! no size and must not be treated as one of the known ones. The
//! `IfdValue` conversions never fabricate: a zero denominator is not a
//! number, and only the types that are already numeric convert to
//! `f64`/`u32`. The orientation mapping is the EXIF 2.31 §4.6.4
//! table: values 2-4 flip, 5-8 also rotate, and anything outside 1-8
//! is the identity.

use super::tags::IfdEntry;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Size in bytes of one value of a TIFF type (§4.5, types 1-13).
#[must_use]
pub fn format_size(format: u16) -> usize {
    match format {
        1 => 1,  // BYTE
        2 => 1,  // ASCII
        3 => 2,  // SHORT
        4 => 4,  // LONG
        5 => 8,  // RATIONAL
        6 => 1,  // SBYTE
        7 => 1,  // UNDEFINED
        8 => 2,  // SSHORT
        9 => 4,  // SLONG
        10 => 8, // SRATIONAL
        11 => 4, // FLOAT
        12 => 8, // DOUBLE
        13 => 4, // IFD
        _ => 0,
    }
}

/// True when the entry's value fits in the 4-byte value slot.
#[must_use]
pub fn is_inline(entry: &IfdEntry) -> bool {
    let size = format_size(entry.format) * entry.count as usize;
    size <= 4
}

/// Absolute position of an entry's value bytes.
///
/// Inline values are already at `entry.value_offset` (the walk recorded
/// the absolute buffer index of the value slot); out-of-line values hold
/// a TIFF-header-relative offset in the slot, which `base_offset`
/// (the TIFF header position) turns into an absolute one.
#[must_use]
pub fn value_offset(entry: &IfdEntry, base_offset: usize) -> usize {
    if is_inline(entry) {
        entry.value_offset
    } else {
        base_offset + entry.value as usize
    }
}

/// Name of a TIFF type.
#[must_use]
pub fn format_name(format: u16) -> &'static str {
    match format {
        1 => "BYTE",
        2 => "ASCII",
        3 => "SHORT",
        4 => "LONG",
        5 => "RATIONAL",
        6 => "SBYTE",
        7 => "UNDEFINED",
        8 => "SSHORT",
        9 => "SLONG",
        10 => "SRATIONAL",
        11 => "FLOAT",
        12 => "DOUBLE",
        13 => "IFD",
        _ => "Unknown",
    }
}

/// One IFD value, typed per §4.5.
#[derive(Debug, Clone)]
pub enum IfdValue {
    Byte(u8),
    Short(u16),
    Long(u32),
    Rational { numerator: u32, denominator: u32 },
    SByte(i8),
    SShort(i16),
    SLong(i32),
    SRational { numerator: i32, denominator: i32 },
    Float(f32),
    Double(f64),
    String(String),
    Bytes(Vec<u8>),
    Shorts(Vec<u16>),
    Longs(Vec<u32>),
    Rationals(Vec<(u32, u32)>),
    Unknown,
}

impl IfdValue {
    /// Text form for a listing. A rational with a zero denominator is
    /// shown as `0/0` rather than evaluated — the field is present but
    /// has no numeric value.
    #[must_use]
    pub fn to_display_string(&self) -> String {
        match self {
            Self::Byte(v) => v.to_string(),
            Self::Short(v) => v.to_string(),
            Self::Long(v) => v.to_string(),
            Self::Rational {
                numerator,
                denominator,
            } => {
                if *denominator == 0 {
                    String::from("0/0")
                } else {
                    let val = *numerator as f64 / *denominator as f64;
                    format!("{:.4}", val)
                }
            }
            Self::SByte(v) => v.to_string(),
            Self::SShort(v) => v.to_string(),
            Self::SLong(v) => v.to_string(),
            Self::SRational {
                numerator,
                denominator,
            } => {
                if *denominator == 0 {
                    String::from("0/0")
                } else {
                    let val = *numerator as f64 / *denominator as f64;
                    format!("{:.4}", val)
                }
            }
            Self::Float(v) => format!("{:.6}", v),
            Self::Double(v) => format!("{:.12}", v),
            Self::String(s) => s.clone(),
            Self::Bytes(b) => format!("[{} bytes]", b.len()),
            Self::Shorts(s) => format!("[{} shorts]", s.len()),
            Self::Longs(l) => format!("[{} longs]", l.len()),
            Self::Rationals(r) => format!("[{} rationals]", r.len()),
            Self::Unknown => String::from("?"),
        }
    }

    /// Numeric view; `None` for the non-numeric types and for a
    /// rational whose denominator is zero.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Byte(v) => Some(*v as f64),
            Self::Short(v) => Some(*v as f64),
            Self::Long(v) => Some(*v as f64),
            Self::Rational {
                numerator,
                denominator,
            } => {
                if *denominator == 0 {
                    None
                } else {
                    Some(*numerator as f64 / *denominator as f64)
                }
            }
            Self::SByte(v) => Some(*v as f64),
            Self::SShort(v) => Some(*v as f64),
            Self::SLong(v) => Some(*v as f64),
            Self::SRational {
                numerator,
                denominator,
            } => {
                if *denominator == 0 {
                    None
                } else {
                    Some(*numerator as f64 / *denominator as f64)
                }
            }
            Self::Float(v) => Some(*v as f64),
            Self::Double(v) => Some(*v),
            _ => None,
        }
    }

    /// Unsigned integer view of the 1-byte/2-byte/4-byte unsigned
    /// types only.
    #[must_use]
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Self::Byte(v) => Some(*v as u32),
            Self::Short(v) => Some(*v as u32),
            Self::Long(v) => Some(*v),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

/// The transform an EXIF orientation value asks for.
#[derive(Debug, Clone, Copy, Default)]
pub struct OrientationTransform {
    /// Flip horizontally.
    pub flip_h: bool,
    /// Flip vertically.
    pub flip_v: bool,
    /// Rotate degrees (0, 90, 180, 270).
    pub rotate: u16,
}

/// EXIF 2.31 §4.6.4 orientation: 1 = top-left (identity), 2-4 mirror
/// or flip in place, 5-8 the same with a 90/270 rotation.
#[must_use]
pub fn orientation_transform(orientation: u16) -> OrientationTransform {
    match orientation {
        1 => OrientationTransform::default(),
        2 => OrientationTransform {
            flip_h: true,
            flip_v: false,
            rotate: 0,
        },
        3 => OrientationTransform {
            flip_h: false,
            flip_v: true,
            rotate: 180,
        },
        4 => OrientationTransform {
            flip_h: true,
            flip_v: true,
            rotate: 0,
        },
        5 => OrientationTransform {
            flip_h: false,
            flip_v: false,
            rotate: 90,
        },
        6 => OrientationTransform {
            flip_h: false,
            flip_v: true,
            rotate: 90,
        },
        7 => OrientationTransform {
            flip_h: true,
            flip_v: false,
            rotate: 270,
        },
        8 => OrientationTransform {
            flip_h: false,
            flip_v: false,
            rotate: 270,
        },
        _ => OrientationTransform::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(1), 1);
        assert_eq!(format_size(3), 2);
        assert_eq!(format_size(4), 4);
        assert_eq!(format_size(5), 8);
        assert_eq!(format_size(12), 8);
    }

    #[test]
    fn test_orientation_transform() {
        let t = orientation_transform(1);
        assert!(!t.flip_h && !t.flip_v && t.rotate == 0);

        let t = orientation_transform(6);
        assert!(!t.flip_h && t.flip_v && t.rotate == 90);

        let t = orientation_transform(3);
        assert!(!t.flip_h && t.flip_v && t.rotate == 180);
    }

    /// The §4.5 type table is complete (types 1-13) and an unknown
    /// type has size 0 — treating it as any other size would put the
    /// walk's inline/offset decision on the wrong side.
    #[test]
    fn every_tiff_type_has_its_spec_size() {
        assert_eq!(format_size(1), 1); // BYTE
        assert_eq!(format_size(2), 1); // ASCII
        assert_eq!(format_size(3), 2); // SHORT
        assert_eq!(format_size(4), 4); // LONG
        assert_eq!(format_size(5), 8); // RATIONAL
        assert_eq!(format_size(6), 1); // SBYTE
        assert_eq!(format_size(7), 1); // UNDEFINED
        assert_eq!(format_size(8), 2); // SSHORT
        assert_eq!(format_size(9), 4); // SLONG
        assert_eq!(format_size(10), 8); // SRATIONAL
        assert_eq!(format_size(11), 4); // FLOAT
        assert_eq!(format_size(12), 8); // DOUBLE
        assert_eq!(format_size(13), 4); // IFD
        assert_eq!(format_size(0), 0);
        assert_eq!(format_size(14), 0);
    }

    /// Inline is exactly `type_size x count <= 4`: a 4-byte LONG is
    /// inline, two SHORTs (4 bytes) are inline, three are not, and an
    /// unknown type (size 0) must not claim a 0-byte inline value.
    #[test]
    fn inline_boundary_is_four_bytes() {
        let entry = |format: u16, count: u32| IfdEntry {
            tag: 0,
            format,
            count,
            value_offset: 100,
            value: 42,
            ifd_type: crate::exif::IfdType::Ifd0,
        };
        assert!(is_inline(&entry(4, 1))); // LONG x1 = 4
        assert!(is_inline(&entry(3, 2))); // SHORT x2 = 4
        assert!(!is_inline(&entry(3, 3))); // SHORT x3 = 6
        assert!(!is_inline(&entry(5, 1))); // RATIONAL x1 = 8
    }

    /// A rational with a zero denominator has no numeric value: it
    /// must not divide, and its display form says so.
    #[test]
    fn a_zero_denominator_is_not_a_number() {
        let r = IfdValue::Rational {
            numerator: 1,
            denominator: 0,
        };
        assert_eq!(r.as_f64(), None);
        assert_eq!(r.to_display_string(), "0/0");
        let sr = IfdValue::SRational {
            numerator: -1,
            denominator: 0,
        };
        assert_eq!(sr.as_f64(), None);
        assert_eq!(sr.to_display_string(), "0/0");
    }
}
