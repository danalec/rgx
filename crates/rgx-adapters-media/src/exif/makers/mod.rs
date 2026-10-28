// SPDX-License-Identifier: Apache-2.0

//! MakerNote support for manufacturer-specific EXIF data.
//!
//! Carries tag tables and parses the MakerNote IFD of the camera makers whose
//! MakerNote is a plain TIFF directory:
//! - Canon
//! - Nikon (type 1 only)
//! - Sony
//! - Olympus
//! - FujiFilm
//! - Panasonic
//! - Pentax
//! - Samsung
//!
//! MakerNote data is stored in the EXIF IFD at tag 0x927C.
//! Each manufacturer uses a different format and tag system.
//!
//! # Unsupported makers
//!
//! Several vendors do not put a plain IFD in the block at all:
//!
//! - **Nikon type 2 and type 3** (type 3 is what current bodies emit) encrypt
//!   the payload with a serial-derived key.
//! - **Sigma** encrypts with a fixed key.
//! - **Leica** and **Ricoh** in some models nest the real IFD behind their own
//!   encrypted header.
//! - **Apple** writes no IFD at all.
//!
//! [`parse_makernote`] returns an empty list for these rather than handing back
//! bytes it could not decode. [`makernote_tag_name`] still answers for any
//! maker listed below, because the tag tables do not depend on the payload.

use super::tiff_format;
use super::{
    format_size, read_rational_array, read_string, read_u16, read_u16_array, read_u32,
    read_u32_array, ByteOrder,
};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// MakerNote manufacturer identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Maker {
    Canon,
    Nikon,
    Sony,
    Olympus,
    FujiFilm,
    Panasonic,
    Pentax,
    Ricoh,
    Samsung,
    Leica,
    Sigma,
    Apple,
    Unknown,
}

impl Maker {
    /// Detect manufacturer from Make string.
    #[must_use]
    pub fn from_make(make: &str) -> Self {
        let make_upper = make.to_uppercase();
        if make_upper.contains("CANON") {
            Self::Canon
        } else if make_upper.contains("NIKON") {
            Self::Nikon
        } else if make_upper.contains("SONY") {
            Self::Sony
        } else if make_upper.contains("OLYMPUS") {
            Self::Olympus
        } else if make_upper.contains("FUJI") || make_upper.contains("FUJIFILM") {
            Self::FujiFilm
        } else if make_upper.contains("PANASONIC") {
            Self::Panasonic
        } else if make_upper.contains("PENTAX") {
            Self::Pentax
        } else if make_upper.contains("RICOH") {
            Self::Ricoh
        } else if make_upper.contains("SAMSUNG") {
            Self::Samsung
        } else if make_upper.contains("LEICA") {
            Self::Leica
        } else if make_upper.contains("SIGMA") {
            Self::Sigma
        } else if make_upper.contains("APPLE") {
            Self::Apple
        } else {
            Self::Unknown
        }
    }
}

/// MakerNote entry.
#[derive(Debug, Clone)]
pub struct MakerNoteEntry {
    /// Tag ID (manufacturer-specific).
    pub tag: u16,
    /// Tag name (if known).
    pub name: Option<String>,
    /// Value interpretation.
    pub value: String,
}

/// Canon MakerNote tag definitions.
pub mod canon {
    pub const CAMERA_SETTINGS: u16 = 0x0001;
    pub const FOCAL_LENGTH: u16 = 0x0002;
    pub const SHOT_INFO: u16 = 0x0004;
    pub const PANORAMA: u16 = 0x0005;
    pub const IMAGE_TYPE: u16 = 0x0006;
    pub const FIRMWARE_VERSION: u16 = 0x0007;
    pub const FILE_NUMBER: u16 = 0x0008;
    pub const OWNER_NAME: u16 = 0x0009;
    pub const SERIAL_NUMBER: u16 = 0x000C;
    pub const CAMERA_INFO: u16 = 0x000D;
    pub const CUSTOM_FUNCTIONS: u16 = 0x000F;
    pub const MODEL_ID: u16 = 0x0010;
    pub const THUMBNAIL_IMAGE_VALID_AREA: u16 = 0x0013;
    pub const SERIAL_NUMBER_FORMAT: u16 = 0x0015;
    pub const SUPER_MACRO: u16 = 0x001A;
    pub const DATE_STAMP_MODE: u16 = 0x001C;
    pub const MY_COLORS: u16 = 0x001D;
    pub const FIRMWARE_REVISION: u16 = 0x001E;
    pub const CATEGORIES: u16 = 0x0023;
    pub const FACE_DETECT: u16 = 0x0024;
    pub const WB_RGB_COEFFS: u16 = 0x0026;
    pub const COLOR_DATA: u16 = 0x0029;
    pub const AF_INFO: u16 = 0x002E;
    pub const CONTRAST_INFO: u16 = 0x0031;
    pub const WB_INFO: u16 = 0x0032;
    pub const ORIENTATION: u16 = 0x0038;
    pub const AF_MICRO_ADJ: u16 = 0x0041;
}

/// Nikon MakerNote tag definitions.
pub mod nikon {
    pub const FIRMWARE_VERSION: u16 = 0x0001;
    pub const ISO: u16 = 0x0002;
    pub const QUALITY: u16 = 0x0003;
    pub const WHITE_BALANCE: u16 = 0x0004;
    pub const SHARPENING: u16 = 0x0005;
    pub const FOCUS_MODE: u16 = 0x0006;
    pub const FLASH_SETTING: u16 = 0x0007;
    pub const FLASH_MODE: u16 = 0x0008;
    pub const WHITE_BALANCE_FINE: u16 = 0x0009;
    pub const WHITE_BALANCE_RB_COEFF: u16 = 0x000A;
    pub const ISO_SELECTION: u16 = 0x000B;
    pub const ISO_2: u16 = 0x000C;
    pub const PIC_CONTROL_DATA: u16 = 0x000D;
    pub const COLOR_MODE: u16 = 0x000E;
    pub const QUALITY_AND_FORMAT: u16 = 0x000F;
    pub const IMAGE_ADJUSTMENT: u16 = 0x0010;
    pub const CCD_SENSITIVITY: u16 = 0x0011;
    pub const WHITE_BALANCE_TONE: u16 = 0x0012;
    pub const LENS_TYPE: u16 = 0x0013;
    pub const LENS_INFO: u16 = 0x0014;
    pub const FOCUS_DISTANCE: u16 = 0x0015;
    pub const DIGITAL_ZOOM: u16 = 0x0016;
    pub const AF_AREA_MODE: u16 = 0x0017;
    pub const AF_POINT: u16 = 0x0018;
    pub const SENSOR_PIXEL_SIZE: u16 = 0x001A;
    pub const SERIAL_NUMBER: u16 = 0x001D;
    pub const COLOR_SPACE: u16 = 0x001E;
    pub const FLASH_INFO: u16 = 0x001F;
    pub const AF_FOCUS_POSITION: u16 = 0x0020;
    pub const VENDOR_NAME: u16 = 0x0023;
    pub const SHOT_INFO: u16 = 0x0025;
    pub const NEF_COMPRESSION: u16 = 0x0034;
    pub const SERIAL_NUMBER_2: u16 = 0x0035;
    pub const EXPOSURE_TUNE: u16 = 0x0037;
    pub const AF_FOCUS: u16 = 0x0038;
    pub const LENS_DATA: u16 = 0x003C;
    pub const RETOUCH_HISTORY: u16 = 0x003E;
    pub const CAMERA_SERIAL_2: u16 = 0x0040;
    pub const AF_INFO_2: u16 = 0x0043;
    pub const AF_FINE_TUNE: u16 = 0x0049;
    pub const AF_TUNE_ADJ: u16 = 0x004A;
    pub const VIRTUALIZATION: u16 = 0x004C;
    pub const MULTI_EXPOSURE: u16 = 0x004D;
    pub const HDR_INFO: u16 = 0x004F;
    pub const AF_CONFIG: u16 = 0x0052;
}

/// Sony MakerNote tag definitions.
pub mod sony {
    pub const AUTO_FOCUS: u16 = 0x0002;
    pub const AF_DISTANCE_SETTING: u16 = 0x0003;
    pub const MULTI_BURST_MODE: u16 = 0x0004;
    pub const MULTI_BURST_IMAGE_SIZE: u16 = 0x0005;
    pub const PANORAMA_DIRECTION: u16 = 0x0006;
    pub const PANORAMA_FIELD_OF_VIEW: u16 = 0x0007;
    pub const PRE_CAPTURE_FRAMES: u16 = 0x0008;
    pub const COLOR_MODE: u16 = 0x000B;
    pub const QUALITY: u16 = 0x000C;
    pub const QUALITY_2: u16 = 0x000D;
    pub const FLASH_LEVEL: u16 = 0x000E;
    pub const RELEASE_MODE: u16 = 0x0010;
    pub const SEQUENCE_NUMBER: u16 = 0x0011;
    pub const CREATIVE_STYLE: u16 = 0x0012;
    pub const CONTRAST: u16 = 0x0013;
    pub const SATURATION: u16 = 0x0014;
    pub const SHARPNESS: u16 = 0x0015;
    pub const FLASH: u16 = 0x0016;
    pub const FLASH_EXPOSURE_COMP_SET: u16 = 0x0017;
    pub const EXPOSURE_PROGRAM: u16 = 0x0018;
    pub const WHITE_BALANCE_FINE: u16 = 0x001A;
    pub const WHITE_BALANCE: u16 = 0x001B;
    pub const ISO_SETTING: u16 = 0x001C;
    pub const ISO_INFO: u16 = 0x001D;
    pub const MACRO: u16 = 0x0020;
    pub const EXPOSURE_MODE: u16 = 0x0021;
    pub const FOCUS_MODE: u16 = 0x0022;
    pub const AF_MODE: u16 = 0x0023;
    pub const AF_POINT: u16 = 0x0024;
    pub const SCENE_MODE: u16 = 0x0025;
    pub const ZONE_MATCHING: u16 = 0x0026;
    pub const DYNAMIC_RANGE_OPTIMIZER: u16 = 0x0027;
    pub const COLOR_TEMPERATURE: u16 = 0x0028;
    pub const LENS_ID: u16 = 0x002A;
    pub const ZOOM_STEP_COUNT: u16 = 0x002B;
    pub const FOCUS_STEP_COUNT: u16 = 0x002C;
    pub const AF_POINT_SELECTED: u16 = 0x002E;
    pub const AF_POINTS_USED: u16 = 0x002F;
    pub const SENSOR_UNIT: u16 = 0x0030;
    pub const HDR: u16 = 0x0031;
    pub const FRAME_NUMBER: u16 = 0x0032;
    pub const CAMERA_INFO: u16 = 0x0033;
    pub const SERIAL_NUMBER: u16 = 0x0034;
    pub const MODEL_YEAR: u16 = 0x0035;
    pub const INTERNAL_SERIAL_NUMBER: u16 = 0x0036;
}

/// FujiFilm MakerNote tag definitions.
pub mod fuji {
    pub const VERSION: u16 = 0x0000;
    pub const SERIAL_NUMBER: u16 = 0x0010;
    pub const QUALITY: u16 = 0x1000;
    pub const SHARPNESS: u16 = 0x1001;
    pub const WHITE_BALANCE: u16 = 0x1002;
    pub const COLOR: u16 = 0x1003;
    pub const TONE: u16 = 0x1004;
    pub const FLASH_MODE: u16 = 0x1010;
    pub const FLASH_STRENGTH: u16 = 0x1011;
    pub const MACRO: u16 = 0x1020;
    pub const FOCUS_MODE: u16 = 0x1021;
    pub const AUTO_FOCUSING: u16 = 0x1022;
    pub const AF_POINT: u16 = 0x1023;
    pub const EXPOSURE_PROGRAM: u16 = 0x1030;
    pub const EXPOSURE_MODE: u16 = 0x1031;
    pub const EXPOSURE_COMPENSATION: u16 = 0x1032;
    pub const SHUTTER_SPEED: u16 = 0x1033;
    pub const APERTURE: u16 = 0x1034;
    pub const SENSITIVITY: u16 = 0x1035;
    pub const BRIGHTNESS_VALUE: u16 = 0x1036;
    pub const FOCAL_LENGTH: u16 = 0x1037;
    pub const FLASH: u16 = 0x1040;
    pub const SELF_TIMER: u16 = 0x1041;
    pub const CONTINUOUS: u16 = 0x1100;
    pub const PANORAMA_MODE: u16 = 0x1101;
    pub const IMAGE_SIZE: u16 = 0x1102;
    pub const ISO: u16 = 0x1200;
    pub const FINEPIX_COLOR: u16 = 0x1210;
    pub const DYNAMIC_RANGE: u16 = 0x1400;
    pub const FILM_MODE: u16 = 0x1401;
    pub const DYNAMIC_RANGE_SETTING: u16 = 0x1402;
    pub const DEVELOPMENT_DYNAMIC_RANGE: u16 = 0x1403;
    pub const MIN_FOCAL_LENGTH: u16 = 0x1404;
    pub const MAX_FOCAL_LENGTH: u16 = 0x1405;
    pub const MAX_APERTURE_AT_MIN_FOCAL: u16 = 0x1406;
    pub const MAX_APERTURE_AT_MAX_FOCAL: u16 = 0x1407;
    pub const INTERNAL_SERIAL_NUMBER: u16 = 0x1409;
    pub const ORDER_NUMBER: u16 = 0x1410;
    pub const FRAME_NUMBER: u16 = 0x1411;
    pub const AUTO_ROTATION: u16 = 0x1422;
}

/// Locate the MakerNote's IFD inside its block.
///
/// Returns `(ifd_offset, byte_order)` for the makers whose MakerNote is a plain
/// TIFF directory, or `None` for the encrypted / IFD-less ones.
fn makernote_ifd_offset(data: &[u8], maker: Maker) -> Option<(usize, ByteOrder)> {
    /// Read the little-endian IFD pointer that follows a vendor signature.
    fn le_offset(data: &[u8], at: usize) -> Option<usize> {
        let bytes = data.get(at..at + 4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
    }

    /// Read the big-endian IFD pointer that follows a vendor signature.
    fn be_offset(data: &[u8], at: usize) -> Option<usize> {
        let bytes = data.get(at..at + 4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
    }

    match maker {
        // Canon and Samsung put the IFD straight at offset 0, no signature.
        Maker::Canon | Maker::Samsung => Some((0, ByteOrder::LittleEndian)),
        // "Nikon\0\x01\x00" marks type 1, whose IFD is a plain directory.
        // Type 2 (encrypted, 3DES) and type 3 (encrypted, serial-derived key)
        // are rejected here rather than decoded as if they were type 1.
        Maker::Nikon => {
            if data.starts_with(b"Nikon\0\x01\x00") {
                Some((le_offset(data, 8)?, ByteOrder::LittleEndian))
            } else {
                None
            }
        }
        Maker::Sony if data.starts_with(b"SONY DSC \0\0\0") => {
            Some((le_offset(data, 12)?, ByteOrder::LittleEndian))
        }
        Maker::Olympus if data.starts_with(b"OLYMPUS\0") => {
            Some((le_offset(data, 8)?, ByteOrder::LittleEndian))
        }
        Maker::FujiFilm if data.starts_with(b"FUJIFILM") => {
            Some((le_offset(data, 8)?, ByteOrder::LittleEndian))
        }
        // Panasonic is the odd one out: big-endian throughout.
        Maker::Panasonic if data.starts_with(b"Panasonic\0\0\0") => {
            Some((be_offset(data, 12)?, ByteOrder::BigEndian))
        }
        Maker::Pentax if data.starts_with(b"PENTAX \0") => {
            Some((le_offset(data, 8)?, ByteOrder::LittleEndian))
        }
        // Ricoh (encrypted variants), Sigma (encrypted), Leica (encrypted
        // variants), Apple (no IFD) and unknown makes stay unsupported.
        _ => None,
    }
}

/// Render a MakerNote entry value as text, following the display conventions
/// of the parent EXIF module.
fn render_value(
    data: &[u8],
    offset: usize,
    format: u16,
    count: usize,
    byte_order: ByteOrder,
) -> String {
    let end = offset.saturating_add(format_size(format).saturating_mul(count));
    if end > data.len() {
        return "?".into();
    }

    match format {
        tiff_format::ASCII => read_string(data, offset, count),
        tiff_format::SHORT => read_u16_array(data, offset, count, byte_order)
            .map(|v| v.iter().map(ToString::to_string).collect::<Vec<_>>())
            .map(|v| v.join(", "))
            .unwrap_or_else(|_| "?".into()),
        tiff_format::LONG => read_u32_array(data, offset, count, byte_order)
            .map(|v| v.iter().map(ToString::to_string).collect::<Vec<_>>())
            .map(|v| v.join(", "))
            .unwrap_or_else(|_| "?".into()),
        tiff_format::RATIONAL | tiff_format::SRATIONAL => {
            read_rational_array(data, offset, count, byte_order)
                .map(|v| {
                    v.iter()
                        .map(|(n, d)| {
                            if *d == 0 {
                                "0/0".into()
                            } else {
                                format!("{:.4}", *n as f64 / *d as f64)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|_| "?".into())
        }
        tiff_format::BYTE | tiff_format::UNDEFINED => format!("[{} bytes]", count),
        _ => format!("[{} values]", count),
    }
}

/// Parse a MakerNote block into its IFD entries.
///
/// Value offsets inside a MakerNote IFD are relative to the start of the
/// MakerNote block itself, which is byte 0 of `data`.
///
/// Returns an empty list for the makers whose MakerNote is encrypted or carries
/// no IFD (see the module docs) and for blocks that are too short to hold one.
pub fn parse_makernote(data: &[u8], maker: Maker) -> Vec<MakerNoteEntry> {
    let Some((ifd_offset, byte_order)) = makernote_ifd_offset(data, maker) else {
        return Vec::new();
    };

    let Ok(count) = read_u16(data, ifd_offset, byte_order) else {
        return Vec::new();
    };

    let mut entries = Vec::new();
    for i in 0..count as usize {
        let entry_offset = ifd_offset + 2 + i * 12;
        let (Ok(tag), Ok(format), Ok(value_count), Ok(value)) = (
            read_u16(data, entry_offset, byte_order),
            read_u16(data, entry_offset + 2, byte_order),
            read_u32(data, entry_offset + 4, byte_order),
            read_u32(data, entry_offset + 8, byte_order),
        ) else {
            break;
        };

        let size = format_size(format);
        if size == 0 {
            continue;
        }

        // Values of 4 bytes or fewer live inline in the entry; anything larger
        // is a pointer relative to the start of the MakerNote block.
        let value_count = value_count as usize;
        let value_offset = if size * value_count <= 4 {
            entry_offset + 8
        } else {
            value as usize
        };

        entries.push(MakerNoteEntry {
            tag,
            name: makernote_tag_name(maker, tag).map(String::from),
            value: render_value(data, value_offset, format, value_count, byte_order),
        });
    }

    entries
}

/// Get the MakerNote tag name for the makers this module carries tables for.
#[must_use]
pub fn makernote_tag_name(maker: Maker, tag: u16) -> Option<&'static str> {
    match maker {
        Maker::Canon => Some(match tag {
            canon::CAMERA_SETTINGS => "CameraSettings",
            canon::FOCAL_LENGTH => "FocalLength",
            canon::SHOT_INFO => "ShotInfo",
            canon::PANORAMA => "Panorama",
            canon::IMAGE_TYPE => "ImageType",
            canon::FIRMWARE_VERSION => "FirmwareVersion",
            canon::FILE_NUMBER => "FileNumber",
            canon::OWNER_NAME => "OwnerName",
            canon::SERIAL_NUMBER => "SerialNumber",
            canon::CAMERA_INFO => "CameraInfo",
            canon::CUSTOM_FUNCTIONS => "CustomFunctions",
            canon::MODEL_ID => "ModelId",
            canon::THUMBNAIL_IMAGE_VALID_AREA => "ThumbnailImageValidArea",
            canon::SERIAL_NUMBER_FORMAT => "SerialNumberFormat",
            canon::SUPER_MACRO => "SuperMacro",
            canon::DATE_STAMP_MODE => "DateStampMode",
            canon::MY_COLORS => "MyColors",
            canon::FIRMWARE_REVISION => "FirmwareRevision",
            canon::CATEGORIES => "Categories",
            canon::FACE_DETECT => "FaceDetect",
            canon::WB_RGB_COEFFS => "WbRgbCoeffs",
            canon::COLOR_DATA => "ColorData",
            canon::AF_INFO => "AfInfo",
            canon::CONTRAST_INFO => "ContrastInfo",
            canon::WB_INFO => "WbInfo",
            canon::ORIENTATION => "Orientation",
            canon::AF_MICRO_ADJ => "AfMicroAdj",
            _ => return None,
        }),
        Maker::Nikon => Some(match tag {
            nikon::FIRMWARE_VERSION => "FirmwareVersion",
            nikon::ISO => "ISO",
            nikon::QUALITY => "Quality",
            nikon::WHITE_BALANCE => "WhiteBalance",
            nikon::SHARPENING => "Sharpening",
            nikon::FOCUS_MODE => "FocusMode",
            nikon::FLASH_SETTING => "FlashSetting",
            nikon::FLASH_MODE => "FlashMode",
            nikon::WHITE_BALANCE_FINE => "WhiteBalanceFine",
            nikon::WHITE_BALANCE_RB_COEFF => "WhiteBalanceRbCoeff",
            nikon::ISO_SELECTION => "IsoSelection",
            nikon::ISO_2 => "Iso2",
            nikon::PIC_CONTROL_DATA => "PicControlData",
            nikon::COLOR_MODE => "ColorMode",
            nikon::QUALITY_AND_FORMAT => "QualityAndFormat",
            nikon::IMAGE_ADJUSTMENT => "ImageAdjustment",
            nikon::CCD_SENSITIVITY => "CcdSensitivity",
            nikon::WHITE_BALANCE_TONE => "WhiteBalanceTone",
            nikon::LENS_TYPE => "LensType",
            nikon::LENS_INFO => "LensInfo",
            nikon::FOCUS_DISTANCE => "FocusDistance",
            nikon::DIGITAL_ZOOM => "DigitalZoom",
            nikon::AF_AREA_MODE => "AfAreaMode",
            nikon::AF_POINT => "AfPoint",
            nikon::SENSOR_PIXEL_SIZE => "SensorPixelSize",
            nikon::SERIAL_NUMBER => "SerialNumber",
            nikon::COLOR_SPACE => "ColorSpace",
            nikon::FLASH_INFO => "FlashInfo",
            nikon::AF_FOCUS_POSITION => "AfFocusPosition",
            nikon::VENDOR_NAME => "VendorName",
            nikon::SHOT_INFO => "ShotInfo",
            nikon::NEF_COMPRESSION => "NefCompression",
            nikon::SERIAL_NUMBER_2 => "SerialNumber2",
            nikon::EXPOSURE_TUNE => "ExposureTune",
            nikon::AF_FOCUS => "AfFocus",
            nikon::LENS_DATA => "LensData",
            nikon::RETOUCH_HISTORY => "RetouchHistory",
            nikon::CAMERA_SERIAL_2 => "CameraSerial2",
            nikon::AF_INFO_2 => "AfInfo2",
            nikon::AF_FINE_TUNE => "AfFineTune",
            nikon::AF_TUNE_ADJ => "AfTuneAdj",
            nikon::VIRTUALIZATION => "Virtualization",
            nikon::MULTI_EXPOSURE => "MultiExposure",
            nikon::HDR_INFO => "HdrInfo",
            nikon::AF_CONFIG => "AfConfig",
            _ => return None,
        }),
        Maker::Sony => Some(match tag {
            sony::AUTO_FOCUS => "AutoFocus",
            sony::AF_DISTANCE_SETTING => "AfDistanceSetting",
            sony::MULTI_BURST_MODE => "MultiBurstMode",
            sony::MULTI_BURST_IMAGE_SIZE => "MultiBurstImageSize",
            sony::PANORAMA_DIRECTION => "PanoramaDirection",
            sony::PANORAMA_FIELD_OF_VIEW => "PanoramaFieldOfView",
            sony::PRE_CAPTURE_FRAMES => "PreCaptureFrames",
            sony::COLOR_MODE => "ColorMode",
            sony::QUALITY => "Quality",
            sony::QUALITY_2 => "Quality2",
            sony::FLASH_LEVEL => "FlashLevel",
            sony::RELEASE_MODE => "ReleaseMode",
            sony::SEQUENCE_NUMBER => "SequenceNumber",
            sony::CREATIVE_STYLE => "CreativeStyle",
            sony::CONTRAST => "Contrast",
            sony::SATURATION => "Saturation",
            sony::SHARPNESS => "Sharpness",
            sony::FLASH => "Flash",
            sony::FLASH_EXPOSURE_COMP_SET => "FlashExposureCompSet",
            sony::EXPOSURE_PROGRAM => "ExposureProgram",
            sony::WHITE_BALANCE_FINE => "WhiteBalanceFine",
            sony::WHITE_BALANCE => "WhiteBalance",
            sony::ISO_SETTING => "IsoSetting",
            sony::ISO_INFO => "IsoInfo",
            sony::MACRO => "Macro",
            sony::EXPOSURE_MODE => "ExposureMode",
            sony::FOCUS_MODE => "FocusMode",
            sony::AF_MODE => "AfMode",
            sony::AF_POINT => "AfPoint",
            sony::SCENE_MODE => "SceneMode",
            sony::ZONE_MATCHING => "ZoneMatching",
            sony::DYNAMIC_RANGE_OPTIMIZER => "DynamicRangeOptimizer",
            sony::COLOR_TEMPERATURE => "ColorTemperature",
            sony::LENS_ID => "LensId",
            sony::ZOOM_STEP_COUNT => "ZoomStepCount",
            sony::FOCUS_STEP_COUNT => "FocusStepCount",
            sony::AF_POINT_SELECTED => "AfPointSelected",
            sony::AF_POINTS_USED => "AfPointsUsed",
            sony::SENSOR_UNIT => "SensorUnit",
            sony::HDR => "Hdr",
            sony::FRAME_NUMBER => "FrameNumber",
            sony::CAMERA_INFO => "CameraInfo",
            sony::SERIAL_NUMBER => "SerialNumber",
            sony::MODEL_YEAR => "ModelYear",
            sony::INTERNAL_SERIAL_NUMBER => "InternalSerialNumber",
            _ => return None,
        }),
        Maker::FujiFilm => Some(match tag {
            fuji::VERSION => "Version",
            fuji::SERIAL_NUMBER => "SerialNumber",
            fuji::QUALITY => "Quality",
            fuji::SHARPNESS => "Sharpness",
            fuji::WHITE_BALANCE => "WhiteBalance",
            fuji::COLOR => "Color",
            fuji::TONE => "Tone",
            fuji::FLASH_MODE => "FlashMode",
            fuji::FLASH_STRENGTH => "FlashStrength",
            fuji::MACRO => "Macro",
            fuji::FOCUS_MODE => "FocusMode",
            fuji::AUTO_FOCUSING => "AutoFocusing",
            fuji::AF_POINT => "AfPoint",
            fuji::EXPOSURE_PROGRAM => "ExposureProgram",
            fuji::EXPOSURE_MODE => "ExposureMode",
            fuji::EXPOSURE_COMPENSATION => "ExposureCompensation",
            fuji::SHUTTER_SPEED => "ShutterSpeed",
            fuji::APERTURE => "Aperture",
            fuji::SENSITIVITY => "Sensitivity",
            fuji::BRIGHTNESS_VALUE => "BrightnessValue",
            fuji::FOCAL_LENGTH => "FocalLength",
            fuji::FLASH => "Flash",
            fuji::SELF_TIMER => "SelfTimer",
            fuji::CONTINUOUS => "Continuous",
            fuji::PANORAMA_MODE => "PanoramaMode",
            fuji::IMAGE_SIZE => "ImageSize",
            fuji::ISO => "ISO",
            fuji::FINEPIX_COLOR => "FinePixColor",
            fuji::DYNAMIC_RANGE => "DynamicRange",
            fuji::FILM_MODE => "FilmMode",
            fuji::DYNAMIC_RANGE_SETTING => "DynamicRangeSetting",
            fuji::DEVELOPMENT_DYNAMIC_RANGE => "DevelopmentDynamicRange",
            fuji::MIN_FOCAL_LENGTH => "MinFocalLength",
            fuji::MAX_FOCAL_LENGTH => "MaxFocalLength",
            fuji::MAX_APERTURE_AT_MIN_FOCAL => "MaxApertureAtMinFocal",
            fuji::MAX_APERTURE_AT_MAX_FOCAL => "MaxApertureAtMaxFocal",
            fuji::INTERNAL_SERIAL_NUMBER => "InternalSerialNumber",
            fuji::ORDER_NUMBER => "OrderNumber",
            fuji::FRAME_NUMBER => "FrameNumber",
            fuji::AUTO_ROTATION => "AutoRotation",
            _ => return None,
        }),
        // No tag table is carried for these, so every lookup is a miss.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maker_detection() {
        assert_eq!(Maker::from_make("Canon"), Maker::Canon);
        assert_eq!(Maker::from_make("NIKON CORPORATION"), Maker::Nikon);
        assert_eq!(Maker::from_make("Sony"), Maker::Sony);
        assert_eq!(Maker::from_make("FUJIFILM"), Maker::FujiFilm);
        assert_eq!(Maker::from_make("Unknown Brand"), Maker::Unknown);
    }

    /// Append a little-endian u16.
    fn push_u16(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    /// Append a little-endian u32.
    fn push_u32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    /// Build a Sony-style MakerNote: a 12-byte signature, a little-endian IFD
    /// offset, then an IFD with `entries` of (tag, type, count, value).
    ///
    /// `value` is the inline word for short values, or the offset of an
    /// out-of-line value block the caller has already appended.
    fn build_makernote(ifd_offset: u32, entries: &[(u16, u16, u32, u32)]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"SONY DSC \0\0\0");
        push_u32(&mut data, ifd_offset);
        while data.len() < ifd_offset as usize {
            data.push(0);
        }

        push_u16(&mut data, entries.len() as u16);
        for &(tag, format, count, value) in entries {
            push_u16(&mut data, tag);
            push_u16(&mut data, format);
            push_u32(&mut data, count);
            push_u32(&mut data, value);
        }
        push_u32(&mut data, 0); // no next IFD

        data
    }

    #[test]
    fn test_parse_sony_makernote_ifd() {
        // Two inline SHORT entries plus a 5-byte ASCII value, which exceeds
        // the 4 inline bytes and so points past the IFD.
        let ifd_offset = 16u32;
        let entries = [
            (sony::WHITE_BALANCE, tiff_format::SHORT, 1, 0),
            (sony::FLASH, tiff_format::SHORT, 1, 1),
        ];

        // The ASCII value is out of line, so it goes right after the IFD.
        let mut with_ascii = entries.to_vec();
        with_ascii.push((0x0100, tiff_format::ASCII, 5, 0));
        let ascii_offset = build_makernote(ifd_offset, &with_ascii).len() as u32;
        with_ascii[2].3 = ascii_offset;

        let mut data = build_makernote(ifd_offset, &with_ascii);
        data.extend_from_slice(b"1.4s\0");

        let parsed = parse_makernote(&data, Maker::Sony);
        assert_eq!(parsed.len(), 3);

        assert_eq!(parsed[0].tag, sony::WHITE_BALANCE);
        assert_eq!(parsed[0].name.as_deref(), Some("WhiteBalance"));
        assert_eq!(parsed[0].value, "0");

        assert_eq!(parsed[1].tag, sony::FLASH);
        assert_eq!(parsed[1].name.as_deref(), Some("Flash"));
        assert_eq!(parsed[1].value, "1");

        assert_eq!(parsed[2].tag, 0x0100);
        assert_eq!(parsed[2].name, None);
        assert_eq!(parsed[2].value, "1.4s");
    }

    #[test]
    fn test_parse_canon_makernote_ifd() {
        // Canon has no signature: the IFD is at offset 0.
        let mut data = Vec::new();
        push_u16(&mut data, 1);
        push_u16(&mut data, canon::FIRMWARE_VERSION);
        push_u16(&mut data, tiff_format::SHORT);
        push_u32(&mut data, 1);
        push_u32(&mut data, 0x0102);
        push_u32(&mut data, 0);

        let parsed = parse_makernote(&data, Maker::Canon);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].tag, canon::FIRMWARE_VERSION);
        assert_eq!(parsed[0].name.as_deref(), Some("FirmwareVersion"));
        assert_eq!(parsed[0].value, "258");
    }

    #[test]
    fn test_parse_panasonic_is_big_endian() {
        // 12-byte header, 4-byte IFD pointer, so the IFD starts at 16: a
        // 2-byte count, one 12-byte entry, then a 4-byte next-IFD pointer.
        let mut data = Vec::new();
        data.extend_from_slice(b"Panasonic\0\0\0");
        data.extend_from_slice(&16u32.to_be_bytes()); // IFD offset
        data.extend_from_slice(&1u16.to_be_bytes()); // entry count
        data.extend_from_slice(&0x002du16.to_be_bytes()); // Quality
        data.extend_from_slice(&3u16.to_be_bytes()); // SHORT
        data.extend_from_slice(&1u32.to_be_bytes()); // count
                                                     // Inline SHORT: 3 in the first two bytes of the value field.
        data.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
        data.extend_from_slice(&0u32.to_be_bytes()); // no next IFD

        let parsed = parse_makernote(&data, Maker::Panasonic);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].tag, 0x002d);
        // Read little-endian this would be 0x0300 = 768.
        assert_eq!(parsed[0].value, "3");
    }

    #[test]
    fn test_parse_returns_empty_for_encrypted_makers() {
        // A Nikon type 3 header: encrypted, so nothing is decoded.
        let mut nikon3 = Vec::new();
        nikon3.extend_from_slice(b"Nikon\0\x02\x00\x00\x00");
        nikon3.extend_from_slice(&[0u8; 32]);
        assert!(parse_makernote(&nikon3, Maker::Nikon).is_empty());

        // Sigma, Leica, Apple, Ricoh and unknown makes are unsupported.
        assert!(parse_makernote(&[0u8; 32], Maker::Sigma).is_empty());
        assert!(parse_makernote(&[0u8; 32], Maker::Leica).is_empty());
        assert!(parse_makernote(&[0u8; 32], Maker::Apple).is_empty());
        assert!(parse_makernote(&[0u8; 32], Maker::Ricoh).is_empty());
        assert!(parse_makernote(&[0u8; 32], Maker::Unknown).is_empty());
    }

    #[test]
    fn test_parse_returns_empty_for_truncated_block() {
        let mut data = Vec::new();
        data.extend_from_slice(b"SONY DSC \0\0\0");
        push_u32(&mut data, 4096); // IFD offset past the end
        assert!(parse_makernote(&data, Maker::Sony).is_empty());

        // A wrong signature must not be read as an IFD either.
        let mut wrong = Vec::new();
        wrong.extend_from_slice(b"NOTSONY\0\0\0\0\0");
        push_u32(&mut wrong, 16);
        push_u16(&mut wrong, 0);
        assert!(parse_makernote(&wrong, Maker::Sony).is_empty());
    }

    #[test]
    fn test_makernote_tag_name_lookup() {
        assert_eq!(
            makernote_tag_name(Maker::Canon, canon::MODEL_ID),
            Some("ModelId")
        );
        assert_eq!(
            makernote_tag_name(Maker::Nikon, nikon::LENS_TYPE),
            Some("LensType")
        );
        assert_eq!(
            makernote_tag_name(Maker::Sony, sony::ISO_SETTING),
            Some("IsoSetting")
        );
        assert_eq!(
            makernote_tag_name(Maker::FujiFilm, fuji::FILM_MODE),
            Some("FilmMode")
        );

        // Genuinely unknown tags and unknown makers are misses.
        assert_eq!(makernote_tag_name(Maker::Canon, 0xFFFF), None);
        assert_eq!(makernote_tag_name(Maker::Unknown, 0x0001), None);
        assert_eq!(makernote_tag_name(Maker::Leica, 0x0001), None);
    }
}
