// SPDX-License-Identifier: Apache-2.0

//! EXIF tag vocabulary (EXIF 2.31 §4.6 / TIFF 6.0 tag registry).
//!
//! Independent reimplementation of the tag identifier tables the
//! specification defines: the IFD0 tags of TIFF 6.0, the Exif IFD and
//! GPS IFD tags of EXIF 2.31, the 13 TIFF field types of §4.5, and the
//! enumerated values for compression, orientation, exposure program,
//! metering mode, light source, flash, color space and sensing method.
//! The numbers are the specification's; nothing here is a transcription
//! of another implementation's code.
//!
//! [`tag_name`] labels a tag for a searchable listing. The names follow
//! the ExifTool spelling because that is the vocabulary users search
//! with — an unknown tag has no name and the caller prints its id.
/// IFD type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfdType {
    Ifd0,
    Ifd1,
    Exif,
    Gps,
    Interop,
    MakerNote,
}

/// IFD entry structure.
#[derive(Debug, Clone)]
pub struct IfdEntry {
    /// Tag ID.
    pub tag: u16,
    /// Data format (TIFF type).
    pub format: u16,
    /// Number of values.
    pub count: u32,
    /// Offset in original data (for value offset tracking).
    pub value_offset: usize,
    /// Value (inline if <= 4 bytes, offset otherwise).
    pub value: u32,
    /// IFD type this entry belongs to.
    pub ifd_type: IfdType,
}

/// EXIF tag constants (IFD0).
pub mod ifd0 {
    pub const IMAGE_WIDTH: u16 = 0x0100;
    pub const IMAGE_HEIGHT: u16 = 0x0101;
    pub const BITS_PER_SAMPLE: u16 = 0x0102;
    pub const COMPRESSION: u16 = 0x0103;
    pub const PHOTOMETRIC_INTERPRETATION: u16 = 0x0106;
    pub const ORIENTATION: u16 = 0x0112;
    pub const SAMPLES_PER_PIXEL: u16 = 0x0115;
    pub const ROWS_PER_STRIP: u16 = 0x0116;
    pub const STRIP_BYTE_COUNTS: u16 = 0x0117;
    pub const X_RESOLUTION: u16 = 0x011A;
    pub const Y_RESOLUTION: u16 = 0x011B;
    pub const PLANAR_CONFIGURATION: u16 = 0x011C;
    pub const RESOLUTION_UNIT: u16 = 0x0128;
    pub const TRANSFER_FUNCTION: u16 = 0x012D;
    pub const SOFTWARE: u16 = 0x0131;
    pub const DATE_TIME: u16 = 0x0132;
    pub const ARTIST: u16 = 0x013B;
    pub const WHITE_POINT: u16 = 0x013E;
    pub const PRIMARY_CHROMATICITIES: u16 = 0x013F;
    pub const Y_CB_CR_COEFFICIENTS: u16 = 0x0211;
    pub const Y_CB_CR_SUB_SAMPLING: u16 = 0x0212;
    pub const Y_CB_CR_POSITIONING: u16 = 0x0213;
    pub const REFERENCE_BLACK_WHITE: u16 = 0x0214;
    pub const COPYRIGHT: u16 = 0x8298;
    pub const EXIF_IFD_POINTER: u16 = 0x8769;
    pub const GPS_IFD_POINTER: u16 = 0x8825;
    pub const MAKE: u16 = 0x010F;
    pub const MODEL: u16 = 0x0110;
}

/// EXIF tag constants (ExifIFD).
pub mod exif_ifd {
    pub const EXPOSURE_TIME: u16 = 0x829A;
    pub const F_NUMBER: u16 = 0x829D;
    pub const EXPOSURE_PROGRAM: u16 = 0x8822;
    pub const ISO_SPEED_RATINGS: u16 = 0x8827;
    pub const SENSITIVITY_TYPE: u16 = 0x8830;
    pub const EXIF_VERSION: u16 = 0x9000;
    pub const DATE_TIME_ORIGINAL: u16 = 0x9003;
    pub const DATE_TIME_DIGITIZED: u16 = 0x9004;
    pub const OFFSET_TIME: u16 = 0x9010;
    pub const OFFSET_TIME_ORIGINAL: u16 = 0x9011;
    pub const OFFSET_TIME_DIGITIZED: u16 = 0x9012;
    pub const COMPONENTS_CONFIGURATION: u16 = 0x9101;
    pub const COMPRESSED_BITS_PER_PIXEL: u16 = 0x9102;
    pub const SHUTTER_SPEED_VALUE: u16 = 0x9201;
    pub const APERTURE_VALUE: u16 = 0x9202;
    pub const BRIGHTNESS_VALUE: u16 = 0x9203;
    pub const EXPOSURE_BIAS_VALUE: u16 = 0x9204;
    pub const MAX_APERTURE_VALUE: u16 = 0x9205;
    pub const SUBJECT_DISTANCE: u16 = 0x9206;
    pub const METERING_MODE: u16 = 0x9207;
    pub const LIGHT_SOURCE: u16 = 0x9208;
    pub const FLASH: u16 = 0x9209;
    pub const FOCAL_LENGTH: u16 = 0x920A;
    pub const SUBJECT_AREA: u16 = 0x9214;
    pub const MAKER_NOTE: u16 = 0x927C;
    pub const USER_COMMENT: u16 = 0x9286;
    pub const SUB_SEC_TIME: u16 = 0x9290;
    pub const SUB_SEC_TIME_ORIGINAL: u16 = 0x9291;
    pub const SUB_SEC_TIME_DIGITIZED: u16 = 0x9292;
    pub const FLASHPIX_VERSION: u16 = 0xA000;
    pub const COLOR_SPACE: u16 = 0xA001;
    pub const PIXEL_X_DIMENSION: u16 = 0xA002;
    pub const PIXEL_Y_DIMENSION: u16 = 0xA003;
    pub const RELATED_SOUND_FILE: u16 = 0xA004;
    pub const FLASH_ENERGY: u16 = 0xA20B;
    pub const SPATIAL_FREQUENCY_RESPONSE: u16 = 0xA20C;
    pub const FOCAL_PLANE_X_RESOLUTION: u16 = 0xA20E;
    pub const FOCAL_PLANE_Y_RESOLUTION: u16 = 0xA20F;
    pub const FOCAL_PLANE_RESOLUTION_UNIT: u16 = 0xA210;
    pub const SUBJECT_LOCATION: u16 = 0xA214;
    pub const EXPOSURE_INDEX: u16 = 0xA215;
    pub const SENSING_METHOD: u16 = 0xA217;
    pub const FILE_SOURCE: u16 = 0xA300;
    pub const SCENE_TYPE: u16 = 0xA301;
    pub const CF_A_PATTERN: u16 = 0xA302;
    pub const CUSTOM_RENDERED: u16 = 0xA401;
    pub const EXPOSURE_MODE: u16 = 0xA402;
    pub const WHITE_BALANCE: u16 = 0xA403;
    pub const DIGITAL_ZOOM_RATIO: u16 = 0xA404;
    pub const FOCAL_LENGTH_IN_35MM_FILM: u16 = 0xA405;
    pub const SCENE_CAPTURE_TYPE: u16 = 0xA406;
    pub const GAIN_CONTROL: u16 = 0xA407;
    pub const CONTRAST: u16 = 0xA408;
    pub const SATURATION: u16 = 0xA409;
    pub const SHARPNESS: u16 = 0xA40A;
    pub const DEVICE_SETTING_DESCRIPTION: u16 = 0xA40B;
    pub const SUBJECT_DISTANCE_RANGE: u16 = 0xA40C;
    pub const IMAGE_UNIQUE_ID: u16 = 0xA420;
    pub const CAMERA_OWNER_NAME: u16 = 0xA430;
    pub const BODY_SERIAL_NUMBER: u16 = 0xA431;
    pub const LENS_SPECIFICATION: u16 = 0xA432;
    pub const LENS_MAKE: u16 = 0xA433;
    pub const LENS_MODEL: u16 = 0xA434;
    pub const LENS_SERIAL_NUMBER: u16 = 0xA435;
    pub const INTEROP_IFD_POINTER: u16 = 0xA005;
}

/// GPS IFD tag constants.
pub mod gps_ifd {
    pub const GPS_VERSION_ID: u16 = 0x0000;
    pub const GPS_LATITUDE_REF: u16 = 0x0001;
    pub const GPS_LATITUDE: u16 = 0x0002;
    pub const GPS_LONGITUDE_REF: u16 = 0x0003;
    pub const GPS_LONGITUDE: u16 = 0x0004;
    pub const GPS_ALTITUDE_REF: u16 = 0x0005;
    pub const GPS_ALTITUDE: u16 = 0x0006;
    pub const GPS_TIME_STAMP: u16 = 0x0007;
    pub const GPS_STATUS: u16 = 0x0008;
    pub const GPS_MEASURE_MODE: u16 = 0x0009;
    pub const GPS_DOP: u16 = 0x000A;
    pub const GPS_SPEED_REF: u16 = 0x000B;
    pub const GPS_SPEED: u16 = 0x000C;
    pub const GPS_TRACK_REF: u16 = 0x000D;
    pub const GPS_TRACK: u16 = 0x000E;
    pub const GPS_IMG_DIRECTION_REF: u16 = 0x000F;
    pub const GPS_IMG_DIRECTION: u16 = 0x0010;
    pub const GPS_MAP_DATUM: u16 = 0x0012;
    pub const GPS_DEST_LATITUDE_REF: u16 = 0x0013;
    pub const GPS_DEST_LATITUDE: u16 = 0x0014;
    pub const GPS_DEST_LONGITUDE_REF: u16 = 0x0015;
    pub const GPS_DEST_LONGITUDE: u16 = 0x0016;
    pub const GPS_DEST_BEARING_REF: u16 = 0x0017;
    pub const GPS_DEST_BEARING: u16 = 0x0018;
    pub const GPS_DEST_DISTANCE_REF: u16 = 0x0019;
    pub const GPS_DEST_DISTANCE: u16 = 0x001A;
    pub const GPS_PROCESSING_METHOD: u16 = 0x001B;
    pub const GPS_AREA_INFORMATION: u16 = 0x001C;
    pub const GPS_DATE_STAMP: u16 = 0x001D;
    pub const GPS_DIFFERENTIAL: u16 = 0x001E;
    pub const GPS_H_POSITIONING_ERROR: u16 = 0x001F;
}

/// TIFF data format types.
pub mod tiff_format {
    pub const BYTE: u16 = 1;
    pub const ASCII: u16 = 2;
    pub const SHORT: u16 = 3;
    pub const LONG: u16 = 4;
    pub const RATIONAL: u16 = 5;
    pub const SBYTE: u16 = 6;
    pub const UNDEFINED: u16 = 7;
    pub const SSHORT: u16 = 8;
    pub const SLONG: u16 = 9;
    pub const SRATIONAL: u16 = 10;
    pub const FLOAT: u16 = 11;
    pub const DOUBLE: u16 = 12;
    pub const IFD: u16 = 13;
    pub const IFD8: u16 = 14;
}

/// Get ExifTool-compatible tag name.
#[must_use]
pub fn tag_name(tag: u16) -> Option<&'static str> {
    for (t, name) in TAG_NAMES {
        if *t == tag {
            return Some(name);
        }
    }
    None
}

/// Tag names (ExifTool compatible).
const TAG_NAMES: &[(u16, &str)] = &[
    (0x0100, "ImageWidth"),
    (0x0101, "ImageHeight"),
    (0x0102, "BitsPerSample"),
    (0x0103, "Compression"),
    (0x0106, "PhotometricInterpretation"),
    (0x010F, "Make"),
    (0x0110, "Model"),
    (0x0112, "Orientation"),
    (0x0115, "SamplesPerPixel"),
    (0x011A, "XResolution"),
    (0x011B, "YResolution"),
    (0x0128, "ResolutionUnit"),
    (0x0131, "Software"),
    (0x0132, "DateTime"),
    (0x013B, "Artist"),
    (0x8298, "Copyright"),
    (0x8769, "ExifIFD"),
    (0x8825, "GPSInfo"),
    (0x829A, "ExposureTime"),
    (0x829D, "FNumber"),
    (0x8822, "ExposureProgram"),
    (0x8827, "ISO"),
    (0x9000, "ExifVersion"),
    (0x9003, "DateTimeOriginal"),
    (0x9004, "CreateDate"),
    (0x9101, "ComponentsConfiguration"),
    (0x9201, "ShutterSpeedValue"),
    (0x9202, "ApertureValue"),
    (0x9207, "MeteringMode"),
    (0x9208, "LightSource"),
    (0x9209, "Flash"),
    (0x920A, "FocalLength"),
    (0x927C, "MakerNote"),
    (0x9286, "UserComment"),
    (0xA000, "FlashpixVersion"),
    (0xA001, "ColorSpace"),
    (0xA002, "ExifImageWidth"),
    (0xA003, "ExifImageHeight"),
    (0xA402, "ExposureMode"),
    (0xA403, "WhiteBalance"),
    (0xA405, "FocalLengthIn35mmFormat"),
    (0xA420, "ImageUniqueID"),
    (0xA432, "LensSpec"),
    (0xA434, "LensModel"),
    (0x0001, "GPSLatitudeRef"),
    (0x0002, "GPSLatitude"),
    (0x0003, "GPSLongitudeRef"),
    (0x0004, "GPSLongitude"),
    (0x0005, "GPSAltitudeRef"),
    (0x0006, "GPSAltitude"),
    (0x0007, "GPSTimeStamp"),
    (0x001D, "GPSDateStamp"),
];

/// Compression type values.
pub mod compression {
    pub const UNCOMPRESSED: u16 = 1;
    pub const JPEG: u16 = 6;
    pub const PACKBITS: u16 = 32773;
}

/// Orientation values.
pub mod orientation {
    pub const TOP_LEFT: u16 = 1;
    pub const TOP_RIGHT: u16 = 2;
    pub const BOTTOM_RIGHT: u16 = 3;
    pub const BOTTOM_LEFT: u16 = 4;
    pub const LEFT_TOP: u16 = 5;
    pub const RIGHT_TOP: u16 = 6;
    pub const RIGHT_BOTTOM: u16 = 7;
    pub const LEFT_BOTTOM: u16 = 8;
}

/// Exposure program values.
pub mod exposure_program {
    pub const NOT_DEFINED: u16 = 0;
    pub const MANUAL: u16 = 1;
    pub const PROGRAM_AUTO: u16 = 2;
    pub const APERTURE_PRIORITY: u16 = 3;
    pub const SHUTTER_PRIORITY: u16 = 4;
    pub const CREATIVE: u16 = 5;
    pub const ACTION: u16 = 6;
    pub const PORTRAIT: u16 = 7;
    pub const LANDSCAPE: u16 = 8;
}

/// Metering mode values.
pub mod metering_mode {
    pub const UNKNOWN: u16 = 0;
    pub const AVERAGE: u16 = 1;
    pub const CENTER_WEIGHTED: u16 = 2;
    pub const SPOT: u16 = 3;
    pub const MULTI_SPOT: u16 = 4;
    pub const PATTERN: u16 = 5;
    pub const PARTIAL: u16 = 6;
    pub const OTHER: u16 = 255;
}

/// Light source values.
pub mod light_source {
    pub const UNKNOWN: u16 = 0;
    pub const DAYLIGHT: u16 = 1;
    pub const FLUORESCENT: u16 = 2;
    pub const TUNGSTEN: u16 = 3;
    pub const FLASH: u16 = 4;
    pub const FINE_WEATHER: u16 = 9;
    pub const CLOUDY: u16 = 10;
    pub const SHADE: u16 = 11;
    pub const DAYLIGHT_FLUORESCENT: u16 = 12;
    pub const D65: u16 = 13;
    pub const D50: u16 = 14;
    pub const ISO_STUDIO_TUNGSTEN: u16 = 15;
    pub const OTHER: u16 = 255;
}

/// Flash values (bitmask).
pub mod flash {
    pub const DID_NOT_FIRE: u16 = 0;
    pub const FIRED: u16 = 1;
    pub const RETURN_NOT_DETECTED: u16 = 5;
    pub const RETURN_DETECTED: u16 = 7;
    pub const NO_FLASH_FUNCTION: u16 = 32;
    pub const RED_EYE_REDUCTION: u16 = 64;
}

/// Color space values.
pub mod color_space {
    pub const SRGB: u16 = 1;
    pub const UNCALIBRATED: u16 = 65535;
}

/// Sensing method values.
pub mod sensing_method {
    pub const NOT_DEFINED: u16 = 1;
    pub const ONE_CHIP_COLOR: u16 = 2;
    pub const TWO_CHIP_COLOR: u16 = 3;
    pub const THREE_CHIP_COLOR: u16 = 4;
    pub const COLOR_SEQUENTIAL: u16 = 5;
    pub const TRILINEAR: u16 = 7;
    pub const COLOR_SEQUENTIAL_LINEAR: u16 = 8;
}
