# rgx-adapters-media/src/exif

## Overview

The crate's own EXIF reader — an independent reimplementation of the
EXIF 2.31 / TIFF 6.0 metadata walk, with no dependency outside
`rgx-core`. It is what the media crate's `ExifJpeg` and `Tiff` adapters,
and the `photos` module's PSD / JPEG 2000 / JPEG XL readers, all use.

The reader has five parts. `mod.rs` owns the container unwrapping and the
IFD walk; `ifd.rs` owns the interpretation of one 12-byte IFD entry;
`tags.rs` owns the tag vocabulary; `tiff.rs` owns the byte-order-aware
scalar readers the walk needs; `makers/` owns the vendor MakerNote tables
and parser.

The one thing the walk is easy to get wrong, and the one a 6-byte skew
hides in: **value offsets are relative to the TIFF header**, which is not
buffer zero when the payload is wrapped in a JPEG APP1 segment's
`Exif\0\0` prefix.

## Interface

- `pub struct ExifReader<'a>` — the reader. Public fields: `byte_order:
  ByteOrder`, `ifd0: Vec<IfdEntry>`, `ifd1: Vec<IfdEntry>` (the thumbnail
  IFD), `exif_ifd: Vec<IfdEntry>`, `gps_ifd: Vec<IfdEntry>`,
  `interop_ifd: Vec<IfdEntry>`.
  - `pub fn new(data: &'a [u8]) -> Self` — an empty reader.
  - `pub fn parse_container(data: &'a [u8]) -> Result<ExifReader<'a>,
    String>` — unwraps the container (JPEG APP1, WebP RIFF `EXIF`, PNG
    `eXIf`, bare TIFF) and then parses the payload.
  - `pub fn parse_jpeg(&mut self) -> Result<(), String>` — parses the
    `Exif\0\0`-prefixed payload of a JPEG APP1 segment.
  - `pub fn parse_tiff(&mut self) -> Result<(), String>` — parses a bare
    TIFF payload.
  - `pub fn entry_value(&self, entry: &IfdEntry) -> String`,
    `pub fn get(&self, tag: u16) -> Option<&IfdEntry>`,
    `pub fn get_string(&self, tag: u16) -> Option<String>`.
  - Convenience accessors: `datetime_original()`, `datetime()`, `make()`,
    `model()`, `get_gps() -> Option<(f64, f64)>`, `iso() -> Option<u16>`,
    `focal_length() -> Option<f64>`, `f_number() -> Option<f64>`,
    `exposure_time() -> Option<f64>`, `image_width() -> Option<u32>`,
    `image_height() -> Option<u32>`, `orientation() -> Option<u16>`,
    `x_resolution() -> Option<f64>`, `y_resolution() -> Option<f64>`.
- `pub enum ByteOrder` — `LittleEndian` (the default) or `BigEndian`.
- `pub fn find_exif_payload(data: &[u8]) -> Option<&[u8]>` — unwraps the
  containers EXIF is shipped in: JPEG (APP1 marker scan), WebP (RIFF `EXIF`
  chunk), PNG (`eXIf` chunk, bare TIFF), and a bare TIFF/GeoTIFF passed
  through as-is.
- Re-exported from the child modules (`pub use ifd::*; pub use tags::*;
  pub use tiff::*;`):
  - `ifd`: `pub fn format_size(format: u16) -> usize` (the §4.5 type table),
    `pub fn is_inline(entry: &IfdEntry) -> bool`,
    `pub fn value_offset(entry: &IfdEntry, base_offset: usize) -> usize`,
    `pub fn format_name(format: u16) -> &'static str`,
    `pub enum IfdValue`, `pub fn to_display_string(&self) -> String`,
    `pub fn as_f64(&self) -> Option<f64>`,
    `pub fn as_u32(&self) -> Option<u32>`,
    `pub fn as_string(&self) -> Option<&str>`,
    `pub struct OrientationTransform`,
    `pub fn orientation_transform(orientation: u16) -> OrientationTransform`.
  - `tags`: `pub enum IfdType` (`Ifd0`, `Ifd1`, `Exif`, `Gps`, `Interop`,
    `MakerNote`), `pub struct IfdEntry` (`tag`, `format`, `count`,
    `value_offset`, `value`, and the IFD type the entry belongs to),
    `pub fn tag_name(tag: u16) -> Option<&'static str>`, the tag-identifier
    modules `ifd0`, `exif_ifd` and `gps_ifd` (the Interop pointer,
    `INTEROP_IFD_POINTER`, lives in `exif_ifd`), the TIFF type table
    `tiff_format`, and the enumerated-value modules (`compression`,
    `orientation`, `exposure_program`, `metering_mode`, `light_source`,
    `flash`, `color_space`, `sensing_method`).
  - `tiff`: `pub struct TiffHeader` (`byte_order`, `magic`, `ifd0_offset`),
    `pub fn parse_header(data: &[u8]) -> Result<TiffHeader, String>`, the
    byte-order-aware readers `read_u16`, `read_u32`, `read_i16`, `read_i32`,
    `read_rational`, `read_srational`, `read_f32`, `read_f64`,
    `read_string`, `read_u16_array`, `read_u32_array`,
    `read_rational_array`, and the APEX conversions `apex_to_f_number`,
    `apex_to_exposure_time`.
- `pub mod makers` — the MakerNote support: the per-vendor tag tables and
  the MakerNote IFD parser for the makers whose MakerNote is a plain TIFF
  directory. Its public symbols are `pub enum Maker` (`Canon`, `Nikon`,
  `Sony`, `Olympus`, `FujiFilm`, `Panasonic`, `Pentax`, `Ricoh`, `Samsung`,
  `Leica`, `Sigma`, `Apple`, `Unknown`) with `pub fn from_make(&str) ->
  Self`, `pub struct MakerNoteEntry`, `pub fn parse_makernote(&[u8], Maker)
  -> Vec<MakerNoteEntry>`, `pub fn makernote_tag_name(Maker, u16) ->
  Option<&'static str>`, and the tag-identifier modules `canon`, `nikon`,
  `sony` and `fuji`. See [makers/EGM.md](./makers/EGM.md).

## Invariants

- **An IFD entry is 12 bytes**: tag, type, count, then a 4-byte value slot.
- A value of `type_size × count ≤ 4` bytes lives **inline** in the slot, in
  the file's byte order — which for a 1- or 2-byte value in a big-endian
  file means the *high* bytes of the slot, so the numeric value is the slot
  shifted down. Anything longer stores an offset to the value, **relative to
  the TIFF header**.
- `format_size` is the §4.5 type table exactly; an unknown type has no size
  and must not be treated as one of the known ones.
- The `IfdValue` conversions never fabricate: a zero denominator is not a
  number, and only the types that are already numeric convert to `f64` /
  `u32`.
- The orientation mapping is the EXIF 2.31 §4.6.4 table: values 2-4 flip,
  5-8 also rotate, and anything outside 1-8 is the identity.
- IFD1 is the thumbnail IFD at the next-IFD offset of IFD0; the pointer
  tags (Exif `0x8769`, GPS `0x8825`, Interop `0xA005`) name the others.
- Every TIFF field is stored in the file's byte order (`II` little-endian,
  `MM` big-endian, declared once in the header), and the value readers take
  that order explicitly rather than holding state.
- Every reader is bounds-checked against the slice and returns `Err` on a
  short buffer — a truncated image must not panic the walk that feeds these.
- `read_string` is the one that does not fail: an ASCII field is cut at the
  first NUL, and a field that runs off the end of the buffer yields the
  part that is there (or empty), because a metadata walk over a damaged file
  still has whatever tags preceded the damage to report.
- The tag numbers are the specification's; nothing in `tags.rs` is a
  transcription of another implementation's code. The *names* follow the
  ExifTool spelling, because that is the vocabulary users search with — an
  unknown tag has no name and the caller prints its id.
- The tag vocabulary and the MakerNote tables are `pub` constants with no
  internal users; the module carries an explicit `#![allow(dead_code)]`
  because the unused pass fires on names the lookups still serve by table.

## Side Effects

- None. The reader is a pure function over `&[u8]`: it reads nothing from
  disk, spawns no process, consults no clock or environment variable, takes
  no lock. It allocates through `alloc`.

## Verification

- Run: `cargo test --release --locked --workspace`
