# rgx-adapters-media/src

## Overview

The implementation of the media-metadata family. `lib.rs` holds the crate's
`no_std` shell, the `adapters()` factory and the five readers that live
there; the other modules hold one container family each.

The rule the whole crate is built on: **metadata, never payload**. No pixel
is decoded, no tile is unpacked, no wavelet is inverted, no frame is
decoded, no audio sample is read. What a search wants from a picture is what
the picture says about itself — its dimensions, its colour space, its
camera, and the text it carries — and all of that is in the header.

## Interface

The crate's public surface is the factory and the five readers that live in
`lib.rs`; every other reader below lives in a private module, so it is
crate-internal and no item of it is nameable from outside the crate.

- `pub fn adapters() -> Vec<Box<dyn Adapter>>` — the factory the binary's
  registry consumes, in feature order: `ExifJpeg`, `Tiff`, `imgmeta::Gif`,
  `imgmeta::Bmp`, `photos::Psd`, `photos::Jpeg2000`, `photos::JpegXl`,
  `photos::OpenExr`, `avi::AviInfo`, `asf::AsfInfo`, `flv::FlvInfo`,
  `mpeg::MpegInfo`, `AudioTags`, `Fits`, `Dicom`, `extra::FontNames`,
  `extra::Woff`, `extra::Mobi`, `mp4mkv::VideoTags`.
- `pub struct ExifJpeg` (feature `exif`) — whole-file EXIF listing for JPEG,
  PNG, WebP and TIFF alike. `impl Adapter`: `name() == "exif"`,
  `extensions() == &["jpg", "jpeg", "webp", "png"]`. Also implements
  `facts()`: `exif.make`, `exif.model`, `exif.camera`, `exif.gps`,
  `exif.datetime`.
- `pub struct Tiff` (feature `tiff`) — `impl Adapter`: `name() == "tiff"`,
  `extensions() == &["tif", "tiff"]`, with the same `facts()` set.
- `pub struct AudioTags` (feature `audio-tags`) — ID3v1/v2, RIFF INFO, FLAC
  Vorbis comment, Ogg Vorbis. `impl Adapter`: `name() == "audiotags"`,
  `extensions() == &["mp3", "wav", "flac", "ogg", "oga", "opus"]`. The
  parser is chosen from the file's extension.
- `pub struct Fits` (feature `fits`) — FITS headers. `impl Adapter`:
  `name() == "fits"`, `extensions() == &["fits", "fit", "fts"]`.
- `pub struct Dicom` (feature `dicom`) — DICOM datasets. `impl Adapter`:
  `name() == "dicom"`, `extensions() == &["dcm", "dicom", "ima"]`.
- `pub struct imgmeta::Gif` (feature `gif`) — crate-internal: `impl
  Adapter`: `name() == "gif"`, `extensions() == &["gif"]`.
- `pub struct imgmeta::Bmp` (feature `bmp`) — crate-internal: `impl
  Adapter`: `name() == "bmp"`, `extensions() == &["bmp"]`.
- `pub struct photos::Psd` (feature `psd`) — crate-internal: `impl Adapter`:
  `name() == "psd"`, `extensions() == &["psd", "psb"]`, magic `8BPS`.
- `pub struct photos::Jpeg2000` (feature `jpeg2000`) — crate-internal:
  `impl Adapter`: `name() == "jpeg2000"`,
  `extensions() == &["jp2", "j2k", "j2c", "jpf", "jpx", "jpm"]`, magic
  `\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a`.
- `pub struct photos::JpegXl` (feature `jpegxl`) — crate-internal: `impl
  Adapter`: `name() == "jpegxl"`, `extensions() == &["jxl"]`, magic
  `\x00\x00\x00\x0cJXL \x0d\x0a\x87\x0a`.
- `pub struct photos::OpenExr` (feature `openexr`) — crate-internal: `impl
  Adapter`: `name() == "openexr"`, `extensions() == &["exr"]`, magic
  `\x76\x2f\x31\x01`.
- `pub struct avi::AviInfo` (feature `avi`) — crate-internal: `impl
  Adapter`: `name() == "avi"`, `extensions() == &["avi"]`.
- `pub struct asf::AsfInfo` (feature `asf`) — crate-internal: `impl
  Adapter`: `name() == "asf"`, `extensions() == &["wmv", "asf", "wm",
  "wma"]`.
- `pub struct flv::FlvInfo` (feature `flv`) — crate-internal: `impl
  Adapter`: `name() == "flv"`, `extensions() == &["flv"]`.
- `pub struct mpeg::MpegInfo` (feature `mpeg`) — crate-internal: `impl
  Adapter`: `name() == "mpeg"`,
  `extensions() == &["ts", "mpg", "mpeg", "m2ts", "vob", "mts"]`.
- `pub struct mp4mkv::VideoTags` (feature `video-tags`) — crate-internal:
  `impl Adapter`: `name() == "videotags"`,
  `extensions() == &["mp4", "m4v", "mov", "mkv", "webm", "m4a", "ogv"]`.
  The module also exposes `pub fn extract_text(data: &[u8]) ->
  Result<String>`, the shared text extractor for the container's tags.
- `pub struct extra::FontNames` (feature `font`) — crate-internal:
  TrueType/OpenType name tables. `impl Adapter`: `name() == "font"`,
  `extensions() == &["ttf", "otf", "ttc", "otc"]`.
- `pub struct extra::Woff` (feature `woff`) — crate-internal: `impl
  Adapter`: `name() == "woff"`, `extensions() == &["woff", "woff2"]`.
- `pub struct extra::Mobi` (feature `mobi`) — crate-internal: `impl
  Adapter`: `name() == "mobi"`, `extensions() == &["mobi", "azw", "azw3",
  "prc"]`.
- `mod exif` (private; compiled when `exif`, `tiff`, `psd`, `jpeg2000` or
  `jpegxl` is on) — the crate's own EXIF reader, an independent
  reimplementation of the EXIF 2.31 / TIFF 6.0 metadata walk with no
  dependency outside `rgx-core`. Its symbols are `pub struct
  ExifReader<'a>` (`byte_order`, `ifd0`, `ifd1`, `exif_ifd`, `gps_ifd`,
  `interop_ifd`, plus `new`, `parse_container`, `parse_jpeg`, `parse_tiff`,
  `entry_value`, `get`, `get_string` and the typed accessors), `pub enum
  ByteOrder`, `pub fn find_exif_payload(&[u8]) -> Option<&[u8]>`, and —
  re-exported from its own modules — the IFD interpretation (`format_size`,
  `is_inline`, `value_offset`, `format_name`, `IfdValue`, `to_display_string`,
  `as_f64`, `as_u32`, `as_string`, `OrientationTransform`,
  `orientation_transform`), the tag vocabulary (`IfdType`, `IfdEntry`,
  `tag_name`, the `ifd0` / `exif_ifd` / `gps_ifd` / `tiff_format` modules and
  the enumerated-value modules) and the byte-order-aware TIFF readers
  (`TiffHeader`, `parse_header`, `read_u16`, `read_u32`, `read_i16`,
  `read_i32`, `read_rational`, `read_srational`, `read_f32`, `read_f64`,
  `read_string`, `read_u16_array`, `read_u32_array`, `read_rational_array`,
  `apex_to_f_number`, `apex_to_exposure_time`). It also owns the `pub mod
  makers` MakerNote support. See [exif/EGM.md](./exif/EGM.md).

## Invariants

- The crate is `#![no_std]` + `alloc`; its only dependency is `rgx-core`.
  Nothing here touches the filesystem, the clock, the environment, a socket
  or a process.
- Every adapter sits behind a Cargo feature named after the format it
  reads; the default build carries all of them.
- **Heavy payloads are never extracted.** No pixel is decoded, no tile is
  unpacked, no wavelet is inverted, no frame, packet or audio sample is
  decoded. Only the front of the file is read, and only its metadata is
  reported.
- A reader that cannot report a fact says so rather than inventing it: the
  JPEG XL adapter does not report the dimensions, because they live in the
  codestream's size header, which is entropy-coded, and a reader that
  invented them would be worse than one that says nothing. The answer reads
  `dimensions: not read (the codestream's size header is entropy-coded)`.
- A file that is not the format is declined (magic check) rather than
  answered, so the raw bytes stay searchable.
- **A MOBI's fixed fields are addressed from the start of record 0, not
  from the `MOBI` magic.** The PalmDOC header is 16 bytes, the `MOBI` magic
  sits at record-0 `0x10`, and the fields the reader wants — Full Name
  Offset (`0x54`), Full Name Length (`0x58`), EXTH flags (`0x80`) — are
  **record-0** addresses. The Full Name Offset's *value* is an offset into
  record 0 as well. Counting those fields from the magic instead lands 16
  bytes late: the "offset" read is the Output Language field, the "length"
  read is the Locale field, and the EXTH flags read falls in the 32 unknown
  bytes after the real ones — so bit `0x40` is clear, the EXTH block is
  never opened, and a valid book yields no title and no author at all.
- Because the MOBI header length is a `u32` with no lower bound, the
  reader's guard on it is not enough: the record must be at least 132 bytes
  before any of `0x54`, `0x58` and `0x80` is in range.
- An adapter must not claim an extension it cannot read. The video-tag
  reader deliberately does **not** claim `aac`: a bare `.aac` is an ADTS
  elementary stream with no `moov` at all, so the claim only ever produced
  a refusal on the one file the extension promises; with the claim gone the
  file falls through to the raw search, which is `rg`'s answer.
- The missing claim is not a cosmetic gap either. The ASF reader claims
  `wma` for the same reason it claims `wmv`: a Windows Media file and a
  Windows Media Video file are the same container, and ASF stores its
  strings as UTF-16 — so the title of a `.wma` is not findable in the raw
  bytes by a search for its own text. The video-tag reader claims `ogv`
  because an Ogg Theora video carries the same comment block the Ogg family
  shares, and the reader for it already existed.
- The audio tag parser is chosen from the file's **extension**
  (`rgx_core::extension_of`): `mp3` → ID3v2, falling back to ID3v1;
  `wav` → RIFF INFO; `flac` → Vorbis comment; `ogg`/`oga`/`opus` → Ogg
  comment. An extension with no parser is declined.
- The DICOM reader requires the `DICM` magic at offset 128 and at least 132
  bytes; the FITS reader validates the 8-character keyword rule.
- The EXIF reader is the crate's own (`exif/`), container-aware for JPEG,
  WebP, PNG and TIFF alike, and the `photos` module renders a PSD's, a
  JPEG 2000's and a JPEG XL's EXIF block the same way.

## Side Effects

- None. Every adapter is a pure function over `&[u8]`: nothing is read
  from disk, no process is spawned, no socket is opened, no clock or
  environment variable is consulted, no lock is taken. The crate allocates
  through `alloc`.

## Verification

- Run: `cargo test --release --locked --workspace`
