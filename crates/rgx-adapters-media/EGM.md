# rgx-adapters-media

## Overview

The media-metadata family of `rgx`. Heavy binary payloads — pixels,
waveforms, media streams — are never extracted; only the metadata is. Audio
tags are parsed by hand (ID3v1/v2, RIFF INFO, FLAC Vorbis comment, Ogg
Vorbis), and so is EXIF/TIFF, which is why the crate's only dependency is
`rgx-core`.

The family spans the still-image formats (JPEG/PNG/WebP EXIF, TIFF, GIF,
BMP, PSD, JPEG 2000, JPEG XL, OpenEXR), the container formats (AVI, ASF/
WMV/WMA, FLV, MPEG TS/PS, MP4/MOV/MKV/WebM, FITS, DICOM), the audio tag
formats (MP3, WAV, FLAC, Ogg, Opus) and the small fixed-layout binaries
(TrueType/OpenType name tables, WOFF/WOFF2, MOBI/AZW e-books).

The crate is `#![no_std]` + `alloc` and declares no `std` feature. Every
adapter sits behind a Cargo feature named after the format it reads, and the
default build carries all of them.

## Subdirectories & Boundaries

- `src`: [src/EGM.md](./src/EGM.md) — the whole implementation: the
  `adapters()` factory and the in-crate readers (`ExifJpeg`, `Tiff`,
  `AudioTags`, `Fits`, `Dicom`), the per-container modules (`asf`, `avi`,
  `flv`, `mpeg`, `mp4mkv`, `imgmeta`, `photos`), the font/e-book module
  `extra`, and the EXIF reader tree. Public symbols: `pub fn adapters()`,
  `pub struct ExifJpeg`, `pub struct Tiff`, `pub struct AudioTags`, `pub
  struct Fits`, `pub struct Dicom`, and `impl Adapter` for each adapter.
  Every other reader — `imgmeta::Gif`, `imgmeta::Bmp`, `photos::Psd`,
  `photos::Jpeg2000`, `photos::JpegXl`, `photos::OpenExr`, `avi::AviInfo`,
  `asf::AsfInfo`, `flv::FlvInfo`, `mpeg::MpegInfo`, `mp4mkv::VideoTags`
  (with `pub fn mp4mkv::extract_text`), `extra::FontNames`, `extra::Woff`,
  `extra::Mobi` — and the whole `exif` tree live in private modules
  (`mod imgmeta;`, `mod photos;`, `mod exif;`, …), so no item of theirs is
  nameable from outside the crate.
- `src/exif`: [src/exif/EGM.md](./src/exif/EGM.md) — the crate's own EXIF
  reader: the container unwrapping, the IFD walk and the value
  interpretation, the tag vocabulary and the TIFF scalar readers.
- `src/exif/makers`: [src/exif/makers/EGM.md](./src/exif/makers/EGM.md) —
  the MakerNote support: the per-vendor tag tables and the MakerNote IFD
  parser for the makers whose MakerNote is a plain TIFF directory.
