# rgx-adapters-media

Media metadata adapters. Heavy payloads are never extracted — not pixels,
not waveforms — only the metadata around them, so an image or a recording
is searchable without the searcher ever walking the sample data. The crate
depends on `rgx-core` alone, and the EXIF/TIFF reader under `src/exif/`
is in-house.

## What it claims

| adapter | extensions |
|---|---|
| `exif` | jpg, jpeg, webp, png |
| `tiff` | tif, tiff |
| `gif` | gif |
| `bmp` | bmp |
| `psd` | psd, psb |
| `jpeg2000` | jp2, j2k, j2c, jpf, jpx, jpm |
| `jpegxl` | jxl |
| `openexr` | exr |
| `avi` | avi |
| `asf` | wmv, asf, wm, wma |
| `flv` | flv |
| `mpeg` | ts, mpg, mpeg, m2ts, vob, mts |
| `audiotags` | mp3, wav, flac, ogg, oga, opus |
| `fits` | fits, fit, fts |
| `dicom` | dcm, dicom, ima |
| `font` | ttf, otf, ttc, otc |
| `woff` | woff, woff2 |
| `mobi` | mobi, azw, azw3, prc |
| `videotags` | mp4, m4v, mov, mkv, webm, m4a, ogv |

Every adapter declares `Reach::Reveal` and returns `Outcome::Text`: these
are binary containers whose contents ripgrep cannot read, and the
extraction is a description rather than a rendering of the same lines.

## How it works

The EXIF arm lists every IFD — primary, thumbnail, Exif, GPS, Interop —
tag by tag, and the in-house reader unwraps the container itself (JPEG
markers, WebP, PNG) rather than needing a container-aware third-party
parser. Audio tags are parsed by hand: ID3v1, RIFF INFO, the FLAC Vorbis
comment and the Ogg comment block — the one every Ogg codec carries, under
each codec's own header name (`\x03vorbis`, `OpusTags`, `\x81theora`).
The ASF arm reads the content description, whose strings are UTF-16, so a
`.wma` gives back its title the way a `.wmv` does. FITS entries are
validated by keyword shape, and DICOM by its `DICM` marker at offset 128.
The `font`, `woff` and `mobi` arms index name tables rather than glyph
data.

## Licence

Apache-2.0 only. Every file in the crate carries the SPDX header saying
so — the EXIF/TIFF reader under `src/exif/` included.
