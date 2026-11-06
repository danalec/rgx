// SPDX-License-Identifier: Apache-2.0

//! The **JEDMICS C4** compressed image file, read as a rendering.
//!
//! **What a C4 file is.** The compressed image of the US Army's EDMICS
//! standard, as fixed by the *JEDMICS C4 Compressed Image File Format
//! Technical Specification* (version 1.0, 8 April 2002, Northrop Grumman
//! Information Technology). The file is, in order: a 128-byte header, a
//! tile index of four bytes per tile, the compressed image data — CCITT
//! Group 4 (ITU-T T.6) tiles of 512 by 512 pixels — and, optionally, a
//! preview tile index and the preview data (zero or six tiles).
//!
//! **The header's byte order is mixed, and that is the whole of the
//! difficulty.** The index offset, the line height, the byte width and the
//! preview index offset are Intel (little-endian); the data offset, the
//! preview data offset, the file type, the QA flag and the dpi are network
//! (big-endian). Reading either family with the other's order yields a
//! header that looks plausible and is wrong: the index offset becomes
//! 0x80000000, the line height 23456, and the file then claims its data
//! lives at an offset no file of its shape could have.
//!
//! **Why it is revealed and not rendered.** `rg` cannot read the file. The
//! bytes are a binary struct and a compressed raster, and none of the
//! numbers in them are greppable. This is [`Reach::Reveal`]: the adapter
//! surfaces bytes the raw searcher cannot reach.
//!
//! **What the rendering is for.** The header says the image is 1728 pels
//! wide, 2200 pels high and 200 dpi — in binary, spread over fields of two
//! different byte orders. The rendering says it in a line of text, so "the
//! image is 1728 pels wide at 200 dpi" is findable. The tile index, the
//! geometry's other half, is rendered with it: how many tiles the image is
//! cut into, how wide and how high they are, how many bytes each holds,
//! and whether it is stored compressed or raw.
//!
//! **What it does not do.** It does not decode a tile. The header and the
//! tile index are read; the pixels are not, and the preview is reported as
//! what the header says about it and not decoded either.

use alloc::string::{String, ToString};
use core::fmt::Write as _;
use rgx_core::{decline, Adapter, Outcome, Reach, Result};

/// Bytes one rendering may produce.
///
/// The input is already in memory — the walker reads the file whole before
/// an adapter sees it — so this is not a bound on what can be read, it is a
/// bound on how much *more* the rendering may cost.
const MAX_RENDER: usize = 64 << 20;

/// The C4 header: 128 bytes.
const HEADER_LEN: usize = 128;

/// A tile index entry: four bytes.
const INDEX_LEN: usize = 4;

/// A tile is 512 by 512 pixels.
const TILE_PELS: u32 = 512;

/// The tiles the index's one-byte tile number can name. Past this the
/// format changes and the tile number is dropped from the index.
const MAX_NAMED_TILES: u32 = 252;

/// A raw tile: 512 by 512 pixels, one bit each.
const RAW_TILE_BYTES: u32 = 32768;

/// A JEDMICS C4 compressed image.
pub struct C4;

impl Adapter for C4 {
    fn name(&self) -> &'static str {
        "edmics-c4"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["c4"]
    }

    /// The bytes are a binary struct and a compressed raster: `rg` reads
    /// neither.
    fn reach(&self) -> Reach {
        Reach::Reveal
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_c4(data)?.into_bytes()))
    }
}

/// The 128-byte C4 header.
struct Header {
    /// The offset of the tile index. The specification fixes it at 128.
    index_offset: u32,
    /// The height of the image in pixels.
    line_height: u16,
    /// The width of the image in bytes.
    byte_width: u16,
    /// The offset of the compressed tiles.
    data_offset: u32,
    /// The number of tiles, when it fits in one byte; 0 when it does not.
    number_of_tiles: u8,
    /// The offset of the preview tile index; 0 when there is no preview.
    preview_index_offset: u32,
    /// The height of the preview in pixels.
    preview_height: u16,
    /// The width of the preview in bytes.
    preview_width: u16,
    /// The number of preview tiles: 0 or 6.
    preview_tiles: u8,
    /// The data format code: 4, or 6 when there are more than 252 tiles.
    format: u8,
    /// The resolution the image was scanned at.
    dpi: u16,
    /// The Hollerith aperture-card field.
    hollerith: String,
}

impl Header {
    /// Reads the header.
    ///
    /// The reads are the specification's own, and the two byte orders sit
    /// next to each other on purpose: the index offset is Intel and the
    /// data offset is network, and a reader that gets one of them wrong
    /// reads a file that says its data is somewhere it cannot be.
    fn parse(data: &[u8]) -> Result<Header> {
        let Some(slice) = data.get(..HEADER_LEN) else {
            decline!("c4: the file is shorter than the {HEADER_LEN}-byte header");
        };
        let Ok(head) = <&[u8; HEADER_LEN]>::try_from(slice) else {
            decline!("c4: the file is shorter than the {HEADER_LEN}-byte header");
        };

        let index_offset = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
        let line_height = u16::from_le_bytes([head[4], head[5]]);
        let byte_width = u16::from_le_bytes([head[6], head[7]]);
        let data_offset = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
        let number_of_tiles = head[12];
        let preview_index_offset = u32::from_le_bytes([head[14], head[15], head[16], head[17]]);
        let preview_height = u16::from_le_bytes([head[18], head[19]]);
        let preview_width = u16::from_le_bytes([head[20], head[21]]);
        let preview_tiles = head[26];
        let format = head[36];
        let dpi = u16::from_be_bytes([head[38], head[39]]);

        // The Hollerith field is 80 bytes of null-padded ASCII; the text
        // ends at the first null.
        let raw = &head[41..121];
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        let hollerith = String::from_utf8_lossy(&raw[..end]).trim().to_string();

        Ok(Header {
            index_offset,
            line_height,
            byte_width,
            data_offset,
            number_of_tiles,
            preview_index_offset,
            preview_height,
            preview_width,
            preview_tiles,
            format,
            dpi,
            hollerith,
        })
    }

    /// The resolution to assume.
    ///
    /// The specification says a dpi of 0 or of more than 400 means 200,
    /// which is what every legacy JEDMICS scanner produced.
    fn effective_dpi(&self) -> u16 {
        if self.dpi == 0 || self.dpi > 400 {
            200
        } else {
            self.dpi
        }
    }
}

/// What the tile index says about the tiles.
struct Index {
    /// How many tiles there are.
    count: u32,
    /// The smallest tile's data size.
    smallest: u32,
    /// The largest tile's data size.
    largest: u32,
    /// How many tiles are stored raw.
    raw: u32,
}

/// The C4 rendering: the header's geometry, and the tile index behind it.
fn render_c4(data: &[u8]) -> Result<String> {
    let header = Header::parse(data)?;

    // The geometry the specification computes out of the header.
    let tile_height = u32::from(header.line_height).div_ceil(TILE_PELS);
    let tile_width = (u32::from(header.byte_width) * 8).div_ceil(TILE_PELS);
    let tile_count = tile_height * tile_width;

    // The specification's error conditions. A file that breaks one of them
    // is not a C4 file this reader can answer for, and each one says what
    // it broke.
    if header.index_offset != HEADER_LEN as u32 {
        decline!(
            "c4: the index offset is {}, not the {HEADER_LEN} the specification fixes",
            header.index_offset
        );
    }
    if header.format != 4 && header.format != 6 {
        decline!("c4: the format is {}, not 4 or 6", header.format);
    }
    if header.format == 4 && tile_count > MAX_NAMED_TILES {
        decline!(
            "c4: the format is 4 but the geometry gives {tile_count} tiles, more than {MAX_NAMED_TILES}"
        );
    }
    if header.format == 6 && header.number_of_tiles != 0 {
        decline!(
            "c4: the format is 6 but the header says {} tiles",
            header.number_of_tiles
        );
    }
    // The header's own tile count is the count the format holds: past 252
    // it is 0, and below it it is the number of tiles.
    if header.format == 4 && u32::from(header.number_of_tiles) != tile_count {
        decline!(
            "c4: the header says {} tiles, the geometry gives {tile_count}",
            header.number_of_tiles
        );
    }
    // The data follows the tile index, and the header has to say so.
    let expected = HEADER_LEN as u32 + INDEX_LEN as u32 * tile_count;
    if header.data_offset != expected {
        decline!(
            "c4: the data offset is {}, not the {expected} that {tile_count} tile index entries need",
            header.data_offset
        );
    }

    let index = read_index(data, tile_count, header.data_offset)?;

    let summary = format!(
        "c4: {}x{} pixels ({} bytes wide), {} dpi, {} tiles",
        u32::from(header.byte_width) * 8,
        header.line_height,
        header.byte_width,
        header.effective_dpi(),
        tile_count
    );

    let mut body = String::new();
    let _ = writeln!(body, "format: {}", header.format);

    // The tile index, in one line: how the image is cut up, how big the
    // pieces are, and whether they are compressed at all.
    let sizes = if index.count == 0 {
        String::new()
    } else if index.smallest == index.largest {
        format!(", {} bytes per tile", index.smallest)
    } else {
        format!(", {}-{} bytes per tile", index.smallest, index.largest)
    };
    let compression = if index.count == 0 {
        "no tiles".to_string()
    } else if index.raw == 0 {
        "G4 compressed".to_string()
    } else if index.raw == index.count {
        format!("raw (negative compression), {RAW_TILE_BYTES} bytes per tile")
    } else {
        format!(
            "{} G4 compressed, {} raw",
            index.count - index.raw,
            index.raw
        )
    };
    let _ = writeln!(
        body,
        "tiles: {tile_width} wide x {tile_height} high, {} index entries{sizes}, {compression}",
        index.count
    );

    // The Hollerith field, and the preview.
    if header.hollerith.is_empty() {
        let _ = writeln!(body, "hollerith: none");
    } else {
        let _ = writeln!(body, "hollerith: {}", header.hollerith);
    }
    if header.preview_index_offset == 0 {
        let _ = writeln!(body, "preview: none");
    } else {
        let _ = writeln!(
            body,
            "preview: {} pixels high, {} bytes wide, {} tiles",
            header.preview_height, header.preview_width, header.preview_tiles
        );
    }

    Ok(finish(&summary, &body))
}

/// Reads the tile index: one four-byte entry per tile.
///
/// The entry is the tile number, the negative compression flag and the size
/// of the tile's data. The tile number is ignored when there are more than
/// 252 tiles — the index is then in row-major order — but the flag and the
/// size are always there.
fn read_index(data: &[u8], count: u32, data_offset: u32) -> Result<Index> {
    let mut smallest = u32::MAX;
    let mut largest = 0u32;
    let mut raw = 0u32;
    let mut total: usize = 0;

    for tile in 0..count {
        let at = HEADER_LEN + tile as usize * INDEX_LEN;
        let Some(entry) = data.get(at..at + INDEX_LEN) else {
            decline!("c4: the tile index ends before tile {tile}");
        };
        let (_number, flag, lo, hi) = match entry {
            [number, flag, lo, hi] => (number, flag, lo, hi),
            _ => decline!("c4: the tile index entry for tile {tile} is not four bytes"),
        };
        // The size of the tile's data, Intel order.
        let size = u32::from(u16::from_le_bytes([*lo, *hi]));
        // A non-zero negative compression flag means the tile is stored raw,
        // uncompressed, in 32768 bytes.
        if *flag != 0 {
            raw += 1;
        }
        smallest = smallest.min(size);
        largest = largest.max(size);
        total = total.saturating_add(size as usize);
    }

    // The tile data has to be in the file: a header that says its data is
    // longer than the file is a header that lies.
    let end = total.saturating_add(data_offset as usize);
    if end > data.len() {
        decline!(
            "c4: the tile data ends at {end} bytes, the file holds {}",
            data.len()
        );
    }

    Ok(Index {
        count,
        smallest,
        largest,
        raw,
    })
}

/// Composes a rendering: the summary in front, the tile index behind it.
///
/// The summary goes first because it is the question the file answers
/// slowest, and the index behind it because it is the question the user is
/// usually asking.
fn finish(summary: &str, body: &str) -> String {
    let mut out = String::with_capacity(body.len() + summary.len() + 64);
    let _ = writeln!(out, "{summary}");
    if body.len() <= MAX_RENDER {
        out.push_str(body);
        return out;
    }
    // Cut on a line boundary: a rendering that stops in the middle of a
    // record is a record that reads as if it were whole.
    let bytes = body.as_bytes();
    let mut cut = MAX_RENDER.min(bytes.len());
    while cut > 0 && !body.is_char_boundary(cut) {
        cut -= 1;
    }
    let cut = body[..cut].rfind('\n').map(|i| i + 1).unwrap_or(cut);
    out.push_str(&body[..cut]);
    let _ = writeln!(
        out,
        "note: the rendering stopped at the {MAX_RENDER}-byte ceiling; the rest of the file is not shown"
    );
    out
}

#[cfg(test)]
mod tests {
    //! The fixture is written to the specification and kept as a file, so
    //! the end-to-end run reads the same bytes the unit tests read.
    //!
    //! The header's numbers are asserted one by one: a header that drifts
    //! away from its own tile index has to fail the test, not pass it.

    use super::*;

    const C4: &[u8] = include_bytes!("../testdata/sample.c4");

    /// The rendering the fixture produces, line for line.
    const EXPECTED: &str = "\
c4: 1728x2200 pixels (216 bytes wide), 200 dpi, 20 tiles
format: 4
tiles: 4 wide x 5 high, 20 index entries, 170-189 bytes per tile, G4 compressed
hollerith: none
preview: none
";

    #[test]
    fn the_fixture_renders_as_expected() {
        let out = render_c4(C4).expect("a c4 is ours");
        assert_eq!(out, EXPECTED);
    }

    #[test]
    fn the_header_carries_the_numbers_its_index_needs() {
        let header = Header::parse(C4).expect("a c4 is ours");
        assert_eq!(header.index_offset, 128);
        assert_eq!(header.line_height, 2200);
        assert_eq!(header.byte_width, 216);
        assert_eq!(header.number_of_tiles, 20);
        assert_eq!(header.format, 4);
        assert_eq!(header.dpi, 200);
        assert_eq!(header.effective_dpi(), 200);
        assert_eq!(header.preview_index_offset, 0);
        assert_eq!(header.preview_tiles, 0);
        assert!(header.hollerith.is_empty());

        // The geometry the specification computes, and the data offset that
        // has to agree with it.
        let tile_height = u32::from(header.line_height).div_ceil(TILE_PELS);
        let tile_width = (u32::from(header.byte_width) * 8).div_ceil(TILE_PELS);
        assert_eq!((tile_width, tile_height), (4, 5));
        assert_eq!(tile_width * tile_height, 20);
        assert_eq!(header.data_offset, 208);
        assert_eq!(header.data_offset, HEADER_LEN as u32 + 4 * 20);

        // The index itself: twenty entries, and their data fills the file.
        let index = read_index(C4, 20, header.data_offset).expect("a c4 is ours");
        assert_eq!(index.count, 20);
        assert_eq!(index.smallest, 170);
        assert_eq!(index.largest, 189);
        assert_eq!(index.raw, 0);
        let total: usize = (0..20)
            .map(|i| {
                let at = HEADER_LEN + i * INDEX_LEN;
                let entry = &C4[at..at + INDEX_LEN];
                u16::from_le_bytes([entry[2], entry[3]]) as usize
            })
            .sum();
        assert_eq!(C4.len(), 208 + total);
    }

    #[test]
    fn a_file_that_is_not_a_c4_is_declined() {
        let err = render_c4(b"not a c4 file at all").expect_err("not a c4");
        assert!(err.is_decline(), "{err}");
        // A file that starts with the right index offset but says nothing
        // sensible about its tiles is not a C4 file either.
        let mut wrong = C4.to_vec();
        wrong[36] = 9;
        let err = render_c4(&wrong).expect_err("not a c4");
        assert!(err.is_decline(), "{err}");
    }

    #[test]
    fn a_truncated_c4_is_declined_and_not_a_panic() {
        // Every prefix of the file is declined, and none of them panics.
        for len in [0usize, 1, 4, 12, 127, 128, 129, 207, 208, 209, 3803] {
            let cut = &C4[..len.min(C4.len())];
            let err = render_c4(cut).expect_err("truncated");
            assert!(err.is_decline(), "at {len} bytes: {err}");
        }
    }

    #[test]
    fn a_header_that_lies_about_where_its_data_is_is_declined() {
        // The data offset has to be the end of the tile index.
        let mut lying = C4.to_vec();
        lying[8..12].copy_from_slice(&(208u32 + 4).to_be_bytes());
        let err = render_c4(&lying).expect_err("a header that lies");
        assert!(err.is_decline(), "{err}");
        assert!(err.to_string().contains("data offset"), "{err}");

        // And a header that is off by more than a tile is the same case.
        let mut elsewhere = C4.to_vec();
        elsewhere[8..12].copy_from_slice(&53_268u32.to_be_bytes());
        let err = render_c4(&elsewhere).expect_err("a header that lies");
        assert!(err.is_decline(), "{err}");
        assert!(err.to_string().contains("data offset"), "{err}");
    }

    #[test]
    fn the_two_byte_orders_are_not_interchangeable() {
        // The index offset, the line height and the byte width are Intel;
        // the data offset and the dpi are network. A header written with
        // the wrong order for the first three is not a C4 file.
        let mut swapped = C4.to_vec();
        swapped[0..4].copy_from_slice(&128u32.to_be_bytes());
        let err = render_c4(&swapped).expect_err("a swapped header");
        assert!(err.is_decline(), "{err}");
        assert!(err.to_string().contains("index offset"), "{err}");

        // And a header whose *network* fields were written little-endian is
        // read differently: the data offset stops being where the index
        // ends.
        let mut swapped = C4.to_vec();
        swapped[8..12].copy_from_slice(&208u32.to_le_bytes());
        let err = render_c4(&swapped).expect_err("a swapped header");
        assert!(err.is_decline(), "{err}");
        assert!(err.to_string().contains("data offset"), "{err}");

        // The dpi is network order too: written the other way it is read as
        // 51200, which the specification says means 200.
        let mut swapped = C4.to_vec();
        swapped[38..40].copy_from_slice(&200u16.to_le_bytes());
        let header = Header::parse(&swapped).expect("a c4 is ours");
        assert_eq!(header.dpi, 51_200);
        assert_eq!(header.effective_dpi(), 200);
    }

    #[test]
    fn a_format_six_file_is_read() {
        // More than 252 tiles: the format is 6, the tile number is dropped
        // and the header's count is 0.
        let line_height = 512u16;
        let byte_width = 16_192u16;
        let tile_height = u32::from(line_height).div_ceil(TILE_PELS);
        let tile_width = (u32::from(byte_width) * 8).div_ceil(TILE_PELS);
        let count = tile_height * tile_width;
        assert_eq!(count, 253);

        let mut file = vec![0u8; HEADER_LEN + 4 * count as usize];
        file[0..4].copy_from_slice(&128u32.to_le_bytes());
        file[4..6].copy_from_slice(&line_height.to_le_bytes());
        file[6..8].copy_from_slice(&byte_width.to_le_bytes());
        let data_offset = HEADER_LEN as u32 + 4 * count;
        file[8..12].copy_from_slice(&data_offset.to_be_bytes());
        file[12] = 0;
        file[36] = 6;
        file[38..40].copy_from_slice(&200u16.to_be_bytes());

        let out = render_c4(&file).expect("a c4 is ours");
        assert!(
            out.contains("c4: 129536x512 pixels (16192 bytes wide), 200 dpi, 253 tiles"),
            "{out}"
        );
        assert!(out.contains("format: 6"), "{out}");
    }

    #[test]
    fn a_raw_tile_is_reported_as_raw() {
        // The negative compression flag is non-zero, so the tile is stored
        // uncompressed.
        let mut raw = C4.to_vec();
        raw[HEADER_LEN + 1] = 1;
        let out = render_c4(&raw).expect("a c4 is ours");
        assert!(out.contains("19 G4 compressed, 1 raw"), "{out}");
    }
}
