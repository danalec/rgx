// SPDX-License-Identifier: Apache-2.0

//! Page-structured raster documents: multi-page TIFF and DjVu.
//!
//! Both are "documents that happen to be pixels": the searchable payload is
//! not the image data but the *structure around it* — a TIFF's per-page tags
//! carry a camera model, a scan operator, a caption and a document name, and
//! a DjVu's annotation chunks carry the OCR-free text a person typed onto
//! the page. Neither is reachable without walking a chain, which is why the
//! generic binary scan reports "TIFF" and stops.

use alloc::string::String;
#[cfg(feature = "tiff")]
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt::Write as _;

use rgx_core::{decline, Adapter, Outcome, Result};

// ---------------------------------------------------------------------------
// TIFF
// ---------------------------------------------------------------------------

#[cfg(feature = "tiff")]
const TAG_WIDTH: u16 = 256;
#[cfg(feature = "tiff")]
const TAG_HEIGHT: u16 = 257;
#[cfg(feature = "tiff")]
const TAG_BITS: u16 = 258;
#[cfg(feature = "tiff")]
const TAG_COMPRESSION: u16 = 259;
#[cfg(feature = "tiff")]
const TAG_PHOTOMETRIC: u16 = 262;
#[cfg(feature = "tiff")]
const TAG_DESCRIPTION: u16 = 270;
#[cfg(feature = "tiff")]
const TAG_MAKE: u16 = 271;
#[cfg(feature = "tiff")]
const TAG_MODEL: u16 = 272;
#[cfg(feature = "tiff")]
const TAG_STRIP_OFFSETS: u16 = 273;
#[cfg(feature = "tiff")]
const TAG_SAMPLES: u16 = 277;
#[cfg(feature = "tiff")]
const TAG_ROWS_PER_STRIP: u16 = 278;
#[cfg(feature = "tiff")]
const TAG_STRIP_BYTES: u16 = 279;
#[cfg(feature = "tiff")]
const TAG_X_RES: u16 = 282;
#[cfg(feature = "tiff")]
const TAG_Y_RES: u16 = 283;
#[cfg(feature = "tiff")]
const TAG_RESOLUTION_UNIT: u16 = 296;
#[cfg(feature = "tiff")]
const TAG_PAGE_NUMBER: u16 = 297;
#[cfg(feature = "tiff")]
const TAG_SOFTWARE: u16 = 305;
#[cfg(feature = "tiff")]
const TAG_DATETIME: u16 = 306;
#[cfg(feature = "tiff")]
const TAG_PREDICTOR: u16 = 317;
#[cfg(feature = "tiff")]
const TAG_T4_OPTIONS: u16 = 292;
#[cfg(feature = "tiff")]
const TAG_T6_OPTIONS: u16 = 293;
#[cfg(feature = "tiff")]
const TAG_JPEG_OFFSET: u16 = 513;
#[cfg(feature = "tiff")]
const TAG_JPEG_BYTES: u16 = 514;
#[cfg(feature = "tiff")]
const TAG_SUBIFDS: u16 = 330;

/// Pages a walk will report, and the IFDs it will follow. A TIFF whose chain
/// loops is real (some writers produce one), so the bound is what stops it.
#[cfg(feature = "tiff")]
const MAX_PAGES: usize = 2048;

#[cfg(feature = "tiff")]
pub struct Tiff;
#[cfg(feature = "tiff")]
impl Adapter for Tiff {
    /// Named distinctly from `rgx-adapters-media`'s `tiff`: both read TIFF, and
    /// `--json` and `--explain-engine` name the adapter that answered, so two
    /// adapters called "tiff" would make the output unactionable.
    fn name(&self) -> &'static str {
        "tiff-pages"
    }
    /// The camera RAW containers here are the ones that *are* TIFF: a CR2, a
    /// DNG, a NEF, a Sony ARW, a Pentax PEF, a Samsung SRW and a Panasonic
    /// RW2 all carry an ordinary TIFF IFD chain, and the reader below walks
    /// it. The ones that are not — an Olympus ORF, a Canon CRW, a Fujifilm
    /// RAF, a Sigma X3F — have a container of their own, so they are not
    /// claimed here: a file that falls back to the raw search is a better
    /// answer than one read as a TIFF it is not.
    fn extensions(&self) -> &'static [&'static str] {
        &[
            "tif", "tiff", "nef", "dng", "arw", "cr2", "pef", "srw", "rw2",
        ]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if !Tiff::is_tiff(data) {
            decline!("not a TIFF (bad byte-order mark)");
        }
        Ok(Outcome::Text(tiff_report(data)))
    }
}

#[cfg(feature = "tiff")]
impl Tiff {
    fn is_tiff(d: &[u8]) -> bool {
        matches!(
            d.get(..4),
            Some([0x49, 0x49, 0x2A, 0x00]) | Some([0x4D, 0x4D, 0x00, 0x2A])
        ) || matches!(
            d.get(..4),
            Some([0x49, 0x49, 0x2B, 0x00]) | Some([0x4D, 0x4D, 0x00, 0x2B])
        ) || matches!(
            d.get(..4),
            // Panasonic's RW2 keeps TIFF's layout and puts 0x55 in the slot
            // where the magic number goes, so its byte-order mark is not the
            // one a TIFF has. Everything after it is an ordinary TIFF IFD
            // chain, which is what the reader below walks.
            Some([0x49, 0x49, 0x55, 0x00])
        )
    }
}

#[cfg(feature = "tiff")]
struct TiffReader<'a> {
    d: &'a [u8],
    big: bool,
    /// BigTIFF widens every offset and count to eight bytes.
    big_tiff: bool,
    /// What the container is called in the report: a plain TIFF, a BigTIFF or
    /// a Panasonic RW2, which is a TIFF with a different magic number.
    variant: &'static str,
}

#[cfg(feature = "tiff")]
impl<'a> TiffReader<'a> {
    fn open(d: &'a [u8]) -> Option<Self> {
        let head = d.get(..4)?;
        let big = head[0] == b'M';
        match head {
            [0x49, 0x49, 0x2A, 0x00] | [0x4D, 0x4D, 0x00, 0x2A] => Some(TiffReader {
                d,
                big,
                big_tiff: false,
                variant: "classic",
            }),
            // BigTIFF: the version tag is 43, and every offset, length and
            // entry grows from 32 bits to 64. Reading a BigTIFF with 32-bit
            // offsets yields a plausible-looking chain of garbage.
            [0x49, 0x49, 0x2B, 0x00] | [0x4D, 0x4D, 0x00, 0x2B] => Some(TiffReader {
                d,
                big,
                big_tiff: true,
                variant: "BigTIFF",
            }),
            // Panasonic RW2: the magic number is 0x55 instead of 0x2A, and the
            // IFD chain that follows is an ordinary TIFF one.
            [0x49, 0x49, 0x55, 0x00] => Some(TiffReader {
                d,
                big: false,
                big_tiff: false,
                variant: "RW2",
            }),
            _ => None,
        }
    }

    fn u16(&self, at: usize) -> Option<u16> {
        let b = self.d.get(at..at + 2)?;
        Some(if self.big {
            u16::from_be_bytes([b[0], b[1]])
        } else {
            u16::from_le_bytes([b[0], b[1]])
        })
    }

    fn u32(&self, at: usize) -> Option<u32> {
        let b = self.d.get(at..at + 4)?;
        Some(if self.big {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        })
    }

    fn u64(&self, at: usize) -> Option<u64> {
        let b = self.d.get(at..at + 8)?;
        let a: [u8; 8] = [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];
        Some(if self.big {
            u64::from_be_bytes(a)
        } else {
            u64::from_le_bytes(a)
        })
    }

    /// Width of the **value/offset** field of one IFD entry, and of the
    /// next-IFD link: 4 bytes in a classic TIFF, 8 in a BigTIFF.
    fn offset_width(&self) -> usize {
        if self.big_tiff {
            8
        } else {
            4
        }
    }

    /// Width of the entry count **inside** one IFD entry: 4 bytes classic,
    /// 8 BigTIFF.
    ///
    /// This is not [`Self::ifd_count_width`] either. The count that opens a
    /// directory is 2 bytes in a classic TIFF while the count inside each of its
    /// entries is 4, so one shared reader for the two silently truncates every
    /// entry count -- and on BigTIFF all three widths are 8, so the mistake never
    /// shows up there.
    fn entry_count_width(&self) -> usize {
        if self.big_tiff {
            8
        } else {
            4
        }
    }

    /// Width of the entry count that **opens** an IFD: 2 bytes classic, 8 BigTIFF.
    fn ifd_count_width(&self) -> usize {
        if self.big_tiff {
            8
        } else {
            2
        }
    }

    /// An IFD link: an **offset**, so it is read at the offset width, never at
    /// the count width. Reading a classic TIFF's 4-byte next-IFD pointer through
    /// a 2-byte count reader keeps only its high half, which makes every page
    /// chain look like it ends after one page.
    fn offset_at(&self, at: usize) -> Option<u64> {
        if self.big_tiff {
            self.u64(at)
        } else {
            self.u32(at).map(u64::from)
        }
    }

    fn entry_size(&self) -> usize {
        if self.big_tiff {
            20
        } else {
            12
        }
    }

    fn first_ifd(&self) -> Option<u64> {
        if self.big_tiff {
            // BigTIFF adds an 8-byte offset to the header plus a 2-byte
            // count and 8 reserved bytes before the first offset.
            self.u64(8)
        } else {
            self.u32(4).map(u64::from)
        }
    }

    /// The count that opens the directory at `at`.
    fn ifd_count_at(&self, at: usize) -> Option<u64> {
        if self.big_tiff {
            self.u64(at)
        } else {
            self.u16(at).map(u64::from)
        }
    }

    /// The count inside the entry whose count field starts at `at`.
    fn entry_count_at(&self, at: usize) -> Option<u64> {
        if self.big_tiff {
            self.u64(at)
        } else {
            self.u32(at).map(u64::from)
        }
    }

    fn value(&self, at: usize, ty: u16, count: u64) -> Vec<u64> {
        let size = type_size(ty);
        let total = size.saturating_mul(count.min(1 << 20) as usize);
        // `at` is the entry's count field; the value-or-offset slot sits one
        // count-width past it, and an entry is tag(2) + type(2) + count +
        // slot. Reaching it by offset width instead lands on the count itself
        // for a classic TIFF, which then reads every value as 0 or 1.
        let slot = at + self.entry_count_width();
        let inline = self.offset_width();
        let base = if total <= inline {
            // A value shorter than the slot is stored **left-justified**, with
            // the padding on the right, so it starts at the slot itself.
            // Right-justifying it (slot + inline - size) reads the padding for
            // a SHORT and turns every 7 into a 0.
            slot
        } else {
            let Some(o) = self.offset_at(slot) else {
                return Vec::new();
            };
            o as usize
        };
        let mut out = Vec::new();
        let mut p = base;
        for _ in 0..count.min(1 << 16) {
            match (ty, size) {
                (1, _) | (7, _) => match self.d.get(p) {
                    Some(b) => out.push(*b as u64),
                    None => break,
                },
                (3, _) => match self.u16(p) {
                    Some(v) => out.push(v as u64),
                    None => break,
                },
                _ => match self.u32(p) {
                    Some(v) => out.push(v as u64),
                    None => break,
                },
            }
            p += size;
        }
        out
    }
}

#[cfg(feature = "tiff")]
fn type_size(ty: u16) -> usize {
    match ty {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 => 4,
        5 | 10 | 12 => 8,
        16..=18 => 8,
        _ => 1,
    }
}

#[cfg(feature = "tiff")]
fn compression_name(t: u64) -> &'static str {
    match t {
        1 => "none",
        2 => "CCITT RLE",
        3 => "CCITT G3",
        4 => "CCITT G4",
        5 => "LZW",
        6 => "JPEG (old)",
        7 => "JPEG",
        8 => "Deflate (Adobe)",
        32773 => "PackBits",
        32946 => "Deflate (Deflate)",
        34712 => "JPEG 2000",
        34887 => "Lerc",
        34925 => "LZMA",
        50000 => "Zstandard",
        50001 => "WebP",
        _ => "unknown",
    }
}

#[cfg(feature = "tiff")]
fn photometric_name(t: u64) -> &'static str {
    match t {
        0 => "white is zero",
        1 => "black is zero",
        2 => "RGB",
        3 => "palette",
        4 => "transparency mask",
        5 => "CMYK",
        6 => "YCbCr",
        8 => "CIELab",
        _ => "unknown",
    }
}

#[cfg(feature = "tiff")]
fn tiff_report(data: &[u8]) -> Vec<u8> {
    let Some(r) = TiffReader::open(data) else {
        return b"not a TIFF".to_vec();
    };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "TIFF ({} {}, byte order {})",
        r.variant,
        if r.big { "big-endian" } else { "little-endian" },
        if r.big { "MSB" } else { "LSB" }
    );
    let mut seen: Vec<u64> = Vec::new();
    let mut at = r.first_ifd();
    let mut page = 0usize;
    while let Some(off) = at {
        if page >= MAX_PAGES {
            let _ = writeln!(out, "stopped after {MAX_PAGES} pages");
            break;
        }
        // A chain that revisits an IFD would otherwise never end.
        if seen.contains(&off) {
            let _ = writeln!(out, "the page chain revisits an earlier page at {off}");
            break;
        }
        seen.push(off);
        let Some(count) = r.ifd_count_at(off as usize) else {
            break;
        };
        let body = off as usize + r.ifd_count_width();
        page += 1;
        let _ = writeln!(out, "page {page}:");

        let mut width = 0u64;
        let mut height = 0u64;
        for i in 0..count.min(1 << 12) {
            let e = body + i as usize * r.entry_size();
            let (Some(tag), Some(ty)) = (r.u16(e), r.u16(e + 2)) else {
                break;
            };
            let Some(n) = r.entry_count_at(e + 4) else {
                break;
            };
            let v = r.value(e + 4, ty, n);
            let first = v.first().copied().unwrap_or(0);
            match tag {
                TAG_WIDTH => width = first,
                TAG_HEIGHT => height = first,
                TAG_BITS => {
                    let _ = writeln!(out, "  bits per sample: {}", join(&v));
                }
                TAG_COMPRESSION => {
                    let _ = writeln!(out, "  compression: {} ({first})", compression_name(first));
                }
                TAG_PHOTOMETRIC => {
                    let _ = writeln!(out, "  colour: {}", photometric_name(first));
                }
                TAG_SAMPLES => {
                    let _ = writeln!(out, "  samples per pixel: {first}");
                }
                TAG_RESOLUTION_UNIT => {
                    let _ = writeln!(
                        out,
                        "  resolution unit: {}",
                        match first {
                            1 => "none",
                            2 => "inch",
                            3 => "centimetre",
                            _ => "unknown",
                        }
                    );
                }
                TAG_X_RES | TAG_Y_RES => {
                    // A rational is a numerator/denominator pair in the same
                    // value slot; printing the numerator alone says 300 when
                    // the file means 300/1 and 72 when it means 1/72.
                    let (num, den) = (
                        v.first().copied().unwrap_or(0),
                        v.get(1).copied().unwrap_or(1),
                    );
                    if den != 0 {
                        let _ = writeln!(out, "  resolution: {}/{}", num, den);
                    }
                }
                TAG_PREDICTOR => {
                    let _ = writeln!(out, "  predictor: {first}");
                }
                TAG_T4_OPTIONS | TAG_T6_OPTIONS => {
                    let _ = writeln!(out, "  fax options: {first}");
                }
                TAG_DESCRIPTION | TAG_MAKE | TAG_MODEL | TAG_SOFTWARE | TAG_DATETIME => {
                    if let Some(t) = text_value(data, &r, e + 4, ty, n) {
                        let _ = writeln!(out, "  {}: {t}", tag_name(tag));
                    }
                }
                TAG_PAGE_NUMBER => {
                    let _ = writeln!(
                        out,
                        "  page number: {}/{}",
                        first,
                        v.get(1).copied().unwrap_or(0)
                    );
                }
                TAG_STRIP_OFFSETS => {
                    // Panasonic's RW2 writes 0xFFFFFFFF when the strip offset is
                    // not in the file at all, and printing that number as if it
                    // were an offset would be a lie about where the pixels are.
                    if first == u32::MAX as u64 {
                        let _ = writeln!(out, "  {} strip(s), offset unknown", v.len());
                    } else {
                        let _ = writeln!(out, "  {} strip(s) starting at {}", v.len(), first);
                    }
                }
                TAG_STRIP_BYTES => {
                    let total: u64 = v.iter().sum();
                    let _ = writeln!(out, "  pixel data: {total} bytes");
                }
                TAG_ROWS_PER_STRIP => {
                    let _ = writeln!(out, "  rows per strip: {first}");
                }
                TAG_JPEG_OFFSET => {
                    let _ = writeln!(
                        out,
                        "  JPEG stream at {first}, {} bytes",
                        v.get(1).copied().unwrap_or(0)
                    );
                }
                TAG_JPEG_BYTES => {
                    let _ = writeln!(out, "  JPEG interchange: {first} bytes");
                }
                TAG_SUBIFDS => {
                    let _ = writeln!(out, "  {} sub-IFD(s) (pyramidal)", v.len());
                }
                _ => {}
            }
        }
        if width == 0 || height == 0 {
            let _ = writeln!(out, "  (no ImageWidth/ImageLength in this IFD)");
        } else {
            // The geometry is the first thing anyone looks for in a scan.
            let _ = writeln!(out, "  {width} x {height} pixels");
        }
        // The chain pointer sits immediately after the last entry, and it is
        // an offset rather than a count.
        at = r.offset_at(body + count as usize * r.entry_size());
        if at == Some(0) {
            break;
        }
    }
    if page == 0 {
        let _ = writeln!(out, "no image file directory");
    } else {
        let _ = writeln!(out, "pages: {page}");
    }
    out.into_bytes()
}

#[cfg(feature = "tiff")]
fn tag_name(tag: u16) -> &'static str {
    match tag {
        TAG_DESCRIPTION => "description",
        TAG_MAKE => "make",
        TAG_MODEL => "model",
        TAG_SOFTWARE => "software",
        TAG_DATETIME => "date",
        _ => "tag",
    }
}

#[cfg(feature = "tiff")]
fn join(v: &[u64]) -> String {
    v.iter()
        .take(16)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

/// An ASCII tag's value, which lives in the value slot when it fits and in
/// the file otherwise. Reading the slot as text either way yields the count
/// bytes as garbage for a long description.
#[cfg(feature = "tiff")]
fn text_value(data: &[u8], r: &TiffReader<'_>, at: usize, ty: u16, n: u64) -> Option<String> {
    if ty != 2 && ty != 7 {
        return None;
    }
    let size = type_size(ty);
    let total = size.saturating_mul(n.min(1 << 20) as usize);
    let slot = at + r.entry_count_width();
    let inline = r.offset_width();
    let start = if total <= inline {
        // Left-justified, as in [`TiffReader::value`].
        slot
    } else {
        r.offset_at(slot)? as usize
    };
    let body = data.get(start..start.checked_add(total)?)?;
    let end = body.iter().position(|b| *b == 0).unwrap_or(body.len());
    let s = String::from_utf8_lossy(&body[..end]);
    if s.trim().is_empty() {
        None
    } else {
        Some(s.into_owned())
    }
}

// ---------------------------------------------------------------------------
// DjVu
// ---------------------------------------------------------------------------

// Sliced constants, not arrays: these are matched against `&[u8]` slice
// patterns below, and an array-typed const cannot unify with one.
#[cfg(feature = "djvu")]
const DJVU_MAGIC: &[u8] = b"AT&TFORM";
#[cfg(feature = "djvu")]
const DJVU_DJVU: &[u8] = b"DJVU";
#[cfg(feature = "djvu")]
const DJVU_DJVM: &[u8] = b"DJVM";
#[cfg(feature = "djvu")]
const DJVU_DJVI: &[u8] = b"DJVI";
#[cfg(feature = "djvu")]
const DJVU_INFO: &[u8] = b"INFO";
#[cfg(feature = "djvu")]
const DJVU_ANTZ: &[u8] = b"ANTz";
#[cfg(feature = "djvu")]
const DJVU_ANTA: &[u8] = b"ANTa";
#[cfg(feature = "djvu")]
const DJVU_FORM: &[u8] = b"FORM";
/// The inflation ceiling for one annotation chunk, the same rule every
/// other inflate in this crate follows: a chunk that expands past it is
/// taken capped rather than whole, and the bytes past the cap are the
/// bomb's, not the answer's.
#[cfg(feature = "djvu")]
const DJVU_MAX_INFLATE: u64 = 32 << 20;

#[cfg(feature = "djvu")]
pub struct Djvu;
#[cfg(feature = "djvu")]
impl Adapter for Djvu {
    fn name(&self) -> &'static str {
        "djvu"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["djvu", "djv"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if !data.starts_with(DJVU_MAGIC) {
            decline!("not a DjVu document (missing AT&TFORM)");
        }
        Ok(Outcome::Text(djvu_report(data)))
    }
}

#[cfg(feature = "djvu")]
fn djvu_report(data: &[u8]) -> Vec<u8> {
    let mut out = String::new();
    // `AT&TFORM` is followed by the FORM's own 4-byte big-endian length;
    // the first chunk starts after it, not after the 8-byte identifier.
    let mut p = 12usize;
    let mut pages: Vec<(usize, usize)> = Vec::new(); // (width, height) in du
    let mut annotations: Vec<u8> = Vec::new();
    let mut bundle_pages = 0usize;
    let mut guard = 0usize;

    while p + 8 <= data.len() && guard < 1_000_000 {
        guard += 1;
        let id = &data[p..p + 4];
        // A chunk header is 7 bytes either way: ID(4) + a length byte whose
        // top bit marks a secondary chunk + two more bytes. On the secondary
        // form those two bytes are the low 16 bits of a 24-bit length whose
        // high 7 bits live in the low bits of byte 4 -- so both forms read 7
        // bytes of header, and reading 8 puts every body one byte late.
        let mut len = data.get(p + 4).copied().unwrap_or(0) as usize;
        let head = 7usize;
        if (len & 0x80) != 0 {
            let b5 = data.get(p + 5).copied().unwrap_or(0);
            len = (((len & 0x7F) << 16) | (b5 as usize) << 8)
                | data.get(p + 6).copied().unwrap_or(0) as usize;
            if b5 & 0x80 != 0 {
                // Bit 23 set is DjVu's "runs to the end of the file" length,
                // used by a bundled DIRM. Reading the low bits as a count
                // would stop the walk early and drop every page after it.
                len = data.len().saturating_sub(p + head);
            }
        }
        if len == 0 {
            break;
        }
        let body = match p.checked_add(head) {
            Some(b) if b + len <= data.len() => b,
            // A length that runs past the file is what a truncated download
            // looks like; stop rather than read the tail as a chunk header.
            _ => break,
        };
        match id {
            DJVU_DJVM | DJVU_FORM => bundle_pages += 1,
            DJVU_DJVU => {
                let _ = writeln!(out, "single-page DjVu");
                pages.push((0, 0));
            }
            DJVU_DJVI => {
                let _ = writeln!(out, "multi-page bundle");
                bundle_pages += 1;
            }
            DJVU_INFO => {
                let w = u16::from_le_bytes([
                    data.get(body).copied().unwrap_or(0),
                    data.get(body + 1).copied().unwrap_or(0),
                ]);
                let h = u16::from_le_bytes([
                    data.get(body + 2).copied().unwrap_or(0),
                    data.get(body + 3).copied().unwrap_or(0),
                ]);
                if !pages.is_empty() {
                    let last = pages.len() - 1;
                    pages[last] = (w as usize, h as usize);
                } else {
                    pages.push((w as usize, h as usize));
                }
            }
            DJVU_ANTZ | DJVU_ANTA => {
                // Both are zlib-framed except ANTa, whose name says it is
                // not. Inflating a chunk that is not framed is the single
                // most common way a DjVu reader loses its annotations.
                // The decode is bounded: an annotation chunk has no
                // business expanding past the ceiling, and the walk
                // accumulates every chunk it meets.
                let body_bytes = &data[body..body + len];
                let plain = rgx_core::compress::zlib::ZlibDecoder::new()
                    .decode_bounded(body_bytes, DJVU_MAX_INFLATE)
                    .map(|b| b.bytes)
                    .unwrap_or_else(|_| body_bytes.to_vec());
                annotations.extend_from_slice(&plain);
            }
            _ => {}
        }
        p = body + len;
    }

    let _ = writeln!(out, "pages: {}", pages.len().max(bundle_pages));
    for (i, (w, h)) in pages.iter().enumerate().take(64) {
        // DjVu stores geometry in "du" units of about 1/100 inch.
        let _ = writeln!(
            out,
            "  page {}: {} x {} du (about {:.2} x {:.2} in)",
            i + 1,
            w,
            h,
            *w as f64 / 100.0,
            *h as f64 / 100.0
        );
    }
    if annotations.is_empty() {
        let _ = writeln!(out, "no annotations");
    } else {
        let _ = writeln!(out, "annotations:");
        for s in annotation_strings(&annotations) {
            let _ = writeln!(out, "  {s}");
        }
    }
    out.into_bytes()
}

/// A DjVu annotation is a sequence of components, each a five-byte type
/// (`ANT` plus a letter), a four-byte big-endian size, and then subtypes:
/// 1 is the component's name, 2 its text. Both are the only prose in the
/// file.
#[cfg(feature = "djvu")]
fn annotation_strings(b: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut p = 0usize;
    let mut guard = 0usize;
    while p + 8 <= b.len() && guard < 100_000 {
        guard += 1;
        let ty = &b[p..p + 3];
        if ty != b"ANT" {
            p += 1;
            continue;
        }
        // The component header is 4 bytes of id plus a 4-byte big-endian
        // size: eight, not nine. Reading the size a byte late turns a 16-byte
        // component into a 1,048,576-byte one, which runs off the end of the
        // annotation buffer and loses every string in the file.
        let size = u32::from_be_bytes([b[p + 4], b[p + 5], b[p + 6], b[p + 7]]) as usize;
        let body = p + 8;
        let Some(span) = body.checked_add(size) else {
            break;
        };
        let Some(comp) = b.get(body..span) else {
            break;
        };
        let mut q = 0usize;
        while q + 3 <= comp.len() {
            let st = comp[q];
            let len = u16::from_be_bytes([comp[q + 1], comp[q + 2]]) as usize;
            let start = q + 3;
            let Some(span) = start.checked_add(len) else {
                break;
            };
            let Some(text) = comp.get(start..span) else {
                break;
            };
            if st == 1 || st == 2 {
                let s = String::from_utf8_lossy(text).into_owned();
                if !s.trim().is_empty() {
                    out.push(s);
                }
            }
            q = start + len;
        }
        p = body + size;
    }
    out.truncate(256);
    out
}

#[cfg(test)]
#[cfg(any(feature = "djvu", feature = "tiff"))]
mod tests {
    use super::*;

    #[cfg(any(feature = "djvu", feature = "tiff"))]
    fn text_of(r: Result<Outcome>) -> String {
        match r.expect("adapter") {
            Outcome::Text(t) => String::from_utf8_lossy(&t).into_owned(),
            _ => panic!("expected Text"),
        }
    }

    /// One IFD with the given (tag, type, count, value), chained to `next`.
    /// The count is explicit because it decides *where* the value lives: a
    /// four-byte-or-shorter total is stored in the entry's own value slot and
    /// an ASCII tag of 9 bytes does not fit there, so a fixture that leaves
    /// count at 1 can never exercise the out-of-line read.
    #[cfg(feature = "tiff")]
    fn ifd_at(entries: &[(u16, u16, u32, u32)], next: u32) -> Vec<u8> {
        let mut b = (entries.len() as u16).to_le_bytes().to_vec();
        for (tag, ty, n, v) in entries {
            b.extend_from_slice(&tag.to_le_bytes());
            b.extend_from_slice(&ty.to_le_bytes());
            b.extend_from_slice(&n.to_le_bytes());
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&next.to_le_bytes());
        b
    }

    #[cfg(feature = "tiff")]
    fn ifd(entries: &[(u16, u16, u64)], next: u32) -> Vec<u8> {
        let wide: Vec<(u16, u16, u32, u32)> = entries
            .iter()
            .map(|(t, ty, v)| (*t, *ty, 1u32, *v as u32))
            .collect();
        ifd_at(&wide, next)
    }

    #[cfg(feature = "tiff")]
    fn tiff_pages(pages: &[Vec<u8>]) -> Vec<u8> {
        let mut out = b"II\x2a\x00".to_vec();
        out.extend_from_slice(&8u32.to_le_bytes());
        let mut offset = 8u32;
        for (i, p) in pages.iter().enumerate() {
            out.extend_from_slice(p);
            let next = if i + 1 == pages.len() {
                0
            } else {
                offset + p.len() as u32
            };
            // The pointer is at the end of the IFD, so it is rewritten here
            // rather than passed in.
            let n = u16::from_le_bytes([p[0], p[1]]) as usize;
            let ptr = offset as usize + 2 + n * 12;
            out[ptr..ptr + 4].copy_from_slice(&next.to_le_bytes());
            offset += p.len() as u32;
        }
        out
    }

    #[test]
    #[cfg(feature = "tiff")]
    fn a_multi_page_tiff_reports_every_page() {
        let a = ifd_at(
            &[
                (TAG_WIDTH, 4, 1, 2480),
                (TAG_HEIGHT, 4, 1, 3508),
                (TAG_COMPRESSION, 3, 1, 7),
                (TAG_PHOTOMETRIC, 3, 1, 1),
                // Both ASCII values live in the file, so their counts are the
                // real byte lengths: 9 and 12, neither of which fits the
                // four-byte value slot.
                (TAG_MODEL, 2, 9, 0),
                (TAG_SOFTWARE, 2, 12, 0),
                (TAG_STRIP_BYTES, 4, 1, 1_048_576),
            ],
            0,
        );
        let b = ifd(
            &[
                (TAG_WIDTH, 4, 1654),
                (TAG_HEIGHT, 4, 2339),
                (TAG_PAGE_NUMBER, 3, 2),
            ],
            0,
        );
        let mut f = tiff_pages(&[a, b]);
        // An ASCII tag whose value does not fit the slot lives in the file,
        // so put the two strings after the IFDs and point at them.
        let text_at = f.len() as u32;
        f.extend_from_slice(b"Fujifilm\0");
        let soft_at = f.len() as u32;
        f.extend_from_slice(b"Scanner 6.2\0");
        // Patch the value slots of MODEL and SOFTWARE, both in the FIRST
        // IFD: entry 4 and entry 5 respectively.
        let first_ifd = 8usize;
        let model_entry = first_ifd + 2 + 4 * 12;
        f[model_entry + 8..model_entry + 12].copy_from_slice(&text_at.to_le_bytes());
        let soft_entry = first_ifd + 2 + 5 * 12;
        f[soft_entry + 8..soft_entry + 12].copy_from_slice(&soft_at.to_le_bytes());

        let out = text_of(Tiff.extract(&f, "x.tif"));
        assert!(out.contains("pages: 2"), "{out}");
        assert!(out.contains("2480 x 3508"), "{out}");
        assert!(out.contains("1654 x 2339"), "{out}");
        assert!(out.contains("JPEG"), "{out}");
        assert!(out.contains("model: Fujifilm"), "{out}");
        assert!(out.contains("software: Scanner 6.2"), "{out}");
        assert!(out.contains("pixel data: 1048576 bytes"), "{out}");
    }

    #[test]
    #[cfg(feature = "tiff")]
    fn a_tiff_page_chain_that_loops_stops() {
        // Two IFDs whose second pointer comes back to the first.
        let a = ifd(&[(TAG_WIDTH, 4, 10), (TAG_HEIGHT, 4, 10)], 0);
        let mut f = b"II\x2a\x00".to_vec();
        f.extend_from_slice(&8u32.to_le_bytes());
        f.extend_from_slice(&a);
        let n = u16::from_le_bytes([f[8], f[9]]) as usize;
        let ptr = 8 + 2 + n * 12;
        f[ptr..ptr + 4].copy_from_slice(&8u32.to_le_bytes());
        let out = text_of(Tiff.extract(&f, "x.tif"));
        assert!(out.contains("revisits"), "{out}");
    }

    #[test]
    #[cfg(feature = "tiff")]
    fn a_file_that_is_not_a_tiff_is_declined() {
        assert!(Tiff.extract(b"\x89PNG\r\n\x1a\n", "x.tif").is_err());
        assert!(Tiff.extract(b"II\x2a", "x.tif").is_err());
    }

    /// Panasonic's RW2 is a TIFF whose magic number is 0x55 instead of 0x2A.
    /// The file here is a TIFF with that one byte replaced, which is the whole
    /// difference between the two containers: the IFD chain that follows is an
    /// ordinary TIFF one.
    #[test]
    #[cfg(feature = "tiff")]
    fn a_panasonic_rw2_is_read_as_a_tiff() {
        let a = ifd(
            &[
                (TAG_WIDTH, 4, 4000),
                (TAG_HEIGHT, 4, 3000),
                (TAG_COMPRESSION, 3, 7),
            ],
            0,
        );
        let mut f = tiff_pages(&[a]);
        f[2] = 0x55;
        let out = text_of(Tiff.extract(&f, "x.rw2"));
        assert!(out.contains("TIFF (RW2"), "{out}");
        assert!(out.contains("4000 x 3000"), "{out}");
        assert!(out.contains("JPEG"), "{out}");
    }

    /// The camera RAW containers that are not TIFF are not read as TIFFs. An
    /// Olympus ORF starts with "IIRO" or "MMOR", a Canon CRW with "II\x1a" and
    /// a Fujifilm RAF with "FUJI"; each one is declined, so the file falls back
    /// to the raw search instead of being answered with a page chain it does
    /// not have.
    #[test]
    #[cfg(feature = "tiff")]
    fn a_camera_raw_container_that_is_not_a_tiff_is_declined() {
        for magic in [
            &b"IIRO"[..],
            &b"MMOR"[..],
            &b"IIRS"[..],
            &b"II\x1a\x00"[..],
            &b"FUJI"[..],
        ] {
            let mut f = magic.to_vec();
            f.extend_from_slice(&[0u8; 64]);
            let Err(err) = Tiff.extract(&f, "x.raw") else {
                panic!("{:?} was read as a TIFF", magic.escape_ascii());
            };
            assert!(err.is_decline(), "{:?}: {err}", magic.escape_ascii());
        }
    }

    #[cfg(feature = "djvu")]
    fn chunk(id: &[u8], body: &[u8]) -> Vec<u8> {
        let mut v = id.to_vec();
        assert!(body.len() < 0x80);
        v.push(body.len() as u8);
        v.extend_from_slice(&[0u8; 2]); // flags
        v.extend_from_slice(body);
        v
    }

    #[test]
    #[cfg(feature = "djvu")]
    fn a_djvu_reports_its_page_geometry() {
        let mut f = DJVU_MAGIC.to_vec();
        f.extend_from_slice(&1000u32.to_be_bytes());
        // A real single-page DjVu is DJVU followed by INFO; an INFO with no
        // page chunk in front of it is not a file any writer produces.
        f.extend_from_slice(&chunk(DJVU_DJVU, &[0u8; 8]));
        f.extend_from_slice(&chunk(DJVU_INFO, &[0x10, 0x27, 0x1a, 0x2b, 24, 1]));
        let out = text_of(Djvu.extract(&f, "x.djvu"));
        assert!(out.contains("single-page DjVu"), "{out}");
        assert!(out.contains("10000 x 11034 du"), "{out}");
        assert!(Djvu.extract(b"not a djvu", "x.djvu").is_err());
    }

    #[test]
    #[cfg(feature = "djvu")]
    fn a_djvu_chunk_length_past_the_file_stops_the_walk() {
        let mut f = DJVU_MAGIC.to_vec();
        f.extend_from_slice(&1000u32.to_be_bytes());
        // length 0x7F claims 127 bytes in a file that has none.
        f.extend_from_slice(b"INFO\x7f\x00\x00\x00");
        let out = text_of(Djvu.extract(&f, "x.djvu"));
        assert!(out.contains("pages: 0"), "{out}");
    }

    #[test]
    #[cfg(feature = "djvu")]
    fn a_djvu_annotation_component_name_is_read() {
        // ANT + a letter, a big-endian size, then subtype 1 (the name).
        let name = b"Title";
        let mut comp = vec![1u8, 0, name.len() as u8];
        comp.extend_from_slice(name);
        let mut ann = b"ANTP".to_vec();
        ann.extend_from_slice(&(comp.len() as u32).to_be_bytes());
        ann.extend_from_slice(&comp);

        let mut f = DJVU_MAGIC.to_vec();
        f.extend_from_slice(&1000u32.to_be_bytes());
        // ANTa is the unframed variant; an ANTa body must survive the reader's
        // attempt to inflate it. Using ANTz here would describe a file that no
        // writer produces.
        f.extend_from_slice(&chunk(DJVU_DJVU, &[0u8; 8]));
        let mut c = DJVU_ANTA.to_vec();
        let len = ann.len();
        assert!(len < 0x80);
        c.push(len as u8);
        c.extend_from_slice(&[0u8; 2]);
        c.extend_from_slice(&ann);
        f.extend_from_slice(&c);

        let out = text_of(Djvu.extract(&f, "x.djvu"));
        assert!(out.contains("Title"), "{out}");
    }
}
