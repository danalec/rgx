// SPDX-License-Identifier: Apache-2.0

//! ZIP container reader (PKWARE APPNOTE .ZIP File Format Specification).
//!
//! Independent reimplementation of the parts of the format a reader
//! needs: the end of central directory record (§4.3.16), the zip64 end
//! of central directory record and its locator (§4.3.14–4.3.15), the
//! central directory file header (§4.3.12), the local file header
//! (§4.3.7), and the zip64 extended information extra field (§4.5.3).
//! Entry bodies are handed to the sibling decoders in
//! `crate::compress` — store (method 0), deflate (8), bzip2 (12), LZMA
//! (14) and XZ (95) each follow the method's own format; zstd (93) is
//! decoded from its frame format.
//!
//! # Contract
//!
//! The end of central directory record is the last record in the
//! archive: a candidate signature is only the real one when the record
//! plus its declared comment length reaches the end of the file. The
//! 32-bit counts and offsets saturate at 0xFFFF / 0xFFFFFFFF, and the
//! real values then live in the zip64 EOCD record, located through the
//! zip64 EOCD locator that sits immediately before the EOCD. The same
//! saturation rule applies per entry through the 0x0001 zip64 extra
//! field, whose values appear in the fixed order uncompressed size,
//! compressed size, local header offset, each present only if the
//! corresponding 32-bit slot saturated. Sizes recorded in the central
//! directory are the authoritative ones — an entry written with a data
//! descriptor (general purpose bit 3) carries zeros in its local header
//! and the reader takes the sizes from the directory either way.
//!
//! Methods the reader does not implement (deflate64, ppmd, …) are
//! refused: returning the raw compressed bytes as the file's content
//! would put garbage in whatever indexes the output. Every entry is
//! decoded under a ceiling ([`default_byte_limit`], overridable with
//! [`ZipReader::with_limit`]): the central directory's uncompressed
//! size is a claim, not a bound, so it is checked before the decode and
//! the running cap is what stops a bomb.

use crate::compress::bzip2::Bzip2Decoder;
use crate::compress::cap::Bounded;
use crate::compress::crc32::crc32;
use crate::compress::deflate::DeflateDecoder;
use crate::compress::error::{CompressError, CompressResult};
use crate::compress::lzma::{LzmaDecoder, LzmaProps};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, OnceCell};

/// Default ceiling on the bytes one archive may expand to: the same number
/// `Ctx::default()` gives the archive adapters' byte budget, so a zip costs
/// no more than the `.gz` beside it.
///
/// This is the *default*, not the process budget — a caller that knows the
/// budget it is running under should pass it to [`ZipReader::with_limit`]
/// instead of taking this.
pub fn default_byte_limit() -> u64 {
    crate::Ctx::default().max_file_size as u64
}

// Record signatures (APPNOTE §4.3.1).
const LOCAL_SIG: &[u8; 4] = b"PK\x03\x04";
const CENTRAL_SIG: &[u8; 4] = b"PK\x01\x02";
const EOCD_SIG: &[u8; 4] = b"PK\x05\x06";
const ZIP64_EOCD_SIG: &[u8; 4] = b"PK\x06\x06";
const ZIP64_LOCATOR_SIG: &[u8; 4] = b"PK\x06\x07";

// Fixed sizes: the local header is 30 bytes, the central header 46, the
// EOCD 22 with no comment, and the zip64 locator is 20.
const LOCAL_HEADER_LEN: usize = 30;
const CENTRAL_HEADER_LEN: usize = 46;
const EOCD_LEN: usize = 22;
const ZIP64_LOCATOR_LEN: usize = 20;
const ZIP64_EOCD_LEN: usize = 56;

/// Saturation markers: the 32-bit slot is full and the real value lives
/// in the zip64 record (APPNOTE §4.4.1.4 / §4.5.3).
const SAT_U16: u16 = 0xFFFF;
const SAT_U32: u32 = 0xFFFF_FFFF;

/// Read a little-endian integer at `at`, or fail if the buffer ends first.
fn u16le(data: &[u8], at: usize) -> CompressResult<u16> {
    let s = data
        .get(at..at + 2)
        .ok_or(CompressError::InvalidFormat("truncated record"))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32le(data: &[u8], at: usize) -> CompressResult<u32> {
    let s = data
        .get(at..at + 4)
        .ok_or(CompressError::InvalidFormat("truncated record"))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64le(data: &[u8], at: usize) -> CompressResult<u64> {
    let s = data
        .get(at..at + 8)
        .ok_or(CompressError::InvalidFormat("truncated record"))?;
    let mut v = [0u8; 8];
    v.copy_from_slice(s);
    Ok(u64::from_le_bytes(v))
}

/// Compression method (APPNOTE §4.4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressionMethod {
    /// No compression (stored).
    Store,
    /// DEFLATE compression.
    #[default]
    Deflate,
    /// BZIP2 compression (decoded by the `bzip2` sibling module).
    Bzip2,
    /// LZMA compression (decoded by the `lzma` sibling module).
    ///
    /// The payload carries the ZIP LZMA header of §4.5.3 - LZMA, see
    /// [`ZipReader::decode_lzma`].
    Lzma,
    /// XZ compression (method 95).
    Xz,
    /// Zstd compression (method 93).
    Zstd,
    /// Any other method (deflate64, ppmd, …). Preserved, never
    /// guessed: mapping these to `Store` handed the caller raw
    /// compressed bytes as if they were the file's text — silent
    /// garbage in whatever indexes the output.
    Unsupported(u16),
}

impl From<u16> for CompressionMethod {
    fn from(method: u16) -> Self {
        match method {
            0 => Self::Store,
            8 => Self::Deflate,
            12 => Self::Bzip2,
            14 => Self::Lzma,
            93 => Self::Zstd,
            95 => Self::Xz,
            other => Self::Unsupported(other),
        }
    }
}

impl From<CompressionMethod> for u16 {
    fn from(method: CompressionMethod) -> Self {
        match method {
            CompressionMethod::Store => 0,
            CompressionMethod::Deflate => 8,
            CompressionMethod::Bzip2 => 12,
            CompressionMethod::Lzma => 14,
            CompressionMethod::Zstd => 93,
            CompressionMethod::Xz => 95,
            CompressionMethod::Unsupported(m) => m,
        }
    }
}

/// ZIP entry metadata, as recorded in the central directory.
#[derive(Debug, Clone)]
pub struct ZipEntryMetadata {
    /// File name.
    pub name: String,
    /// Uncompressed size.
    pub size: u32,
    /// Compressed size.
    pub compressed_size: u32,
    /// CRC-32 checksum.
    pub crc32: u32,
    /// Compression method.
    pub method: CompressionMethod,
    /// Last modified time (DOS format).
    pub modified_time: u16,
    /// Last modified date (DOS format).
    pub modified_date: u16,
    /// Offset to local file header within the archive.
    pub local_header_offset: u32,
}

/// ZIP file reader.
#[derive(Debug)]
pub struct ZipReader<'a> {
    data: &'a [u8],
    entries: Vec<ZipEntryMetadata>,
    /// `entries[i].name -> i` for O(1) by-name extraction. The Office and
    /// GGUF/Keras adapters walk the list once and then look each member
    /// up by name (e.g. `xl/sharedStrings.xml`, `[Content_Types].xml`,
    /// `m.keras/data/...`), and an O(N) scan turns a 65 536-entry
    /// archive into a multi-second walk (measured, see commit log).
    /// Built lazily on the first `extract(name)` call; the linear scan
    /// the rest of the API used to do lives on as a single O(N) at that
    /// point, after which every name lookup is amortised O(1).
    by_name: OnceCell<BTreeMap<String, usize>>,
    /// Ceiling on the bytes every entry of this archive may expand to.
    limit: u64,
    spent: Cell<u64>,
}

impl<'a> ZipReader<'a> {
    /// Open a ZIP file. Extraction is bounded by
    /// [`default_byte_limit`]; see [`Self::with_limit`] to supply the
    /// process budget instead.
    pub fn new(data: &'a [u8]) -> CompressResult<Self> {
        Self::with_limit(data, default_byte_limit())
    }

    /// [`Self::new`] with the caller's own ceiling on total decoded bytes.
    ///
    /// The ceiling is a property of the archive, not of the entry: it is
    /// spent across every [`Self::extract`] on this reader, which is the
    /// same accounting the archive adapters' byte budget uses.
    pub fn with_limit(data: &'a [u8], limit: u64) -> CompressResult<Self> {
        let entries = Self::parse_central_directory(data)?;
        Ok(Self {
            data,
            entries,
            by_name: OnceCell::new(),
            limit,
            spent: Cell::new(0),
        })
    }

    /// The ceiling on total decoded bytes, and how much of it is spent.
    pub fn budget(&self) -> (u64, u64) {
        (self.limit, self.spent.get())
    }

    /// The refusal a byte budget produces. It carries both the limit and
    /// what the header declared: with a lying header those differ by orders
    /// of magnitude, and the difference is the whole finding.
    fn over_budget(entry: &ZipEntryMetadata, spent: u64, limit: u64) -> CompressError {
        CompressError::DecompressionFailed(format!(
            "zip entry `{}` stopped at the {limit}-byte archive budget ({spent} bytes already \
             decoded, {} declared): the entry expands further than the budget allows",
            entry.name, entry.size
        ))
    }

    /// One zip64 extra-field value (§4.5.3): when the 32-bit slot
    /// saturated, the next 8 bytes hold the real value. Only saturated
    /// slots appear in the field, in the order uncompressed, compressed,
    /// local header offset. A value past 4 GiB is refused — the metadata
    /// fields are u32, and truncating them would slice the wrong byte
    /// range on extract.
    fn zip64_field(body: &[u8], at: &mut usize, saturated: u32) -> CompressResult<u32> {
        if saturated != SAT_U32 {
            return Ok(saturated);
        }
        let v = u64le(body, *at)?;
        *at += 8;
        u32::try_from(v).map_err(|_| {
            CompressError::InvalidFormat("zip64 entry larger than 4 GiB is out of range")
        })
    }

    /// Find the end of central directory record: the last signature
    /// whose record, plus the comment length it declares, reaches the
    /// end of the file. A signature inside an archive comment is not
    /// that record, so candidates are tried newest-first.
    fn find_eocd(data: &[u8]) -> CompressResult<usize> {
        // APPNOTE bounds the record to the final 65 557 bytes (22-byte
        // record + up to 65 535 of comment), so only that window can
        // hold it.
        const EOCD_MAX_COMMENT: usize = u16::MAX as usize; // 65 535
        let floor = data.len().saturating_sub(EOCD_LEN + EOCD_MAX_COMMENT);
        let tail = &data[floor..];

        let mut from = tail.len();
        while let Some(hit) = crate::memchr::memmem::rfind(&tail[..from], EOCD_SIG) {
            let start = floor + hit;
            if start + EOCD_LEN <= data.len() {
                let comment_len = u16le(data, start + 20)? as usize;
                if start + EOCD_LEN + comment_len == data.len() {
                    return Ok(start);
                }
            }
            from = hit;
        }
        Err(CompressError::InvalidFormat("EOCD not found"))
    }

    /// Parse the central directory.
    fn parse_central_directory(data: &[u8]) -> CompressResult<Vec<ZipEntryMetadata>> {
        let eocd_start = Self::find_eocd(data)?;

        let mut num_entries = u16le(data, eocd_start + 10)? as usize;
        let mut central_dir_offset = u32le(data, eocd_start + 16)? as usize;

        // Zip64: the 32-bit EOCD fields saturate and the real values
        // live in the zip64 EOCD record, found through the locator that
        // sits immediately before the EOCD (§4.3.15).
        if num_entries == SAT_U16 as usize || central_dir_offset == SAT_U32 as usize {
            let loc = eocd_start
                .checked_sub(ZIP64_LOCATOR_LEN)
                .ok_or(CompressError::InvalidFormat("zip64 locator missing"))?;
            if data.get(loc..loc + 4) != Some(&ZIP64_LOCATOR_SIG[..]) {
                return Err(CompressError::InvalidFormat("zip64 locator not found"));
            }
            let eocd64_off = u64le(data, loc + 8)? as usize;
            if data.get(eocd64_off..eocd64_off + 4) != Some(&ZIP64_EOCD_SIG[..]) {
                return Err(CompressError::InvalidFormat("zip64 EOCD not found"));
            }
            // The fixed part of the record is 56 bytes; the extensible
            // data sector after it is not read.
            if eocd64_off + ZIP64_EOCD_LEN > data.len() {
                return Err(CompressError::InvalidFormat("truncated zip64 EOCD"));
            }
            num_entries = u64le(data, eocd64_off + 32)? as usize;
            central_dir_offset = u64le(data, eocd64_off + 48)? as usize;
        }

        let mut entries = Vec::with_capacity(num_entries.min(1024));
        let mut pos = central_dir_offset;

        for _ in 0..num_entries {
            if data.get(pos..pos + 4) != Some(&CENTRAL_SIG[..]) {
                return Err(CompressError::InvalidFormat(
                    "invalid central directory signature",
                ));
            }

            let method = u16le(data, pos + 10)?;
            let modified_time = u16le(data, pos + 12)?;
            let modified_date = u16le(data, pos + 14)?;
            let crc = u32le(data, pos + 16)?;
            let compressed_size = u32le(data, pos + 20)?;
            let uncompressed_size = u32le(data, pos + 24)?;
            let name_len = u16le(data, pos + 28)? as usize;
            let extra_len = u16le(data, pos + 30)? as usize;
            let comment_len = u16le(data, pos + 32)? as usize;
            let local_header_offset = u32le(data, pos + 42)?;

            let name_end = (pos + CENTRAL_HEADER_LEN)
                .checked_add(name_len)
                .ok_or(CompressError::InvalidFormat("entry name length overflows"))?;
            let name = data
                .get(pos + CENTRAL_HEADER_LEN..name_end)
                .ok_or(CompressError::InvalidFormat("entry name out of bounds"))?;
            let name = String::from_utf8_lossy(name).into_owned();

            // Zip64 per-entry extra (header id 0x0001): the 32-bit
            // fields above saturate, and the real values follow in the
            // fixed order uncompressed, compressed, local header
            // offset — only for the fields that actually saturated.
            let (mut size, mut csize, mut lho) =
                (uncompressed_size, compressed_size, local_header_offset);
            if size == SAT_U32 || csize == SAT_U32 || lho == SAT_U32 {
                let extra = data
                    .get(name_end..name_end + extra_len)
                    .ok_or(CompressError::InvalidFormat("extra field out of bounds"))?;
                let mut cur = 0usize;
                let mut found = false;
                while cur + 4 <= extra.len() {
                    let id = u16::from_le_bytes([extra[cur], extra[cur + 1]]);
                    let len = u16::from_le_bytes([extra[cur + 2], extra[cur + 3]]) as usize;
                    let body = extra
                        .get(cur + 4..cur + 4 + len)
                        .ok_or(CompressError::InvalidFormat("zip64 extra truncated"))?;
                    if id == 0x0001 {
                        let mut b = 0usize;
                        size = Self::zip64_field(body, &mut b, size)?;
                        csize = Self::zip64_field(body, &mut b, csize)?;
                        lho = Self::zip64_field(body, &mut b, lho)?;
                        found = true;
                        break;
                    }
                    cur += 4 + len;
                }
                if !found {
                    return Err(CompressError::InvalidFormat(
                        "zip64 entry without a 0x0001 extra field",
                    ));
                }
            }

            entries.push(ZipEntryMetadata {
                name,
                size,
                compressed_size: csize,
                crc32: crc,
                method: CompressionMethod::from(method),
                modified_time,
                modified_date,
                local_header_offset: lho,
            });

            pos = name_end + extra_len + comment_len;
        }

        Ok(entries)
    }

    /// List entries in the archive.
    pub fn list(&self) -> &[ZipEntryMetadata] {
        &self.entries
    }

    /// Extract a file by name, under the archive's byte budget.
    ///
    /// An entry whose expansion runs past the budget is refused, not
    /// truncated: see [`Self::with_limit`].
    ///
    /// The first by-name call builds a name -> index map in O(N) and
    /// every later call is O(log N). The Office and Keras/GGUF
    /// adapters chain several `extract(name)` calls per archive, so
    /// the old O(N) scan was the difference between a millisecond and
    /// a multi-second walk on a 65 536-entry fixture.
    pub fn extract(&self, name: &str) -> CompressResult<Vec<u8>> {
        let map = self.by_name.get_or_init(|| {
            let mut m = BTreeMap::new();
            for (i, e) in self.entries.iter().enumerate() {
                m.insert(e.name.to_string(), i);
            }
            m
        });
        let &idx = map
            .get(name)
            .ok_or(CompressError::InvalidFormat("file not found"))?;
        self.extract_entry(&self.entries[idx])
    }

    /// Extract a specific entry by its index in [`Self::list`], under the
    /// archive's remaining byte budget.
    ///
    /// This is the O(1) counterpart to [`Self::extract`]: callers iterating
    /// the entry list already have the index in hand, and the name lookup
    /// in `extract` is an O(N) scan that turns a 65 536-entry archive into
    /// a 6 s walk (measured on a fixture, see commit log).
    pub fn extract_index(&self, idx: usize) -> CompressResult<Vec<u8>> {
        let entry = self
            .entries
            .get(idx)
            .ok_or(CompressError::InvalidFormat("entry index out of range"))?;
        self.extract_entry(entry)
    }

    /// Extract a specific entry, under the archive's remaining byte budget.
    fn extract_entry(&self, entry: &ZipEntryMetadata) -> CompressResult<Vec<u8>> {
        let limit = self.limit;
        let spent = self.spent.get();
        let remaining = limit.saturating_sub(spent);

        // The declared size is checked first so a header announcing more
        // than the whole archive may expand to is refused for free. It is
        // not trusted as the bound: a header is exactly what a bomb lies
        // in, and the running cap below is what actually stops one.
        if entry.size as u64 > remaining {
            return Err(Self::over_budget(entry, spent, limit));
        }

        // The local header offset comes from the central directory; the
        // body length comes from the directory too, which is what makes a
        // data-descriptor entry (zero sizes in its local header) extract
        // the same way as any other.
        let pos = entry.local_header_offset as usize;
        if self.data.get(pos..pos + 4) != Some(&LOCAL_SIG[..]) {
            return Err(CompressError::InvalidFormat(
                "invalid local header signature",
            ));
        }

        let name_len = u16le(self.data, pos + 26)? as usize;
        let extra_len = u16le(self.data, pos + 28)? as usize;
        let data_start = (pos + LOCAL_HEADER_LEN)
            .checked_add(name_len)
            .and_then(|s| s.checked_add(extra_len))
            .ok_or(CompressError::InvalidFormat(
                "local header length overflows",
            ))?;

        // `data_start` comes from the *local* file header while
        // `compressed_size` comes from the *central* directory, so a
        // crafted or truncated archive can point past the end of the
        // data. Bound the slice rather than indexing blindly: this is
        // untrusted input and a panic here aborts the caller.
        let end = data_start
            .checked_add(entry.compressed_size as usize)
            .ok_or(CompressError::InvalidFormat("compressed size overflows"))?;
        let compressed_data =
            self.data
                .get(data_start..end)
                .ok_or(CompressError::InvalidFormat(
                    "compressed data range out of bounds",
                ))?;

        let decoded = match entry.method {
            CompressionMethod::Store => {
                Bounded::complete(compressed_data.to_vec(), Some(entry.size as u64), remaining)
            }
            CompressionMethod::Deflate => {
                DeflateDecoder::new().decode_bounded(compressed_data, remaining)?
            }
            CompressionMethod::Bzip2 => {
                Bzip2Decoder::new().decode_bounded(compressed_data, remaining)?
            }
            CompressionMethod::Lzma => {
                Self::decode_lzma(compressed_data, entry.size as u64, remaining)?
            }
            CompressionMethod::Xz => {
                crate::compress::xz::XzReader::decompress_bounded(compressed_data, remaining)?
            }
            CompressionMethod::Zstd => crate::compress::zstd::ZstdDecoder::new()
                .decode_bounded(compressed_data, remaining)?,
            CompressionMethod::Unsupported(m) => {
                return Err(CompressError::InvalidFormat(match m {
                    9 => "deflate64 zip entry (method 9) not supported",
                    98 => "ppmd-compressed zip entry (method 98) not supported",
                    _ => "unsupported zip compression method",
                }))
            }
        };

        // A short read is an error, not a payload: the prefix the cap kept
        // cannot match the recorded CRC, so returning it would report a
        // corrupt archive rather than a budget that ran out.
        if decoded.capped || decoded.bytes.len() as u64 > remaining {
            return Err(Self::over_budget(entry, spent, limit));
        }

        // Verify CRC
        let computed_crc = crc32(&decoded.bytes);
        if computed_crc != entry.crc32 {
            return Err(CompressError::CrcMismatch {
                expected: entry.crc32,
                actual: computed_crc,
            });
        }

        self.spent.set(spent + decoded.bytes.len() as u64);
        Ok(decoded.bytes)
    }

    /// Decode an LZMA entry (method 14) under `limit`.
    ///
    /// The ZIP payload is wrapped in the §4.5.3 LZMA header before the
    /// raw LZMA1 stream: 2 bytes of LZMA version (ignored here) followed
    /// by a 2-byte little-endian length of the property block, then the
    /// properties themselves (1 byte `lc`/`lp`/`pb` plus a 4-byte
    /// little-endian dictionary size). This is *not* the 13-byte `.lzma`
    /// "alone" header that [`LzmaDecoder::decode`] expects, so the stream
    /// is handed to [`LzmaDecoder::decode_raw_bounded`] with the
    /// properties parsed out.
    fn decode_lzma(data: &[u8], uncompressed_size: u64, limit: u64) -> CompressResult<Bounded> {
        // 4-byte ZIP header + 5-byte LZMA property block.
        if data.len() < 9 {
            return Err(CompressError::InvalidFormat("truncated LZMA header"));
        }
        let props_size = u16le(data, 2)? as usize;
        if props_size != 5 {
            // LZMA2-in-ZIP (a different property block) is not implemented.
            return Err(CompressError::Unsupported(
                "unsupported LZMA property block",
            ));
        }

        let props = LzmaProps::from_byte(data[4])?;
        let dict_size = u32le(data, 5)?;

        LzmaDecoder::new().decode_raw_bounded(
            &data[9..],
            props,
            dict_size,
            Some(uncompressed_size),
            limit,
        )
    }

    /// Extract all files.
    pub fn extract_all(&self) -> CompressResult<BTreeMap<String, Vec<u8>>> {
        let mut result = BTreeMap::new();

        for entry in &self.entries {
            let data = self.extract_entry(entry)?;
            result.insert(entry.name.clone(), data);
        }

        Ok(result)
    }
}

/// ZIP error type (alias for CompressError with ZIP-specific messages).
pub type ZipError = CompressError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::huffman::BitWriter;

    /// A zip whose central-directory sizes and CRC are the caller's to
    /// choose, so a test can make the header lie. The writer half of the
    /// format is not vendored; this is the minimum needed to say so.
    ///
    /// Each entry is `(name, method, payload, declared_size, declared_crc)`.
    /// The defaults are the payload's own length and CRC, which is right for
    /// a stored entry; a compressed one has to pass the CRC of what it
    /// decodes to.
    type RawZipEntry<'a> = (&'a str, u16, &'a [u8], Option<u32>, Option<u32>);

    fn zip_entry(entries: &[RawZipEntry<'_>]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, method, payload, declared_size, declared_crc) in entries {
            let size = declared_size.unwrap_or(payload.len() as u32);
            let crc = declared_crc.unwrap_or_else(|| crc32(payload));
            let offset = out.len() as u32;

            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0u8; 4]); // time, date
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(payload);

            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&20u16.to_le_bytes()); // version made by
            central.extend_from_slice(&20u16.to_le_bytes()); // version needed
            central.extend_from_slice(&0u16.to_le_bytes()); // flags
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0u8; 4]); // time, date
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            central.extend_from_slice(&size.to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0u8; 12]);
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }

        let cd_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    /// A raw DEFLATE stream of `target` bytes from three symbols: literal
    /// 'A', length-258 and end-of-block, all with 2-bit codes in a dynamic
    /// block, plus a 2-bit distance-1. Every 258 output bytes cost 8 bits,
    /// so this is the shape of 42.zip — a header that costs little and an
    /// expansion that does not — at roughly 258:1.
    fn deflate_bomb(target: usize) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.write_bits(1, 1); // BFINAL
        w.write_bits(2, 2); // BTYPE = dynamic Huffman
        w.write_bits(29, 5); // HLIT: 286 literal/length codes
        w.write_bits(0, 5); // HDIST: one distance code
        w.write_bits(14, 4); // HCLEN: 18 code-length codes

        // Code-length alphabet, RFC 1951 order. Symbols 0, 1, 2 and 18 get
        // length 2 — all four at one length is a complete code, so nothing
        // here depends on a decoder accepting an incomplete one. The set is
        // the one this stream emits: 18 for a run of zeros, 2 for a code
        // length, 0 and 1 unused but needed to complete the code.
        const CL_ORDER: [u16; 18] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1];
        for &sym in &CL_ORDER {
            w.write_bits(
                match sym {
                    0 | 1 | 2 | 18 => 2u32,
                    _ => 0,
                },
                3,
            );
        }

        // Canonical codes over {0, 1, 2, 18} at length 2, in symbol order.
        const CL_ZERO_RUN: u64 = 0b11; // symbol 18: repeat a zero 11..138 times
        const CL_TWO: u64 = 0b10; // symbol 2: a literal code length

        let zeros = |w: &mut BitWriter, n: usize| {
            let mut left = n;
            while left > 0 {
                let take = left.min(138);
                w.write_bits_msb(CL_ZERO_RUN, 2);
                w.write_bits((take - 11) as u32, 7);
                left -= take;
            }
        };

        // Literal/length lengths: 'A' at 65, end-of-block at 256, the
        // length-258 code at 285. The one distance code is length 2 too.
        for run in [65usize, 190, 28] {
            zeros(&mut w, run);
            w.write_bits_msb(CL_TWO, 2);
        }
        w.write_bits_msb(CL_TWO, 2); // the distance code's length

        const LIT_A: u64 = 0b00; // 65
        const EOB: u64 = 0b01; // 256
        const LEN_258: u64 = 0b10; // 285
        const DIST_1: u64 = 0b00; // 0
        for _ in 0..target / 258 {
            w.write_bits_msb(LIT_A, 2);
            w.write_bits_msb(LEN_258, 2);
            w.write_bits_msb(DIST_1, 2);
        }
        w.write_bits_msb(EOB, 2);
        w.finish()
    }

    /// The bomb the budget exists for: the central directory says 1 KB and
    /// the payload expands to `target` bytes.
    fn lying_zip(target: usize) -> Vec<u8> {
        let bomb = deflate_bomb(target);
        let prefix_crc = crc32(&vec![b'A'; 1024]);
        zip_entry(&[("bomb.txt", 8, &bomb, Some(1024), Some(prefix_crc))])
    }

    /// How many bytes `deflate_bomb(target)` expands to: one literal plus a
    /// 258-byte match per repetition.
    fn bomb_expansion(target: usize) -> usize {
        (target / 258) * 259
    }

    #[test]
    fn the_deflate_bomb_fixture_is_a_bomb() {
        // Guard for the fixture, not the reader: if this stops holding, the
        // budget tests below would pass for the wrong reason.
        let small = deflate_bomb(1 << 20);
        let whole = DeflateDecoder::new().decode(&small).expect("bomb decodes");
        assert_eq!(whole.len(), bomb_expansion(1 << 20));
        assert!(
            whole.iter().all(|&b| b == b'A'),
            "the expansion is not what was encoded"
        );
        assert!(
            small.len() * 300 < whole.len(),
            "{} bytes expanded to {} — that is not a bomb",
            small.len(),
            whole.len()
        );
        // The ratio is linear, so the big fixtures are the same shape.
        let big = deflate_bomb(10 << 30);
        assert!(
            big.len() * 300 < 10 << 30,
            "10 GB costs {} bytes on disk",
            big.len()
        );
    }

    /// The shape the task names: a central directory claiming 1 KB per
    /// entry over a payload that expands to tens of megabytes. The cap has
    /// to stop it while it expands, because the declared size is the lie.
    #[test]
    fn a_zip_declaring_1kb_and_expanding_to_64mb_is_stopped() {
        let z = lying_zip(64 << 20);
        let r = ZipReader::with_limit(&z, 1 << 20).expect("parse");
        assert_eq!(
            r.list()[0].size,
            1024,
            "the header must be lying for this test to mean anything"
        );

        let err = r.extract("bomb.txt").expect_err("must stop at the budget");
        let CompressError::DecompressionFailed(msg) = &err else {
            panic!("expected a budget refusal, got {err:?}")
        };
        assert!(
            msg.contains("1048576"),
            "the limit must be in the message: {msg}"
        );
        assert!(
            msg.contains("1024 declared"),
            "the lie must be in the message: {msg}"
        );
        assert_eq!(r.budget().1, 0, "a refused entry must not spend the budget");

        // The whole payload is 186 KB on disk; the declared size is 1 KB.
        // Whatever the cap is, the bytes actually decoded are bounded by it.
        assert!(z.len() < 1 << 20, "fixture is {} bytes", z.len());
    }

    /// The budget belongs to the archive, not to the entry: no single entry
    /// is over the limit here, and together they are.
    #[test]
    fn the_budget_is_shared_across_the_whole_archive() {
        let bomb = deflate_bomb(1 << 20);
        let one = bomb_expansion(1 << 20);
        let limit = one as u64 + one as u64 / 2;
        let crc = crc32(&vec![b'A'; one]);
        let z = zip_entry(&[
            ("a.txt", 8, &bomb, Some(one as u32), Some(crc)),
            ("b.txt", 8, &bomb, Some(one as u32), Some(crc)),
        ]);

        let r = ZipReader::with_limit(&z, limit).expect("parse");
        let first = r.extract("a.txt").expect("first entry fits");
        assert_eq!(first.len(), one);
        assert!(first.iter().all(|&b| b == b'A'));
        assert_eq!(r.budget(), (limit, one as u64));

        let err = r.extract("b.txt").expect_err("the archive budget is spent");
        let CompressError::DecompressionFailed(msg) = &err else {
            panic!("{err:?}")
        };
        assert!(
            msg.contains(&format!("{one} bytes already decoded")),
            "{msg}"
        );
    }

    /// A header that declares more than the archive may expand to is
    /// refused before a byte of it is decoded.
    #[test]
    fn a_declared_size_over_the_budget_is_refused_before_decoding() {
        let bomb = deflate_bomb(1 << 20);
        let z = zip_entry(&[("huge.txt", 8, &bomb, Some(1 << 30), None)]);
        let r = ZipReader::with_limit(&z, 1 << 20).expect("parse");
        let err = r
            .extract("huge.txt")
            .expect_err("must refuse the declaration");
        let CompressError::DecompressionFailed(msg) = &err else {
            panic!("{err:?}")
        };
        assert!(msg.contains("1073741824 declared"), "{msg}");
        assert_eq!(
            r.budget().1,
            0,
            "nothing may be decoded to refuse a declaration"
        );
    }

    /// A stored entry with a lying uncompressed size is caught the same way
    /// the compressed ones are — `reserve` on the declared size would not
    /// catch it, and the copy is the cheapest way to spend a budget.
    #[test]
    fn a_stored_entry_lying_about_its_size_is_stopped() {
        let payload = vec![b'Z'; 1 << 20];
        let z = zip_entry(&[("flat.bin", 0, &payload, Some(1024), None)]);
        let r = ZipReader::with_limit(&z, 1 << 16).expect("parse");
        let err = r.extract("flat.bin").expect_err("must stop at the budget");
        let CompressError::DecompressionFailed(msg) = &err else {
            panic!("{err:?}")
        };
        assert!(msg.contains("1024 declared"), "{msg}");
        assert!(msg.contains("65536"), "{msg}");
    }

    /// The other half: a real archive has to come out whole. 5000 stored
    /// entries, every one of them checked against its own content, under
    /// the default budget. This passes with or without the cap — that is
    /// what a control is for.
    #[test]
    fn five_thousand_entries_still_extract_whole() {
        let body = vec![b'q'; 256];
        let entries: Vec<(String, Vec<u8>)> = (0..5000)
            .map(|i| (format!("dir/f{i:05}.txt"), body.clone()))
            .collect();
        let entries: Vec<RawZipEntry<'_>> = entries
            .iter()
            .map(|(n, d)| (n.as_str(), 0u16, &d[..], None, None))
            .collect();
        let z = zip_entry(&entries);

        let r = ZipReader::new(&z).expect("parse");
        assert_eq!(r.list().len(), 5000);
        let all = r
            .extract_all()
            .expect("every entry fits under the default budget");
        assert_eq!(all.len(), 5000);
        for (i, (name, _, bytes, _, _)) in entries.iter().enumerate() {
            assert_eq!(
                all.get(*name).map(Vec::as_slice),
                Some(&bytes[..]),
                "entry {i}"
            );
        }
        assert_eq!(r.budget(), (default_byte_limit(), 5000 * 256));
    }

    /// The number the default is, so it cannot drift from the one the
    /// archive adapters' byte budget falls back to.
    #[test]
    fn the_default_limit_is_the_context_default() {
        assert_eq!(
            default_byte_limit(),
            crate::Ctx::default().max_file_size as u64
        );
    }

    /// Every method the reader implements still decodes whole under a cap
    /// barely above its real size, on the python-zipfile vectors rather
    /// than on anything built here — bzip2, lzma and xz each take a
    /// different bounded path than deflate, and none may regress into a
    /// refusal or a short read.
    #[test]
    fn every_supported_method_still_decodes_under_a_tight_cap() {
        macro_rules! case {
            ($name:literal) => {{
                let z = include_bytes!(concat!("../testdata/zip_", $name, ".zip"));
                let expected = include_bytes!(concat!("../testdata/zip_", $name, ".expected"));
                let r = ZipReader::with_limit(z, 4096)
                    .unwrap_or_else(|e| panic!("{}/{}: {e}", $name, $name));
                let got = r
                    .extract("readme.txt")
                    .unwrap_or_else(|e| panic!("{}/{}: {e}", $name, $name));
                assert_eq!(got, &expected[..], "{}/{}/readme", $name, $name);
                assert_eq!(
                    r.budget().1,
                    expected.len() as u64,
                    "{}/{} spend",
                    $name,
                    $name
                );
            }};
        }
        case!("text_store");
        case!("text_deflate");
        case!("text_bzip2");
        case!("text_lzma");
        case!("binary_deflate");
        case!("binary_bzip2");
        case!("binary_lzma");
        case!("empty_store");
        case!("empty_bzip2");
        case!("empty_lzma");
        case!("zip64");
        case!("text_m95");
    }

    /// The measurement the whole change turns on, and the reason it is
    /// `#[ignore]`d because it builds a 10 GB expansion: the ratio the
    /// header in `lying_zip` claims, at the scale the task names. It
    /// measures rather than asserts timing — the assertion is that the
    /// budget stops it, and `RGX_ZIP_BOMB_BYTES` scales the corpus down
    /// when 10 GB of allocation is not wanted.
    ///
    /// The uncoded column is what the same entry costs through
    /// `DeflateDecoder::decode`, i.e. the path this replaced.
    #[test]
    #[ignore = "10 GB of allocation; run with --release --ignored"]
    fn ten_gigabytes_from_a_1kb_declaration() {
        let target: usize = std::env::var("RGX_ZIP_BOMB_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10 << 30);
        let bomb = deflate_bomb(target);
        let expansion = bomb_expansion(target);
        let z = zip_entry(&[(
            "bomb.txt",
            8,
            &bomb,
            Some(1024),
            Some(crc32(&vec![b'A'; 1024])),
        )]);
        let r = ZipReader::new(&z).expect("parse");
        std::eprintln!(
            "zip on disk {} B, header declares {} B, real expansion {} B, budget {} B",
            z.len(),
            r.list()[0].size,
            expansion,
            r.budget().0
        );

        let t = std::time::Instant::now();
        let err = r.extract("bomb.txt").expect_err("stopped");
        let bounded = t.elapsed();
        assert!(matches!(err, CompressError::DecompressionFailed(_)));
        std::eprintln!("capped at default: {bounded:?}");

        for limit in [64 << 20, 8 << 20] {
            let t = std::time::Instant::now();
            let err = ZipReader::with_limit(&z, limit)
                .expect("parse")
                .extract("bomb.txt");
            std::eprintln!(
                "capped at {limit:>12}: {:?} ({})",
                t.elapsed(),
                err.err().map(|_| "refused").unwrap_or("extracted")
            );
        }

        let t = std::time::Instant::now();
        let whole = DeflateDecoder::new()
            .decode(&bomb)
            .map(|v| v.len())
            .unwrap_or(0);
        std::eprintln!("uncapped:          {:?} -> {whole} B", t.elapsed());
        assert_eq!(whole, expansion);
    }

    /// Third-party vectors: archives emitted by Python's zipfile module
    /// (the reference writers) over empty/text/binary payloads in store,
    /// deflate, bzip2 and lzma, plus an allowZip64 archive. Readme.txt's
    /// content is the .expected twin; nested/inner.bin is its reversal.
    #[test]
    fn test_zip_third_party_vectors() {
        macro_rules! case {
            ($name:literal) => {{
                let data = include_bytes!(concat!("../testdata/zip_", $name, ".zip"));
                let expected = include_bytes!(concat!("../testdata/zip_", $name, ".expected"));
                let r = ZipReader::new(data).unwrap_or_else(|e| panic!("zip_{}: {e}", $name));
                assert_eq!(r.list().len(), 2, "zip_{} entries", $name);
                assert_eq!(
                    r.extract("readme.txt")
                        .unwrap_or_else(|e| panic!("zip_{}: {e}", $name)),
                    expected,
                    "zip_{} readme",
                    $name
                );
                let mut rev: Vec<u8> = expected.to_vec();
                rev.reverse();
                assert_eq!(
                    r.extract("nested/inner.bin")
                        .unwrap_or_else(|e| panic!("zip_{}: {e}", $name)),
                    rev,
                    "zip_{} nested",
                    $name
                );
            }};
        }
        case!("empty_store");
        case!("empty_deflate");
        case!("text_store");
        case!("text_deflate");
        case!("text_bzip2");
        case!("text_lzma");
        case!("binary_store");
        case!("binary_deflate");
        case!("binary_bzip2");
        case!("binary_lzma");
        case!("zip64");
    }

    /// A method we do not implement must be an error, never the raw
    /// compressed bytes passed off as the file's content.
    #[test]
    fn test_unknown_method_is_refused() {
        let raw = zip_entry(&[("readme.txt", 98, b"data", Some(4), Some(crc32(b"data")))]);
        let r = ZipReader::new(&raw).expect("parse");
        let err = r.extract("readme.txt").expect_err("must refuse ppmd");
        assert!(matches!(err, CompressError::InvalidFormat(_)));
    }

    #[test]
    fn test_method_93_zstd_decodes() {
        let frame = b"\x28\xb5\x2f\xfd\x04\x58\x61\x00\x00hello zstd\\n\xca\xfb\x72\x73";
        let original = b"hello zstd\\n";
        let raw = zip_entry(&[(
            "readme.txt",
            93,
            frame,
            Some(original.len() as u32),
            Some(crc32(original)),
        )]);
        let r = ZipReader::new(&raw).expect("parse");
        assert_eq!(r.extract("readme.txt").expect("extract zstd"), original);
    }

    /// Method 95 (XZ) inside a zip: a hand-built archive around a
    /// python-lzma (liblzma) FORMAT_XZ stream, decoded and CRC-verified.
    #[test]
    fn test_method_95_decodes() {
        let data = include_bytes!("../testdata/zip_text_m95.zip");
        let expected = include_bytes!("../testdata/zip_text_m95.expected");
        let r = ZipReader::new(data).expect("parse");
        assert_eq!(r.extract("readme.txt").expect("extract"), &expected[..]);
    }

    #[test]
    fn test_rejects_non_zip() {
        assert!(ZipReader::new(b"not a zip at all").is_err());
    }

    /// Truncation at every length must error, never panic.
    #[test]
    fn test_truncated_never_panics() {
        let data = include_bytes!("../testdata/zip_text_deflate.zip");
        for cut in (0..data.len()).step_by(97) {
            let _ = ZipReader::new(&data[..cut]);
        }
    }

    // ---- shapes the tests above do not cover -------------------------

    /// The knobs a raw entry needs: the general purpose flag, the sizes
    /// written into the local header, the sizes written into the central
    /// directory, and an extra field.
    struct RawSpec<'a> {
        name: &'a str,
        flags: u16,
        payload: &'a [u8],
        local_csize: u32,
        local_size: u32,
        central_csize: u32,
        central_size: u32,
        extra: &'a [u8],
    }

    fn zip_entry_raw(s: RawSpec<'_>) -> Vec<u8> {
        let RawSpec {
            name,
            flags,
            payload,
            local_csize,
            local_size,
            central_csize,
            central_size,
            extra,
        } = s;
        let crc = crc32(payload);
        let mut out = Vec::new();
        let offset = 0u32;

        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // store
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&local_csize.to_le_bytes());
        out.extend_from_slice(&local_size.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(extra);
        out.extend_from_slice(payload);

        let mut central = Vec::new();
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&flags.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&[0u8; 4]);
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&central_csize.to_le_bytes());
        central.extend_from_slice(&central_size.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        // comment len (2), disk number (2), internal (2), external (4)
        central.extend_from_slice(&[0u8; 10]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
        central.extend_from_slice(extra);

        let cd_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    /// A zip64 extra field (id 0x0001, §4.5.3) holding `values` as
    /// little-endian u64s, in the fixed order uncompressed, compressed,
    /// local header offset.
    fn zip64_extra(values: &[u64]) -> Vec<u8> {
        let mut body = Vec::new();
        for v in values {
            body.extend_from_slice(&v.to_le_bytes());
        }
        let mut out = Vec::new();
        out.extend_from_slice(&1u16.to_le_bytes()); // header id
        out.extend_from_slice(&(body.len() as u16).to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// A 0xFFFFFFFF size slot takes its value from the 0x0001 extra
    /// field, and only saturated slots appear there — so a 2-value field
    /// supplies uncompressed and compressed size while the offset keeps
    /// its 32-bit value.
    #[test]
    fn a_zip64_extra_field_supplies_the_saturated_sizes() {
        let payload = b"data";
        let extra = zip64_extra(&[payload.len() as u64, payload.len() as u64]);
        let z = zip_entry_raw(RawSpec {
            name: "z64.txt",
            flags: 0,
            payload,
            local_csize: payload.len() as u32,
            local_size: payload.len() as u32,
            central_csize: SAT_U32,
            central_size: SAT_U32, // both central sizes saturated
            extra: &extra,
        });

        let r = ZipReader::new(&z).expect("parse");
        assert_eq!(r.list().len(), 1);
        assert_eq!(r.list()[0].size, 4, "the 32-bit slot is saturated");
        assert_eq!(r.list()[0].compressed_size, 4);
        assert_eq!(r.extract("z64.txt").expect("extract"), payload);
    }

    /// A zip64 value past u32 is refused rather than truncated: the
    /// metadata fields are u32, and wrapping one would slice the wrong
    /// byte range on extract.
    #[test]
    fn a_zip64_size_past_4gib_is_refused() {
        let payload = b"tiny";
        let too_big = u32::MAX as u64 + 1;
        let extra = zip64_extra(&[too_big, payload.len() as u64]);
        let z = zip_entry_raw(RawSpec {
            name: "big.txt",
            flags: 0,
            payload,
            local_csize: payload.len() as u32,
            local_size: payload.len() as u32,
            central_csize: SAT_U32,
            central_size: SAT_U32,
            extra: &extra,
        });
        let err = ZipReader::new(&z).expect_err("must refuse");
        assert!(matches!(err, CompressError::InvalidFormat(_)), "{err:?}");
    }

    /// An entry written with a data descriptor (general purpose bit 3)
    /// carries zeros in its local header; the sizes the reader uses come
    /// from the central directory either way, and the descriptor after
    /// the body is not read on the extract path at all.
    #[test]
    fn an_entry_with_a_data_descriptor_extracts_from_the_central_directory() {
        let payload = b"streamed payload";
        let mut z = zip_entry_raw(RawSpec {
            name: "dd.txt",
            flags: 0x0008, // bit 3: sizes live in a trailing descriptor
            payload,
            local_csize: 0,
            local_size: 0, // local header: no sizes here
            central_csize: payload.len() as u32,
            central_size: payload.len() as u32,
            extra: &[],
        });
        // Splice a data descriptor between the body and the central
        // directory: optional signature, CRC, compressed size,
        // uncompressed size. The extract path must not need it.
        let cd_start = z
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .expect("central directory");
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(b"PK\x07\x08");
        descriptor.extend_from_slice(&crc32(payload).to_le_bytes());
        descriptor.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        descriptor.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        z.splice(cd_start..cd_start, descriptor);
        // The central directory offset in the EOCD moves by the
        // descriptor's length; the reader does not use the EOCD offset
        // for the entry walk (it walks from the offset the zip64 branch
        // or the plain field gives), but keep the archive self-consistent.
        let eocd = z.len() - 22;
        let old = u32::from_le_bytes([z[eocd + 16], z[eocd + 17], z[eocd + 18], z[eocd + 19]]);
        let new = old + 16; // descriptor length
        z[eocd + 16..eocd + 20].copy_from_slice(&new.to_le_bytes());

        let r = ZipReader::new(&z).expect("parse");
        let e = &r.list()[0];
        assert_eq!(e.size, payload.len() as u32);
        assert_eq!(
            r.extract("dd.txt").expect("extract"),
            payload,
            "central directory sizes win over the zero local header"
        );
    }

    /// The zip64 EOCD is found through the locator immediately before
    /// the EOCD when the 32-bit EOCD fields saturate. The locator and
    /// record signatures are checked, and the counts/offset come from
    /// the zip64 record.
    #[test]
    fn the_zip64_eocd_is_read_through_its_locator() {
        let payload = b"zip64 counts";
        let mut z = zip_entry(&[("c.txt", 0, payload, None, None)]);
        // The last 22 bytes are the EOCD; replace it with a zip64 EOCD
        // + locator + saturated EOCD, keeping the central directory
        // where it is.
        z.truncate(z.len() - 22);
        let cd_offset = z
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .expect("central directory");
        let eocd64_off = z.len() as u64;
        let cd_size = eocd64_off - cd_offset as u64;

        z.extend_from_slice(b"PK\x06\x06"); // zip64 EOCD
        z.extend_from_slice(&44u64.to_le_bytes()); // record size after these 12 bytes
        z.extend_from_slice(&45u16.to_le_bytes()); // version made by
        z.extend_from_slice(&45u16.to_le_bytes()); // version needed
        z.extend_from_slice(&0u32.to_le_bytes()); // disk
        z.extend_from_slice(&0u32.to_le_bytes()); // disk with CD
        z.extend_from_slice(&1u64.to_le_bytes()); // entries on this disk
        z.extend_from_slice(&1u64.to_le_bytes()); // total entries
        z.extend_from_slice(&cd_size.to_le_bytes());
        z.extend_from_slice(&(cd_offset as u64).to_le_bytes());

        z.extend_from_slice(b"PK\x06\x07"); // zip64 locator
        z.extend_from_slice(&0u32.to_le_bytes()); // disk with zip64 EOCD
        z.extend_from_slice(&eocd64_off.to_le_bytes());
        z.extend_from_slice(&1u32.to_le_bytes()); // total disks

        z.extend_from_slice(b"PK\x05\x06"); // EOCD, fields saturated
        z.extend_from_slice(&[0u8; 4]);
        z.extend_from_slice(&0xFFFFu16.to_le_bytes());
        z.extend_from_slice(&0xFFFFu16.to_le_bytes());
        z.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        z.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());

        let r = ZipReader::new(&z).expect("parse through the zip64 records");
        assert_eq!(r.list().len(), 1);
        assert_eq!(r.extract("c.txt").expect("extract"), payload);
    }

    /// A `PK\x05\x06` inside an archive comment is not the end of
    /// central directory: the real record is the one whose own comment
    /// length reaches the end of the file.
    #[test]
    fn an_eocd_signature_inside_the_comment_is_not_the_record() {
        let mut z = zip_entry(&[("c.txt", 0, b"x", None, None)]);
        // comment: a fake signature followed by zeros (which would read
        // as comment length 0 and a zero central directory)
        z.truncate(z.len() - 2); // drop the zero comment length
        let mut comment = b"PK\x05\x06".to_vec();
        comment.extend_from_slice(&[0u8; 30]);
        z.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        z.extend_from_slice(&comment);

        let r = ZipReader::new(&z).expect("the real EOCD wins");
        assert_eq!(r.list().len(), 1);
        assert_eq!(r.extract("c.txt").expect("extract"), b"x");
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: Vec<(&'static str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("zeros", vec![0u8; 256]),
            ("zip", zip_entry(&[("a.txt", 0, b"hi", None, None)])),
            ("sig", b"PK\x05\x06".to_vec()),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 200, "zip", |data| {
            let _ = ZipReader::new(data);
        });
    }
}
