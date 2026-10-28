// SPDX-License-Identifier: Apache-2.0

//! 7z archive container reader.
//!
//! Independent reimplementation of the 7z format (7zFormat.txt from the
//! 7-Zip SDK): signature header with CRC, raw and encoded (compressed)
//! headers, bind-pair coder chains (Copy, LZMA1, LZMA2, Deflate, BZip2,
//! Delta, x86 BCJ), UTF-16LE file table, sub-streams, and per-entry CRC
//! verification.  Encrypted (AES-256), PPMd, and non-x86 BCJ filters
//! report [`CompressError::Unsupported`] rather than silently
//! mis-decoding.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::bzip2::Bzip2Decoder;
use super::crc32::crc32;
use super::deflate::DeflateDecoder;
use super::error::{CompressError, CompressResult};
use super::lzma::{LzmaDecoder, LzmaProps};

// ── Test instrumentation ─────────────────────────────────────────────────

// Folder decodes performed on the current thread.
//
// The contract this pins is "one decode per folder, however many files the
// folder holds" -- the thing a per-file extract violates silently, with no
// wrong answer to catch it. A timing assertion cannot hold on a shared CI
// box, and a global counter would make the test depend on which unrelated
// cases run alongside it, so this is thread-local and count-based.
#[cfg(test)]
std::thread_local! {
    static FOLDER_DECODES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
#[inline]
fn count_decode() {
    FOLDER_DECODES.with(|c| c.set(c.get() + 1));
}

#[cfg(not(test))]
#[inline]
fn count_decode() {}

/// Folder decodes since the last [`take_folder_decodes`].
#[cfg(test)]
pub(crate) fn take_folder_decodes() -> usize {
    FOLDER_DECODES.with(|c| c.take())
}

// ── Format constants ────────────────────────────────────────────────────

const K_END: u8 = 0x00;
const K_HEADER: u8 = 0x01;
const K_ARCHIVE_PROPERTIES: u8 = 0x02;
const K_MAIN_STREAMS_INFO: u8 = 0x04;
const K_FILES_INFO: u8 = 0x05;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SUB_STREAMS_INFO: u8 = 0x08;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0A;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const K_NUM_UNPACK_STREAM: u8 = 0x0D;
const K_EMPTY_STREAM: u8 = 0x0E;
const K_EMPTY_FILE: u8 = 0x0F;
const K_ANTI: u8 = 0x10;
const K_NAME: u8 = 0x11;
const K_C_TIME: u8 = 0x12;
const K_A_TIME: u8 = 0x13;
const K_M_TIME: u8 = 0x14;
const K_WIN_ATTRIBUTES: u8 = 0x15;
const K_START_POS: u8 = 0x18;
const K_DUMMY: u8 = 0x19;
const K_ENCODED_HEADER: u8 = 0x17;

const SIGNATURE: [u8; 6] = *b"7z\xBC\xAF\x27\x1C";
const SIGNATURE_HEADER_SIZE: usize = 32;

// Coder method IDs.
const ID_COPY: [u8; 1] = [0x00];
const ID_DELTA: [u8; 1] = [0x03];
const ID_LZMA1: [u8; 3] = [0x03, 0x01, 0x01];
const ID_PPMD: [u8; 3] = [0x03, 0x04, 0x01];
const ID_LZMA2: [u8; 1] = [0x21];
const ID_DEFLATE: [u8; 3] = [0x04, 0x01, 0x08];
const ID_BZIP2: [u8; 3] = [0x04, 0x02, 0x02];
const ID_BCJ_X86: [u8; 4] = [0x03, 0x03, 0x01, 0x03];

// ── Public data types ───────────────────────────────────────────────────

/// One file (or directory) entry of a [`SevenzArchive`].
#[derive(Debug, Clone)]
pub struct SevenzFile {
    /// UTF-16 decoded entry name, with `/` separators.
    pub name: String,
    /// True for directory entries (no payload).
    pub is_directory: bool,
    /// Unpacked size in bytes (0 for directories and empty files).
    pub size: u64,
    /// CRC-32 of the unpacked payload, when the archive records one.
    pub crc32: Option<u32>,
    /// (folder, sub-stream) location of the payload.
    stream: Option<(usize, usize)>,
}

/// A parsed 7z archive.  Borrows the original buffer for payload
/// extraction.
#[derive(Debug)]
pub struct SevenzArchive<'a> {
    data: &'a [u8],
    /// Offset of the pack-data area, relative to the end of the
    /// 32-byte signature header.
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    pack_offsets: Vec<u64>,
    folders: Vec<SevenzFolder>,
    files: Vec<SevenzFile>,
}

#[derive(Debug)]
struct SevenzFolder {
    coders: Vec<SevenzCoder>,
    bind_pairs: Vec<(u64, u64)>,
    packed_streams: Vec<u64>,
    /// Index of this folder's first packed stream in the archive's global
    /// pack-stream list.
    ///
    /// **Folders own consecutive pack streams, so this is the only thing
    /// that tells folder N where its compressed bytes live.** 7z stores one
    /// packed stream per folder by default, which is why an implementation
    /// that assumes "the pack stream is always number 0" passes every
    /// single-folder archive it is given and corrupts everything after the
    /// first in a multi-folder one -- the decoded bytes are folder 0's,
    /// re-run through folder N's coder chain, and the sub-stream CRC turns
    /// that into `CRC mismatch` instead of wrong text. `pack_offsets` holds
    /// the matching byte offset; both are computed once, in `parse`.
    pack_start_index: usize,
    /// Unpack size per coder output stream, in global output order.
    unpack_sizes: Vec<u64>,
    /// Total folder output size (main coder output).
    unpack_size: u64,
    /// Per sub-stream: (size, crc).
    substreams: Vec<(u64, Option<u32>)>,
}

#[derive(Debug)]
struct SevenzCoder {
    id: Vec<u8>,
    num_in: u64,
    num_out: u64,
    props: Vec<u8>,
}

// ── Reader helpers ──────────────────────────────────────────────────────

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn u8(&mut self) -> CompressResult<u8> {
        let b = *self.buf.get(self.pos).ok_or(CompressError::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }

    fn u32le(&mut self) -> CompressResult<u32> {
        let b = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or(CompressError::UnexpectedEof)?;
        self.pos += 4;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64le(&mut self) -> CompressResult<u64> {
        let b = self
            .buf
            .get(self.pos..self.pos + 8)
            .ok_or(CompressError::UnexpectedEof)?;
        self.pos += 8;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn take(&mut self, n: usize) -> CompressResult<&'a [u8]> {
        let b = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or(CompressError::UnexpectedEof)?;
        self.pos += n;
        Ok(b)
    }

    fn skip(&mut self, n: usize) -> CompressResult<()> {
        self.take(n).map(|_| ())
    }

    /// 7z variable-length integer: leading mask bits select how many
    /// extra bytes carry the low-order value.
    fn varint(&mut self) -> CompressResult<u64> {
        let first = self.u8()? as u64;
        let mut mask = 0x80u64;
        let mut value = 0u64;
        for i in 0..8 {
            if (first & mask) == 0 {
                return Ok(value | ((first & (mask - 1)) << (8 * i)));
            }
            let b = self.u8()? as u64;
            value |= b << (8 * i);
            mask >>= 1;
        }
        Ok(value)
    }

    /// Bounded count: every counted element consumes at least one header
    /// byte, so no legitimate count can exceed the remaining input.
    fn bounded(&mut self, field: &'static str) -> CompressResult<usize> {
        let v = self.varint()?;
        if v > self.remaining() as u64 {
            return Err(CompressError::InvalidFormat(field));
        }
        Ok(v as usize)
    }
}

/// MSB-first bit vector, as used by empty-stream/file and CRC-defined maps.
fn read_bits(r: &mut Reader, size: usize) -> CompressResult<Vec<bool>> {
    let mut bits = Vec::with_capacity(size);
    let mut mask = 0u8;
    let mut cache = 0u8;
    for _ in 0..size {
        if mask == 0 {
            mask = 0x80;
            cache = r.u8()?;
        }
        bits.push((cache & mask) != 0);
        mask >>= 1;
    }
    Ok(bits)
}

/// Either "all defined" (non-zero marker byte) or an explicit bit map.
fn read_all_or_bits(r: &mut Reader, size: usize) -> CompressResult<Vec<bool>> {
    if r.u8()? != 0 {
        Ok(vec![true; size])
    } else {
        read_bits(r, size)
    }
}

/// CRC section: definition map followed by one LE u32 per defined entry.
fn read_crc_section(r: &mut Reader, size: usize) -> CompressResult<Vec<Option<u32>>> {
    let defined = read_all_or_bits(r, size)?;
    let mut out = Vec::with_capacity(size);
    for d in defined {
        out.push(if d { Some(r.u32le()?) } else { None });
    }
    Ok(out)
}

// ── Parsing ─────────────────────────────────────────────────────────────

struct StreamsInfo {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    folders: Vec<SevenzFolder>,
}

impl<'a> SevenzArchive<'a> {
    /// Parse the archive structure (headers, folders, file table).
    /// Payload data is decoded lazily by [`Self::extract`].
    pub fn parse(data: &'a [u8]) -> CompressResult<Self> {
        let sig = data
            .get(..SIGNATURE_HEADER_SIZE)
            .ok_or(CompressError::UnexpectedEof)?;
        if sig[..6] != SIGNATURE {
            return Err(CompressError::InvalidFormat("not a 7z archive"));
        }
        let start_header_crc = u32::from_le_bytes([sig[8], sig[9], sig[10], sig[11]]);
        if crc32(&sig[12..32]) != start_header_crc {
            return Err(CompressError::CorruptedData("start header CRC mismatch"));
        }
        let next_header_offset = u64::from_le_bytes([
            sig[12], sig[13], sig[14], sig[15], sig[16], sig[17], sig[18], sig[19],
        ]);
        let next_header_size = u64::from_le_bytes([
            sig[20], sig[21], sig[22], sig[23], sig[24], sig[25], sig[26], sig[27],
        ]);
        let next_header_crc = u32::from_le_bytes([sig[28], sig[29], sig[30], sig[31]]);

        let header_start = SIGNATURE_HEADER_SIZE as u64 + next_header_offset;
        let header_end = header_start
            .checked_add(next_header_size)
            .ok_or(CompressError::InvalidFormat("header offset overflow"))?;
        if header_end > data.len() as u64 {
            return Err(CompressError::UnexpectedEof);
        }
        let header_bytes = &data[header_start as usize..header_end as usize];
        if crc32(header_bytes) != next_header_crc {
            return Err(CompressError::CorruptedData("next header CRC mismatch"));
        }

        let mut r = Reader::new(header_bytes);
        let nid = r.u8()?;
        let main: StreamsInfo;
        let files: Vec<SevenzFile>;
        if nid == K_ENCODED_HEADER {
            // The real header is the single folder described by the
            // streams-info that follows; its pack data sits at `pack_pos`
            // relative to the end of the signature header.
            let enc = Self::read_streams_info(&mut r)?;
            if enc.folders.len() != 1 || enc.pack_sizes.is_empty() {
                return Err(CompressError::InvalidFormat(
                    "encoded header must have exactly one folder",
                ));
            }
            let pack_start = SIGNATURE_HEADER_SIZE as u64 + enc.pack_pos;
            let pack_len = enc.pack_sizes[0] as usize;
            let pack_end = pack_start
                .checked_add(pack_len as u64)
                .ok_or(CompressError::InvalidFormat("pack offset overflow"))?;
            if pack_end > data.len() as u64 {
                return Err(CompressError::UnexpectedEof);
            }
            let decoded = Self::decode_folder_bytes(
                &enc.folders[0],
                &data[pack_start as usize..pack_end as usize],
                enc.folders[0].unpack_size,
            )?;
            let mut hr = Reader::new(&decoded);
            if hr.u8()? != K_HEADER {
                return Err(CompressError::InvalidFormat("missing 7z header"));
            }
            let (m, f) = Self::read_header(&mut hr)?;
            main = m;
            files = f;
        } else if nid == K_HEADER {
            let (m, f) = Self::read_header(&mut r)?;
            main = m;
            files = f;
        } else {
            return Err(CompressError::InvalidFormat("missing 7z header"));
        }

        // Cumulative pack-stream offsets within the pack area.
        let mut pack_offsets = Vec::with_capacity(main.pack_sizes.len());
        let mut acc = 0u64;
        for &s in &main.pack_sizes {
            pack_offsets.push(acc);
            acc = acc
                .checked_add(s)
                .ok_or(CompressError::InvalidFormat("pack size overflow"))?;
        }

        Ok(Self {
            data,
            pack_pos: main.pack_pos,
            pack_sizes: main.pack_sizes,
            pack_offsets,
            folders: main.folders,
            files,
        })
    }

    /// Archive entries in stored order.
    pub fn files(&self) -> &[SevenzFile] {
        &self.files
    }

    /// How many folders the archive holds -- one decoder run each, at most.
    pub fn folder_count(&self) -> usize {
        self.folders.len()
    }

    /// `(folder, sub-stream)` holding the entry's payload, if it has one.
    pub fn stream_of(&self, index: usize) -> Option<(usize, usize)> {
        self.files.get(index).and_then(|f| f.stream)
    }

    /// The pack area: every folder's packed stream, concatenated in order.
    fn pack_area(&self) -> CompressResult<&[u8]> {
        let start = SIGNATURE_HEADER_SIZE as u64 + self.pack_pos;
        let total = self
            .pack_sizes
            .iter()
            .try_fold(0u64, |a, &b| a.checked_add(b))
            .ok_or(CompressError::InvalidFormat("pack size overflow"))?;
        let end = start
            .checked_add(total)
            .ok_or(CompressError::InvalidFormat("pack offset overflow"))?;
        if end > self.data.len() as u64 {
            return Err(CompressError::UnexpectedEof);
        }
        Ok(&self.data[start as usize..end as usize])
    }

    /// One folder's packed bytes, addressed by that folder's own index into
    /// the global pack tables.
    fn folder_packed(&self, folder_idx: usize) -> CompressResult<&[u8]> {
        let folder = self
            .folders
            .get(folder_idx)
            .ok_or(CompressError::InvalidFormat("folder index out of range"))?;
        if folder.packed_streams.len() != 1 {
            return Err(CompressError::Unsupported("multi-pack-stream folders"));
        }
        let pi = folder.pack_start_index;
        let off = usize::try_from(self.pack_offsets[pi])
            .map_err(|_| CompressError::InvalidFormat("pack offset out of range"))?;
        let len = usize::try_from(self.pack_sizes[pi])
            .map_err(|_| CompressError::InvalidFormat("pack size out of range"))?;
        let area = self.pack_area()?;
        let end = off
            .checked_add(len)
            .ok_or(CompressError::InvalidFormat("pack offset overflow"))?;
        area.get(off..end).ok_or(CompressError::UnexpectedEof)
    }

    /// Decode a folder's full output.
    ///
    /// **Callers that walk many entries must hold the result and reuse it**
    /// -- this is the expensive call. See the adapter: one decode per folder,
    /// not one per file.
    pub fn folder_output(&self, folder_idx: usize) -> CompressResult<Vec<u8>> {
        Self::decode_folder_bytes(
            &self.folders[folder_idx],
            self.folder_packed(folder_idx)?,
            self.folder_unpack_size(folder_idx)?,
        )
    }

    /// The bytes a folder declares it will unpack to, before anything is
    /// decoded. A caller with a byte budget asks this first: decoding
    /// materializes the whole folder whether or not the entries inside it
    /// fit what the caller has left.
    pub fn folder_unpack_size(&self, folder_idx: usize) -> CompressResult<u64> {
        self.folders
            .get(folder_idx)
            .map(|f| f.unpack_size)
            .ok_or(CompressError::InvalidFormat("folder index out of range"))
    }

    /// One file's bytes, carved out of a folder output decoded earlier.
    ///
    /// Verifies every sub-stream CRC up to and including the one returned --
    /// the same coverage a per-file decode gave, so a corrupt entry is still
    /// refused rather than searched.
    pub fn substream_bytes(
        &self,
        folder_idx: usize,
        sub_idx: usize,
        folder_out: &[u8],
    ) -> CompressResult<Vec<u8>> {
        let folder = self
            .folders
            .get(folder_idx)
            .ok_or(CompressError::InvalidFormat("folder index out of range"))?;
        let mut out_pos = 0usize;
        for (i, &(size, crc)) in folder.substreams.iter().enumerate() {
            let end = out_pos
                .checked_add(
                    usize::try_from(size)
                        .map_err(|_| CompressError::CorruptedData("substream size out of range"))?,
                )
                .ok_or(CompressError::CorruptedData("substream size overflow"))?;
            if end > folder_out.len() {
                return Err(CompressError::CorruptedData(
                    "substream exceeds folder output",
                ));
            }
            if let Some(expected) = crc {
                let actual = crc32(&folder_out[out_pos..end]);
                if actual != expected {
                    return Err(CompressError::CrcMismatch { expected, actual });
                }
            }
            if i == sub_idx {
                return Ok(folder_out[out_pos..end].to_vec());
            }
            out_pos = end;
        }
        Err(CompressError::CorruptedData("substream index out of range"))
    }

    /// Unpack one entry by index.  Directories and empty files yield an
    /// empty buffer.
    ///
    /// Decodes the entry's whole folder, so a caller extracting many entries
    /// should prefer `folder_output` + `substream_bytes`.
    pub fn extract(&self, index: usize) -> CompressResult<Vec<u8>> {
        let Some((folder_idx, sub_idx)) = self.stream_of(index) else {
            return Ok(Vec::new());
        };
        let out = self.folder_output(folder_idx)?;
        self.substream_bytes(folder_idx, sub_idx, &out)
    }

    /// Find an entry by exact name.
    pub fn index_of_name(&self, name: &str) -> Option<usize> {
        self.files.iter().position(|f| f.name == name)
    }

    // ── Header parsing ──────────────────────────────────────────────

    /// Parse a top-level header: optional archive properties, optional
    /// main streams info, optional files info, kEnd.
    fn read_header(r: &mut Reader) -> CompressResult<(StreamsInfo, Vec<SevenzFile>)> {
        let mut nid = r.u8()?;
        if nid == K_ARCHIVE_PROPERTIES {
            let mut pid = r.u8()?;
            while pid != K_END {
                let size = r.bounded("archive property size")?;
                r.skip(size)?;
                pid = r.u8()?;
            }
            nid = r.u8()?;
        }

        let streams = if nid == K_MAIN_STREAMS_INFO {
            let s = Self::read_streams_info(r)?;
            nid = r.u8()?;
            s
        } else {
            StreamsInfo {
                pack_pos: 0,
                pack_sizes: Vec::new(),
                folders: Vec::new(),
            }
        };

        let files = if nid == K_FILES_INFO {
            let f = Self::read_files_info(r, &streams)?;
            nid = r.u8()?;
            f
        } else {
            Vec::new()
        };

        if nid != K_END {
            return Err(CompressError::InvalidFormat("unterminated 7z header"));
        }
        Ok((streams, files))
    }

    fn read_streams_info(r: &mut Reader) -> CompressResult<StreamsInfo> {
        let mut pack_pos = 0u64;
        let mut pack_sizes: Vec<u64> = Vec::new();
        let mut folders: Vec<SevenzFolder> = Vec::new();
        let mut folder_crcs: Vec<Option<u32>> = Vec::new();
        let mut num_unpack_stream: Option<Vec<u64>> = None;
        let mut sub_sizes: Vec<u64> = Vec::new();
        let mut sub_crcs: Option<Vec<Option<u32>>> = None;

        let mut nid = r.u8()?;
        if nid == K_PACK_INFO {
            pack_pos = r.varint()?;
            let num_packs = r.bounded("pack stream count")?;
            let mut sub = r.u8()?;
            if sub == K_SIZE {
                for _ in 0..num_packs {
                    pack_sizes.push(r.varint()?);
                }
                sub = r.u8()?;
            }
            if sub == K_CRC {
                let _pack_crcs = read_crc_section(r, num_packs)?;
                sub = r.u8()?;
            }
            if sub != K_END {
                return Err(CompressError::InvalidFormat("unterminated pack info"));
            }
            nid = r.u8()?;
        }

        if nid == K_UNPACK_INFO {
            if r.u8()? != K_FOLDER {
                return Err(CompressError::InvalidFormat("expected folder section"));
            }
            let num_folders = r.bounded("folder count")?;
            let external = r.u8()?;
            if external != 0 {
                return Err(CompressError::Unsupported("external folders"));
            }
            for _ in 0..num_folders {
                folders.push(Self::read_folder(r)?);
            }
            if r.u8()? != K_CODERS_UNPACK_SIZE {
                return Err(CompressError::InvalidFormat("expected unpack sizes"));
            }
            for folder in folders.iter_mut() {
                let mut total_out = 0usize;
                for c in &folder.coders {
                    total_out += c.num_out as usize;
                }
                for _ in 0..total_out {
                    folder.unpack_sizes.push(r.varint()?);
                }
            }
            let mut sub = r.u8()?;
            if sub == K_CRC {
                folder_crcs = read_crc_section(r, num_folders)?;
                sub = r.u8()?;
            }
            if sub != K_END {
                return Err(CompressError::InvalidFormat("unterminated unpack info"));
            }
            nid = r.u8()?;
        }

        if nid == K_SUB_STREAMS_INFO {
            let mut sub = r.u8()?;
            if sub == K_NUM_UNPACK_STREAM {
                let mut v = Vec::with_capacity(folders.len());
                for _ in 0..folders.len() {
                    v.push(r.varint()?);
                }
                num_unpack_stream = Some(v);
                sub = r.u8()?;
            }
            if sub == K_SIZE {
                for (fi, _) in folders.iter().enumerate() {
                    let n = num_unpack_stream
                        .as_ref()
                        .and_then(|v| v.get(fi))
                        .copied()
                        .unwrap_or(1);
                    if n > 1 {
                        for _ in 0..n - 1 {
                            sub_sizes.push(r.varint()?);
                        }
                    }
                }
                sub = r.u8()?;
            }
            if sub == K_CRC {
                let total: usize = match &num_unpack_stream {
                    Some(v) => v.iter().try_fold(0usize, |a, &n| {
                        a.checked_add(n as usize)
                            .ok_or(CompressError::InvalidFormat("substream count overflow"))
                    })?,
                    None => folders.len(),
                };
                sub_crcs = Some(read_crc_section(r, total)?);
                sub = r.u8()?;
            }
            if sub != K_END {
                return Err(CompressError::InvalidFormat("unterminated substreams info"));
            }
            nid = r.u8()?;
        }

        if nid != K_END {
            return Err(CompressError::InvalidFormat("unterminated streams info"));
        }

        // Resolve per-folder sub-stream (size, crc) lists.
        let mut sub_size_iter = sub_sizes.iter().copied();
        let mut sub_crc_iter = sub_crcs.map(|v| v.into_iter());
        // Pack streams are handed to folders in order, so folder N's packed
        // bytes start after every folder before it has taken its share. Done
        // here, once, because resolving it per file is what made every entry
        // past the first folder decode the wrong bytes.
        let mut next_pack = 0usize;
        for (i, folder) in folders.iter_mut().enumerate() {
            folder.pack_start_index = next_pack;
            next_pack += folder.packed_streams.len();
            folder.unpack_size = folder.main_unpack_size();
            let n = num_unpack_stream.as_ref().map(|v| v[i]).unwrap_or(1).max(1);
            if n == 1 {
                let crc = folder_crcs
                    .get(i)
                    .copied()
                    .flatten()
                    .or_else(|| sub_crc_iter.as_mut().and_then(|it| it.next()).flatten());
                folder.substreams = vec![(folder.unpack_size, crc)];
            } else {
                let mut sizes = Vec::with_capacity(n as usize);
                let mut sum = 0u64;
                for _ in 0..n - 1 {
                    let s = sub_size_iter
                        .next()
                        .ok_or(CompressError::InvalidFormat("missing substream size"))?;
                    sizes.push(s);
                    sum = sum
                        .checked_add(s)
                        .ok_or(CompressError::InvalidFormat("substream size overflow"))?;
                }
                let last =
                    folder
                        .unpack_size
                        .checked_sub(sum)
                        .ok_or(CompressError::InvalidFormat(
                            "substream sizes exceed folder",
                        ))?;
                sizes.push(last);
                let mut crcs = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    crcs.push(sub_crc_iter.as_mut().and_then(|it| it.next()).flatten());
                }
                folder.substreams = sizes.into_iter().zip(crcs).collect();
            }
        }

        Ok(StreamsInfo {
            pack_pos,
            pack_sizes,
            folders,
        })
    }

    /// Parse one folder: coder list, bind pairs, packed-stream indices.
    fn read_folder(r: &mut Reader) -> CompressResult<SevenzFolder> {
        let num_coders = r.bounded("coder count")?;
        let mut coders = Vec::with_capacity(num_coders);
        let mut total_in = 0u64;
        let mut total_out = 0u64;
        for _ in 0..num_coders {
            let bits = r.u8()?;
            let id_size = (bits & 0x0F) as usize;
            let is_simple = (bits & 0x10) == 0;
            let has_attrs = (bits & 0x20) != 0;
            if (bits & 0x80) != 0 {
                return Err(CompressError::Unsupported("alternative coder methods"));
            }
            let id = r.take(id_size)?.to_vec();
            let (num_in, num_out) = if is_simple {
                (1u64, 1u64)
            } else {
                let i = r.varint()?;
                let o = r.varint()?;
                if i == 0 || o == 0 {
                    return Err(CompressError::InvalidFormat("coder with zero streams"));
                }
                (i, o)
            };
            total_in = total_in
                .checked_add(num_in)
                .ok_or(CompressError::InvalidFormat("coder stream count overflow"))?;
            total_out = total_out
                .checked_add(num_out)
                .ok_or(CompressError::InvalidFormat("coder stream count overflow"))?;
            if total_in > (1 << 20) || total_out > (1 << 20) {
                return Err(CompressError::InvalidFormat("coder stream count overflow"));
            }
            let props = if has_attrs {
                let n = r.bounded("coder properties size")?;
                r.take(n)?.to_vec()
            } else {
                Vec::new()
            };
            coders.push(SevenzCoder {
                id,
                num_in,
                num_out,
                props,
            });
        }

        if total_out == 0 {
            return Err(CompressError::InvalidFormat(
                "folder with no output streams",
            ));
        }
        let num_bind_pairs = (total_out - 1) as usize;
        let mut bind_pairs = Vec::with_capacity(num_bind_pairs);
        for _ in 0..num_bind_pairs {
            let in_index = r.varint()?;
            let out_index = r.varint()?;
            if in_index >= total_in || out_index >= total_out {
                return Err(CompressError::InvalidFormat("bind pair out of range"));
            }
            bind_pairs.push((in_index, out_index));
        }

        if total_in < num_bind_pairs as u64 {
            return Err(CompressError::InvalidFormat("more bind pairs than inputs"));
        }
        let num_packed = (total_in - num_bind_pairs as u64) as usize;
        let mut packed_streams = Vec::with_capacity(num_packed);
        if num_packed == 1 {
            let mut found = None;
            for s in 0..total_in {
                if !bind_pairs.iter().any(|&(bi, _)| bi == s) {
                    found = Some(s);
                    break;
                }
            }
            packed_streams
                .push(found.ok_or(CompressError::InvalidFormat("no packed stream input"))?);
        } else {
            for _ in 0..num_packed {
                let idx = r.varint()?;
                if idx >= total_in {
                    return Err(CompressError::InvalidFormat(
                        "packed stream index out of range",
                    ));
                }
                packed_streams.push(idx);
            }
        }

        Ok(SevenzFolder {
            coders,
            bind_pairs,
            packed_streams,
            pack_start_index: 0,
            unpack_sizes: Vec::new(),
            unpack_size: 0,
            substreams: Vec::new(),
        })
    }

    /// Parse the files section and wire each non-empty file to its
    /// (folder, sub-stream) payload.
    fn read_files_info(r: &mut Reader, streams: &StreamsInfo) -> CompressResult<Vec<SevenzFile>> {
        let num_files = r.bounded("file count")?;
        let mut names: Vec<String> = Vec::new();
        let mut is_empty_stream: Option<Vec<bool>> = None;
        let mut is_empty_file: Option<Vec<bool>> = None;

        loop {
            let prop = r.u8()?;
            if prop == K_END {
                break;
            }
            let size = r.varint()?;
            match prop {
                K_EMPTY_STREAM => {
                    is_empty_stream = Some(read_bits(r, num_files)?);
                }
                K_EMPTY_FILE => {
                    let n = is_empty_stream
                        .as_ref()
                        .map(|v| v.iter().filter(|&&b| b).count())
                        .ok_or(CompressError::InvalidFormat(
                            "kEmptyFile before kEmptyStream",
                        ))?;
                    is_empty_file = Some(read_bits(r, n)?);
                }
                K_ANTI => {
                    let n = is_empty_stream
                        .as_ref()
                        .map(|v| v.iter().filter(|&&b| b).count())
                        .ok_or(CompressError::InvalidFormat("kAnti before kEmptyStream"))?;
                    r.skip(n.div_ceil(8))?;
                }
                K_NAME => {
                    let external = r.u8()?;
                    if external != 0 {
                        return Err(CompressError::Unsupported("external file names"));
                    }
                    // `size` counts the external byte plus the UTF-16LE
                    // blob; the blob itself is `size - 1` bytes and must
                    // contain an even number of code units.
                    if size == 0 || (size - 1) & 1 != 0 {
                        return Err(CompressError::InvalidFormat("invalid names size"));
                    }
                    let nbytes = (size - 1) as usize;
                    let blob = r.take(nbytes)?;
                    names = parse_names(blob, num_files)?;
                }
                K_C_TIME | K_A_TIME | K_M_TIME => {
                    let defined = read_all_or_bits(r, num_files)?;
                    let external = r.u8()?;
                    if external != 0 {
                        return Err(CompressError::Unsupported("external times"));
                    }
                    for d in &defined {
                        if *d {
                            r.skip(8)?;
                        }
                    }
                }
                K_WIN_ATTRIBUTES => {
                    let defined = read_all_or_bits(r, num_files)?;
                    let external = r.u8()?;
                    if external != 0 {
                        return Err(CompressError::Unsupported("external attributes"));
                    }
                    for d in &defined {
                        if *d {
                            r.skip(4)?;
                        }
                    }
                }
                K_START_POS => {
                    return Err(CompressError::Unsupported("kStartPos"));
                }
                K_DUMMY => {
                    let n = if size > r.remaining() as u64 {
                        return Err(CompressError::InvalidFormat("dummy property size"));
                    } else {
                        size as usize
                    };
                    r.skip(n)?;
                }
                _ => {
                    if size > r.remaining() as u64 {
                        return Err(CompressError::InvalidFormat("files property size"));
                    }
                    r.skip(size as usize)?;
                }
            }
        }

        // Assign payload streams: non-empty files consume sub-streams in
        // (folder, sub-stream) order.
        let mut locations: Vec<Option<(usize, usize)>> = Vec::with_capacity(num_files);
        let mut folder_iter = streams
            .folders
            .iter()
            .enumerate()
            .flat_map(|(fi, f)| (0..f.substreams.len()).map(move |si| (fi, si)));
        let mut non_empty_count = 0usize;
        for i in 0..num_files {
            let has_stream = is_empty_stream.as_ref().map(|v| !v[i]).unwrap_or(true);
            if has_stream {
                locations.push(folder_iter.next());
                non_empty_count += 1;
            } else {
                locations.push(None);
            }
        }
        let total_substreams: usize = streams.folders.iter().map(|f| f.substreams.len()).sum();
        if non_empty_count > total_substreams {
            return Err(CompressError::InvalidFormat(
                "more streamed files than sub-streams",
            ));
        }

        let mut files = Vec::with_capacity(num_files);
        let mut empty_counter = 0usize;
        for i in 0..num_files {
            let has_stream = is_empty_stream.as_ref().map(|v| !v[i]).unwrap_or(true);
            let (is_dir, size, crc) = if has_stream {
                let loc = locations[i]
                    .ok_or(CompressError::InvalidFormat("file without payload stream"))?;
                let (sz, c) = streams.folders[loc.0].substreams[loc.1];
                (false, sz, c)
            } else {
                let is_file = is_empty_file
                    .as_ref()
                    .map(|v| v[empty_counter])
                    .unwrap_or(false);
                empty_counter += 1;
                (!is_file, 0, None)
            };
            files.push(SevenzFile {
                name: names
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| alloc::string::ToString::to_string(&i)),
                is_directory: is_dir,
                size,
                crc32: crc,
                stream: locations[i],
            });
        }
        Ok(files)
    }

    // ── Decoding ────────────────────────────────────────────────────

    /// Decode one folder to its full output buffer.
    ///
    /// `packed` is THIS folder's own packed stream, already sliced out of the
    /// pack area by the caller. The decoder takes the bytes rather than the
    /// archive's pack tables because the tables are where the wrong-index bug
    /// lived: a decoder that resolves "my packed stream" from a shared list
    /// cannot forget to apply the folder's own offset, whereas one handed the
    /// right bytes has no choice to make.
    fn decode_folder_bytes(
        folder: &SevenzFolder,
        packed: &[u8],
        expected_size: u64,
    ) -> CompressResult<Vec<u8>> {
        count_decode();
        if folder.coders.is_empty() {
            if expected_size == 0 {
                return Ok(Vec::new());
            }
            return Err(CompressError::InvalidFormat("empty folder with data"));
        }
        // Global input-stream base per coder.
        let mut in_base = Vec::with_capacity(folder.coders.len());
        let mut acc = 0u64;
        for c in &folder.coders {
            in_base.push(acc);
            acc += c.num_in;
        }

        // The length is checked before the index below needs it: a folder
        // may declare no packed stream at all (every input bound to a bind
        // pair), and the encoded-header path reaches this decoder without
        // the guard the normal path has.
        if folder.packed_streams.is_empty() {
            return Err(CompressError::InvalidFormat("folder with no packed stream"));
        }

        // First coder: the one owning the first packed stream.
        let first_in = folder.packed_streams[0];
        let mut coder_idx = folder
            .coders
            .iter()
            .enumerate()
            .position(|(i, c)| first_in >= in_base[i] && first_in < in_base[i] + c.num_in)
            .ok_or(CompressError::InvalidFormat("packed stream owner missing"))?;

        if folder.packed_streams.len() != 1 {
            return Err(CompressError::Unsupported("multi-pack-stream folders"));
        }
        let mut data = packed.to_vec();

        // Global output-stream base per coder.
        let mut out_base = Vec::with_capacity(folder.coders.len());
        let mut acc = 0u64;
        for c in &folder.coders {
            out_base.push(acc);
            acc += c.num_out;
        }

        loop {
            let coder = &folder.coders[coder_idx];
            if coder.num_in != 1 || coder.num_out != 1 {
                return Err(CompressError::Unsupported(
                    "multi-stream coders (e.g. BCJ2)",
                ));
            }
            let out_size = folder
                .unpack_sizes
                .get(out_base[coder_idx] as usize)
                .copied()
                .ok_or(CompressError::InvalidFormat("missing unpack size"))?;
            data = Self::apply_coder(coder, &data, out_size)?;
            let out_global = out_base[coder_idx];
            match folder.bind_pairs.iter().find(|&&(_, og)| og == out_global) {
                Some(&(next_in, _)) => {
                    coder_idx = folder
                        .coders
                        .iter()
                        .enumerate()
                        .position(|(i, c)| next_in >= in_base[i] && next_in < in_base[i] + c.num_in)
                        .ok_or(CompressError::InvalidFormat("bond owner missing"))?;
                }
                None => break,
            }
        }

        if data.len() as u64 != expected_size {
            return Err(CompressError::CorruptedData("folder size mismatch"));
        }
        Ok(data)
    }

    /// Apply one coder stage.
    fn apply_coder(coder: &SevenzCoder, input: &[u8], out_size: u64) -> CompressResult<Vec<u8>> {
        let id = coder.id.as_slice();
        if id == ID_COPY {
            return Ok(input.to_vec());
        }
        if id == ID_LZMA1 {
            if coder.props.len() != 5 {
                return Err(CompressError::InvalidFormat("bad LZMA properties"));
            }
            let props = LzmaProps::from_byte(coder.props[0])?;
            let dict = u32::from_le_bytes([
                coder.props[1],
                coder.props[2],
                coder.props[3],
                coder.props[4],
            ]);
            return LzmaDecoder::new().decode_raw(input, props, dict, Some(out_size));
        }
        if id == ID_LZMA2 {
            if coder.props.len() != 1 {
                return Err(CompressError::InvalidFormat("bad LZMA2 properties"));
            }
            let dict = lzma2_dict_size(coder.props[0]);
            let out = LzmaDecoder::new().decode_lzma2(input, dict)?;
            return fit_size(out, out_size);
        }
        if id == ID_DEFLATE {
            let out = DeflateDecoder::new().decode(input)?;
            return fit_size(out, out_size);
        }
        if id == ID_BZIP2 {
            let out = Bzip2Decoder::new().decode(input)?;
            return fit_size(out, out_size);
        }
        if id == ID_BCJ_X86 {
            let mut out = fit_size(input.to_vec(), out_size)?;
            let start = if coder.props.len() == 4 {
                u32::from_le_bytes([
                    coder.props[0],
                    coder.props[1],
                    coder.props[2],
                    coder.props[3],
                ])
            } else {
                0
            };
            bcj_x86_decode(&mut out, start);
            return Ok(out);
        }
        if id == ID_DELTA {
            if coder.props.len() != 1 {
                return Err(CompressError::InvalidFormat("bad Delta properties"));
            }
            let dist = coder.props[0] as usize + 1;
            let mut out = input.to_vec();
            for i in dist..out.len() {
                out[i] = out[i].wrapping_add(out[i - dist]);
            }
            return fit_size(out, out_size);
        }
        if id.first() == Some(&0x06) {
            return Err(CompressError::Unsupported("AES-256 encrypted 7z"));
        }
        if id == ID_PPMD {
            return Err(CompressError::Unsupported("PPMd-compressed 7z"));
        }
        if id.first() == Some(&0x03) {
            return Err(CompressError::Unsupported("BCJ filters in 7z"));
        }
        if id.first() == Some(&0x04) {
            return Err(CompressError::UnsupportedFormat(alloc::format!(
                "7z coder {:02X?}",
                id
            )));
        }
        Err(CompressError::UnsupportedFormat(alloc::format!(
            "7z coder {:02X?}",
            id
        )))
    }
}

impl SevenzFolder {
    /// The folder output is the coder output stream not consumed by any
    /// bind pair (the last one, by construction).
    fn main_unpack_size(&self) -> u64 {
        let total_out: u64 = self.coders.iter().map(|c| c.num_out).sum();
        for o in (0..total_out).rev() {
            if !self.bind_pairs.iter().any(|&(_, og)| og == o) {
                return self.unpack_sizes[o as usize];
            }
        }
        0
    }
}

/// Decode a UTF-16LE null-separated name blob into exactly `num_files`
/// names.
fn parse_names(blob: &[u8], num_files: usize) -> CompressResult<Vec<String>> {
    let mut names = Vec::with_capacity(num_files);
    let mut units: Vec<u16> = Vec::new();
    let mut rest = blob;
    while rest.len() >= 2 {
        let u = u16::from_le_bytes([rest[0], rest[1]]);
        rest = &rest[2..];
        if u == 0 {
            let name: String = core::char::decode_utf16(units.iter().copied())
                .map(|r| r.unwrap_or(core::char::REPLACEMENT_CHARACTER))
                .collect();
            names.push(name);
            units.clear();
        } else {
            units.push(u);
        }
    }
    if !units.is_empty() || names.len() != num_files {
        return Err(CompressError::InvalidFormat("file name count mismatch"));
    }
    Ok(names)
}

/// LZMA2 dictionary size from the 1-byte property.
fn lzma2_dict_size(b: u8) -> u32 {
    if b < 40 {
        (2u32 | (b as u32 & 1)) << (b / 2 + 11)
    } else {
        u32::MAX
    }
}

#[inline]
const fn test_86_ms_byte(b: u8) -> bool {
    b == 0x00 || b == 0xFF
}

/// x86 BCJ filter, decode direction: convert E8/E9 relative call/jump
/// targets back to absolute addresses.
fn bcj_x86_decode(buf: &mut [u8], start_pos: u32) {
    const MASK_TO_ALLOWED_STATUS: [bool; 8] = [true, true, true, false, true, false, false, false];
    const MASK_TO_BIT_NUMBER: [u8; 8] = [0, 1, 2, 2, 3, 3, 3, 3];

    let len = buf.len();
    if len < 5 {
        return;
    }
    let end = len - 5;
    let mut pos: u32 = start_pos.wrapping_add(5);
    let mut prev_mask: u32 = 0;
    let mut prev_pos: isize = -1;
    let mut i = 0usize;
    while i <= end {
        let b = buf[i];
        if b != 0xE9 && b != 0xE8 {
            i += 1;
            continue;
        }
        prev_pos = i as isize - prev_pos;
        if (prev_pos & !3) != 0 {
            prev_mask = 0;
        } else {
            prev_mask = (prev_mask << (prev_pos - 1)) & 7;
            if prev_mask != 0
                && (!MASK_TO_ALLOWED_STATUS[prev_mask as usize]
                    || test_86_ms_byte(
                        buf[i + 4 - MASK_TO_BIT_NUMBER[prev_mask as usize] as usize],
                    ))
            {
                prev_pos = i as isize;
                prev_mask = (prev_mask << 1) | 1;
                i += 1;
                continue;
            }
        }

        prev_pos = i as isize;
        if test_86_ms_byte(buf[i + 4]) {
            let mut src = i32::from_le_bytes([buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]]);
            let dest: i32;
            loop {
                let d = src.wrapping_sub(pos.wrapping_add(i as u32) as i32);
                if prev_mask == 0 {
                    dest = d;
                    break;
                }
                let index = MASK_TO_BIT_NUMBER[prev_mask as usize] * 8;
                if !test_86_ms_byte(((d >> (24 - index)) & 0xFF) as u8) {
                    dest = d;
                    break;
                }
                src = d ^ ((1i32 << (32 - index)) - 1);
            }

            buf[i + 1] = dest as u8;
            buf[i + 2] = (dest >> 8) as u8;
            buf[i + 3] = (dest >> 16) as u8;
            buf[i + 4] = (!(((dest >> 24) & 1) - 1)) as u8;
            i += 4;
        } else {
            prev_mask = (prev_mask << 1) | 1;
        }
        i += 1;
    }
    let _ = pos;
}

/// Truncate or reject a naturally-terminated decode against the
/// declared unpacked size.
fn fit_size(mut out: Vec<u8>, out_size: u64) -> CompressResult<Vec<u8>> {
    if (out.len() as u64) < out_size {
        return Err(CompressError::UnexpectedEof);
    }
    out.truncate(out_size as usize);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_single(archive_bytes: &[u8], expected: &[u8]) {
        let arc = SevenzArchive::parse(archive_bytes).expect("parse");
        assert_eq!(arc.files().len(), 1);
        assert!(!arc.files()[0].is_directory);
        let out = arc.extract(0).expect("extract");
        assert_eq!(out, expected);
    }

    #[test]
    fn test_7z_copy() {
        check_single(
            include_bytes!("../../testdata/copy.7z"),
            include_bytes!("../../testdata/copy.7z.hello.txt.expected"),
        );
    }

    #[test]
    fn test_7z_lzma1() {
        check_single(
            include_bytes!("../../testdata/lzma.7z"),
            include_bytes!("../../testdata/lzma.7z.data.bin.expected"),
        );
    }

    #[test]
    fn test_7z_lzma2() {
        check_single(
            include_bytes!("../../testdata/lzma2.7z"),
            include_bytes!("../../testdata/lzma2.7z.data.bin.expected"),
        );
    }

    #[test]
    fn test_7z_deflate() {
        check_single(
            include_bytes!("../../testdata/deflate.7z"),
            include_bytes!("../../testdata/deflate.7z.d.txt.expected"),
        );
    }

    #[test]
    fn test_7z_bzip2() {
        check_single(
            include_bytes!("../../testdata/bzip2.7z"),
            include_bytes!("../../testdata/bzip2.7z.b.txt.expected"),
        );
    }

    #[test]
    fn test_7z_delta_lzma2_chain() {
        // Exercises bind pairs: pack -> LZMA2 -> Delta.
        check_single(
            include_bytes!("../../testdata/delta_lzma2.7z"),
            include_bytes!("../../testdata/delta_lzma2.7z.s.bin.expected"),
        );
    }

    #[test]
    fn test_7z_multifile_substreams() {
        let arc =
            SevenzArchive::parse(include_bytes!("../../testdata/multifile.7z")).expect("parse");
        assert_eq!(arc.files().len(), 3);
        let cases: [(&str, &[u8]); 3] = [
            (
                "a.txt",
                include_bytes!("../../testdata/multifile.7z.a.txt.expected"),
            ),
            (
                "b/bb.txt",
                include_bytes!("../../testdata/multifile.7z.b_bb.txt.expected"),
            ),
            (
                "c.txt",
                include_bytes!("../../testdata/multifile.7z.c.txt.expected"),
            ),
        ];
        for (name, expected) in cases {
            let idx = arc.index_of_name(name).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(arc.extract(idx).expect("extract"), expected);
        }
    }

    #[test]
    fn test_7z_empty_file() {
        let arc =
            SevenzArchive::parse(include_bytes!("../../testdata/empty_file.7z")).expect("parse");
        assert_eq!(arc.files().len(), 1);
        assert_eq!(arc.files()[0].name, "empty.txt");
        assert!(!arc.files()[0].is_directory);
        assert_eq!(arc.extract(0).expect("extract"), Vec::<u8>::new());
    }

    /// The multifolder fixture is a 4,400x expansion: 24 KB on disk, 107 MB
    /// declared across its two folders (64 MB and 43 MB). Decoding runs at
    /// ~1.3 GB/s, so the folders themselves are cheap -- the cost of this
    /// archive is the extraction and the search over what it expands to, not
    /// the coder chain. Pinned because it is the file the per-folder decode
    /// fix is measured on, and because a reader that stops expanding early
    /// would make both numbers smaller for the wrong reason.
    #[test]
    fn the_multifolder_fixture_declares_the_expansion_the_folder_fix_is_measured_on() {
        let arc = SevenzArchive::parse(include_bytes!("../../testdata/sevenz_multifolder.7z"))
            .expect("parse");
        let declared: u64 = arc.folders.iter().map(|f| f.unpack_size).sum();
        assert_eq!(
            declared, 107_415_075,
            "fixture changed; re-measure before trusting a timing"
        );
        assert!(declared > 64 << 20 && declared < 128 << 20);
    }

    #[test]
    fn test_7z_rejects_garbage() {
        assert!(SevenzArchive::parse(b"not a 7z archive at all............").is_err());
        // Truncated signature header.
        assert!(SevenzArchive::parse(b"7z\xBC\xAF\x27\x1C").is_err());
    }

    // ── New tests for shapes the old suite missed ────────────────────

    #[test]
    fn test_7z_bad_start_header_crc() {
        let mut data = include_bytes!("../../testdata/copy.7z").to_vec();
        // Flip a byte in the start-header CRC (offset 8..12).
        data[8] ^= 0xFF;
        assert!(matches!(
            SevenzArchive::parse(&data),
            Err(CompressError::CorruptedData(_))
        ));
    }

    #[test]
    fn test_7z_bad_next_header_crc() {
        let mut data = include_bytes!("../../testdata/copy.7z").to_vec();
        // Flip a byte in the next-header CRC (offset 28..32).
        data[28] ^= 0xFF;
        assert!(matches!(
            SevenzArchive::parse(&data),
            Err(CompressError::CorruptedData(_))
        ));
    }

    #[test]
    fn test_7z_truncated_signature_header() {
        // Valid signature but only 20 of the 32 header bytes.
        let short = b"7z\xBC\xAF\x27\x1C\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(SevenzArchive::parse(short).is_err());
    }

    #[test]
    fn test_7z_unsupported_aes_coder() {
        // Build a minimal 7z with a single folder whose coder ID starts
        // with 0x06 (AES-256 encrypted).  Parsing succeeds (the coder
        // is described); extraction rejects it.
        let header = build_minimal_header_with_coder(&[0x06]);
        let archive = wrap_in_signature(&header);
        let arc = SevenzArchive::parse(&archive).expect("parse");
        let result = arc.extract(0);
        assert!(
            matches!(result, Err(CompressError::Unsupported(_))),
            "expected Unsupported for AES coder, got {result:?}"
        );
    }

    #[test]
    fn test_7z_unsupported_ppmd_coder() {
        let header = build_minimal_header_with_coder(&ID_PPMD);
        let archive = wrap_in_signature(&header);
        let arc = SevenzArchive::parse(&archive).expect("parse");
        let result = arc.extract(0);
        assert!(
            matches!(result, Err(CompressError::Unsupported(_))),
            "expected Unsupported for PPMd coder, got {result:?}"
        );
    }

    #[test]
    fn test_7z_substream_count_mismatch() {
        // One folder with one sub-stream, but two streamed files.
        let header = build_header_substream_mismatch();
        let archive = wrap_in_signature(&header);
        let result = SevenzArchive::parse(&archive);
        assert!(
            matches!(result, Err(CompressError::InvalidFormat(_))),
            "expected InvalidFormat for substream mismatch, got {result:?}"
        );
    }

    // ── Helpers to build minimal synthetic 7z headers ────────────────

    /// Encode a 7z varint.
    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut mask = 0x80u8;
        let mut buf = [0u8; 9];
        let mut n = 0;
        loop {
            if v < mask as u64 {
                buf[0] |= (v as u8) & (mask - 1);
                break;
            }
            buf[0] |= mask;
            n += 1;
            buf[n] = (v & 0xFF) as u8;
            v >>= 8;
            mask >>= 1;
            if mask == 0 {
                break;
            }
        }
        out.extend_from_slice(&buf[..=n]);
        out
    }

    /// Build a raw kHeader containing a single folder with one coder of
    /// the given method ID, one packed stream, and one file entry.
    fn build_minimal_header_with_coder(coder_id: &[u8]) -> Vec<u8> {
        let mut h = Vec::new();
        h.push(K_HEADER); // kHeader

        // kMainStreamsInfo
        h.push(K_MAIN_STREAMS_INFO);

        // kPackInfo: pack_pos=0, 1 pack of size 1
        h.push(K_PACK_INFO);
        h.extend(varint(0)); // pack_pos
        h.extend(varint(1)); // num_pack_streams
        h.push(K_SIZE);
        h.extend(varint(1)); // pack size
        h.push(K_END); // end pack info

        // kUnpackInfo
        h.push(K_UNPACK_INFO);
        h.push(K_FOLDER);
        h.extend(varint(1)); // num_folders
        h.push(0); // external = 0

        // Folder: 1 coder
        h.extend(varint(1)); // num_coders
        let bits = (coder_id.len() as u8) & 0x0F | 0x20; // id_size + has_attrs
        h.push(bits);
        h.extend_from_slice(coder_id);
        h.extend(varint(1)); // properties size = 1
        h.push(0); // dummy properties byte

        // kCodersUnpackSize: 1 output stream, unpack size = 1
        h.push(K_CODERS_UNPACK_SIZE);
        h.extend(varint(1));
        h.push(K_END); // end unpack info

        h.push(K_END); // end streams info

        // kFilesInfo: 1 file named "x"
        h.push(K_FILES_INFO);
        h.extend(varint(1)); // num_files
        h.push(K_NAME);
        let name_blob: Vec<u8> = b"x\0".iter().flat_map(|&b| [b, 0]).collect();
        // size = 1 (external byte) + name_blob.len()
        h.extend(varint(1 + name_blob.len() as u64));
        h.push(0); // external = 0
        h.extend_from_slice(&name_blob);
        h.push(K_END); // end files info

        h.push(K_END); // end header
        h
    }

    /// Build a raw kHeader with 1 folder (1 sub-stream) but 2 streamed
    /// files to trigger the sub-stream count mismatch.
    fn build_header_substream_mismatch() -> Vec<u8> {
        let mut h = Vec::new();
        h.push(K_HEADER);

        h.push(K_MAIN_STREAMS_INFO);
        h.push(K_PACK_INFO);
        h.extend(varint(0));
        h.extend(varint(1));
        h.push(K_SIZE);
        h.extend(varint(4)); // 4 bytes of pack data
        h.push(K_END);

        h.push(K_UNPACK_INFO);
        h.push(K_FOLDER);
        h.extend(varint(1));
        h.push(0);
        // 1 copy coder, no properties
        h.extend(varint(1));
        h.push(0x00); // simple copy: id_size=0, no attrs
        h.push(K_CODERS_UNPACK_SIZE);
        h.extend(varint(4));
        h.push(K_END);

        h.push(K_END); // end streams

        // 2 files, both streamed (no kEmptyStream)
        h.push(K_FILES_INFO);
        h.extend(varint(2));
        h.push(K_NAME);
        let names: Vec<u8> = b"a\0b\0".iter().flat_map(|&b| [b, 0]).collect();
        h.extend(varint(1 + names.len() as u64));
        h.push(0);
        h.extend_from_slice(&names);
        h.push(K_END);

        h.push(K_END);
        h
    }

    /// Wrap raw header bytes in a valid 32-byte signature header +
    /// 4 bytes of pack data (so the pack area is present).
    fn wrap_in_signature(header: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&SIGNATURE);
        out.extend_from_slice(&[0x00, 0x04]); // version
        out.extend_from_slice(&[0u8; 4]); // start header CRC — filled below
        let next_header_offset = 4u64; // 4 bytes of pack data before header
        let next_header_size = header.len() as u64;
        out.extend_from_slice(&next_header_offset.to_le_bytes());
        out.extend_from_slice(&next_header_size.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]); // next header CRC — filled below

        // Pack data (4 zero bytes)
        out.extend_from_slice(&[0u8; 4]);
        // Header
        out.extend_from_slice(header);

        // Fill the next-header CRC first: the start-header CRC covers
        // bytes 12..32 which includes it.
        let header_crc = crc32(&out[36..36 + header.len()]);
        out[28..32].copy_from_slice(&header_crc.to_le_bytes());
        let start_crc = crc32(&out[12..32]);
        out[8..12].copy_from_slice(&start_crc.to_le_bytes());
        out
    }
}
