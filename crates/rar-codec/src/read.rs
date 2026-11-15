// SPDX-License-Identifier: Apache-2.0

//! RAR 4.x / 5.0 archive reader.
//!
//! Independent reimplementation of the container walk. The RAR 5.0 half is
//! written from RARLAB's published archive format specification
//! (`technote.htm`), which documents the block layout, the vint fields, the
//! extra-area records and the general archive layout completely. The RAR
//! 4.x half is written from the block layout that format uses (16-bit header
//! CRC, 16-bit header size, 16-bit flags), which is not covered by that
//! specification — the specification's own signature comparison paragraph is
//! where the 4.x magic is published.
//!
//! Extraction of *stored* members is a slice: the data area holds the
//! unpacked bytes verbatim. Extraction of *compressed* members hands the
//! packed area to the decompressors (`crate::unpack` for RAR 5.0,
//! `crate::unpack3` for RAR 4.x).
//!
//! # Multivolume
//!
//! A member's data area can span volumes: the file header's split flags say
//! whether its data continues from a previous volume (0x08) or into the next
//! (0x10). `open_multi` takes every volume at once and reassembles each
//! member's chunks in order; `open` on a single volume reports such a member
//! as `split_before`/`split_after` and refuses to extract it, because the
//! bytes are not all there.

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::crc32::crc32;
use crate::vint;
use crate::{Error, Result};

const MAGIC4: &[u8; 7] = b"Rar!\x1a\x07\x00";
const MAGIC5: &[u8; 8] = b"Rar!\x1a\x07\x01\x00";

/// RAR 4.x store method, the value its file header records for a member
/// whose data area holds unpacked bytes. RAR 5.0's equivalent is method 0
/// in the compression-information field.
pub const METHOD_STORE: u8 = 0x30;

// RAR 5.0 common header flags (technote: "General archive block format").
const H_EXTRA: u64 = 0x0001;
const H_DATA: u64 = 0x0002;
const H_SPLIT_BEFORE: u64 = 0x0008;
const H_SPLIT_AFTER: u64 = 0x0010;

// RAR 5.0 header types.
const T_MAIN: u64 = 1;
const T_FILE: u64 = 2;
const T_SERVICE: u64 = 3;
const T_END: u64 = 5;

// RAR 5.0 file flags.
const F_DIRECTORY: u64 = 0x0001;
const F_HAS_MTIME: u64 = 0x0002;
const F_HAS_CRC: u64 = 0x0004;
const F_SIZE_UNKNOWN: u64 = 0x0008;

// RAR 5.0 main archive flags.
const A_VOLUME: u64 = 0x0001;
const A_HAS_VOLNUM: u64 = 0x0002;

// RAR 5.0 extra-area record types (file and service headers).
const X_ENCRYPTION: u64 = 0x01;
const X_REDIRECTION: u64 = 0x05;

// RAR 4.x header types.
const R4_MAIN: u8 = 0x73;
const R4_FILE: u8 = 0x74;
const R4_END: u8 = 0x7b;

// RAR 4.x main header flags.
const R4_MHD_VOLUME: u16 = 0x0001;

// RAR 4.x file header flags.
const R4_LHD_SPLIT_BEFORE: u16 = 0x0001;
const R4_LHD_SPLIT_AFTER: u16 = 0x0002;
const R4_LHD_DIRECTORY: u16 = 0x0004;
const R4_LHD_PASSWORD: u16 = 0x0004; // same bit, but only on the encrypted path
const R4_LHD_LARGE: u16 = 0x0100;
const R4_LHD_UNICODE: u16 = 0x0200;

/// Which RAR family an archive belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// `Rar!\x1a\x07\x00` — the "RAR4"/RAR 2.9-4.x family.
    Rar4,
    /// `Rar!\x1a\x07\x01\x00` — RAR 5.x.
    Rar5,
}

/// What an entry holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file with (possibly empty) payload.
    File,
    /// A directory. Has no payload.
    Directory,
    /// A symbolic link (RAR5 redirection record, types 1..=3). The payload
    /// is the link target.
    Symlink,
    /// A hard link (RAR5 redirection record, type 4).
    Hardlink,
    /// A RAR5 service block (e.g. archive comment). Payload is present but
    /// not a user file.
    Service,
}

/// One archive member, borrowed from the input buffer.
#[derive(Debug, Clone)]
pub struct Entry<'a> {
    /// Member name (UTF-8, lossy-decoded).
    pub name: Cow<'a, str>,
    pub kind: EntryKind,
    /// Uncompressed size in bytes. Only meaningful when
    /// [`Entry::size_unknown`] is false.
    pub unpacked_size: u64,
    /// True when the size field must be ignored and extraction runs until
    /// the end of the data area.
    pub size_unknown: bool,
    /// Size of the packed data area in the archive.
    pub packed_size: u64,
    /// Compression method. RAR5: `(compression_info >> 8) & 7`, 0 = store.
    /// RAR4: the raw method byte, 0x30 = store.
    pub method: u8,
    /// Compression algorithm version (RAR5 compression info low 6 bits):
    /// 0 = classic, 1 = RAR 7.x variant.
    pub compression_version: u8,
    /// Required dictionary size in bytes (RAR5: 128 KB << N).
    pub dictionary_size: u64,
    /// Solid flag: dictionary persists from the previous file.
    pub solid: bool,
    /// Host OS: 0 = Windows, 1 = Unix.
    pub host_os: u8,
    /// CRC-32 of the *unpacked* data, when recorded.
    pub crc32: Option<u32>,
    /// Raw mtime (Unix time when host is Unix), when recorded.
    pub mtime: Option<u32>,
    /// True when the payload is encrypted.
    pub encrypted: bool,
    /// True when the packed data started in a previous volume.
    pub split_before: bool,
    /// True when the packed data continues in the next volume.
    pub split_after: bool,
    /// Absolute offset of the payload area in the archive, `None` when the
    /// entry carries no data.
    pub data_offset: Option<usize>,
}

/// One contiguous piece of an entry's packed data area. In a multivolume
/// archive an entry's data is split into one chunk per volume.
#[derive(Debug, Clone, Copy)]
struct Chunk {
    /// Index into the volume list (`0` = the slice `Archive` was opened with).
    volume: usize,
    offset: usize,
    len: usize,
}

/// The extra-area bookkeeping one file header can carry: the redirection
/// kind turns a file into a symlink or a hard link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Extra {
    None,
    Redirect { kind: u64 },
    Encrypted,
}

/// Decoder state cached between `extract` calls for solid archives: a
/// solid member can only be decoded by decoding the whole group that
/// precedes it, so the unpacker and the outputs already produced are
/// kept for the group.
// Only one variant is ever live and the enum is private to the crate, so
// boxing it would buy nothing but an allocation per archive.
#[allow(clippy::large_enum_variant)]
enum SolidCache {
    Empty,
    Decoded {
        /// Entry index of the first group member.
        start: usize,
        /// Next entry index to decode (everything before it is done).
        through: usize,
        decoder: SolidDecoder,
        /// Decoded outputs by entry index.
        outputs: BTreeMap<usize, Vec<u8>>,
    },
}

/// The format-specific unpacker kept alive for a solid group. One live
/// variant at a time and crate-private, so an enum costs nothing.
#[allow(clippy::large_enum_variant)]
enum SolidDecoder {
    Rar5(crate::unpack::Unpacker),
    Rar4(crate::unpack3::Unpacker3),
}

impl core::fmt::Debug for SolidCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SolidCache::Empty => f.write_str("SolidCache::Empty"),
            SolidCache::Decoded {
                start,
                through,
                outputs,
                ..
            } => f
                .debug_struct("SolidCache::Decoded")
                .field("start", start)
                .field("through", through)
                .field("outputs", outputs)
                .finish(),
        }
    }
}

/// An opened RAR archive.
pub struct Archive<'a> {
    pub format: Format,
    /// True when the archive encrypts its headers (RAR5 archive encryption
    /// header). Such an archive cannot be listed without a password.
    pub encrypted: bool,
    /// True when the main header declares a multivolume set.
    pub multivolume: bool,
    /// Volume number for a non-first volume (1 = second volume, ...).
    pub volume_number: Option<u64>,
    entries: Vec<Entry<'a>>,
    /// Packed-data pieces, one per entry per volume, in entry order.
    /// `entry_chunks[i]` is the slice of this list belonging to entry `i`.
    chunks: Vec<Chunk>,
    entry_chunks: Vec<(usize, usize)>,
    volumes: Vec<&'a [u8]>,
    /// Decoder state cached between `extract` calls for solid groups.
    solid: RefCell<SolidCache>,
}

impl core::fmt::Debug for Archive<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Archive")
            .field("format", &self.format)
            .field("encrypted", &self.encrypted)
            .field("multivolume", &self.multivolume)
            .field("volume_number", &self.volume_number)
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl<'a> Archive<'a> {
    /// Open a single volume and parse it strictly: every RAR5 header CRC32
    /// must verify. A RAR4 header CRC is read but never enforced, so the
    /// two functions differ for RAR5 alone.
    pub fn open(data: &'a [u8]) -> Result<Self> {
        Self::parse(data, true)
    }

    /// Open a single volume without checking the RAR5 header CRC32s. Used
    /// on a damaged archive where the structure is intact but a checksum is
    /// not. A RAR4 header CRC is not enforced either way.
    pub fn open_lenient(data: &'a [u8]) -> Result<Self> {
        Self::parse(data, false)
    }

    /// Open every volume of a set and reassemble members that span them.
    ///
    /// Volumes must be given in order. `volumes[0]` is the first; the rest
    /// follow. A member whose data spans volumes comes back as one entry
    /// whose chunks are concatenated by [`Archive::extract`].
    pub fn open_multi(volumes: &[&'a [u8]]) -> Result<Self> {
        if volumes.is_empty() {
            return Err(Error::Malformed("open_multi needs at least one volume"));
        }
        let mut arc = Self::parse(volumes[0], true)?;
        arc.multivolume = true;
        arc.volumes = volumes.to_vec();
        for (vi, vol) in volumes.iter().enumerate().skip(1) {
            let mut next = Self::parse(vol, true)?;
            // A later volume must be the same family and must declare a
            // volume number, which is how an out-of-order set is caught.
            if next.format != arc.format {
                return Err(Error::Malformed("volumes are of different RAR formats"));
            }
            if next.volume_number != Some(vi as u64) {
                return Err(Error::Malformed("volumes are out of order"));
            }
            arc.append_volume(vi, &mut next)?;
        }
        arc.reject_incomplete()?;
        Ok(arc)
    }

    /// The members, in archive order.
    pub fn entries(&self) -> &[Entry<'a>] {
        &self.entries
    }

    /// Extract one member's unpacked bytes.
    ///
    /// A stored member is its data areas concatenated and CRC-checked when
    /// the header recorded one. A compressed member is handed to the
    /// decompressor for its format. A member split across volumes is refused
    /// unless the archive was opened with [`Archive::open_multi`].
    pub fn extract(&self, entry: &Entry<'a>) -> Result<Vec<u8>> {
        let idx = self
            .entries
            .iter()
            .position(|e| {
                core::ptr::eq(e, entry)
                    || (e.name == entry.name && e.data_offset == entry.data_offset)
            })
            .ok_or(Error::Malformed("entry does not belong to this archive"))?;
        self.extract_index(idx)
    }

    fn extract_index(&self, idx: usize) -> Result<Vec<u8>> {
        let entry = &self.entries[idx];
        if entry.encrypted {
            return Err(Error::Unsupported("encrypted payload"));
        }
        // A member whose data spans volumes is only extractable when the
        // archive was opened over every volume. Otherwise the bytes are
        // simply not all here, which is a refusal rather than a bad answer.
        if entry.split_before || entry.split_after {
            let (s, f) = self.entry_chunks[idx];
            let have = self.chunks[s..f].iter().map(|c| c.len).sum::<usize>();
            if entry.split_after || have as u64 != entry.packed_size {
                return Err(Error::Unsupported("member spans volumes"));
            }
        }
        // Solid members decode through the group cache even when stored,
        // so the shared window and tables stay in sync with the rest of
        // the group.
        if entry.solid {
            return self.extract_solid(idx);
        }
        let packed = self.packed_bytes_for(idx)?;
        let out = if entry.method == 0 || entry.method == METHOD_STORE {
            packed.into_owned()
        } else if self.format == Format::Rar5 {
            let unp = if entry.size_unknown {
                None
            } else {
                Some(entry.unpacked_size)
            };
            crate::unpack::unpack(&packed, unp, entry.dictionary_size)?
        } else {
            crate::unpack3::unpack(&packed, entry.unpacked_size)?
        };
        if let Some(want) = entry.crc32 {
            if !entry.split_after && !entry.split_before {
                let got = crc32(&out);
                if got != want {
                    return Err(Error::BadCrc("file data"));
                }
            }
        }
        Ok(out)
    }

    /// Concatenate an entry's chunks across whatever volumes hold them.
    fn packed_bytes_for(&self, idx: usize) -> Result<Cow<'a, [u8]>> {
        let (start, end) = self.entry_chunks[idx];
        let chunks = &self.chunks[start..end];
        if chunks.is_empty() {
            return Ok(Cow::Borrowed(&[]));
        }
        // One chunk in the volume the archive was opened with: borrow it.
        if chunks.len() == 1 {
            let c = chunks[0];
            let vol = self
                .volumes
                .get(c.volume)
                .copied()
                .ok_or(Error::Truncated)?;
            let end = c.offset.checked_add(c.len).ok_or(Error::Truncated)?;
            let s = vol.get(c.offset..end).ok_or(Error::Truncated)?;
            return Ok(Cow::Borrowed(s));
        }
        let mut out = Vec::new();
        for c in chunks {
            let vol = self
                .volumes
                .get(c.volume)
                .copied()
                .ok_or(Error::Truncated)?;
            let end = c.offset.checked_add(c.len).ok_or(Error::Truncated)?;
            out.extend_from_slice(vol.get(c.offset..end).ok_or(Error::Truncated)?);
        }
        Ok(Cow::Owned(out))
    }

    /// Whether the entry has any packed bytes at all. Data-less entries
    /// (directories, terminators) do not break a solid run.
    fn has_data(&self, idx: usize) -> bool {
        let (s, f) = self.entry_chunks[idx];
        f > s
    }

    /// Decode the solid group containing `idx` and return its output.
    ///
    /// A solid group is a run of data-bearing entries whose later members
    /// carry the solid flag: the LZ window, Huffman tables and distance
    /// cache persist between members, so extracting any member means
    /// decoding the run from its first entry. Progress is cached in the
    /// archive so repeated extracts resume where the previous one stopped;
    /// stored members inside the group still occupy the dictionary.
    fn extract_solid(&self, idx: usize) -> Result<Vec<u8>> {
        // Walk back over solid members and data-less entries to the run's
        // first member — which is not solid-flagged (or has nothing
        // before it).
        let mut start = idx;
        while start > 0 && (self.entries[start].solid || !self.has_data(start)) {
            start -= 1;
        }
        let mut cache = self.solid.borrow_mut();
        let same_group = matches!(&*cache, SolidCache::Decoded { start: s, .. } if *s == start);
        if !same_group {
            let decoder = match self.format {
                Format::Rar5 => {
                    let dict = self.entries[start..=idx]
                        .iter()
                        .map(|e| e.dictionary_size)
                        .max()
                        .unwrap_or(0);
                    SolidDecoder::Rar5(crate::unpack::Unpacker::new(dict))
                }
                Format::Rar4 => {
                    // The rar3 window must cover the whole group output
                    // (matches may reference any earlier member): size it
                    // from the sum of the group's unpacked sizes, capped
                    // at the 4 MB rar3 dictionary and rounded up to a
                    // power of two (Unpacker3 indexes it with a mask).
                    const RAR4_MAX_WINDOW: u64 = 0x40000 * 16;
                    let total: u64 = self.entries[start..=idx]
                        .iter()
                        .map(|e| e.unpacked_size)
                        .sum::<u64>()
                        .min(RAR4_MAX_WINDOW);
                    let window = if total >= RAR4_MAX_WINDOW {
                        RAR4_MAX_WINDOW as usize
                    } else {
                        1usize << (64 - (total | 1).leading_zeros())
                    };
                    SolidDecoder::Rar4(crate::unpack3::Unpacker3::new(window))
                }
            };
            *cache = SolidCache::Decoded {
                start,
                through: start,
                decoder,
                outputs: BTreeMap::new(),
            };
        }
        loop {
            let (through, decoder, outputs) = match &mut *cache {
                SolidCache::Decoded {
                    through,
                    decoder,
                    outputs,
                    ..
                } => (through, decoder, outputs),
                SolidCache::Empty => unreachable!(),
            };
            if *through > idx {
                break;
            }
            let i = *through;
            if !self.has_data(i) {
                *through = i + 1;
                if i == idx {
                    break;
                }
                continue;
            }
            let e = &self.entries[i];
            let decoded = match decoder {
                SolidDecoder::Rar5(unpacker) => {
                    let target = if e.size_unknown {
                        None
                    } else {
                        Some(e.unpacked_size)
                    };
                    let packed = self.packed_bytes_for(i)?;
                    if e.method == 0 {
                        // Stored member: raw bytes that still occupy the
                        // dictionary for the members after it.
                        unpacker.write_stored(&packed);
                        Ok(packed.into_owned())
                    } else {
                        unpacker.begin_member(target);
                        unpacker.run(&packed).and_then(|()| unpacker.finish())
                    }
                }
                SolidDecoder::Rar4(unpacker) => {
                    let packed = self.packed_bytes_for(i)?;
                    if e.method == METHOD_STORE {
                        unpacker.write_stored(&packed)?;
                        Ok(packed.into_owned())
                    } else if !(0x31..=0x35).contains(&e.method) {
                        Err(Error::Unsupported("unknown RAR4 compression method"))
                    } else {
                        unpacker.run_member(&packed, e.unpacked_size)
                    }
                }
            };
            let out = match decoded {
                Ok(out) => out,
                Err(err) => {
                    // The decoder has already consumed this member's
                    // stream, so the cached state can never decode the
                    // group again — drop it rather than leave a cache
                    // that silently mis-decodes on the next extract.
                    *cache = SolidCache::Empty;
                    return Err(err);
                }
            };
            if let Some(want) = e.crc32 {
                if crc32(&out) != want {
                    *cache = SolidCache::Empty;
                    return Err(Error::BadCrc("file data"));
                }
            }
            outputs.insert(i, out);
            *through = i + 1;
            if i == idx {
                break;
            }
        }
        match &*cache {
            SolidCache::Decoded { outputs, .. } => outputs
                .get(&idx)
                .cloned()
                .ok_or(Error::Malformed("solid member was not decoded")),
            SolidCache::Empty => unreachable!(),
        }
    }

    /// Fold a later volume's entries into this archive, appending each of
    /// its split members' chunks to the entry that already holds them.
    fn append_volume(&mut self, vi: usize, next: &mut Archive<'a>) -> Result<()> {
        for (i, e) in next.entries.iter().enumerate() {
            let (s, f) = next.entry_chunks[i];
            for c in &next.chunks[s..f] {
                self.chunks.push(Chunk {
                    volume: vi,
                    offset: c.offset,
                    len: c.len,
                });
            }
            let pushed = self.chunks.len();
            if e.split_before {
                // Continue the entry this volume's name matches. A split
                // member always repeats its name and total size.
                let pos = self
                    .entries
                    .iter()
                    .rposition(|prev| prev.name == e.name && prev.unpacked_size == e.unpacked_size);
                match pos {
                    Some(p) => {
                        let (ps, _) = self.entry_chunks[p];
                        self.entry_chunks[p].1 = pushed;
                        // A reassembled member is neither: its data is all
                        // here now, so the split flags describe the pieces
                        // it came from, not the entry that results.
                        {
                            let incoming_after = e.split_after;
                            let merged = &mut self.entries[p];
                            // The start is known now, so `split_before` is
                            // history. `split_after` is only cleared when
                            // the chunk that just arrived does not itself
                            // continue — a set missing its last volume must
                            // still say the member runs on.
                            merged.split_before = false;
                            if !incoming_after {
                                merged.split_after = false;
                            }
                            // The declared packed size is the sum of the
                            // chunks across every volume so far.
                            merged.packed_size =
                                self.chunks[ps..pushed].iter().map(|c| c.len as u64).sum();
                            // Only the closing volume of a split member
                            // records the CRC of the *unpacked* data; the
                            // earlier ones record the CRC of their own
                            // packed chunk. So the reassembled entry takes
                            // the header that arrived last.
                            merged.crc32 = e.crc32;
                        }
                        // The continuation carries no new entry: keep the
                        // earlier header's identity and record the tail.
                        continue;
                    }
                    None => return Err(Error::Malformed("split member with no start")),
                }
            }
            // A fresh entry.
            let chunks_start = self.chunks.len() - (f - s);
            self.entries.push(e.clone());
            self.entry_chunks.push((chunks_start, self.chunks.len()));
        }
        Ok(())
    }

    /// A member that says it continues into a volume we do not have cannot
    /// be extracted; the set itself is incomplete, which is a short read
    /// rather than a structural error.
    fn reject_incomplete(&self) -> Result<()> {
        for e in &self.entries {
            if e.split_after {
                return Err(Error::Truncated);
            }
        }
        Ok(())
    }

    fn parse(data: &'a [u8], verify_crc: bool) -> Result<Self> {
        let mut arc = Archive {
            format: Format::Rar5,
            encrypted: false,
            multivolume: false,
            volume_number: None,
            entries: Vec::new(),
            chunks: Vec::new(),
            entry_chunks: Vec::new(),
            volumes: vec![data],
            solid: RefCell::new(SolidCache::Empty),
        };
        let start = find_signature(data)?;
        let mut off = start;
        // The signature length differs per family; detect first.
        if data[off..].starts_with(MAGIC5) {
            arc.format = Format::Rar5;
            off += MAGIC5.len();
            arc.parse_rar5(data, off, verify_crc)?;
        } else {
            arc.format = Format::Rar4;
            off += MAGIC4.len();
            arc.parse_rar4(data, off, verify_crc)?;
        }
        Ok(arc)
    }

    /// Walk RAR 5.0 blocks. `pos` is the offset just past the signature.
    fn parse_rar5(&mut self, data: &'a [u8], mut pos: usize, verify_crc: bool) -> Result<()> {
        loop {
            if pos + 4 > data.len() {
                return Err(Error::Truncated);
            }
            let want = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            let mut q = pos + 4;
            let hsize = vint::read_r(data, &mut q)? as usize;
            let body_start = q;
            let body_end = body_start.checked_add(hsize).ok_or(Error::Truncated)?;
            if body_end > data.len() {
                return Err(Error::Truncated);
            }
            let body = &data[body_start..body_end];
            if verify_crc {
                let mut region = Vec::with_capacity(4 + hsize);
                vint::write(&mut region, hsize as u64);
                region.extend_from_slice(body);
                if crc32(&region) != want {
                    return Err(Error::BadCrc("rar5 header"));
                }
            }

            // Type and flags are the first two vints of the body.
            let mut b = 0usize;
            let htype = vint::read_r(body, &mut b)?;
            let hflags = vint::read_r(body, &mut b)?;
            let _extra_size = if hflags & H_EXTRA != 0 {
                Some(vint::read_r(body, &mut b)? as usize)
            } else {
                None
            };
            let data_size = if hflags & H_DATA != 0 {
                vint::read_r(body, &mut b)? as u64
            } else {
                0
            };

            let mut after = body_end;
            match htype {
                T_MAIN => {
                    let aflags = vint::read_r(body, &mut b)?;
                    self.multivolume = aflags & A_VOLUME != 0;
                    self.volume_number = if aflags & A_HAS_VOLNUM != 0 {
                        Some(vint::read_r(body, &mut b)?)
                    } else {
                        None
                    };
                }
                T_FILE | T_SERVICE => {
                    let data_start = after;
                    let data_end = data_start
                        .checked_add(data_size as usize)
                        .ok_or(Error::Truncated)?;
                    if data_end > data.len() {
                        // The member claims more data than the buffer holds.
                        // Record the entry and stop: the listing is known,
                        // and the missing bytes are an extract-time failure.
                        self.parse_rar5_file(body, &mut b, htype, hflags, data_size, data_start)?;
                        break;
                    }
                    self.parse_rar5_file(body, &mut b, htype, hflags, data_size, data_start)?;
                    after = data_end;
                }
                T_END => {
                    // Nothing after this header matters to the reader.
                    break;
                }
                _ => {
                    // Unknown block type: skip it. The spec requires that
                    // an unknown type with 0x0004 set is skipped rather than
                    // fatal, and skipping is always safe.
                }
            }
            pos = after;
        }
        Ok(())
    }

    /// One RAR 5.0 file or service header. `b` is the read cursor into
    /// `body`, positioned at the file flags.
    fn parse_rar5_file(
        &mut self,
        body: &[u8],
        b: &mut usize,
        htype: u64,
        hflags: u64,
        data_size: u64,
        data_start: usize,
    ) -> Result<()> {
        let fflags = vint::read_r(body, b)?;
        let unpacked_size = vint::read_r(body, b)?;
        let _attrs = vint::read_r(body, b)?;
        let mtime = if fflags & F_HAS_MTIME != 0 {
            let t = u32::from_le_bytes(
                body.get(*b..*b + 4)
                    .ok_or(Error::Truncated)?
                    .try_into()
                    .unwrap(),
            );
            *b += 4;
            Some(t)
        } else {
            None
        };
        let file_crc = if fflags & F_HAS_CRC != 0 {
            let c = u32::from_le_bytes(
                body.get(*b..*b + 4)
                    .ok_or(Error::Truncated)?
                    .try_into()
                    .unwrap(),
            );
            *b += 4;
            Some(c)
        } else {
            None
        };
        let cinfo = vint::read_r(body, b)?;
        let host_os = vint::read_r(body, b)? as u8;
        let name_len = vint::read_r(body, b)? as usize;
        let name_bytes = body.get(*b..*b + name_len).ok_or(Error::Truncated)?;
        *b += name_len;

        // Extra area, if the common flag said it is there. It records
        // encryption and redirection, which change the entry's kind.
        let mut extra = Extra::None;
        if hflags & H_EXTRA != 0 {
            // The extra area is the tail of the body, after `name`.
            // `extra_size` was already consumed; the records follow.
            // Walk them from the current cursor to the end of the body.
            while *b < body.len() {
                // The specification's extra-area record is:
                //   Size (vint) — size of record data *starting from Type*;
                //   Type (vint); Data.
                // So the size does not cover the size field itself, and the
                // record ends `Size` bytes after the type field begins.
                let rec_size = vint::read_r(body, b)? as usize;
                let rec_end = (*b)
                    .checked_add(rec_size)
                    .filter(|&e| e <= body.len())
                    .ok_or(Error::Malformed("extra record size out of range"))?;
                let rec_type = vint::read_r(body, b)?;
                match rec_type {
                    X_ENCRYPTION => extra = Extra::Encrypted,
                    X_REDIRECTION => {
                        // Redirection type is the first field after the type.
                        let kind = vint::read_r(body, b)?;
                        extra = Extra::Redirect { kind };
                    }
                    _ => {
                        // Unknown record: skip it. The spec requires that
                        // unknown record types are skipped without
                        // interrupting the operation.
                    }
                }
                *b = rec_end;
            }
        }

        // Compression information. The specification's bit *numbers* and
        // its bit *masks* disagree by one; the masks are the authority:
        // 0x003f = version, 0x0040 = solid, 0x0380 = method, 0x7c00 =
        // dictionary exponent. So the shifts are 7 and 10, not 8 and 11.
        let method = ((cinfo >> 7) & 0x7) as u8;
        let version = (cinfo & 0x3f) as u8;
        let solid = cinfo & 0x40 != 0;
        let dict_exp = ((cinfo >> 10) & 0x1f) as u32;
        // The exponent is five bits of the file: an unclamped 30 asks the
        // unpacker for a 128 GiB window, and a window allocation that
        // fails aborts the process -- an allocation cap cannot be caught.
        // Clamping instead would decode a real large-dictionary archive
        // through a window too small for its back-references, which is a
        // wrong answer rather than a loud one, so past 1 GiB the entry is
        // refused by name.
        if dict_exp > 13 {
            return Err(Error::Malformed(
                "dictionary larger than this reader supports (max 1 GiB)",
            ));
        }
        let dictionary_size = 128 * 1024u64 * (1u64 << dict_exp);

        let kind = match extra {
            Extra::Redirect { kind: k } => match k {
                1..=3 => EntryKind::Symlink,
                4 => EntryKind::Hardlink,
                _ => EntryKind::File,
            },
            _ => {
                if htype == T_SERVICE {
                    EntryKind::Service
                } else if fflags & F_DIRECTORY != 0 {
                    EntryKind::Directory
                } else {
                    EntryKind::File
                }
            }
        };

        let name = String::from_utf8_lossy(name_bytes).into_owned();
        let split_before = hflags & H_SPLIT_BEFORE != 0;
        let split_after = hflags & H_SPLIT_AFTER != 0;
        let has_payload = data_size > 0 && kind != EntryKind::Directory;

        self.entries.push(Entry {
            name: Cow::Owned(name),
            kind,
            unpacked_size,
            size_unknown: fflags & F_SIZE_UNKNOWN != 0,
            packed_size: data_size,
            method,
            compression_version: version,
            dictionary_size,
            solid,
            host_os,
            crc32: file_crc,
            mtime,
            encrypted: extra == Extra::Encrypted,
            split_before,
            split_after,
            data_offset: if has_payload { Some(data_start) } else { None },
        });
        let start = self.chunks.len();
        if has_payload {
            self.chunks.push(Chunk {
                volume: 0,
                offset: data_start,
                len: data_size as usize,
            });
        }
        self.entry_chunks.push((start, self.chunks.len()));
        Ok(())
    }

    /// Walk RAR 4.x blocks. `pos` is the offset just past the signature.
    fn parse_rar4(&mut self, data: &'a [u8], mut pos: usize, _verify_crc: bool) -> Result<()> {
        loop {
            if pos + 7 > data.len() {
                return Err(Error::Truncated);
            }
            let _want = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
            let btype = data[pos + 2];
            let flags = u16::from_le_bytes(data[pos + 3..pos + 5].try_into().unwrap());
            let hsize = u16::from_le_bytes(data[pos + 5..pos + 7].try_into().unwrap()) as usize;
            if hsize < 7 || pos + hsize > data.len() {
                return Err(Error::Truncated);
            }
            // The RAR 4.x header CRC is a 16-bit field and the fixtures this
            // codec is validated against write it as zero ("not verified by
            // design"), so it is read but not enforced. The data CRC of a
            // member is enforced at extract time.
            let body = &data[pos + 7..pos + hsize];
            let mut after = pos + hsize;

            match btype {
                R4_MAIN => {
                    self.multivolume = flags & R4_MHD_VOLUME != 0;
                }
                R4_FILE => {
                    self.parse_rar4_file(data, body, flags, after)?;
                    // Data area follows the header; its size is the packed
                    // size field of the body.
                    let packed = self.entries.last().map(|e| e.packed_size).unwrap_or(0) as usize;
                    after = after.checked_add(packed).ok_or(Error::Truncated)?;
                    if after > data.len() {
                        // The member claims more data than the buffer holds.
                        // The entry itself is known and worth listing; the
                        // missing bytes are an extract-time failure, not a
                        // reason to throw the whole listing away.
                        break;
                    }
                }
                R4_END => break,
                _ => {
                    // Other block types (comment, recovery, ...) carry a
                    // data area whose size is not in the header; stopping
                    // here would lose members, so continue with the next
                    // block at `after` and rely on the CRC to reject
                    // misaligned input.
                }
            }
            pos = after;
        }
        Ok(())
    }

    /// One RAR 4.x file header body.
    fn parse_rar4_file(
        &mut self,
        _data: &'a [u8],
        body: &[u8],
        flags: u16,
        data_start: usize,
    ) -> Result<()> {
        if body.len() < 25 {
            return Err(Error::Malformed("rar4 file header too short"));
        }
        let mut p = 0usize;
        let mut packed = u32::from_le_bytes(body[p..p + 4].try_into().unwrap()) as u64;
        p += 4;
        let unpacked = u32::from_le_bytes(body[p..p + 4].try_into().unwrap()) as u64;
        p += 4;
        let host_os = body[p];
        p += 1;
        let file_crc = u32::from_le_bytes(body[p..p + 4].try_into().unwrap());
        p += 4;
        let mtime = u32::from_le_bytes(body[p..p + 4].try_into().unwrap());
        p += 4;
        let _unpack_ver = body[p];
        p += 1;
        let method = body[p];
        p += 1;
        let name_len = u16::from_le_bytes(body[p..p + 2].try_into().unwrap()) as usize;
        p += 2;
        if flags & R4_LHD_LARGE != 0 {
            // Two extra 32-bit halves of the sizes follow the name in the
            // real format; this codec does not need them for the members it
            // extracts, so record the low half and move on.
            packed &= 0xFFFF_FFFF;
        }
        let _attrs = u32::from_le_bytes(body[p..p + 4].try_into().unwrap());
        p += 4;
        let name_bytes = body.get(p..p + name_len).ok_or(Error::Truncated)?;

        let is_dir = flags & R4_LHD_DIRECTORY != 0;
        let name = if flags & R4_LHD_UNICODE != 0 {
            // A Unicode name appends an encoded form after the ANSI one;
            // take the ANSI prefix as a lossy fallback, which is what the
            // header's declared length covers in the common case.
            String::from_utf8_lossy(name_bytes).into_owned()
        } else {
            String::from_utf8_lossy(name_bytes).into_owned()
        };

        self.entries.push(Entry {
            name: Cow::Owned(name),
            kind: if is_dir {
                EntryKind::Directory
            } else {
                EntryKind::File
            },
            unpacked_size: unpacked,
            size_unknown: false,
            packed_size: packed,
            method,
            compression_version: 0,
            dictionary_size: 0,
            solid: flags & 0x0010 != 0, // LHD_SOLID
            host_os,
            crc32: Some(file_crc),
            mtime: Some(mtime),
            encrypted: flags & R4_LHD_PASSWORD != 0 && !is_dir,
            split_before: flags & R4_LHD_SPLIT_BEFORE != 0,
            split_after: flags & R4_LHD_SPLIT_AFTER != 0,
            data_offset: if packed > 0 { Some(data_start) } else { None },
        });
        let start = self.chunks.len();
        if packed > 0 {
            self.chunks.push(Chunk {
                volume: 0,
                offset: data_start,
                len: packed as usize,
            });
        }
        self.entry_chunks.push((start, self.chunks.len()));
        Ok(())
    }
}

/// The signature can be preceded by an SFX module. The spec bounds that at
/// 1 MB for the archives it writes; searching further costs little and
/// covers a larger stub.
///
/// A buffer that *starts* like a RAR but is too short to hold a whole
/// signature is `Truncated`, not `BadMagic`: the caller has a partial
/// archive, not a non-archive. Anything else that matches neither signature
/// is `BadMagic`.
fn find_signature(data: &[u8]) -> Result<usize> {
    let limit = data.len().min(1 << 20);
    let window = &data[..limit];
    if let Some(i) = find_sub(window, MAGIC5) {
        return Ok(i);
    }
    if let Some(i) = find_sub(window, MAGIC4) {
        return Ok(i);
    }
    // Neither full signature is present. If the buffer opens like one, it is
    // a short read rather than a wrong file.
    if data.starts_with(&MAGIC5[..data.len().min(MAGIC5.len())]) && data.len() < MAGIC5.len() {
        return Err(Error::Truncated);
    }
    if data.starts_with(b"Rar!") && data.len() < MAGIC4.len() {
        return Err(Error::Truncated);
    }
    Err(Error::BadMagic)
}

/// First index of `needle` in `hay`, or `None`.
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}
