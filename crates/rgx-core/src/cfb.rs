// SPDX-License-Identifier: Apache-2.0

//! Minimal CFB (OLE2) compound-file reader.
//!
//! The subset needed to reach named streams in legacy `.doc`/`.xls`/`.ppt`,
//! Outlook `.msg`, and MSI-style containers: header (v3/v4), DIFAT + FAT
//! chain walking, directory entries, and the mini stream via mini-FAT.
//! Hardened: DIFAT growth is bounded by the sectors physically present,
//! and every chain walk has a step cap — fuzzed headers cannot loop or
//! allocate without limit.
//!
//! Lives in rgx-core so every adapter crate (mail, office, …) shares one
//! implementation instead of growing private copies.

use crate::{bail, decline, Result};
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::OnceCell;

pub const CFB_SIG: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FREESECT: u32 = 0xFFFF_FFFF;

fn rd_u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd_u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

pub struct Entry {
    pub name: String,
    /// 2 = stream, 5 = root storage
    pub kind: u8,
    pub start: u32,
    pub size: u64,
}

pub struct Cfb<'a> {
    data: &'a [u8],
    sector_size: usize,
    mini_sector_size: usize,
    mini_cutoff: u64,
    fat: Vec<u32>,
    minifat: Vec<u32>,
    /// Start sector of the mini stream chain (the root storage's chain
    /// of regular sectors that collectively hold the mini stream).
    /// Read on demand in `read_stream` rather than copied wholesale
    /// at parse time: a .doc that needs only WordDocument (a regular
    /// stream) was reading and duplicating every mini sector in the
    /// file just to leave them on the heap.
    mini_stream_start: u32,
    /// Cached sector-ID list for the mini stream's root-storage chain.
    /// Walking the chain once per call to `read_mini_sector` made
    /// streaming K mini sectors an O(K^2) FAT traversal; a 4 MiB
    /// mini stream is K = 65 536 and the redundant pointer hops
    /// measured in the millions. The cache is built lazily on the
    /// first mini-sector read -- a file that touches only regular
    /// streams never pays for it.
    mini_stream_chain: OnceCell<Vec<u32>>,
    pub entries: Vec<Entry>,
}

impl<'a> Cfb<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 512 || data[0..8] != CFB_SIG {
            // A decline, not a failure: a file that does not carry the
            // signature is not a compound file, and the eleven extensions
            // that reach this reader — `.doc`, `.xls`, `.ppt`, `.msg` and
            // the rest — are mostly *not* compound files in the wild. A
            // note here put "not an OLE2 compound file" into the corpus of
            // every plain text file wearing a `.doc` name.
            decline!("not an OLE2 compound file (bad signature)");
        }
        let sector_size = 1usize << rd_u16le(data, 30);
        let mini_sector_size = 1usize << rd_u16le(data, 32);
        if !(512..=4096).contains(&sector_size) {
            bail!("unsupported sector size {sector_size}");
        }
        if !(8..=4096).contains(&mini_sector_size) {
            bail!("unsupported mini sector size {mini_sector_size}");
        }
        let num_fat = rd_u32le(data, 44) as usize;
        let first_dir = rd_u32le(data, 48);
        let first_minifat = rd_u32le(data, 60);
        let num_minifat = rd_u32le(data, 64) as usize;
        let mini_cutoff = rd_u32le(data, 56) as u64;

        let sector = |id: u32| -> Option<&'a [u8]> {
            let off = 512 + id as usize * sector_size;
            data.get(off..off + sector_size)
        };

        // header DIFAT (109 entries) + optional DIFAT sectors, bounded by
        // the sectors the file can physically contain
        let max_sectors = data.len().saturating_sub(512) / sector_size;
        let mut difat: Vec<u32> = Vec::new();
        for i in 0..109usize {
            let id = rd_u32le(data, 76 + i * 4);
            if id != FREESECT && difat.len() < max_sectors {
                difat.push(id);
            }
        }
        let mut next_difat = rd_u32le(data, 68);
        while next_difat != FREESECT && difat.len() < num_fat.min(max_sectors) {
            let Some(s) = sector(next_difat) else { break };
            for i in 0..(sector_size / 4 - 1) {
                let id = rd_u32le(s, i * 4);
                if id != FREESECT && difat.len() < max_sectors {
                    difat.push(id);
                }
            }
            next_difat = rd_u32le(s, sector_size - 4);
        }
        // FAT = concatenation of FAT sectors; cap the capacity claim —
        // a fuzzed header can set num_fat to u32::MAX (multi-TiB alloc)
        let mut fat =
            Vec::with_capacity((num_fat.min(difat.len().max(1)) * sector_size / 4).min(1 << 20));
        for &id in difat.iter().take(num_fat) {
            let Some(s) = sector(id) else { continue };
            for i in 0..sector_size / 4 {
                fat.push(rd_u32le(s, i * 4));
            }
        }

        // chain reader over regular sectors
        let chain = |start: u32, table: &[u32], limit: usize| -> Vec<u8> {
            let mut out = Vec::new();
            let mut id = start;
            let mut guard = 0usize;
            while id != ENDOFCHAIN && id != FREESECT && guard < limit {
                guard += 1;
                let Some(s) = sector(id) else { break };
                out.extend_from_slice(s);
                id = *table.get(id as usize).unwrap_or(&ENDOFCHAIN);
            }
            out
        };

        // directory
        let dir_bytes = chain(first_dir, &fat, 1 << 20);
        let mut entries = Vec::new();
        for chunk in dir_bytes.as_chunks::<128>().0 {
            let nlen = rd_u16le(chunk, 64) as usize;
            if !(2..=64).contains(&nlen) {
                continue;
            }
            let name: String = chunk[0..nlen - 2]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .map(|u| char::from_u32(u as u32).unwrap_or('\u{FFFD}'))
                .collect();
            let kind = chunk[66];
            let start = rd_u32le(chunk, 116);
            let size = if sector_size == 512 {
                rd_u32le(chunk, 120) as u64 // v3: u32 size
            } else {
                u64::from_le_bytes(chunk[120..128].try_into().unwrap_or([0u8; 8]))
            };
            if kind == 2 || kind == 5 {
                entries.push(Entry {
                    name,
                    kind,
                    start,
                    size,
                });
            }
        }
        if entries.is_empty() {
            bail!("no directory entries");
        }

        // mini stream: only the FAT is read eagerly; the chain itself is
        // walked on demand in `read_stream`. The previous path copied
        // every mini sector into a single Vec (4 MB for a 64 MB .xls,
        // often never read because the caller asked for the regular
        // WordDocument stream).
        let root = entries.iter().find(|e| e.kind == 5);
        let (mini_stream_start, minifat) = if let Some(_root) = root {
            let mf_bytes = chain(first_minifat, &fat, 1 << 20);
            let mf: Vec<u32> = mf_bytes
                .as_chunks::<4>()
                .0
                .iter()
                .take(num_minifat * sector_size / 4)
                .map(|c| rd_u32le(c, 0))
                .collect();
            // We still need root.start for the mini-stream chain head.
            // The `find` above was by reference; redo by copying.
            let mini_stream_start = entries
                .iter()
                .find(|e| e.kind == 5)
                .map(|e| e.start)
                .unwrap_or(ENDOFCHAIN);
            (mini_stream_start, mf)
        } else {
            (ENDOFCHAIN, Vec::new())
        };

        Ok(Cfb {
            data,
            sector_size,
            mini_sector_size,
            mini_cutoff,
            fat,
            minifat,
            mini_stream_start,
            mini_stream_chain: OnceCell::new(),
            entries,
        })
    }

    /// Find the first stream whose name ends with `suffix`.
    pub fn find_stream_suffix(&self, suffix: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| e.kind == 2 && e.name.ends_with(suffix))
    }

    /// Find an entry by exact name.
    pub fn find(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Read a single mini sector (64 B by default) from the lazy mini
    /// stream. The mini stream lives in regular sectors; each regular
    /// sector holds `sector_size / mini_sector_size` mini sectors. The
    /// mini-FAT chains mini-sector IDs.
    fn read_mini_sector(&self, id: u32) -> Option<&[u8]> {
        // Step 1: which regular sector holds this mini sector?
        let sectors_per_regular = self.sector_size / self.mini_sector_size;
        if sectors_per_regular == 0 {
            return None;
        }
        let regular_sector_index = id as usize / sectors_per_regular;
        let offset_in_regular = (id as usize % sectors_per_regular) * self.mini_sector_size;
        // Step 2: resolve the regular-sector chain. Walking it on
        // every call to read_mini_sector is the O(K^2) FAT traversal
        // the audit called out: K mini-sectors, K chain-walks of up
        // to K/8 sectors each, where the only thing that changes
        // between calls is `regular_sector_index`. The cache
        // collapses the second step to a single array index. The
        // chain is built lazily on the first mini-sector read.
        let chain = self.mini_stream_chain.get_or_init(|| {
            let mut v = Vec::new();
            let mut reg_id = self.mini_stream_start;
            // The chain is bounded by the FAT itself; the
            // `guard < fat.len()` cap matches the original walk's
            // `guard <= regular_sector_index` check in spirit
            // (a malformed chain cannot loop here, because FAT
            // entries are u32 and `v.push` cannot grow past
            // u32::MAX without OOM first).
            while reg_id != ENDOFCHAIN
                && reg_id != FREESECT
                && (v.len() as u32) < self.fat.len() as u32
            {
                v.push(reg_id);
                let next = self.fat.get(reg_id as usize).copied().unwrap_or(ENDOFCHAIN);
                reg_id = next;
            }
            v
        });
        let reg_id = *chain.get(regular_sector_index)?;
        let off = 512 + reg_id as usize * self.sector_size + offset_in_regular;
        self.data.get(off..off + self.mini_sector_size)
    }

    /// read a stream's bytes, following the mini-FAT when small.
    /// Truncated or corrupt chains yield the bytes gathered so far.
    pub fn read_stream(&self, e: &Entry) -> Vec<u8> {
        if e.size < self.mini_cutoff && !self.minifat.is_empty() && e.kind == 2 {
            // Mini stream walk: each mini sector is read on demand
            // from its containing regular sector. The full mini stream
            // is never copied into a single Vec.
            let mut out = Vec::new();
            let mut id = e.start;
            let mut guard = 0usize;
            while id != ENDOFCHAIN && id != FREESECT && guard < 1 << 16 {
                guard += 1;
                if let Some(sector) = self.read_mini_sector(id) {
                    let end = (self.mini_sector_size).min(e.size as usize - out.len());
                    out.extend_from_slice(&sector[..end.min(sector.len())]);
                } else {
                    break;
                }
                id = *self.minifat.get(id as usize).unwrap_or(&ENDOFCHAIN);
                if out.len() >= e.size as usize {
                    break;
                }
            }
            out.truncate(e.size as usize);
            out
        } else {
            let mut out = Vec::new();
            let mut id = e.start;
            let mut guard = 0usize;
            while id != ENDOFCHAIN && id != FREESECT && guard < 1 << 20 {
                guard += 1;
                let off = 512 + id as usize * self.sector_size;
                let end = (off + self.sector_size).min(self.data.len());
                if off >= self.data.len() {
                    break;
                }
                out.extend_from_slice(&self.data[off..end]);
                id = *self.fat.get(id as usize).unwrap_or(&ENDOFCHAIN);
            }
            out.truncate(e.size as usize);
            out
        }
    }

    /// Read the named stream, if present.
    pub fn stream(&self, name: &str) -> Option<Vec<u8>> {
        let e = self.find(name)?;
        if e.kind != 2 {
            return None;
        }
        Some(self.read_stream(e))
    }
}
