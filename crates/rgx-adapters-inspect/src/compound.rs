// SPDX-License-Identifier: Apache-2.0

//! OLE2 compound files (MS-CFB): the container behind OneNote, Lotus Notes,
//! Hangul Word Processor, Project, Publisher and every pre-2007 Office file.
//!
//! A CFB file is a small filesystem: a FAT sector chain, a 128-byte-per-entry
//! directory, and a second "mini" FAT for streams under 4 KiB. Nothing in
//! it is text, which is exactly why `Reach::Reveal` applies — but the
//! directory is a *list of names*, and those names are what a user greps
//! for. A OneNote file's section names, a Notes database's form names and a
//! Project file's task names are all reachable from the directory alone.
//!
//! The format is specified in [MS-CFB]; the constants and the layout below
//! are transcribed from it rather than inferred, because every one of them
//! has a magic sentinel that a plausible-looking reader gets wrong.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use rgx_core::{decline, Adapter, Outcome, Result};

/// `D0 CF 11 E0 A1 B1 1A E1` — the only signature that identifies a CFB.
const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FREESECT: u32 = 0xFFFF_FFFF;

// Directory entry object types.
const OBJ_EMPTY: u8 = 0;
const OBJ_STORAGE: u8 = 1;
const OBJ_STREAM: u8 = 2;
const OBJ_ROOT: u8 = 5;

const DIR_ENTRY: usize = 128;

/// How many directory entries to report, and how deep to walk the red-black
/// tree. Both are attacker-controlled: a directory entry can point its child
/// at itself, and a name can be 64 UTF-16 units long.
const MAX_ENTRIES: usize = 20_000;
const MAX_DEPTH: usize = 32;

/// The OLE2 container, reported by storage and stream name.
///
/// `.rvt` is deliberately absent: the CAD adapter in `cad.rs` claims it
/// because it can say something Revit-specific about the streams it finds,
/// and registration order means first match wins.
pub struct Compound;
impl Adapter for Compound {
    fn name(&self) -> &'static str {
        "ole2-compound"
    }
    /// `pub` and `xltm` are **fallbacks, not duplicates**: `rgx-adapters-docs`
    /// claims `pub` (only when its external binary is on `PATH`) and
    /// `rgx-adapters-office` claims `xltm` for the OOXML template, which is a
    /// ZIP. Both of those bail on a real compound file, and the claim here is
    /// what answers then. Deleting either "duplicate" would leave those two
    /// shapes with no reader whenever the first claimant declines.
    /// `sxw`/`sxc`/`sxi`/`sxd` are the StarOffice 6/7 documents — the
    /// pre-ODF generation, which is OLE2 rather than a ZIP package like
    /// everything StarOffice wrote afterwards. The reader does not need to
    /// know which application wrote the storage; it names the streams.
    fn extensions(&self) -> &'static [&'static str] {
        &[
            "one", "nsf", "hwp", "mpp", "pub", "msp", "vsdm", "cdr", "xltm", "sxw", "sxc", "sxi",
            "sxd",
        ]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let Some(c) = Cfb::open(data) else {
            decline!("not an OLE2 compound file (bad magic)");
        };
        Ok(Outcome::Text(c.report()))
    }
}

struct Cfb<'a> {
    data: &'a [u8],
    sector_size: usize,
    mini_sector_size: usize,
    mini_cutoff: u32,
    fat: Vec<u32>,
    mini_fat: Vec<u32>,
    dir: Vec<u8>,
    mini_stream: Vec<u8>,
}

impl<'a> Cfb<'a> {
    fn open(data: &'a [u8]) -> Option<Self> {
        if data.len() < 512 || data[..8] != CFB_MAGIC {
            return None;
        }
        let u16at = |o: usize| -> Option<u16> {
            let b = data.get(o..o + 2)?;
            Some(u16::from_le_bytes([b[0], b[1]]))
        };
        let u32at = |o: usize| -> Option<u32> {
            let b = data.get(o..o + 4)?;
            Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };

        // 0xFFFE is the required byte-order mark; a file that says otherwise
        // is not one, and reading it as little-endian would produce a FAT of
        // plausible-looking nonsense.
        if u16at(28)? != 0xFFFE {
            return None;
        }
        let sector_shift = u16at(30)? as u32;
        let mini_shift = u16at(32)? as u32;
        // Version 3 uses 512-byte sectors, version 4 uses 4096. Anything else
        // would make every sector offset below wrong.
        if !matches!(sector_shift, 9 | 12) || mini_shift != 6 {
            return None;
        }
        let sector_size = 1usize << sector_shift;
        let fat_sectors = u32at(44)? as usize;
        let dir_start = u32at(48)?;
        let mini_cutoff = u32at(56)?;
        let mini_fat_start = u32at(60)?;
        let mini_fat_count = u32at(64)? as usize;
        let difat_start = u32at(68)?;
        let _difat_count = u32at(72)? as usize;

        let mut me = Cfb {
            data,
            sector_size,
            mini_sector_size: 1usize << mini_shift,
            mini_cutoff,
            fat: Vec::new(),
            mini_fat: Vec::new(),
            dir: Vec::new(),
            mini_stream: Vec::new(),
        };

        // The DIFAT: 109 entries live in the header, and any beyond that live
        // in a chain of DIFAT sectors whose last field is the next one.
        let mut fat_sector_ids: Vec<u32> = Vec::new();
        for i in 0..109 {
            if let Some(s) = u32at(76 + i * 4) {
                if s != FREESECT {
                    fat_sector_ids.push(s);
                }
            }
        }
        let mut difat = difat_start;
        let mut guard = 0usize;
        // The bound is a constant, not the header's own `difat_count`:
        // that count is a field of the file, and a chain that points at
        // itself walks it however many times the header claims. The CFB
        // twin in `cad.rs` holds the same line with `MAX_CHAIN`.
        while difat != ENDOFCHAIN && difat != FREESECT && guard < (1usize << 16) {
            guard += 1;
            let Some(sector) = me.sector(difat) else {
                break;
            };
            let per = sector_size / 4;
            for i in 0..per.saturating_sub(1) {
                let v = u32le(sector, i * 4);
                if v != FREESECT {
                    fat_sector_ids.push(v);
                }
            }
            difat = u32le(sector, (per - 1) * 4);
        }
        // The header's 109 slots plus the DIFAT chain is the authoritative
        // count; a file that claims more is lying, and trusting the claim is
        // how a reader ends up allocating a 4 GiB FAT.
        fat_sector_ids.truncate(fat_sectors.min(fat_sector_ids.len()));

        for &id in &fat_sector_ids {
            let Some(sector) = me.sector(id) else {
                continue;
            };
            for i in 0..sector_size / 4 {
                me.fat.push(u32le(sector, i * 4));
            }
        }

        me.dir = me.chain_read(dir_start, usize::MAX).unwrap_or_default();

        let _ = (mini_fat_start, mini_fat_count);
        if mini_fat_start != ENDOFCHAIN && mini_fat_start != FREESECT {
            me.mini_fat = me
                .chain_read(mini_fat_start, usize::MAX)
                .map(|b| b.as_chunks::<4>().0.iter().map(|c| u32le(c, 0)).collect())
                .unwrap_or_default();
        }

        // The root entry's stream is the mini stream: a normal chain of
        // sectors holding the 64-byte mini sectors the small streams live in.
        if let Some(root) = me.entry(0) {
            let start = u32at_entry(root, 116);
            let size = u64::from(u32at_entry(root, 120));
            if start != ENDOFCHAIN {
                me.mini_stream = me.chain_read(start, size as usize).unwrap_or_default();
            }
        }
        Some(me)
    }

    /// Sector `n` as a slice. Sector 0 follows the header, which is why the
    /// offset is `(n + 1) * size` and not `n * size`: in version 3 the header
    /// is 512 bytes = one sector, and in version 4 it is 4096 = one sector.
    fn sector(&self, n: u32) -> Option<&'a [u8]> {
        let n = n as usize;
        if n >= FREESECT as usize {
            return None;
        }
        let start = n.checked_add(1)?.checked_mul(self.sector_size)?;
        self.data.get(start..start.checked_add(self.sector_size)?)
    }

    /// Follow a FAT chain and concatenate, stopping at `max` bytes. The cap
    /// is what keeps a cyclic or absurd chain from becoming an allocation.
    fn chain_read(&self, start: u32, max: usize) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut n = start;
        let mut guard = 0usize;
        while n != ENDOFCHAIN && n != FREESECT && n != 0xFFFF_FFFD && n != 0xFFFF_FFFC {
            guard += 1;
            if guard > self.fat.len() + 8 || out.len() >= max {
                return Some(out);
            }
            let s = self.sector(n)?;
            let room = max.saturating_sub(out.len());
            out.extend_from_slice(&s[..room.min(s.len())]);
            n = *self.fat.get(n as usize)?;
        }
        Some(out)
    }

    fn chain_read_mini(&self, start: u32, size: usize) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut n = start;
        let mut guard = 0usize;
        while n != ENDOFCHAIN && n != FREESECT && out.len() < size {
            guard += 1;
            if guard > self.mini_fat.len() + 8 {
                break;
            }
            let off = (n as usize).checked_mul(self.mini_sector_size)?;
            let s = self
                .mini_stream
                .get(off..off.checked_add(self.mini_sector_size)?)?;
            out.extend_from_slice(s);
            n = *self.mini_fat.get(n as usize)?;
        }
        out.truncate(size);
        Some(out)
    }

    fn entry(&self, id: u32) -> Option<&[u8]> {
        let off = (id as usize).checked_mul(DIR_ENTRY)?;
        self.dir.get(off..off.checked_add(DIR_ENTRY)?)
    }

    /// A stream's bytes: a normal chain when it is over the cutoff, and a
    /// mini chain when it is under. The cutoff is 4096 by spec, but reading
    /// it rather than assuming is what makes a small file work.
    fn stream_bytes(&self, entry: &[u8]) -> Option<Vec<u8>> {
        let start = u32at_entry(entry, 116);
        let size = u64::from(u32at_entry(entry, 120)) as usize;
        if start == ENDOFCHAIN || start == FREESECT {
            return Some(Vec::new());
        }
        if size < self.mini_cutoff as usize {
            self.chain_read_mini(start, size)
        } else {
            self.chain_read(start, size)
        }
    }

    fn report(&self) -> Vec<u8> {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "OLE2 compound file: {} sectors of {} bytes, mini sectors of {} bytes, cutoff {}",
            self.fat.len(),
            self.sector_size,
            self.mini_sector_size,
            self.mini_cutoff
        );
        let mut seen = Vec::new();
        let mut count = 0usize;
        self.walk(&mut out, 0, "", &mut seen, &mut count, 0);
        let _ = writeln!(out, "entries: {count}");
        out.into_bytes()
    }

    /// Walk the directory's red-black tree. The tree is a *graph*: entries
    /// name left/right/child siblings, and a malformed file can make one
    /// point back at itself, so `seen` is what stops the recursion.
    fn walk(
        &self,
        out: &mut String,
        id: u32,
        prefix: &str,
        seen: &mut Vec<u32>,
        count: &mut usize,
        depth: usize,
    ) {
        if depth > MAX_DEPTH || *count >= MAX_ENTRIES || id >= 0xFFFF_FFFA {
            return;
        }
        if seen.contains(&id) {
            return;
        }
        seen.push(id);
        let Some(e) = self.entry(id) else { return };
        let kind = e.get(66).copied().unwrap_or(OBJ_EMPTY);
        if kind == OBJ_EMPTY {
            return;
        }
        let name = entry_name(e);
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            alloc::format!("{prefix}/{name}")
        };
        let clsid = entry_clsid(e);
        let start = u32at_entry(e, 116);
        let size = u64::from(u32at_entry(e, 120));

        match kind {
            OBJ_STORAGE | OBJ_ROOT => {
                *count += 1;
                let _ = writeln!(
                    out,
                    "storage {path}{}{}",
                    if clsid.is_empty() { "" } else { " " },
                    clsid
                );
                self.walk(out, u32at_entry(e, 76), &path, seen, count, depth + 1);
            }
            OBJ_STREAM => {
                *count += 1;
                let _ = writeln!(out, "stream {path} ({size} bytes)");
                // The head of a stream is where the identifiable content
                // lives: a HWP `BodyText` record header, a Notes form, a
                // Publisher tag list. Print the printable prefix rather than
                // guessing at a full decode.
                if let Some(bytes) = self.stream_bytes(e) {
                    for line in readable_lines(&bytes, 12, 200) {
                        let _ = writeln!(out, "  {line}");
                    }
                }
                let _ = start;
            }
            _ => {
                let _ = writeln!(out, "entry {path} (type {kind})");
            }
        }

        let left = u32at_entry(e, 68);
        let right = u32at_entry(e, 72);
        self.walk(out, left, prefix, seen, count, depth + 1);
        self.walk(out, right, prefix, seen, count, depth + 1);
    }
}

fn u32le(d: &[u8], o: usize) -> u32 {
    match d.get(o..o + 4) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => ENDOFCHAIN,
    }
}

fn u32at_entry(e: &[u8], o: usize) -> u32 {
    u32le(e, o)
}

/// The name is UTF-16LE in 64 bytes, NUL-terminated, with the length field
/// counting the terminator *and* counting bytes, not units. Dividing by two
/// is therefore right and taking the length field directly is the classic
/// off-by-two that produces names with a stray `n` or `\0`.
fn entry_name(e: &[u8]) -> String {
    let raw = e.get(0..64).unwrap_or(&[]);
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn entry_clsid(e: &[u8]) -> String {
    let Some(b) = e.get(80..96) else {
        return String::new();
    };
    if b.iter().all(|x| *x == 0) {
        return String::new();
    }
    let mut s = String::with_capacity(38);
    for (i, byte) in b.iter().enumerate() {
        if matches!(i, 2..=7) {
            s.push('-');
        }
        let _ = write!(s, "{byte:02x}");
    }
    alloc::format!("[CLSID {s}]")
}

/// The printable prefix of a stream, one line per run of text. This is a
/// triage view, not a decode: it is honest about being a prefix.
fn readable_lines(bytes: &[u8], max_lines: usize, max_bytes: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len().min(max_bytes) && out.len() < max_lines {
        let b = bytes[i];
        let ok = b == b'\t' || b >= 0x20;
        if !ok {
            if i > start && i - start >= 4 {
                out.push(String::from_utf8_lossy(&bytes[start..i]).trim().to_string());
                if out.len() >= max_lines {
                    break;
                }
            }
            start = i + 1;
        }
        i += 1;
    }
    if out.len() < max_lines && i > start && i - start >= 4 {
        out.push(
            String::from_utf8_lossy(&bytes[start..i.min(bytes.len())])
                .trim()
                .to_string(),
        );
    }
    out.retain(|s| !s.is_empty());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Build a minimal version-3 compound file with the given
    /// (name, type, payload) entries in one root-level chain.
    ///
    /// Streams under the 4096-byte cutoff go into the *mini* stream the way a
    /// real writer puts them there, and larger ones into whole sectors, so
    /// both branches of `stream_bytes` are exercised rather than one of them
    /// being dead.
    struct Builder {
        data: Vec<u8>,
        entries: Vec<(String, u8, Vec<u8>)>,
    }

    impl Builder {
        fn new() -> Self {
            Builder {
                // header + FAT + minifat + mini stream + directory + payloads
                data: vec![0u8; 512 * 64],
                entries: Vec::new(),
            }
        }
        fn add(mut self, name: &str, kind: u8, payload: &[u8]) -> Self {
            self.entries
                .push((name.to_string(), kind, payload.to_vec()));
            self
        }
        fn build(mut self) -> Vec<u8> {
            const S: usize = 512;
            const MS: usize = 64;
            const CUTOFF: usize = 4096;

            // 1. Streams under the cutoff go into the mini stream, the way a
            //    real writer puts them there; the rest get whole sectors.
            //    Both branches of `stream_bytes` are therefore exercised,
            //    rather than one of them being dead code.
            let mut mini_buf: Vec<u8> = Vec::new();
            let mut place: Vec<(u32, u64)> = vec![(ENDOFCHAIN, 0); self.entries.len()];
            for (i, (_, kind, payload)) in self.entries.iter().enumerate() {
                if *kind != OBJ_STREAM {
                    continue;
                }
                let start = (mini_buf.len() / MS) as u32;
                mini_buf.extend_from_slice(payload);
                while !mini_buf.len().is_multiple_of(MS) {
                    mini_buf.push(0);
                }
                place[i] = (start, payload.len() as u64);
            }

            // 2. Sector layout: 0 = FAT, 1.. = directory, big payloads, mini
            //    stream, mini FAT.
            let dir_sectors = self.entries.len().div_ceil(S / DIR_ENTRY).max(1);
            let dir_start = 2usize;
            let mut next = dir_start + dir_sectors;

            for (i, (_, kind, payload)) in self.entries.iter().enumerate() {
                if *kind != OBJ_STREAM || payload.len() < CUTOFF {
                    continue;
                }
                let s = next;
                for (k, chunk) in payload.chunks(S).enumerate() {
                    let off = (s + k + 1) * S;
                    let end = (off + chunk.len()).min(self.data.len());
                    self.data[off..end].copy_from_slice(&chunk[..end - off]);
                }
                next += payload.len().div_ceil(S);
                place[i] = (s as u32, payload.len() as u64);
            }

            let mini_start = next;
            for (k, chunk) in mini_buf.chunks(S).enumerate() {
                let off = (mini_start + k + 1) * S;
                let end = (off + chunk.len()).min(self.data.len());
                self.data[off..end].copy_from_slice(&chunk[..end - off]);
            }
            let mini_sectors = mini_buf.len().div_ceil(S);
            next += mini_sectors;

            // Each stream's mini sectors form their own chain, and eight mini
            // sectors share one 512-byte sector, so the chain breaks there.
            let n_mini = mini_buf.len() / MS;
            let minifat_start = next;
            let minifat_sectors = n_mini.div_ceil(S / 4).max(1);
            let minifat_off = (minifat_start + 1) * S;
            for k in 0..n_mini {
                let v = if (k + 1) % MS == 0 || k + 1 == n_mini {
                    ENDOFCHAIN
                } else {
                    (k + 1) as u32
                };
                let o = minifat_off + k * 4;
                self.data[o..o + 4].copy_from_slice(&v.to_le_bytes());
            }
            next += minifat_sectors;
            let total = next;

            // 3. header
            self.data[..8].copy_from_slice(&CFB_MAGIC);
            self.data[24..26].copy_from_slice(&0x003Eu16.to_le_bytes());
            self.data[26..28].copy_from_slice(&3u16.to_le_bytes());
            self.data[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
            self.data[30..32].copy_from_slice(&9u16.to_le_bytes());
            self.data[32..34].copy_from_slice(&6u16.to_le_bytes());
            self.data[44..48].copy_from_slice(&1u32.to_le_bytes());
            self.data[48..52].copy_from_slice(&(dir_start as u32).to_le_bytes());
            self.data[56..60].copy_from_slice(&(CUTOFF as u32).to_le_bytes());
            self.data[60..64].copy_from_slice(&(minifat_start as u32).to_le_bytes());
            self.data[64..68].copy_from_slice(&(minifat_sectors as u32).to_le_bytes());
            self.data[68..72].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
            self.data[72..76].copy_from_slice(&0u32.to_le_bytes());
            self.data[76..80].copy_from_slice(&0u32.to_le_bytes()); // DIFAT[0] = sector 0
            for i in 1..109 {
                let o = 76 + i * 4;
                self.data[o..o + 4].copy_from_slice(&FREESECT.to_le_bytes());
            }

            // 4. Directory, as a right-leaning spine from the root so every
            //    entry is reachable: the root's child is entry 1 and each
            //    entry's right sibling is the next.
            let mut dir = vec![0u8; dir_sectors * S];
            // The root's stream *is* the mini stream, and its size field is
            // how the reader knows where the mini sectors stop. A root that
            // declares zero yields an empty mini stream, which is what a real
            // writer never does.
            let mini_len = mini_buf.len() as u64;
            write_entry(
                &mut dir,
                0,
                "Root Entry",
                OBJ_ROOT,
                mini_start as u32,
                mini_len,
            );
            dir[76..80].copy_from_slice(&1u32.to_le_bytes());
            for (i, (name, kind, _)) in self.entries.iter().enumerate() {
                let off = (i + 1) * DIR_ENTRY;
                let (start, size) = place[i];
                write_entry(&mut dir, off, name, *kind, start, size);
                let sib = if i + 2 <= self.entries.len() {
                    (i + 2) as u32
                } else {
                    FREESECT
                };
                dir[off + 72..off + 76].copy_from_slice(&sib.to_le_bytes());
            }
            let dir_off = (dir_start + 1) * S;
            self.data[dir_off..dir_off + dir.len()].copy_from_slice(&dir);

            // 5. FAT
            let mut fat = vec![FREESECT; S / 4];
            fat[0] = 0xFFFF_FFFD; // FATSECT
            chain(&mut fat, dir_start, dir_sectors);
            for (i, (_, kind, payload)) in self.entries.iter().enumerate() {
                if *kind == OBJ_STREAM && payload.len() >= CUTOFF {
                    chain(&mut fat, place[i].0 as usize, payload.len().div_ceil(S));
                }
            }
            chain(&mut fat, mini_start, mini_sectors);
            chain(&mut fat, minifat_start, minifat_sectors);
            let fat_off = S;
            for (i, v) in fat.iter().enumerate() {
                let o = fat_off + i * 4;
                self.data[o..o + 4].copy_from_slice(&v.to_le_bytes());
            }
            self.data.truncate((total + 1) * S);
            self.data
        }
    }

    fn chain(fat: &mut [u32], start: usize, n: usize) {
        for k in 0..n {
            if let Some(slot) = fat.get_mut(start + k) {
                *slot = if k + 1 == n {
                    ENDOFCHAIN
                } else {
                    start as u32 + k as u32 + 1
                };
            }
        }
    }

    fn write_entry(dir: &mut [u8], off: usize, name: &str, kind: u8, start: u32, size: u64) {
        for (i, u) in name.encode_utf16().take(31).enumerate() {
            dir[off + i * 2..off + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        let len = ((name.encode_utf16().count() + 1) * 2) as u16;
        dir[off + 64..off + 66].copy_from_slice(&len.to_le_bytes());
        dir[off + 66] = kind;
        dir[off + 67] = 1; // black
        dir[off + 68..off + 72].copy_from_slice(&FREESECT.to_le_bytes());
        dir[off + 72..off + 76].copy_from_slice(&FREESECT.to_le_bytes());
        dir[off + 76..off + 80].copy_from_slice(&FREESECT.to_le_bytes());
        dir[off + 116..off + 120].copy_from_slice(&start.to_le_bytes());
        dir[off + 120..off + 124].copy_from_slice(&(size as u32).to_le_bytes());
        dir[off + 124..off + 128].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
    }

    #[test]
    fn a_compound_file_reports_its_storage_and_stream_names() {
        let data = Builder::new()
            .add("BodyText", OBJ_STREAM, b"HWPTAG_DOCUMENT_PROPERTIES\0\0\0")
            .add(
                "DocInfo",
                OBJ_STREAM,
                b"title=Relatorio Anual\nauthor=Dana\n",
            )
            .build();
        let out =
            String::from_utf8_lossy(&match Compound.extract(&data, "x.hwp").expect("compound") {
                Outcome::Text(t) => t,
                _ => panic!("expected Text"),
            })
            .into_owned();
        assert!(out.contains("BodyText"), "{out}");
        assert!(out.contains("DocInfo"), "{out}");
        // The stream's own bytes, which is the part that makes the
        // directory useful rather than merely structural.
        assert!(out.contains("Relatorio Anual"), "{out}");
    }

    #[test]
    fn a_name_does_not_keep_its_terminator() {
        let e = {
            let mut v = vec![0u8; DIR_ENTRY];
            write_entry(&mut v, 0, "BodyText", OBJ_STREAM, ENDOFCHAIN, 0);
            v
        };
        assert_eq!(entry_name(&e), "BodyText");
    }

    #[test]
    fn a_file_that_is_not_compound_is_declined_not_misparsed() {
        assert!(Compound
            .extract(b"PK\x03\x04 zip zip zip", "x.one")
            .is_err());
        assert!(Compound.extract(&[0u8; 128], "x.hwp").is_err());
        // Right magic, wrong byte order mark: every sector offset would be
        // wrong, so this must not be read as a filesystem.
        let mut d = Builder::new().build();
        d[28..30].copy_from_slice(&0x0000u16.to_le_bytes());
        assert!(Compound.extract(&d, "x.nsf").is_err());
    }

    #[test]
    fn a_directory_entry_that_points_at_itself_stops() {
        let mut d = Builder::new().build();
        let dir_off = 3 * 512;
        d[dir_off + 68..dir_off + 72].copy_from_slice(&1u32.to_le_bytes());
        d[dir_off + 72..dir_off + 76].copy_from_slice(&1u32.to_le_bytes());
        // Must terminate rather than recurse forever.
        let out = match Compound.extract(&d, "x.one") {
            Ok(Outcome::Text(t)) => String::from_utf8_lossy(&t).into_owned(),
            _ => String::new(),
        };
        assert!(out.contains("OLE2 compound file"), "{out}");
    }
}
