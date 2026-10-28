// SPDX-License-Identifier: Apache-2.0

//! Store compaction: reclaim the bytes that edit churn leaves behind.
//!
//! `update_store` is append-only. A modified file gets a *tombstone* on its
//! old record and a fresh record pointing into a new pack, and nothing ever
//! removes a pack file — so a store that is updated daily grows without bound
//! even when its live corpus is unchanged.
//!
//! Compaction rewrites just the live records into fresh packs and drops the
//! rest. The order is what makes it safe to run at all:
//!
//! 1. write the new packs (they are unreferenced, so a crash here is inert);
//! 2. publish the manifest atomically, which now names only the new packs
//!    (`publish_atomic` is write-and-rename, so a reader sees the whole old
//!    catalog or the whole new one);
//! 3. delete the superseded pack files.
//!
//! A crash before step 3 leaves orphan files that nothing references. That is
//! the safe direction to fail in — a dangling reference would break every
//! query, whereas an orphan costs only disk — so [`compact_store`] sweeps
//! them on the next run.

use alloc::string::ToString;
use alloc::vec::Vec;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::format::{
    load_manifest, now_secs, publish_atomic, FileRecord, Manifest, PackHeader, PackRecord,
    DEFAULT_PACK_SIZE,
};

/// Compaction ran, and what it reclaimed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CompactStats {
    pub packs_before: usize,
    pub packs_after: usize,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub live_files: usize,
    /// Pack files deleted because nothing referenced them any more.
    pub packs_removed: usize,
    pub orphans_removed: usize,
    pub elapsed_ms: f64,
}

impl CompactStats {
    /// Bytes actually reclaimed.
    pub fn reclaimed(&self) -> u64 {
        self.bytes_before.saturating_sub(self.bytes_after)
    }

    /// Fraction of the store's bytes that were dead before this ran.
    pub fn waste_ratio(&self) -> f64 {
        if self.bytes_before == 0 {
            0.0
        } else {
            self.reclaimed() as f64 / self.bytes_before as f64
        }
    }
}

/// Dead bytes below this fraction of the store: nothing worth rewriting.
const DEFAULT_MIN_WASTE: f64 = 0.10;
/// A store smaller than this is not worth walking end to end. Part of the
/// "is it worth it" decision, not of the rewrite itself.
const MIN_BYTES_TO_COMPACT: u64 = 1 << 20;

fn crc32(bytes: &[u8]) -> u32 {
    crate::compress::crc32::crc32(bytes)
}

/// Bytes of every `.tvp` sitting in the store directory.
fn pack_bytes_on_disk(store_dir: &Path) -> io::Result<(u64, Vec<PathBuf>)> {
    let mut total = 0u64;
    let mut files = Vec::new();
    for entry in fs::read_dir(store_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("tvp") {
            continue;
        }
        total += entry.metadata().map(|m| m.len()).unwrap_or(0);
        files.push(path);
    }
    Ok((total, files))
}

/// Rewrite the live records into fresh packs and drop everything superseded.
///
/// Returns `Ok(None)` when the store's dead bytes are below `min_waste` —
/// compaction is not free, and running it on every update would make the
/// common case slower. Pass `0.0` to force the rewrite.
///
/// This is the raw operation: it does not apply a minimum store size. For
/// the "should I bother?" policy that answers the question a caller can
/// actually use, see [`compact_store_if_worth_it`].
pub fn compact_store(store_dir: &Path, min_waste: f64) -> io::Result<Option<CompactStats>> {
    let t0 = Instant::now();
    let manifest = load_manifest(store_dir)?;

    let packs_before = manifest.packs.len();
    let live: Vec<&FileRecord> = manifest.files.iter().filter(|f| !f.is_deleted).collect();
    let live_bytes: u64 = live.iter().map(|f| f.length).sum();
    let (bytes_before, on_disk) = pack_bytes_on_disk(store_dir)?;

    // Dead = every byte the store holds that no live record points into.
    // Measured against the files actually on disk, so a previous crash's
    // orphans count as waste too.
    let waste = bytes_before.saturating_sub(live_bytes);
    let ratio = if bytes_before == 0 {
        0.0
    } else {
        waste as f64 / bytes_before as f64
    };
    if ratio < min_waste {
        return Ok(None);
    }

    // Read each source pack at most once, in pack-id order.
    let mut sources: HashMap<u32, PathBuf> = HashMap::new();
    for p in &manifest.packs {
        sources.insert(p.pack_id, store_dir.join(&p.filename));
    }

    let mut next_pack_id = manifest
        .packs
        .iter()
        .map(|p| p.pack_id)
        .max()
        .map_or(0, |m| m + 1);

    let mut open: HashMap<u32, fs::File> = HashMap::new();
    let mut new_packs: Vec<PackRecord> = Vec::new();
    let mut new_files: Vec<FileRecord> = Vec::with_capacity(live.len());

    // Current output pack state.
    let mut cur_id = next_pack_id;
    let mut cur_name = format!("{cur_id:08}.tvp");
    let mut cur_buf: Vec<u8> = Vec::with_capacity(DEFAULT_PACK_SIZE as usize);
    let mut cur_count: u32 = 0;

    let write_current =
        |pack_id: u32, name: &str, buf: &mut Vec<u8>, count: u32| -> io::Result<PackRecord> {
            let content_len = buf.len() as u64;
            let content_crc32 = crc32(buf);
            let header = PackHeader::new(pack_id, count, content_len, content_crc32);
            let mut out = Vec::with_capacity(PackHeader::SIZE + buf.len());
            header.extend(&mut out);
            out.extend_from_slice(buf);
            let tmp = store_dir.join(format!("{name}.tmp"));
            {
                let mut f = fs::File::create(&tmp)?;
                f.write_all(&out)?;
                f.sync_data()?;
            }
            fs::rename(&tmp, store_dir.join(name))?;
            buf.clear();
            Ok(PackRecord {
                pack_id,
                filename: name.to_string(),
                file_count: count,
                content_len,
                content_crc32,
            })
        };

    for rec in &live {
        // An empty file has no payload to copy; keep the record, point it at
        // pack 0 with a zero offset so nothing tries to read it.
        if rec.length == 0 {
            let mut r = (*rec).clone();
            r.is_deleted = false;
            new_files.push(r);
            continue;
        }
        let src_path = sources.get(&rec.pack_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("file {} names missing pack {}", rec.rel_path, rec.pack_id),
            )
        })?;
        // `Entry`, but not `or_insert`: that would call `fs::File::open` on
        // every record and throw the result away whenever the pack is already
        // open. Opening happens in the vacant arm alone.
        let f = match open.entry(rec.pack_id) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => e.insert(fs::File::open(src_path)?),
        };
        f.seek(SeekFrom::Start(PackHeader::SIZE as u64 + rec.offset))?;
        let mut payload = vec![0u8; rec.length as usize];
        f.read_exact(&mut payload)?;

        if !cur_buf.is_empty() && cur_buf.len() as u64 + payload.len() as u64 > DEFAULT_PACK_SIZE {
            let rec_meta = write_current(cur_id, &cur_name, &mut cur_buf, cur_count)?;
            new_packs.push(rec_meta);
            next_pack_id += 1;
            cur_id = next_pack_id;
            cur_name = format!("{cur_id:08}.tvp");
            cur_count = 0;
        }

        let offset = cur_buf.len() as u64;
        cur_buf.extend_from_slice(&payload);
        cur_count += 1;

        let mut r = (*rec).clone();
        r.pack_id = cur_id;
        r.offset = offset;
        r.is_deleted = false;
        new_files.push(r);
    }
    if !cur_buf.is_empty() {
        let rec_meta = write_current(cur_id, &cur_name, &mut cur_buf, cur_count)?;
        new_packs.push(rec_meta);
    }

    let bytes_after: u64 = new_packs
        .iter()
        .map(|p| p.content_len + PackHeader::SIZE as u64)
        .sum();

    // --- publish before deleting ---
    let next = Manifest {
        generation: manifest.generation + 1,
        timestamp_secs: now_secs(),
        corpus: manifest.corpus,
        // Compaction drops records; it does not re-sign them. The head's
        // extraction fingerprint describes the surviving rollups exactly as
        // it described them before, so it travels unchanged.
        extract_fp: manifest.extract_fp,
        root_path: manifest.root_path.clone(),
        packs: new_packs.clone(),
        files: new_files,
    };
    publish_atomic(&next, store_dir)?;

    // Now, and only now, the superseded packs are unreferenced.
    let live_names: HashSet<&str> = next.packs.iter().map(|p| p.filename.as_str()).collect();
    let mut packs_removed = 0usize;
    let mut orphans_removed = 0usize;
    let known: HashSet<&str> = manifest.packs.iter().map(|p| p.filename.as_str()).collect();
    for path in &on_disk {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if live_names.contains(name) {
            continue;
        }
        if fs::remove_file(path).is_ok() {
            if known.contains(name) {
                packs_removed += 1;
            } else {
                orphans_removed += 1;
            }
        }
    }

    Ok(Some(CompactStats {
        packs_before,
        packs_after: next.packs.len(),
        bytes_before,
        bytes_after,
        live_files: next.files.len(),
        packs_removed,
        orphans_removed,
        elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
    }))
}

/// Compact only when the store is big enough *and* dirty enough to be worth
/// walking end to end.
///
/// This is the one to call on a schedule or after an update: a small clean
/// store is not worth a full rewrite, and the default 10% dead-byte floor
/// keeps a healthy store untouched.
pub fn compact_store_if_worth_it(store_dir: &Path) -> io::Result<Option<CompactStats>> {
    if pack_bytes_on_disk(store_dir)?.0 < MIN_BYTES_TO_COMPACT {
        return Ok(None);
    }
    compact_store(store_dir, DEFAULT_MIN_WASTE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tv_runtime::builder::{build_store, BuildConfig};
    use crate::tv_runtime::format::load_manifest;
    use crate::tv_runtime::update::update_store;
    use alloc::string::String;

    fn store(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rgx-compact-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("root")).unwrap();
        dir
    }

    /// Fill the root with files big enough that the packs really hold bytes.
    fn fill(root: &Path, n: usize, size: usize) {
        for i in 0..n {
            let sub = root.join(format!("d{}", i % 4));
            fs::create_dir_all(&sub).unwrap();
            fs::write(sub.join(format!("f{i:04}.txt")), vec![b'x'; size]).unwrap();
        }
    }

    /// Every live file's bytes, read back through the pack layout the searcher
    /// uses: header + offset, length bytes.
    fn live_payloads(store_dir: &Path) -> HashMap<String, Vec<u8>> {
        let manifest = load_manifest(store_dir).expect("manifest loads");
        let mut packs: HashMap<u32, fs::File> = HashMap::new();
        let mut out = HashMap::new();
        for f in manifest
            .files
            .iter()
            .filter(|f| !f.is_deleted && f.length > 0)
        {
            let path = store_dir.join(
                manifest
                    .packs
                    .iter()
                    .find(|p| p.pack_id == f.pack_id)
                    .expect("live record names a listed pack")
                    .filename
                    .clone(),
            );
            let file = packs
                .entry(f.pack_id)
                .or_insert_with(|| fs::File::open(&path).unwrap());
            file.seek(SeekFrom::Start(PackHeader::SIZE as u64 + f.offset))
                .unwrap();
            let mut buf = vec![0u8; f.length as usize];
            file.read_exact(&mut buf).unwrap();
            out.insert(f.rel_path.clone(), buf);
        }
        out
    }

    /// The bug this exists for: updates are append-only, so a store that is
    /// edited repeatedly keeps every superseded payload forever.
    #[test]
    fn compaction_reclaims_bytes_that_updates_left_behind() {
        let dir = store("reclaim");
        let root = dir.join("root");
        fill(&root, 40, 8192);
        let store_dir = dir.join("store");

        let cfg = BuildConfig::default();
        build_store(&root, &store_dir, &cfg).expect("build");
        let after_build: u64 = pack_bytes_on_disk(&store_dir).unwrap().0;
        assert!(after_build > 0, "the store must actually hold packs");

        // Edit the same files over and over: each pass appends a new pack and
        // tombstones the old records, so live bytes stay flat while disk grows.
        for round in 0..6 {
            for i in 0..40 {
                let sub = root.join(format!("d{}", i % 4));
                fs::write(sub.join(format!("f{i:04}.txt")), vec![b'y'; 8192 + round]).unwrap();
            }
            update_store(&root, &store_dir, &cfg).expect("update");
        }
        let before = pack_bytes_on_disk(&store_dir).unwrap().0;
        assert!(
            before > after_build * 2,
            "append-only updates must have inflated the store \
             (built {after_build}, now {before}); without that there is \
             nothing for compaction to reclaim and this test proves nothing"
        );

        let stats = compact_store(&store_dir, 0.0)
            .expect("compact runs")
            .expect("compaction is worth it here");

        let after = pack_bytes_on_disk(&store_dir).unwrap().0;
        assert!(
            after < before,
            "compaction must reclaim disk: {before} -> {after}"
        );
        assert!(stats.packs_removed > 0, "superseded packs must be deleted");
        assert!(stats.reclaimed() > 0);
        let _ = fs::remove_dir_all(&dir);
    }

    /// The point of the exercise: the store must answer exactly as it did
    /// before. A compaction that reclaims the right bytes but loses or
    /// reorders payloads would be worse than the leak it fixes.
    #[test]
    fn compaction_preserves_every_live_payload() {
        let dir = store("preserve");
        let root = dir.join("root");
        fill(&root, 30, 4096);
        // A file that does not survive, so a tombstone exists too.
        fs::remove_file(root.join("d0").join("f0000.txt")).unwrap();
        let store_dir = dir.join("store");
        let cfg = BuildConfig::default();

        build_store(&root, &store_dir, &cfg).expect("build");
        update_store(&root, &store_dir, &cfg).expect("update");
        for i in 1..30 {
            let sub = root.join(format!("d{}", i % 4));
            fs::write(sub.join(format!("f{i:04}.txt")), vec![b'z'; 9000]).unwrap();
        }
        update_store(&root, &store_dir, &cfg).expect("update");

        let want = live_payloads(&store_dir);
        assert!(!want.is_empty(), "fixture must hold live payloads");

        compact_store(&store_dir, 0.0)
            .expect("compact runs")
            .expect("compaction is worth it here");

        assert_eq!(
            live_payloads(&store_dir),
            want,
            "compaction changed what the store answers"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Compaction must be idempotent in its decision: a store already compact
    /// is not rewritten, so this cannot be run on every update for free.
    #[test]
    fn a_compact_store_is_left_alone() {
        let dir = store("noop");
        let root = dir.join("root");
        fill(&root, 20, 4096);
        let store_dir = dir.join("store");
        let cfg = BuildConfig::default();

        build_store(&root, &store_dir, &cfg).expect("build");
        compact_store(&store_dir, 0.0)
            .expect("compact runs")
            .expect("first run rewrites");

        let second = compact_store(&store_dir, DEFAULT_MIN_WASTE).expect("second run is clean");
        assert!(
            second.is_none(),
            "a store with no waste must not be rewritten again"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A pack file nothing references — what a crash between publishing and
    /// deleting leaves behind — costs only disk, and the next run clears it.
    #[test]
    fn orphan_packs_from_an_interrupted_run_are_swept() {
        let dir = store("orphan");
        let root = dir.join("root");
        fill(&root, 20, 8192);
        let store_dir = dir.join("store");
        let cfg = BuildConfig::default();
        build_store(&root, &store_dir, &cfg).expect("build");

        let orphan = store_dir.join("99999999.tvp");
        fs::write(&orphan, b"not referenced by anything").unwrap();
        assert!(orphan.exists());

        let stats = compact_store(&store_dir, 0.0)
            .expect("compact runs")
            .expect("runs");
        assert!(!orphan.exists(), "an unreferenced pack must be removed");
        assert_eq!(stats.orphans_removed, 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
