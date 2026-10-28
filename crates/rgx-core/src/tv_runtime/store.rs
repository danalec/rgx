// SPDX-License-Identifier: Apache-2.0

//! A warm, bounded pool of pack mappings for long-lived processes.
//!
//! `search_store` pays three costs on every call that a long-lived process pays
//! exactly once: `load_manifest` (CRC + parse of the whole catalog),
//! `open`+`mmap` of every pack, and the serial teardown that unmaps all of them
//! at the end. Only the first is cheap. The third is the largest single stage of
//! a query over the registry store, and it is pure prologue/epilogue.
//!
//! `MappedStore` holds the parsed manifest, the filtered file indexes and the
//! pack mappings alive across calls. A pooled search takes one read lock, bumps
//! an LRU tick, and never unmaps anything.
//!
//! # What the pool is actually for
//!
//! It removes the teardown, the re-map and the manifest re-parse from every
//! query **after the first**. It removes them from *none* of them when the
//! process makes exactly one query and then exits: the mappings are dropped
//! when the pool drops, and that drop unmaps all of them just as expensively.
//!
//! So the pool is for an embedder that queries one store many times in one
//! process. For a single-shot query it is dead weight, which is why the CLI
//! asks for it explicitly (`--pool`) rather than by default.
//!
//! # Bounds
//!
//! The pool is bounded on purpose. `PoolLimits::max_mapped_bytes` is a hard
//! ceiling on total mapped payload. Packs are admitted in LRU order, so a
//! ceiling that cannot hold the whole store keeps the packs the process
//! actually reads rather than the first ones on disk.
//!
//! # Two independent axes
//!
//! `PoolLimits::use_mmap` exists so this cannot be confused with
//! `SearchConfig::read_mode`, which selects mmap versus buffered reads.
//!
//! # Invalidation
//!
//! Every snapshot is pinned to the `(mtime, len)` of `manifest.tvm` taken when it
//! was parsed. `update_store` publishes a new generation by atomic rename, which
//! changes both, so the next [`snapshot`](MappedStore::snapshot) reparses. Pack
//! files are append-only and never rewritten, so a mapping whose filename and
//! length still appear in the new manifest is reused across the change.

use alloc::string::String;
use alloc::vec::Vec;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::UNIX_EPOCH;

use crate::memmap2::Mmap;

use super::format::{Manifest, PackHeader};

/// Default ceiling: 4 GiB of mapped payload. That holds the 1.87 GB registry
/// store whole while still being a real bound rather than "whatever fits".
pub const DEFAULT_MAX_MAPPED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Ceilings and switches for a [`MappedStore`].
#[derive(Debug, Clone)]
pub struct PoolLimits {
    /// Hard ceiling on total mapped payload the pool keeps alive.
    pub max_mapped_bytes: u64,
    /// Independent of `SearchConfig::use_mmap`: when false the pool maps
    /// nothing and pooled searches fall back to the cold path.
    pub use_mmap: bool,
    /// Which file set the cached filter indexes describe.
    pub search_binary: bool,
}

impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            max_mapped_bytes: DEFAULT_MAX_MAPPED_BYTES,
            use_mmap: true,
            search_binary: false,
        }
    }
}

/// Identity of a parsed `manifest.tvm`: the stat that decides whether the cache
/// still describes what is on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ManifestKey {
    pub mtime_nanos: u64,
    pub len: u64,
}

/// A consistent, immutable view of a store: manifest, mappings and the filtered
/// file indexes. Any number of searches can hold one of these at once.
pub struct StoreSnapshot {
    pub manifest: Arc<Manifest>,
    /// Indexed by `pack_id`. `None` where the ceiling excluded a pack.
    pub packs: Arc<Vec<Option<Arc<Mmap>>>>,
    /// Indices into `manifest.files` that reach the worker loop.
    pub active: Arc<Vec<u32>>,
    /// Indices into `manifest.files` that are 0-byte.
    pub empty: Arc<Vec<u32>>,
    pub mapped_bytes: u64,
    /// False when the ceiling left packs unmapped. A search must then open the
    /// rest itself: a pack store is searched whole or not at all.
    pub complete: bool,
    pub key: ManifestKey,
    used: Arc<Mutex<Vec<u64>>>,
    clock: Arc<AtomicU64>,
}

impl StoreSnapshot {
    /// Marks every mapping most-recently-used. Called once per pooled query,
    /// outside the search, so the search itself does no coordination at all.
    pub fn touch(&self) {
        let now = self.clock.fetch_add(1, Ordering::Relaxed);
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        for (i, p) in self.packs.iter().enumerate() {
            if p.is_some() {
                used[i] = now;
            }
        }
    }

    /// The packs the pool is not holding, by id.
    pub fn cold_packs(&self) -> Vec<u32> {
        self.packs
            .iter()
            .enumerate()
            .filter(|(_, p)| p.is_none())
            .map(|(i, _)| i as u32)
            .collect()
    }
}

/// Counters that say whether the pool is doing anything at all.
#[derive(Debug, Clone, Copy, Default)]
pub struct PoolCounters {
    pub manifest_hits: u64,
    pub manifest_misses: u64,
    pub map_hits: u64,
    pub map_misses: u64,
    pub refreshes: u64,
    /// Mappings released by a refresh, i.e. unmapped on the pool's clock
    /// rather than on a query's.
    pub unmapped: u64,
    pub unmapped_bytes: u64,
}

/// What the pool currently holds.
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub generation: u64,
    pub mapped_packs: usize,
    pub total_packs: usize,
    pub mapped_bytes: u64,
    pub max_mapped_bytes: u64,
    /// False when the ceiling could not hold the whole store. Queries still
    /// return complete results; they open the missing packs per query.
    pub complete: bool,
    pub warm: bool,
    pub active_files: usize,
    pub empty_files: usize,
    pub counters: PoolCounters,
}

/// A long-lived pool of pack mappings and a parsed manifest for one store
/// directory.
pub struct MappedStore {
    dir: PathBuf,
    limits: PoolLimits,
    snap: RwLock<Option<Arc<StoreSnapshot>>>,
    /// `pack_id -> filename` of the snapshot currently installed, so a
    /// generation change can tell which mappings are still the same bytes.
    names: RwLock<Arc<Vec<String>>>,
    clock: Arc<AtomicU64>,
    counters: Mutex<PoolCounters>,
}

impl MappedStore {
    /// Creates a pool. Does no I/O; the store is read on the first
    /// [`warm`](Self::warm) or [`snapshot`](Self::snapshot).
    pub fn open(dir: &Path, limits: PoolLimits) -> io::Result<Self> {
        Ok(Self {
            dir: dir.to_path_buf(),
            limits,
            snap: RwLock::new(None),
            names: RwLock::new(Arc::new(Vec::new())),
            clock: Arc::new(AtomicU64::new(0)),
            counters: Mutex::new(PoolCounters::default()),
        })
    }

    pub fn limits(&self) -> &PoolLimits {
        &self.limits
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// True when the pool can serve a query at all. False only when the
    /// `use_mmap` axis is switched off.
    pub fn enabled(&self) -> bool {
        self.limits.use_mmap
    }

    /// Reads the manifest and maps everything that fits under the ceiling,
    /// paying the whole cost here rather than inside a query.
    pub fn warm(&self) -> io::Result<Arc<StoreSnapshot>> {
        self.refresh(None)
    }

    /// The hot path: one `stat`, a read lock and an LRU tick per call, and zero
    /// re-parsing or re-mapping while `manifest.tvm` is unchanged.
    pub fn snapshot(&self) -> io::Result<Arc<StoreSnapshot>> {
        let key = self.manifest_key()?;
        {
            let guard = self.snap.read().unwrap_or_else(|e| e.into_inner());
            if let Some(s) = guard.as_ref() {
                if s.key == key {
                    s.touch();
                    self.counters
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .manifest_hits += 1;
                    return Ok(Arc::clone(s));
                }
            }
        }
        self.refresh(Some(key))
    }

    pub fn stats(&self) -> PoolStats {
        let counters = *self.counters.lock().unwrap_or_else(|e| e.into_inner());
        let guard = self.snap.read().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(s) => PoolStats {
                generation: s.manifest.generation,
                mapped_packs: s.packs.iter().filter(|p| p.is_some()).count(),
                total_packs: s.manifest.packs.len(),
                mapped_bytes: s.mapped_bytes,
                max_mapped_bytes: self.limits.max_mapped_bytes,
                complete: s.complete,
                warm: true,
                active_files: s.active.len(),
                empty_files: s.empty.len(),
                counters,
            },
            None => PoolStats {
                generation: 0,
                mapped_packs: 0,
                total_packs: 0,
                mapped_bytes: 0,
                max_mapped_bytes: self.limits.max_mapped_bytes,
                complete: false,
                warm: false,
                active_files: 0,
                empty_files: 0,
                counters,
            },
        }
    }

    fn manifest_key(&self) -> io::Result<ManifestKey> {
        let md = std::fs::metadata(self.dir.join("manifest.tvm"))?;
        let mtime_nanos = md
            .modified()?
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Ok(ManifestKey {
            mtime_nanos,
            len: md.len(),
        })
    }

    fn refresh(&self, want_key: Option<ManifestKey>) -> io::Result<Arc<StoreSnapshot>> {
        let key = match want_key {
            Some(k) => k,
            None => self.manifest_key()?,
        };

        let (old_packs, old_used, old_names) = {
            let guard = self.snap.read().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(s) => (
                    Arc::clone(&s.packs),
                    s.used.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                    Arc::clone(&self.names.read().unwrap_or_else(|e| e.into_inner())),
                ),
                None => (Arc::new(Vec::new()), Vec::new(), Arc::new(Vec::new())),
            }
        };

        // What the previous snapshot had mapped, by filename and byte length.
        // A pack file is written once and never rewritten, so a name+length
        // hit means the same bytes and the mapping can be carried forward.
        let mut prior: HashMap<&str, (u32, u64)> = HashMap::new();
        for (id, m) in old_packs.iter().enumerate() {
            if let Some(m) = m {
                if let Some(name) = old_names.get(id) {
                    let payload = m.len().saturating_sub(PackHeader::SIZE) as u64;
                    prior.insert(name.as_str(), (id as u32, payload));
                }
            }
        }

        let manifest = Arc::new(super::format::load_manifest(&self.dir)?);

        let slots = manifest.packs.iter().map(|p| p.pack_id).max().unwrap_or(0) as usize + 1;
        let mut packs: Vec<Option<Arc<Mmap>>> = vec![None; slots];
        let mut used: Vec<u64> = vec![0; slots];
        let mut names: Vec<String> = vec![String::new(); slots];

        // Admit in LRU order so a ceiling that cannot hold everything keeps the
        // packs the process actually reads.
        let mut order: Vec<u32> = (0..slots as u32).collect();
        order.sort_by_key(|&i| (old_used.get(i as usize).copied().unwrap_or(0), i));

        let mut mapped_bytes: u64 = 0;
        let mut hits = 0u64;
        let mut misses = 0u64;
        for id in order {
            let Some(rec) = manifest.packs.iter().find(|p| p.pack_id == id) else {
                continue;
            };
            names[id as usize] = rec.filename.clone();
            if !self.limits.use_mmap {
                continue;
            }
            if mapped_bytes + rec.content_len > self.limits.max_mapped_bytes {
                continue;
            }
            if let Some(&(old_id, old_len)) = prior.get(rec.filename.as_str()) {
                if old_len == rec.content_len {
                    if let Some(m) = old_packs[old_id as usize].clone() {
                        mapped_bytes += rec.content_len;
                        packs[id as usize] = Some(m);
                        used[id as usize] = u64::MAX;
                        hits += 1;
                        continue;
                    }
                }
            }
            let path = self.dir.join(&rec.filename);
            let f = File::open(&path)?;
            let m = unsafe { Mmap::map(&f)? };
            mapped_bytes += rec.content_len;
            packs[id as usize] = Some(Arc::new(m));
            used[id as usize] = 0;
            misses += 1;
        }

        // Reused entries inherit the previous snapshot's tick so a generation
        // change does not reset the LRU order.
        let tick = self.clock.fetch_add(1, Ordering::Relaxed);
        for (i, u) in used.iter_mut().enumerate() {
            if *u == u64::MAX {
                *u = old_used.get(i).copied().unwrap_or(tick);
            }
        }

        let mut active = Vec::new();
        let mut empty = Vec::new();
        for (i, f) in manifest.files.iter().enumerate() {
            if f.is_deleted {
                continue;
            }
            if !self.limits.search_binary && f.is_binary {
                continue;
            }
            if f.is_empty {
                empty.push(i as u32);
            } else {
                active.push(i as u32);
            }
        }

        // Complete means every pack the manifest lists is actually mapped. The
        // reuse/miss counters describe where the bytes came from, not coverage.
        let mapped: usize = packs.iter().filter(|p| p.is_some()).count();
        let complete = mapped == manifest.packs.len();

        let snap = Arc::new(StoreSnapshot {
            manifest: Arc::clone(&manifest),
            packs: Arc::new(packs),
            active: Arc::new(active),
            empty: Arc::new(empty),
            mapped_bytes,
            complete,
            key,
            used: Arc::new(Mutex::new(used)),
            clock: Arc::clone(&self.clock),
        });

        // Whatever the previous snapshot held and this one does not is released
        // here, on the refresh, never on a query.
        let previous = {
            let mut g = self.snap.write().unwrap_or_else(|e| e.into_inner());
            g.replace(Arc::clone(&snap))
        };
        {
            let mut g = self.names.write().unwrap_or_else(|e| e.into_inner());
            *g = Arc::new(names);
        }
        let (unmapped, unmapped_bytes) = match previous {
            Some(p) => {
                let n = p.packs.iter().flatten().count() as u64;
                let b: u64 = p.packs.iter().flatten().map(|m| m.len() as u64).sum();
                (n, b)
            }
            None => (0, 0),
        };

        let mut c = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        c.map_hits += hits;
        c.map_misses += misses;
        c.refreshes += 1;
        c.unmapped += unmapped;
        c.unmapped_bytes += unmapped_bytes;
        // A refresh always reparsed the manifest; the hit is counted at the
        // snapshot() fast path.
        c.manifest_misses += 1;

        Ok(snap)
    }
}
