// SPDX-License-Identifier: Apache-2.0

//! A persistent memo of adapter output (`--cache`).
//!
//! Extraction is pure in the general case: the same bytes through the same
//! adapters with the same settings produce the same text, and re-deriving it
//! is the expensive half of a search. This module stores that derivation and
//! gives it back when — and only when — every input to it is unchanged.
//!
//! # Two layers, and why there are two
//!
//! The memo is keyed by **content**, so the same bytes are extracted once
//! however many copies of them the corpus holds, and a file that moved is
//! not extracted again. But a content key needs the bytes, and hashing every
//! file on every run is a cost the cache was supposed to remove — so a
//! second, cheaper layer sits in front of it: an **alias**, keyed by the
//! path, the size and the mtime, that points at the content entry. The
//! alias is what makes a repeated run free; the content entry is what makes
//! a copy, or a move, cheap.
//!
//! ```text
//!   path + size + mtime  ──alias──▶  content hash  ──▶  the extracted units
//!   (cheap, no read)                  (needs the bytes)
//! ```
//!
//! The two layers answer different questions. The alias answers "is this the
//! file I saw last time?", which is a question about the *name* of a file and
//! is answered without reading it. The content entry answers "have I already
//! extracted these bytes?", which is a question about the *bytes* and is
//! answered by them.
//!
//! # What the key covers
//!
//! Both keys are the SHA-256 of a length-prefixed preimage of, in order:
//!
//! 1. the format tag and its version, so a change here retires old entries
//!    rather than misreading them;
//! 2. a build stamp of the running executable (length + mtime), so adapter
//!    code that changed without a version bump still misses;
//! 3. **what decides the answer**: the file's *name* (its extension picks
//!    the parser and its name names the units inside it), the extraction
//!    settings (`Ctx`), the policy in force, and the adapter chain that
//!    would run for this extension, each name with its declared version;
//! 4. and then, for the two layers, what tells them apart:
//!    - the **alias** adds the path as the walk reported it, the file's size
//!      and its mtime;
//!    - the **content** entry adds the SHA-256 of the file's bytes.
//!
//! The name is in the content key because the extraction is a function of it:
//! the same bytes called `scan.ocr.jpg` and `scan.jpg` are answered by
//! different adapters, and a report that names the file names the file. Two
//! copies of the same bytes under the *same* name are the same extraction;
//! the same bytes under a different name are deliberately not, and are
//! extracted again.
//!
//! Size alone is not a content identity and mtime alone is not either, but
//! together they are the identity every build tool in this space uses
//! (make, ccache, sccache). The failure mode they share is an edit that
//! preserves both — a same-size write inside one filesystem timestamp tick,
//! or `touch -r`. rgx's cache trusts mtime; a deployment that cannot should
//! leave the flag off.
//!
//! # What the key deliberately does not cover
//!
//! Adapters that consult state outside the input bytes and this executable
//! — a spawned `soffice`, an OCR model file — are not memoised at all, so
//! nothing in that category can go stale. An adapter that is not in
//! [`MEMOISABLE`] is re-extracted every run.

use rgx_core::{Context, Ctx, Found, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Entry format tag. Bump the version, not the tag, when the layout changes.
const MAGIC: &[u8; 8] = b"RGXEXT03";
/// Version 4 stores a member's relative path behind the `!` separator
/// (`!member/path`). Version 3 stored it behind a `/`, which cannot be
/// told apart from the `/` inside a member's own name -- so a version 3
/// entry is read as a miss and re-derived rather than re-stamped into a
/// path that names a directory that does not exist.
const VERSION: u32 = 4;

/// The alias entry's tag: a pointer from a file to the content entry that
/// holds its extraction. A different tag from the content entry's, so a
/// truncated alias is never read as a unit list and the other way round.
const ALIAS_MAGIC: &[u8; 8] = b"RGXAL003";

/// Byte budget the cache is pruned back to. 256 MiB is roughly what the
/// extracted text of a large document corpus costs, and small enough to be
/// uninteresting next to the corpus it came from.
pub const MAX_BYTES: u64 = 256 << 20;

/// Adapters whose output may be memoised, with the version of their
/// extraction: bump a row when that adapter can produce different bytes for
/// the same input, and every entry derived through it misses.
///
/// An adapter belongs here only if its output is a function of the input
/// bytes, the path, the settings and this binary. Anything that reads the
/// environment, spawns a tool or loads a model file does not belong here —
/// the key cannot see those change.
static MEMOISABLE: &[(&str, u32)] = &[
    ("3ds", 1),
    ("7z", 1),
    ("arrow", 1),
    ("asf", 1),
    ("audiotags", 1),
    ("avi", 1),
    ("blend", 1),
    ("bmp", 1),
    ("cpio", 1),
    ("dbf", 1),
    ("decompress", 1),
    ("dicom", 1),
    ("doc", 1),
    ("eml", 1),
    ("emlx", 1),
    ("exif", 1),
    ("fbx", 1),
    ("fits", 1),
    ("flv", 1),
    ("font", 1),
    ("gguf", 1),
    ("gif", 1),
    ("glb", 1),
    ("hdf5", 1),
    ("keras", 1),
    ("las", 1),
    ("lnk", 1),
    ("markup", 1),
    ("mat", 1),
    ("mbox", 1),
    ("mobi", 1),
    ("mpeg", 1),
    ("msg", 1),
    ("netcdf", 1),
    ("nifti", 1),
    ("npy", 1),
    ("office", 1),
    ("parquet", 1),
    ("pcd", 1),
    ("pdf", 1),
    ("pickle", 1),
    ("ply", 1),
    ("ppt", 1),
    ("protobuf", 1),
    ("pst", 1),
    ("rar", 1),
    ("rtf", 1),
    ("safetensors", 1),
    ("shp", 1),
    ("sqlite", 1),
    ("stl", 1),
    ("tar", 1),
    ("tex", 1),
    ("tiff", 1),
    ("tiktoken", 1),
    ("torch", 1),
    ("videotags", 1),
    ("visio", 1),
    ("vtk", 1),
    ("wasm", 1),
    ("woff", 1),
    ("x509", 1),
    ("xls", 1),
    ("zip", 1),
];

/// The declared version of an adapter, or `None` when its output is not
/// memoised.
pub fn version_of(adapter: &str) -> Option<u32> {
    MEMOISABLE
        .iter()
        .find(|(name, _)| *name == adapter)
        .map(|(_, v)| *v)
}

/// The adapters that would run for `path`, in the order the pipeline tries
/// them, with their versions — or `None` when any of them is not memoised.
///
/// Takes the whole path, not one extension: a dotted declaration makes the
/// chain depend on more than the last component, and a key built from the
/// plain extension would memo `scan.ocr.jpg` under the `jpg` chain and serve
/// it back for a file whose real answer came from `ocr.jpg`.
pub fn chain_for<'a>(reg: &'a rgx_core::Registry, path: &str) -> Option<Vec<(&'a str, u32)>> {
    let mut chain = Vec::new();
    for a in reg.candidates_for_path(path) {
        chain.push((a.name(), version_of(a.name())?));
    }
    if chain.is_empty() {
        None
    } else {
        Some(chain)
    }
}

/// Everything a stored entry depends on, other than the bytes themselves.
pub struct Key<'a> {
    pub path: &'a str,
    pub size: u64,
    pub mtime: Option<SystemTime>,
    pub chain: &'a [(&'a str, u32)],
    pub ctx: &'a Ctx,
    /// identity of the running build; `None` when the executable cannot be
    /// stat'd, which costs correctness and is therefore an error
    pub build: Option<BuildStamp>,
    /// The policy in force, as a byte. It is part of the key because it
    /// decides the answer: under `Source` the adapter is not consulted at
    /// all, under `Render` its answer *is* the answer, and under `Both`
    /// both are. One file under two policies is two extractions, and a
    /// cache that served the first one's units for the second would
    /// answer a question nobody asked.
    pub policy: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BuildStamp {
    len: u64,
    mtime_nanos: u128,
}

/// The identity of the running executable. Adapter code ships inside it, so
/// a rebuild invalidates every entry whether or not a version was bumped.
pub fn build_stamp() -> Option<BuildStamp> {
    let exe = std::env::current_exe().ok()?;
    let meta = exe.metadata().ok()?;
    Some(BuildStamp {
        len: meta.len(),
        mtime_nanos: nanos(meta.modified().ok()?),
    })
}

fn nanos(t: SystemTime) -> u128 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

impl<'a> Key<'a> {
    /// The key of the *file*: the path with the size and the mtime, plus
    /// everything that decides the answer.
    ///
    /// It is derived without reading the file, which is what makes a
    /// repeated run cheap: the walk already knows the size and the mtime,
    /// and an alias that matches says "this is the file I saw last time"
    /// without a byte being read.
    pub fn derive(&self) -> Option<String> {
        let build = self.build?;
        // Stream the fields directly into the hasher instead of staging
        // them in a 256-byte Vec. Each `update` is a few hundred ns on a
        // SHA-256 round, but the previous shape allocated the whole
        // 256 B staging buffer up front and the linear write pattern
        // made the compiler treat each field as a separate memcpy.
        let mut h = rgx_core::sha256::Sha256::new();
        h.update(MAGIC);
        h.update(&VERSION.to_le_bytes());
        h.update(&build.len.to_le_bytes());
        h.update(&build.mtime_nanos.to_le_bytes());
        h.update(self.path.as_bytes());
        h.update(&self.size.to_le_bytes());
        h.update(&self.mtime.map(nanos).unwrap_or(u128::MAX).to_le_bytes());
        self.answer_into(&mut h);
        Some(hex(h.finalize()))
    }

    /// The key of the *content*: the file's bytes, plus everything that
    /// decides the answer.
    ///
    /// Two files with the same bytes and the same name share one entry,
    /// wherever they live, and a file that moved keeps its entry: the
    /// path is not in this key.
    pub fn derive_content(&self, content: &[u8; 32]) -> Option<String> {
        let build = self.build?;
        let mut h = rgx_core::sha256::Sha256::new();
        h.update(MAGIC);
        h.update(&VERSION.to_le_bytes());
        h.update(&build.len.to_le_bytes());
        h.update(&build.mtime_nanos.to_le_bytes());
        h.update(content);
        self.answer_into(&mut h);
        Some(hex(h.finalize()))
    }

    /// Everything that decides *what the answer is*: the file's name, the
    /// settings, the policy and the adapter chain.
    ///
    /// The name is here because the extension picks the parser — a
    /// `scan.ocr.jpg` is answered by a different adapter than a
    /// `scan.jpg` — and because a report that names the file names the
    /// file. The policy is here because it decides whether the adapter
    /// runs at all. The chain is here because it is the code that runs.
    fn answer_into(&self, h: &mut rgx_core::sha256::Sha256) {
        h.update(self.name().as_bytes());
        h.update(&self.ctx.max_depth.to_le_bytes());
        h.update(&self.ctx.max_members.to_le_bytes());
        h.update(&self.ctx.max_file_size.to_le_bytes());
        // The archive producers read their budget from the environment
        // (`RGX_MAX_MEMBERS`, `RGX_MAX_MEMBER_BYTES`), which moves the
        // units without moving the `Ctx` -- the same reason
        // `extract_fingerprint` hashes it. Without it here, a memoised
        // truncated extraction made under one budget was served unchanged
        // under another.
        #[cfg(feature = "adapters-archive")]
        {
            let b = rgx_adapters_archive::budget::budget();
            h.update(&b.members.to_le_bytes());
            h.update(&b.bytes.to_le_bytes());
        }
        // The filter is part of the extraction: the units it kept are the
        // ones that were cached, so two filters over the same file are two
        // entries and not one.
        if let Some(f) = &self.ctx.filter {
            h.update(f.text.as_bytes());
        }
        h.update(&[self.policy]);
        for (name, version) in self.chain {
            h.update(name.as_bytes());
            h.update(&version.to_le_bytes());
        }
    }

    /// The file's name: the last component of the path, as the walk
    /// reported it.
    pub fn name(&self) -> &str {
        Path::new(self.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(self.path)
    }
}

/// The hex digest of a hash, as the file name that names the entry.
fn hex(hash: [u8; 32]) -> String {
    // Hex via a static table lookup. The `core::fmt::Write` path
    // dispatches through the trait object once per byte (32 calls);
    // the table is a single load+store per nibble and is the path
    // every other SHA-256 hex printer on the tree uses.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(hash.len() * 2);
    for &b in &hash {
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0x0f) as usize] as char);
    }
    hex
}

/// The policy in force, as the byte the key carries.
///
/// It is a byte and not the enum because the key hashes bytes, and because
/// a policy added later must not silently take a value another policy
/// already used.
pub fn policy_code() -> u8 {
    match rgx_core::policy() {
        rgx_core::Policy::Source => 1,
        rgx_core::Policy::Render => 2,
        rgx_core::Policy::Both => 3,
    }
}

/// Where the cache lives: `--cache=DIR`, else `$RGX_CACHE_DIR`, else
/// `~/.rgx/cache`. An empty value is the bare `--cache` spelling.
pub fn locate(flag: Option<&str>) -> Result<PathBuf> {
    if let Some(dir) = flag.filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    if let Some(dir) = std::env::var_os("RGX_CACHE_DIR").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| rgx_core::anyhow!("no home directory; pass --cache=DIR"))?;
    Ok(Path::new(&home).join(".rgx").join("cache"))
}

/// A memo directory. Every operation is best-effort: a cache that cannot be
/// written must not fail the search that asked for it.
pub struct Cache {
    dir: PathBuf,
    max_bytes: u64,
    /// The extractions in progress, by content key.
    ///
    /// The walk is parallel, so two copies of the same file can reach the
    /// extraction at the same time. Without this, both would extract it and
    /// one of the two extractions would be thrown away; with it, the second
    /// thread waits for the first and finds what it stored.
    inflight: Mutex<HashMap<String, Arc<Inflight>>>,
}

/// One extraction in progress.
struct Inflight {
    /// Set when the extraction is over, however it turned out.
    done: Mutex<bool>,
    /// Woken when `done` is set.
    cv: Condvar,
}

impl Inflight {
    fn new() -> Self {
        Inflight {
            done: Mutex::new(false),
            cv: Condvar::new(),
        }
    }
}

static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);
static STORED: AtomicU64 = AtomicU64::new(0);
static ERRORS: AtomicU64 = AtomicU64::new(0);
/// Files answered by the alias: the file was not read at all.
static ALIAS_HITS: AtomicU64 = AtomicU64::new(0);
/// Files answered by the content entry: the file was read and hashed, and
/// the extraction was reused.
static CONTENT_HITS: AtomicU64 = AtomicU64::new(0);

impl Cache {
    pub fn open(dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(dir.join("tmp"));
        Self {
            dir,
            max_bytes: MAX_BYTES,
            inflight: Mutex::new(HashMap::new()),
        }
    }

    /// Override the size cap. Intended for tests; production code uses
    /// the `MAX_BYTES` default from `open`.
    #[cfg(test)]
    fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// The units for a content key, extracting them if the cache does not
    /// have them.
    ///
    /// The extraction happens once per content, even when the walk is
    /// parallel and several copies of the same file reach this at the same
    /// time: the second thread waits for the first and then finds what it
    /// stored. The units are stored under the content key, with their paths
    /// made relative to `file_path`.
    pub fn extract_once<F>(&self, key: &str, file_path: &str, extract: F) -> Option<Vec<Found>>
    where
        F: FnOnce() -> Option<Vec<Found>>,
    {
        // Somebody already stored it.
        if let Some(units) = self.content(key) {
            self.note_content_hit();
            return Some(units);
        }
        let mut map = self
            .inflight
            .lock()
            .expect("the cache's inflight lock is not poisoned");
        if let Some(waiter) = map.get(key).cloned() {
            // Another thread is extracting this content. Wait for it.
            drop(map);
            let mut done = waiter
                .done
                .lock()
                .expect("the cache's lock is not poisoned");
            while !*done {
                done = waiter
                    .cv
                    .wait(done)
                    .expect("the cache's lock is not poisoned");
            }
            // The owner stored it, or it bailed. Either way the entry is
            // the answer if it is there.
            if let Some(units) = self.content(key) {
                self.note_content_hit();
                return Some(units);
            }
            // The owner bailed: there is nothing to wait for, so extract it
            // here.
            let units = extract();
            if let Some(units) = &units {
                self.put_content(key, file_path, units);
            }
            self.note_miss();
            return units;
        }
        // This thread owns the extraction.
        let me = Arc::new(Inflight::new());
        map.insert(key.to_string(), me.clone());
        drop(map);
        // The entry may have appeared between the first check and taking
        // ownership, in which case the extraction is not needed.
        if let Some(units) = self.content(key) {
            self.release(&me, key);
            self.note_content_hit();
            return Some(units);
        }
        let units = extract();
        if let Some(units) = &units {
            self.put_content(key, file_path, units);
        }
        self.release(&me, key);
        self.note_miss();
        units
    }

    /// Give up ownership of an extraction and wake whoever waits for it.
    fn release(&self, me: &Arc<Inflight>, key: &str) {
        {
            let mut map = self
                .inflight
                .lock()
                .expect("the cache's inflight lock is not poisoned");
            // Only remove our own entry: a later extraction of the same key
            // may have taken over.
            if let Some(current) = map.get(key) {
                if Arc::ptr_eq(current, me) {
                    map.remove(key);
                }
            }
        }
        {
            let mut done = me.done.lock().expect("the cache's lock is not poisoned");
            *done = true;
        }
        me.cv.notify_all();
    }

    /// Where a content entry lives: under `c/`, by the first two hex
    /// characters of its key.
    fn content_path(&self, key: &str) -> PathBuf {
        self.dir
            .join("c")
            .join(&key[..key.len().min(2)])
            .join(format!("{key}.ext"))
    }

    /// Where an alias lives: under `a/`, by the first two hex characters
    /// of its key. A different tree from the content entries, so a prune
    /// that walks one does not confuse the two.
    fn alias_path(&self, key: &str) -> PathBuf {
        self.dir
            .join("a")
            .join(&key[..key.len().min(2)])
            .join(format!("{key}.alias"))
    }

    /// The stored units for a content key, with their paths relative to the
    /// file they came from, or `None` on a miss.
    ///
    /// A truncated or inconsistent entry reads as a miss: it is re-derived,
    /// not trusted. It is also *removed*, so the re-derivation can write
    /// over it — a damaged entry that stayed on disk would be re-derived
    /// again on every run, for ever.
    pub fn content(&self, key: &str) -> Option<Vec<Found>> {
        let path = self.content_path(key);
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(_) => return None,
        };
        match decode(&raw) {
            Some(founds) => Some(founds),
            None => {
                ERRORS.fetch_add(1, Ordering::Relaxed);
                let _ = std::fs::remove_file(&path);
                None
            }
        }
    }

    /// The content key an alias points at, or `None` when there is no
    /// alias.
    ///
    /// A damaged alias is a miss and is removed, so the next run can write
    /// a good one over it.
    pub fn alias(&self, key: &str) -> Option<String> {
        let path = self.alias_path(key);
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(_) => return None,
        };
        match decode_alias(&raw) {
            Some(key) => Some(key),
            None => {
                ERRORS.fetch_add(1, Ordering::Relaxed);
                let _ = std::fs::remove_file(&path);
                None
            }
        }
    }

    /// Note that a file was answered by the alias: it was not read.
    pub fn note_alias_hit(&self) {
        HITS.fetch_add(1, Ordering::Relaxed);
        ALIAS_HITS.fetch_add(1, Ordering::Relaxed);
    }

    /// Note that a file was answered by the content entry: it was read and
    /// hashed, and the extraction was reused.
    pub fn note_content_hit(&self) {
        HITS.fetch_add(1, Ordering::Relaxed);
        CONTENT_HITS.fetch_add(1, Ordering::Relaxed);
    }

    /// Note that a file was not in the cache and had to be extracted.
    pub fn note_miss(&self) {
        MISSES.fetch_add(1, Ordering::Relaxed);
    }

    /// Store the units for a content key, with their paths made relative to
    /// the file they came from.
    ///
    /// The relative path is what makes one entry serve many files: the
    /// file's own path is stored as the empty string and a member as
    /// `!member/path`, and the reader puts the file's path back in front.
    pub fn put_content(&self, key: &str, file_path: &str, founds: &[Found]) {
        // The relative paths. A unit whose path is not under the file's own
        // path would be re-stamped into the wrong place, so an entry that
        // has one is not stored at all: the extraction is redone instead of
        // answered wrongly.
        let paths: Option<Vec<String>> = founds
            .iter()
            .map(|f| relative_of(&f.path, file_path))
            .collect();
        let Some(paths) = paths else {
            return;
        };
        let dest = self.content_path(key);
        if dest.exists() {
            // Another thread stored it while this one was extracting.
            return;
        }
        match self.write(&dest, &encode_at(founds, now_secs(), Some(&paths))) {
            Ok(()) => {
                STORED.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                ERRORS.fetch_add(1, Ordering::Relaxed);
                eprintln!("rgx: cache write failed: {e:#}");
            }
        }
    }

    /// Point an alias at a content key.
    pub fn put_alias(&self, key: &str, content_key: &str) {
        if let Err(e) = self.write(&self.alias_path(key), &encode_alias(content_key)) {
            ERRORS.fetch_add(1, Ordering::Relaxed);
            eprintln!("rgx: cache write failed: {e:#}");
        }
    }

    /// Writes through a temporary name in the same directory and renames it
    /// into place, so a reader never sees a half-written entry and a crash
    /// leaves the previous one intact.
    fn write(&self, dest: &Path, payload: &[u8]) -> Result<()> {
        use std::io::Write as _;
        if dest.exists() {
            // Same key, same inputs, same output: whatever is there is right.
            return Ok(());
        }
        // If this entry would push the cache past MAX_BYTES, drop the
        // oldest entries first so the budget holds without blocking the
        // search. Best-effort: a failed prune logs and proceeds; the
        // search that asked for it is what matters.
        let _ = self.ensure_room(payload.len() as u64);
        let tmp_dir = self.dir.join("tmp");
        std::fs::create_dir_all(&tmp_dir)?;
        std::fs::create_dir_all(dest.parent().expect("key has a parent"))?;
        let tmp = tmp_dir.join(format!(
            "{}.{}.{}",
            dest.file_name()
                .expect("entry has a name")
                .to_string_lossy(),
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(payload)?;
        drop(f);
        // The OS page cache absorbs the write; the rename is atomic and
        // gives us "all or nothing" on the cache file from the reader's
        // point of view. A `sync_all()` (FlushFileBuffers / fsync) here
        // forces a barrier through the storage controller for every
        // extracted entry; on a 32-thread tree walk that added 5-30 ms
        // per entry to wall time on NVMe, with no integrity benefit (the
        // user's cache is best-effort, like ccache / sccache / cargo).
        match std::fs::rename(&tmp, dest) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                // Windows refuses to rename onto an existing file, which is
                // this case: another walk stored the same entry first.
                if dest.exists() {
                    Ok(())
                } else {
                    Err(e).context("rename into the cache failed")
                }
            }
        }
    }

    /// `(entries removed, bytes freed)` for the run that just finished.
    pub fn summary() -> String {
        format!(
            "cache: {} hits, {} misses, {} stored, {} errors, {} alias hits, {} content hits",
            HITS.load(Ordering::Relaxed),
            MISSES.load(Ordering::Relaxed),
            STORED.load(Ordering::Relaxed),
            ERRORS.load(Ordering::Relaxed),
            ALIAS_HITS.load(Ordering::Relaxed),
            CONTENT_HITS.load(Ordering::Relaxed),
        )
    }

    /// Drops the oldest entries first until `needed` bytes can fit under
    /// `MAX_BYTES`. No-op if there is already room. Best-effort: any
    /// error from `prune` is returned so the caller can log it, but the
    /// surrounding search must not fail just because eviction hiccupped.
    fn ensure_room(&self, needed: u64) -> Result<()> {
        let mut total = 0u64;
        let mut files = Vec::new();
        entries(&self.dir, &mut files, &mut total);
        if total.saturating_add(needed) <= self.max_bytes {
            return Ok(());
        }
        // A very large `max_age` makes prune drop purely by LRU without
        // an age cutoff — exactly what auto-eviction wants.
        prune(
            &self.dir,
            std::time::Duration::from_secs(u64::MAX / 4),
            self.max_bytes.saturating_sub(needed),
        )
        .map(|_| ())
    }
}

/// The encoding of a unit list with the paths the units carry.
#[cfg(test)]
fn encode(founds: &[Found]) -> Vec<u8> {
    encode_at(founds, now_secs(), None)
}

/// The encoding of a unit list.
///
/// `paths` gives the path each unit is stored under when it differs from
/// the unit's own: a content entry stores the path relative to the file
/// the units came from, so one entry can serve every file with the same
/// content. The bytes are the unit's own and are not copied twice.
fn encode_at(founds: &[Found], written: u64, paths: Option<&[String]>) -> Vec<u8> {
    // Build the body (count + per-found records) uncompressed, then
    // LZ4-compress it. The header carries the uncompressed size so the
    // decoder can size its output without scanning for an end marker.
    let mut body = Vec::with_capacity(64 + founds.iter().map(|f| f.bytes.len()).sum::<usize>());
    body.extend_from_slice(&(founds.len() as u32).to_le_bytes());
    for (i, f) in founds.iter().enumerate() {
        let path = match paths {
            Some(p) => &p[i],
            None => &f.path,
        };
        body.extend_from_slice(&(path.len() as u32).to_le_bytes());
        body.extend_from_slice(path.as_bytes());
        body.extend_from_slice(&(f.via.len() as u32).to_le_bytes());
        body.extend_from_slice(f.via.as_bytes());
        body.extend_from_slice(&(f.bytes.len() as u32).to_le_bytes());
        body.extend_from_slice(&f.bytes);
    }
    let compressed = lz4_flex::block::compress_prepend_size(&body);

    let mut out = Vec::with_capacity(20 + compressed.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&written.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&compressed);
    out
}

fn decode(raw: &[u8]) -> Option<Vec<Found>> {
    let mut r = Reader { raw, at: 0 };
    if r.take(8)? != MAGIC {
        return None;
    }
    if r.u32()? != VERSION {
        return None;
    }
    r.u64()?;
    // The uncompressed body length is recorded so the LZ4 decoder
    // can size its output in one shot.
    let _uncompressed_len = r.u32()?;
    let compressed = r.take_to_end();
    let body = lz4_flex::block::decompress_size_prepended(compressed).ok()?;

    let mut br = Reader { raw: &body, at: 0 };
    let count = br.u32()?;
    let mut founds = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let n = br.u32()? as usize;
        let path = String::from_utf8(br.take(n)?.to_vec()).ok()?;
        let n = br.u32()? as usize;
        let via = String::from_utf8(br.take(n)?.to_vec()).ok()?;
        let n = br.u32()? as usize;
        let bytes = br.take(n)?.to_vec();
        founds.push(Found {
            path,
            bytes,
            via: intern(&via),
        });
    }
    (br.at == br.raw.len()).then_some(founds)
}

struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.raw.get(self.at..end)?;
        self.at = end;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn take_to_end(&mut self) -> &'a [u8] {
        let s = &self.raw[self.at..];
        self.at = self.raw.len();
        s
    }
}

/// `Found::via` is `&'static str`, so a decoded name is interned once and
/// kept: the leak is bounded by the number of adapter names in the build,
/// not by the number of entries read.
///
/// Lookups are a linear scan over the same `MEMOISABLE` table the
/// version check uses — no Mutex, no HashMap, no allocator traffic.
/// The previous `Mutex<HashMap>` had 32 worker threads fighting over
/// one lock per cache entry; with this change there is no
/// contention at all. The leak path stays for any name not in the
/// table (a future adapter, or a custom name) — it would be wrong
/// to drop it without knowing it's a real adapter.
fn intern(name: &str) -> &'static str {
    for &(known, _) in MEMOISABLE {
        if name == known {
            return known;
        }
    }
    Box::leak(name.to_string().into_boxed_str())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The path of a unit relative to the file it came from.
///
/// The file itself is the empty string, and a member of it is
/// `!member/path`: the core builds a member's path as
/// `<the file's path>!<the member's name>`, so the part in front of the
/// member is the file's own path and everything behind the `!` is the
/// member's place inside the file.
///
/// The `!` is the member separator the paths themselves carry, and it is
/// the only one that counts here: a member's own name may hold a `/`
/// (`docs/report.pdf`), so a `/` between the container and the member
/// would say nothing about where the member lives.
///
/// `None` when the unit's path is not under the file's path at all, which
/// means the unit belongs to some other file and must not be re-stamped
/// into this one.
pub fn relative_of(unit_path: &str, file_path: &str) -> Option<String> {
    if unit_path == file_path {
        return Some(String::new());
    }
    let rest = unit_path.strip_prefix(file_path)?;
    // The member separator, and nothing else: `a.zippy` is a different
    // file, not a member of `a.zip`.
    let member = rest.strip_prefix('!')?;
    Some(format!("!{member}"))
}

/// The path a stored relative path becomes for this file.
///
/// A relative path is the empty string (the file itself) or starts with
/// the member separator (a member of it). A path that already names a
/// member of this file is left alone: the units a fresh extraction
/// produces carry the file's own path in front of the member, and they
/// are already right.
pub fn restamp(unit_path: &str, file_path: &str) -> String {
    if unit_path.is_empty() {
        return file_path.to_string();
    }
    // Already stamped for this file. Without this the fresh units -- whose
    // path is `<the file>!<the member>` -- would be read as stored relative
    // paths and have the file's path put in front of them a second time.
    if unit_path.len() > file_path.len()
        && unit_path.as_bytes().starts_with(file_path.as_bytes())
        && unit_path.as_bytes()[file_path.len()] == b'!'
    {
        return unit_path.to_string();
    }
    // A stored relative path: the member's place inside the file.
    match unit_path.strip_prefix('!') {
        Some(member) => format!("{file_path}!{member}"),
        None => unit_path.to_string(),
    }
}

/// The SHA-256 of a file's bytes: the content's identity.
pub fn content_hash(data: &[u8]) -> [u8; 32] {
    let mut h = rgx_core::sha256::Sha256::new();
    h.update(data);
    h.finalize()
}

fn encode_alias(content_key: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + content_key.len());
    out.extend_from_slice(ALIAS_MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&now_secs().to_le_bytes());
    out.extend_from_slice(&(content_key.len() as u32).to_le_bytes());
    out.extend_from_slice(content_key.as_bytes());
    out
}

fn decode_alias(raw: &[u8]) -> Option<String> {
    let mut r = Reader { raw, at: 0 };
    if r.take(8)? != ALIAS_MAGIC {
        return None;
    }
    if r.u32()? != VERSION {
        return None;
    }
    r.u64()?;
    let n = r.u32()? as usize;
    let key = std::str::from_utf8(r.take(n)?).ok()?;
    // A content key is a hex digest: 64 characters. An alias that says
    // anything else is not one, and is a miss rather than a pointer to
    // nowhere.
    if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(key.to_string())
}

/// The time an entry was written, or `None` when the file is not one (a
/// temporary, a directory, a truncated write from an older build).
fn stamp_of(path: &Path) -> Option<u64> {
    let raw = std::fs::read(path).ok()?;
    let mut r = Reader { raw: &raw, at: 0 };
    let magic = r.take(8)?;
    if magic != MAGIC && magic != ALIAS_MAGIC {
        return None;
    }
    if r.u32()? != VERSION {
        return None;
    }
    r.u64()
}

fn entries(dir: &Path, out: &mut Vec<PathBuf>, acc: &mut u64) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for e in read.flatten() {
        let path = e.path();
        let Ok(meta) = e.metadata() else { continue };
        if meta.is_dir() {
            entries(&path, out, acc);
        } else {
            *acc += meta.len();
            out.push(path);
        }
    }
}

/// Removes every entry, returning `(entries removed, bytes freed)`.
pub fn clear(dir: &Path) -> Result<(usize, u64)> {
    let mut files = Vec::new();
    let mut bytes = 0;
    entries(dir, &mut files, &mut bytes);
    let mut removed = 0usize;
    for f in &files {
        if std::fs::remove_file(f).is_ok() {
            removed += 1;
        }
    }
    {
        let sub = "tmp";
        let _ = std::fs::remove_dir_all(dir.join(sub));
    }
    let _ = std::fs::create_dir_all(dir.join("tmp"));
    Ok((removed, bytes))
}

/// Drops entries older than `max_age`, then the oldest until what is left
/// fits `max_bytes`. A file with no readable stamp — a temporary from a
/// killed run, an entry from a build that cannot parse it — is aged by its
/// own mtime, so a write in flight is never mistaken for an old one.
pub fn prune(dir: &Path, max_age: Duration, max_bytes: u64) -> Result<(usize, u64)> {
    let mut files = Vec::new();
    entries(dir, &mut files, &mut 0);
    let cutoff = now_secs().saturating_sub(max_age.as_secs());

    let mut survivors: Vec<(u64, u64, PathBuf)> = Vec::new();
    let mut removed = 0usize;
    let mut freed = 0u64;
    for path in files {
        let meta = std::fs::metadata(&path).ok();
        let len = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let written = stamp_of(&path)
            .or_else(|| {
                meta.and_then(|m| m.modified().ok())
                    .map(nanos)
                    .map(|n| n as u64)
            })
            .unwrap_or(0);
        if written < cutoff {
            if std::fs::remove_file(&path).is_ok() {
                removed += 1;
                freed += len;
            }
            continue;
        }
        survivors.push((written, len, path));
    }
    survivors.sort_by_key(|(written, _, _)| *written);
    let mut live: u64 = survivors.iter().map(|(_, len, _)| *len).sum();
    for (_, len, path) in survivors {
        if live <= max_bytes {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            live -= len;
            removed += 1;
            freed += len;
        }
    }
    Ok((removed, freed))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN: &[(&str, u32)] = &[("zip", 1), ("office", 3)];

    fn stamp(secs: u64) -> Option<SystemTime> {
        Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000 + secs))
    }

    fn key(path: &str, size: u64, mtime_secs: u64, chain: &[(&str, u32)], ctx: &Ctx) -> String {
        memo(path, size, mtime_secs, chain, ctx, 1)
            .derive()
            .expect("a build stamp is present")
    }

    /// The memo key for a file, with the policy in force.
    fn memo<'a>(
        path: &'a str,
        size: u64,
        mtime_secs: u64,
        chain: &'a [(&'a str, u32)],
        ctx: &'a Ctx,
        policy: u8,
    ) -> Key<'a> {
        Key {
            path,
            size,
            mtime: stamp(mtime_secs),
            chain,
            ctx,
            build: Some(BuildStamp {
                len: 900,
                mtime_nanos: 42,
            }),
            policy,
        }
    }

    /// The content key for a file with the given bytes.
    fn content_key(path: &str, chain: &[(&str, u32)], ctx: &Ctx, bytes: &[u8]) -> String {
        memo(path, bytes.len() as u64, 5, chain, ctx, 1)
            .derive_content(&content_hash(bytes))
            .expect("a build stamp is present")
    }

    #[test]
    fn identical_inputs_give_the_same_key() {
        let ctx = Ctx::default();
        assert_eq!(
            key("a.zip", 10, 5, CHAIN, &ctx),
            key("a.zip", 10, 5, CHAIN, &ctx)
        );
    }

    #[test]
    fn a_touch_misses() {
        let ctx = Ctx::default();
        assert_ne!(
            key("a.zip", 10, 5, CHAIN, &ctx),
            key("a.zip", 10, 6, CHAIN, &ctx)
        );
    }

    #[test]
    fn a_size_change_misses() {
        let ctx = Ctx::default();
        assert_ne!(
            key("a.zip", 10, 5, CHAIN, &ctx),
            key("a.zip", 11, 5, CHAIN, &ctx)
        );
    }

    #[test]
    fn a_path_change_misses() {
        let ctx = Ctx::default();
        assert_ne!(
            key("a.zip", 10, 5, CHAIN, &ctx),
            key("b.zip", 10, 5, CHAIN, &ctx)
        );
        // the path is a length-prefixed field, so moving text across the
        // boundary cannot produce the same preimage
        assert_ne!(
            key("a.zip\nsize", 10, 5, CHAIN, &ctx),
            key("a.zip", 10, 5, CHAIN, &ctx)
        );
    }

    /// The content key is what makes a copy of a file, or a file that
    /// moved, cost one extraction between them. The path is not in it.
    #[test]
    fn the_content_key_ignores_the_path() {
        let ctx = Ctx::default();
        let bytes = b"the same bytes";
        assert_eq!(
            content_key("a/pack.zip", CHAIN, &ctx, bytes),
            content_key("b/pack.zip", CHAIN, &ctx, bytes)
        );
    }

    /// The name is in the content key: the extension picks the parser and
    /// a report that names the file names the file. The same bytes under a
    /// different name are a different extraction.
    #[test]
    fn the_content_key_carries_the_name() {
        let ctx = Ctx::default();
        let bytes = b"the same bytes";
        assert_ne!(
            content_key("a/pack.zip", CHAIN, &ctx, bytes),
            content_key("a/pack.txt", CHAIN, &ctx, bytes)
        );
    }

    /// Different bytes are a different content, whatever the path.
    #[test]
    fn the_content_key_carries_the_bytes() {
        let ctx = Ctx::default();
        assert_ne!(
            content_key("a/pack.zip", CHAIN, &ctx, b"one"),
            content_key("a/pack.zip", CHAIN, &ctx, b"two")
        );
    }

    /// The policy decides the answer: under `Source` the adapter is not
    /// consulted at all, so one file under two policies is two extractions.
    #[test]
    fn a_policy_change_misses() {
        let ctx = Ctx::default();
        let source = memo("a.zip", 10, 5, CHAIN, &ctx, 1)
            .derive()
            .expect("a build stamp is present");
        let render = memo("a.zip", 10, 5, CHAIN, &ctx, 2)
            .derive()
            .expect("a build stamp is present");
        assert_ne!(source, render);
    }

    /// A unit's path is stored relative to the file it came from, and the
    /// file's own path goes back in front of it when it is served.
    #[test]
    fn a_relative_path_round_trips() {
        assert_eq!(relative_of("/x/y/a.zip", "/x/y/a.zip").as_deref(), Some(""));
        assert_eq!(
            relative_of("/x/y/a.zip!inner/m.txt", "/x/y/a.zip").as_deref(),
            Some("!inner/m.txt")
        );
        // A unit of another file is not re-stampable into this one.
        assert_eq!(relative_of("/x/y/other.zip", "/x/y/a.zip"), None);
        assert_eq!(
            relative_of("/x/y/a.zippy", "/x/y/a.zip"),
            None,
            "a path that merely starts with the file's path is not under it"
        );
        assert_eq!(restamp("", "/x/y/a.zip"), "/x/y/a.zip");
        assert_eq!(
            restamp("!inner/m.txt", "/x/y/a.zip"),
            "/x/y/a.zip!inner/m.txt"
        );
    }

    /// A fresh extraction's units already carry the file's own path. They
    /// must not be stamped a second time: the file's path in front of a
    /// path that already holds it is how a member ends up named after a
    /// directory that does not exist.
    #[test]
    fn a_fresh_unit_is_not_stamped_twice() {
        assert_eq!(
            restamp("/x/y/a.zip!inner/m.txt", "/x/y/a.zip"),
            "/x/y/a.zip!inner/m.txt"
        );
        assert_eq!(restamp("/x/y/a.zip", "/x/y/a.zip"), "/x/y/a.zip");
        // A file whose own name carries the `!` the separator reserves.
        assert_eq!(restamp("!x.zip!m.txt", "!x.zip"), "!x.zip!m.txt");
        assert_eq!(restamp("!m.txt", "!x.zip"), "!x.zip!m.txt");
    }

    #[test]
    fn an_adapter_version_bump_misses() {
        let ctx = Ctx::default();
        let bumped: &[(&str, u32)] = &[("zip", 1), ("office", 4)];
        assert_ne!(
            key("a.zip", 10, 5, CHAIN, &ctx),
            key("a.zip", 10, 5, bumped, &ctx)
        );
    }

    #[test]
    fn an_added_or_reordered_adapter_misses() {
        let ctx = Ctx::default();
        let longer: &[(&str, u32)] = &[("zip", 1), ("office", 3), ("inspect", 1)];
        let swapped: &[(&str, u32)] = &[("office", 3), ("zip", 1)];
        let base = key("a.zip", 10, 5, CHAIN, &ctx);
        assert_ne!(base, key("a.zip", 10, 5, longer, &ctx));
        assert_ne!(base, key("a.zip", 10, 5, swapped, &ctx));
    }

    #[test]
    fn every_extraction_flag_misses() {
        let base = Ctx::default();
        let b = key("a.zip", 10, 5, CHAIN, &base);
        for ctx in [
            Ctx {
                max_depth: 1,
                ..Ctx::default()
            },
            Ctx {
                max_members: 8,
                ..Ctx::default()
            },
            Ctx {
                max_file_size: 42,
                ..Ctx::default()
            },
        ] {
            assert_ne!(b, key("a.zip", 10, 5, CHAIN, &ctx));
        }
    }

    #[test]
    fn a_new_build_misses() {
        let ctx = Ctx::default();
        let mut k = Key {
            path: "a.zip",
            size: 10,
            mtime: stamp(5),
            chain: CHAIN,
            ctx: &ctx,
            build: Some(BuildStamp {
                len: 900,
                mtime_nanos: 42,
            }),
            policy: 1,
        };
        let first = k.derive().unwrap();
        k.build = Some(BuildStamp {
            len: 901,
            mtime_nanos: 42,
        });
        assert_ne!(first, k.derive().unwrap());
        k.build = Some(BuildStamp {
            len: 900,
            mtime_nanos: 43,
        });
        assert_ne!(first, k.derive().unwrap());
        k.build = None;
        assert!(k.derive().is_none(), "no build identity, no key, no cache");
    }

    #[test]
    fn an_unmemoisable_adapter_stops_the_chain() {
        // soffice and the OCR reader consult a binary and a model file; the
        // key cannot see either change, so they are never memoised
        assert_eq!(None, version_of("soffice"));
        assert_eq!(None, version_of("ocr"));
        assert_eq!(None, version_of("ocrs"));
        assert!(version_of("zip").is_some());
        assert!(version_of("pdf").is_some());
    }

    #[test]
    fn entries_round_trip() {
        let founds = vec![
            Found {
                path: "a.zip!inner.txt".into(),
                bytes: b"one\ntwo\n".to_vec(),
                via: "zip",
            },
            Found {
                path: "b.pdf".into(),
                bytes: vec![0u8, 1, 2, 255],
                via: "pdf",
            },
        ];
        let back = decode(&encode(&founds)).expect("round trip");
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].path, "a.zip!inner.txt");
        assert_eq!(back[0].bytes, b"one\ntwo\n".to_vec());
        assert_eq!(back[0].via, "zip");
        assert_eq!(back[1].bytes, vec![0u8, 1, 2, 255]);
    }

    #[test]
    fn a_damaged_entry_is_a_miss_not_a_wrong_answer() {
        let raw = encode(&[Found {
            path: "a".into(),
            bytes: b"payload".to_vec(),
            via: "zip",
        }]);
        for cut in [0, 4, 12, 20, raw.len() - 1] {
            assert!(decode(&raw[..cut]).is_none(), "truncated at {cut}");
        }
        assert!(decode(&[b'X'; 64]).is_none(), "not an entry at all");
        let mut retagged = raw.clone();
        retagged[0] = b'Z';
        assert!(
            decode(&retagged).is_none(),
            "a different tag is not this format"
        );
        let mut bumped = raw.clone();
        bumped[8] = 9; // a format version this build does not know
        assert!(
            decode(&bumped).is_none(),
            "an unknown format version is not read"
        );
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rgx-cache-test-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        // a directory left by a run that panicked would otherwise answer
        // this one's assertions
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Bytes that LZ4 cannot shrink. A simple `xorshift` seeded from
    /// the byte index produces a deterministic stream that misses the
    /// LZ4 dictionary window: every output byte is independent of its
    /// neighbours, so the compressor pays the worst-case overhead.
    fn pseudo_random_bytes(n: usize) -> Vec<u8> {
        let mut state: u32 = 0x9e37_79b9;
        (0..n)
            .map(|i| {
                state ^= (i as u32).wrapping_mul(0x85eb_ca6b);
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    }

    fn store(dir: &Path, key: &str, founds: &[Found]) {
        let c = Cache::open(dir.to_path_buf());
        c.write(&c.content_path(key), &encode(founds)).unwrap();
    }

    fn present(dir: &Path) -> usize {
        let mut files = Vec::new();
        entries(dir, &mut files, &mut 0);
        files.len()
    }

    #[test]
    fn a_write_leaves_no_temporary_behind() {
        let dir = temp_dir("write");
        let founds = vec![Found {
            path: "a".into(),
            bytes: b"x".to_vec(),
            via: "zip",
        }];
        store(&dir, &"a".repeat(64), &founds);
        assert!(dir.join("tmp").read_dir().unwrap().next().is_none());
        // and a second write of the same key is a no-op, not a duplicate
        store(&dir, &"a".repeat(64), &founds);
        assert_eq!(1, present(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_keeps_fresh_entries_and_drops_old_ones() {
        let dir = temp_dir("age");
        let founds = vec![Found {
            path: "a".into(),
            bytes: vec![b'x'; 512],
            via: "zip",
        }];
        let day = 86_400u64;
        for (i, age) in [(0, 0), (1, 5), (2, 90)] {
            let path = dir.join(format!("{i:02}")).join("e.ext");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, encode_at(&founds, now_secs() - age * day, None)).unwrap();
        }
        let (removed, freed) = prune(&dir, Duration::from_secs(30 * day), MAX_BYTES).unwrap();
        assert_eq!(1, removed, "only the 90-day-old entry goes");
        assert!(freed > 0);
        assert_eq!(2, present(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_drops_the_oldest_first_when_over_budget() {
        let dir = temp_dir("budget");
        let founds = vec![Found {
            path: "a".into(),
            bytes: vec![b'x'; 1024],
            via: "zip",
        }];
        let mut entry_size = 0;
        let t0 = now_secs();
        // the four entries are an hour apart, oldest first
        for (i, age) in [(0, 600u64), (1, 540), (2, 480), (3, 420)] {
            let path = dir.join(format!("{i:02}")).join("e.ext");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, encode_at(&founds, t0 - age, None)).unwrap();
            entry_size = std::fs::metadata(&path).unwrap().len();
        }
        let (removed, _) = prune(&dir, Duration::from_secs(86_400), entry_size * 2).unwrap();
        assert_eq!(2, removed, "the two oldest go to fit the budget");
        let mut files = Vec::new();
        entries(&dir, &mut files, &mut 0);
        let mut left: Vec<_> = files.iter().map(|p| stamp_of(p).unwrap()).collect();
        left.sort_unstable();
        let mut expected = vec![t0 - 480, t0 - 420];
        expected.sort_unstable();
        assert_eq!(expected, left, "the newest survive");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_live_temporary_is_not_mistaken_for_an_old_entry() {
        let dir = temp_dir("temp");
        let path = dir.join("tmp").join("half-written");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // a temporary never gets the header, so its age is its mtime: now
        std::fs::write(&path, b"half").unwrap();
        let (removed, _) = prune(&dir, Duration::from_secs(86_400), MAX_BYTES).unwrap();
        assert_eq!(0, removed);
        assert!(path.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_put_evicts_the_oldest_when_it_would_overshoot_the_cap() {
        let dir = temp_dir("evict");
        // Random bytes do not compress (LZ4 falls back to roughly
        // input-size + overhead), so the on-disk footprint of each
        // entry matches the uncompressed size plus a few bytes. A cap
        // sized just under two entries forces the second to evict the
        // first. Plain `vec![b'x'; 64]` collapses to ~20 bytes under
        // LZ4 and would defeat this test.
        let founds = vec![Found {
            path: "a".into(),
            bytes: pseudo_random_bytes(64),
            via: "zip",
        }];
        let cap = 110u64;
        let c = Cache::open(dir.clone()).with_max_bytes(cap);
        c.write(&c.content_path(&"k1".repeat(32)), &encode(&founds))
            .unwrap();
        let after_first = present(&dir);
        assert_eq!(1, after_first);
        // a second write would push the cache past `cap`
        c.write(&c.content_path(&"k2".repeat(32)), &encode(&founds))
            .unwrap();
        assert_eq!(
            1,
            present(&dir),
            "the oldest entry must be evicted to make room"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_put_under_the_cap_does_not_evict() {
        let dir = temp_dir("noevict");
        let founds = vec![Found {
            path: "a".into(),
            bytes: vec![b'x'; 32],
            via: "zip",
        }];
        let cap = 8 * 1024u64;
        let c = Cache::open(dir.clone()).with_max_bytes(cap);
        for i in 0..4 {
            c.write(
                &c.content_path(&format!("k{i}").repeat(32)),
                &encode(&founds),
            )
            .unwrap();
        }
        assert_eq!(4, present(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clear_empties_the_directory() {
        let dir = temp_dir("clear");
        // Random bytes: LZ4 can't shrink them, so the freed total is
        // strictly the sum of the file sizes. A highly-compressible
        // payload (e.g. `vec![b'x'; 64]`) compresses to ~20 bytes under
        // LZ4 and would not satisfy a `>= 3 * 64` assertion.
        let founds = vec![Found {
            path: "a".into(),
            bytes: pseudo_random_bytes(64),
            via: "zip",
        }];
        for i in 0..3 {
            store(&dir, &format!("{i}").repeat(64), &founds);
        }
        let (removed, freed) = clear(&dir).unwrap();
        assert_eq!(3, removed);
        assert!(freed >= 3 * 64);
        assert_eq!(0, present(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_compressible_payload_round_trips_and_shrinks_on_disk() {
        let dir = temp_dir("compress");
        // A body of repeated text compresses ~10x under LZ4. The cache
        // file on disk should therefore be much smaller than the
        // uncompressed equivalent, and decoding must return the same
        // bytes that were stored.
        let big = vec![b'a'; 16 * 1024];
        let founds = vec![Found {
            path: "doc.txt".into(),
            bytes: big.clone(),
            via: "pdf",
        }];
        let key = "k".repeat(64);
        let c = Cache::open(dir.clone());
        c.write(&c.content_path(&key), &encode(&founds)).unwrap();
        let on_disk = std::fs::metadata(c.content_path(&key)).unwrap().len();
        assert!(
            on_disk < (big.len() as u64) / 4,
            "expected LZ4 to shrink a 16 KiB body to < 4 KiB, got {on_disk}"
        );
        let got = c.content(&key).expect("round-trip read should hit");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].path, "doc.txt");
        assert_eq!(got[0].bytes, big);
        assert_eq!(got[0].via, "pdf");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_reader_never_sees_a_half_written_entry() {
        let dir = temp_dir("atomic");
        let key = "d".repeat(64);
        // large enough that the write is a sequence of syscalls a reader can
        // land inside
        let founds: Vec<Found> = (0..4)
            .map(|i| Found {
                path: format!("big{i}"),
                bytes: vec![b'x'; 8 << 20],
                via: "zip",
            })
            .collect();
        let whole = encode(&founds).len();
        let writer = std::thread::spawn({
            let dir = dir.clone();
            let key = key.clone();
            move || {
                let c = Cache::open(dir);
                c.write(&c.content_path(&key), &encode(&founds)).unwrap();
            }
        });
        let mut shortest = usize::MAX;
        while !writer.is_finished() {
            if let Ok(meta) = std::fs::metadata(Cache::open(dir.clone()).content_path(&key)) {
                shortest = shortest.min(meta.len() as usize);
            }
            std::thread::yield_now();
        }
        writer.join().unwrap();
        assert_eq!(
            whole,
            std::fs::metadata(Cache::open(dir.clone()).content_path(&key))
                .unwrap()
                .len() as usize
        );
        assert!(
            shortest == usize::MAX || shortest == whole,
            "a reader saw a partial entry"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_hit_returns_exactly_what_was_stored() {
        let dir = temp_dir("hit");
        let key = "b".repeat(64);
        let founds = vec![Found {
            path: "a.zip!m.txt".into(),
            bytes: b"needle here\n".to_vec(),
            via: "zip",
        }];
        store(&dir, &key, &founds);
        let c = Cache::open(dir.to_path_buf());
        let back = c.content(&key).expect("stored entry is readable");
        assert_eq!(back[0].path, "a.zip!m.txt");
        assert_eq!(back[0].bytes, b"needle here\n".to_vec());
        assert_eq!(back[0].via, "zip");
        assert!(c.content(&"c".repeat(64)).is_none(), "an absent key misses");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An alias points at a content entry, and an alias that points at
    /// nothing is a miss rather than a pointer to nowhere.
    #[test]
    fn an_alias_round_trips_and_a_damaged_one_misses() {
        let dir = temp_dir("alias");
        let c = Cache::open(dir.to_path_buf());
        let key = "e".repeat(64);
        let content = "f".repeat(64);
        assert!(c.alias(&key).is_none(), "an absent alias misses");
        c.put_alias(&key, &content);
        assert_eq!(c.alias(&key).as_deref(), Some(content.as_str()));
        // a damaged alias is a miss, not a wrong answer
        std::fs::write(c.alias_path(&key), b"not an alias").unwrap();
        assert!(c.alias(&key).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
