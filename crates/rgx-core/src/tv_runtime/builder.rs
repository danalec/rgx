// SPDX-License-Identifier: Apache-2.0

//! Aggregated pack builder and ingestion engine.
//!
//! Converts raw directory trees into contiguous, verified `.tvp` packs and
//! an atomically published `manifest.tvm`.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::time::{Instant, UNIX_EPOCH};

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use ignore::overrides::OverrideBuilder;
use ignore::{Walk, WalkBuilder};
use std::eprintln;

use crate::compress::crc32::crc32;

use super::format::{FileRecord, Manifest, PackHeader, PackRecord, DEFAULT_PACK_SIZE};

/// Configuration options for building aggregated packs.
#[derive(Debug, Clone)]
pub struct BuildConfig {
    pub target_pack_size: u64,
    pub follow_symlinks: bool,
    /// Search hidden files, which is what rgx's `--hidden` means. The
    /// opposite of `ignore::WalkBuilder::hidden`, which reads `true` as
    /// "skip them" -- the walkers translate.
    pub hidden: bool,
    pub gitignore: bool,
    /// `--no-ignore` reaches the ignore files of the directories ABOVE the
    /// search root, which `ignore` honours by default. rgx's direct walker
    /// binds both to the same flag, so the store has to as well.
    pub parents: bool,
    /// `--max-depth`. The direct walker applies it; a build that did not
    /// would ingest the whole tree under a flag that says otherwise.
    pub max_depth: Option<usize>,
    /// `-g` globs, gitignore-style: a pattern that does not start with `!`
    /// excludes, and one that does is a whitelist.
    pub globs: Vec<String>,
    /// Compact the store after a successful update, reclaiming the payloads
    /// that append-only updates supersede.
    ///
    /// Off by default: compaction rewrites every live payload, which is real
    /// work, and a store that is updated rarely does not need it on every pass.
    /// Like `target_pack_size` this is maintenance policy, not a statement
    /// about which files belong to the corpus, so it is deliberately **not**
    /// part of [`fingerprint`](Self::fingerprint).
    pub compact_after_update: bool,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            target_pack_size: DEFAULT_PACK_SIZE,
            follow_symlinks: false,
            hidden: false,
            gitignore: true,
            parents: true,
            max_depth: None,
            globs: Vec::new(),
            compact_after_update: false,
        }
    }
}

impl BuildConfig {
    /// A hash of everything that decides *which files belong to this corpus*,
    /// and deliberately not of `target_pack_size`, which decides only how they
    /// are cut up.
    ///
    /// It is written into the manifest so an update cannot quietly answer a
    /// different question than the build did. A store built with `-g '*.rs'`
    /// and updated without the glob walks a wider tree, does not see the
    /// `.md` files, and concludes they were deleted — tombstones the whole
    /// filtered corpus in one pass.
    pub fn fingerprint(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut eat = |b: &[u8]| {
            for &x in b {
                h ^= x as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        };
        for f in [
            self.hidden,
            self.gitignore,
            self.parents,
            self.follow_symlinks,
        ] {
            eat(&[f as u8]);
        }
        match self.max_depth {
            None => eat(&[0]),
            Some(d) => {
                eat(&[1]);
                eat(&d.to_le_bytes());
            }
        }
        eat(&(self.globs.len() as u32).to_le_bytes());
        for g in &self.globs {
            eat(g.as_bytes());
            eat(&[0xff]);
        }
        h
    }
}

/// Statistics reported after building a corpus pack store.
#[derive(Debug, Clone)]
pub struct BuildStats {
    pub total_files: usize,
    pub total_packs: usize,
    pub total_bytes_ingested: u64,
    pub total_pack_bytes: u64,
    pub elapsed_ms: f64,
}

/// Builds the one walker both the initial build and the incremental update
/// walk with.
///
/// `hidden` is translated rather than passed: `BuildConfig::hidden` means
/// *search* hidden files, `WalkBuilder::hidden` means *skip* them.
pub fn walk_root(root: &Path, store: &Path, config: &BuildConfig) -> io::Result<Walk> {
    let mut builder = WalkBuilder::new(root);
    builder
        .follow_links(config.follow_symlinks)
        .hidden(!config.hidden)
        .git_ignore(config.gitignore)
        .git_global(config.gitignore)
        .git_exclude(config.gitignore)
        .parents(config.parents)
        .max_depth(config.max_depth);

    // Never descend into the store. The walker starts at the canonicalised
    // root, so the store's canonical path is exactly what it would yield for
    // that directory.
    //
    // The repository's own state is skipped here too, and for the same
    // reason the direct walker skips it: it is metadata about the corpus,
    // not the corpus. A `.gitignore` is a file and is still read.
    let store_dir_to_prune = store.to_path_buf();
    builder.filter_entry(move |e| {
        if e.path() == store_dir_to_prune {
            return false;
        }
        let is_vcs = e.file_type().is_some_and(|t| t.is_dir())
            && e.file_name()
                .to_str()
                .is_some_and(crate::walk_policy::is_vcs_dir);
        !is_vcs
    });

    if !config.globs.is_empty() {
        let mut ob = OverrideBuilder::new(".");
        for g in &config.globs {
            ob.add(g).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("rgx-tv: invalid glob '{}': {}", g, e),
                )
            })?;
        }
        builder.overrides(ob.build().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("rgx-tv: invalid glob set: {}", e),
            )
        })?);
    }

    Ok(builder.build())
}

pub type PreExtractor = dyn Fn(&str, &[u8]) -> Option<Vec<(String, Vec<u8>)>> + Send + Sync;

/// The texts a searcher may see for a record *in addition to* the record's
/// own bytes: every unit and `[rgx: ...]` note [`crate::process`] hands the
/// search after the adapter pipeline runs. The stored signature is rolled up
/// over these so a filter may reject an adapter-claimed file before its bytes
/// are read. Returning too little loses matches, returning more (the raw
/// bytes included) only costs prunes, so the hook mirrors the extraction
/// hook's answer -- `Some(units)` when the pipeline answers for the file,
/// flattened to bytes -- and one closure can serve both roles without the
/// two disagreeing about what a file contains.
pub type UnitSigner = dyn Fn(&str, &[u8]) -> Vec<Vec<u8>> + Send + Sync;

/// The separators a member record's name can carry.
///
/// `!` is the separator the runtime path uses between a container and its
/// member (`a.zip!member.txt`); `#` is the shape [`member_rel`] falls back
/// to when a member's name does not already start with its container's;
/// `/` is the path separator, which a member's own name can hold
/// (`a.zip!docs/report.pdf`).
///
/// Every place that reads a record name back has to know all three: a
/// prefix cut at the wrong separator names a path that does not exist, and
/// a member whose owner cannot be found is a record whose answer is
/// thrown away.
pub const MEMBER_SEPARATORS: [char; 3] = ['/', '#', '!'];

/// A member record's catalog name: the container's path with the member's
/// appended, or `container#member` when the member name does not already
/// start with the container's. The update path splits a record name on these
/// prefixes to find the records one container owns; keep the two in step.
pub fn member_rel(rel_path: &str, member_name: &str) -> String {
    if member_name.is_empty() {
        rel_path.to_string()
    } else if member_name.starts_with(rel_path) {
        member_name.to_string()
    } else {
        format!("{}#{}", rel_path, member_name)
    }
}

/// The signature stored on one record and whether it is the adapter rollup.
///
/// [`crate::ngram::build_stored_sig512`] over the record's own bytes, OR'd
/// with the same over every extra unit the signer names. The OR is what
/// [`crate::tv::format::FileLoc::SIG_COVERS_ADAPTER`] promises: any single
/// text holding the needle carries all the pattern's bits in its own
/// signature, so the union carries them too and only a file no text holds
/// the needle in is pruned. With no signer the signature covers the bytes
/// alone and the flag stays clear, which is the signal for a search that
/// runs the adapter pipeline to stand its filter down on the record.
pub(crate) fn record_sig(signer: Option<&UnitSigner>, rel: &str, bytes: &[u8]) -> ([u64; 8], bool) {
    let mut words = crate::ngram::build_stored_sig512(bytes).into_words();
    if let Some(signer) = signer {
        for unit in signer(rel, bytes) {
            let unit_words = crate::ngram::build_stored_sig512(&unit).into_words();
            for (w, uw) in words.iter_mut().zip(unit_words.iter()) {
                *w |= uw;
            }
        }
    }
    (words, signer.is_some())
}

/// Builds aggregated packs from `root_dir` into `store_dir`.
pub fn build_store(
    root_dir: &Path,
    store_dir: &Path,
    config: &BuildConfig,
) -> io::Result<BuildStats> {
    build_store_with_extractor(root_dir, store_dir, config, None, None, 0)
}

/// Builds aggregated packs with optional prepare-stage adapter extraction
/// and adapter rollup signing.
///
/// `extractor` stores a claimed file's units as records of their own;
/// `signer` names the units every record's `ngram` must additionally cover
/// (a signer-only build keeps one record per file and still signs for the
/// pipeline its queries will run). `extract_fp` is the fingerprint of the
/// extraction context both hooks ran under, stamped into the manifest head
/// so a query can tell whether the rollups describe *its* pipeline.
pub fn build_store_with_extractor(
    root_dir: &Path,
    store_dir: &Path,
    config: &BuildConfig,
    extractor: Option<&PreExtractor>,
    signer: Option<&UnitSigner>,
    extract_fp: u64,
) -> io::Result<BuildStats> {
    let t0 = Instant::now();
    fs::create_dir_all(store_dir)?;

    let canon_root = root_dir.canonicalize()?;
    let canon_store = store_dir.canonicalize()?;

    let mut manifest = Manifest::with_corpus_at(
        canon_root.to_string_lossy().to_string(),
        1,
        config.fingerprint(),
        super::format::now_secs(),
    );
    manifest.extract_fp = extract_fp;

    let walker = walk_root(&canon_root, &canon_store, config)?;

    let mut current_pack_id: u32 = 1;
    let mut current_pack_files: Vec<FileRecord> = Vec::new();
    let mut current_pack_payload: Vec<u8> = Vec::new();
    let mut total_files = 0usize;
    let mut total_bytes = 0u64;

    let flush_pack = |pack_id: u32,
                      payload: &mut Vec<u8>,
                      files: &mut Vec<FileRecord>,
                      manifest: &mut Manifest,
                      store_dir: &Path|
     -> io::Result<()> {
        if files.is_empty() && payload.is_empty() {
            return Ok(());
        }
        let filename = format!("pack_{:05}.tvp", pack_id);
        let pack_path = store_dir.join(&filename);

        let content_len = payload.len() as u64;
        let content_crc = crc32(payload);

        let header = PackHeader::new(pack_id, files.len() as u32, content_len, content_crc);

        let mut head = Vec::with_capacity(PackHeader::SIZE);
        header.extend(&mut head);
        let mut file = File::create(&pack_path)?;
        file.write_all(&head)?;
        file.write_all(payload)?;
        file.sync_all()?;

        manifest.packs.push(PackRecord {
            pack_id,
            filename,
            file_count: files.len() as u32,
            content_len,
            content_crc32: content_crc,
        });

        manifest.files.append(files);
        payload.clear();
        Ok(())
    };

    let mut file_id_counter: u64 = 1;

    for result in walker {
        let entry = match result {
            Ok(e) => e,
            Err(err) => {
                eprintln!("rgx-tv: warning: {}", err);
                continue;
            }
        };

        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        // The store is not ingested into itself: the builder prunes the
        // store's directory, so nothing under it is ever yielded.

        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        let file_len = metadata.len();
        let (mtime_secs, mtime_nanos) = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| (d.as_secs(), d.subsec_nanos()))
            .unwrap_or((0, 0));

        let rel_path = match path.strip_prefix(&canon_root) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => path.to_string_lossy().to_string(),
        };

        // Handle 0-byte files: no payload in pack
        if file_len == 0 {
            manifest.files.push(FileRecord {
                file_id: file_id_counter,
                rel_path,
                pack_id: 0,
                offset: 0,
                length: 0,
                mtime_secs,
                mtime_nanos,
                crc32: 0,
                is_empty: true,
                is_deleted: false,
                is_binary: false,
                // No bytes to sign. Zero is "unknown", not "empty", and
                // unknown never rejects -- an empty file still matches a
                // pattern that can match nothing (`x*`). An empty record
                // never reaches a searcher's n-gram filter either (it is
                // searched as empty text), so it does not claim a rollup.
                sig_covers_adapter: false,
                ngram: [0; 8],
            });
            file_id_counter += 1;
            total_files += 1;
            continue;
        }

        let content = match fs::read(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("rgx-tv: warning: cannot read {}: {}", path.display(), e);
                continue;
            }
        };

        let file_crc = crc32(&content);
        // The binary test is the one the searchers apply, over the whole
        // file. A kilobyte head used to be the answer here, and it was
        // a different question: a file holding a NUL at byte 4,000 has no
        // NUL in its first kilobyte, so the build ingested it as text and
        // the pack answered for it while `rg` and `rgx` both suppressed
        // it. UTF-16LE is half NUL bytes from its first one, so the mark
        // has to be decoded first and the decoded NUL is the code unit
        // U+0000. `is_binary` is that rule over everything, and it costs
        // one `memchr` per unmarked file.
        let is_binary = crate::encoding::is_binary(&content);

        if let Some(ext) = extractor {
            if let Some(members) = ext(&rel_path, &content) {
                for (member_name, member_bytes) in members {
                    if member_bytes.is_empty() {
                        continue;
                    }
                    let m_len = member_bytes.len() as u64;
                    let m_crc = crc32(&member_bytes);
                    let m_binary = crate::encoding::is_binary(&member_bytes);
                    let m_rel = member_rel(&rel_path, &member_name);
                    if !current_pack_payload.is_empty()
                        && (current_pack_payload.len() as u64 + m_len > config.target_pack_size)
                    {
                        flush_pack(
                            current_pack_id,
                            &mut current_pack_payload,
                            &mut current_pack_files,
                            &mut manifest,
                            store_dir,
                        )?;
                        current_pack_id += 1;
                    }
                    let offset = current_pack_payload.len() as u64;
                    current_pack_payload.extend_from_slice(&member_bytes);
                    let (m_ngram, m_rollup) = record_sig(signer, &m_rel, &member_bytes);
                    current_pack_files.push(FileRecord {
                        file_id: file_id_counter,
                        rel_path: m_rel,
                        pack_id: current_pack_id,
                        offset,
                        length: m_len,
                        mtime_secs,
                        mtime_nanos,
                        crc32: m_crc,
                        is_empty: false,
                        is_deleted: false,
                        is_binary: m_binary,
                        sig_covers_adapter: m_rollup,
                        ngram: m_ngram,
                    });
                    file_id_counter += 1;
                    total_files += 1;
                    total_bytes += m_len;
                    if m_len >= config.target_pack_size {
                        flush_pack(
                            current_pack_id,
                            &mut current_pack_payload,
                            &mut current_pack_files,
                            &mut manifest,
                            store_dir,
                        )?;
                        current_pack_id += 1;
                    }
                }
                continue;
            }
        }

        // Check if current pack would overflow
        if !current_pack_payload.is_empty()
            && (current_pack_payload.len() as u64 + file_len > config.target_pack_size)
        {
            flush_pack(
                current_pack_id,
                &mut current_pack_payload,
                &mut current_pack_files,
                &mut manifest,
                store_dir,
            )?;
            current_pack_id += 1;
        }

        let offset = current_pack_payload.len() as u64;
        current_pack_payload.extend_from_slice(&content);

        let (ngram, rollup) = record_sig(signer, &rel_path, &content);
        current_pack_files.push(FileRecord {
            file_id: file_id_counter,
            rel_path,
            pack_id: current_pack_id,
            offset,
            length: file_len,
            mtime_secs,
            mtime_nanos,
            crc32: file_crc,
            is_empty: false,
            is_deleted: false,
            is_binary,
            sig_covers_adapter: rollup,
            ngram,
        });

        file_id_counter += 1;
        total_files += 1;
        total_bytes += file_len;

        // If a single file exceeds target_pack_size, flush it immediately as dedicated pack
        if file_len >= config.target_pack_size {
            flush_pack(
                current_pack_id,
                &mut current_pack_payload,
                &mut current_pack_files,
                &mut manifest,
                store_dir,
            )?;
            current_pack_id += 1;
        }
    }

    // Flush any remaining files
    flush_pack(
        current_pack_id,
        &mut current_pack_payload,
        &mut current_pack_files,
        &mut manifest,
        store_dir,
    )?;

    // Publish manifest atomically
    super::format::publish_atomic(&manifest, store_dir)?;

    let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
    let total_pack_bytes: u64 = manifest
        .packs
        .iter()
        .map(|p| p.content_len + PackHeader::SIZE as u64)
        .sum();

    Ok(BuildStats {
        total_files,
        total_packs: manifest.packs.len(),
        total_bytes_ingested: total_bytes,
        total_pack_bytes,
        elapsed_ms: elapsed,
    })
}

/// What the build/update operation did.
///
/// `Built` for a fresh store, `Updated` when the store already had a
/// manifest and the new generation was republished with the diff. A
/// caller that wants to print both legs (build counters plus update
/// counters) keys the match arm on this, not on which branch ran.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoreAction {
    Built,
    Updated,
}

/// Build a fresh store or update an existing one, depending on whether
/// `store_dir/manifest.tvm` already exists.
///
/// The extractor and signer (if any) are forwarded to both the build and
/// the update paths -- an update that re-extracted through a different hook
/// than the build signed through would roll its changed files up over units
/// the catalog's `extract_fp` does not describe -- and `build_store` calls
/// `build_store_with_extractor` with `None, None, 0` when neither was given.
pub fn build_or_update_store_with_extractor(
    root_dir: &Path,
    store_dir: &Path,
    config: &BuildConfig,
    extractor: Option<&PreExtractor>,
    signer: Option<&UnitSigner>,
    extract_fp: u64,
) -> io::Result<(
    StoreAction,
    BuildStats,
    Option<crate::tv_runtime::update::UpdateStats>,
)> {
    use crate::tv_runtime::update::update_store_with;
    if store_dir.join("manifest.tvm").exists() {
        let u = update_store_with(root_dir, store_dir, config, extractor, signer, extract_fp)?;
        // The update path does not re-run the build counters. Zero the
        // unused fields so a downstream that prints one struct per
        // action sees the same shape.
        let b = BuildStats {
            total_files: 0,
            total_packs: 0,
            total_bytes_ingested: 0,
            total_pack_bytes: 0,
            elapsed_ms: 0.0,
        };
        Ok((StoreAction::Updated, b, Some(u)))
    } else {
        let b =
            build_store_with_extractor(root_dir, store_dir, config, extractor, signer, extract_fp)?;
        Ok((StoreAction::Built, b, None))
    }
}
