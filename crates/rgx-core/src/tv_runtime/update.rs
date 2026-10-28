// SPDX-License-Identifier: Apache-2.0

//! Incremental update and generation publishing engine for rgx-tv.
//!
//! Compares the live filesystem state against the stored generation, appending
//! modified/added files into new packs and publishing an updated generation atomically.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::time::{Instant, UNIX_EPOCH};

use crate::compress::crc32::crc32;

use super::builder::BuildConfig;
use super::format::{FileRecord, Manifest, PackHeader, PackRecord};

/// Statistics reported after an incremental update.
#[derive(Debug, Clone)]
pub struct UpdateStats {
    pub files_added: usize,
    pub files_modified: usize,
    pub files_deleted: usize,
    pub new_packs_written: usize,
    pub new_bytes_written: u64,
    pub new_generation: u64,
    pub elapsed_ms: f64,
}

/// Incrementally updates `store_dir` against `root_dir`, with no extraction.
/// Every changed file is re-signed over its own bytes only; see
/// [`update_store_with`] for the hooks and the fingerprint.
pub fn update_store(
    root_dir: &Path,
    store_dir: &Path,
    config: &BuildConfig,
) -> io::Result<UpdateStats> {
    update_store_with(root_dir, store_dir, config, None, None, 0)
}

/// Incrementally updates `store_dir` against `root_dir`, extracting and
/// signing through the same hooks the build used.
///
/// `extractor` and `signer` are the build's hooks forwarded -- an update that
/// re-extracted through a different one would roll its changed files up over
/// units the catalog does not describe -- and `extract_fp` is the fingerprint
/// of the context both ran under. A signer carrying a different fingerprint
/// than the manifest head names is refused like a differing `corpus` is: the
/// records of *unchanged* files would keep rollups from the old context while
/// the head swore to the new one, and a filter trusting the head would prune
/// matches the rollups never covered. A signer-less update is safe under any
/// head: its records are signed over their own bytes and flagged accordingly,
/// so a filter stands down on exactly those.
pub fn update_store_with(
    root_dir: &Path,
    store_dir: &Path,
    config: &BuildConfig,
    extractor: Option<&super::builder::PreExtractor>,
    signer: Option<&super::builder::UnitSigner>,
    extract_fp: u64,
) -> io::Result<UpdateStats> {
    let t0 = Instant::now();

    let mut manifest = super::format::load_manifest(store_dir)?;
    let canon_root = root_dir.canonicalize()?;
    let canon_store = store_dir.canonicalize()?;

    // An update that walks a different tree than the build did does not find
    // the files the build excluded, and concludes they were deleted - a
    // tombstone per excluded file, published atomically, not recoverable
    // by rebuilding the packs. Refuse instead.
    let want = config.fingerprint();
    if manifest.corpus != want {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "rgx-tv update: this store was built with a different file selection \
                 (store corpus {:#018x}, this invocation {:#018x}). An update must walk \
                 the same tree the build walked; pass the same --hidden/--no-ignore/\
                 --max-depth/-g/--follow, or rebuild the store from scratch.",
                manifest.corpus, want
            ),
        ));
    }

    if signer.is_some() && manifest.extract_fp != 0 && manifest.extract_fp != extract_fp {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "rgx-tv update: this store's signatures were rolled up under a different \
                 extraction context (store extract_fp {:#018x}, this invocation {:#018x}). \
                 An update re-signs only the files that changed, so the unchanged ones would \
                 keep rollups this head no longer describes; pass the same \
                 --max-filesize/--max-adapter-depth and member-budget environment, or \
                 rebuild the store from scratch.",
                manifest.extract_fp, extract_fp
            ),
        ));
    }
    if signer.is_some() {
        manifest.extract_fp = extract_fp;
    }

    // Every live record, indexed by its catalog name and by each name prefix
    // a container's members hang off (`container!member` and `container#member`
    // are the two shapes `member_rel` writes). Looking a walker path up here
    // finds the records that path owns: a file's own record plus any member
    // records a previous pre-extract build made from it, which is what makes a
    // re-ingested container replace its old members instead of duplicating
    // them and an untouched one keep them instead of being tombstoned for
    // "not in seen_paths" (a member's name is never a walker path).
    let mut owned: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, f) in manifest.files.iter().enumerate() {
        if f.is_deleted {
            continue;
        }
        owned.entry(f.rel_path.clone()).or_default().push(i);
        // Only prefixes from the start of the name: `a.zip!b/c.txt` owns
        // under `a.zip` and `a.zip!b`, never under `b`. A prefix can only be
        // a walker path when it is the record's owner (a path that holds a
        // file holds no directory of the same name), so a changed file
        // tombstones its own records and nothing else's.
        for (p, _) in f.rel_path.match_indices(super::builder::MEMBER_SEPARATORS) {
            owned
                .entry(f.rel_path[..p].to_string())
                .or_default()
                .push(i);
        }
    }

    let mut seen_paths: HashSet<String> = HashSet::new();

    let walker = super::builder::walk_root(&canon_root, &canon_store, config)?;

    let mut next_pack_id = manifest.packs.iter().map(|p| p.pack_id).max().unwrap_or(0) + 1;

    let mut new_pack_files: Vec<FileRecord> = Vec::new();
    let mut new_pack_payload: Vec<u8> = Vec::new();

    let mut files_added = 0usize;
    let mut files_modified = 0usize;
    let mut files_deleted = 0usize;
    let mut new_bytes = 0u64;
    let mut file_id_counter = manifest.files.iter().map(|f| f.file_id).max().unwrap_or(0) + 1;

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

    for result in walker {
        let entry = match result {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        // The store is not ingested into itself: the builder prunes the
        // store's directory.

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

        seen_paths.insert(rel_path.clone());

        // The records this walker path owns: its own from an earlier
        // generation, and any member records a pre-extract build derived
        // from it. All of them describe the file's previous content, so a
        // changed file supersedes the whole set and an unchanged one keeps
        // it whole -- members included.
        let old: Vec<usize> = owned.get(&rel_path).cloned().unwrap_or_default();

        let mut unchanged = false;
        let mut has_exact = false;
        let mut all_mtime = true;
        for &i in &old {
            let r = &manifest.files[i];
            if r.rel_path == rel_path {
                has_exact = true;
            }
            if r.length == file_len && r.mtime_secs == mtime_secs && r.mtime_nanos == mtime_nanos {
                unchanged = true;
            }
            if r.mtime_secs != mtime_secs || r.mtime_nanos != mtime_nanos {
                all_mtime = false;
            }
        }
        // A member record's length is the member's, never the container's,
        // so a pre-extract group can only vouch for its container's mtime.
        // The hole that leaves -- a size change under a restored mtime --
        // is the raw path's own hole widened (there the length pins it),
        // and it is why the fingerprints exist: a record this pass does not
        // re-sign keeps whatever the head already describes.
        if !has_exact && !old.is_empty() && all_mtime {
            unchanged = true;
        }

        if unchanged {
            continue;
        }
        for &i in &old {
            manifest.files[i].is_deleted = true;
        }
        if old.is_empty() {
            files_added += 1;
        } else {
            files_modified += 1;
        }

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
                // never reaches a searcher's n-gram filter (it is searched
                // as empty text), so it does not claim a rollup.
                sig_covers_adapter: false,
                ngram: [0; 8],
            });
            file_id_counter += 1;
            continue;
        }

        let content = match fs::read(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let file_crc = crc32(&content);
        // The same rule the build applies, for the same reason: an update
        // that decides differently from the build it is updating is the
        // two-axes defect this crate keeps running into. A UTF-16LE file
        // -- half NUL bytes from its first one -- used to come back
        // binary from an update and text from a build of the same tree,
        // and a file whose NUL sat at byte 4,000 came back the other way.
        let is_binary = crate::encoding::is_binary(&content);

        // The build's extraction hook, forwarded: a changed container
        // re-derives its member records here exactly as a fresh build
        // would, or the update's answer holds the container's bytes under
        // a name the build never wrote.
        let members = extractor.and_then(|ext| ext(&rel_path, &content));
        let mut placed = false;
        if let Some(members) = members {
            for (member_name, member_bytes) in members {
                if member_bytes.is_empty() {
                    continue;
                }
                let m_len = member_bytes.len() as u64;
                let m_crc = crc32(&member_bytes);
                let m_binary = crate::encoding::is_binary(&member_bytes);
                let m_rel = super::builder::member_rel(&rel_path, &member_name);
                if !new_pack_payload.is_empty()
                    && (new_pack_payload.len() as u64 + m_len > config.target_pack_size)
                {
                    flush_pack(
                        next_pack_id,
                        &mut new_pack_payload,
                        &mut new_pack_files,
                        &mut manifest,
                        store_dir,
                    )?;
                    next_pack_id += 1;
                }
                let offset = new_pack_payload.len() as u64;
                new_pack_payload.extend_from_slice(&member_bytes);
                let (m_ngram, m_rollup) = super::builder::record_sig(signer, &m_rel, &member_bytes);
                new_pack_files.push(FileRecord {
                    file_id: file_id_counter,
                    rel_path: m_rel,
                    pack_id: next_pack_id,
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
                new_bytes += m_len;
                if m_len >= config.target_pack_size {
                    flush_pack(
                        next_pack_id,
                        &mut new_pack_payload,
                        &mut new_pack_files,
                        &mut manifest,
                        store_dir,
                    )?;
                    next_pack_id += 1;
                }
            }
            placed = true;
        }

        if !placed {
            if !new_pack_payload.is_empty()
                && (new_pack_payload.len() as u64 + file_len > config.target_pack_size)
            {
                flush_pack(
                    next_pack_id,
                    &mut new_pack_payload,
                    &mut new_pack_files,
                    &mut manifest,
                    store_dir,
                )?;
                next_pack_id += 1;
            }

            let offset = new_pack_payload.len() as u64;
            new_pack_payload.extend_from_slice(&content);

            let (ngram, rollup) = super::builder::record_sig(signer, &rel_path, &content);
            new_pack_files.push(FileRecord {
                file_id: file_id_counter,
                rel_path,
                pack_id: next_pack_id,
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
            new_bytes += file_len;
        }
    }

    // Detect deleted files. A record whose owner -- its name, or the
    // container prefix its member name hangs off -- is no longer on disk is
    // gone; a member of a live container is not. The old rule (tombstone
    // every record whose own name the walk did not yield) deleted every
    // member record of every container on every pass, changed or not.
    let mut orphans: Vec<usize> = Vec::new();
    for (i, f) in manifest.files.iter().enumerate() {
        if f.is_deleted || seen_paths.contains(&f.rel_path) {
            continue;
        }
        let owned_by_live = f
            .rel_path
            .match_indices(super::builder::MEMBER_SEPARATORS)
            .any(|(p, _)| seen_paths.contains(&f.rel_path[..p]));
        if !owned_by_live {
            orphans.push(i);
        }
    }
    for i in orphans {
        manifest.files[i].is_deleted = true;
        files_deleted += 1;
    }

    let packs_before = manifest.packs.len();
    flush_pack(
        next_pack_id,
        &mut new_pack_payload,
        &mut new_pack_files,
        &mut manifest,
        store_dir,
    )?;
    let new_packs_written = manifest.packs.len() - packs_before;

    // Increment generation
    manifest.generation += 1;
    manifest.timestamp_secs = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Atomically publish updated generation
    super::format::publish_atomic(&manifest, store_dir)?;

    // Reclaim what this append-only pass superseded. Opt-in, and only after
    // the new generation is published: compaction deletes the pack files the
    // old manifest named, and a crash before this point must leave a working
    // store rather than a truncated one.
    if config.compact_after_update {
        let _ = super::compact::compact_store_if_worth_it(store_dir);
    }

    let elapsed = t0.elapsed().as_secs_f64() * 1000.0;

    Ok(UpdateStats {
        files_added,
        files_modified,
        files_deleted,
        new_packs_written,
        new_bytes_written: new_bytes,
        new_generation: manifest.generation,
        elapsed_ms: elapsed,
    })
}

#[cfg(test)]
mod tests {
    //! What an update owes the store it updates: the same hooks, the same
    //! rollups, and a tombstone only for what a walk actually superseded.

    use super::*;
    use crate::tv_runtime::builder::build_store_with_extractor;
    use std::fs;

    /// A stand-in adapter: a `.box` file is a container of `name<TAB>hex`
    /// lines, and each line is a unit named `container/name` holding the
    /// hex-decoded body. The body is encoded so the container's own bytes
    /// never contain a unit's text -- a gzip member's text does not appear
    /// in its compressed stream either, which is the whole reason the raw
    /// signature cannot answer for a container. Everything else is raw. The
    /// unit tests drive the build and update hooks with this instead of a
    /// real registry so the hook plumbing -- forwarding, naming, signing --
    /// is what is under test.
    fn box_units(rel: &str, data: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
        if !rel.ends_with(".box") {
            return None;
        }
        let text = String::from_utf8_lossy(data).into_owned();
        let members: Vec<(String, Vec<u8>)> = text
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .map(|(name, body)| (format!("{rel}/{name}"), unhex(body)))
            .collect();
        if members.is_empty() {
            None
        } else {
            Some(members)
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(s: &str) -> String {
        s.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The signing half of the same hook: the units flattened to bytes,
    /// as `main.rs` wires one closure for both roles.
    fn box_signer(rel: &str, data: &[u8]) -> Vec<Vec<u8>> {
        box_units(rel, data)
            .unwrap_or_default()
            .into_iter()
            .map(|(_, b)| b)
            .collect()
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rgx_update_sigroll_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn live_records(store: &std::path::Path) -> Vec<String> {
        let m = super::super::format::load_manifest(store).unwrap();
        m.files
            .iter()
            .filter(|f| !f.is_deleted)
            .map(|f| f.rel_path.clone())
            .collect()
    }

    /// The signing hook is what puts a container's units into its record's
    /// signature. Without it the raw signature would prune a file whose text
    /// lives in the pipeline's units -- the exact match loss the rollup
    /// exists to prevent.
    #[test]
    fn a_signed_record_covers_the_units_the_pipeline_produces() {
        let root = scratch("sign");
        let store = root.join("store");
        fs::write(
            root.join("a.box"),
            format!("inner\t{}\n", hex("hidden rollup text")),
        )
        .unwrap();
        let cfg = BuildConfig::default();

        build_store_with_extractor(&root, &store, &cfg, None, Some(&box_signer), 0x51).unwrap();
        let m = super::super::format::load_manifest(&store).unwrap();
        assert_eq!(m.extract_fp, 0x51);
        let rec = m.files.iter().find(|f| f.rel_path == "a.box").unwrap();
        assert!(rec.sig_covers_adapter, "a signed record claims the rollup");
        let q = crate::ngram::query_sig512("hidden rollup text", false).expect("literal run");
        assert!(
            crate::ngram::NgramSig512::from_words(rec.ngram).contains_query(&q),
            "the rollup must cover the unit text the pipeline produces"
        );

        // And the unsigned build proves the assertion has teeth: the same
        // record, signed over its own bytes only, does not cover it. Built
        // in its own tree so the first store is not corpus the second one
        // walks into.
        let root2 = scratch("sign2");
        fs::write(
            root2.join("a.box"),
            format!("inner\t{}\n", hex("hidden rollup text")),
        )
        .unwrap();
        let store2 = root2.join("store");
        build_store_with_extractor(&root2, &store2, &cfg, None, None, 0).unwrap();
        let m2 = super::super::format::load_manifest(&store2).unwrap();
        let rec2 = m2.files.iter().find(|f| f.rel_path == "a.box").unwrap();
        assert!(!rec2.sig_covers_adapter);
        assert!(
            !crate::ngram::NgramSig512::from_words(rec2.ngram).contains_query(&q),
            "the raw signature must not claim the unit text"
        );

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&root2);
    }

    /// The extractor is forwarded to the update: a changed container
    /// re-derives its member records through it, old members included in the
    /// tombstone and new ones rolled up through the same signer.
    #[test]
    fn an_update_re_derives_a_changed_containers_members() {
        let root = scratch("changed");
        let store = root.join("store");
        fs::write(
            root.join("a.box"),
            format!("x\t{}\n", hex("first member text")),
        )
        .unwrap();
        let cfg = BuildConfig::default();
        build_store_with_extractor(
            &root,
            &store,
            &cfg,
            Some(&box_units),
            Some(&box_signer),
            0x77,
        )
        .unwrap();
        assert_eq!(live_records(&store), vec!["a.box/x".to_string()]);

        // The second text is not the same length as the first on purpose:
        // the update decides that a file has not changed when its length
        // and its mtime are the ones the manifest holds, and two writes in
        // the same tick of the clock share the mtime. With the two lengths
        // equal, the test was a coin toss on a filesystem whose clock ticks
        // in coarse steps -- and the CI's Windows runner lost it.
        fs::write(
            root.join("a.box"),
            format!("y\t{}\n", hex("the second member text")),
        )
        .unwrap();
        let stats = update_store_with(
            &root,
            &store,
            &cfg,
            Some(&box_units),
            Some(&box_signer),
            0x77,
        )
        .unwrap();
        assert_eq!(stats.files_modified, 1);
        assert_eq!(stats.files_added, 0);

        let m = super::super::format::load_manifest(&store).unwrap();
        assert_eq!(
            m.extract_fp, 0x77,
            "the update keeps the head's fingerprint"
        );
        let live: Vec<&str> = m
            .files
            .iter()
            .filter(|f| !f.is_deleted)
            .map(|f| f.rel_path.as_str())
            .collect();
        assert_eq!(live, vec!["a.box/y"]);
        let rec = m.files.iter().find(|f| f.rel_path == "a.box/y").unwrap();
        assert!(rec.sig_covers_adapter);
        let q = crate::ngram::query_sig512("the second member text", false).expect("literal run");
        assert!(
            crate::ngram::NgramSig512::from_words(rec.ngram).contains_query(&q),
            "the update re-signs through the same signer as the build"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// A member record's name is never a walker path, so the deletion pass
    /// must find its owner and keep it: an update that changes nothing keeps
    /// every record it started with.
    #[test]
    fn an_update_keeps_an_untouched_containers_members() {
        let root = scratch("keep");
        let store = root.join("store");
        fs::write(root.join("a.box"), format!("x\t{}\n", hex("member text"))).unwrap();
        fs::write(root.join("b.txt"), "plain\n").unwrap();
        let cfg = BuildConfig::default();
        build_store_with_extractor(
            &root,
            &store,
            &cfg,
            Some(&box_units),
            Some(&box_signer),
            0x99,
        )
        .unwrap();
        let before = live_records(&store);
        assert_eq!(before.len(), 2);

        let stats = update_store_with(
            &root,
            &store,
            &cfg,
            Some(&box_units),
            Some(&box_signer),
            0x99,
        )
        .unwrap();
        assert_eq!(
            stats.files_added + stats.files_modified + stats.files_deleted,
            0
        );
        assert_eq!(
            live_records(&store),
            before,
            "nothing changed, nothing lost"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// Deleting a container takes its members with it: the owner is gone, so
    /// the records it owned cannot answer for files that do not exist.
    #[test]
    fn a_deleted_container_takes_its_members() {
        let root = scratch("deleted");
        let store = root.join("store");
        fs::write(root.join("a.box"), format!("x\t{}\n", hex("member text"))).unwrap();
        fs::write(root.join("b.txt"), "plain\n").unwrap();
        let cfg = BuildConfig::default();
        build_store_with_extractor(
            &root,
            &store,
            &cfg,
            Some(&box_units),
            Some(&box_signer),
            0x99,
        )
        .unwrap();

        fs::remove_file(root.join("a.box")).unwrap();
        let stats = update_store_with(
            &root,
            &store,
            &cfg,
            Some(&box_units),
            Some(&box_signer),
            0x99,
        )
        .unwrap();
        assert_eq!(stats.files_deleted, 1, "the container, counted once");
        assert_eq!(live_records(&store), vec!["b.txt".to_string()]);

        let _ = fs::remove_dir_all(&root);
    }

    /// An update that signs under a different extraction context than the
    /// head names would leave unchanged records' rollups swearing to one
    /// pipeline and the head to another. Refusing is the only answer that
    /// cannot lose a match to the mismatch.
    #[test]
    fn an_update_under_a_different_extraction_fingerprint_is_refused() {
        let root = scratch("fingerprint");
        let store = root.join("store");
        fs::write(root.join("a.box"), format!("x\t{}\n", hex("member text"))).unwrap();
        let cfg = BuildConfig::default();
        build_store_with_extractor(
            &root,
            &store,
            &cfg,
            Some(&box_units),
            Some(&box_signer),
            0x11,
        )
        .unwrap();

        let err = update_store_with(
            &root,
            &store,
            &cfg,
            Some(&box_units),
            Some(&box_signer),
            0x22,
        )
        .expect_err("a differing fingerprint must refuse");
        assert!(
            err.to_string().contains("extraction context"),
            "the refusal names the mismatch, got: {err}"
        );
        assert_eq!(
            m_generation(&store),
            1,
            "a refused update publishes nothing"
        );

        let _ = fs::remove_dir_all(&root);
    }

    fn m_generation(store: &std::path::Path) -> u64 {
        super::super::format::load_manifest(store)
            .unwrap()
            .generation
    }
}
