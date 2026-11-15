// SPDX-License-Identifier: Apache-2.0

//! Inspection and integrity verification engine for the pack store.
//!
//! Validates CRC32 checksums of manifest and pack files, checking for
//! bit-rot, truncation, or corruption. Gated on the `tv-runtime` feature
//! because the read path uses `std::fs::File`.

use alloc::string::String;
use alloc::vec::Vec;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::compress::crc32::crc32;

/// Results from inspecting an rgx-tv store.
#[derive(Debug, Clone)]
pub struct StoreReport {
    pub generation: u64,
    pub timestamp_secs: u64,
    /// Fingerprint of the walk configuration the build used. An `update` has
    /// to reproduce it exactly; `rgx-tv update --store <dir>` without the same
    /// flags is refused rather than allowed to delete the rest.
    pub corpus: u64,
    pub root_path: String,
    pub total_files: usize,
    pub active_files: usize,
    pub deleted_files: usize,
    pub empty_files: usize,
    pub total_packs: usize,
    pub total_payload_bytes: u64,
    pub corrupted_packs: Vec<(String, String)>,
}

/// Inspects and verifies `store_dir`.
pub fn inspect_store(store_dir: &Path) -> io::Result<StoreReport> {
    let manifest = super::format::load_manifest(store_dir)?;

    let mut active = 0usize;
    let mut deleted = 0usize;
    let mut empty = 0usize;

    for f in &manifest.files {
        if f.is_deleted {
            deleted += 1;
        } else if f.is_empty {
            empty += 1;
            active += 1;
        } else {
            active += 1;
        }
    }

    let mut corrupted = Vec::new();
    let mut total_payload = 0u64;

    for p in &manifest.packs {
        total_payload += p.content_len;
        let pack_path = store_dir.join(&p.filename);
        let mut f = match File::open(&pack_path) {
            Ok(file) => file,
            Err(e) => {
                corrupted.push((p.filename.clone(), format!("cannot open: {e}")));
                continue;
            }
        };

        let header = match super::format::read_pack_header(&mut f) {
            Ok(h) => h,
            Err(e) => {
                corrupted.push((p.filename.clone(), format!("header error: {e}")));
                continue;
            }
        };

        if header.pack_id != p.pack_id {
            corrupted.push((
                p.filename.clone(),
                format!("pack_id mismatch: {} vs {}", header.pack_id, p.pack_id),
            ));
            continue;
        }

        if header.content_len != p.content_len {
            corrupted.push((
                p.filename.clone(),
                format!(
                    "content_len mismatch: {} vs {}",
                    header.content_len, p.content_len
                ),
            ));
            continue;
        }

        let mut payload = vec![0u8; header.content_len as usize];
        if let Err(e) = f.read_exact(&mut payload) {
            corrupted.push((p.filename.clone(), format!("truncated pack: {e}")));
            continue;
        }

        let actual_crc = crc32(&payload);
        if actual_crc != header.content_crc32 {
            corrupted.push((
                p.filename.clone(),
                format!(
                    "crc mismatch: expected {:#x}, got {:#x}",
                    header.content_crc32, actual_crc
                ),
            ));
            continue;
        }
    }

    Ok(StoreReport {
        generation: manifest.generation,
        timestamp_secs: manifest.timestamp_secs,
        corpus: manifest.corpus,
        root_path: manifest.root_path,
        total_files: manifest.files.len(),
        active_files: active,
        deleted_files: deleted,
        empty_files: empty,
        total_packs: manifest.packs.len(),
        total_payload_bytes: total_payload,
        corrupted_packs: corrupted,
    })
}
