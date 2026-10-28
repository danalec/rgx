// SPDX-License-Identifier: Apache-2.0

//! The `std` shell over [`super::format`]: everything there, plus the
//! filesystem.
//!
//! The codec is `no_std` and lives in [`super::format`] (the `tv` module),
//! so that a process can read a pack store without linking the rest of the
//! runtime. What only a `std` process can do -- open a file, rename over
//! one, ask what time it is -- is here, as free functions, because an
//! inherent method cannot be added to a type this crate already exports.
//!
//! `load_raw_manifest` reads the bytes and hands them to
//! `RawManifest::from_bytes`, so there is exactly one parser, and
//! `publish_atomic` encodes once and writes the result twice -- to the
//! temp file and, on success, over the old manifest by rename.

use alloc::string::ToString;
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub use crate::tv::format::{
    FileLoc, FileRecord, Manifest, ManifestHead, PackHeader, PackRecord, RawManifest,
    DEFAULT_PACK_SIZE, FORMAT_VERSION, MANIFEST_MAGIC, MANIFEST_VERSION, PACK_MAGIC,
};

/// Seconds since the epoch, or `0` before it. The manifest's timestamp field
/// is a `u64` of these, and `SystemTime` is the one thing in the format that
/// genuinely needs an operating system.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reads and verifies `store_dir/manifest.tvm`.
pub fn load_manifest(store_dir: &Path) -> io::Result<Manifest> {
    load_raw_manifest(store_dir)?.decode().map_err(to_io)
}

/// Reads `store_dir/manifest.tvm` without decoding it, so pack reads can
/// start while the coordinator is still turning file records into a plan.
pub fn load_raw_manifest(store_dir: &Path) -> io::Result<RawManifest> {
    let mut f = File::open(store_dir.join("manifest.tvm"))?;
    let len = f.metadata()?.len() as usize;
    let mut bytes = vec![0u8; len];
    f.read_exact(&mut bytes)?;
    RawManifest::from_bytes(bytes).map_err(to_io)
}

/// Atomically publishes a manifest into `store_dir/manifest.tvm`, by
/// write-and-rename: a reader either sees the whole old catalog or the whole
/// new one, never half of either.
pub fn publish_atomic(manifest: &Manifest, store_dir: &Path) -> io::Result<()> {
    let manifest_path = store_dir.join("manifest.tvm");
    let tmp_path = store_dir.join("manifest.tvm.tmp");

    {
        let mut f = File::create(&tmp_path)?;
        f.write_all(&manifest.encode())?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, &manifest_path)?;
    Ok(())
}

/// The 32-byte header at the front of a pack file.
pub fn read_pack_header(f: &mut File) -> io::Result<PackHeader> {
    let mut buf = [0u8; PackHeader::SIZE];
    f.read_exact(&mut buf)?;
    PackHeader::decode(&buf).map_err(to_io)
}

/// The store's own error type carries no I/O kind -- `core::io::Error` is
/// unstable, so a `no_std` codec cannot construct one. Everything that
/// crosses this boundary is bytes that do not parse: a bad magic, a wrong
/// version, a truncated record, a CRC mismatch, a path that is not UTF-8.
/// That is `InvalidData` by definition, and the equivalence test says so
/// on purpose, because a caller deciding whether to rebuild a store wants
/// "this store is corrupt" and not "this store failed".
pub fn to_io(e: crate::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}
