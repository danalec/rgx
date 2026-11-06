// SPDX-License-Identifier: Apache-2.0
//
// The framing and the metadata below were learned from borg 1.2's own
// implementation, which is the description of the format that exists; the
// code here is rgx's own. The provenance is recorded in `NOTICE`.

//! A borg repository segment — the file `borg create` writes into `data/`.
//!
//! **What it is.** A borg repository is a directory of segments: `data/0/0`,
//! `data/0/1`, ... Each segment is a sequence of entries, and an entry is
//! either a chunk of a backed-up file or the metadata of one. The segment
//! carries no extension and no name of its own — it is `data/0/2` — so this
//! is the one format rgx reaches by what it IS rather than by what it is
//! called.
//!
//! **Where the layout comes from.** Every position below follows borg 1.2's
//! own source — `src/borg/repository.py` for the segment framing,
//! `src/borg/crypto/key.py` for the payload envelope, `src/borg/compress.pyx`
//! for the compressor tags, `src/borg/item.pyx` for the item metadata — and
//! not a description of it, because the framing is exactly the place
//! where a reader can be nearly right and still desync on the second entry.
//!
//! **The four things that are load-bearing.**
//!
//! 1. *The entry header is a CRC, a size and a tag, and the size counts the
//!    WHOLE entry.* A PUT entry is `crc(4) | size(4) | tag(1) | id(32) | data`,
//!    and `size` is the length of that whole thing, the CRC included, so the
//!    entry is `size` bytes long and the entries tile the file exactly. A
//!    COMMIT entry is `crc(4) | size(4) | tag(1)` and nothing else, and its
//!    size is 9. The CRC covers the size and the tag, then the id, then the
//!    data, in that order — it does not cover itself.
//! 2. *The payload carries an envelope.* One byte says which key the
//!    repository uses, and for a repository without encryption — or with
//!    borg's "authenticated" mode, which signs without encrypting — the
//!    next two bytes name the compressor and the rest is the compressed
//!    body. For an encrypted repository the rest is a MAC and a ciphertext,
//!    and no amount of reading gets at it.
//! 3. *A chunk's id IS the entry's id.* The 32 bytes after the tag are the
//!    id of the object the entry carries, so the chunks of a file can be
//!    found by id without reading the index, and the item metadata names
//!    the chunks it is made of.
//! 4. *An item's metadata is a sequence of maps, not one map.* The first is
//!    the "safe" metadata of the archive's top item — the path and the
//!    times, the part a server may read without the key — and the rest are
//!    the full items, each with its size and its chunk list. A reader that
//!    decodes one map and stops reports the directory and nothing else.
//!
//! **What is refused rather than guessed.** A file that does not start with
//! `BORG_SEG` is not a segment and is declined, so a segment of some other
//! tool falls through untouched. A compressor this reader does not have is
//! refused by name. An encrypted repository is not refused as a file — its
//! structure is still readable — but its contents are not guessed at: the
//! key is the one thing a search tool may not ask for.
//!
//! **What a single segment can and cannot say.** A segment is one file, and
//! a backup is many: the items of an archive and the chunks of a file larger
//! than one segment live in different segments. This reader reports what
//! the segment it was handed holds, and says which chunks and which items
//! are elsewhere rather than pretending the repository is one file.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use rgx_core::compress::crc32::crc32_update;
use rgx_core::compress::lzma::LzmaDecoder;
use rgx_core::compress::{ZlibDecoder, ZstdDecoder};
use rgx_core::{bail, decline, Adapter, Outcome, Result};

use crate::budget;
use crate::lz4::Lz4Decoder;
use crate::msgpack::{Decoder as Msgpack, Value};

/// The eight bytes every borg segment starts with.
const MAGIC: &[u8; 8] = b"BORG_SEG";

/// The entry tags, from `borg/repository.py`.
const TAG_PUT: u8 = 0;
const TAG_DELETE: u8 = 1;
const TAG_COMMIT: u8 = 2;

/// The encryption types, from `borg/crypto/key.py`.
///
/// The two that are not encryption are the two a reader can go through: the
/// plaintext key stores the data as it is, and the "authenticated" keys sign
/// the data without hiding it.
const TYPE_PLAINTEXT: u8 = 0x02;
const TYPE_AUTHENTICATED_BLAKE2: u8 = 0x06;
const TYPE_AUTHENTICATED: u8 = 0x07;

/// The compressor tags, from `borg/compress.pyx`.
const COMP_NONE: [u8; 2] = [0x00, 0x00];
const COMP_LZ4: [u8; 2] = [0x01, 0x00];
const COMP_LZMA: [u8; 2] = [0x02, 0x00];
const COMP_ZSTD: [u8; 2] = [0x03, 0x00];
const COMP_ZLIB: [u8; 2] = [0x08, 0x00];

/// The largest payload one entry may expand to.
///
/// borg's chunker cuts a file into chunks of a few megabytes, and the
/// metadata of an archive is small. A ceiling this high is not a limit a
/// real backup reaches; it is the bound a compression bomb does not.
const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

/// The name of the member that carries the structure of a segment.
const STRUCTURE_MEMBER: &str = "borg.txt";

/// A borg repository segment.
pub struct Borg;

impl Adapter for Borg {
    fn name(&self) -> &'static str {
        "borg"
    }

    /// No extension: a segment is `data/0/2`, and the only thing that says
    /// what it is lives in its first eight bytes.
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }

    fn magic(&self) -> Option<&'static [u8]> {
        Some(MAGIC)
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if !data.starts_with(MAGIC) {
            decline!("borg: not a segment");
        }
        let entries = parse_entries(data)?;
        if entries.is_empty() {
            // A segment borg wrote always holds at least a commit, so a
            // segment with no entries is a segment that was cut short.
            bail!("borg: the segment holds no entries");
        }

        let mut puts = 0usize;
        let mut deletes = 0usize;
        let mut commits = 0usize;
        let mut payload_bytes = 0usize;
        for e in &entries {
            match e.tag {
                TAG_PUT => puts += 1,
                TAG_DELETE => deletes += 1,
                TAG_COMMIT => commits += 1,
                _ => {}
            }
            payload_bytes += e.payload.len();
        }

        // The payload of every PUT, decompressed, keyed by the id of the
        // entry that carried it. Each entry's expansion is capped on its
        // own; the budget caps them together, because every payload is
        // held at once for the passes that follow, and a segment of a few
        // megabytes can name thousands of entries.
        let mut payloads: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        let mut encrypted = false;
        let cap = budget::budget_for_depth(rgx_core::current_depth()).bytes;
        let mut spent: u64 = 0;
        let mut skipped_puts = 0usize;
        for e in &entries {
            if e.tag != TAG_PUT {
                continue;
            }
            match envelope(e.payload)? {
                Envelope::Encrypted => encrypted = true,
                Envelope::Compressed { compressor, body } => {
                    if spent >= cap {
                        // The walk continues so the count is the truth; the
                        // decode is what the budget refused.
                        skipped_puts += 1;
                        continue;
                    }
                    let payload = decompress(compressor, body)?;
                    spent = spent.saturating_add(payload.len() as u64);
                    if spent > cap {
                        skipped_puts += 1;
                        continue;
                    }
                    payloads.push((e.id, payload));
                }
            }
        }

        let mut text = String::new();
        let _ = writeln!(
            text,
            "borg segment: {} entries ({} put, {} delete, {} commit), {} bytes of payload",
            entries.len(),
            puts,
            deletes,
            commits,
            payload_bytes
        );
        if skipped_puts > 0 {
            let _ = writeln!(
                text,
                "[rgx: borg: {skipped_puts} put entries were not decoded; {cap} bytes of \
                 payload is the budget; raise RGX_MAX_MEMBER_BYTES to read them]"
            );
        }

        if encrypted {
            // The structure is readable and the contents are not, and the
            // reason is the one thing this reader may not ask for.
            let _ = writeln!(
                text,
                "[rgx: borg: the payload of this segment is encrypted, so its contents are not here; the repository key is the one thing a search tool may not ask for]"
            );
            return Ok(Outcome::Text(text.into_bytes()));
        }

        // The first pass tells the three kinds of metadata apart from a
        // chunk's data, and collects the ids of the archive's items -- those
        // ids are what tell an item's metadata apart from a chunk's data,
        // because both are entries and both carry a 32-byte id.
        //
        // The signatures are deliberately narrow. A chunk holds the content
        // of a file, and the content of a file is whatever the file held, so
        // a chunk can decode as a map with any keys at all. The repository
        // manifest is recognised by three keys at once, the archive metadata
        // by three more, and the item metadata by a shape a text file does
        // not have: a sequence of maps that all carry a path, and one of
        // which carries the chunk list.
        let mut archive = Archive::default();
        let mut manifest: Option<Manifest> = None;
        let mut sequences: Vec<([u8; 32], Vec<Value>)> = Vec::new();
        for (id, payload) in &payloads {
            let sequence = decode_sequence(payload);
            let Some(first) = sequence.first() else {
                sequences.push((*id, sequence));
                continue;
            };
            if first.get("archives").is_some()
                && first.get("item_keys").is_some()
                && first.get("version").is_some()
            {
                manifest = Some(Manifest::from_value(first));
                continue;
            }
            if first.get("name").is_some()
                && first.get("items").is_some()
                && first.get("hostname").is_some()
            {
                archive.name = first
                    .get("name")
                    .and_then(Value::as_bytes)
                    .map(|b| b.to_vec());
                archive.hostname = first
                    .get("hostname")
                    .and_then(Value::as_bytes)
                    .map(|b| b.to_vec());
                archive.username = first
                    .get("username")
                    .and_then(Value::as_bytes)
                    .map(|b| b.to_vec());
                archive.time = first
                    .get("time")
                    .and_then(Value::as_bytes)
                    .map(|b| b.to_vec());
                archive.nfiles = first.get("nfiles").and_then(Value::as_i64);
                archive.size = first.get("size").and_then(Value::as_i64);
                archive.csize = first.get("csize").and_then(Value::as_i64);
                if let Some(items) = first.get("items").and_then(Value::as_array) {
                    for item in items {
                        if let Some(bytes) = item.as_bytes() {
                            if let Some(id) = id_of(bytes) {
                                archive.item_ids.push(id);
                            }
                        }
                    }
                }
                continue;
            }
            sequences.push((*id, sequence));
        }

        if let Some(manifest) = &manifest {
            let _ = writeln!(
                text,
                "repository manifest: {} archive(s)",
                manifest.archives.len()
            );
            for (name, time) in &manifest.archives {
                let _ = write!(text, "  {name}");
                if let Some(time) = time {
                    let _ = write!(text, "  {}", String::from_utf8_lossy(time));
                }
                let _ = writeln!(text);
            }
            if let Some(timestamp) = manifest.timestamp.as_deref() {
                let _ = writeln!(text, "  updated: {}", String::from_utf8_lossy(timestamp));
            }
        }

        if let Some(name) = archive.name.as_deref() {
            let _ = writeln!(text, "archive: {}", String::from_utf8_lossy(name));
        }
        if let Some(host) = archive.hostname.as_deref() {
            let _ = writeln!(text, "  host: {}", String::from_utf8_lossy(host));
        }
        if let Some(user) = archive.username.as_deref() {
            let _ = writeln!(text, "  user: {}", String::from_utf8_lossy(user));
        }
        if let Some(time) = archive.time.as_deref() {
            let _ = writeln!(text, "  created: {}", String::from_utf8_lossy(time));
        }
        if let Some(n) = archive.nfiles {
            let _ = write!(text, "  files: {n}");
            if let Some(size) = archive.size {
                let _ = write!(text, ", {size} bytes");
            }
            if let Some(csize) = archive.csize {
                let _ = write!(text, " ({csize} compressed)");
            }
            let _ = writeln!(text);
        }

        // The item metadata: the entry whose id the archive names. When the
        // archive metadata is in another segment the ids are not known, and
        // the item metadata is recognised by its shape instead: a sequence
        // of maps that all carry a path, and at least one of them carries
        // the chunk list that only a full item has. Two maps is the floor,
        // because the safe metadata and the full item are two maps, and a
        // file whose content is one map with a path in it is a file.
        let mut items: Vec<Item> = Vec::new();
        let mut chunk_payloads: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        for (id, sequence) in &sequences {
            let known = archive.item_ids.iter().any(|i| i == id);
            let shaped = sequence.len() >= 2
                && sequence.iter().all(|v| v.get("path").is_some())
                && sequence.iter().any(|v| v.get("chunks").is_some());
            if known || shaped {
                for value in sequence {
                    if let Some(item) = Item::from_value(value) {
                        items.push(item);
                    }
                }
                continue;
            }
            if let Some((_, raw)) = payloads.iter().find(|(pid, _)| pid == id) {
                chunk_payloads.push((*id, raw.clone()));
            }
        }

        let _ = writeln!(text, "items:");
        let mut used_chunks: Vec<[u8; 32]> = Vec::new();
        for item in &items {
            let complete = item
                .chunks
                .iter()
                .all(|c| chunk_payloads.iter().any(|(id, _)| *id == c.id));
            let where_ = if item.chunks.is_empty() {
                "directory".to_string()
            } else if complete {
                "in this segment".to_string()
            } else {
                "chunks are in another segment".to_string()
            };
            let _ = write!(text, "  {}", String::from_utf8_lossy(&item.path));
            if item.size > 0 {
                let _ = write!(text, "  {} bytes", item.size);
            }
            if item.mtime > 0 {
                let _ = write!(text, "  {}", format_time(item.mtime));
            }
            let _ = writeln!(text, "  ({where_})");
            for chunk in &item.chunks {
                used_chunks.push(chunk.id);
            }
        }
        if items.is_empty() {
            let _ = writeln!(text, "  (none in this segment)");
        }

        // The chunks that no item here claims are still the content of the
        // backup, and the content is the reason to read the file.
        let mut members: Vec<(String, Vec<u8>)> = Vec::new();
        let mut unattributed = 0usize;
        for (id, payload) in &chunk_payloads {
            if used_chunks.iter().any(|u| u == id) {
                continue;
            }
            unattributed += 1;
            members.push((format!("chunk-{}.bin", hex16(id)), payload.clone()));
        }
        if unattributed > 0 {
            let _ = writeln!(
                text,
                "chunks: {unattributed} in this segment belong to an item in another segment"
            );
        }

        // A file whose chunks are all here is put back together, under the
        // name it had in the backup.
        for item in &items {
            if item.chunks.is_empty() {
                continue;
            }
            let mut content = Vec::new();
            let mut complete = true;
            for chunk in &item.chunks {
                match chunk_payloads.iter().find(|(id, _)| *id == chunk.id) {
                    Some((_, data)) => content.extend_from_slice(data),
                    None => {
                        complete = false;
                        break;
                    }
                }
            }
            if !complete {
                continue;
            }
            members.push((String::from_utf8_lossy(&item.path).into_owned(), content));
        }

        let mut all = Vec::with_capacity(members.len() + 1);
        all.push((STRUCTURE_MEMBER.to_string(), text.into_bytes()));
        all.extend(members);
        Ok(Outcome::Members(all))
    }
}

/// The metadata of the archive a segment belongs to.
///
/// The archive is written at the end of the transaction, in the same segment
/// as the items it names, so a segment usually carries both.
#[derive(Default)]
struct Archive {
    name: Option<Vec<u8>>,
    hostname: Option<Vec<u8>>,
    username: Option<Vec<u8>>,
    time: Option<Vec<u8>>,
    nfiles: Option<i64>,
    size: Option<i64>,
    csize: Option<i64>,
    /// The ids of the items of the archive. These are what tell an item's
    /// metadata apart from a chunk's data: both are entries, and both carry
    /// a 32-byte id.
    item_ids: Vec<[u8; 32]>,
}

/// The manifest of a repository: the archives it holds.
#[derive(Default)]
struct Manifest {
    /// The name of each archive and when it was created.
    archives: Vec<(String, Option<Vec<u8>>)>,
    /// When the manifest was written.
    timestamp: Option<Vec<u8>>,
}

impl Manifest {
    /// The manifest a metadata map describes.
    fn from_value(value: &Value) -> Manifest {
        let mut manifest = Manifest {
            timestamp: value
                .get("timestamp")
                .and_then(Value::as_bytes)
                .map(|b| b.to_vec()),
            ..Default::default()
        };
        if let Some(Value::Map(pairs)) = value.get("archives") {
            for (key, archive) in pairs {
                let Some(name) = key.as_bytes() else {
                    continue;
                };
                let time = archive
                    .get("time")
                    .and_then(Value::as_bytes)
                    .map(|b| b.to_vec());
                manifest
                    .archives
                    .push((String::from_utf8_lossy(name).into_owned(), time));
            }
        }
        manifest
    }
}

/// One entry of a segment.
struct Entry<'a> {
    tag: u8,
    /// The id of the object the entry carries: the chunk id for a PUT, the
    /// deleted id for a DELETE, and nothing for a COMMIT.
    id: [u8; 32],
    /// The bytes after the header.
    payload: &'a [u8],
}

/// The payload envelope of an entry.
enum Envelope<'a> {
    /// `type(1) | compressor(2) | compressed body`.
    Compressed { compressor: [u8; 2], body: &'a [u8] },
    /// `type(1) | mac(32) | nonce(8) | ciphertext`: the body is encrypted and
    /// the key is what is missing.
    Encrypted,
}

/// Split a segment into its entries, checking every CRC on the way.
fn parse_entries(data: &[u8]) -> Result<Vec<Entry<'_>>> {
    let mut entries = Vec::new();
    let mut off = MAGIC.len();
    while off < data.len() {
        if data.len() - off < 9 {
            bail!("borg: the segment ends inside an entry header");
        }
        let crc = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        let size = u32::from_le_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]]);
        let tag = data[off + 8];
        // The header the CRC covers: the size and the tag, in that order.
        let header = &data[off + 4..off + 9];
        match tag {
            TAG_PUT | TAG_DELETE => {
                if size < 41 {
                    bail!("borg: an entry claims {size} bytes, which is shorter than its header");
                }
                let size = size as usize;
                if data.len() - off < size {
                    bail!("borg: an entry claims {size} bytes and the segment has fewer");
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&data[off + 9..off + 41]);
                let payload = &data[off + 41..off + size];
                let mut c = crc32_update(u32::MAX, header);
                c = crc32_update(c, &id);
                c = crc32_update(c, payload) ^ u32::MAX;
                if c != crc {
                    bail!("borg: an entry has a checksum that does not match its bytes");
                }
                entries.push(Entry { tag, id, payload });
                off += size;
            }
            TAG_COMMIT => {
                let c = crc32_update(u32::MAX, header) ^ u32::MAX;
                if c != crc {
                    bail!("borg: a commit entry has a checksum that does not match its header");
                }
                entries.push(Entry {
                    tag,
                    id: [0u8; 32],
                    payload: &data[off + 9..off + 9],
                });
                off += 9;
            }
            other => bail!("borg: unknown entry tag {other}"),
        }
    }
    Ok(entries)
}

/// The envelope of an entry's payload.
fn envelope(payload: &[u8]) -> Result<Envelope<'_>> {
    let Some(&ty) = payload.first() else {
        bail!("borg: an entry has no payload");
    };
    match ty {
        TYPE_PLAINTEXT | TYPE_AUTHENTICATED | TYPE_AUTHENTICATED_BLAKE2 => {
            if payload.len() < 3 {
                bail!("borg: an entry payload is shorter than its envelope");
            }
            Ok(Envelope::Compressed {
                compressor: [payload[1], payload[2]],
                body: &payload[3..],
            })
        }
        // keyfile, passphrase, repokey and their blake2 variants: the body is
        // a mac and a ciphertext, and there is no reading it without the key.
        0x00 | 0x01 | 0x03 | 0x04 | 0x05 => Ok(Envelope::Encrypted),
        other => bail!("borg: unknown encryption type {other}"),
    }
}

/// Decompress one payload with the compressor its envelope names.
fn decompress(compressor: [u8; 2], body: &[u8]) -> Result<Vec<u8>> {
    if compressor == COMP_NONE {
        return Ok(body.to_vec());
    }
    let decoded = if compressor == COMP_LZ4 {
        Lz4Decoder::new()
            .decode_block_bounded(body, MAX_ENTRY_BYTES)
            .map_err(|e| rgx_core::anyhow!("borg: the lz4 block does not decode: {e}"))?
    } else if compressor == COMP_LZMA {
        LzmaDecoder::new()
            .decode_bounded(body, MAX_ENTRY_BYTES)
            .map_err(|e| rgx_core::anyhow!("borg: the lzma stream does not decode: {e}"))?
    } else if compressor == COMP_ZSTD {
        ZstdDecoder::new()
            .decode_bounded(body, MAX_ENTRY_BYTES)
            .map_err(|e| rgx_core::anyhow!("borg: the zstd stream does not decode: {e}"))?
    } else if compressor == COMP_ZLIB {
        ZlibDecoder::new()
            .decode_bounded(body, MAX_ENTRY_BYTES)
            .map_err(|e| rgx_core::anyhow!("borg: the zlib stream does not decode: {e}"))?
    } else {
        bail!(
            "borg: compression algorithm {compressor:02x?} is not one this reader has",
            compressor = compressor
        );
    };
    if decoded.capped {
        bail!("borg: an entry expands past the {MAX_ENTRY_BYTES} byte ceiling");
    }
    Ok(decoded.bytes)
}

/// Every MessagePack value in a payload, in order.
///
/// A payload is a sequence of values, and a value that does not decode is
/// not an error: the payload of a chunk is the content of a file, and the
/// content of a file is whatever the file held.
fn decode_sequence(payload: &[u8]) -> Vec<Value> {
    let mut decoder = Msgpack::new(payload);
    let mut values = Vec::new();
    while !decoder.is_empty() {
        match decoder.decode() {
            Ok(value) => values.push(value),
            Err(_) => break,
        }
    }
    values
}

/// The id of an object, when the bytes are one.
fn id_of(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(bytes);
    Some(id)
}

/// One chunk of a backed-up file.
struct Chunk {
    id: [u8; 32],
}

/// One item of a backup: a file, a directory, or a symlink.
struct Item {
    path: Vec<u8>,
    size: u64,
    mtime: i64,
    chunks: Vec<Chunk>,
}

impl Item {
    /// The item a metadata map describes, when it describes one.
    fn from_value(value: &Value) -> Option<Item> {
        let path = value.get("path")?.as_bytes()?.to_vec();
        let size = value.get("size").and_then(Value::as_u64).unwrap_or(0);
        let mtime = value.get("mtime").and_then(Value::as_i64).unwrap_or(0);
        let mut chunks = Vec::new();
        if let Some(list) = value.get("chunks").and_then(Value::as_array) {
            for chunk in list {
                // A chunk entry is [id, size, compressed size].
                let Some(elements) = chunk.as_array() else {
                    continue;
                };
                let Some(id) = elements.first().and_then(Value::as_bytes) else {
                    continue;
                };
                if let Some(id) = id_of(id) {
                    chunks.push(Chunk { id });
                }
            }
        }
        Some(Item {
            path,
            size,
            mtime,
            chunks,
        })
    }
}

/// A unix timestamp in nanoseconds, as borg stores it, in readable form.
fn format_time(nanos: i64) -> String {
    let seconds = nanos.div_euclid(1_000_000_000);
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    format!(
        "{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02}",
        rest / 3600,
        (rest / 60) % 60,
        rest % 60
    )
}

/// Howard Hinnant's `civil_from_days`: the day number since the epoch as a
/// civil date. Nine lines, and the archive crate is `no_std` + `alloc`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The first sixteen hex digits of an id, for a member name.
fn hex16(id: &[u8; 32]) -> String {
    let mut out = String::with_capacity(16);
    for byte in &id[..8] {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    /// The segment of a repository created with `borg init --encryption=none`
    /// and one `borg create`: the archive metadata, the two items and the
    /// two chunks.
    const PLAIN: &[u8] = include_bytes!("../testdata/borg_segment_plain.bin");

    /// The manifest of the same repository.
    const MANIFEST: &[u8] = include_bytes!("../testdata/borg_manifest_plain.bin");

    /// The segment of a repository created with `borg init --encryption=keyfile`.
    const ENCRYPTED: &[u8] = include_bytes!("../testdata/borg_segment_enc.bin");

    /// The same segment as `PLAIN` with its two chunk entries left out, so
    /// the items name chunks that are in another segment.
    ///
    /// It is the real segment's own bytes, cut down: the two metadata
    /// entries keep their ids, their sizes and their CRCs, and the two
    /// chunk entries are simply not there.
    const PLAIN_NO_CHUNKS: &[u8] = include_bytes!("../testdata/borg_segment_nochunks.bin");

    /// The members of an extraction, by name.
    fn members(out: Outcome) -> Vec<(String, Vec<u8>)> {
        match out {
            Outcome::Members(m) => m,
            _ => panic!("expected members"),
        }
    }

    /// The text of an extraction.
    fn text(out: Outcome) -> String {
        match out {
            Outcome::Text(t) => String::from_utf8_lossy(&t).into_owned(),
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn a_plain_segment_gives_back_the_files_it_holds() {
        let m = members(Borg.extract(PLAIN, "data/0/2").expect("a segment is ours"));
        let names: Vec<&str> = m.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&"data/factura.txt") && names.contains(&"data/nota.txt"),
            "the two files of the backup are missing: {names:?}"
        );
        let factura = m
            .iter()
            .find(|(n, _)| n == "data/factura.txt")
            .map(|(_, b)| b.clone())
            .expect("factura.txt");
        assert_eq!(factura, b"conteudo de teste\r\n");
        let nota = m
            .iter()
            .find(|(n, _)| n == "data/nota.txt")
            .map(|(_, b)| b.clone())
            .expect("nota.txt");
        assert_eq!(nota, b"segunda linha\r\n");
    }

    #[test]
    fn the_structure_of_the_segment_names_the_archive_and_its_files() {
        let m = members(Borg.extract(PLAIN, "data/0/2").expect("a segment is ours"));
        let structure = m
            .iter()
            .find(|(n, _)| n == STRUCTURE_MEMBER)
            .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
            .expect("the structure");
        assert!(structure.contains("archive: me"), "{structure}");
        assert!(structure.contains("data/factura.txt"), "{structure}");
        assert!(structure.contains("19 bytes"), "{structure}");
        // The path is the searchable part: a user who knows the name of a
        // file in the backup must find it.
        assert!(structure.contains("data/nota.txt"), "{structure}");
    }

    #[test]
    fn the_repository_manifest_names_the_archives_it_holds() {
        let m = members(
            Borg.extract(MANIFEST, "data/0/0")
                .expect("a manifest is ours"),
        );
        let structure = m
            .iter()
            .find(|(n, _)| n == STRUCTURE_MEMBER)
            .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
            .expect("the structure");
        assert!(structure.contains("repository manifest"), "{structure}");
        assert!(structure.contains("me"), "{structure}");
    }

    #[test]
    fn an_encrypted_segment_says_why_it_cannot_read_the_rest() {
        let out = text(
            Borg.extract(ENCRYPTED, "data/0/2")
                .expect("a segment is ours"),
        );
        assert!(out.contains("encrypted"), "{out}");
        assert!(
            out.contains("[rgx: borg:") && out.contains("repository key"),
            "the note must name the blocker: {out}"
        );
    }

    #[test]
    fn a_file_that_is_not_a_segment_is_declined() {
        match Borg.extract(b"PK\x03\x04 not a segment", "x") {
            Err(e) => assert!(e.to_string().contains("not a segment"), "{e}"),
            _ => panic!("a zip is not a borg segment"),
        }
    }

    #[test]
    fn a_cut_segment_is_refused_rather_than_half_read() {
        for cut in [8usize, 20, 100, 400, 900] {
            let cut = cut.min(PLAIN.len());
            let e = Borg.extract(&PLAIN[..cut], "data/0/2");
            assert!(e.is_err(), "a cut segment at {cut} must not decode");
        }
    }

    #[test]
    fn the_reader_never_panics_on_a_mutated_segment() {
        rgx_core::fuzzkit::assert_never_panics(
            vec![
                ("plain", PLAIN.to_vec()),
                ("manifest", MANIFEST.to_vec()),
                ("encrypted", ENCRYPTED.to_vec()),
                ("no chunks", PLAIN_NO_CHUNKS.to_vec()),
            ],
            200,
            "borg",
            |d| {
                let _ = Borg.extract(d, "data/0/2");
            },
        );
    }

    #[test]
    fn a_file_whose_chunks_are_elsewhere_is_said_to_be_elsewhere() {
        let m = members(
            Borg.extract(PLAIN_NO_CHUNKS, "data/0/2")
                .expect("a segment is ours"),
        );
        let structure = m
            .iter()
            .find(|(n, _)| n == STRUCTURE_MEMBER)
            .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
            .expect("the structure");
        // The items are named -- the metadata IS in this segment -- and the
        // reader says where their content is not.
        assert!(structure.contains("data/factura.txt"), "{structure}");
        assert!(
            structure.contains("chunks are in another segment"),
            "{structure}"
        );
        // And it does not hand out the files it cannot put together: a
        // member with no content would be a file that is not in the file.
        let names: Vec<&str> = m.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            !names.contains(&"data/factura.txt") && !names.contains(&"data/nota.txt"),
            "the files are not here: {names:?}"
        );
    }
}
