// SPDX-License-Identifier: Apache-2.0

//! LevelDB and RocksDB — the key/value stores behind them.
//!
//! Two file kinds live in a store directory and they are read differently,
//! because they are different things:
//!
//! - **`LOG`** — the write-ahead log. Every write the database ever took is
//!   a record here, in order, with its key and its value intact. This is the
//!   searchable half: a string that was written and then deleted is still on
//!   disk in the log and nowhere else.
//! - **`ldb` / `sst`** — an immutable sorted table. Keys are present but
//!   *prefix-compressed* against the previous key in the block, so they are
//!   only recoverable by walking the block in order, and the blocks
//!   themselves are Snappy-compressed by default.
//!
//! So the adapter claims both, routes on the file's own shape rather than on
//! its extension, and the extension claim is deliberately narrow: `.ldb`,
//! `.log`, `.sst`, and the RocksDB spellings. A file named `LOG` is
//! ordinary text and is claimed by nothing here — the reader is chosen by
//! the structure, and a text file that happens to be called `LOG` still
//! gets searched as text.
//!
//! ## What is verified
//!
//! The log carries a masked CRC32-C over each record and this reader checks
//! it: a log whose records do not check is a log whose contents cannot be
//! trusted, and a wrong key read out of a misaligned record would be
//! printed as if it were a fact about the database. A CRC failure ends the
//! walk where it happened and says so, keeping the records before it.
//!
//! A sorted table carries a masked CRC32-C per block over its contents plus
//! the type byte, and this reader checks it too. The checksum is over the
//! bytes as they are in the file, so it is checked *before* the Snappy
//! decoder sees them: a block that fails it is a block whose bytes are
//! wrong, and not one the decoder disagreed about. A block that fails ends
//! the walk of that table where it happened and says so, keeping the blocks
//! before it.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use rgx_core::compress::snappy::SnappyDecoder;
use rgx_core::{bail, decline, Adapter, Outcome, Result};

/// The table footer magic, at the last eight bytes of every `.ldb`/`.sst`.
/// RocksDB forked it from LevelDB and kept it, so one magic covers both.
const TABLE_MAGIC: u64 = 0xdb47_7524_8b80_fb57;

/// The log's physical block size, from `leveldb/log_format.h`.
const LOG_BLOCK: usize = 32768;

/// Bytes a log record header occupies before its payload.
const LOG_HEADER: usize = 7;

/// Ceiling on records printed from one file. A busy store's log holds every
/// write since it was created; a grep should not page through all of it
/// without saying so.
const MAX_RECORDS: usize = 200_000;

/// Ceiling on one value's printed length.
const MAX_VALUE: usize = 4096;

pub struct LevelDb;
impl Adapter for LevelDb {
    fn name(&self) -> &'static str {
        "leveldb"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ldb", "log", "sst"]
    }
    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome> {
        // Routed on structure, not on the name: a `.log` is a write-ahead log
        // only if its records are framed the way one frames them, and a file
        // that fails the framing is more likely to be something else than a
        // corrupt store.
        if looks_like_table(data) {
            return read_table(data);
        }
        if looks_like_log(data) {
            return read_log(data);
        }
        // A RocksDB `.sst` may carry a different footer revision, and a log
        // with no records yet is legal. Rather than guess from the
        // extension -- which would claim files this reader cannot read --
        // both shapes were checked and neither held.
        let _ = path;
        decline!("not a LevelDB or RocksDB file (neither a table footer nor a framed log)");
    }
}

/// A sorted table ends in the footer magic.
fn looks_like_table(d: &[u8]) -> bool {
    d.len() >= 8 && rd_u64le(d, d.len() - 8) == TABLE_MAGIC
}

/// A write-ahead log opens with a record whose checksum has to match, which
/// is a far stronger claim than "the extension is `.log`".
fn looks_like_log(d: &[u8]) -> bool {
    log_record(d, 0).is_some()
}

/// One framed record: where its payload starts, its fragment type, and
/// where that payload ends.
struct Rec {
    at: usize,
    kind: u8,
    end: usize,
}

/// Read the record framed at `at`, checking its CRC.
///
/// `None` covers both "there is no record here" and "the record does not
/// check"; the caller cannot tell them apart from the return value alone,
/// and does not need to -- either way the remainder is not read.
fn log_record(d: &[u8], at: usize) -> Option<Rec> {
    let len = u16::from_le_bytes([*d.get(at + 4)?, *d.get(at + 5)?]) as usize;
    let kind = *d.get(at + 6)?;
    let payload = at + LOG_HEADER;
    let end = payload.checked_add(len)?;
    let body = d.get(payload..end)?;
    let stored = u32::from_le_bytes([
        *d.get(at)?,
        *d.get(at + 1)?,
        *d.get(at + 2)?,
        *d.get(at + 3)?,
    ]);
    // The CRC covers the type byte and the payload, and is stored masked so
    // a byte-swapped or truncated file does not pass by accident.
    if unmask_crc(stored) != crc32c(&[&[kind], body]) {
        return None;
    }
    Some(Rec {
        at: payload,
        kind,
        end,
    })
}

/// A whole log, assembled across the `FIRST`/`MIDDLE`/`LAST` fragments a
/// large write is split into.
fn read_log(data: &[u8]) -> Result<Outcome> {
    let mut out = String::new();
    let _ = writeln!(out, "-- leveldb write-ahead log --");
    let mut records = 0usize;
    let mut reported = false;
    let mut pending: Vec<u8> = Vec::new();
    let mut p = 0usize;
    let mut stopped: Option<&str> = None;

    'outer: while p < data.len() && records < MAX_RECORDS {
        // A block too short to hold a header is zero-filled and skipped.
        let in_block = p % LOG_BLOCK;
        if LOG_BLOCK - in_block < LOG_HEADER {
            p += LOG_BLOCK - in_block;
            continue;
        }
        let Some(rec) = log_record(data, p) else {
            // End of file, or a record that does not check. Either way the
            // remainder is not read, and saying so is the whole difference
            // between a truncated answer and a complete one.
            stopped = if p + LOG_HEADER >= data.len() {
                None
            } else {
                Some("checksum or framing failed")
            };
            break 'outer;
        };
        p = rec.end;
        match rec.kind {
            1 => {
                // A complete write arriving while a previous one is still
                // open is malformed. Dropping the fragments without a word
                // would make the log read as if that write never existed.
                if !pending.is_empty() {
                    let _ = writeln!(
                        out,
                        "[log: {} bytes of a write with no closing record were dropped]",
                        pending.len()
                    );
                    reported = true;
                }
                flush_batch(&mut out, &data[rec.at..rec.end], &mut records);
                reported |= records > 0;
                pending.clear();
            }
            2 => {
                pending.clear();
                pending.extend_from_slice(&data[rec.at..rec.end]);
            }
            3 => pending.extend_from_slice(&data[rec.at..rec.end]),
            4 => {
                pending.extend_from_slice(&data[rec.at..rec.end]);
                flush_batch(&mut out, &pending, &mut records);
                reported |= records > 0;
                pending.clear();
            }
            // Types 0 and above 4 do not exist; refusing the walk is better
            // than reading a payload that is not a write.
            _ => {
                stopped = Some("unknown record type");
                break 'outer;
            }
        }
    }

    if !pending.is_empty() {
        // A write that never got its LAST fragment: the batch is unusable,
        // and printing half of it would print a claim the file did not make.
        let _ = writeln!(
            out,
            "[log: {} bytes belong to a write with no closing record]",
            pending.len()
        );
        reported = true;
    }
    // Only a log with nothing at all to say is a refusal. A log holding one
    // unclosed write has something true to report, and declining it would
    // hand the caller the raw bytes and none of the reason.
    if records == 0 && !reported {
        bail!("log holds no records");
    }
    if let Some(why) = stopped {
        let _ = writeln!(out, "[log: stopped at offset {p}: {why}]");
    } else if records >= MAX_RECORDS {
        let _ = writeln!(out, "[log: stopped at {MAX_RECORDS} records]");
    }
    Ok(Outcome::Text(out.into_bytes()))
}

/// One write batch: an eight-byte sequence number, a four-byte count, and
/// that many records of a type byte, a length-prefixed key, and for a put a
/// length-prefixed value.
fn flush_batch(out: &mut String, batch: &[u8], records: &mut usize) {
    if batch.len() < 12 {
        return;
    }
    let seq = u64::from_le_bytes(batch[..8].try_into().unwrap_or([0; 8]));
    let count = u32::from_le_bytes(batch[8..12].try_into().unwrap_or([0; 4])) as usize;
    let mut p = 12usize;
    let _ = writeln!(out, "batch seq {seq} ({count} records)");
    for _ in 0..count {
        if p >= batch.len() {
            let _ = writeln!(out, "[batch: truncated at offset {p}]");
            return;
        }
        let kind = batch[p];
        p += 1;
        // One cursor for the whole loop: shadowing it inside the body leaves
        // the outer `p` where it was, and the next iteration re-reads the
        // same byte as if it were a fresh record.
        let Some((klen, after_len)) = varint32(batch, p) else {
            let _ = writeln!(out, "[batch: key length unreadable at {p}]");
            return;
        };
        p = after_len;
        let Some(kend) = p.checked_add(klen) else {
            let _ = writeln!(out, "[batch: key length overflows]");
            return;
        };
        let Some(key_bytes) = batch.get(p..kend) else {
            let _ = writeln!(out, "[batch: key runs past the record]");
            return;
        };
        p = kend;
        let verb = match kind {
            // A deletion carries a key and nothing else -- no length, no
            // value -- so reading one here would consume the first byte of
            // the next record as if it were a length.
            0 => {
                let _ = writeln!(out, "delete {}", quoted(key_bytes));
                *records += 1;
                continue;
            }
            1 => "put",
            // A merge carries the operand set, which the log does not
            // resolve -- it names the key and the operation, and says so.
            _ => {
                let _ = writeln!(out, "op {kind} {} (payload not decoded)", quoted(key_bytes));
                *records += 1;
                continue;
            }
        };
        let Some((vlen, after_vlen)) = varint32(batch, p) else {
            let _ = writeln!(out, "[batch: value length unreadable at {p}]");
            return;
        };
        let Some(vend) = after_vlen.checked_add(vlen) else {
            let _ = writeln!(out, "[batch: value length overflows]");
            return;
        };
        let Some(val) = batch.get(after_vlen..vend) else {
            let _ = writeln!(out, "[batch: value runs past the record]");
            return;
        };
        p = vend;
        let _ = writeln!(out, "{verb} {} {}", quoted(key_bytes), quoted(val));
        *records += 1;
    }
}

// ---- sorted tables ------------------------------------------------------

fn read_table(data: &[u8]) -> Result<Outcome> {
    if data.len() < 48 + 2 {
        decline!("too small for a table footer");
    }
    let footer = &data[data.len() - 48..];
    let mut p = 0usize;
    let Some((index, _)) = block_handle(footer, &mut p) else {
        bail!("table footer names no index block");
    };
    // The metaindex handle names the filter policy and the statistics; both
    // are about the table rather than in it, so neither is read.
    let _ = block_handle(footer, &mut p);
    if p > 40 {
        bail!("table footer runs past its own 40 bytes");
    }

    let mut out = String::new();
    let _ = writeln!(out, "-- leveldb sorted table --");
    let mut keys = 0usize;
    let mut halted: Option<&str> = None;

    // The index block maps a block's last key to its handle, so it is
    // walked first and each entry it names is read in turn.
    match read_block_body(data, index, &mut out, &mut keys) {
        Ok(()) => {}
        Err(why) => halted = Some(why),
    }
    if keys == 0 && halted.is_none() {
        bail!("table holds no keys");
    }
    if let Some(why) = halted {
        let _ = writeln!(out, "[table: {why}]");
    }
    Ok(Outcome::Text(out.into_bytes()))
}

/// A `BlockHandle`: a varint offset and a varint size.
fn block_handle(d: &[u8], p: &mut usize) -> Option<(Handle, usize)> {
    let (offset, n1) = varint64(d, *p)?;
    let (size, n2) = varint64(d, n1)?;
    *p = n2;
    Some((
        Handle {
            offset: offset as usize,
            size: size as usize,
        },
        n2,
    ))
}

/// A block's key/value rows, or the reason the block could not be read.
/// Named because the spelled-out form reads worse than the thing it names.
type Rows = core::result::Result<Vec<(Vec<u8>, Vec<u8>)>, &'static str>;

#[derive(Clone, Copy)]
struct Handle {
    offset: usize,
    size: usize,
}

/// Read the index block and, for each entry it names, the data block.
fn read_block_body(
    data: &[u8],
    index: Handle,
    out: &mut String,
    keys: &mut usize,
) -> core::result::Result<(), &'static str> {
    let index_entries = decode_block(data, index)?;
    for (last_key, handle_bytes) in index_entries {
        // An index entry's value is the *encoded* handle of the block it
        // names, not that block's contents: reading it as a row would print
        // a handful of varints as if they were keys.
        let mut q = 0usize;
        let Some((h, _)) = block_handle(&handle_bytes, &mut q) else {
            return Err("index entry carries no block handle");
        };
        for (key, value) in decode_block(data, h)? {
            let _ = writeln!(out, "{} {}", quoted(&key), quoted(&value));
            *keys += 1;
            if *keys >= MAX_RECORDS {
                return Ok(());
            }
        }
        // The index entry's key is the block's last key, already printed as
        // one of that block's own rows; it names the block and adds nothing.
        let _ = last_key;
    }
    Ok(())
}

/// One block: its key/value entries, with the Snappy trailer handled.
fn decode_block(data: &[u8], h: Handle) -> Rows {
    let raw = data
        .get(
            h.offset
                ..h.offset
                    .checked_add(h.size)
                    .ok_or("block handle overflows")?,
        )
        .ok_or("block handle points past the file")?;
    // The block is followed by a five-byte trailer: a compression type and
    // a checksum of the type and the data. The checksum is over the bytes
    // as they are in the file, before the Snappy decoder sees them, so a
    // failure means the file's bytes are wrong, and not that the decoder
    // disagrees.
    let (body, trailer) = match raw.split_at_checked(raw.len().saturating_sub(5)) {
        Some((b, t)) if !b.is_empty() && t.len() == 5 => (b, t),
        _ => (raw, &[][..]),
    };
    let comp = match trailer {
        [c, rest @ ..] if rest.len() == 4 => {
            let stored = u32::from_le_bytes(rest.try_into().unwrap());
            if unmask_crc(stored) != crc32c(&[body, &[*c]]) {
                return Err("the block's checksum does not match its data");
            }
            *c
        }
        _ => 0,
    };
    let plain: Vec<u8> = match comp {
        0 => body.to_vec(),
        1 => {
            let mut cap = rgx_core::compress::OutputCap::new(1 << 30);
            let d = SnappyDecoder::new()
                .decompress(body, &mut cap)
                .map_err(|_| "block is Snappy and did not decode")?;
            if d.capped {
                return Err("block decode stopped at the ceiling");
            }
            d.bytes
        }
        _ => return Err("unknown block compression"),
    };
    parse_block_entries(&plain)
}

/// The block body proper: delta-encoded entries, then a restart array, then
/// the restart count.
fn parse_block_entries(b: &[u8]) -> Rows {
    if b.len() < 4 {
        return Err("block has no restart count");
    }
    let nrestarts = u32::from_le_bytes(b[b.len() - 4..].try_into().unwrap()) as usize;
    let array = 4usize
        .checked_add(nrestarts.checked_mul(4).ok_or("restart array overflows")?)
        .ok_or("restart array overflows")?;
    if array > b.len() {
        return Err("restart array runs past the block");
    }
    let end = b.len() - array;
    let mut p = 0usize;
    let mut prev: Vec<u8> = Vec::new();
    let mut out = Vec::new();
    while p < end {
        let (shared, n1) = varint32(b, p).ok_or("entry header unreadable")?;
        let (non_shared, n2) = varint32(b, n1).ok_or("entry header unreadable")?;
        let (vlen, n3) = varint32(b, n2).ok_or("entry header unreadable")?;
        // A shared prefix longer than the previous key is a block that says
        // something about bytes it does not hold.
        if shared > prev.len() {
            return Err("entry shares more prefix than the previous key has");
        }
        let kend = n3.checked_add(non_shared).ok_or("entry key overflows")?;
        let Some(delta) = b.get(n3..kend) else {
            return Err("entry key runs past the block");
        };
        let Some(vend) = kend.checked_add(vlen) else {
            return Err("entry value overflows");
        };
        let Some(value) = b.get(kend..vend) else {
            return Err("entry value runs past the block");
        };
        let mut key = prev[..shared].to_vec();
        key.extend_from_slice(delta);
        out.push((key, value.to_vec()));
        prev = out.last().map(|(k, _)| k.clone()).unwrap_or_default();
        p = vend;
    }
    Ok(out)
}

// ---- primitives ---------------------------------------------------------

/// A varint as LevelDB writes them: seven bits per byte, low group first.
fn varint32(d: &[u8], mut p: usize) -> Option<(usize, usize)> {
    let mut v = 0usize;
    let mut shift = 0u32;
    loop {
        let b = *d.get(p)?;
        p += 1;
        if shift >= 35 {
            return None;
        }
        v |= usize::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((v, p));
        }
        shift += 7;
    }
}

fn varint64(d: &[u8], mut p: usize) -> Option<(u64, usize)> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *d.get(p)?;
        p += 1;
        if shift >= 64 {
            return None;
        }
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((v, p));
        }
        shift += 7;
    }
}

/// Undo the stored form of a record checksum.
///
/// The store writes `(crc >> 15 | crc << 17) + kMaskDelta`, which is a
/// rotate **right** by 15 followed by an offset. Undoing it means undoing
/// the steps in the opposite order -- take the offset off first, then
/// rotate **left** -- and both directions matter: rotating the wrong way
/// here does not degrade the check, it inverts it, and every record in every
/// real log is then refused.
fn unmask_crc(masked: u32) -> u32 {
    masked.wrapping_sub(0xa282_ead8).rotate_left(15)
}

/// CRC-32C (Castagnoli), the polynomial LevelDB and RocksDB use.
fn crc32c(parts: &[&[u8]]) -> u32 {
    let mut crc = !0u32;
    for chunk in parts.iter().copied() {
        for &b in chunk {
            crc ^= u32::from(b);
            for _ in 0..8 {
                let mask = 0u32.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
            }
        }
    }
    !crc
}

/// A key or value, printable if it is text and summarised if it is not.
/// The length is in the marker, so a binary value's size is searchable even
/// though its bytes are not.
fn quoted(b: &[u8]) -> String {
    let take = b.len().min(MAX_VALUE);
    let head = b.get(..take).unwrap_or_default();
    let mut s = String::with_capacity(head.len() + 16);
    s.push('"');
    for &c in head {
        match c {
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            0x20..=0x7e => s.push(c as char),
            _ => {
                let _ = write!(s, "\\x{c:02x}");
            }
        }
    }
    if b.len() > MAX_VALUE {
        let _ = write!(s, "…(+{} bytes)", b.len() - MAX_VALUE);
    }
    s.push('"');
    s
}

fn rd_u64le(d: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = d.get(at + i).copied().unwrap_or(0);
    }
    u64::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    //! The framing is built here from the documented layouts, because there
    //! is no reference implementation to generate it -- which is exactly why
    //! the one piece of this reader with published constants, CRC-32C, is
    //! checked against its standard test vectors below. A checksum that
    //! silently computes the wrong polynomial would accept every fixture and
    //! reject every real store.

    use super::*;
    use rgx_core::Outcome;

    /// CRC-32C as Castagnoli's standard check values: the empty string, one
    /// byte, and the conventional nine-byte string.
    #[test]
    fn crc32c_matches_the_published_check_values() {
        assert_eq!(crc32c(&[b""]), 0);
        assert_eq!(crc32c(&[b"a"]), 0xc1d0_4330);
        assert_eq!(crc32c(&[b"123456789"]), 0xe306_9283);
        // Over two chunks, because the record CRC covers the type byte and
        // the payload as two separate pieces.
        assert_eq!(
            crc32c(&[b"1", b"23456789"]),
            crc32c(&[b"123456789"]),
            "chunking must not change the result"
        );
    }

    #[test]
    fn the_masked_crc_is_the_one_the_store_writes() {
        // A record whose stored CRC is the mask of the computed one is
        // accepted; a byte-swapped one is not.
        let body = b"payload";
        let stored = mask_crc(crc32c(&[&[1u8], body]));
        assert_eq!(unmask_crc(stored), crc32c(&[&[1u8], body]));
        assert_ne!(stored, crc32c(&[&[1u8], body]));
    }

    fn mask_crc(crc: u32) -> u32 {
        crc.rotate_right(15).wrapping_add(0xa282_ead8)
    }

    /// A write batch: a sequence number, a record count, then records of a
    /// type byte and two length-prefixed blobs.
    fn batch(seq: u64, puts: &[(&[u8], &[u8])], dels: &[&[u8]]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&seq.to_le_bytes());
        b.extend_from_slice(&((puts.len() + dels.len()) as u32).to_le_bytes());
        for (k, v) in puts {
            b.push(1);
            varint(&mut b, k.len() as u32);
            b.extend_from_slice(k);
            varint(&mut b, v.len() as u32);
            b.extend_from_slice(v);
        }
        for k in dels {
            b.push(0);
            varint(&mut b, k.len() as u32);
            b.extend_from_slice(k);
        }
        b
    }

    fn varint(out: &mut Vec<u8>, mut v: u32) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            out.push(b | if v != 0 { 0x80 } else { 0 });
            if v == 0 {
                return;
            }
        }
    }

    /// One framed log record, CRC and all.
    fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&mask_crc(crc32c(&[&[kind], payload])).to_le_bytes());
        r.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        r.push(kind);
        r.extend_from_slice(payload);
        r
    }

    fn text_of(data: &[u8]) -> String {
        match LevelDb.extract(data, "000003.log").expect("extracted") {
            Outcome::Text(t) => String::from_utf8(t).expect("utf-8"),
            Outcome::Members(_) => panic!("expected text"),
            Outcome::Bail(_) => panic!("expected text"),
        }
    }

    #[test]
    fn a_log_reads_back_every_put_and_delete_in_order() {
        let mut log = record(
            1,
            &batch(
                100,
                &[(b"user:1", b"RGX-ALADDIN"), (b"user:2", b"sin senha")],
                &[b"user:0"],
            ),
        );
        log.extend(record(1, &batch(200, &[], &[b"user:1"])));
        let out = text_of(&log);
        assert!(out.contains("batch seq 100"), "{out}");
        assert!(out.contains("put \"user:1\" \"RGX-ALADDIN\""), "{out}");
        assert!(out.contains("put \"user:2\" \"sin senha\""), "{out}");
        assert!(out.contains("delete \"user:0\""), "{out}");
        assert!(out.contains("batch seq 200"), "{out}");
        assert!(out.contains("delete \"user:1\""), "{out}");
    }

    /// A write larger than one block is split, and only reassembled when the
    /// fragments pair up.
    #[test]
    fn a_split_write_is_reassembled_from_its_fragments() {
        let payload = batch(7, &[(&b"big-key"[..], &vec![b'v'; 9000])], &[]);
        let (head, tail) = payload.split_at(payload.len() / 2);
        let mut log = record(2, head);
        log.extend(record(3, tail));
        // Without the LAST fragment the batch is never complete, and the
        // reader must not act as though the first half were a whole write.
        log.extend(record(4, &[]));
        log.extend(record(1, &batch(8, &[], &[])));
        let out = text_of(&log);
        assert!(out.contains("put \"big-key\""), "{out}");
        assert!(out.contains("…(+"), "a capped value must say so: {out}");
    }

    /// A write whose closing fragment never arrived must not be printed as
    /// if it had: the batch is unusable without its LAST.
    #[test]
    fn a_write_with_no_closing_record_is_reported_not_guessed() {
        let payload = batch(7, &[(&b"k"[..], &vec![b'v'; 400])], &[]);
        let mut log = record(2, &payload[..payload.len() / 2]);
        log.extend(record(1, &batch(9, &[], &[])));
        let out = text_of(&log);
        assert!(out.contains("no closing record"), "{out}");
        assert!(
            !out.contains("put \"k\""),
            "an unclosed write is not a fact: {out}"
        );
    }

    /// The log is the readable half of the store, so a record that does not
    /// check has to end the walk and say where.
    #[test]
    fn a_record_that_does_not_check_ends_the_walk_and_says_so() {
        let mut log = record(1, &batch(1, &[(&b"good"[..], b"1")], &[]));
        let mut bad = record(1, &batch(2, &[(&b"bad"[..], b"2")], &[]));
        bad[0] ^= 0xff; // break the stored checksum
        log.extend(bad);
        let out = text_of(&log);
        assert!(out.contains("put \"good\""), "{out}");
        assert!(
            !out.contains("put \"bad\""),
            "a record that fails its CRC is not read: {out}"
        );
        assert!(out.contains("stopped at offset"), "{out}");
    }

    /// Routing is on structure, not on the extension: a file named `LOG` that
    /// holds text must stay text.
    #[test]
    fn a_text_file_named_like_a_log_is_declined_not_claimed() {
        let Err(err) = LevelDb.extract(b"just some ordinary log lines\n", "LOG") else {
            panic!("a text file must be left to the raw path");
        };
        assert!(err.is_decline(), "expected a decline, got: {err}");
    }

    // ---- sorted tables ---------------------------------------------------

    /// A block: delta-encoded entries, then the restart array and its count.
    fn block(entries: &[(&[u8], &[u8])], compress: bool) -> Vec<u8> {
        let mut body = Vec::new();
        let mut prev: &[u8] = b"";
        // One restart per entry keeps the test free of prefix-sharing
        // arithmetic; the shared-prefix path is exercised by the delta case.
        let mut restarts = Vec::new();
        for (i, (k, v)) in entries.iter().enumerate() {
            if i == 0 {
                restarts.push(body.len() as u32);
                varint(&mut body, 0);
                varint(&mut body, k.len() as u32);
                varint(&mut body, v.len() as u32);
                body.extend_from_slice(k);
            } else {
                let shared = k.iter().zip(prev).take_while(|(a, b)| a == b).count();
                varint(&mut body, shared as u32);
                varint(&mut body, (k.len() - shared) as u32);
                varint(&mut body, v.len() as u32);
                body.extend_from_slice(&k[shared..]);
            }
            body.extend_from_slice(v);
            prev = k;
        }
        for r in &restarts {
            body.extend_from_slice(&r.to_le_bytes());
        }
        body.extend_from_slice(&(restarts.len() as u32).to_le_bytes());
        if compress {
            // Snappy has no encoder in this tree, so the compressed form is
            // written by hand as a single literal element, which is a valid
            // stream and exercises exactly the path a real table takes.
            let mut s = Vec::new();
            let n = body.len();
            let mut v = n as u32;
            loop {
                let b = (v & 0x7f) as u8;
                v >>= 7;
                s.push(b | if v != 0 { 0x80 } else { 0 });
                if v == 0 {
                    break;
                }
            }
            if n - 1 < 60 {
                s.push(((n - 1) as u8) << 2);
            } else {
                s.push(60 << 2);
                s.push((n - 1) as u8);
            }
            s.extend_from_slice(&body);
            body = s;
        }
        // Five-byte trailer: the compression type plus a masked CRC-32C of
        // the type and the data, the way the store writes it.
        body.push(u8::from(compress));
        let split = body.len() - 1;
        let crc = mask_crc(crc32c(&[&body[..split], &body[split..]]));
        body.extend_from_slice(&crc.to_le_bytes());
        body
    }

    fn table(data_block: Vec<u8>, compress: bool) -> Vec<u8> {
        let mut file = data_block.clone();
        // The index names the data block by handle, with the block's last key
        // as the entry's key.
        let mut handle_bytes = Vec::new();
        varint64(&mut handle_bytes, 0);
        varint64(&mut handle_bytes, data_block.len() as u64);
        let index_off = file.len();
        file.extend(block(&[(b"user:3", &handle_bytes)], compress));
        let index_size = file.len() - index_off;

        let mut footer = Vec::new();
        varint64(&mut footer, index_off as u64);
        varint64(&mut footer, index_size as u64);
        varint64(&mut footer, 0); // metaindex offset
        varint64(&mut footer, 0); // metaindex size
        while footer.len() < 40 {
            footer.push(0);
        }
        footer.extend_from_slice(&TABLE_MAGIC.to_le_bytes());
        file.extend_from_slice(&footer);
        file
    }

    fn varint64(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            out.push(b | if v != 0 { 0x80 } else { 0 });
            if v == 0 {
                return;
            }
        }
    }

    #[test]
    fn a_table_reads_back_its_keys_and_values() {
        let rows: Vec<(&[u8], &[u8])> = vec![
            (b"user:1", b"RGX-TABLE-1"),
            (b"user:2", b"senha-secreta"),
            (b"user:3", b"terceiro"),
        ];
        let file = table(block(&rows, false), false);
        let out = text_of(&file);
        assert!(out.contains("\"user:1\" \"RGX-TABLE-1\""), "{out}");
        assert!(out.contains("\"user:2\" \"senha-secreta\""), "{out}");
        assert!(out.contains("\"user:3\" \"terceiro\""), "{out}");
    }

    #[test]
    fn a_table_block_with_a_bad_checksum_is_refused() {
        // The checksum is over the bytes as they are in the file, so a
        // block whose bytes were changed does not decode into something
        // that looks like data.
        let rows: Vec<(&[u8], &[u8])> = vec![(b"user:1", b"RGX-SNAPPY-TABLE")];
        let mut data = block(&rows, true);
        let n = data.len();
        data[n - 4] ^= 0xff; // the checksum
        let file = table(data, true);
        let out = text_of(&file);
        assert!(out.contains("checksum"), "{out}");
    }

    /// A real table's blocks are Snappy, and without the decoder the table
    /// is noise.
    #[test]
    fn a_snappy_compressed_table_block_is_read() {
        let rows: Vec<(&[u8], &[u8])> = vec![
            (b"user:1", b"RGX-SNAPPY-TABLE"),
            (b"user:2", b"outro valor"),
        ];
        let file = table(block(&rows, true), true);
        let out = text_of(&file);
        assert!(out.contains("RGX-SNAPPY-TABLE"), "{out}");
        assert!(out.contains("outro valor"), "{out}");
    }

    #[test]
    fn a_file_that_is_neither_shape_is_declined() {
        let Err(err) = LevelDb.extract(b"random bytes that are not a store", "x.ldb") else {
            panic!("expected a decline");
        };
        assert!(err.is_decline(), "got: {err}");
    }

    mod fuzz {
        use super::*;

        #[test]
        fn never_panics_on_arbitrary_bytes() {
            let rows: Vec<(&[u8], &[u8])> = vec![(b"k", b"v"), (b"kk", b"vv")];
            let corpus = vec![
                ("log", record(1, &batch(1, &rows, &[b"gone"]))),
                ("table", table(block(&rows, false), false)),
                ("table-snappy", table(block(&rows, true), true)),
                ("empty", Vec::new()),
                ("magic-only", TABLE_MAGIC.to_le_bytes().to_vec()),
            ];
            rgx_core::fuzzkit::assert_never_panics(corpus, 2000, "leveldb", |data| {
                let _ = LevelDb.extract(data, "fuzz.ldb");
            });
        }
    }
}
